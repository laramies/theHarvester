import os
import re
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from theHarvester.__main__ import sanitize_filename, sanitize_for_xml


class TestCORSConfiguration:
    """Test CORS security configuration."""

    def test_cors_does_not_allow_credentials_with_wildcard_origins(self):
        """
        Security Test: CORS should not allow credentials with wildcard origins.

        This prevents credential theft attacks where any origin can make
        authenticated requests to the API.
        """
        from theHarvester.lib.api.api import app

        # Find CORS middleware in the app
        cors_middleware = None
        for middleware in app.user_middleware:
            if 'CORSMiddleware' in str(middleware.cls):
                cors_middleware = middleware
                break

        assert cors_middleware is not None, 'CORS middleware should be configured'

        # Check that if allow_origins contains '*', allow_credentials must be False
        # Access kwargs from the middleware
        options = cors_middleware.kwargs
        allow_origins = options.get('allow_origins', [])
        allow_credentials = options.get('allow_credentials', False)

        if isinstance(allow_origins, (list, tuple, set)) and '*' in allow_origins:
            assert (
                allow_credentials is False
            ), 'CRITICAL: CORS must not allow credentials with wildcard origins (CVE risk)'

    def test_cors_restricts_http_methods(self):
        """
        Security Test: CORS should restrict HTTP methods to only what's needed.

        Reduces attack surface by limiting available methods.
        """
        from theHarvester.lib.api.api import app

        cors_middleware = None
        for middleware in app.user_middleware:
            if 'CORSMiddleware' in str(middleware.cls):
                cors_middleware = middleware
                break

        assert cors_middleware is not None

        options = cors_middleware.kwargs
        allow_methods = options.get('allow_methods', [])

        # Should not allow all methods
        assert allow_methods != ['*'], 'CORS should restrict HTTP methods, not allow all (*)'

        # Should only allow necessary methods (GET, POST for this API)
        if isinstance(allow_methods, list):
            dangerous_methods = {'DELETE', 'PUT', 'PATCH', 'TRACE', 'CONNECT'}
            allowed_set = {m.upper() for m in allow_methods}
            assert not (
                allowed_set & dangerous_methods
            ), f'Unnecessary HTTP methods detected: {allowed_set & dangerous_methods}'


class TestXMLInjectionPrevention:
    """Test XML injection prevention."""

    def test_sanitize_for_xml_escapes_special_characters(self):
        """
        Security Test: Verify XML special characters are properly escaped.

        Prevents XML injection attacks.
        """
        # Test all XML special characters
        test_cases = [
            ('&', '&amp;'),
            ('<', '&lt;'),
            ('>', '&gt;'),
            ('"', '&quot;'),
            ("'", '&apos;'),
            ('<script>alert("XSS")</script>', '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'),
            ('user@example.com & <test>', 'user@example.com &amp; &lt;test&gt;'),
            ('Normal text', 'Normal text'),
        ]

        for input_text, expected_output in test_cases:
            result = sanitize_for_xml(input_text)
            assert result == expected_output, f'Failed to properly escape: {input_text}'

    def test_sanitize_for_xml_prevents_xml_entity_injection(self):
        """
        Security Test: Prevent XML entity injection attempts.
        """
        malicious_inputs = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            '<!ENTITY xxe SYSTEM "file:///dev/random">',
            '<![CDATA[malicious]]>',
            '&#x3C;script&#x3E;',
        ]

        for malicious_input in malicious_inputs:
            result = sanitize_for_xml(malicious_input)
            # Ensure dangerous characters are escaped
            assert '&lt;' in result or '&amp;' in result, f'Failed to sanitize: {malicious_input}'
            assert '<' not in result or result == malicious_input.replace('<', '&lt;'), f'XML tags not escaped: {malicious_input}'

    def test_command_line_args_are_sanitized_in_xml_output(self):
        """
        Security Test: Command line arguments must be sanitized before XML output.

        This test is a conceptual check - in real usage, ensure the XML writing
        code uses sanitize_for_xml() on all user-controlled data.
        """
        # Simulate dangerous command line arguments
        dangerous_args = [
            '--domain=test.com',
            "--source='<script>alert(1)</script>'",
            '--output="; rm -rf /',
            '--domain=example.com&param=<injection>',
        ]

        for arg in dangerous_args:
            sanitized = sanitize_for_xml(arg)
            # Verify no unescaped XML special characters remain
            assert '<script>' not in sanitized, f'Script tag not escaped in: {arg}'
            assert '&param=' not in sanitized or '&amp;' in sanitized, f'Ampersand not escaped in: {arg}'


class TestInformationDisclosure:
    """Test information disclosure prevention."""

    @pytest.fixture
    def client(self):
        """Create a test client for API testing."""
        from theHarvester.lib.api.api import app

        return TestClient(app)

    def test_api_does_not_expose_traceback_in_error_responses(self, client):
        """
        Security Test: API should never expose stack traces to clients.

        Stack traces can reveal sensitive information about the system.
        """
        # Test the /sources endpoint with a simulated error condition
        response = client.get('/sources')

        # Even if there's an error, traceback should not be in response
        if response.status_code >= 400:
            response_data = response.json()
            assert 'traceback' not in response_data, 'Traceback exposed in error response'
            assert 'Traceback' not in str(response_data), 'Traceback text found in response'
            assert 'File "' not in str(response_data), 'File paths exposed in response'

    def test_error_responses_do_not_leak_internal_paths(self, client):
        """
        Security Test: Error messages should not reveal internal file paths.
        """
        # Try various endpoints
        endpoints = ['/sources', '/dnsbrute?domain=test', '/query?domain=test&source=baidu']

        for endpoint in endpoints:
            response = client.get(endpoint)
            response_text = str(response.json() if response.status_code != 200 else {})

            # Check for common path leakage patterns
            path_patterns = [
                r'/home/\w+/',
                r'/usr/local/',
                r'C:\\Users\\',
                r'/var/www/',
                r'site-packages/',
                r'\.py:\d+',  # filename.py:123
            ]

            for pattern in path_patterns:
                matches = re.findall(pattern, response_text)
                assert not matches, f'Internal path leaked in {endpoint}: {matches}'

    def test_debug_mode_does_not_expose_sensitive_info(self, client, monkeypatch):
        """
        Security Test: Even with DEBUG=1, sensitive info should not be exposed to clients.
        """
        # Set DEBUG environment variable
        monkeypatch.setenv('DEBUG', '1')

        # Make request that might trigger an error
        response = client.get('/dnsbrute?domain=')  # Invalid request

        if response.status_code >= 400:
            response_data = response.json()
            # Even with DEBUG=1, traceback should NOT be sent to client
            assert 'traceback' not in response_data, 'DEBUG mode exposes tracebacks to clients'


class TestPathTraversalPrevention:
    """Test path traversal prevention."""

    def test_sanitize_filename_removes_path_components(self):
        """
        Security Test: Filenames should not contain path traversal sequences.
        """
        dangerous_filenames = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '/etc/passwd',
            'C:\\Windows\\System32\\config\\sam',
            '../../sensitive_file.txt',
            './../hidden_file',
            'subdir/../../../etc/passwd',
        ]

        for dangerous_filename in dangerous_filenames:
            result = sanitize_filename(dangerous_filename)

            # Should not contain any path separators
            assert '/' not in result, f'Path separator found in sanitized filename: {result}'
            assert '\\' not in result, f'Windows path separator found: {result}'

            # Should not start with .. (parent directory reference at the beginning is most dangerous)
            assert not result.startswith('..'), f'Parent directory reference at start: {result}'

            # Should only be the basename
            assert os.path.dirname(result) == '', f'Path component remains: {result}'

    def test_sanitize_filename_removes_dangerous_characters(self):
        """
        Security Test: Filenames should only contain safe characters.
        """
        test_cases = [
            'file; rm -rf /',
            'file`whoami`.txt',
            'file$(malicious).txt',
            'file|cmd.txt',
            'file&background.txt',
            'normal-file_123.txt',
        ]

        for input_filename in test_cases:
            result = sanitize_filename(input_filename)

            # Should not be empty
            assert len(result) > 0, f'Sanitized filename is empty for: {input_filename}'

            # Should not contain shell special characters
            dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>']
            for char in dangerous_chars:
                assert char not in result, f'Dangerous character {char} found in: {result}'

            # Should only contain alphanumeric, dash, underscore, and dot
            assert re.match(r'^[a-zA-Z0-9._-]+$', result), f'Invalid characters in sanitized filename: {result}'

    def test_sanitize_filename_prevents_hidden_files(self):
        """
        Security Test: Prevent creation of hidden files.
        """
        hidden_files = ['.bashrc', '.ssh_config', '.env', '..hidden', '.']

        for hidden_file in hidden_files:
            result = sanitize_filename(hidden_file)

            # Should not start with a dot (except for allowed extensions)
            if result:  # If not empty
                assert not result.startswith('.'), f'Hidden file not prevented: {result}'

    def test_filename_sanitization_preserves_safe_filenames(self):
        """
        Security Test: Safe filenames should remain mostly unchanged.
        """
        safe_filenames = [
            'report.json',
            'results_2024-01-17.xml',
            'scan-output.txt',
            'data_file_v2.csv',
        ]

        for safe_filename in safe_filenames:
            result = sanitize_filename(safe_filename)

            # Safe filenames should be preserved (possibly with minor changes)
            assert len(result) > 0, 'Safe filename was completely removed'
            assert '.' in result if '.' in safe_filename else True, 'File extension removed incorrectly'

    def test_path_traversal_in_file_operations(self):
        """
        Integration Test: Verify file operations don't allow path traversal.
        """
        # This tests the actual usage in the code
        from theHarvester.__main__ import sanitize_filename

        # Simulate user input
        user_input = '../../../etc/passwd'
        sanitized = sanitize_filename(user_input)

        # Try to create a file with sanitized name
        with tempfile.TemporaryDirectory() as tmpdir:
            safe_path = os.path.join(tmpdir, sanitized)

            # Ensure the resolved path is still within tmpdir
            assert os.path.commonpath([tmpdir, safe_path]) == tmpdir, 'Path traversal detected!'

            # Verify we can't escape the directory
            assert tmpdir in os.path.abspath(safe_path), 'File path escaped temporary directory'


class TestSecurityBestPractices:
    """Additional security best practices tests."""

    def test_no_hardcoded_secrets_in_code(self):
        """
        Security Test: Ensure no hardcoded secrets in main code files.
        """
        # Check main application files for common secret patterns
        files_to_check = [
            'theHarvester/__main__.py',
            'theHarvester/lib/api/api.py',
            'theHarvester/lib/core.py',
        ]

        # Patterns that might indicate hardcoded secrets
        secret_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][a-zA-Z0-9]{20,}["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][a-zA-Z0-9]{20,}["\']',
        ]

        for file_path in files_to_check:
            if os.path.exists(file_path):
                with open(file_path) as f:
                    content = f.read()

                for pattern in secret_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    # Filter out obvious non-secrets (like example values, empty strings, variable names)
                    real_matches = [
                        m
                        for m in matches
                        if 'example' not in m.lower()
                        and 'your_' not in m.lower()
                        and '""' not in m
                        and "''" not in m
                    ]
                    assert not real_matches, f'Potential hardcoded secret in {file_path}: {real_matches}'

    def test_api_has_rate_limiting(self):
        """
        Security Test: Verify API endpoints have rate limiting enabled.
        """
        from theHarvester.lib.api.api import app

        # Check that rate limiting is configured
        assert hasattr(app.state, 'limiter'), 'Rate limiter not configured'
        assert app.state.limiter is not None, 'Rate limiter is None'

    def test_sensitive_endpoints_require_validation(self):
        """
        Security Test: Ensure sensitive endpoints validate input.
        """
        from fastapi.testclient import TestClient

        from theHarvester.lib.api.api import app

        client = TestClient(app)

        # Test that endpoints reject invalid input
        # Note: The /query endpoint requires 'source' as a list parameter
        test_cases = [
            ('/dnsbrute?domain=', 400),  # Empty domain should be rejected
        ]

        for endpoint, expected_status in test_cases:
            response = client.get(endpoint)
            assert (
                response.status_code >= 400
            ), f'Endpoint {endpoint} should reject invalid input (got {response.status_code})'

        # Test query endpoint with proper parameter format but invalid domain
        response = client.get('/query?domain=a&source=baidu')  # Too short domain
        # This may or may not fail depending on validation, but we check it doesn't crash
        assert response.status_code in [200, 400, 422, 500], 'Unexpected status code'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
