import os
import re
import tempfile
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from theHarvester.__main__ import sanitize_filename, sanitize_for_xml


class TestCORSConfiguration:
    """Check CORS configuration."""

    def test_api_does_not_enable_cross_origin_requests(self):
        from theHarvester.lib.api.api import app

        assert all('CORSMiddleware' not in str(middleware.cls) for middleware in app.user_middleware)


class TestXMLInjectionPrevention:
    """Check XML escaping."""

    def test_sanitize_for_xml_escapes_special_characters(self):
        """Escape XML special characters."""
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
        """Escape XML entity declarations and references."""
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
        """Escape command-line arguments before writing them to XML."""
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
    """Check that API errors do not disclose internal details."""

    @pytest.fixture
    def client(self):
        """Create an API test client."""
        from theHarvester.lib.api.api import app

        return TestClient(app)

    def test_api_does_not_expose_traceback_in_error_responses(self, client):
        """Keep stack traces out of API error responses."""
        response = client.get('/api/v1/sources')

        # Even if there's an error, traceback should not be in response
        if response.status_code >= 400:
            response_data = response.json()
            assert 'traceback' not in response_data, 'Traceback exposed in error response'
            assert 'Traceback' not in str(response_data), 'Traceback text found in response'
            assert 'File "' not in str(response_data), 'File paths exposed in response'

    def test_error_responses_do_not_leak_internal_paths(self, client, tmp_path, monkeypatch):
        """Keep internal paths out of API error responses."""
        fetch_all = AsyncMock(side_effect=AssertionError('API security test attempted a provider request'))
        monkeypatch.setenv('THEHARVESTER_API_KEY', 'operator-secret')
        monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
        monkeypatch.setattr('theHarvester.lib.core.AsyncFetcher.fetch_all', fetch_all)

        endpoints = ['/api/v1/sources', '/api/v1/runs/not-found']

        for endpoint in endpoints:
            response = client.get(endpoint, headers={'X-API-Key': 'operator-secret'})
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

        fetch_all.assert_not_awaited()

    def test_debug_mode_does_not_expose_sensitive_info(self, client, monkeypatch):
        """Keep sensitive details hidden when ``DEBUG=1``."""
        # Set DEBUG environment variable
        monkeypatch.setenv('DEBUG', '1')

        # Make request that might trigger an error
        response = client.get('/api/v1/runs/not-found')

        if response.status_code >= 400:
            response_data = response.json()
            # Even with DEBUG=1, traceback should NOT be sent to client
            assert 'traceback' not in response_data, 'DEBUG mode exposes tracebacks to clients'


class TestAPIAuthentication:
    """Check authentication and errors for the versioned API."""

    @pytest.fixture
    def client(self):
        """Create an API test client."""
        from theHarvester.lib.api.api import app

        return TestClient(app)

    def test_api_fails_closed_without_configured_api_key(self, client, monkeypatch):
        monkeypatch.delenv('THEHARVESTER_API_KEY', raising=False)
        monkeypatch.delenv('THEHARVESTER_API_KEY_FILE', raising=False)

        response = client.get('/api/v1/sources')

        assert response.status_code == 503

    def test_api_key_can_be_read_from_a_docker_secret_file(self, client, tmp_path, monkeypatch):
        secret = tmp_path / 'operator-api-key'
        secret.write_text('test-secret\n', encoding='utf-8')
        monkeypatch.delenv('THEHARVESTER_API_KEY', raising=False)
        monkeypatch.setenv('THEHARVESTER_API_KEY_FILE', str(secret))

        response = client.get('/api/v1/sources', headers={'X-API-Key': 'test-secret'})

        assert response.status_code == 200

    def test_api_rejects_missing_or_invalid_api_key(self, client, monkeypatch):
        monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-secret')

        missing_response = client.get('/api/v1/sources')
        invalid_response = client.get('/api/v1/sources', headers={'X-API-Key': 'wrong'})

        assert missing_response.status_code == 401
        assert invalid_response.status_code == 401

    def test_api_does_not_expose_internal_errors(self, monkeypatch):
        from theHarvester.lib.api import api
        from theHarvester.lib.api.run_store import RunStore

        async def fail(_self):
            raise RuntimeError('/home/user/project/secret.py:123 internal failure')

        monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-secret')
        monkeypatch.setattr(RunStore, 'list_runs', fail)
        client = TestClient(api.app, raise_server_exceptions=False)

        response = client.get('/api/v1/runs', headers={'X-API-Key': 'test-secret'})

        assert response.status_code == 500
        response_text = response.text
        assert 'internal failure' not in response_text
        assert '/home/user/project' not in response_text


class TestPathTraversalPrevention:
    """Check filename sanitization and path containment."""

    def test_sanitize_filename_removes_path_components(self):
        """Remove path components from filenames."""
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
        """Remove shell metacharacters from filenames."""
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
        """Prevent sanitized filenames from naming hidden files."""
        hidden_files = ['.bashrc', '.ssh_config', '.env', '..hidden', '.']

        for hidden_file in hidden_files:
            result = sanitize_filename(hidden_file)

            # Should not start with a dot (except for allowed extensions)
            if result:  # If not empty
                assert not result.startswith('.'), f'Hidden file not prevented: {result}'

    def test_filename_sanitization_preserves_safe_filenames(self):
        """Preserve safe filenames and their extensions."""
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
        """Keep a sanitized output path inside its destination directory."""
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
    """Check repository and API security invariants."""

    def test_no_hardcoded_secrets_in_code(self):
        """Reject common hard-coded secret patterns in application files."""
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
                        if 'example' not in m.lower() and 'your_' not in m.lower() and '""' not in m and "''" not in m
                    ]
                    assert not real_matches, f'Potential hardcoded secret in {file_path}: {real_matches}'

    def test_sensitive_endpoints_require_validation(self, monkeypatch, tmp_path):
        """Reject invalid requests to authenticated endpoints."""
        from fastapi.testclient import TestClient

        from theHarvester.lib.api.api import app

        monkeypatch.setenv('THEHARVESTER_API_KEY', 'test-secret')
        monkeypatch.setenv('THEHARVESTER_RUN_DB', str(tmp_path / 'runs.sqlite'))
        monkeypatch.setenv('THEHARVESTER_SCHEDULE_DB', str(tmp_path / 'schedules.sqlite'))
        monkeypatch.setenv('THEHARVESTER_RUN_WORKER', 'disabled')
        monkeypatch.setenv('THEHARVESTER_SCHEDULER', 'disabled')
        headers = {'X-API-Key': 'test-secret'}

        with TestClient(app) as client:
            missing_target = client.post('/api/v1/runs', headers=headers, json={'sources': ['crtsh']})
            empty_sources = client.post('/api/v1/runs', headers=headers, json={'target': 'example.test', 'sources': []})

        assert missing_target.status_code == 422
        assert empty_sources.status_code == 422


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
