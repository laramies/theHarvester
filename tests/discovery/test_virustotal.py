import pytest

from theHarvester.discovery import virustotal


@pytest.mark.asyncio
async def test_parse_hostnames_preserves_www_evidence() -> None:
    data = [
        {
            'id': 'www.example.com',
            'attributes': {
                'last_dns_records': [{'value': 'www.api.example.com'}],
                'last_https_certificate': {
                    'extensions': {'subject_alternative_name': ['www.mail.example.com']}
                },
            },
        }
    ]

    assert await virustotal.SearchVirustotal.parse_hostnames(data, 'example.com') == [
        'www.api.example.com',
        'www.example.com',
        'www.mail.example.com',
    ]
