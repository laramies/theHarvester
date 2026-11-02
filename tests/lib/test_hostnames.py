from theHarvester.lib.hostnames import (
    host_ip_sort_key,
    ip_sort_key,
    normalize_scoped_hostname,
    sort_host_ip_row,
)


def test_normalize_scoped_hostname_keeps_www_as_the_boundary() -> None:
    assert normalize_scoped_hostname('dev.www.example.com', 'WWW.Example.COM.') == 'dev.www.example.com'
    assert normalize_scoped_hostname('www.example.com', 'WWW.Example.COM.') == 'www.example.com'
    assert normalize_scoped_hostname('admin.example.com', 'WWW.Example.COM.') is None


def test_normalize_scoped_hostname_idna_encodes_value_and_target() -> None:
    assert normalize_scoped_hostname('API.München.Example.TEST.', 'münchen.example.test') == 'api.xn--mnchen-3ya.example.test'
    assert (
        normalize_scoped_hostname('api.xn--mnchen-3ya.example.test', 'münchen.example.test') == 'api.xn--mnchen-3ya.example.test'
    )
    assert normalize_scoped_hostname('admin.example.test', 'münchen.example.test') is None


def test_normalize_scoped_hostname_rejects_invalid_or_unscoped_values() -> None:
    assert normalize_scoped_hostname('bad_label.example.com', 'example.com') is None
    assert normalize_scoped_hostname('192.0.2.1', 'example.com') is None
    assert normalize_scoped_hostname('api.example.com', '192.0.2.1') is None
    assert normalize_scoped_hostname(123, 'example.com') is None


def test_ip_sort_key() -> None:
    ips = [
        '2001:db8::2',
        '192.0.2.100',
        '192.0.2.2',
        'not-an-ip',
        '192.0.2.1',
        '2001:db8::1',
    ]
    assert sorted(ips, key=ip_sort_key) == [
        '192.0.2.1',
        '192.0.2.2',
        '192.0.2.100',
        '2001:db8::1',
        '2001:db8::2',
        'not-an-ip',
    ]


def test_sort_host_ip_row() -> None:
    assert (
        sort_host_ip_row('api.example.test:192.0.2.100,192.0.2.2')
        == 'api.example.test:192.0.2.2,192.0.2.100'
    )
    assert (
        sort_host_ip_row('api.example.test:2001:db8::10,192.0.2.1,2001:db8::2,192.0.2.100')
        == 'api.example.test:192.0.2.1,192.0.2.100,2001:db8::2,2001:db8::10'
    )
    assert sort_host_ip_row('api.example.test:192.0.2.1') == 'api.example.test:192.0.2.1'
    assert sort_host_ip_row('api.example.test') == 'api.example.test'


def test_host_ip_sort_key_orders_subdomains_and_numeric_ips() -> None:
    entries = [
        'api.example.test:192.0.2.100',
        'api.example.test:192.0.2.2',
        'api.example.test:192.0.2.1',
        'api.example.test',
        'api.example.test:192.0.2.2,192.0.2.100',
        'api.example.test:2001:db8::1',
        'api.example.test:not-an-ip',
        'beta.example.test:192.0.2.1',
        'alpha.example.test',
    ]
    sorted_entries = sorted(entries, key=host_ip_sort_key)
    assert sorted_entries == [
        'alpha.example.test',
        'api.example.test',
        'api.example.test:192.0.2.1',
        'api.example.test:192.0.2.2',
        'api.example.test:192.0.2.2,192.0.2.100',
        'api.example.test:192.0.2.100',
        'api.example.test:2001:db8::1',
        'api.example.test:not-an-ip',
        'beta.example.test:192.0.2.1',
    ]
