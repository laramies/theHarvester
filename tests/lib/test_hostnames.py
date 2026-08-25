from theHarvester.lib.hostnames import normalize_scoped_hostname


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
