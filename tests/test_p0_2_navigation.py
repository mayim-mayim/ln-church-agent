import pytest

from ln_church_agent.exceptions import NavigationGuardrailError
from ln_church_agent.navigation import (
    canonicalize_http_target,
    validate_redirect_target,
)


def _public(_host, _port):
    return ("93.184.216.34",)


def test_canonical_target_normalizes_default_port_and_fragment():
    target = canonicalize_http_target("HTTPS://Provider.TEST:443/a?b=1#ignored")
    assert target.origin == "https://provider.test"
    assert target.url == "https://provider.test/a?b=1"
    assert target.port == 443


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "https://user:password@provider.test/a",
        "https://provider.test:22/a",
        "https://127.0.0.1/a",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/a",
    ],
)
def test_redirect_rejects_unsafe_scheme_userinfo_port_and_literal_addresses(url):
    with pytest.raises(NavigationGuardrailError):
        validate_redirect_target(url, resolver=_public)


@pytest.mark.parametrize("address", ["10.0.0.7", "172.16.0.1", "192.168.1.2", "fe80::1"])
def test_redirect_rejects_any_private_dns_answer(address):
    with pytest.raises(NavigationGuardrailError, match="non-public"):
        validate_redirect_target(
            "https://provider.test/a",
            resolver=lambda _host, _port: ("93.184.216.34", address),
        )


def test_redirect_accepts_public_dns_answers_only():
    target = validate_redirect_target(
        "https://provider.test:8443/a", resolver=_public
    )
    assert target.origin == "https://provider.test:8443"
