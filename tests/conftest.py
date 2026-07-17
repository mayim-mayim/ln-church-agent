"""Deterministic network boundaries for unit tests.

Transport calls are mocked throughout the suite.  Redirect validation must not
perform real DNS beside those mocks, so the default test resolver returns one
public documentation address.  Security tests override the per-client resolver
to exercise private/mixed answers explicitly.
"""

import pytest


@pytest.fixture(autouse=True)
def _deterministic_public_redirect_dns(monkeypatch):
    monkeypatch.setattr(
        "ln_church_agent.client.resolve_host_addresses",
        lambda _host, _port: ("93.184.216.34",),
    )
