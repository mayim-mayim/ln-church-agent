"""Deterministic network boundaries for unit tests.

Transport calls are mocked throughout the suite.  Redirect validation must not
perform real DNS beside those mocks, so the default test resolver returns one
public documentation address.  Security tests override the per-client resolver
to exercise private/mixed answers explicitly.
"""

import pytest


_LEGACY_INSPECT_TEST_MODULES = frozenset(
    {
        "test_cli_inspect",
        "test_v1_10_2_capability_matrix",
        "test_v1_11_1_auth_capture_inspect",
        "test_v1_11_2_grant_signal_detection",
        "test_v1_8_1_hotfix",
        "test_v1_8_2_response_adapter",
        "test_v1_9_0_ap2_acp_inspect",
        "test_v1_9_1_guided_handoff",
        "test_v1_9_2_mcp_inspect",
        "test_v1_9_5_settlement_options",
        "test_v1_9_7_batch_settlement_inspect",
    }
)


@pytest.fixture(autouse=True)
def _deterministic_public_redirect_dns(monkeypatch):
    monkeypatch.setattr(
        "ln_church_agent.client.resolve_host_addresses",
        lambda _host, _port: ("93.184.216.34",),
    )


@pytest.fixture(autouse=True)
def _deterministic_legacy_inspect_dns(request, monkeypatch):
    """Keep legacy public.example fixtures on the real Inspect policy path."""
    module = getattr(request.node, "module", None)
    module_basename = getattr(module, "__name__", "").rsplit(".", 1)[-1]
    if module_basename not in _LEGACY_INSPECT_TEST_MODULES:
        return

    monkeypatch.setattr(
        "ln_church_agent.inspect_transport._resolve_addresses",
        lambda _host, _port: ("93.184.216.34",),
    )
