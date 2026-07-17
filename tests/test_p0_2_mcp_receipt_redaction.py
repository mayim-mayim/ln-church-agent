from types import SimpleNamespace
from unittest.mock import MagicMock

from ln_church_agent.integrations import mcp as mcp_integration
from ln_church_agent.payment_contract import sha256_prefixed


def test_mcp_body_receipt_fallback_exposes_only_a_hash(monkeypatch):
    raw_token = "header.payload.signature-secret"
    client = MagicMock()
    client.agent_id = "agent-test"
    client.probe_token = "probe-secret"
    client.faucet_token = None
    client.execute_detailed.return_value = SimpleNamespace(
        response={
            "result": "entropy",
            "message": "ok",
            "paid": True,
            "receipt": {"verify_token": raw_token},
        },
        settlement_receipt=None,
    )
    monkeypatch.setattr(mcp_integration, "get_client", lambda: client)

    output = mcp_integration.execute_paid_entropy_oracle()

    assert raw_token not in output
    assert "VERIFY TOKEN (JWS)" not in output
    assert sha256_prefixed(raw_token) in output
