# tests/test_v1_10_0_goal_attempt_observation.py
import pytest
import asyncio
from unittest.mock import patch, MagicMock
from ln_church_agent.client import LnChurchClient

def test_submit_goal_attempt_observation_without_outcome():
    """A. sync: outcomeなしで送信でき、payloadに含まれないことを検証"""
    client = LnChurchClient(
        private_key="0x0000000000000000000000000000000000000000000000000000000000000001"
    )

    with patch.object(client, "execute_request", return_value={"status": "accepted"}) as mock_exec:
        res = client.submit_goal_attempt_observation(
            goal={
                "goal_text": "Explain this transaction",
                "declared_goal_type": "tx_explanation",
                "domain_hint": "crypto"
            },
            attempt={
                "attempt_mode": "free",
                "completion_status": "partial_success",
                "total_monetary_cost": 0,
                "total_reasoning_cost_estimate": "medium"
            },
            steps=[
                {
                    "step_index": 1,
                    "step_role": "fetch",
                    "surface_key": "web:example:tx",
                    "surface_type": "web_page",
                    "payment_performed": False,
                    "status": "success"
                }
            ],
            evidence={
                "evidence_class": "agent_report",
                "verification_status": "self_reported",
                "payment_performed": False
            }
        )

    args = mock_exec.call_args.args
    kwargs = mock_exec.call_args.kwargs

    assert args[0] == "POST"
    assert args[1] == "/api/agent/external/attempt/observe"

    payload = kwargs.get("payload")
    assert payload["schema_version"] == "goal_attempt.v1"
    assert "outcome" not in payload
    assert payload["attempt"]["attempt_mode"] == "free"
    assert payload["steps"][0]["surface_key"] == "web:example:tx"
    assert res["status"] == "accepted"


def test_submit_goal_attempt_observation_with_outcome():
    """B. sync: outcomeありで送信した場合のみpayloadに含まれることを検証"""
    client = LnChurchClient(
        private_key="0x0000000000000000000000000000000000000000000000000000000000000001"
    )

    with patch.object(client, "execute_request", return_value={"status": "accepted"}) as mock_exec:
        client.submit_goal_attempt_observation(
            goal={"goal_text": "Assess endpoint quality"},
            attempt={"attempt_mode": "mixed", "completion_status": "success"},
            steps=[],
            outcome={
                "goal_achieved": True,
                "satisfaction_level": "full",
                "confidence": 0.91,
                "upgrade_signal": "none",
                "rubric_version": "outcome_rubric.v1"
            }
        )

    payload = mock_exec.call_args.kwargs["payload"]
    assert "outcome" in payload
    assert payload["outcome"]["satisfaction_level"] == "full"


def test_submit_goal_attempt_observation_async_without_outcome():
    """C. async: outcomeなしで正常に非同期送信できるか検証"""
    async def run_test():
        client = LnChurchClient(
            private_key="0x0000000000000000000000000000000000000000000000000000000000000001"
        )

        async def fake_execute_request_async(method, path, payload=None, **kwargs):
            assert method == "POST"
            assert path == "/api/agent/external/attempt/observe"
            assert "outcome" not in payload
            assert payload["steps"] == []
            return {"status": "accepted"}

        client.execute_request_async = fake_execute_request_async

        res = await client.submit_goal_attempt_observation_async(
            goal={"goal_text": "Investigate endpoint"},
            attempt={"attempt_mode": "free", "completion_status": "unknown"}
        )

        assert res["status"] == "accepted"

    asyncio.run(run_test())


def test_goal_attempt_secret_stripping_preserves_public_metadata():
    """D. secret stripping: 公開メタデータが維持され、秘密情報のみが削られることを検証"""
    client = LnChurchClient(
        private_key="0x0000000000000000000000000000000000000000000000000000000000000001"
    )

    clean = client._strip_secrets_from_evidence({
        "authorization_scheme": "x402",
        "payment_performed": False,
        "payment_receipt_present": False,
        "selected_requirement_fingerprint": "abc123",
        "raw_requirement_fingerprint": "def456",
        "surface_key": "paid:example",
        "surface_type": "paid_surface",
        "authorization": "Bearer secret",
        "preimage": "secret-preimage",
        "private_key": "secret-key",
        "grant_token": "secret-grant",
        "headers": {
            "Authorization": "Bearer secret"
        }
    })

    # 公開メタデータが確実に残る
    assert clean["authorization_scheme"] == "x402"
    assert clean["payment_performed"] is False
    assert clean["payment_receipt_present"] is False
    assert clean["selected_requirement_fingerprint"] == "abc123"
    assert clean["raw_requirement_fingerprint"] == "def456"
    assert clean["surface_key"] == "paid:example"

    # 秘密情報・コンテナが確実に消去されている
    assert "authorization" not in clean
    assert "preimage" not in clean
    assert "private_key" not in clean
    assert "grant_token" not in clean
    assert "headers" not in clean


@patch("requests.request")
def test_goal_attempt_no_automatic_hook(mock_req):
    """E. no automatic hook: 通常のパブリック決済リクエスト時にGoal Attemptが自動送信されない検証"""
    client = LnChurchClient(
        base_url="https://api.test",
        private_key="0x0000000000000000000000000000000000000000000000000000000000000001"
    )
    
    # 200 OKの通常レスポンス
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.headers = {}
    mock_res.content = b'{"status":"success"}'
    mock_res.json.return_value = {"status": "success"}
    mock_req.return_value = mock_res
    
    client.execute_request("POST", "/api/v1/resource", payload={"test": "data"})
    
    # 通常リクエストは1回のみで、別エンドポイントへの自動フック通信が走っていないこと
    assert mock_req.call_count == 1
    assert mock_req.call_args.args[1] == "https://api.test/api/v1/resource"