import asyncio
from copy import deepcopy
import json

import pytest
from unittest.mock import patch, MagicMock
from ln_church_agent.client import LnChurchClient
from ln_church_agent.exceptions import NavigationGuardrailError
from ln_church_agent.models import ExecutionContext
from test_paid_result_connection import response, transport

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_submit_unmapped_observation_payload_shape(mock_execute):
    """Test A: Payload shape validation for unmapped observation"""
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")

    target_url = "https://example.com/api/endpoint"
    client.submit_unmapped_observation(
        target_url=target_url,
        detection_note="payment_scheme_unmapped",
        rails_detected=["Payment"]
    )

    args, kwargs = mock_execute.call_args
    assert args[0] == "POST"
    assert args[1] == "/api/agent/external/observe"

    payload = kwargs["payload"]
    assert payload["targetUrl"] == target_url
    assert payload["source_scope"] == "external_agent_report"
    assert payload["protocol"]["rail"] == "unknown"
    assert payload["protocol"]["draft_shape"] == "payment_scheme_unmapped"
    assert payload["evidence"]["evidence_class"] == "crawler_detected_402"
    assert payload["evidence"]["payment_performed"] is False
    assert payload["evidence"]["payment_receipt_present"] is False
    assert "payment_scheme_unmapped" in payload["missing_information"]

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_unsupported_challenge_shape_normalization(mock_execute):
    """Test B: unsupported_challenge_shape is normalized properly"""
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")

    client.submit_unmapped_observation(
        target_url="https://example.com/api/endpoint",
        detection_note="unsupported_challenge_shape"
    )

    payload = mock_execute.call_args[1]["payload"]
    assert payload["protocol"]["draft_shape"] == "unsupported_challenge_shape"
    assert payload["protocol"]["rail"] == "unknown"
    assert payload["evidence"]["verification_status"] == "unverified"

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_unknown_rail_normalization(mock_execute):
    """Test C: unknown_rail normalization and missing_info mapping"""
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")

    client.submit_unmapped_observation(
        target_url="https://example.com/api/endpoint",
        detection_note="unknown_rail"
    )

    payload = mock_execute.call_args[1]["payload"]
    assert payload["protocol"]["rail"] == "unknown"
    assert "unknown_rail" in payload["missing_information"]
    assert "settlement_rail_not_declared" in payload["missing_information"]

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_secret_stripping_applied(mock_execute):
    """Test D: Secret stripping is applied to extra_protocol"""
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")

    unsafe_protocol = {
        "some_safe_key": "safe_value",
        "macaroon": "SECRET_MACAROON",
        "private_key": "SECRET_KEY",
        "authorization": "Bearer SECRET_TOKEN"
    }

    client.submit_unmapped_observation(
        target_url="https://example.com/api/endpoint",
        detection_note="payment_scheme_unmapped",
        extra_protocol=unsafe_protocol
    )

    payload = mock_execute.call_args[1]["payload"]
    protocol = payload["protocol"]

    assert "some_safe_key" in protocol
    assert "macaroon" not in protocol
    assert "private_key" not in protocol
    assert "authorization" not in protocol

def test_guardrail_remains_unchanged():
    """Test G: Guardrail remains completely unchanged"""
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001", auto_navigate=True)

    with patch("requests.request") as mock_req:
        resp_cross_origin = MagicMock()
        resp_cross_origin.status_code = 302
        resp_cross_origin.headers = {"Location": "https://evil.com/steal"}
        resp_cross_origin.json.side_effect = ValueError()
        mock_req.return_value = resp_cross_origin

        with pytest.raises(NavigationGuardrailError, match="(?i).*Cross-origin.*|.*Stopped unsafe.*"):
            client.execute_detailed("GET", "/first")

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_nested_secret_stripping_applied(mock_execute):
    """Test D-2: Nested secret stripping is applied recursively"""
    client = LnChurchClient(private_key="0x" + "1" * 64)

    client.submit_unmapped_observation(
        target_url="https://example.com/api/endpoint",
        detection_note="payment_scheme_unmapped",
        extra_protocol={
            "safe": "ok",
            "nested": {
                "access_token": "SECRET",
                "safe_inner": "ok"
            },
            "payment-response": "SECRET"
        }
    )

    protocol = mock_execute.call_args[1]["payload"]["protocol"]
    assert "payment-response" not in protocol
    assert "access_token" not in protocol.get("nested", {})
    assert protocol["nested"]["safe_inner"] == "ok"


@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.parametrize("shape_source", ["detection_note", "challenge_shape", "extra_protocol", "ordinary"])
def test_unmapped_public_wire_redacts_purchaser_proof_without_changing_input(
    monkeypatch, async_mode, shape_source
):
    handle = "pr_" + "a" * 32
    request_hash = "sha256:" + "b" * 64
    private_url = f"https://public.example/api/bazaar/paid-results/{handle}?request_hash={request_hash}&page=2"
    ordinary = shape_source == "ordinary"
    target_url = "https://public.example/data?category=weather&page=2" if ordinary else private_url
    public_url = target_url if ordinary else "https://public.example/api/bazaar/paid-results/REDACTED?request_hash=REDACTED&page=2"
    detection_note = "Unmapped payment at " + target_url
    extra_protocol = {"nested": {"reference": target_url, "normal": "kept"}}
    if shape_source == "extra_protocol":
        extra_protocol["draft_shape"] = target_url
    inputs = {
        "target_url": target_url,
        "detection_note": detection_note,
        "method": "head",
        "status_code": 402,
        "rails_detected": ["x402"] if ordinary else ["Payment"],
        "challenge_shape": target_url if shape_source == "challenge_shape" else None,
        "extra_protocol": extra_protocol,
        "missing_information": ["Inspect " + target_url],
        "sdk_version": "test-version",
    }
    original = deepcopy(inputs)
    client = LnChurchClient(agent_id="unmapped-test", base_url="https://observer.test")
    send = transport(monkeypatch, client, async_mode, [response(200, {"status": "accepted"})])
    assert send.call_count == 0
    if async_mode:
        result = asyncio.run(client.submit_unmapped_observation_async(**inputs))
    else:
        result = client.submit_unmapped_observation(**inputs)
    assert result == {"status": "accepted"}
    assert send.call_count == 1
    assert send.call_args.args[:2] == ("POST", "https://observer.test/api/agent/external/observe")
    payload = send.call_args.kwargs["json"]
    expected_note = "Unmapped payment at " + public_url
    assert payload == {
        "agentId": "unmapped-test",
        "targetUrl": public_url,
        "method": "HEAD",
        "statusCode": 402,
        "source_scope": "external_agent_report",
        "protocol": {
            "rail": "x402" if ordinary else "unknown",
            "network": "unknown",
            "asset": "unknown",
            "authorization_scheme": "unknown",
            "draft_shape": public_url if shape_source in {"challenge_shape", "extra_protocol"} else expected_note,
            "payment_intent": "unknown",
            "payment_method": "unknown",
            "nested": {"reference": public_url, "normal": "kept"},
        },
        "evidence": {
            "evidence_class": "crawler_detected_402",
            "verification_status": "unverified",
            "verification_method": "none",
            "payment_performed": False,
            "payment_receipt_present": False,
        },
        "missing_information": ["Inspect " + public_url, expected_note,
                                "settlement_rail_not_declared", "network_not_declared", "asset_not_declared"],
        "sdk_version": "test-version",
    }
    assert handle not in json.dumps(payload) and request_hash not in json.dumps(payload)
    assert "outcome" not in payload
    assert inputs == original
    if shape_source == "detection_note":
        # The existing general-observation exit applies the same public boundary.
        external_send = transport(monkeypatch, client, async_mode, [response(200, {"status": "accepted"})])
        if async_mode:
            asyncio.run(client.submit_external_observation_async(target_url=target_url, evidence=extra_protocol))
        else:
            client.submit_external_observation(target_url=target_url, evidence=extra_protocol)
        external = external_send.call_args.kwargs["json"]
        assert external_send.call_count == 1
        assert external["targetUrl"] == public_url
        assert external["evidence"] == {"nested": {"reference": public_url, "normal": "kept"}}
        assert inputs == original
