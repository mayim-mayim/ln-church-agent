import pytest
from unittest.mock import patch, MagicMock
from ln_church_agent.client import LnChurchClient
from ln_church_agent.exceptions import NavigationGuardrailError
from ln_church_agent.models import ExecutionContext

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

        with pytest.raises(NavigationGuardrailError, match="Stopped unsafe automatic navigation"):
            client.execute_detailed("GET", "/first")

@patch("ln_church_agent.client.LnChurchClient.execute_request")
def test_nested_secret_stripping_applied(mock_execute):
    """Test D-2: Nested secret stripping is applied recursively"""
    client = LnChurchClient(private_key="0x" + "0" * 64)

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