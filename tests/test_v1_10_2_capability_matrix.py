import pytest
from ln_church_agent.capabilities import get_capability_matrix
from ln_church_agent.cli import inspect_url
from unittest.mock import patch, MagicMock
import json
import base64

def test_capability_matrix_contains_core_boundaries():
    matrix = get_capability_matrix()
    names = [row["name"] for row in matrix]
    assert "L402" in names
    assert "AP2" in names
    assert "x402 batch-settlement" in names

def test_capability_matrix_marks_commerce_surfaces_non_executable():
    matrix = get_capability_matrix()
    ap2 = next(row for row in matrix if row["id"] == "ap2")
    assert ap2["layer"] == "commerce_surface"
    assert ap2["execution_behavior"] == "halt"
    assert ap2["proof_semantics"] == "authorization_or_commerce_artifact_not_settlement_proof"

def test_capability_matrix_marks_batch_settlement_observe_only():
    matrix = get_capability_matrix()
    batch = next(row for row in matrix if row["id"] == "x402_batch_settlement")
    assert batch["current_sdk_support"] == "observe_only"
    assert batch["proof_semantics"] == "deferred_voucher_not_settlement_proof"

def test_inspect_outputs_remain_non_executing():
    matrix = get_capability_matrix()
    for row in matrix:
        if row["layer"] == "settlement_rail" and row["execution_behavior"] == "execute":
            # For executing rails, inspect must not execute
            assert "executed_in_inspect" in row["inspect_behavior"] or row["inspect_behavior"] == "supported_but_not_executed_in_inspect"

@patch("ln_church_agent.cli.requests.request")
def test_no_execution_behavior_changed(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    payload = {"accepts": [{"scheme": "batch-settlement", "network": "eip155:8453", "asset": "USDC", "amount": "100"}]}
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    mock_res.headers = {"PAYMENT-REQUIRED": b64_str}
    mock_res.content = b""
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res
    
    res = inspect_url("http://test.local")
    
    assert res.ok is True
    assert res.will_execute_payment is False
    assert res.recommended_action == "observe_only"
    assert "x402" in res.settlement_rails_detected

def test_capability_matrix_is_readonly_and_static():
    # Calling the method should not perform any HTTP requests or state changes
    matrix = get_capability_matrix()
    assert isinstance(matrix, list)
    assert len(matrix) > 0
    assert isinstance(matrix[0], dict)

from ln_church_agent import get_capability_matrix

def test_capability_matrix_public_import():
    matrix = get_capability_matrix()
    assert isinstance(matrix, list)
    assert any(row["id"] == "x402_batch_settlement" for row in matrix)

def test_capability_matrix_new_boundary_fields():
    """Ensure the capability matrix clearly separates inspect_only and execution_runtime boundaries."""
    from ln_church_agent.capabilities import get_capability_matrix
    matrix = get_capability_matrix()
    
    # Executable Settlement Rail
    l402 = next(row for row in matrix if row["id"] == "l402")
    assert l402["mode"] == "execution_runtime"
    assert l402["requires_private_key"] is False  # PR 2.1 で False に変更
    assert l402["can_execute_payment"] is True
    assert l402["auto_submits_telemetry"] is False
    
    # Inspect-Only Commerce Surface
    ap2 = next(row for row in matrix if row["id"] == "ap2")
    assert ap2["mode"] == "inspect_only"
    assert ap2["requires_private_key"] is False
    assert ap2["can_execute_payment"] is False
    assert ap2["auto_submits_telemetry"] is False

    # Explicit Observation
    ext_obs = next(row for row in matrix if row["id"] == "external_observation")
    assert ext_obs["mode"] == "explicit_observation"
    assert ext_obs["can_execute_payment"] is False
    assert ext_obs["can_submit_telemetry"] is True
    assert ext_obs["auto_submits_telemetry"] is False

def test_capability_matrix_credential_and_grant_semantics():
    """Ensure Lightning rails do not require private keys and Grant does not execute payments."""
    from ln_church_agent.capabilities import get_capability_matrix
    matrix = get_capability_matrix()
    
    # L402 Semantics
    l402 = next(row for row in matrix if row["id"] == "l402")
    assert l402["requires_private_key"] is False
    assert l402["requires_payment_credential"] is True
    assert l402["credential_requirement"] == "lightning_wallet_or_ln_adapter"
    assert l402["can_execute_payment"] is True

    # MPP charge Semantics
    mpp = next(row for row in matrix if row["id"] == "mpp_charge")
    assert mpp["requires_private_key"] is False
    assert mpp["requires_payment_credential"] is True
    assert mpp["credential_requirement"] == "lightning_wallet_or_mpp_capable_adapter"

    # x402 Semantics
    x402_evm = next(row for row in matrix if row["id"] == "x402_v1_evm")
    assert x402_evm["requires_private_key"] is True
    assert x402_evm["can_execute_payment"] is True

    # Grant Semantics
    grant = next(row for row in matrix if row["id"] == "grant_sponsored_access")
    assert grant["requires_private_key"] is False
    assert grant["can_execute_payment"] is False
    assert grant["can_authorize_access"] is True
    assert grant["can_execute_protected_action"] is True
    assert grant["requires_payment_credential"] is False
    assert grant["proof_semantics"] == "grant_validated_not_settlement_proof"

def test_capability_matrix_payment_draft_semantics():
    """Ensure Payment draft challenge is conditional and does not generate JSON credentials."""
    from ln_church_agent.capabilities import get_capability_matrix
    matrix = get_capability_matrix()

    # Payment draft challenge の検証
    draft = next(row for row in matrix if row["id"] == "payment_draft_challenge")
    assert draft["current_sdk_support"] == "conditional_execution"
    assert draft["execution_behavior"] == "execute_when_mapped_to_supported_payment_method"
    assert draft["proof_semantics"] == "method_dependent"
    assert draft["does_not_construct_payment_auth_json_credential"] is True
    assert draft["unsupported_shapes_default_action"] == "stop_safely"

    # MPP session が安全に停止 (stop_safely) することの検証
    mpp_session = next(row for row in matrix if row["id"] == "mpp_session_intent")
    assert mpp_session["current_sdk_support"] == "stop_safely"

    # auth-capture と batch-settlement が inspect_only であることの検証
    auth_capture = next(row for row in matrix if row["id"] == "x402_auth_capture")
    assert auth_capture["mode"] == "inspect_only"

    batch_settlement = next(row for row in matrix if row["id"] == "x402_batch_settlement")
    assert batch_settlement["mode"] == "inspect_only"

def test_capability_matrix_observation_semantics():
    """Ensure observation and memory layers explicitly declare they are reusable records, not verdicts."""
    from ln_church_agent.capabilities import get_capability_matrix
    matrix = get_capability_matrix()

    memory_layers = ["surface_preflight", "goal_attempt_observation", "external_observation", "sandbox_evidence"]
    
    for layer_id in memory_layers:
        layer = next(row for row in matrix if row["id"] == layer_id)
        assert layer.get("not_a_verdict") is True
        assert layer.get("not_a_recommendation") is True
        assert layer.get("observation_semantics") == "reusable_observation_record"
        assert "Final payment authority remains" in layer.get("interpretation_hint", "")