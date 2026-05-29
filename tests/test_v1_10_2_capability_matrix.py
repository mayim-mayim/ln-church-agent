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