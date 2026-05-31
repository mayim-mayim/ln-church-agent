import pytest
import asyncio
from unittest.mock import patch, MagicMock
from ln_church_agent.client import LnChurchClient, SURFACE_PREFLIGHT_SCHEMA_VERSION

def make_valid_response(known=True):
    return {
        "schema_version": SURFACE_PREFLIGHT_SCHEMA_VERSION,
        "not_a_recommendation": True,
        "not_a_verdict": True,
        "surface": {"known": known},
        "guardrails": {
            "final_authority": "local_runtime",
            "this_read_model_does_not_execute_payments": True,  # ←追加
            "this_read_model_does_not_prove_settlement": True   # ←追加
        }
    }

@patch("requests.get")
def test_surface_key_lookup_success(mock_get):
    """Test standard surface_key lookup."""
    client = LnChurchClient(private_key="0x" + "0"*64)
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.json.return_value = make_valid_response(known=True)
    mock_get.return_value = mock_res

    res = client.get_surface_preflight(surface_key="surface_0123456789abcdef01234567")
    
    assert res["schema_version"] == SURFACE_PREFLIGHT_SCHEMA_VERSION
    assert res["surface"]["known"] is True
    assert res["not_a_recommendation"] is True
    assert res["not_a_verdict"] is True
    assert res["guardrails"]["final_authority"] == "local_runtime"
    
    args, kwargs = mock_get.call_args
    assert "surface_key" in kwargs["params"]
    assert kwargs["params"]["surface_key"] == "0123456789abcdef01234567"

@patch("requests.get")
def test_target_url_lookup_success(mock_get):
    """Test lookup via target_url and shaping parameters."""
    client = LnChurchClient(private_key="0x" + "0"*64)
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.json.return_value = make_valid_response(known=True)
    mock_get.return_value = mock_res

    res = client.get_surface_preflight(
        target_url="https://api.example.com",
        method="post",
        rail="x402"
    )
    
    args, kwargs = mock_get.call_args
    params = kwargs["params"]
    assert params["target_url"] == "https://api.example.com"
    assert params["method"] == "POST"
    assert params["rail"] == "x402"

@patch("requests.get")
def test_unknown_surface_no_error(mock_get):
    """Test that a known: false surface returns the dict without error."""
    client = LnChurchClient(private_key="0x" + "0"*64)
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.json.return_value = make_valid_response(known=False)
    mock_get.return_value = mock_res

    res = client.get_surface_preflight(surface_key="0123456789abcdef01234567")
    assert res["surface"]["known"] is False

def test_validation_errors():
    """Test input validations."""
    client = LnChurchClient(private_key="0x" + "0"*64)
    
    # Missing locator
    with pytest.raises(ValueError, match="Either surface_key or target_url must be provided"):
        client.get_surface_preflight()

    # Mutual exclusivity
    with pytest.raises(ValueError, match="Provide either surface_key or target_url, not both"):
        client.get_surface_preflight(surface_key="abc", target_url="http")

    # Bad hex
    with pytest.raises(ValueError, match="Must be 24-character hex"):
        client.get_surface_preflight(surface_key="invalid_hex_string")

    # Empty target URL
    with pytest.raises(ValueError, match="target_url cannot be empty"):
        client.get_surface_preflight(target_url="   ")

@patch("requests.get")
def test_schema_guard_fails(mock_get):
    """Test that safety boundary guards raise exceptions if missing or invalid."""
    client = LnChurchClient(private_key="0x" + "0"*64)
    
    # 1. Invalid schema_version
    mock_res = MagicMock(status_code=200)
    mock_res.json.return_value = {"schema_version": "wrong.v1", "not_a_recommendation": True, "not_a_verdict": True}
    mock_get.return_value = mock_res
    with pytest.raises(ValueError, match="Invalid schema_version"):
        client.get_surface_preflight(surface_key="0123456789abcdef01234567")

    # 2. Missing not_a_recommendation
    mock_res.json.return_value = {"schema_version": SURFACE_PREFLIGHT_SCHEMA_VERSION, "not_a_verdict": True}
    with pytest.raises(ValueError, match="not_a_recommendation"):
        client.get_surface_preflight(surface_key="0123456789abcdef01234567")

    # 3. Missing not_a_verdict
    mock_res.json.return_value = {"schema_version": SURFACE_PREFLIGHT_SCHEMA_VERSION, "not_a_recommendation": True}
    with pytest.raises(ValueError, match="not_a_verdict"):
        client.get_surface_preflight(surface_key="0123456789abcdef01234567")

    # 4. guardrails.final_authority 不正
    mock_res.json.return_value = {
        "schema_version": SURFACE_PREFLIGHT_SCHEMA_VERSION, "not_a_recommendation": True, "not_a_verdict": True,
        "guardrails": {"final_authority": "server_enforced", "this_read_model_does_not_execute_payments": True, "this_read_model_does_not_prove_settlement": True}
    }
    with pytest.raises(ValueError, match="guardrails.final_authority must be local_runtime"):
        client.get_surface_preflight(surface_key="0123456789abcdef01234567")

    # 5. guardrails.this_read_model_does_not_execute_payments が True ではない
    mock_res.json.return_value = {
        "schema_version": SURFACE_PREFLIGHT_SCHEMA_VERSION, "not_a_recommendation": True, "not_a_verdict": True,
        "guardrails": {"final_authority": "local_runtime", "this_read_model_does_not_execute_payments": False, "this_read_model_does_not_prove_settlement": True}
    }
    with pytest.raises(ValueError, match="read model must not execute payments"):
        client.get_surface_preflight(surface_key="0123456789abcdef01234567")

    # 6. guardrails.this_read_model_does_not_prove_settlement が欠落
    mock_res.json.return_value = {
        "schema_version": SURFACE_PREFLIGHT_SCHEMA_VERSION, "not_a_recommendation": True, "not_a_verdict": True,
        "guardrails": {"final_authority": "local_runtime", "this_read_model_does_not_execute_payments": True}
    }
    with pytest.raises(ValueError, match="read model must not prove settlement"):
        client.get_surface_preflight(surface_key="0123456789abcdef01234567")

@patch("ln_church_agent.client.LnChurchClient.execute_request")
@patch("requests.get")
def test_no_payment_execution(mock_get, mock_execute):
    """Test that getting preflight absolutely bypasses the payment execution engine."""
    client = LnChurchClient(private_key="0x" + "0"*64)
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.json.return_value = make_valid_response(known=True)
    mock_get.return_value = mock_res

    client.get_surface_preflight(surface_key="0123456789abcdef01234567")
    
    assert mock_get.call_count == 1
    assert mock_execute.call_count == 0

@patch("httpx.AsyncClient.get")
def test_async_surface_key_success(mock_get_async):
    """Test the async version of the method."""
    async def run_test():
        client = LnChurchClient(private_key="0x" + "0"*64)
        mock_res = MagicMock()
        mock_res.status_code = 200
        mock_res.json.return_value = make_valid_response(known=True)
        mock_get_async.return_value = mock_res

        res = await client.get_surface_preflight_async(surface_key="0123456789abcdef01234567")
        assert res["schema_version"] == SURFACE_PREFLIGHT_SCHEMA_VERSION
        assert res["surface"]["known"] is True

    asyncio.run(run_test())

def test_internal_surface_key_derivation():
    client = LnChurchClient(private_key="0x" + "0"*64)
    from ln_church_agent.client import _derive_surface_key
    key = _derive_surface_key(target_url="https://api.example.com/endpoint?volatile=ignore", method="GET", rail="x402")
    assert len(key) == 24

