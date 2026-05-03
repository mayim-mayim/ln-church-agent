import pytest
import httpx
import base64
import json
from unittest.mock import patch, MagicMock

from ln_church_agent.client import Payment402Client, LnChurchClient
from ln_church_agent.challenges import SOLANA_USDC_MINT

# ==========================================
# 1. Challenge Parser Tests (Hybrid V1+V2 Shape)
# ==========================================
def _create_hybrid_challenge(is_svm: bool) -> httpx.Response:
    if is_svm:
        payload = {
            "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            "amount": "0.01",
            "asset": "USDC",
            "destination": "SolanaTreasuryAddress",
            "token_address": SOLANA_USDC_MINT,
            "decimals": 6,
            "reference": "SolanaReferenceKey",
            "challenge": "macaroon_dummy",
            "accepts": [{
                "scheme": "exact",
                "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "asset": SOLANA_USDC_MINT,
                "symbol": "USDC",
                "decimals": 6,
                "amount": "10000",
                "payTo": "SolanaTreasuryAddress",
                "extra": {
                    "feePayer": "SolanaTreasuryAddress",
                    "reference": "SolanaReferenceKey"
                }
            }],
            "resource": {"url": "http://api.test", "method": "GET"}
        }
    else:
        payload = {
            "network": "eip155:8453",
            "amount": "0.01",
            "asset": "USDC",
            "destination": "0xBaseTreasury",
            "token_address": "0xBaseUSDCContract",
            "decimals": 6,
            "challenge": "macaroon_dummy",
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": "0xBaseUSDCContract",
                "symbol": "USDC",
                "decimals": 6,
                "amount": "10000",
                "payTo": "0xBaseTreasury"
            }],
            "resource": {"url": "http://api.test", "method": "GET"}
        }

    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    return httpx.Response(402, headers={"PAYMENT-REQUIRED": b64_str})

def test_parse_evm_exact_hybrid_challenge():
    """EVM Exact Hybrid Shape が正確にパースされること"""
    client = Payment402Client()
    mock_res = _create_hybrid_challenge(is_svm=False)
    
    parsed = client._parse_challenge(mock_res, expected_chain_id="8453")
    
    assert parsed.asset == "USDC"  # Root asset (Logical)
    assert parsed.parameters["token_address"] == "0xBaseUSDCContract"
    assert parsed.parameters["decimals"] == 6
    assert parsed.network == "eip155:8453"
    
    raw_accepted = parsed.parameters["_raw_accepted"]
    assert raw_accepted["asset"] == "0xBaseUSDCContract" # Accepts[].asset is contract
    assert raw_accepted["symbol"] == "USDC"
    assert raw_accepted["amount"] == "10000"

def test_parse_svm_exact_hybrid_challenge():
    """SVM Exact Hybrid Shape が正確にパースされること"""
    client = Payment402Client()
    mock_res = _create_hybrid_challenge(is_svm=True)
    
    parsed = client._parse_challenge(mock_res, prefer_svm=True)
    
    assert parsed.asset == "USDC"  # Root asset (Logical)
    assert parsed.parameters["token_address"] == SOLANA_USDC_MINT
    assert parsed.parameters["decimals"] == 6
    assert parsed.parameters["reference"] == "SolanaReferenceKey" # Top-level reference
    assert parsed.network.startswith("solana:")
    
    raw_accepted = parsed.parameters["_raw_accepted"]
    assert raw_accepted["asset"] == SOLANA_USDC_MINT # Accepts[].asset is mint
    assert raw_accepted["symbol"] == "USDC"
    assert raw_accepted["amount"] == "10000"
    assert raw_accepted["extra"]["reference"] == "SolanaReferenceKey"

# ==========================================
# 2. & 3. Diagnostic Runner Expected Rejection Tests
# ==========================================
@patch.object(LnChurchClient, "execute_detailed")
def test_x402_svm_exact_invalid_signature_classified_as_post_settlement_required(mock_execute):
    """SVM の Invalid format 拒否が Diagnostic Runner で正確に Expected として分類されること"""
    mock_execute.side_effect = Exception("API Error 403: Invalid Solana signature format. Evidence must be a submitted transaction signature.")
    
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    client._last_parsed_challenge = MagicMock(network="solana:123", asset="USDC", draft_shape="x402-v2-exact-svm", parameters={"token_address": SOLANA_USDC_MINT})
    
    result = client.run_x402_svm_exact_sandbox_diagnostic()
    
    assert result.ok is True
    assert result.expected_rejection is True
    assert result.diagnostic_class == "post_settlement_proof_required"
    assert result.failure_class == "settlement_model_mismatch"
    assert "Invalid Solana signature format" in result.rejection_reason

@patch.object(LnChurchClient, "execute_detailed")
def test_x402_evm_exact_invalid_txhash_classified_as_post_settlement_required(mock_execute):
    """EVM の Invalid TxHash 拒否が Diagnostic Runner で正確に Expected として分類されること"""
    mock_execute.side_effect = Exception("API Error 403: Invalid TxHash format. Must be a 0x-prefixed 66-char string.")
    
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    client._last_parsed_challenge = MagicMock(network="eip155:8453", asset="USDC", draft_shape="x402-v2-exact", parameters={"token_address": "0xBaseUSDCContract"})
    
    result = client.run_x402_evm_exact_sandbox_diagnostic()
    
    assert result.ok is True
    assert result.expected_rejection is True
    assert result.diagnostic_class == "post_settlement_proof_required"
    assert result.failure_class == "settlement_model_mismatch"

@patch.object(LnChurchClient, "execute_detailed")
def test_transaction_not_found_classified_as_post_settlement_required(mock_execute):
    """RPC 到達後の Transaction not found 拒否が Expected として分類されること"""
    mock_execute.side_effect = Exception("API Error 403: Transaction not found on RPC.")
    
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    # 💡 修正: MagicMock が子モックを生成して Pydantic に怒られないように、明示的にダミー値を入れる
    client._last_parsed_challenge = MagicMock(
        network="eip155:8453",
        asset="USDC",
        draft_shape="x402-v2-exact",
        parameters={"token_address": "0xBaseUSDCContract"}
    )
    
    result = client.run_x402_evm_exact_sandbox_diagnostic()
    
    assert result.ok is True
    assert result.expected_rejection is True
    assert result.diagnostic_class == "post_settlement_proof_required"

@patch.object(LnChurchClient, "execute_detailed")
def test_run_x402_svm_exact_sandbox_diagnostic_expected_rejection_ok(mock_execute):
    """予期せぬエラー(500)等の場合は ok=False になること"""
    mock_execute.side_effect = Exception("API Error 500: Internal Server Error")
    
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    result = client.run_x402_svm_exact_sandbox_diagnostic()
    
    assert result.ok is False
    assert result.expected_rejection is False
    assert result.diagnostic_class is None

@patch.object(LnChurchClient, "execute_detailed")
def test_run_x402_evm_exact_sandbox_diagnostic_expected_rejection_ok(mock_execute):
    """予期せぬエラーの場合はEVNでも ok=False になること"""
    mock_execute.side_effect = Exception("API Error 400: Bad Request")
    
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    result = client.run_x402_evm_exact_sandbox_diagnostic()
    
    assert result.ok is False
    assert result.expected_rejection is False

# ==========================================
# 4. External Observation Client Tests
# ==========================================
@patch.object(LnChurchClient, "execute_request")
def test_submit_external_observation_payload_shape(mock_request):
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    
    protocol_data = {"rail": "x402", "draft_shape": "x402-v2-exact-svm"}
    evidence_data = {"verification_status": "self_reported"}
    
    client.submit_external_observation(
        target_url="https://api.external.com",
        protocol=protocol_data,
        evidence=evidence_data
    )
    
    args, kwargs = mock_request.call_args
    payload = kwargs["payload"]
    
    assert payload["targetUrl"] == "https://api.external.com"
    assert payload["source_scope"] == "external_agent_report"
    assert payload["protocol"] == protocol_data
    assert payload["evidence"] == evidence_data
    assert "sdk_version" in payload

@patch.object(LnChurchClient, "execute_request")
def test_get_external_observations_filters(mock_request):
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    
    client.get_external_observations(limit=20, rail="L402", quality="strong")
    
    args, kwargs = mock_request.call_args
    payload = kwargs["payload"]
    
    assert payload["limit"] == 20
    assert payload["rail"] == "L402"
    assert payload["quality"] == "strong"

@patch.object(LnChurchClient, "execute_request")
def test_external_observation_does_not_send_raw_secret(mock_request):
    """Raw Secret (preimage, macaroon 等) がサーバー送信前にローカルでストリップされること"""
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    
    evidence_data = {
        "verification_status": "self_reported",
        "proof_reference": "safe_hash_123",
        "preimage": "RAW_SECRET_PREIMAGE",
        "macaroon": "RAW_SECRET_MACAROON",
        "PRIVATE_KEY": "RAW_SECRET_KEY"
    }
    
    client.submit_external_observation(
        target_url="https://api.external.com",
        evidence=evidence_data
    )
    
    args, kwargs = mock_request.call_args
    sent_evidence = kwargs["payload"]["evidence"]
    
    assert "verification_status" in sent_evidence
    assert "proof_reference" in sent_evidence
    # 以下はストリップされているはず
    assert "preimage" not in sent_evidence
    assert "macaroon" not in sent_evidence
    assert "PRIVATE_KEY" not in sent_evidence