import pytest
import json
import base64
import httpx
from unittest.mock import patch, MagicMock

from ln_church_agent.cli import inspect_url, _extract_settlement_options
from ln_church_agent.challenges import parse_challenge_from_response
from ln_church_agent.integrations.mcp_inspect import build_mcp_observation_payload
from ln_church_agent.failures import fingerprint_public_challenge_summary

def _create_mock_402(payload: dict) -> httpx.Response:
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    return httpx.Response(402, headers={"PAYMENT-REQUIRED": b64_str})

# ==========================================
# A. x402 accepts[] 複数候補の全列挙テスト
# ==========================================
@patch("ln_church_agent.inspect_transport._exchange_once")
def test_accepts_array_multiple_options_extracted(mock_req):
    payload = {
        "accepts": [
            {"scheme": "exact", "network": "eip155:137", "asset": "USDC", "amount": "100"},
            {"scheme": "exact", "network": "eip155:8453", "asset": "USDC", "amount": "100"},
            {"scheme": "exact", "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "asset": "USDC", "amount": "100"}
        ]
    }
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"PAYMENT-REQUIRED": base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')}
    mock_res.content = b""
    mock_res.url = "http://public.example"
    mock_req.return_value = mock_res

    res = inspect_url("http://public.example")
    
    assert res.ok is True
    # 候補がすべて観測されているか
    assert len(res.settlement_options) == 3
    
    # Chain Family の推測が正しいか
    assert res.settlement_options[0].chain_family == "evm"
    assert res.settlement_options[1].chain_family == "evm"
    assert res.settlement_options[2].chain_family == "svm"
    
    # 選択されたオプションがデフォルト(先頭)であること
    assert res.selected_settlement_option is not None
    assert res.selected_settlement_option.network == "eip155:137"
    assert res.selected_settlement_option.selected is True
    
    # LN Church Observatory のメタデータが付随していること
    assert res.ln_church_observatory is not None
    assert res.ln_church_observatory.submitted is False

# ==========================================
# B. allowed_networks による選択テスト
# ==========================================
def test_allowed_networks_selection_reason():
    payload = {
        "accepts": [
            {"scheme": "exact", "network": "eip155:137", "asset": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", "amount": "100"},
            {"scheme": "exact", "network": "eip155:8453", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "amount": "100"}
        ]
    }
    res_mock = _create_mock_402(payload)
    
    # ポリシー（allowed_networks）を適用してパース
    parsed = parse_challenge_from_response(res_mock, allowed_networks=["eip155:8453"])
    opts, sel = _extract_settlement_options(parsed)
    
    assert len(opts) == 2
    assert sel is not None
    assert sel.network == "eip155:8453"
    # 💡 修正: valid_accepts[0] として拾われるため first_acceptable となる
    assert sel.selection_reason == "first_acceptable"
    
    assert opts[0].selected is False
    assert opts[1].selected is True

# ==========================================
# C. prefer_svm による Solana 優先テスト
# ==========================================
def test_prefer_svm_selection_reason():
    payload = {
        "accepts": [
            {"scheme": "exact", "network": "eip155:137", "asset": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", "amount": "100"},
            {"scheme": "exact", "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "amount": "100"}
        ]
    }
    res_mock = _create_mock_402(payload)
    
    parsed = parse_challenge_from_response(res_mock, prefer_svm=True)
    opts, sel = _extract_settlement_options(parsed)
    
    assert len(opts) == 2
    assert sel is not None
    assert sel.network.startswith("solana:")
    assert sel.chain_family == "svm"
    assert sel.selection_reason == "prefer_svm"
    
    assert opts[0].network == "eip155:137"
    assert opts[0].selected is False

# ==========================================
# D. MCP observation payload の network / asset 継承テスト
# ==========================================
def test_mcp_observation_payload_network_asset_inherited():
    fake_inspect_result = {
        "url": "http://public.example",
        "method": "GET",
        "status_code": 402,
        "settlement_rails_detected": ["x402"],
        "selected_settlement_option": {
            "network": "eip155:8453",
            "asset": "USDC",
            "rail": "x402"
        },
        "settlement_options": [
            {"network": "eip155:8453", "asset": "USDC", "rail": "x402", "selected": True}
        ]
    }
    
    payload = build_mcp_observation_payload(fake_inspect_result)
    
    assert payload["protocol"]["network"] == "eip155:8453"
    assert payload["protocol"]["asset"] == "USDC"
    # 💡 Nice to have: トップレベルに配置したことの確認
    assert "settlement_options_summary" in payload

# ==========================================
# E. APP/AP2/ACP inspect-only safety test
# ==========================================
@patch("ln_church_agent.inspect_transport._exchange_once")
def test_app_ap2_acp_inspect_only_safety(mock_req):
    mock_res = MagicMock()
    mock_res.status_code = 402
    mock_res.headers = {"Content-Type": "application/json"}
    
    payload = {"protocol": "ap2", "intent": "payment_mandate"}
    mock_res.json.return_value = payload
    mock_res.content = json.dumps(payload).encode()
    mock_res.url = "http://public.example"
    mock_req.return_value = mock_res

    res = inspect_url("http://public.example")
    
    assert res.ok is True
    assert "AP2" in res.surfaces_detected
    assert res.recommended_action == "observe_only"
    assert res.will_execute_payment is False
    
    assert len(res.settlement_options) == 0
    assert res.selected_settlement_option is None
    
    assert "settlement_rail_not_declared" in res.missing_information
    assert "network_not_declared" in res.missing_information

# ==========================================
# F. Redaction safety test
# ==========================================
def test_redaction_safety():
    unsafe_req = {
        "scheme": "exact",
        "network": "eip155:137",
        "amount": "100",
        "macaroon": "super_secret_macaroon",
        "preimage": "super_secret_preimage",
        "extra": {"feePayer": "0xABC"}
    }
    
    safe_req = {
        "scheme": "exact",
        "network": "eip155:137",
        "amount": "100",
        "extra": {"feePayer": "0xABC"}
    }
    
    fp_unsafe = fingerprint_public_challenge_summary(unsafe_req)
    fp_safe = fingerprint_public_challenge_summary(safe_req)
    
    assert fp_unsafe == fp_safe

# ==========================================
# 1. allowed_networks に一致候補がない場合、先頭候補へ落ちないことのテスト
# ==========================================
def test_allowed_networks_no_match():
    payload = {
        "accepts": [
            {"scheme": "exact", "network": "eip155:137", "asset": "USDC", "amount": "100"},
            {"scheme": "exact", "network": "solana:1234", "asset": "USDC", "amount": "100"}
        ]
    }
    res_mock = _create_mock_402(payload)
    
    parsed = parse_challenge_from_response(res_mock, allowed_networks=["eip155:8453"])
    opts, sel = _extract_settlement_options(parsed)
    
    assert len(opts) == 2
    assert sel is None  # 💡 決して opts[0] にフォールバックしてはならない
    
    assert opts[0].selected is False
    assert opts[1].selected is False
    # 💡 修正: no_allowed_network_match が各オプションにも伝播していること
    assert opts[0].selection_reason == "no_allowed_network_match"

# ==========================================
# 2. x402 実例寄りフィールド (maxAmountRequired, mint) の反映テスト
# ==========================================
def test_x402_real_world_fields():
    payload = {
        "accepts": [
            {
                "scheme": "exact", 
                "network": "solana:1234", 
                "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "maxAmountRequired": "500000"
            }
        ]
    }
    res_mock = _create_mock_402(payload)
    parsed = parse_challenge_from_response(res_mock)
    opts, sel = _extract_settlement_options(parsed)
    
    assert len(opts) == 1
    assert opts[0].asset == "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    assert opts[0].amount == "REDACTED"

# ==========================================
# 3. execution_support が「SDK対応」と「inspectでは実行しない」を区別していることのテスト
# ==========================================
def test_execution_support_clarification():
    payload = {
        "accepts": [
            {"scheme": "exact", "network": "eip155:137"},         # V2 exact (Post-settlement)
            {"scheme": "x402", "network": "eip155:8453"},         # V1 standard EVM
            {"scheme": "x402", "network": "unknown_chain:123"}    # 全く未知のチェーン
        ]
    }
    res_mock = _create_mock_402(payload)
    parsed = parse_challenge_from_response(res_mock)
    opts, sel = _extract_settlement_options(parsed)
    
    assert opts[0].execution_support == "observe_only"
    assert opts[1].execution_support == "supported_but_not_executed_in_inspect"
    assert opts[2].execution_support == "unsupported"
