import pytest
import json
from unittest.mock import patch, MagicMock
from ln_church_agent.cli import inspect_url

@patch("ln_church_agent.cli.requests.request")
def test_requests_to_httpx_strips_content_encoding(mock_req):
    """
    requestsがデコード済みであるにも関わらず 'Content-Encoding: gzip' が残っているレスポンスでも、
    httpx変換時にエラーにならず、正しくパースされることを確認
    """
    mock_res = MagicMock()
    mock_res.status_code = 402
    
    payload = {
        "accepts": [{"scheme": "exact", "network": "eip155:196", "payTo": "0xABC"}]
    }
    
    mock_res.headers = {
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
        "Content-Length": "999"
    }
    # requests によって展開済みの生の JSON bytes になっている想定
    mock_res.content = json.dumps(payload).encode()
    mock_res.json.return_value = payload
    mock_res.url = "http://test.local"
    mock_req.return_value = mock_res

    res = inspect_url("http://test.local")
    
    assert res.ok is True
    assert "x402" in res.rails_detected
    assert res.diagnostic_class == "post_settlement_proof_required"


@patch("ln_church_agent.cli._requests_to_httpx_response")
@patch("ln_church_agent.cli.requests.request")
def test_requests_to_httpx_conversion_error_returns_structured_diagnostic(mock_req, mock_adapter):
    """
    httpxへの変換で予期せぬ例外（httpx.DecodingErrorなど）が発生した場合に、
    InspectResultとして構造化して返すことを確認
    """
    mock_res = MagicMock(status_code=402, url="http://test.local")
    mock_req.return_value = mock_res
    
    # 変換時にクラッシュさせる
    mock_adapter.side_effect = Exception("incorrect header check")

    res = inspect_url("http://test.local")
    
    assert res.ok is True  # 402は見えているため True とする
    assert res.recommended_action == "observe_only"
    assert res.error_stage == "response_adapter"
    assert res.diagnostic_class == "response_decoding_error"
    assert res.failure_class == "requests_to_httpx_conversion_failed"
    assert "incorrect header check" in res.failure_reason

@patch("ln_church_agent.cli._requests_to_httpx_response")
@patch("ln_church_agent.cli.requests.request")
def test_requests_to_httpx_conversion_error_non_402(mock_req, mock_adapter):
    """
    402以外のステータス（200 OK等）で変換に失敗した場合は stop_safely になることを確認
    """
    mock_res = MagicMock(status_code=200, url="http://test.local")
    mock_req.return_value = mock_res
    mock_adapter.side_effect = Exception("some random error")

    res = inspect_url("http://test.local")
    
    assert res.ok is False  # 402ではないので False
    assert res.recommended_action == "stop_safely"
    assert res.error_stage == "response_adapter"
    assert res.diagnostic_class == "response_decoding_error"