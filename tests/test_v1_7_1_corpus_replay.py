# tests/test_v1_7_1_corpus_replay.py
import pytest
import asyncio
from unittest.mock import patch, MagicMock
from ln_church_agent.client import LnChurchClient

# ★ 本物の requests.Response に似せた安全なモックを作るヘルパー
def _make_mock_res(status_code, json_data, headers=None, url="http://mock/url"):
    res = MagicMock()
    res.status_code = status_code
    res.headers = headers or {}
    res.json.return_value = json_data
    import json
    res.content = json.dumps(json_data).encode('utf-8')
    res.url = url
    return res

def test_dry_run_false_raises():
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    with pytest.raises(NotImplementedError):
        client.run_corpus_replay("corp_123", dry_run=False)

@patch("requests.get")
def test_corpus_replay_strong_pay_and_verify(mock_get):
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")

    desc_res = _make_mock_res(200, {
        "replay_type": "synthetic_from_corpus_v1",
        "expected_client_behavior": {"action": "pay_and_verify"},
        "endpoints": {"challenge": "/api/agent/benchmark/replay/corp_strong/challenge"}
    })
    
    chal_res = _make_mock_res(402, 
        {"expected_client_behavior": {"action": "pay_and_verify"}},
        {"WWW-Authenticate": 'L402 macaroon="mac", invoice="inv"'}
    )
    
    mock_get.side_effect = [desc_res, chal_res]

    res = client.run_corpus_replay("corp_strong")
    assert res.ok is True
    assert res.replay_type == "synthetic_from_corpus_v1"
    assert res.observed_action == "pay_and_verify"
    assert res.parsed_scheme == "L402"

@patch("requests.get")
def test_corpus_replay_session_stop_safely(mock_get):
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")

    desc_res = _make_mock_res(200, {
        "expected_client_behavior": {"action": "stop_safely"},
        "endpoints": {"challenge": "/challenge"}
    })
    
    chal_res = _make_mock_res(402, 
        {"expected_client_behavior": {"action": "stop_safely"}},
        {"WWW-Authenticate": 'MPP invoice="inv", intent="session"'}
    )
    
    mock_get.side_effect = [desc_res, chal_res]

    res = client.run_corpus_replay("corp_session")
    assert res.ok is True
    assert res.observed_action == "stop_safely"

@patch("requests.get")
def test_corpus_replay_invalid_reject(mock_get):
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")

    desc_res = _make_mock_res(200, {
        "expected_client_behavior": {"action": "reject_invalid"}, 
        "endpoints": {"challenge": "/challenge"}
    })
    
    chal_res = _make_mock_res(422, {"expected_client_behavior": {"action": "reject_invalid"}})
    
    mock_get.side_effect = [desc_res, chal_res]

    res = client.run_corpus_replay("corp_invalid")
    assert res.ok is True
    assert res.observed_action == "reject_invalid"

@patch("requests.get")
def test_corpus_replay_weak_observe_only(mock_get):
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")

    desc_res = _make_mock_res(200, {
        "expected_client_behavior": {"action": "observe_only"}, 
        "endpoints": {"challenge": "/challenge"}
    })
    
    chal_res = _make_mock_res(402, 
        {"expected_client_behavior": {"action": "observe_only"}},
        {"WWW-Authenticate": 'UnknownScheme param="123"'}
    )
    
    mock_get.side_effect = [desc_res, chal_res]

    res = client.run_corpus_replay("corp_weak")
    assert res.ok is True
    assert res.observed_action == "observe_only"

@patch("requests.get")
def test_corpus_replay_unreachable(mock_get):
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    
    mock_get.side_effect = Exception("Connection Refused")
    res = client.run_corpus_replay("corp_unreachable")
    assert res.ok is False
    assert "fetch failed" in res.failure_reason

@patch("httpx.AsyncClient.get")
def test_corpus_replay_async_strong_pay_and_verify(mock_get):
    client = LnChurchClient(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")

    class MockResponse:
        def __init__(self, status_code, json_data, headers=None):
            self.status_code = status_code
            self._json_data = json_data
            self.headers = headers or {}
            self.url = "http://mock/challenge" # ★ ここにも安全のためURLを追加
        def json(self):
            return self._json_data

    desc_res = MockResponse(200, {
        "replay_type": "synthetic_from_corpus_v1",
        "expected_client_behavior": {"action": "pay_and_verify"},
        "endpoints": {"challenge": "/api/agent/benchmark/replay/corp_strong_async/challenge"}
    })
    
    chal_res = MockResponse(402, 
        json_data={"expected_client_behavior": {"action": "pay_and_verify"}},
        headers={"WWW-Authenticate": 'L402 macaroon="mac", invoice="inv"'}
    )

    async def mock_get_side_effect(url, *args, **kwargs):
        if "challenge" in str(url):
            return chal_res
        return desc_res
        
    mock_get.side_effect = mock_get_side_effect

    async def run_test():
        res = await client.run_corpus_replay_async("corp_strong_async")
        assert res.ok is True
        assert res.replay_type == "synthetic_from_corpus_v1"
        assert res.observed_action == "pay_and_verify"
        assert res.parsed_scheme == "L402"

    asyncio.run(run_test())