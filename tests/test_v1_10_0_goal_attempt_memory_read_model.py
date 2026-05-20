import pytest
import asyncio
from unittest.mock import patch, MagicMock
from ln_church_agent.client import LnChurchClient
from ln_church_agent.models import AssetType

def test_get_goal_attempt_summary_builds_correct_request():
    client = LnChurchClient(private_key="0x" + "0"*64)
    with patch.object(client, "execute_request", return_value={"status": "ok"}) as mock_exec:
        res = client.get_goal_attempt_summary(goal_type="tx_investigation", limit=50)
        
    args, kwargs = mock_exec.call_args
    assert args[0] == "GET"
    assert args[1] == "/api/agent/monzen/goal-attempts/summary"
    assert kwargs["payload"]["goal_type"] == "tx_investigation"
    assert kwargs["payload"]["include_unassessed"] == "true"
    assert kwargs["payload"]["limit"] == 50

def test_get_goal_surface_candidates_negotiates_402():
    client = LnChurchClient(private_key="0x" + "0"*64)
    mock_result = MagicMock()
    mock_result.response = {"status": "ok", "candidate_groups": []}
    
    with patch.object(client, "execute_detailed", return_value=mock_result) as mock_detailed:
        res = client.get_goal_surface_candidates(goal_type="audit", prefer_free_first=False, asset=AssetType.USDC, scheme="x402")
        
    args, kwargs = mock_detailed.call_args
    assert args[0] == "GET"
    assert args[1] == "/api/agent/monzen/goal-attempts/candidates"
    payload = kwargs["payload"]
    assert payload["goal_type"] == "audit"
    assert payload["prefer_free_first"] == "false"
    assert payload["asset"] == "USDC"
    assert payload["scheme"] == "x402"
    assert "candidate_groups" in res

def test_no_automatic_hook_into_execution_paths():
    client = LnChurchClient(private_key="0x" + "0"*64)
    with patch("requests.request") as mock_req:
        mock_resp = MagicMock(status_code=200, content=b'{"status":"success"}')
        mock_resp.json.return_value = {"status": "success"}
        mock_req.return_value = mock_resp
        
        client.execute_request("POST", "/api/v1/dummy")
        assert mock_req.call_count == 1
        # 通常実行パスが勝手にread modelエンドポイントにフック通信しないことを担保
        assert "/goal-attempts/" not in mock_req.call_args[0][1]