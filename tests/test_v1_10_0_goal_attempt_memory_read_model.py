import asyncio
import json
from urllib.parse import parse_qs, urlsplit
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import requests

from ln_church_agent.client import LnChurchClient
from ln_church_agent.exceptions import PaymentExecutionError
from ln_church_agent.models import AssetType


@pytest.mark.parametrize('async_mode', [False, True])
@pytest.mark.parametrize('status', [200, 302, 402, 404, 500])
def test_summary_uses_one_free_get_and_keeps_query_status(async_mode, status):
    client = LnChurchClient(base_url='https://api.test')
    body = {'status': 'ok', 'message': 'read failed', 'next_action': {'url': '/purchase', 'method': 'GET'}}
    if async_mode:
        response = httpx.Response(status, json=body, request=httpx.Request('GET', 'https://api.test'))
        target, mock_type = 'httpx.AsyncClient.request', AsyncMock
    else:
        response = requests.Response()
        response.status_code = status
        response._content = json.dumps(body).encode()
        target, mock_type = 'requests.request', MagicMock
    with patch(target, new_callable=mock_type, return_value=response) as transport, \
         patch.object(client, '_process_payment', side_effect=AssertionError('payment')), \
         patch.object(client, '_restore_session_spend_from_evidence', side_effect=AssertionError('budget')), \
         patch.object(client, '_restore_session_spend_from_evidence_async', side_effect=AssertionError('budget')):
        def invoke():
            kwargs = dict(goal_type='tx_investigation', domain_hint='query?a=b', include_unassessed=False, limit=50)
            if async_mode:
                async def run():
                    try:
                        return await client.get_goal_attempt_summary_async(**kwargs)
                    finally:
                        await client.aclose()
                return asyncio.run(run())
            return client.get_goal_attempt_summary(**kwargs)
        if status == 200:
            assert invoke() == body
        else:
            with pytest.raises(PaymentExecutionError, match=f'API Error {status}:') as caught:
                invoke()
            assert caught.value.status_code == status
    assert transport.call_count == 1
    args, kwargs = transport.call_args
    assert args[0] == 'GET'
    url = urlsplit(args[1])
    assert url.path == '/api/agent/monzen/goal-attempts/summary'
    assert parse_qs(url.query) == {
        'include_unassessed': ['false'], 'limit': ['50'],
        'goal_type': ['tx_investigation'], 'domain_hint': ['query?a=b'], 'agentId': [client.agent_id],
    }
    assert kwargs['params'] is None
    assert kwargs['follow_redirects' if async_mode else 'allow_redirects'] is False


@pytest.mark.parametrize('async_mode', [False, True])
def test_candidates_still_use_explicit_purchase_driver(async_mode):
    client = LnChurchClient(base_url='https://api.test')
    result = MagicMock(response={'status': 'ok', 'candidate_groups': []})
    name = 'execute_detailed_async' if async_mode else 'execute_detailed'
    with patch.object(client, name, return_value=result) as execute:
        kwargs = dict(goal_type='audit', prefer_free_first=False, asset=AssetType.USDC, scheme='x402')
        response = (
            asyncio.run(client.get_goal_surface_candidates_async(**kwargs))
            if async_mode else client.get_goal_surface_candidates(**kwargs)
        )
    assert execute.call_args.args == ('GET', '/api/agent/monzen/goal-attempts/candidates')
    payload = execute.call_args.kwargs['payload']
    assert payload['goal_type'] == 'audit'
    assert payload['prefer_free_first'] == 'false'
    assert payload['asset'] == 'USDC' and payload['scheme'] == 'x402'
    assert 'candidate_groups' in response
