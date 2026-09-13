import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from ln_church_agent.client import LnChurchClient


@pytest.mark.parametrize('async_mode', [False, True])
@pytest.mark.parametrize('outcome', [None, {'satisfaction_level': 'full', 'goal_achieved': True}])
def test_explicit_goal_observation_preserves_unassessed_and_public_metadata(async_mode, outcome):
    client = LnChurchClient(base_url='https://api.test')
    public = {
        'authorization_scheme': 'x402', 'payment_performed': False,
        'payment_receipt_present': False, 'selected_requirement_fingerprint': 'abc123',
        'raw_requirement_fingerprint': 'def456', 'surface_key': 'paid:example',
        'surface_type': 'paid_surface',
    }
    secrets = {'authorization': 'Bearer secret', 'preimage': 'secret', 'private_key': 'secret',
               'grant_token': 'secret', 'headers': {'Authorization': 'secret'}}
    kwargs = dict(goal={'goal_text': 'Assess endpoint'},
                  attempt={'attempt_mode': 'free', 'completion_status': 'partial_success'},
                  steps=[dict(public, **secrets)], evidence=dict(public, **secrets), outcome=outcome)
    target = 'execute_request_async' if async_mode else 'execute_request'
    with patch.object(client, target, return_value={'status': 'accepted'}) as execute:
        response = (
            asyncio.run(client.submit_goal_attempt_observation_async(**kwargs))
            if async_mode else client.submit_goal_attempt_observation(**kwargs)
        )
    assert execute.call_args.args == ('POST', '/api/agent/external/attempt/observe')
    payload = execute.call_args.kwargs['payload']
    assert payload['schema_version'] == 'goal_attempt.v1'
    assert payload['attempt']['attempt_mode'] == 'free'
    assert payload['evidence'] == public and payload['steps'] == [public]
    assert ('outcome' in payload) == (outcome is not None)
    if outcome is not None:
        assert payload['outcome'] == outcome
    assert response['status'] == 'accepted'
    assert kwargs['evidence']['private_key'] == 'secret'


@pytest.mark.parametrize('async_mode', [False, True])
def test_goal_observation_defaults(async_mode):
    client = LnChurchClient(base_url='https://api.test')
    name = 'execute_request_async' if async_mode else 'execute_request'
    with patch.object(client, name, return_value={}) as execute:
        kwargs = dict(goal={}, attempt={})
        if async_mode:
            asyncio.run(client.submit_goal_attempt_observation_async(**kwargs))
        else:
            client.submit_goal_attempt_observation(**kwargs)
    payload = execute.call_args.kwargs['payload']
    assert payload['steps'] == [] and payload['evidence'] == {} and 'outcome' not in payload


@pytest.mark.parametrize('async_mode', [False, True])
def test_normal_execution_has_no_observation_or_verification_hook(async_mode):
    client = LnChurchClient(base_url='https://api.test')
    response = MagicMock(status_code=200, content=b'{}', headers={})
    response.json.return_value = {'status': 'success'}
    name = 'httpx.AsyncClient.request' if async_mode else 'requests.request'
    with patch(name, new_callable=AsyncMock if async_mode else MagicMock, return_value=response) as transport:
        if async_mode:
            async def run():
                try:
                    return await client.execute_request_async('POST', '/api/v1/resource', {'test': 'data'})
                finally:
                    await client.aclose()
            asyncio.run(run())
        else:
            client.execute_request('POST', '/api/v1/resource', {'test': 'data'})
    assert transport.call_count == 1
    assert transport.call_args.args[1] == 'https://api.test/api/v1/resource'
