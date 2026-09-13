import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from ln_church_agent.client import LnChurchClient, SURFACE_PREFLIGHT_SCHEMA_VERSION


def make_valid_response(known=True):
    return {
        'schema_version': SURFACE_PREFLIGHT_SCHEMA_VERSION,
        'not_a_recommendation': True, 'not_a_verdict': True, 'surface': {'known': known},
        'guardrails': {'final_authority': 'local_runtime',
                       'this_read_model_does_not_execute_payments': True,
                       'this_read_model_does_not_prove_settlement': True},
    }


@pytest.fixture(params=[False, True], ids=['sync', 'async'])
def preflight(request):
    client = LnChurchClient(base_url='https://api.test')
    response = MagicMock(status_code=200)
    target = 'httpx.AsyncClient.get' if request.param else 'requests.get'
    with patch(target, new_callable=AsyncMock if request.param else MagicMock, return_value=response) as transport, \
         patch.object(client, 'execute_request', side_effect=AssertionError('purchase')), \
         patch.object(client, 'execute_request_async', side_effect=AssertionError('purchase')):
        def invoke(**kwargs):
            if request.param:
                return asyncio.run(client.get_surface_preflight_async(**kwargs))
            return client.get_surface_preflight(**kwargs)
        yield invoke, response, transport


@pytest.mark.parametrize('locator, expected', [
    ({'surface_key': 'surface_0123456789abcdef01234567'}, {'surface_key': '0123456789abcdef01234567'}),
    ({'target_url': 'https://api.example.com', 'method': 'post', 'rail': 'x402'},
     {'target_url': 'https://api.example.com', 'method': 'POST', 'rail': 'x402', 'network': 'unknown',
      'asset': 'unknown', 'authorization_scheme': 'unknown', 'draft_shape': 'unknown'}),
])
@pytest.mark.parametrize('known', [False, True])
def test_preflight_locator_and_public_read(preflight, locator, expected, known):
    invoke, response, transport = preflight
    response.json.return_value = make_valid_response(known)
    assert invoke(**locator) == make_valid_response(known)
    assert transport.call_count == 1
    assert transport.call_args.kwargs['params'] == expected
    assert transport.call_args.args[0] == 'https://api.test/api/agent/monzen/surface-preflight'


@pytest.mark.parametrize('kwargs, message', [
    ({}, 'Either surface_key or target_url must be provided'),
    ({'surface_key': 'abc', 'target_url': 'http'}, 'Provide either'),
    ({'surface_key': 'invalid_hex_string'}, '24-character hex'),
    ({'target_url': '   '}, 'target_url cannot be empty'),
])
def test_preflight_invalid_locator_has_no_io(preflight, kwargs, message):
    invoke, _, transport = preflight
    with pytest.raises(ValueError, match=message):
        invoke(**kwargs)
    transport.assert_not_called()


@pytest.mark.parametrize('path, value, message', [
    (('schema_version',), 'wrong.v1', 'Invalid schema_version'),
    (('not_a_recommendation',), None, 'not_a_recommendation'),
    (('not_a_verdict',), None, 'not_a_verdict'),
    (('guardrails', 'final_authority'), 'server_enforced', 'final_authority must be local_runtime'),
    (('guardrails', 'this_read_model_does_not_execute_payments'), False, 'must not execute payments'),
    (('guardrails', 'this_read_model_does_not_prove_settlement'), None, 'must not prove settlement'),
])
def test_preflight_semantic_flags(preflight, path, value, message):
    invoke, response, _ = preflight
    data = make_valid_response()
    container = data if len(path) == 1 else data[path[0]]
    if value is None:
        container.pop(path[-1])
    else:
        container[path[-1]] = value
    response.json.return_value = data
    with pytest.raises(ValueError, match=message):
        invoke(surface_key='0123456789abcdef01234567')


def test_internal_surface_key_derivation():
    from ln_church_agent.client import _derive_surface_key
    key = _derive_surface_key(target_url='https://api.example.com/endpoint?volatile=ignore', method='GET', rail='x402')
    assert len(key) == 24
