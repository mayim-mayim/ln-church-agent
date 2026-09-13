import asyncio
import time
from unittest.mock import patch

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from ln_church_agent.client import LnChurchClient


@pytest.mark.parametrize('async_mode', [False, True])
def test_reporter_signature_cache_and_force_refresh(async_mode):
    private_key = '0x' + '1' * 64
    client = LnChurchClient(base_url='https://api.test', private_key=private_key)
    challenge = {'challenge_id': 'chal_123', 'message': 'LN Church Reporter Verification'}
    verified = {'status': 'verified', 'verified_until': int(time.time() * 1000) + 600000, 'proof_id': 'proof_123'}
    suffix = '_async' if async_mode else ''
    with patch.object(client, 'execute_request' + suffix, side_effect=[challenge, verified, challenge, verified]) as execute:
        method = getattr(client, 'ensure_reporter_verification' + suffix)
        def invoke(**kwargs):
            return asyncio.run(method(**kwargs)) if async_mode else method(**kwargs)
        assert invoke() == verified
        cached = invoke()
        assert cached['status'] == 'cached' and cached['proof_id'] == 'proof_123'
        assert execute.call_count == 2
        assert invoke(force_refresh=True) == verified
    assert execute.call_count == 4
    payload = execute.call_args_list[1].kwargs['payload']
    assert payload['challenge_id'] == 'chal_123' and payload['schema_version'] == 'agent_identity_verify.v1'
    recovered = Account.recover_message(
        encode_defunct(text=challenge['message']), signature=payload['signature']
    )
    assert recovered == Account.from_key(private_key).address


@pytest.mark.parametrize('async_mode', [False, True])
@pytest.mark.parametrize('kind, message', [('solana', "Only 'evm'"), ('evm', 'EVM private_key is strictly required')])
def test_reporter_rejects_unsupported_or_missing_key_before_io(async_mode, kind, message):
    client = LnChurchClient(base_url='https://api.test')
    suffix = '_async' if async_mode else ''
    with patch.object(client, 'execute_request' + suffix) as execute:
        method = getattr(client, 'ensure_reporter_verification' + suffix)
        with pytest.raises(ValueError, match=message):
            asyncio.run(method(public_key_type=kind)) if async_mode else method(public_key_type=kind)
    execute.assert_not_called()
