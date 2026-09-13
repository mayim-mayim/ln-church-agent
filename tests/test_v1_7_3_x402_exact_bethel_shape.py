import asyncio
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

@pytest.mark.parametrize('async_mode', [False, True])
@pytest.mark.parametrize('rail', ['evm', 'svm'])
@pytest.mark.parametrize('failure', ['invalid_proof', 'Transaction not found', 'API Error 500: Internal Server Error', None])
def test_exact_diagnostic_result_classification(async_mode, rail, failure):
    client = LnChurchClient(base_url='https://api.test')
    client._last_parsed_challenge = MagicMock(network='test-network', asset='USDC',
        draft_shape='x402-v2-exact', parameters={'token_address': 'test-token'})
    if failure == 'invalid_proof':
        failure = 'Invalid TxHash format' if rail == 'evm' else 'Invalid Solana signature format'
    expected = failure is not None and 'Internal Server Error' not in failure
    suffix = '_async' if async_mode else ''
    with patch.object(client, 'execute_detailed' + suffix, side_effect=Exception(failure) if failure else None) as execute:
        method = getattr(client, 'run_x402_' + rail + '_exact_sandbox_diagnostic' + suffix)
        result = asyncio.run(method()) if async_mode else method()
    assert result.ok == expected and result.expected_rejection == expected
    assert result.rejection_reason == failure
    assert result.diagnostic_class == ('post_settlement_proof_required' if expected else None)
    assert result.failure_class == ('settlement_model_mismatch' if expected else None)
    assert result.network == 'test-network' and result.token_address == 'test-token'
    assert execute.call_count == 1
    assert execute.call_args.args == ('GET', f'/api/agent/sandbox/x402/{rail}/exact/basic')
    assert execute.call_args.kwargs == ({'payload': {'asset': 'USDC'}} if rail == 'evm' else {})


@pytest.mark.parametrize('async_mode', [False, True])
def test_external_observation_payload_preserves_metadata_without_secrets(async_mode):
    client = LnChurchClient(base_url='https://api.test')
    protocol = {'rail': 'x402', 'draft_shape': 'x402-v2-exact-svm'}
    evidence = {'verification_status': 'self_reported', 'proof_reference': 'safe_hash_123',
                'preimage': 'secret', 'macaroon': 'secret', 'PRIVATE_KEY': 'secret'}
    suffix = '_async' if async_mode else ''
    with patch.object(client, 'execute_request' + suffix, return_value={}) as execute:
        method = getattr(client, 'submit_external_observation' + suffix)
        kwargs = dict(target_url='https://api.external.com', protocol=protocol, evidence=evidence)
        asyncio.run(method(**kwargs)) if async_mode else method(**kwargs)
    payload = execute.call_args.kwargs['payload']
    assert payload['targetUrl'] == 'https://api.external.com'
    assert payload['source_scope'] == 'external_agent_report'
    assert payload['protocol'] == protocol and 'sdk_version' in payload
    assert payload['evidence'] == {'verification_status': 'self_reported', 'proof_reference': 'safe_hash_123'}
    assert evidence['preimage'] == 'secret'


@pytest.mark.parametrize('async_mode', [False, True])
def test_external_observation_filters(async_mode):
    client = LnChurchClient(base_url='https://api.test')
    suffix = '_async' if async_mode else ''
    with patch.object(client, 'execute_request' + suffix, return_value={}) as execute:
        method = getattr(client, 'get_external_observations' + suffix)
        asyncio.run(method(limit=20, rail='L402', quality='strong')) if async_mode else method(limit=20, rail='L402', quality='strong')
    assert execute.call_args.kwargs['payload'] == {'limit': 20, 'rail': 'L402', 'quality': 'strong'}


@pytest.mark.parametrize('async_mode', [False, True])
@pytest.mark.parametrize('failure, stage, origin', [
    (None, None, 'unknown'),
    ('LNBits Payment Failed Error code 502', 'payment_initiation', 'payment_backend'),
    ('payment initiated but not settled', 'payment_settlement_check', 'payment_backend'),
    ('invalid 402 challenge', 'challenge_parse', 'target_endpoint'),
])
def test_external_protocol_diagnostic_result_selection(async_mode, failure, stage, origin):
    from ln_church_agent.models import ExecutionResult
    client = LnChurchClient(base_url='https://api.test')
    fetched = ExecutionResult(response={'data': 'read'}, final_url='https://target.test')
    suffix = '_async' if async_mode else ''
    with patch.object(client, 'execute_detailed' + suffix, return_value=fetched,
                      side_effect=RuntimeError(failure) if failure else None):
        method = getattr(client, 'run_external_protocol_verification' + suffix)
        result = asyncio.run(method('https://target.test')) if async_mode else method('https://target.test')
    assert result.ok == (failure is None)
    assert result.error_stage == stage and result.suspected_failure_origin == origin
    assert result.status_code_after_payment == (200 if failure is None else 502 if '502' in failure else 500)
    assert result.payment_performed == (origin == 'payment_backend')
