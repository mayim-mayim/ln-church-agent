import pytest
import base64
import json
import httpx
from unittest.mock import patch, MagicMock

from ln_church_agent.client import Payment402Client
from ln_church_agent.challenges import parse_challenge_from_response
from ln_church_agent.models import ChallengeSource

def _create_mock_response(headers):
    return httpx.Response(402, headers=headers)

def test_1_payment_required_beats_www_authenticate_x402():
    client = Payment402Client()
    payload = {
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": "USDC",
                "amount": "1000",
                "payTo": "0xABC"
            }
        ]
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    
    res = _create_mock_response({
        "WWW-Authenticate": 'x402 macaroon="mac", invoice="inv"',
        "PAYMENT-REQUIRED": b64_str
    })
    
    parsed = client._parse_challenge(res)
    assert parsed.source == ChallengeSource.STANDARD_X402
    assert parsed.network == "eip155:8453"
    assert parsed.asset == "USDC"
    assert parsed.parameters["_raw_accepted"]["amount"] == "1000"

def test_2_base_usdc_token_address_only_asset_resolved():
    client = Payment402Client()
    payload = {
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "amount": "1000",
                "payTo": "0x0000000000000000000000000000000000000001"
            }
        ],
        "resource": {"url": "https://hello-world-x402.vercel.app/hello", "method": "GET"}
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    res = _create_mock_response({"PAYMENT-REQUIRED": b64_str})
    
    parsed = client._parse_challenge(res)
    assert parsed.scheme == "exact"
    assert parsed.network == "eip155:8453"
    assert parsed.asset == "USDC"
    assert parsed.amount == 0.001
    assert parsed.parameters["token_address"].lower() == "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".lower()
    assert parsed.parameters["decimals"] == 6
    assert parsed.parameters["_raw_amount"] == "1000"
    assert parsed.parameters["_raw_accepted"]["amount"] == "1000"

def test_3_polygon_usdc_token_address_only_asset_resolved():
    client = Payment402Client()
    payload = {
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:137",
                "asset": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
                "amount": "1000000",
                "payTo": "0x0000000000000000000000000000000000000001"
            }
        ]
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    res = _create_mock_response({"PAYMENT-REQUIRED": b64_str})
    
    parsed = client._parse_challenge(res)
    assert parsed.asset == "USDC"
    assert parsed.amount == 1.0
    assert parsed.parameters["decimals"] == 6
    assert parsed.parameters["token_address"].lower() == "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174".lower()

def test_4_relayer_endpoint_survives_parsing():
    client = Payment402Client()
    payload = {
        "scheme": "lnc-evm-relay",
        "network": "eip155:8453",
        "asset": "USDC",
        "amount": "0.001",
        "parameters": {
            "relayer_endpoint": "https://example.com/relay"
        },
        "accepts": [
            {
                "scheme": "lnc-evm-relay",
                "network": "eip155:8453",
                "asset": "USDC",
                "amount": "1000",
                "payTo": "0x0000000000000000000000000000000000000001",
                "parameters": {
                    "relayer_endpoint": "https://example.com/relay_inner"
                }
            }
        ]
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    res = _create_mock_response({"PAYMENT-REQUIRED": b64_str})
    
    parsed = client._parse_challenge(res)
    # The inner should override or the outer should be present
    assert parsed.parameters.get("relayer_endpoint") in ["https://example.com/relay", "https://example.com/relay_inner"]

@patch("ln_church_agent.crypto.evm.LocalKeyAdapter.generate_eip3009_payload_atomic")
@patch("eth_account.Account.recover_message")
def test_5_evm_exact_signer_receives_correct_amount_semantics(mock_recover, mock_gen):
    client = Payment402Client(private_key="0x" + "1"*64)
    mock_gen.return_value = {
        "signature": "0x" + "1"*130,
        "authorization": {
            "value": "1000",
            "to": "0x1111111111111111111111111111111111111111",
            "from": client.evm_signer.address,
            "validAfter": "0",
            "validBefore": "9999999999",
            "nonce": "0x" + "a"*64
         }
     }
    mock_recover.return_value = client.evm_signer.address
    payload = {
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "amount": "1000",
                "payTo": "0x1111111111111111111111111111111111111111"
            }
        ]
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    res = _create_mock_response({"PAYMENT-REQUIRED": b64_str})
    
    parsed = client._parse_challenge(res)
    
    headers = {}
    client._process_payment(parsed, headers, {}, url="http://mock")
    
    args, kwargs = mock_gen.call_args
    assert kwargs["atomic_amount_str"] == "1000"
    
    b64_env = headers["PAYMENT-SIGNATURE"]
    env = json.loads(base64.urlsafe_b64decode(b64_env + '==').decode('utf-8'))
    assert env["accepted"]["amount"] == "1000"
    assert env["accepted"]["asset"].lower() == "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".lower()

def test_6_l402_mpp_priority_regression():
    client = Payment402Client()
    res = _create_mock_response({
        "WWW-Authenticate": 'L402 macaroon="mac", invoice="inv"',
        "PAYMENT-REQUIRED": "base64..."
    })
    parsed = client._parse_challenge(res)
    assert parsed.scheme == "L402"
    
    res = _create_mock_response({
        "WWW-Authenticate": 'MPP invoice="inv", intent="charge"'
    })
    parsed = client._parse_challenge(res)
    assert parsed.scheme == "MPP"

    req_json = {"amount": "1000", "currency": "sats", "methodDetails": {"invoice": "lnbc123"}}
    b64_req = base64.urlsafe_b64encode(json.dumps(req_json).encode()).decode().rstrip('=')
    res = _create_mock_response({
        "WWW-Authenticate": f'Payment id="ch_123", method="lightning", intent="charge", request="{b64_req}"'
    })
    parsed = client._parse_challenge(res)
    assert parsed.scheme == "Payment"

def test_7_exact_symbol_asset_does_not_become_token_address():
    client = Payment402Client()
    payload = {
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": "USDC",
                "amount": "1000",
                "payTo": "0x0000000000000000000000000000000000000001"
            }
        ]
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    res = _create_mock_response({"PAYMENT-REQUIRED": b64_str})

    parsed = client._parse_challenge(res)

    assert parsed.asset == "USDC"
    # 論理シンボル(USDC)なので token_address には混入しないこと
    assert parsed.parameters.get("token_address") in [None, ""]
