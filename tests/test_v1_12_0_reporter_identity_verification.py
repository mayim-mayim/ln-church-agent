import pytest
import time
from unittest.mock import patch, MagicMock
from ln_church_agent.client import LnChurchClient

def test_ensure_reporter_verification_success():
    client = LnChurchClient(private_key="0x" + "1"*64)
    
    with patch.object(client, "execute_request") as mock_exec:
        # Mock Challenge
        mock_exec.side_effect = [
            {"challenge_id": "chal_123", "message": "LN Church Reporter Verification\n...", "expires_at": ""},
            {"status": "verified", "verified_until": int(time.time()*1000) + 600000, "proof_id": "proof_123"}
        ]
        
        res = client.ensure_reporter_verification()
        
        assert res["status"] == "verified"
        assert client._reporter_proof_id == "proof_123"
        assert mock_exec.call_count == 2
        
        # Test Cache
        res_cached = client.ensure_reporter_verification()
        assert res_cached["status"] == "cached"
        assert mock_exec.call_count == 2 # Did not execute again

def test_ensure_reporter_verification_unsupported_key():
    client = LnChurchClient(private_key="0x" + "1"*64)
    with pytest.raises(ValueError, match="Only 'evm' public_key_type is currently supported"):
        client.ensure_reporter_verification(public_key_type="solana")

def test_ensure_reporter_verification_no_key():
    client = LnChurchClient()
    client.private_key = None
    client.evm_signer = None
    # match の文字列を新しいエラーメッセージに適合するように修正
    with pytest.raises(ValueError, match="EVM private_key is strictly required"):
        client.ensure_reporter_verification()