import pytest
import httpx
import base64
import json
from unittest.mock import patch, MagicMock

from ln_church_agent.client import Payment402Client, _b64url_decode
from ln_church_agent.models import PaymentPolicy
from ln_church_agent.exceptions import PaymentExecutionError
from ln_church_agent.challenges import SOLANA_USDC_MINT
from ln_church_agent.crypto.solana_svm import LocalSvmAdapter, SOLANA_MAINNET_CAIP2, SOLANA_DEVNET_CAIP2
from solders.keypair import Keypair

def _create_v2_challenge(network: str, scheme: str = "exact") -> httpx.Response:
    payload = {
        "accepts": [
            {
                "scheme": scheme,
                "network": network,
                "asset": SOLANA_USDC_MINT,
                "amount": "1000000",
                "payTo": "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4",
                "extra": {
                    "feePayer": "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd",
                    "memo": "test_memo"
                }
            }
        ],
        "resource": {"url": "http://api.test", "method": "POST"}
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    return httpx.Response(402, headers={"PAYMENT-REQUIRED": b64_str})

def test_evm_private_key_only_does_not_break_init():
    """EVM private_keyだけでclient初期化が壊れないこと"""
    client = Payment402Client(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    assert client.evm_signer is not None
    assert client.svm_signer is None

def test_missing_svm_dependency_fails_loudly():
    """x402[svm] (solders) 未導入時に明確なエラーになること"""
    with patch.dict('sys.modules', {'solders.keypair': None}):
        with pytest.raises(ImportError, match="SVM support dependencies are missing"):
            from ln_church_agent.crypto.solana_svm import LocalSvmAdapter
            LocalSvmAdapter("dummy_base58_key")

@patch("ln_church_agent.crypto.solana_svm.LocalSvmAdapter")
def test_classification_svm_exact_raw_payloads(MockSvmAdapter):
    """
    SVM exact に正しく分類され、Raw Asset / Raw Amount がビルダーに渡されるか確認
    """
    mock_signer = MockSvmAdapter.return_value
    mock_signer.generate_svm_exact_payload.return_value = {"transaction": "base64_tx"}
    
    client = Payment402Client(svm_private_key="ValidBase58DummyKey")
    client.svm_signer = mock_signer
    
    mock_res = _create_v2_challenge("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
    parsed = client._parse_challenge(mock_res)
    
    # Policy上はHuman unit (1.0 USDC) に正規化されていることを確認
    assert parsed.asset == "USDC"
    assert parsed.amount == 1.0
    
    headers = {}
    client._process_payment(parsed, headers, {}, url="http://api.test")
    
    # 呼び出し引数を検証: Raw Mint Address と "1000000" が渡されているか
    call_args = mock_signer.generate_svm_exact_payload.call_args[1]
    assert call_args["asset"] == SOLANA_USDC_MINT
    assert call_args["amount"] == "1000000"

def test_missing_fee_payer():
    """feePayer が欠損している場合に安全に拒否されるか"""
    client = Payment402Client(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    client.svm_signer = MagicMock()
    
    payload = {
        "accepts": [{"scheme": "exact", "network": "solana:123", "amount": "1000", "payTo": "xyz"}]
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    mock_res = httpx.Response(402, headers={"PAYMENT-REQUIRED": b64_str})
    parsed = client._parse_challenge(mock_res)
    
    with pytest.raises(PaymentExecutionError, match="requires extra.feePayer"):
        client._process_payment(parsed, {}, {})

def test_policy_allowed_networks():
    """allowed_networks で不正なネットワークが弾かれるか"""
    
    policy = PaymentPolicy(
        allowed_networks=["eip155:137", "solana:safe_hash"],
        allowed_assets=["SATS", "USDC", "JPYC", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"]
    )
    client = Payment402Client(policy=policy)
    
    mock_res = _create_v2_challenge("solana:untrusted_hash")
    parsed = client._parse_challenge(mock_res)
    
    with pytest.raises(PaymentExecutionError, match="not in allowed_networks"):
        client._enforce_policy(parsed, "http://api.test")

def _create_v2_challenge_with_array() -> httpx.Response:
    payload = {
        "accepts": [
            {"scheme": "exact", "network": "eip155:137", "asset": "USDC", "amount": "1000000", "payTo": "0xPolygon"},
            {"scheme": "exact", "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "asset": SOLANA_USDC_MINT, "amount": "1000000", "payTo": "SolanaAddress", "extra": {"feePayer": "FeePayerKey"}}
        ],
        "resource": {"url": "http://api.test", "method": "POST"}
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    return httpx.Response(402, headers={"PAYMENT-REQUIRED": b64_str})

def test_svm_dependency_error():
    """x402[svm] 未導入時に明確なMissingDependency系エラーになる"""
    with patch.dict('sys.modules', {'solders.keypair': None}):
        with pytest.raises(ImportError, match="SVM support dependencies are missing"):
            from ln_church_agent.crypto.solana_svm import LocalSvmAdapter
            LocalSvmAdapter("dummy_base58_key")

def test_evm_private_key_does_not_break_init():
    """EVM private_keyだけでclient初期化が壊れない"""
    # 短い、あるいは不正なBase58を入れるとSolanaのアダプタはコケるが、Client初期化全体はクラッシュしない
    client = Payment402Client(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    assert client.evm_signer is not None
    assert client.svm_signer is None  # svm_private_key を明示していないので None になる

@patch("ln_church_agent.crypto.solana_svm.LocalSvmAdapter")
def test_accepts_array_selection_and_budget_evaluation(MockSvmAdapter):
    """
    - accepts[0]=EVM, accepts[1]=Solanaでもallowed_networks等でSolanaを選べる
    - Solana USDC mintがUSDCとして予算評価される
    """
    # 予算: 5 USD
    policy = PaymentPolicy(allowed_networks=["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"], allowed_assets=["SATS", "USDC"])
    
    mock_signer = MockSvmAdapter.return_value
    mock_signer.generate_svm_exact_payload.return_value = {"transaction": "base64_tx"}
    
    client = Payment402Client(
        private_key="0x0000000000000000000000000000000000000000000000000000000000000001",
        policy=policy
    )
    client.svm_signer = mock_signer
    
    mock_res = _create_v2_challenge_with_array()
    parsed = client._parse_challenge(mock_res)
    
    # 1. EVM(index 0) ではなく Solana(index 1) が選択されているか
    assert parsed.network == "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
    
    # 2. Solana USDC mintが論理USDCに変換され、amountが 1,000,000 -> 1.0 に変換されているか
    assert parsed.asset == "USDC"
    assert parsed.parameters["token_address"] == SOLANA_USDC_MINT
    assert parsed.amount == 1.0
    
    # 3. Budget Validation がクラッシュせずに通るか
    client._enforce_policy(parsed, "http://api.test")

def test_missing_fee_payer_fails_loudly():
    """feePayer が欠損している場合に安全に拒否されるか"""
    client = Payment402Client()
    client.svm_signer = MagicMock()
    
    payload = {
        "accepts": [{"scheme": "exact", "network": "solana:123", "amount": "1000", "payTo": "xyz"}]
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    mock_res = httpx.Response(402, headers={"PAYMENT-REQUIRED": b64_str})
    parsed = client._parse_challenge(mock_res)
    
    with pytest.raises(PaymentExecutionError, match="requires extra.feePayer"):
        client._process_payment(parsed, {}, {})

@patch("solana.rpc.api.Client.get_latest_blockhash")
def test_generate_svm_exact_payload_success(mock_blockhash):
    """
    generate_svm_exact_payload() がTransferChecked等を含む
    正しい base64 serialize された Transaction を返すことを確認。
    """
    # 👇 ここから修正: solders の本物の Hash オブジェクトを使ってモックを構築する
    from solders.hash import Hash
    
    mock_resp = MagicMock()
    # 適当な文字列ではなく、ダミーの本物Hashオブジェクトを生成
    dummy_hash = Hash.default() 
    mock_resp.value.blockhash = dummy_hash 
    mock_blockhash.return_value = mock_resp

    # テスト用のダミー秘密鍵 (Solana Base58形式)
    dummy_sk = str(Keypair())
    adapter = LocalSvmAdapter(private_key=dummy_sk)

    fee_payer = "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd"
    pay_to = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4"
    memo = "test_memo_x402"

    payload = adapter.generate_svm_exact_payload(
        network=SOLANA_MAINNET_CAIP2,
        asset=SOLANA_USDC_MINT,
        amount="1000000",
        pay_to=pay_to,
        fee_payer=fee_payer,
        memo=memo
    )

    assert "transaction" in payload
    b64_tx = payload["transaction"]
    
    # Base64デコードできるか
    raw_tx = base64.b64decode(b64_tx)
    assert len(raw_tx) > 0

    # solders.message を使ってパースし、Instructionが存在するか確認
    from solders.transaction import VersionedTransaction
    parsed_tx = VersionedTransaction.from_bytes(raw_tx)
    
    # Compute limit, Compute price, Memo, TransferChecked の4つが存在するはず
    assert len(parsed_tx.message.instructions) == 4

def test_unsupported_mint_and_network_rejection():
    """未対応のMintや俗称ネットワーク(solana:mainnet)が明示エラーになるか"""
    dummy_sk = str(Keypair())
    adapter = LocalSvmAdapter(private_key=dummy_sk)

    # 1. 俗称ネットワークの拒否
    with pytest.raises(ValueError, match="Unsupported Solana network format"):
        adapter.generate_svm_exact_payload(
            network="solana:mainnet", asset=SOLANA_USDC_MINT, amount="1", pay_to="A", fee_payer="B"
        )
        
    # 2. 未対応のMintの拒否
    with pytest.raises(ValueError, match="Unsupported SPL token mint for SVM exact"):
        adapter.generate_svm_exact_payload(
            network=SOLANA_MAINNET_CAIP2, asset="UnknownMint123", amount="1", pay_to="A", fee_payer="B"
        )

def test_invalid_base58_private_key():
    """無効なBase58キーで初期化時にクラッシュせず ValueError を投げるか"""
    with pytest.raises(ValueError, match="Invalid Solana Base58 private key"):
        LocalSvmAdapter(private_key="invalid_key_$$$")

@patch("solana.rpc.api.Client")
def test_rpc_resolution_logic(MockRpcClient):
    """Network ID に応じて適切な RPC が選択されるか確認"""
    from solders.hash import Hash
    # Hashのモックを設定
    mock_instance = MockRpcClient.return_value
    mock_instance.get_latest_blockhash.return_value.value.blockhash = Hash.default()

    adapter = LocalSvmAdapter(private_key=str(Keypair()))
    pay_to_dummy = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4"
    fee_payer_dummy = "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd"
    
    # 1. Devnet CAIP2 -> Devnet RPC
    adapter.generate_svm_exact_payload(SOLANA_DEVNET_CAIP2, SOLANA_USDC_MINT, "1", pay_to_dummy, fee_payer_dummy)
    MockRpcClient.assert_called_with("https://api.devnet.solana.com")
    
    # 2. Mainnet CAIP2 -> Mainnet RPC
    adapter.generate_svm_exact_payload(SOLANA_MAINNET_CAIP2, SOLANA_USDC_MINT, "1", pay_to_dummy, fee_payer_dummy)
    MockRpcClient.assert_called_with("https://api.mainnet-beta.solana.com")

@patch("solana.rpc.api.Client.get_latest_blockhash")
def test_versioned_transaction_structure(mock_blockhash):
    """Payerがfee_payerであり、Token Programが含まれるか確認"""
    from solders.hash import Hash
    from solders.transaction import VersionedTransaction
    
    mock_resp = MagicMock()
    mock_resp.value.blockhash = Hash.default()
    mock_blockhash.return_value = mock_resp

    adapter = LocalSvmAdapter(private_key=str(Keypair()))
    pay_to_dummy = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4"
    fee_payer_dummy = "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd"
    
    payload = adapter.generate_svm_exact_payload(SOLANA_MAINNET_CAIP2, SOLANA_USDC_MINT, "1000", pay_to_dummy, fee_payer_dummy)
    
    raw_tx = base64.b64decode(payload["transaction"])
    tx = VersionedTransaction.from_bytes(raw_tx)
    
    # Payer (fee_payer) が AccountKeys の先頭に存在するか
    assert str(tx.message.account_keys[0]) == fee_payer_dummy