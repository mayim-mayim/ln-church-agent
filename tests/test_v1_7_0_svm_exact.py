import pytest
import httpx
import base64
import json
from unittest.mock import patch, MagicMock

from ln_church_agent.client import Payment402Client, _b64url_decode
from ln_church_agent.models import PaymentPolicy
from ln_church_agent.exceptions import PaymentExecutionError
from ln_church_agent.challenges import SOLANA_USDC_MINT
from ln_church_agent.crypto.solana_svm import (
    COMPUTE_BUDGET_PROGRAM_ID_STR,
    MEMO_PROGRAM_ID_STR,
    TOKEN_PROGRAM_ID_STR,
    LocalSvmAdapter,
    SOLANA_DEVNET_CAIP2,
    SOLANA_MAINNET_CAIP2,
    validate_svm_exact_payload,
)
from solders.keypair import Keypair

SOLANA_DEVNET_USDC_MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"

_SVM_PAY_TO = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4"
_SVM_FEE_PAYER = "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd"


def _set_default_blockhash(mock_blockhash):
    from solders.hash import Hash

    response = MagicMock()
    response.value.blockhash = Hash.default()
    mock_blockhash.return_value = response


def _parsed_transaction(payload):
    from solders.transaction import VersionedTransaction

    return VersionedTransaction.from_bytes(base64.b64decode(payload["transaction"]))


def _instruction_programs(transaction):
    account_keys = list(transaction.message.account_keys)
    return [
        str(account_keys[instruction.program_id_index])
        for instruction in transaction.message.instructions
    ]


def _payload_with_instructions(payload, source_keypair, instructions):
    """Rebuild and re-sign a payload after a test-only instruction mutation."""
    from solders.message import MessageV0
    from solders.null_signer import NullSigner
    from solders.transaction import VersionedTransaction

    original = _parsed_transaction(payload)
    message = MessageV0(
        original.message.header,
        original.message.account_keys,
        original.message.recent_blockhash,
        instructions,
        original.message.address_table_lookups,
    )
    signers = [
        source_keypair if key == source_keypair.pubkey() else NullSigner(key)
        for key in message.account_keys[:message.header.num_required_signatures]
    ]
    transaction = VersionedTransaction(message, signers)
    return {"transaction": base64.b64encode(bytes(transaction)).decode("ascii")}


def _validate_payload(payload, adapter, *, memo=None, canonical_expires_at=None):
    return validate_svm_exact_payload(
        payload,
        network=SOLANA_MAINNET_CAIP2,
        asset=SOLANA_USDC_MINT,
        amount="1000000",
        pay_to=_SVM_PAY_TO,
        fee_payer=_SVM_FEE_PAYER,
        signer_address=adapter.address,
        memo=memo,
        canonical_expires_at=canonical_expires_at,
    )

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
    mock_signer = MockSvmAdapter.return_value
    mock_signer.generate_svm_exact_payload.return_value = {"transaction": "base64_tx"}

    client = Payment402Client(svm_private_key="ValidBase58DummyKey")
    client.svm_signer = mock_signer

    mock_res = _create_v2_challenge("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
    parsed = client._parse_challenge(mock_res)

    assert parsed.asset == "USDC"
    assert parsed.amount == 1.0

    headers = {}
    with pytest.raises(
        PaymentExecutionError,
        match="canonical SVM exact auto-payment",
    ):
        client._process_payment(parsed, headers, {}, url="http://api.test")

    mock_signer.generate_svm_exact_payload.assert_not_called()

def test_high_level_svm_halts_before_fee_payer_requirement():
    """高水準SVMはfeePayerの有無より先に恒久的な境界で停止する。"""
    client = Payment402Client(private_key="0x0000000000000000000000000000000000000000000000000000000000000001")
    client.svm_signer = MagicMock()

    payload = {
        "accepts": [{"scheme": "exact", "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "asset": SOLANA_USDC_MINT, "amount": "1000", "payTo": "xyz"}]
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    mock_res = httpx.Response(402, headers={"PAYMENT-REQUIRED": b64_str})
    parsed = client._parse_challenge(mock_res)

    with pytest.raises(
        PaymentExecutionError,
        match="canonical SVM exact auto-payment",
    ):
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

def test_high_level_svm_halts_without_signer_or_fee_payer():
    """鍵やfeePayerがなくても実行可能性を示さず同じ境界で停止する。"""
    client = Payment402Client()

    payload = {
        "accepts": [{"scheme": "exact", "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "asset": SOLANA_USDC_MINT, "amount": "1000", "payTo": "xyz"}]
    }
    b64_str = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    mock_res = httpx.Response(402, headers={"PAYMENT-REQUIRED": b64_str})
    parsed = client._parse_challenge(mock_res)

    with pytest.raises(
        PaymentExecutionError,
        match="canonical SVM exact auto-payment",
    ):
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

    # Reference facilitator order: CU limit, CU price, TransferChecked, Memo.
    assert len(parsed_tx.message.instructions) == 4
    assert _instruction_programs(parsed_tx) == [
        COMPUTE_BUDGET_PROGRAM_ID_STR,
        COMPUTE_BUDGET_PROGRAM_ID_STR,
        TOKEN_PROGRAM_ID_STR,
        MEMO_PROGRAM_ID_STR,
    ]
    assert bytes(parsed_tx.message.instructions[3].data).decode("utf-8") == memo
    validated = _validate_payload(payload, adapter, memo=memo)
    assert validated["memo"] == memo


@patch("ln_church_agent.crypto.solana_svm.secrets.token_hex", return_value="ab" * 16)
@patch("solana.rpc.api.Client.get_latest_blockhash")
def test_standard_facilitator_layout_without_extra_memo(
    mock_blockhash, mock_token_hex
):
    """Without extra.memo, emit one 16-byte lowercase-hex memo at index 3."""
    _set_default_blockhash(mock_blockhash)
    adapter = LocalSvmAdapter(private_key=str(Keypair()))

    payload = adapter.generate_svm_exact_payload(
        SOLANA_MAINNET_CAIP2,
        SOLANA_USDC_MINT,
        "1000000",
        _SVM_PAY_TO,
        _SVM_FEE_PAYER,
    )

    transaction = _parsed_transaction(payload)
    assert _instruction_programs(transaction) == [
        COMPUTE_BUDGET_PROGRAM_ID_STR,
        COMPUTE_BUDGET_PROGRAM_ID_STR,
        TOKEN_PROGRAM_ID_STR,
        MEMO_PROGRAM_ID_STR,
    ]
    assert bytes(transaction.message.instructions[3].data).decode("utf-8") == "ab" * 16
    assert _validate_payload(payload, adapter)["memo"] == "ab" * 16
    mock_token_hex.assert_called_once_with(16)


@patch("solana.rpc.api.Client.get_latest_blockhash")
def test_validator_rejects_wrong_standard_instruction_order(mock_blockhash):
    """A memo before TransferChecked is incompatible with the facilitator."""
    _set_default_blockhash(mock_blockhash)
    adapter = LocalSvmAdapter(private_key=str(Keypair()))
    payload = adapter.generate_svm_exact_payload(
        SOLANA_MAINNET_CAIP2,
        SOLANA_USDC_MINT,
        "1000000",
        _SVM_PAY_TO,
        _SVM_FEE_PAYER,
        memo="challenge-memo",
    )
    instructions = list(_parsed_transaction(payload).message.instructions)
    instructions[2], instructions[3] = instructions[3], instructions[2]
    reordered = _payload_with_instructions(payload, adapter.keypair, instructions)

    with pytest.raises(ValueError, match="instruction order"):
        _validate_payload(reordered, adapter, memo="challenge-memo")


@patch("solana.rpc.api.Client.get_latest_blockhash")
def test_validator_rejects_duplicate_memo(mock_blockhash):
    """The facilitator-compatible shape contains exactly one memo."""
    _set_default_blockhash(mock_blockhash)
    adapter = LocalSvmAdapter(private_key=str(Keypair()))
    payload = adapter.generate_svm_exact_payload(
        SOLANA_MAINNET_CAIP2,
        SOLANA_USDC_MINT,
        "1000000",
        _SVM_PAY_TO,
        _SVM_FEE_PAYER,
        memo="challenge-memo",
    )
    instructions = list(_parsed_transaction(payload).message.instructions)
    instructions.append(instructions[-1])
    duplicate = _payload_with_instructions(payload, adapter.keypair, instructions)

    with pytest.raises(ValueError, match="exactly four instructions and one memo"):
        _validate_payload(duplicate, adapter, memo="challenge-memo")


@patch("solana.rpc.api.Client.get_latest_blockhash")
def test_validator_rejects_challenge_memo_mismatch(mock_blockhash):
    """The sole memo must equal extra.memo byte-for-byte when it is supplied."""
    _set_default_blockhash(mock_blockhash)
    adapter = LocalSvmAdapter(private_key=str(Keypair()))
    payload = adapter.generate_svm_exact_payload(
        SOLANA_MAINNET_CAIP2,
        SOLANA_USDC_MINT,
        "1000000",
        _SVM_PAY_TO,
        _SVM_FEE_PAYER,
        memo="challenge-memo",
    )

    with pytest.raises(ValueError, match="does not match the challenge memo"):
        _validate_payload(payload, adapter, memo="different-memo")


@patch("solana.rpc.api.Client.get_latest_blockhash")
def test_validator_fails_closed_for_canonical_unix_expiry(mock_blockhash):
    """Recent-blockhash lifetime cannot prove a canonical wall-clock expiry bound."""
    _set_default_blockhash(mock_blockhash)
    adapter = LocalSvmAdapter(private_key=str(Keypair()))
    payload = adapter.generate_svm_exact_payload(
        SOLANA_MAINNET_CAIP2,
        SOLANA_USDC_MINT,
        "1000000",
        _SVM_PAY_TO,
        _SVM_FEE_PAYER,
        memo="challenge-memo",
    )

    with pytest.raises(ValueError, match="cannot mechanically bound"):
        _validate_payload(
            payload,
            adapter,
            memo="challenge-memo",
            canonical_expires_at=1_900_000_000,
        )


@pytest.mark.parametrize(
    "memo",
    [None, "official-facilitator-memo"],
    ids=["extra-memo-absent", "extra-memo-present"],
)
@patch("solana.rpc.api.Client.get_latest_blockhash")
def test_payload_is_accepted_by_official_x402_python_facilitator(
    mock_blockhash, memo
):
    """Exercise the installed x402 2.16.0 production facilitator verifier."""
    from importlib.metadata import version

    from x402.mechanisms.svm.exact.facilitator import ExactSvmScheme
    from x402.schemas import PaymentPayload, PaymentRequirements

    class OfflineFacilitatorSigner:
        def get_addresses(self):
            return [_SVM_FEE_PAYER]

        def sign_transaction(self, transaction, fee_payer, network):
            assert fee_payer == _SVM_FEE_PAYER
            assert network == SOLANA_MAINNET_CAIP2
            return transaction

        def simulate_transaction(self, transaction, network):
            assert transaction
            assert network == SOLANA_MAINNET_CAIP2

    assert version("x402") == "2.16.0"
    _set_default_blockhash(mock_blockhash)
    adapter = LocalSvmAdapter(private_key=str(Keypair()))
    transaction_payload = adapter.generate_svm_exact_payload(
        SOLANA_MAINNET_CAIP2,
        SOLANA_USDC_MINT,
        "1000000",
        _SVM_PAY_TO,
        _SVM_FEE_PAYER,
        memo=memo,
    )
    extra = {"feePayer": _SVM_FEE_PAYER}
    if memo is not None:
        extra["memo"] = memo
    requirements = PaymentRequirements(
        scheme="exact",
        network=SOLANA_MAINNET_CAIP2,
        asset=SOLANA_USDC_MINT,
        amount="1000000",
        pay_to=_SVM_PAY_TO,
        max_timeout_seconds=60,
        extra=extra,
    )
    payment = PaymentPayload(
        x402_version=2,
        accepted=requirements,
        payload=transaction_payload,
    )

    result = ExactSvmScheme(OfflineFacilitatorSigner()).verify(
        payment, requirements
    )

    assert result.is_valid is True
    assert result.invalid_reason is None


@patch("solana.rpc.api.Client.get_latest_blockhash")
def test_svm_challenge_memo_enforces_256_byte_limit(mock_blockhash):
    _set_default_blockhash(mock_blockhash)
    adapter = LocalSvmAdapter(private_key=str(Keypair()))

    accepted = adapter.generate_svm_exact_payload(
        SOLANA_MAINNET_CAIP2,
        SOLANA_USDC_MINT,
        "1000000",
        _SVM_PAY_TO,
        _SVM_FEE_PAYER,
        memo="m" * 256,
    )
    assert _validate_payload(accepted, adapter, memo="m" * 256)["memo"] == "m" * 256

    with pytest.raises(ValueError, match="256-byte"):
        adapter.generate_svm_exact_payload(
            SOLANA_MAINNET_CAIP2,
            SOLANA_USDC_MINT,
            "1000000",
            _SVM_PAY_TO,
            _SVM_FEE_PAYER,
            memo="m" * 257,
        )

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
    adapter.generate_svm_exact_payload(SOLANA_DEVNET_CAIP2, SOLANA_DEVNET_USDC_MINT, "1", pay_to_dummy, fee_payer_dummy)
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
