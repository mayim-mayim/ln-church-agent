import base64
import math
import re
from typing import Optional, Dict, Any, Union
from .protocols import X402SvmSigner

SOLANA_MAINNET_CAIP2 = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
SOLANA_DEVNET_CAIP2 = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"

KNOWN_SPL_TOKEN_DECIMALS = {
    # Solana Mainnet USDC
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": 6,
    # Solana Devnet USDC
    "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU": 6,
}

TRUSTED_SVM_TOKEN_DECIMALS = {
    (SOLANA_MAINNET_CAIP2, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"): 6,
    (SOLANA_DEVNET_CAIP2, "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"): 6,
}

MEMO_PROGRAM_ID_STR = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
COMPUTE_BUDGET_PROGRAM_ID_STR = "ComputeBudget111111111111111111111111111111"
TOKEN_PROGRAM_ID_STR = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

MAX_COMPUTE_UNIT_LIMIT = 200_000
MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS = 1_000_000
MAX_PRIORITY_FEE_LAMPORTS = 200_000

_SUPPORTED_SVM_NETWORKS = {SOLANA_MAINNET_CAIP2, SOLANA_DEVNET_CAIP2}
_ATOMIC_AMOUNT_RE = re.compile(r"^[1-9][0-9]*$")


def _normalize_atomic_amount(amount: Union[str, int, float]) -> str:
    if isinstance(amount, bool):
        raise ValueError("Invalid SVM atomic amount.")
    if isinstance(amount, str):
        normalized = amount
    elif isinstance(amount, int):
        normalized = str(amount)
    elif isinstance(amount, float) and math.isfinite(amount) and amount.is_integer():
        normalized = str(int(amount))
    else:
        raise ValueError("Invalid SVM atomic amount.")
    if _ATOMIC_AMOUNT_RE.fullmatch(normalized) is None:
        raise ValueError("Invalid SVM atomic amount: expected a canonical positive integer.")
    if int(normalized) >= 2 ** 64:
        raise ValueError("Invalid SVM atomic amount: exceeds SPL Token uint64 range.")
    return normalized


def _validate_network_and_mint(network: Any, mint: Any) -> int:
    if network not in _SUPPORTED_SVM_NETWORKS:
        if network in ("solana:mainnet", "solana:devnet"):
            raise ValueError(
                f"Unsupported Solana network format '{network}'. "
                f"Use CAIP-2 genesisHash (e.g., '{SOLANA_MAINNET_CAIP2}')."
            )
        raise ValueError(f"Unsupported CAIP-2 network for SVM exact: {network}")
    if not isinstance(mint, str) or mint not in KNOWN_SPL_TOKEN_DECIMALS:
        raise ValueError(
            f"Unsupported SPL token mint for SVM exact: {mint}. Token decimals are required."
        )
    decimals = TRUSTED_SVM_TOKEN_DECIMALS.get((network, mint))
    if decimals is None:
        raise ValueError("SVM network/mint pair is not trusted.")
    return decimals


def _parse_pubkey(value: Any, field_name: str):
    if not isinstance(value, str) or not value:
        raise ValueError(f"Invalid Solana {field_name} public key.")
    try:
        from solders.pubkey import Pubkey
        pubkey = Pubkey.from_string(value)
    except ImportError:
        raise ImportError(
            "SVM support dependencies are missing. "
            "Install with: pip install 'ln-church-agent[svm]'"
        ) from None
    except Exception:
        raise ValueError(f"Invalid Solana {field_name} public key.") from None
    if str(pubkey) != value:
        raise ValueError(f"Non-canonical Solana {field_name} public key.")
    return pubkey


def validate_svm_exact_payload(
    payload: Any, *, network: str, asset: str,
    amount: Union[str, int, float], pay_to: str, fee_payer: str,
    signer_address: str, memo: Optional[str] = None
) -> Dict[str, Any]:
    """Validate a serialized x402 SVM transfer against canonical inputs."""
    if not isinstance(payload, dict) or not isinstance(payload.get("transaction"), str):
        raise ValueError("Invalid or incomplete SVM exact payload.")
    if set(payload.keys()) != {"transaction"}:
        raise ValueError("Unexpected SVM exact payload fields.")

    decimals = _validate_network_and_mint(network, asset)
    normalized_amount = _normalize_atomic_amount(amount)
    mint_pubkey = _parse_pubkey(asset, "mint")
    destination_owner = _parse_pubkey(pay_to, "destination")
    expected_fee_payer = _parse_pubkey(fee_payer, "fee payer")
    source_owner = _parse_pubkey(signer_address, "signer")
    if memo is not None and not isinstance(memo, str):
        raise ValueError("Invalid SVM memo.")
    if memo == "":
        memo = None

    try:
        raw_transaction = base64.b64decode(payload["transaction"], validate=True)
    except Exception:
        raise ValueError("Invalid base64 SVM transaction.") from None
    if not raw_transaction:
        raise ValueError("Empty SVM transaction.")
    if len(raw_transaction) > 1232:
        raise ValueError("Oversized SVM transaction.")

    try:
        from solders.message import MessageV0, to_bytes_versioned
        from solders.transaction import VersionedTransaction
        from spl.token.instructions import get_associated_token_address
        transaction = VersionedTransaction.from_bytes(raw_transaction)
    except ImportError:
        raise ImportError(
            "SVM support dependencies are missing. "
            "Install with: pip install 'ln-church-agent[svm]'"
        ) from None
    except Exception:
        raise ValueError("Invalid serialized SVM transaction.") from None

    message = transaction.message
    if not isinstance(message, MessageV0):
        raise ValueError("SVM exact requires a versioned v0 transaction.")
    if message.address_table_lookups:
        raise ValueError("SVM exact transactions with unresolved address lookups are not accepted.")

    account_keys = list(message.account_keys)
    if not account_keys or account_keys[0] != expected_fee_payer:
        raise ValueError("SVM transaction fee payer does not match the canonical requirement.")
    if message.header.num_required_signatures < 1 or not message.is_signer(0):
        raise ValueError("SVM transaction fee payer is not a required signer.")

    expected_source = get_associated_token_address(source_owner, mint_pubkey)
    expected_destination = get_associated_token_address(destination_owner, mint_pubkey)
    transfer_details = None
    memo_values = []
    compute_discriminators = set()
    compute_unit_limit = None
    compute_unit_price = None

    for compiled_instruction in message.instructions:
        program_index = compiled_instruction.program_id_index
        if program_index >= len(account_keys):
            raise ValueError("SVM instruction contains an invalid program index.")
        program_id = str(account_keys[program_index])
        data = bytes(compiled_instruction.data)

        if program_id == COMPUTE_BUDGET_PROGRAM_ID_STR:
            if compiled_instruction.accounts:
                raise ValueError("Unexpected account-bearing compute-budget instruction.")
            if not data or data[0] not in (2, 3):
                raise ValueError("Unexpected SVM compute-budget instruction.")
            expected_length = 5 if data[0] == 2 else 9
            if len(data) != expected_length or data[0] in compute_discriminators:
                raise ValueError("Invalid or duplicate SVM compute-budget instruction.")
            compute_discriminators.add(data[0])
            decoded_value = int.from_bytes(data[1:], byteorder="little", signed=False)
            if data[0] == 2:
                if decoded_value <= 0 or decoded_value > MAX_COMPUTE_UNIT_LIMIT:
                    raise ValueError("SVM compute-unit limit exceeds the buyer safety bound.")
                compute_unit_limit = decoded_value
            else:
                if decoded_value > MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS:
                    raise ValueError("SVM compute-unit price exceeds the buyer safety bound.")
                compute_unit_price = decoded_value
            continue

        if program_id == MEMO_PROGRAM_ID_STR:
            if compiled_instruction.accounts:
                raise ValueError("Unexpected account-bearing SVM memo instruction.")
            try:
                memo_values.append(data.decode("utf-8"))
            except UnicodeDecodeError:
                raise ValueError("Invalid UTF-8 SVM memo instruction.") from None
            if len(memo_values) > 1:
                raise ValueError("Duplicate SVM memo instruction.")
            continue

        if program_id != TOKEN_PROGRAM_ID_STR:
            raise ValueError(f"Unexpected SVM instruction program: {program_id}")
        if transfer_details is not None:
            raise ValueError("SVM exact payload must contain exactly one token transfer.")
        if len(data) != 10 or data[0] != 12:
            raise ValueError("SVM exact payload requires SPL Token TransferChecked.")

        account_indices = list(compiled_instruction.accounts)
        if len(account_indices) != 4 or any(index >= len(account_keys) for index in account_indices):
            raise ValueError("Invalid SPL Token TransferChecked account layout.")
        source, mint, destination, authority = [account_keys[index] for index in account_indices]
        if source != expected_source:
            raise ValueError("SVM transfer source does not match the signer/mint ATA.")
        if mint != mint_pubkey:
            raise ValueError("SVM transfer mint does not match the canonical requirement.")
        if destination != expected_destination:
            raise ValueError("SVM transfer destination does not match canonical payTo.")
        if authority != source_owner or not message.is_signer(account_indices[3]):
            raise ValueError("SVM transfer authority does not match the configured signer.")
        if not message.is_maybe_writable(account_indices[0]) or not message.is_maybe_writable(account_indices[2]):
            raise ValueError("SVM transfer source and destination must be writable.")

        instruction_amount = int.from_bytes(data[1:9], byteorder="little", signed=False)
        instruction_decimals = data[9]
        if instruction_amount != int(normalized_amount):
            raise ValueError("SVM transfer amount does not match the canonical atomic amount.")
        if instruction_decimals != decimals:
            raise ValueError("SVM TransferChecked decimals do not match trusted mint metadata.")
        transfer_details = {
            "source": str(source),
            "mint": str(mint),
            "destination": str(destination),
            "authority": str(authority),
            "amount": normalized_amount,
            "decimals": decimals,
        }

    if compute_discriminators not in (set(), {2, 3}):
        raise ValueError(
            "SVM compute-budget limit and price must either both be absent or both be present."
        )
    if compute_unit_limit is not None and compute_unit_price is not None:
        priority_fee_lamports = (
            compute_unit_limit * compute_unit_price + 999_999
        ) // 1_000_000
        if priority_fee_lamports > MAX_PRIORITY_FEE_LAMPORTS:
            raise ValueError("SVM priority fee exceeds the buyer safety bound.")

    if transfer_details is None:
        raise ValueError("SVM exact payload is missing SPL Token TransferChecked.")
    if memo is not None and memo_values != [memo]:
        raise ValueError("SVM memo does not match the canonical requirement.")

    try:
        signer_index = account_keys.index(source_owner)
    except ValueError:
        raise ValueError("SVM signer is missing from transaction account keys.") from None
    if signer_index >= message.header.num_required_signatures:
        raise ValueError("SVM signer is not a required transaction signer.")
    if signer_index >= len(transaction.signatures) or not transaction.signatures[signer_index].verify(
        source_owner, to_bytes_versioned(message)
    ):
        raise ValueError("Invalid SVM source-owner signature.")

    return {
        "network": network,
        "fee_payer": str(expected_fee_payer),
        "memo": memo_values[0] if memo_values else None,
        "transfer": transfer_details,
    }

class LocalSvmAdapter(X402SvmSigner):
    """
    SVM Exact 用のローカル・トランザクション構築アダプタ。
    x402 v2 規格に準拠した partially-signed VersionedTransaction を生成します。
    """
    def __init__(self, private_key: str, rpc_url: Optional[str] = None):
        if not private_key:
            raise ValueError("LocalSvmAdapter requires a private_key.")

        self.private_key = private_key
        self.rpc_url = rpc_url  # v1.7.0 Final: ここでは保持のみ。解決は生成時に行う。
        try:
            from solders.keypair import Keypair
            self.keypair = Keypair.from_base58_string(private_key)
        except ImportError:
            raise ImportError(
                "SVM support dependencies are missing. "
                "Install with: pip install 'ln-church-agent[svm]'"
            )
        except Exception as e:
            raise ValueError(f"Invalid Solana Base58 private key for SVM Adapter: {e}")

    @property
    def address(self) -> str:
        return str(self.keypair.pubkey())

    def generate_svm_exact_payload(
        self, network: str, asset: str, amount: Union[str, int, float], pay_to: str,
        fee_payer: str, memo: Optional[str] = None
    ) -> Dict[str, Any]:
        decimals = _validate_network_and_mint(network, asset)
        atomic_amount = _normalize_atomic_amount(amount)
        mint_pubkey = _parse_pubkey(asset, "mint")
        dest_pubkey = _parse_pubkey(pay_to, "destination")
        fee_payer_pubkey = _parse_pubkey(fee_payer, "fee payer")
        payer_pubkey = self.keypair.pubkey()
        if memo is not None and not isinstance(memo, str):
            raise ValueError("Invalid SVM memo.")
        if memo == "":
            memo = None

        target_rpc = self.rpc_url
        if not target_rpc:
            if network == SOLANA_MAINNET_CAIP2:
                target_rpc = "https://api.mainnet-beta.solana.com"
            elif network == SOLANA_DEVNET_CAIP2:
                target_rpc = "https://api.devnet.solana.com"
        raw_amount = int(atomic_amount)

        try:
            from solders.pubkey import Pubkey
            from solders.instruction import Instruction
            from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
            from solders.message import MessageV0
            from solders.transaction import VersionedTransaction
            from solders.null_signer import NullSigner
            from solana.rpc.api import Client
            from spl.token.instructions import transfer_checked, TransferCheckedParams, get_associated_token_address
            from spl.token.constants import TOKEN_PROGRAM_ID

            # ATA (Associated Token Account) の解決
            source_ata = get_associated_token_address(payer_pubkey, mint_pubkey)
            dest_ata = get_associated_token_address(dest_pubkey, mint_pubkey)

            # RPCから最新のBlockhashを取得
            client = Client(target_rpc)
            blockhash_resp = client.get_latest_blockhash()
            recent_blockhash = blockhash_resp.value.blockhash

            instructions = []

            # 1. Compute Budget Instructions
            instructions.append(set_compute_unit_limit(200_000))
            instructions.append(set_compute_unit_price(1))

            # 2. Memo Instruction (Optional)
            if memo:
                memo_ix = Instruction(
                    program_id=Pubkey.from_string(MEMO_PROGRAM_ID_STR),
                    accounts=[],
                    data=memo.encode('utf-8')
                )
                instructions.append(memo_ix)

            # 3. SPL Token TransferChecked Instruction
            instructions.append(
                transfer_checked(
                    TransferCheckedParams(
                        program_id=TOKEN_PROGRAM_ID,
                        source=source_ata,
                        mint=mint_pubkey,
                        dest=dest_ata,
                        owner=payer_pubkey,
                        amount=raw_amount,
                        decimals=decimals,
                        signers=[]
                    )
                )
            )

            if not instructions:
                raise RuntimeError("SVM exact transaction has no instructions.")

            # Facilitator(fee_payer) を Payer として MessageV0 をコンパイル
            msg = MessageV0.try_compile(
                payer=fee_payer_pubkey,
                instructions=instructions,
                address_lookup_table_accounts=[],
                recent_blockhash=recent_blockhash
            )

            # 署名者の順序を Message の AccountKeys と一致させる (Partial Sign)
            # Payer(fee_payer) は NullSigner(ダミー署名) とし、Sender は本物の Keypair で署名する
            num_signers = msg.header.num_required_signatures
            signers = []
            for key in msg.account_keys[:num_signers]:
                if key == payer_pubkey:
                    signers.append(self.keypair)
                else:
                    signers.append(NullSigner(key))

            tx = VersionedTransaction(msg, signers)

            # Serialize & Base64 Encode
            tx_bytes = bytes(tx)
            tx_b64 = base64.b64encode(tx_bytes).decode('utf-8')

            payload = {"transaction": tx_b64}
            validate_svm_exact_payload(
                payload,
                network=network,
                asset=asset,
                amount=atomic_amount,
                pay_to=pay_to,
                fee_payer=fee_payer,
                signer_address=self.address,
                memo=memo,
            )
            return payload

        except ImportError:
            raise ImportError("Solana dependencies are missing. Install with 'pip install ln-church-agent[svm]'")
        except Exception as e:
            # 秘密鍵をログに出さないように安全にエラーをバブリング
            raise RuntimeError(f"Local SVM transaction build failed: {str(e)}")
