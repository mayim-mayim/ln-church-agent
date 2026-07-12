import time
import os
import requests
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import Optional, Dict, Any, Mapping, Tuple
from eth_account import Account
from eth_account.messages import encode_typed_data

# モデルとプロトコルのインポート
from .protocols import EVMSigner
from ..models import ParsedChallenge

# フォールバック用辞書
TOKENS = {
    "JPYC": {"address": "0xe7c3d8c9a439fede00d2600032d5db0be71c3c29", "name": "JPY Coin", "version": "1", "decimals": 18},
    "USDC": {"address": "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", "name": "USD Coin", "version": "2", "decimals": 6}
}

_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ATOMIC_AMOUNT_RE = re.compile(r"^[1-9][0-9]*$")
_UINT_RE = re.compile(r"^(0|[1-9][0-9]*)$")
_BYTES32_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_SIGNATURE_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{130}$")


@dataclass(frozen=True)
class EIP3009TokenMetadata:
    asset: str
    name: str
    version: str
    decimals: int


# EIP-712 domain values are security inputs. They are selected only by the
# canonical chain/contract pair and are never inferred from untrusted symbols.
TRUSTED_EIP3009_TOKENS: Mapping[Tuple[int, str], EIP3009TokenMetadata] = MappingProxyType({
    (8453, "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"): EIP3009TokenMetadata(
        asset="USDC", name="USD Coin", version="2", decimals=6
    ),
    (137, "0x2791bca1f2de4661ed88a30c99a7a9449aa84174"): EIP3009TokenMetadata(
        asset="USDC", name="USD Coin (PoS)", version="2", decimals=6
    ),
    (137, "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359"): EIP3009TokenMetadata(
        asset="USDC", name="USD Coin", version="2", decimals=6
    ),
    (137, "0xe7c3d8c9a439fede00d2600032d5db0be71c3c29"): EIP3009TokenMetadata(
        asset="JPYC", name="JPY Coin", version="1", decimals=18
    ),
})

EIP3009_TYPES = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}


def is_valid_evm_address(value: Any) -> bool:
    """Return True only for an explicit 20-byte hexadecimal EVM address."""
    return (
        isinstance(value, str)
        and _EVM_ADDRESS_RE.fullmatch(value) is not None
        and int(value[2:], 16) != 0
    )


def validate_evm_address(value: Any, field_name: str = "address") -> str:
    if not is_valid_evm_address(value):
        raise ValueError(f"Invalid {field_name}: expected a 20-byte 0x-prefixed EVM address.")
    return value


def _validate_chain_id(chain_id: Any) -> int:
    if isinstance(chain_id, bool):
        raise ValueError("Invalid EVM chain ID.")
    try:
        normalized = int(chain_id)
    except (TypeError, ValueError):
        raise ValueError("Invalid EVM chain ID.") from None
    if normalized <= 0 or str(chain_id).strip() != str(normalized):
        raise ValueError("Invalid EVM chain ID.")
    return normalized


def _validate_atomic_amount(value: Any) -> str:
    if not isinstance(value, str) or _ATOMIC_AMOUNT_RE.fullmatch(value) is None:
        raise ValueError("Invalid atomic amount: expected a canonical positive integer string.")
    return value


def _human_amount_to_atomic(human_amount: Any, decimals: int) -> str:
    try:
        amount = Decimal(str(human_amount))
    except (InvalidOperation, TypeError, ValueError):
        raise ValueError("Invalid human-readable token amount.") from None
    if not amount.is_finite() or amount <= 0:
        raise ValueError("Invalid human-readable token amount.")
    scaled = amount * (Decimal(10) ** decimals)
    if scaled != scaled.to_integral_value():
        raise ValueError("Token amount cannot be represented exactly in atomic units.")
    return _validate_atomic_amount(format(scaled, "f").split(".", 1)[0])


def _parse_uint(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"Invalid EIP-3009 {field_name}.")
    if isinstance(value, int):
        normalized = str(value)
    elif isinstance(value, str):
        normalized = value
    else:
        raise ValueError(f"Invalid EIP-3009 {field_name}.")
    if _UINT_RE.fullmatch(normalized) is None:
        raise ValueError(f"Invalid EIP-3009 {field_name}.")
    parsed = int(normalized)
    if parsed >= 2 ** 256:
        raise ValueError(f"Invalid EIP-3009 {field_name}.")
    return parsed


def get_trusted_eip3009_metadata(
    chain_id: Any, token_address: Any, asset: Optional[str] = None
) -> EIP3009TokenMetadata:
    normalized_chain = _validate_chain_id(chain_id)
    normalized_contract = validate_evm_address(token_address, "token contract").lower()
    metadata = TRUSTED_EIP3009_TOKENS.get((normalized_chain, normalized_contract))
    if metadata is None:
        raise ValueError("Unknown EIP-3009 network/token contract pair.")
    if asset is not None and (not isinstance(asset, str) or asset.upper() != metadata.asset):
        raise ValueError("EIP-3009 asset does not match the trusted token contract.")
    return metadata


def build_eip3009_typed_data(
    *, chain_id: Any, token_address: Any, asset: str,
    authorization: Mapping[str, Any]
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    """Build typed data exclusively from registry metadata and validated fields."""
    if not isinstance(authorization, Mapping):
        raise ValueError("Invalid EIP-3009 authorization object.")
    metadata = get_trusted_eip3009_metadata(chain_id, token_address, asset)
    from_address = validate_evm_address(authorization.get("from"), "authorization.from")
    to_address = validate_evm_address(authorization.get("to"), "authorization.to")
    value = _parse_uint(authorization.get("value"), "value")
    valid_after = _parse_uint(authorization.get("validAfter"), "validAfter")
    valid_before = _parse_uint(authorization.get("validBefore"), "validBefore")
    nonce = authorization.get("nonce")
    if not isinstance(nonce, str) or _BYTES32_RE.fullmatch(nonce) is None:
        raise ValueError("Invalid EIP-3009 nonce: expected 32-byte hex.")

    domain = {
        "name": metadata.name,
        "version": metadata.version,
        "chainId": _validate_chain_id(chain_id),
        "verifyingContract": validate_evm_address(token_address, "token contract"),
    }
    message = {
        "from": from_address,
        "to": to_address,
        "value": value,
        "validAfter": valid_after,
        "validBefore": valid_before,
        "nonce": bytes.fromhex(nonce[2:]),
    }
    return domain, EIP3009_TYPES, message


def validate_eip3009_payload(
    payload: Any, *, expected_signer: Any, chain_id: Any,
    token_address: Any, asset: str, atomic_amount: Any, pay_to: Any,
    now: Optional[int] = None
) -> str:
    """Validate signer output against one canonical EIP-3009 requirement."""
    if not isinstance(payload, Mapping):
        raise ValueError("Invalid or incomplete EIP-3009 payload.")
    if set(payload.keys()) != {"authorization", "signature"}:
        raise ValueError("Unexpected EIP-3009 payload fields.")
    authorization = payload.get("authorization")
    signature = payload.get("signature")
    if not isinstance(authorization, Mapping):
        raise ValueError("Invalid or incomplete EIP-3009 payload.")
    if set(authorization.keys()) != {
        "from", "to", "value", "validAfter", "validBefore", "nonce"
    }:
        raise ValueError("Unexpected EIP-3009 authorization fields.")
    if not isinstance(signature, str) or _SIGNATURE_RE.fullmatch(signature) is None:
        raise ValueError("Invalid EIP-3009 signature format.")

    normalized_signer = validate_evm_address(expected_signer, "signer address")
    normalized_pay_to = validate_evm_address(pay_to, "payTo")
    normalized_amount = _validate_atomic_amount(atomic_amount)
    get_trusted_eip3009_metadata(chain_id, token_address, asset)

    auth_from = validate_evm_address(authorization.get("from"), "authorization.from")
    auth_to = validate_evm_address(authorization.get("to"), "authorization.to")
    if auth_from.lower() != normalized_signer.lower():
        raise ValueError("EIP-3009 authorization.from does not match the signer.")
    if auth_to.lower() != normalized_pay_to.lower():
        raise ValueError("EIP-3009 authorization.to does not match canonical payTo.")
    if not isinstance(authorization.get("value"), str) or authorization["value"] != normalized_amount:
        raise ValueError("EIP-3009 authorization.value does not match the canonical atomic amount.")

    valid_after = _parse_uint(authorization.get("validAfter"), "validAfter")
    valid_before = _parse_uint(authorization.get("validBefore"), "validBefore")
    verification_time = int(time.time()) if now is None else _parse_uint(now, "verification time")
    if valid_after >= valid_before or not (valid_after < verification_time < valid_before):
        raise ValueError("EIP-3009 authorization time window is not currently valid.")

    domain, types, message = build_eip3009_typed_data(
        chain_id=chain_id,
        token_address=token_address,
        asset=asset,
        authorization=authorization,
    )
    normalized_signature = signature if signature.startswith("0x") else "0x" + signature
    try:
        signable_message = encode_typed_data(
            domain_data=domain, message_types=types, message_data=message
        )
        recovered = Account.recover_message(signable_message, signature=normalized_signature)
    except Exception:
        raise ValueError("EIP-3009 signature recovery failed.") from None
    if recovered.lower() != normalized_signer.lower():
        raise ValueError("Recovered EIP-3009 signer does not match the configured signer.")
    return recovered

# ==========================================
# 1. 標準 x402 規格用の証明生成 (新規)
# ==========================================
def sign_standard_x402_evm(private_key: str, challenge: ParsedChallenge) -> str:
    """
    x402 Foundation 標準に準拠した証明文字列を生成します。
    形式: <macaroon_base64>:<txHash_or_signature>
    """
    macaroon = challenge.parameters.get("macaroon") or challenge.parameters.get("token") or ""

    tx_hash = challenge.parameters.get("txHash", "")
    return f"{macaroon}:{tx_hash}"

# ==========================================
# 2. Concrete Adapter (LocalKeyAdapter)
# ==========================================
class LocalKeyAdapter(EVMSigner):
    """従来の private_key を内部に保持し、EVMSignerプロトコルを満たすデフォルトアダプター"""

    def __init__(self, private_key: str):
        if not private_key:
            raise ValueError("LocalKeyAdapter requires a private_key.")
        self.account = Account.from_key(private_key)
        validate_evm_address(self.account.address, "signer address")

    @property
    def address(self) -> str:
        return self.account.address

    def execute_lnc_evm_relay_settlement(
        self, asset: str, human_amount: float, relayer_url: str, treasury_address: str,
        chain_id: int = 137, token_address: str = None
    ) -> str:
        if not relayer_url or not treasury_address:
            raise ValueError("HATEOASエラー: Relayer URL または Treasury Address が指定されていません。")

        validate_evm_address(treasury_address, "treasury address")
        token_info = TOKENS.get(asset, {})
        contract_address = token_address or token_info.get("address")
        if not contract_address:
            raise ValueError(f"トークンアドレスが不明です: {asset}")
        metadata = get_trusted_eip3009_metadata(chain_id, contract_address, asset)
        atomic_amount = _human_amount_to_atomic(human_amount, metadata.decimals)
        signed_payload = self.generate_eip3009_payload_atomic(
            asset, atomic_amount, treasury_address, chain_id, contract_address
        )
        authorization = signed_payload["authorization"]
        signature = signed_payload["signature"]
        sig_hex = signature[2:] if signature.startswith("0x") else signature

        relayer_payload = {
            "token": contract_address,
            "from": authorization["from"],
            "to": authorization["to"],
            "value": authorization["value"],
            "validAfter": int(authorization["validAfter"]),
            "validBefore": int(authorization["validBefore"]),
            "nonce": authorization["nonce"],
            "v": int(sig_hex[128:130], 16),
            "r": "0x" + sig_hex[0:64],
            "s": "0x" + sig_hex[64:128],
            "chainId": _validate_chain_id(chain_id)
        }

        res = requests.post(relayer_url, json=relayer_payload)
        if not res.ok:
            raise Exception(f"Relayer Error: {res.text}")

        data = res.json()
        tx_hash = data.get("txHash")

        if not tx_hash:
            raise Exception(f"Relayer returned 200 OK but no txHash found. Response: {data}")

        return tx_hash

    def execute_lnc_evm_transfer_settlement(
        self, asset: str, human_amount: float, treasury_address: str,
        chain_id: int = 137, token_address: str = None, rpc_url: str = None
    ) -> str:
        if not treasury_address:
            raise ValueError("A treasury_address is required for lnc-evm-transfer payments.")
        validate_evm_address(treasury_address, "treasury address")
        validate_evm_address(self.account.address, "signer address")

        node_url = os.environ.get("EVM_RPC_URL") or rpc_url
        if not node_url:
            if chain_id == 137: node_url = "https://polygon-rpc.com"
            elif chain_id == 8453: node_url = "https://mainnet.base.org"
            else: raise ValueError(f"Unknown chain ID {chain_id}. Please provide EVM_RPC_URL.")

        token_info = TOKENS.get(asset, {})
        contract_address = token_address or token_info.get("address")
        if not contract_address:
            raise ValueError(f"The token address is unknown: {asset}")
        validate_evm_address(contract_address, "token contract")

        from eth_utils import to_checksum_address
        contract_address = to_checksum_address(contract_address)

        decimals = token_info.get("decimals", 6 if asset == "USDC" else 18)
        value_wei = int(human_amount * (10 ** decimals))

        def rpc_call(method, params):
            res = requests.post(node_url, json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1})
            if not res.ok: raise Exception(f"RPC Error: {res.text}")
            data = res.json()
            if "error" in data: raise Exception(f"RPC Error: {data['error']}")
            return data["result"]

        nonce_hex = rpc_call("eth_getTransactionCount", [self.account.address, "pending"])
        nonce = int(nonce_hex, 16)

        gas_price_hex = rpc_call("eth_gasPrice", [])
        gas_price = int(gas_price_hex, 16)

        method_id = "a9059cbb"
        padded_to = treasury_address.lower().replace("0x", "").rjust(64, "0")
        padded_value = hex(value_wei).replace("0x", "").rjust(64, "0")
        tx_data = f"0x{method_id}{padded_to}{padded_value}"

        tx = {
            "nonce": nonce, "gasPrice": int(gas_price * 1.1), "gas": 100000,
            "to": contract_address, "value": 0, "data": tx_data, "chainId": int(chain_id)
        }

        signed_tx = self.account.sign_transaction(tx)

        raw_tx_payload = signed_tx.raw_transaction.hex()
        if not raw_tx_payload.startswith("0x"):
            raw_tx_payload = "0x" + raw_tx_payload

        tx_hash_hex = rpc_call("eth_sendRawTransaction", [raw_tx_payload])
        return tx_hash_hex

    # 既存のレガシー互換メソッド (破壊的変更を回避・プロトコル要件)
    def generate_eip3009_payload(
        self, asset: str, human_amount: float, treasury_address: str,
        chain_id: int = 137, token_address: str = None
    ) -> dict:
        token_info = TOKENS.get(asset, {})
        contract_address = token_address or token_info.get("address")
        if not contract_address:
            raise ValueError(f"The token address is unknown: {asset}")
        metadata = get_trusted_eip3009_metadata(chain_id, contract_address, asset)
        atomic_amount_str = _human_amount_to_atomic(human_amount, metadata.decimals)
        return self.generate_eip3009_payload_atomic(asset, atomic_amount_str, treasury_address, chain_id, token_address)

    # P0-B: 安全な Atomic パス (オプショナルCapabilityとして追加。client.pyが優先利用する)
    def generate_eip3009_payload_atomic(
        self, asset: str, atomic_amount_str: str, treasury_address: str,
        chain_id: int = 137, token_address: str = None
    ) -> dict:
        atomic_amount_str = _validate_atomic_amount(atomic_amount_str)
        validate_evm_address(treasury_address, "treasury address")
        validate_evm_address(self.account.address, "signer address")

        token_info = TOKENS.get(asset, {})
        contract_address = token_address or token_info.get("address")
        if not contract_address:
            raise ValueError(f"The token address is unknown: {asset}")
        get_trusted_eip3009_metadata(chain_id, contract_address, asset)

        valid_after = 0
        valid_before = int(time.time()) + 3600
        authorization = {
            "from": self.account.address,
            "to": treasury_address,
            "value": atomic_amount_str,
            "validAfter": str(valid_after),
            "validBefore": str(valid_before),
            "nonce": "0x" + os.urandom(32).hex(),
        }
        domain, types, message = build_eip3009_typed_data(
            chain_id=chain_id,
            token_address=contract_address,
            asset=asset,
            authorization=authorization,
        )
        signable_msg = encode_typed_data(
            domain_data=domain, message_types=types, message_data=message
        )
        signed_tx = self.account.sign_message(signable_msg)

        signature_hex = signed_tx.signature.hex()
        if not signature_hex.startswith("0x"):
            signature_hex = "0x" + signature_hex

        payload = {
            "signature": signature_hex,
            "authorization": authorization,
        }
        validate_eip3009_payload(
            payload,
            expected_signer=self.account.address,
            chain_id=chain_id,
            token_address=contract_address,
            asset=asset,
            atomic_amount=atomic_amount_str,
            pay_to=treasury_address,
        )
        return payload

def execute_x402_gasless(private_key: str, challenge: ParsedChallenge, relayer_url: str) -> str:
    adapter = LocalKeyAdapter(private_key)
    asset = challenge.asset
    amount = challenge.amount
    treasury = challenge.parameters.get("destination")
    chain_id = int(challenge.parameters.get("chain_id", 137))
    token_addr = challenge.parameters.get("token_address")
    return adapter.execute_lnc_evm_relay_settlement(asset, amount, relayer_url, treasury, chain_id, token_addr)

def execute_x402_direct(private_key: str, challenge: ParsedChallenge) -> str:
    adapter = LocalKeyAdapter(private_key)
    asset = challenge.asset
    amount = challenge.amount
    treasury = challenge.parameters.get("destination")
    chain_id = int(challenge.parameters.get("chain_id", 137))
    token_addr = challenge.parameters.get("token_address")
    return adapter.execute_lnc_evm_transfer_settlement(asset, amount, treasury, chain_id, token_addr)
