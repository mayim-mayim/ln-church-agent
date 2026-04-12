import time
import os
import requests
from typing import Optional, Protocol
from eth_account import Account

# 🚨 修正: トップレベルインポートを削除
# from eth_account.messages import encode_typed_data
from .protocols import EVMSigner

# フォールバック用辞書
TOKENS = {
    "JPYC": {"address": "0xe7c3d8c9a439fede00d2600032d5db0be71c3c29", "name": "JPY Coin", "version": "1", "decimals": 18},
    "USDC": {"address": "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", "name": "USD Coin", "version": "2", "decimals": 6}
}

# --- v1.2.0: Concrete Adapter (Default) ---
class LocalKeyAdapter(EVMSigner):
    """従来の private_key を内部に保持し、EVMSignerプロトコルを満たすデフォルトアダプター"""
    
    def __init__(self, private_key: str):
        if not private_key:
            raise ValueError("LocalKeyAdapter requires a private_key.")
        self.account = Account.from_key(private_key)

    @property
    def address(self) -> str:
        return self.account.address

    def execute_x402_gasless(
        self, asset: str, human_amount: float, relayer_url: str, treasury_address: str,
        chain_id: int = 137, token_address: str = None
    ) -> str:
        from eth_account.messages import encode_typed_data
        if not relayer_url or not treasury_address:
            raise ValueError("HATEOASエラー: Relayer URL または Treasury Address が指定されていません。")
            
        token_info = TOKENS.get(asset, {})
        contract_address = token_address or token_info.get("address")
        if not contract_address:
            raise ValueError(f"トークンアドレスが不明です: {asset}")

        token_name = token_info.get("name", "USD Coin" if asset == "USDC" else asset)
        token_version = token_info.get("version", "2" if asset == "USDC" else "1")
        decimals = token_info.get("decimals", 6 if asset == "USDC" else 18)

        value_wei = int(human_amount * (10 ** decimals))
        valid_after = 0
        valid_before = int(time.time()) + 3600 
        nonce = os.urandom(32).hex() 

        domain = {
            "name": token_name,
            "version": token_version,
            "chainId": int(chain_id),
            "verifyingContract": contract_address
        }
        
        types = {
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"}
            ]
        }
        
        message = {
            "from": self.account.address,
            "to": treasury_address,
            "value": value_wei,
            "validAfter": valid_after,
            "validBefore": valid_before,
            "nonce": bytes.fromhex(nonce)
        }

        signable_msg = encode_typed_data(domain_data=domain, message_types=types, message_data=message)
        signed_tx = self.account.sign_message(signable_msg)

        relayer_payload = {
            "token": contract_address,
            "from": self.account.address,
            "value": str(value_wei),
            "validAfter": valid_after,
            "validBefore": valid_before,
            "nonce": "0x" + nonce,
            "v": signed_tx.v,
            "r": "0x" + signed_tx.r.hex(),
            "s": "0x" + signed_tx.s.hex()
        }

        res = requests.post(relayer_url, json=relayer_payload)
        if not res.ok:
            raise Exception(f"Relayer Error: {res.text}")
            
        return res.json().get("txHash")

    def execute_x402_direct(
        self, asset: str, human_amount: float, treasury_address: str, 
        chain_id: int = 137, token_address: str = None, rpc_url: str = None
    ) -> str:
        if not treasury_address:
            raise ValueError("lnc-evm-transfer決済には treasury_address が必要です。")

        node_url = os.environ.get("EVM_RPC_URL") or rpc_url
        if not node_url:
            if chain_id == 137: node_url = "https://polygon-rpc.com"
            elif chain_id == 8453: node_url = "https://mainnet.base.org"
            else: raise ValueError(f"Unknown chain ID {chain_id}. Please provide EVM_RPC_URL.")

        token_info = TOKENS.get(asset, {})
        contract_address = token_address or token_info.get("address")
        if not contract_address:
            raise ValueError(f"トークンアドレスが不明です: {asset}")

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
            "nonce": nonce,
            "gasPrice": int(gas_price * 1.1),
            "gas": 100000,
            "to": contract_address,
            "value": 0,
            "data": tx_data,
            "chainId": int(chain_id)
        }

        signed_tx = self.account.sign_transaction(tx)
        tx_hash_hex = rpc_call("eth_sendRawTransaction", [signed_tx.raw_transaction.hex()])
        
        return tx_hash_hex