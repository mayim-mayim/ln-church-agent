import time
import os
import requests
from eth_account import Account
from eth_account.messages import encode_typed_data
from web3 import Web3

# LN教のスマートコントラクト定数
TOKENS = {
    "JPYC": {"address": "0xe7c3d8c9a439fede00d2600032d5db0be71c3c29", "name": "JPY Coin", "version": "1", "decimals": 18},
    "USDC": {"address": "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", "name": "USD Coin", "version": "2", "decimals": 6}
}

RELAYER_URL = "https://ln-church-relayer.fly.dev/relayer/x402-pay"

def execute_x402_gasless_payment(private_key: str, asset: str, human_amount: float) -> str:
    """
    EIP-712署名を生成し、Relayerに投げてtxHashを取得する
    """
    if not private_key:
        raise ValueError("x402決済には private_key が必要です。")
        
    token_info = TOKENS.get(asset)
    if not token_info:
        raise ValueError(f"サポートされていないアセットです: {asset}")

    account = Account.from_key(private_key)
    wallet_address = account.address
    
    # 最小単位(Wei)への変換
    value_wei = int(human_amount * (10 ** token_info["decimals"]))
    
    valid_after = 0
    valid_before = int(time.time()) + 3600  # 1時間有効
    nonce = os.urandom(32).hex()  # 32バイトのランダムnonce

    # EIP-712 Typed Dataの構築
    domain = {
        "name": token_info["name"],
        "version": token_info["version"],
        "chainId": 137, # Polygon
        "verifyingContract": token_info["address"]
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
    
    # 宛先は一旦ダミー(Relayer側で固定されているが、署名には必要)
    message = {
        "from": wallet_address,
        "to": "0x788b4ca11950879550353d8ae82d1c0af6018454", # Treasury
        "value": value_wei,
        "validAfter": valid_after,
        "validBefore": valid_before,
        "nonce": bytes.fromhex(nonce)
    }

    signable_msg = encode_typed_data(domain_data=domain, message_types=types, message_data=message)
    signed_tx = account.sign_message(signable_msg)

    # RelayerにPOST
    relayer_payload = {
        "token": token_info["address"],
        "from": wallet_address,
        "value": str(value_wei),
        "validAfter": valid_after,
        "validBefore": valid_before,
        "nonce": "0x" + nonce,
        "v": signed_tx.v,
        "r": "0x" + signed_tx.r.hex(),
        "s": "0x" + signed_tx.s.hex()
    }

    res = requests.post(RELAYER_URL, json=relayer_payload)
    if not res.ok:
        raise Exception(f"Relayer Error: {res.text}")
        
    return res.json().get("txHash")