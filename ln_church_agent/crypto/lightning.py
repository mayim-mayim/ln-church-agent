import requests
import time
from typing import Optional

def pay_lightning_invoice(
    invoice: str, 
    api_url: str, 
    api_key: str, 
    provider: str = "lnbits"
) -> str:
    """
    指定されたウォレットプロバイダーのAPIを叩いてBOLT11インボイスを支払い、Preimageを取得する
    """
    if not api_key:
        raise ValueError("L402決済には api_key が必要です。")

    provider = provider.lower()

    # プロバイダーごとに処理を振り分け
    if provider == "lnbits":
        return _pay_with_lnbits(invoice, api_url, api_key)
    elif provider == "alby":
        return _pay_with_alby(invoice, api_key)
    # 今後StrikeやLNDを追加する場合はここに elif を足すだけ！
    else:
        raise ValueError(f"サポートされていないLightningプロバイダーです: {provider}")

def _pay_with_lnbits(invoice: str, url: str, api_key: str) -> str:
    """既存の LNBits 決済ロジック"""
    if not url:
        raise ValueError("LNBitsには api_url が必要です。")
        
    headers = {
        "X-Api-Key": api_key,
        "Content-Type": "application/json"
    }
    payload = {"out": True, "bolt11": invoice}

    # 支払い実行
    res = requests.post(f"{url.rstrip('/')}/api/v1/payments", json=payload, headers=headers)
    if not res.ok:
        raise Exception(f"LNBits Payment Failed: {res.text}")
    
    payment_hash = res.json().get("payment_hash")

    # Preimageの取得（支払いが完了するまで少し待つ必要がある場合があります）
    time.sleep(1) # 決済完了のバッファ
    verify_res = requests.get(f"{url.rstrip('/')}/api/v1/payments/{payment_hash}", headers=headers)
    verify_data = verify_res.json()
    
    if not verify_data.get("paid"):
        raise Exception("LNBits Payment initiated but not settled.")
        
    return verify_data.get("preimage")

def _pay_with_alby(invoice: str, access_token: str) -> str:
    """新規追加: NWC/Alby API 決済ロジック"""
    # AlbyはURLが固定なので引数のURLは無視してOK
    alby_url = "https://api.getalby.com/payments/bolt11"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    payload = {"invoice": invoice}

    res = requests.post(alby_url, json=payload, headers=headers)
    if not res.ok:
        raise Exception(f"Alby Payment Failed: {res.text}")
    
    data = res.json()
    preimage = data.get("preimage")
    
    if not preimage:
        raise Exception("Alby Payment succeeded but preimage was not returned.")
        
    return preimage