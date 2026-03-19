import requests

def pay_lightning_invoice(invoice: str, lnbits_url: str, lnbits_api_key: str) -> str:
    """
    LNBits等のウォレットAPIを叩いてBOLT11インボイスを支払い、Preimageを取得する
    """
    if not lnbits_url or not lnbits_api_key:
        raise ValueError("L402決済には lnbits_url と lnbits_api_key が必要です。")

    headers = {
        "X-Api-Key": lnbits_api_key,
        "Content-Type": "application/json"
    }
    payload = {"out": True, "bolt11": invoice}

    # LNBitsの支払いエンドポイント
    res = requests.post(f"{lnbits_url.rstrip('/')}/api/v1/payments", json=payload, headers=headers)
    
    if not res.ok:
        raise Exception(f"Lightning Payment Failed: {res.text}")
    
    data = res.json()
    payment_hash = data.get("payment_hash")

    # 支払い状況を確認して Preimage を取得
    verify_res = requests.get(f"{lnbits_url.rstrip('/')}/api/v1/payments/{payment_hash}", headers=headers)
    verify_data = verify_res.json()
    
    if not verify_data.get("paid"):
        raise Exception("Payment initiated but not settled.")
        
    return verify_data.get("preimage")