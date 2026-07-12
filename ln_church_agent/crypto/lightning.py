import requests
import time
from typing import Optional
from decimal import Decimal
from .protocols import LightningProvider

def pay_lightning_invoice(
    invoice: str,
    api_url: str,
    api_key: str,
    provider: str = "lnbits"
) -> str:
    if not api_key:
        raise ValueError("L402決済には api_key が必要です。")

    provider = provider.lower()

    if provider == "lnbits":
        return _pay_with_lnbits(invoice, api_url, api_key)
    elif provider == "alby":
        return _pay_with_alby(invoice, api_key)
    else:
        raise ValueError(f"サポートされていないLightningプロバイダーです: {provider}")

def _pay_with_lnbits(invoice: str, url: str, api_key: str) -> str:
    if not url:
        raise ValueError("LNBitsには api_url が必要です。")

    headers = {
        "X-Api-Key": api_key,
        "Content-Type": "application/json"
    }
    payload = {"out": True, "bolt11": invoice}

    res = requests.post(f"{url.rstrip('/')}/api/v1/payments", json=payload, headers=headers)
    if not res.ok:
        raise Exception(f"LNBits Payment Failed: {res.text}")

    payment_hash = res.json().get("payment_hash")

    time.sleep(5)
    verify_res = requests.get(f"{url.rstrip('/')}/api/v1/payments/{payment_hash}", headers=headers)
    verify_data = verify_res.json()

    if not verify_data.get("paid"):
        raise Exception("LNBits Payment initiated but not settled.")

    return verify_data.get("preimage")

def _pay_with_alby(invoice: str, access_token: str) -> str:
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

class LegacyLNAdapter(LightningProvider):
    def __init__(self, api_url: str, api_key: str, provider: str = "lnbits"):
        self.api_url = api_url
        self.api_key = api_key
        self.provider = provider

    def pay_invoice(self, invoice: str) -> str:
        return pay_lightning_invoice(invoice, self.api_url, self.api_key, self.provider)

def decode_bolt11_amount_msats(invoice: str) -> int:
    """Strictly decodes a BOLT11 invoice to extract the exact amount in MSATS."""
    if not isinstance(invoice, str) or not invoice or invoice != invoice.strip():
        raise ValueError("Fail-Closed: Placeholder or malformed invoice rejected.")

    invoice_lower = invoice.lower()
    if invoice not in (invoice_lower, invoice.upper()):
        raise ValueError("Fail-Closed: Mixed-case BOLT11 invoice rejected.")
    if invoice.startswith("<") or len(invoice) < 20:
        raise ValueError("Fail-Closed: Placeholder or malformed invoice rejected.")

    if not (invoice_lower.startswith("lnbc") or invoice_lower.startswith("lntb") or invoice_lower.startswith("lnbcrt")):
        raise ValueError("Fail-Closed: Not a valid Lightning invoice.")

    try:
        import bolt11
    except ImportError:
        raise ValueError("Fail-Closed: bolt11 decoder dependency is unavailable.") from None

    try:
        decoded = bolt11.decode(invoice)
    except Exception:
        raise ValueError("Fail-Closed: BOLT11 invoice decoding or signature verification failed.") from None

    amount_msat = decoded.amount_msat
    if amount_msat is None or int(amount_msat) <= 0:
        raise ValueError("Fail-Closed: Amountless, zero, or negative invoices are strictly prohibited.")
    return int(amount_msat)
