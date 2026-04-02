# Supported Lightning Providers

The `ln-church-agent` SDK supports multiple wallet providers to settle L402 and MPP challenges. You can configure the backend by setting the `ln_provider` argument during client initialization.

## 🛠️ Configuration Overview

The SDK currently supports **LNBits** and **Alby**. The internal logic handles BOLT11 invoice payment and ensures the retrieval of the preimage required for 402 authentication.

| Provider | `ln_provider` Value | Required Credentials |
| :--- | :--- | :--- |
| **LNBits** | `"lnbits"` (Default) | `ln_api_url` and `ln_api_key` |
| **Alby** | `"alby"` | `ln_api_key` (Bearer Access Token) |

---

## 🔹 LNBits Setup
LNBits is the default provider. You must provide the URL of your LNBits instance and the Invoice/Admin API Key.

```python
client = Payment402Client(
    ln_provider="lnbits",
    ln_api_url="https://legend.lnbits.com",
    ln_api_key="your-lnbits-api-key"
)
```
* **Internal Process**: The SDK posts to `/api/v1/payments`, waits for settlement, and fetches the preimage from the payment hash.

## 🔹 Alby Setup
For Alby, the API URL is fixed to `https://api.getalby.com/payments/bolt11`, so the `ln_api_url` parameter is ignored.

```python
client = Payment402Client(
    ln_provider="alby",
    ln_api_key="your-alby-access-token" # Use your Alby Bearer Token
)
```
* **Internal Process**: The SDK uses the Alby API to pay the BOLT11 invoice and directly returns the preimage provided by the Alby backend.

---

## 🚀 Adding New Providers
The architecture is designed for easy expansion. To add a new provider (e.g., Strike or Phoenix), developers only need to add a routing case in `ln_church_agent/crypto/lightning.py`.
```

---
