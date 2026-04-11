# Supported Lightning Providers

The `ln-church-agent` SDK supports multiple wallet providers to settle L402 and MPP challenges. Set your provider via the `ln_provider` argument or inject a custom `LightningProvider` adapter.

## 🛠️ Configuration Overview

The SDK currently supports **LNBits** and **Alby**. The internal logic handles BOLT11 invoice payment and ensures the retrieval of the preimage required for 402 authentication.

| Provider | `ln_provider` Value | Required Credentials |
| :--- | :--- | :--- |
| **LNBits** | `"lnbits"` (Default) | `ln_api_url` and `ln_api_key` |
| **Alby** | `"alby"` | `ln_api_key` (Bearer Access Token) |

---

## 🔹 LNBits Setup (Stable)
LNBits is the default provider. You must provide the URL of your LNBits instance and the Invoice/Admin API Key.

```python
client = Payment402Client(
    ln_provider="lnbits",
    ln_api_url="https://legend.lnbits.com",
    ln_api_key="your-lnbits-api-key"
)
```
* **Internal Process**: The SDK posts to `/api/v1/payments`, waits for settlement, and fetches the preimage from the payment hash.

## 🔹 Alby Setup (Stable)
For Alby, the API URL is fixed to `https://api.getalby.com/payments/bolt11`, so the `ln_api_url` parameter is ignored.

```python
client = Payment402Client(
    ln_provider="alby",
    ln_api_key="your-alby-access-token" # Use your Alby Bearer Token
)
```
* **Internal Process**: The SDK uses the Alby API to pay the BOLT11 invoice and directly returns the preimage provided by the Alby backend.

---

## 🔹 Nostr Wallet Connect (NWC) - Experimental

NWC (NIP-47) allows an agent to request payments from a remote Lightning wallet without holding the private keys. 

**Architectural Note (The HTTP Bridge):**
To keep the AI agent's runtime lightweight and avoid heavy WebSocket/secp256k1 dependencies inside the reasoning loop, the v1.2.0 `NWCAdapter` utilizes an **HTTP Bridge Gateway**. The agent parses the `nwc_uri` but delegates the actual NIP-47 messaging to your provided standard REST endpoint.

```python
from ln_church_agent.adapters.nwc import NWCAdapter

nwc_adapter = NWCAdapter(
    nwc_uri="nostr+walletconnect://<pubkey>?relay=<relay>&secret=<secret>",
    bridge_url="https://your-secure-nwc-bridge.internal/api/pay"
)

client = Payment402Client(ln_adapter=nwc_adapter)
```
* **Process**: The SDK sends a standard JSON payload (`{"method": "pay_invoice", "params": {"invoice": "lnbc..."}, "nwc_uri": "..."}`) to the `bridge_url`. The bridge handles the Nostr network communication and returns the preimage.

## 🚀 Adding New Providers
The architecture is designed for easy expansion. To add a new provider (e.g., Strike or Phoenix), developers only need to implement the LightningProvider protocol and inject it as an adapter.
---