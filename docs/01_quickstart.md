# Quickstart: The Standard 402 Loop

To begin your agent's economic journey, you must first establish its identity and settlement credentials. The SDK turns the complex **Probe → Pay → Execute** sequence into a reliable, standard execution path.

## 🛂 Identity & Keys (Stable)

This SDK natively supports open standard machine-to-machine payment protocols.

### 🌐 Standard: x402 (EVM Networks)
For standard EVM-based assets (USDC/JPYC), the SDK requires a standard `0x`-prefixed private key.
* **Private Key**: A valid Ethereum-compatible private key. 
* **Agent ID**: Your public wallet address.

### ⚡ Standard: L402 / MPP (Lightning Network)
For standard Lightning-based settlements (SATS), the identity requirements are more flexible.
* **Identity**: Any generic unique identifier or secure string.

### ⛩️ Extended: LN Church Testbed (Solana, etc.)
For custom routing within the LN Church testbed (e.g., `lnc-solana-transfer`), a Base58-encoded private key is required.

---

## 🛠️ Basic Usage (Standard x402 Flow)

The `Payment402Client` is the core engine. For any API compliant with x402 Foundation standards, the loop is fully automated: The client intercepts the `PAYMENT-REQUIRED` header, signs the challenge, and retries with a `PAYMENT-SIGNATURE`. 

```python
from ln_church_agent import Payment402Client

# Initialize with your identity key
client = Payment402Client(
    private_key="your-agent-private-key",
    base_url="https://api.standard-402-provider.com"
)

# The SDK handles 402 challenges and captures JWS receipts automatically.
# execute_detailed is recommended to access the full settlement evidence.
result = client.execute_detailed(
    method="POST",
    endpoint_path="/api/v1/action",
    payload={"input": "data"}
)

print(f"Status: {result.response['status']}")
print(f"Receipt Token (JWS): {result.settlement_receipt.receipt_token}")
print(f"Attestation: {result.settlement_receipt.source}") # -> server_attested
```

## ⛩️ Reference Testbed: LN Church Pilgrimage

To test your agent's capabilities in the official reference environment, use the `LnChurchClient` adapter. This adapter prioritizes standard x402/L402 but supports optimized `lnc-` routes. 

```python
from ln_church_agent import LnChurchClient, AssetType

client = LnChurchClient(private_key="0x...")
client.init_probe()             
client.claim_faucet_if_empty()  

# Standard L402 is used by default for SATS
result = client.draw_omikuji(asset=AssetType.SATS)
print(f"Oracle Result: {result.result}")
```

---

## ⚡ Async Usage (v1.x)

For concurrent agent runtimes, the SDK provides an async request engine with the same economic loop.

```python
async def main():
    client = Payment402Client(base_url="https://your-402-api.com", private_key=key)
    result = await client.execute_detailed_async("POST", "/api/protected", payload={...})
    print(result.response)
```

---

## 🧪 Advanced Usage: Guardrails & NWC (v1.6+)

### 1. Setting a Payment Policy
Prevent AI hallucinations from draining wallets by enforcing strict rules. 

```python
strict_policy = PaymentPolicy(
    allowed_schemes=["L402", "x402"],
    max_spend_per_tx_usd=1.0,        # Block any transaction > $1.00 USD
    max_spend_per_session_usd=10.0   # Session-wide limit
)
```

### 2. Using NWC (Keyless Agent)
Delegate signing to a remote wallet using Nostr Wallet Connect via an HTTP Bridge. 
```python
nwc_adapter = NWCAdapter(nwc_uri="nostr+walletconnect://...", bridge_url="...")
client = Payment402Client(ln_adapter=nwc_adapter, policy=strict_policy)
```

## 🔐 Security Best Practice: Handling Private Keys

**NEVER hardcode your private key in your scripts.** Autonomous agents should always load their credentials securely from environment variables or a secret manager.

```python
import os
from ln_church_agent import Payment402Client

# Load from environment variable
AGENT_KEY = os.environ.get("AGENT_PRIVATE_KEY")
if not AGENT_KEY:
    raise ValueError("Critical Error: AGENT_PRIVATE_KEY is not set in the environment.")

client = Payment402Client(
    private_key=AGENT_KEY,
    base_url="https://kari.mayim-mayim.com/api/agent",
    # ...
)
```