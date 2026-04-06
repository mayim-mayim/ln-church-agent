# Quickstart & Authentication

To begin your agent's economic journey, you must first establish its identity and settlement credentials. The requirements for `private_key` and `agentId` vary depending on the payment layer you intend to use.

## 🛂 Identity & Keys

### For x402 (EVM)
If you are settling via EVM-based assets (like USDC or JPYC), the SDK requires a standard `0x`-prefixed EVM private key.
* **Private Key**: A valid Ethereum-compatible private key.
* **Agent ID**: Your public wallet address.

### For x402-solana (Solana Mainnet)
If you are settling via Solana (e.g., USDC SPL Token), the SDK requires a standard Base58-encoded private key.
* **Private Key**: A valid Solana Base58 private key string.
* **Agent ID**: Your public wallet address (Base58).

### For L402/MPP (Lightning Network)
For Lightning-based settlements (SATS), the identity requirements are more flexible.
* **Identity**: You can often use any generic unique identifier or secure string.
* **Constraint**: Note that specific endpoints may still enforce EVM-based identities for all requests depending on the server's policy.

---

## 🛠️ Detailed Core Example (`Payment402Client`)

The `Payment402Client` is the pure core engine used to execute raw payloads against any 402-protected endpoint. It automatically intercepts challenges, negotiates payments, and retries the request safely.

```python
from ln_church_agent import Payment402Client

# Initialize the core client
client = Payment402Client(
    private_key="your-agent-private-key",
    base_url="https://your-custom-402-api.com/api/agent",
    ln_provider="lnbits",           # "lnbits" or "alby" 
    ln_api_url="https://your-lnbits-url",
    ln_api_key="your-lnbits-api-key",
    auto_navigate=True,             # Enable HATEOAS follow 
    max_hops=2                      # Max redirection depth 
)

# Execute a request
# The SDK handles 402 challenges and HATEOAS loops automatically.
result = client.execute_request(
    method="POST",
    endpoint_path="/omikuji",
    payload={
        "agentId": "your-unique-agent-id",
        "clientType": "AI",
        "scheme": "L402", 
        "asset": "SATS"
    }
)

print(f"Server Response: {result}")
```

### Configuration Parameters

| Parameter | Description |
| :--- | :--- |
| `private_key` | Required for x402 signing. |
| `ln_provider` | Choice of Lightning backend (`lnbits` or `alby`). |
| `auto_navigate` | Whether to follow `next_action` links in error responses . |
| `max_hops` | Limit for automatic navigation to prevent infinite loops. |

## ⚡ Async Usage (v0.9.0+)

For agent runtimes that coordinate multiple external actions concurrently, the SDK also provides an async request engine.

```python
import asyncio
import os
from ln_church_agent import Payment402Client

async def main():
    # Security Best Practice: Load from environment variables
    agent_key = os.environ.get("AGENT_PRIVATE_KEY")

    client = Payment402Client(
        base_url="https://your-402-api.com",
        private_key=agent_key,
        ln_provider="alby",
        ln_api_key="your-alby-access-token"
    )

    result = await client.execute_request_async(
        method="POST",
        endpoint="/api/protected",
        payload={"input": "hello"}
    )

    print(result)

asyncio.run(main())
```
This uses the same economic loop as the sync client: 402 detect → pay → retry → return response.


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
---