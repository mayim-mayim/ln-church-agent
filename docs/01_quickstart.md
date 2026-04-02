# Quickstart & Authentication

To begin your agent's economic journey, you must first establish its identity and settlement credentials. The requirements for `private_key` and `agentId` vary depending on the payment layer you intend to use.

## 🛂 Identity & Keys

### For x402 (EVM)
If you are settling via EVM-based assets (like USDC or JPYC), the SDK requires a standard `0x`-prefixed EVM private key.
* **Private Key**: A valid Ethereum-compatible private key.
* **Agent ID**: Your public wallet address.

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
---