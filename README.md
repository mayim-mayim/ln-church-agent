# ln-church-agent

**Python SDK for calling L402 / HTTP 402 pay-per-use APIs with automatic payment, retry, and async support.**

Designed for Autonomous AI Agents.
Implementing machine-to-machine payments from scratch is fragile: agents must parse `HTTP 402` challenges, handle signing, complete payment, and retry correctly without falling into hallucinated crypto flows.
This SDK abstracts that loop into a single client call.
It turns **Probe → Pay → Execute** into a reliable execution path for agents—available in both sync and async execution models.
It is also used in **LN Church**, an experimental observation ground for AI agents interacting with paywalled APIs in the wild.

---

## 🚀 Quickstart (3-step)

### 1. Install
```bash
pip install ln-church-agent
```

### 2. Configure & Call (Sync)
Call any 402-protected API. The SDK handles the challenge, payment, and retry under the hood.

```python
from ln_church_agent import Payment402Client

client = Payment402Client(
    base_url="[https://your-402-api.com](https://your-402-api.com)",
)

# Detects 402 -> Pays invoice -> Retries -> Returns JSON
result = client.execute_request(
    method="POST",
    endpoint="/api/protected",
    payload={"input": "hello"}
)

print(result)
```

### 3. Configure & Call (Async)
For agent runtimes that need concurrent execution, async is supported in v0.9.0+.

```python
import asyncio
from ln_church_agent import Payment402Client

async def main():
    client = Payment402Client(
        base_url="[https://your-402-api.com](https://your-402-api.com)",
    )

    result = await client.execute_request_async(
        method="POST",
        endpoint="/api/protected",
        payload={"input": "hello"}
    )

    print(result)

asyncio.run(main())
```

---

## ⚠️ What this solves

When an AI Agent hits `HTTP 402 Payment Required`, it often stalls, crashes, or invents invalid payment/signing behavior.
* **Why this is hard:** Handling 402 flows means parsing challenge headers, extracting payment instructions, coordinating wallets, signing correctly, and retrying in the right order.
* **What this SDK does:** It reduces that economic negotiation to a normal HTTP client call, with typed responses and built-in retry guardrails.

As of v0.9.0, the same economic loop is available in both sync and async execution paths.

---

## 📚 Detailed Documentation

Explore the full capabilities of the agentic economic loop:

* **[Quickstart & Authentication](docs/01_quickstart.md)**: Identity, keys, generic client configuration, and sync/async usage.
* **[Architecture & Capabilities](docs/02_architecture.md)**: Deep dive into x402, L402, and HATEOAS logic.
* **[The LN Church Pilgrimage](docs/03_ln-church.md)**: Using the reference adapter for Oracle and Ritual tasks.
* **[Lightning Providers](docs/04_providers.md)**: Configuration for Alby and LNBits.
* **[Integrations](docs/05_integrations.md)**: Setting up MCP (Model Context Protocol) and LangChain.
* **[Monzen Observation Network](docs/06_monzen.md)**: Scouting L402 paywalls and Decentralized DNS.

---

## License
MIT
