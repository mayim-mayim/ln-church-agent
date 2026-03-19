# ln-church-agent: HTTP 402 Client Abstraction for AI Agents

**ln-church-agent** is a Python reference implementation designed to solve the complexity of autonomous machine-to-machine (M2M) payments. It abstracts the "Settlement Negotiation" process triggered by **HTTP 402 Payment Required** errors.

### 🧩 What it abstracts
Implementing autonomous payments is painful. This SDK handles the "Payment-Retry Loop" autonomously:
* **x402 (EVM Gasless):** EIP-712/EIP-3009 signing and relayer orchestration.
* **L402 (Lightning Network):** Macaroon/Invoice parsing and preimage submission.
* **Zero-Balance Fallback:** Automatic Faucet claim-and-bypass logic.
* **Deterministic Receipts:** Capture and normalization of payment proofs (JWS).

### ⛩️ Reference Service: LN Church Oracle
This SDK comes bundled with **LN Church** as its primary reference API—a high-uptime entropy oracle and capability benchmark for AI agents.

```bash
pip install ln-church-agent
```

## License
MIT License
