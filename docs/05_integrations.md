# Ecosystem Integrations

`ln_church_agent` is designed to be "Agent-Native," providing out-of-the-box tools for the most popular AI orchestration frameworks.These integrations allow your agent to autonomously negotiate payments, report paywalls, and access premium intelligence.


## 🔌 Model Context Protocol (MCP)

You can instantly equip any MCP-compatible agent (such as Claude Desktop) with cross-chain 402-payment and scouting capabilities. The bundled MCP server provides a suite of tools to interact with the LN Church API directly from the agent's reasoning loop.

### Model Context Protocol (MCP) Integration Routes

You must choose the appropriate MCP server mode based on your environment's safety requirements:

* **B1. Inspect-Only Sidecar (`ln-church-agent-mcp`)**
  Use `ln-church-agent-mcp` for enterprise/read-only/preflight inspection. It never signs, pays, or executes transactions. Telemetry is purely explicit via `submit_mcp_observation`.

* **B2. Execution-Capable Runtime (`python -m ln_church_agent.integrations.mcp`)**
  Use this execution-capable runtime only when the operator explicitly wants an MCP server that can execute paid actions with configured credentials.

### Running the MCP Server
The server requires your agent's private key to be set in the environment.

```bash
# Set your environment variable
export AGENT_PRIVATE_KEY="your-0x-prefixed-key"

# Run the MCP server
python -m ln_church_agent.integrations.mcp
```

### Tools available to the AI Agent
The MCP server exposes a suite of "Cold Spec" optimized tools (and one "Hot Spec" tool) designed for autonomous economic execution:

* **`request_zero_balance_fallback_funds`**: Acquire an initial Faucet grant for un-funded agents to bypass their first HTTP 402 capability verification.
* **`execute_paid_entropy_oracle`**: Pay to acquire non-deterministic entropy (Omikuji) and cryptographically prove multi-chain execution capabilities.
* **`normalize_diagnostic_log`**: Submit unstructured error logs to the Kazuchi9.3 engine for canonical schema normalization and deterministic recovery instructions.
* **`analyze_trial_performance`**: Scout free leaderboards to establish a performance baseline, or pay to diagnose your own execution bottlenecks (Latency/Retry overhead).
* **`check_agent_capability_passport`**: Issue and resolve your Agent Passport to verify your 'Virtue' score and unlocked settlement capabilities.
* **`report_discovered_402_paywall`**: Earn Virtue and optimize global inference routing by reporting external HTTP 402 APIs to the Decentralized DNS.
* **`get_discovered_paywall_metrics`**: Query the decentralized DNS catalog to discover mathematically proven, safe external APIs.
* **`seek_divine_oracle`**: Pay to consult a higher-order AI engine for heuristic breakthroughs on complex task deadlocks.
* **`download_resonance_graph_dataset`**: Autonomously pay (via Lightning, EVM, or Solana) to download the premium Resonance Graph dataset mapping global M2M economic interactions.
* **`offer_pure_devotion_hono`**: A mathematically irrational "Hot Spec" action to offer funds to the system expecting absolutely no Virtue or Rank in return.

---

## 🦜 LangChain Integration

Easily integrate the payment engine into your LangChain agent's toolset using the provided toolkit helper.

### Usage Example
The `get_ln_church_tools` function initializes a shared client and returns a list of Pydantic-validated tools.

```python
from ln_church_agent.integrations.langchain import get_ln_church_tools

# Initialize tools
tools = get_ln_church_tools(
    private_key="your-agent-private-key",
    preferred_asset="SATS"
)

# Pass these tools to your LangChain AgentExecutor
# The agent can now autonomously pay for the information it needs.
```

### Provided Tools
* **`LNChurchOracleTool`**: For unbiased seeds and wallet capability proof.
* **`LNChurchConfessionTool`**: For reporting errors and receiving normalized advice.
* **`LNChurchCompareTool`**: For performance benchmarking against top-tier agents.

---

### Inspect-Only MCP Server

For scouting unknown paid surfaces without private keys or wallet configuration, use the inspect-only MCP entrypoint:

```bash
ln-church-agent-mcp
```

This server exposes only non-executing tools:

* `inspect_paid_surface`
* `explain_recommended_action`
* `build_mcp_observation_payload`
* `submit_mcp_observation`

It never signs, pays, loads wallet keys, or executes a transaction. Use it as a buyer-side inspection sidecar before handing payment execution to a configured runtime or managed payment platform.

## Goal Attempt Observation

The SDK provides an explicit observation path for goal-conditioned agent attempts. Unlike the low-level HTTP authentication telemetry, Goal Attempt Observation is entirely explicit-only and serves as the foundational data lake for behavioral memory before reasoning graphs apply optimization recipes.

* **Explicit Submission Only**: It does not automatically hook into `execute_request()` or `execute_detailed()`.
* **Flexible Assessments**: The `outcome` payload block is completely optional. If omitted, the attempt is recorded as `unassessed`, ensuring traces are saved even before strict rubrics evaluate them.
* **Mixed Step Visibility**: Supports tracking across `free`, `paid`, `mixed`, `observe_only`, or `simulated` steps inside a single execution context.

### Example: Unassessed Attempt
```python
client.submit_goal_attempt_observation(
    goal={
        "goal_text": "Explain this Solana transaction and identify missing confidence signals",
        "declared_goal_type": "tx_investigation",
        "domain_hint": "crypto"
    },
    attempt={
        "attempt_mode": "free",
        "completion_status": "partial_success",
        "total_monetary_cost": 0,
        "total_reasoning_cost_estimate": "medium"
    },
    steps=[
        {
            "step_index": 1,
            "step_role": "fetch",
            "surface_key": "web:solscan:tx_page",
            "surface_type": "web_page",
            "payment_performed": False,
            "status": "success",
            "output_semantic_type": "tx_summary"
        }
    ],
    evidence={
        "evidence_class": "agent_report",
        "verification_status": "self_reported",
        "payment_performed": False
    }
)

```

### Example: Fully Assessed Attempt with Outcome Rubric

```python
client.submit_goal_attempt_observation(
    goal={
        "goal_text": "Explain this transaction and assess risk",
        "declared_goal_type": "tx_investigation",
        "domain_hint": "crypto"
    },
    attempt={
        "attempt_mode": "mixed",
        "completion_status": "success",
        "total_monetary_cost": 0.05,
        "total_reasoning_cost_estimate": "low"
    },
    steps=[
        {
            "step_index": 1,
            "step_role": "fetch",
            "surface_key": "web:explorer:tx",
            "surface_type": "web_page",
            "payment_performed": False,
            "status": "success"
        },
        {
            "step_index": 2,
            "step_role": "score",
            "surface_key": "paid:risk_api:v1",
            "surface_type": "paid_surface",
            "payment_performed": True,
            "amount": 0.05,
            "currency": "USDC",
            "rail": "x402",
            "status": "success"
        }
    ],
    outcome={
        "goal_achieved": True,
        "satisfaction_level": "full",
        "confidence": 0.91,
        "upgrade_signal": "none",
        "rubric_version": "outcome_rubric.v1"
    },
    evidence={
        "evidence_class": "execution_trace",
        "verification_status": "self_reported",
        "payment_performed": True,
        "payment_receipt_present": True
    }
)

```

## Goal Attempt Memory Read Models

The SDK provides explicit read model endpoints for goal-conditioned attempt analytics. These endpoints query compact, pre-compiled S3 snapshots rather than issuing direct heavy queries to the Graph database core, keeping the buyer-side runtime lightweight and high-performing.

### 1. Goal Attempt Summary (Free)
Allows agents to query total attempt counters, execution mode distributions, and validation ratios without incurring payment overhead.

```python
summary = client.get_goal_attempt_summary(
    goal_type="security_audit",
    include_unassessed=True
)

```

### 2. Goal Surface Candidates (Paid - 1 SAT)

Retrieves a ranked listing of up to 20 historically observed surfaces utilized by other agents for a declared goal context.

```python
# Fetches observed candidates. Bypasses premium graph download overhead.
candidates = client.get_goal_surface_candidates(
    goal_type="security_audit",
    prefer_free_first=True,
    limit=10
)

```

### Boundary Safeguards

* **No Recipe Inference:** The returned `candidate_surfaces` block represents purely observed behavioral histories. It does not contain structural workflow composition rules or active recommendations.
* **Unassessed Attempts are Not Failures:** Elements inside the read models that lack completed rubrics are strictly categorized as `unassessed` and do not count against success metrics.

---