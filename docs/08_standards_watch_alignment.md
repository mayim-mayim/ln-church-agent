# Standards Watch Alignment

## Purpose
This document provides rules on how to interpret `STANDARDS_WATCHLIST.md` and establishes firm boundaries to prevent AI or human contributors from prematurely building unstable functionality.

## Interpreting the Watchlist

* **Implemented Baseline**: Features located here have been fully integrated into the SDK's stable boundary. Do not re-propose them as "new work" or "missing functionality." Only monitor them for structural upstream drift.
* **Watch Now**: High-priority ecosystem shifts. Monitor upstream drift carefully. **Only implement when strict trigger conditions are met** (e.g., official specification stabilization).
* **Design Prep**: Long-term conceptual architectures. Keep as design notes. Do not build them prematurely.
* **Explicitly Deferred**: Functionality that is explicitly halted to protect the buyer-side runtime from unstable wire-level schemas or heavy infrastructure burdens.

## Rules for Future AI Coding Agents

To maintain the safety and focus of the `ln-church-agent` SDK, **DO NOT** implement the following features under any circumstances until they are removed from the "Deferred" list:

* **AP2 / ACP / APP Payment Execution**: Do not implement mandate signing, broker negotiation calls, or ACP checkout completions. They remain strictly `observe_only`.
* **Payment Auth Credential Execution**: Do not construct the `Authorization: Payment <base64url-json>` header until schemas are globally stable.
* **batch-settlement Execution**: Do not implement deposit calls, voucher signing, channel state persistence, refund handling, or claim execution.
* **MPP Session Execution**: Do not implement `intent="session"` continuous state-channel logic.
* **AWS AgentCore Direct Integration**: Do not integrate directly with managed AWS SDK logic.
* **Bazaar / MCP Paid Connectivity**: Do not implement as a stable public abstraction until the x402 Bazaar API is completely stable.
* **Token-2022 / ATA Auto-Creation**: Do not inject SPL Token-2022 extensions or ATA creation instructions into the transaction builder unless universally accepted by all facilitators.