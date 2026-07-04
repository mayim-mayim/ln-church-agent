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
* **auth-capture Execution**: Do not implement EIP-3009 / Permit2 signing, capture, void, refund, reclaim, contract simulation, or fee-policy enforcement until the scheme is stable across official SDKs and production facilitators. Keep it strictly inspect-only.
* **Payment Auth Credential Execution**: Do not construct the `Authorization: Payment <base64url-json>` header until schemas are globally stable.
* **batch-settlement Execution**: Do not implement deposit calls, voucher signing, channel state persistence, refund handling, or claim execution.
* **MPP Session Execution**: Do not implement `intent="session"` continuous state-channel logic.
* **AWS AgentCore Direct Integration**: Do not integrate directly with managed AWS SDK logic.
* **Bazaar / MCP Paid Connectivity**: Do not implement as a stable public abstraction until the x402 Bazaar API is completely stable.
* **Token-2022 / ATA Auto-Creation**: Do not inject SPL Token-2022 extensions or ATA creation instructions into the transaction builder unless universally accepted by all facilitators.
* **Grant-like Signal Detection**: 
  * Do not implement grant marketplace / resale / broker / exchange.
  * Do not verify redeemability by calling redemption endpoints.
  * Do not auto-submit grant-like signals to Hon-den.
  * Do not treat grant-like signals as proof of availability.
  * Do not rank or recommend surfaces based on grant-like signals.
  * Grant-like signal detection is inspect-only and sidecar-only.
* **Domain Sponsor Verification**:
  * Do not treat `/.well-known/ln-church-domain-sponsor.json` as an AI discovery standard, ARD, A2A Agent Card, or standard compliance proof. It is strictly an LN Church domain-control challenge path.
  * Do not use `domain_owner_verified` as a primary semantic; it is a legacy compatibility field for `domain_control_verified`.  

### 1. Payment-Receipt Semantics & Cache Rules
* **Observation:** The IETF payment draft is expanding beyond prefix negotiation and is clarifying `Payment-Receipt` semantics, retry expectations, and cache behavior around `402`, `401`, and `403` flows. Payment-Receipt presence is not final settlement by itself. Future receipt states may include SETTLED, PENDING_FINALITY, REVERSED, CANCELLED-like categories.
* **SDK Stance:** The SDK already extracts receipt artifacts when provided, but cache-control behavior and receipt-driven retry semantics are still monitored rather than hard-coded into the stable public contract. Receipt class, settlement state, attestor, canonical reference, and reversal state are evaluated separately. Currently, verification API implementations are not enforced.