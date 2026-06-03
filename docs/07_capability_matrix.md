# Capability Matrix

This matrix defines the strict boundaries of what the `ln-church-agent` SDK can execute versus what it only inspects, observes, or halts on.

| Capability / Surface | Layer | Current SDK Support | Inspect Behavior | Execution Behavior | Proof Semantics | Default Recommended Action | Watchlist Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **L402** | settlement_rail | `executable_now` | `supported_but_not_executed_in_inspect` | `execute` | `verified` | `pay_and_verify` | `implemented` |
| **MPP charge** | settlement_rail | `executable_now` | `supported_but_not_executed_in_inspect` | `execute` | `verified` | `pay_and_verify` | `implemented` |
| **MPP session intent** | settlement_rail | `stop_safely` | `stop_safely` | `halt` | `unverified` | `stop_safely` | `watch_only` |
| **Payment draft challenge** | settlement_rail | `executable_now` | `supported_but_not_executed_in_inspect` | `execute` | `verified` | `pay_and_verify` | `implemented` |
| **x402 V1 EVM** | settlement_rail | `executable_now` | `supported_but_not_executed_in_inspect` | `execute` | `verified` | `pay_and_verify` | `implemented` |
| **x402 V2 exact EVM** | settlement_rail | `executable_now` | `supported_but_not_executed_in_inspect` | `execute` | `verified` | `pay_and_verify` | `implemented` |
| **x402 V2 exact SVM** | settlement_rail | `executable_now` | `supported_but_not_executed_in_inspect` | `execute` | `verified` | `pay_and_verify` | `implemented` |
| **x402 exact post-settlement diagnostic endpoint** | settlement_rail | `observe_only` | `observe_only` | `halt` | `post_settlement_proof_required` | `observe_only` | `implemented` |
| **x402 batch-settlement** | settlement_rail | `observe_only` | `observe_only` | `halt` | `deferred_voucher_not_settlement_proof` | `observe_only` | `implemented` |
| **x402 auth-capture** | settlement_rail | `observe_only` | `observe_only` | `halt` | `authorization_signature_not_settlement_proof` | `observe_only` | `watch_only` |
| **Grant / Sponsored Access** | authorization_artifact | `executable_now` | `inspect_supported` | `execute` | `verified` | `use_grant` | `implemented` |
| **Grant-like Signal Detection** | incentive_signal | `observe_only` | `sidecar_detection` | `none` | `unverified_signal_not_grant_proof` | `observe_only` | `experimental` |
| **External Observation** | observation | `explicit_only` | `observe_only` | `none` | `unverified` | `observe_only` | `implemented` |
| **Sandbox Evidence** | observation | `explicit_only` | `observe_only` | `none` | `unverified` | `observe_only` | `implemented` |
| **Goal Attempt Observation** | memory | `explicit_only` | `observe_only` | `none` | `unverified` | `observe_only` | `implemented` |
| **AP2** | commerce_surface | `observe_only` | `observe_only` | `halt` | `authorization_or_commerce_artifact_not_settlement_proof` | `observe_only` | `watch_only` |
| **ACP** | commerce_surface | `observe_only` | `observe_only` | `halt` | `authorization_or_commerce_artifact_not_settlement_proof` | `observe_only` | `watch_only` |
| **OKX APP** | commerce_surface | `observe_only` | `observe_only` | `halt` | `authorization_or_commerce_artifact_not_settlement_proof` | `observe_only` | `watch_only` |
| **Unknown / unmapped** | observation | `unsupported_or_unmapped` | `observe_only` | `halt` | `not_verified` | `reject_invalid` | `implemented` |
| **AWS AgentCore payments** | managed_platform | `unsupported_or_unmapped` | `observe_only` | `none` | `not_verified` | `observe_only` | `watch_only` |
| **x402 Bazaar / Discovery** | discovery | `unsupported_or_unmapped` | `observe_only` | `none` | `not_verified` | `observe_only` | `watch_only` |
| **OpenAPI multi-offer discovery** | discovery | `unsupported_or_unmapped` | `observe_only` | `none` | `not_verified` | `observe_only` | `watch_only` |

### Semantic Glossary
* **`classified`** is not payment success.
* **`observe_only`** is not proof.
* **`authorization_artifact`** is not settlement proof.
* **`verified`** requires cryptographic proof, submitted tx evidence, L402 preimage, or a signed provider receipt.
* **AP2 / ACP / OKX APP** are not settlement rails.
* **Grant** is an access override / sponsored entitlement, not a settlement rail.
* **batch-settlement voucher** is not a final settlement proof.
* **auth-capture authorization signature** is not final settlement proof.
* **capture / void / refund / reclaim lifecycle state** must not be collapsed into a single verified payment state.
* **Payment-Receipt presence** is not final settlement by itself. Future receipt states may include SETTLED, PENDING_FINALITY, REVERSED, CANCELLED-like categories. Receipt class, settlement state, attestor, canonical reference, and reversal state must be evaluated separately.
* **Goal Surface Candidates** are observed historical memories, not automated recommendations.