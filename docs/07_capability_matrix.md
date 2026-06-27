# Capability Matrix

This matrix defines the strict boundaries of what the `ln-church-agent` SDK can execute versus what it only inspects, observes, or halts on.

| Capability / Surface | Layer | Mode | Req. Private Key | Req. Payment Cred. | Credential Requirement | Exec. Payment | Auth. Access | Submit Telemetry | Auto Submit |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **L402** | settlement_rail | `execution_runtime` | False | True | `lightning_wallet_or_ln_adapter` | Yes | No | False | False |
| **MPP charge** | settlement_rail | `execution_runtime` | False | True | `lightning_wallet_or_mpp_capable_adapter` | Yes | No | False | False |
| **MPP session intent** | settlement_rail | `inspect_only` | False | False | `none` | False | No | False | False |
| **Payment draft challenge** | settlement_rail | `execution_runtime` | False | True | `depends_on_payment_method` | Yes | No | False | False |
| **x402 V1 EVM** | settlement_rail | `execution_runtime` | True | True | `evm_or_svm_signer` | Yes | No | False | False |
| **x402 V2 exact EVM** | settlement_rail | `execution_runtime` | True | True | `evm_or_svm_signer` | Yes | No | False | False |
| **x402 V2 exact SVM** | settlement_rail | `execution_runtime` | True | True | `evm_or_svm_signer` | Yes | No | False | False |
| **x402 exact post-settlement diagnostic endpoint** | settlement_rail | `inspect_only` | False | False | `none` | False | No | False | False |
| **x402 batch-settlement** | settlement_rail | `inspect_only` | False | False | `none` | False | No | False | False |
| **x402 auth-capture** | settlement_rail | `inspect_only` | False | False | `none` | False | No | False | False |
| **Grant / Sponsored Access** | authorization_artifact | `execution_runtime` | False | False | `scoped_grant_token` | **False** | **Yes** | False | False |
| **Grant-like Signal Detection** | incentive_signal | `inspect_only` | False | False | `none` | False | No | False | False |
| **External Observation** | observation | `explicit_observation`| False | False | `none` | False | No | True | False |
| **Sandbox Evidence** | observation | `explicit_observation`| False | False | `none` | False | No | True | False |
| **Goal Attempt Observation** | memory | `explicit_observation`| False | False | `none` | False | No | True | False |
| **Surface Preflight** | memory | `read_only` | False | False | `none` | False | No | False | False |
| **AP2** | commerce_surface | `inspect_only` | False | False | `none` | False | No | False | False |
| **ACP** | commerce_surface | `inspect_only` | False | False | `none` | False | No | False | False |
| **OKX APP** | commerce_surface | `inspect_only` | False | False | `none` | False | No | False | False |
| **Unknown / unmapped** | observation | `inspect_only` | False | False | `none` | False | No | False | False |
| **AWS AgentCore payments** | managed_platform | `inspect_only` | False | False | `none` | False | No | False | False |
| **x402 Bazaar / Discovery** | discovery | `inspect_only` | False | False | `none` | False | No | False | False |
| **OpenAPI multi-offer discovery**| discovery | `inspect_only` | False | False | `none` | False | No | False | False |


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
* **Payment draft challenge** is not blanket execution permission. Only concrete challenge shapes mapped to natively supported rails may execute. The SDK explicitly defers generating unstable `Authorization: Payment <base64url-json>` credentials until schemas completely stabilize (`does_not_construct_payment_auth_json_credential = true`). Any unsupported shapes will halt execution safely (`stop_safely`).