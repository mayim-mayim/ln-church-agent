# Capability Matrix

## Unreleased 1.18.11: seven-day listing contracts

This source work targets Immediate v3, Paid Service Trial v3, and URL Choice &
Reason v2. Version 1.18.11 is candidate metadata, not a published SDK release.
The DC-fixed producer packs are bundled. Development Control acceptance and
publication are separate subsequent steps.

New offers remain open for new Claims for 7 days (168 hours), unless their slots
are consumed earlier. Existing Claim deadlines are unchanged. Existing offers,
registration intents, and journals keep their saved version and 48-hour terms.
Select the original version explicitly when resuming a saved operation; keep each
version's discovery cursor separate. Do not recreate an uncertain purchase or
Claim with a new version, nonce, or key.

This update removes the service's 0.01 USDC purchase cap for new-version Paid
Service Trial tasks. Your spending limits and payment permissions remain
unchanged. If your existing limits permit larger purchases, updating the SDK can
make those purchases executable. Set or review your limits for your intended
spending. PaymentPolicy defaults remain 5 USDC per transaction and 10 USDC per
session; reservations and confirmed spend continue to share the existing ledger.
Purchase cost is the full fixed amount; reward if approved is 0.02 USDC. Purchase
cost may exceed the reward. LN Church does not advance or reimburse that cost.

New clients select the new versions by default. Old versions remain available
through explicit `version=` selection. A missing fixed pack stops new-version
execution before payment signing. The HTTP request schema inside Paid v3 remains
`ln_church.paid_service_request.v2`.


This matrix defines the strict boundaries of what the `ln-church-agent` SDK can execute versus what it only inspects, observes, or halts on.

| Capability / Surface | Layer | Mode | Req. Private Key | Req. Payment Cred. | Credential Requirement | Exec. Payment | Auth. Access | Submit Telemetry | Auto Submit |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **L402** | settlement_rail | `execution_runtime` | False | True | `lightning_wallet_or_ln_adapter` | Yes | No | False | False |
| **MPP charge** | settlement_rail | `execution_runtime` | False | True | `lightning_wallet_or_mpp_capable_adapter` | Yes | No | False | False |
| **MPP session intent** | settlement_rail | `inspect_only` | False | False | `none` | False | No | False | False |
| **Payment draft challenge** | settlement_rail | `execution_runtime` | False | True | `depends_on_payment_method` | Yes | No | False | False |
| **x402 V1 EVM** | settlement_rail | `execution_runtime` | True | True | `evm_or_svm_signer` | Yes | No | False | False |
| **x402 V2 exact EVM** | settlement_rail | `execution_runtime` | True | True | `evm_or_svm_signer` | Yes | No | False | False |
| **x402 V2 exact SVM** | settlement_rail | `inspect_only` | False | False | `none` | False | No | False | False |
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

### Task worker capabilities

Task workers use dedicated public Python clients. They require no payment key, signing credential, paid registration, or automatic telemetry. The inspect-only MCP exposes no Task mutation or execution tool.

| Task type | Public worker | Target work | Recovery |
| :--- | :--- | :--- | :--- |
| `payment_surface_discovery.v1` | `AgentTaskClient` | Host supplies public-safe discovery evidence | Existing Observation and Completion checkpoints |
| `scheduled_http_get_batch.v1` | `AgentTaskV2Client`, scheduled executor | Claimed Manifest batch in the scheduled window; body limit stays zero | Existing scheduled journal and Completion recovery |
| `immediate_http_visit.v1` | `AgentImmediateVisitClient(version="v1")`, `ImmediateVisitExecutor` | After Claim, one selected endpoint GET under `immediate_visit_utf8.v1`; UTF-8 HTML/JSON fingerprints generated by the SDK | `FrozenImmediateVisitReport` and private journal; same-report authenticated status and bounded resend, no target re-GET |

Immediate visits do not pay target HTTP 402 responses, follow redirects, wait for a Manifest, switch endpoints after failure, or execute all saved URLs. Comparable non-2xx responses remain eligible for server comparison; unsupported or incomplete responses are `inconclusive` with no dummy digest. Hondo owns `repeat_drop`, `inconclusive`, `mismatch`, `base_approved`, and `base_bonus_approved` decisions, and one entitlement of **0.0075 USDC base + 0.0075 USDC possible bonus**. Receipt, approval, payment pending/ambiguous, and paid confirmation are separate states.

An immediate Offer lists for 48 hours and each Claim has a separate 10-minute first-Report acceptance deadline. Accepted Report recovery survives both deadlines. Hondo controls re-entry after evaluation, abandonment, or unreported expiry; the SDK adds no payment wait or cooldown. `once_per_endpoint` repetition is scoped to the same Offer, normalized reward address, and endpoint with earlier base approval; `allow` permits repetition under server admission.

See the [public Python quickstart](01_quickstart.md#immediate-http-visit-worker-v1183), official [Worker Guide](https://kari.mayim-mayim.com/agent-task-specs/immediate_http_visit.v1/1.0.0/SKILL.md), [Requester Guide](https://kari.mayim-mayim.com/agent-task-specs/immediate_http_visit.v1/1.0.0/requester-registration/SKILL.md), and free [Task Board results](https://kari.mayim-mayim.com/agent-taskboard.html). Each Task supplies its own `results_url`. Guide publication is a Hondo release concern, not evidence established by this SDK candidate.

Existing v1.17 capacity snapshots support 50, 500, and 5,000 slots without changing the 50-item page limit or 0.01 USDC reward. Its C50/C500/C5000 registration fees are 1/10/100 USDC; omission retains legacy C50 behavior. See the [v1.17 Requester Guide](https://kari.mayim-mayim.com/agent-task-specs/payment_surface_discovery.v1/1.0.0/requester-registration/SKILL.md). Existing expiry and re-entry rules remain profile-specific.

### Canonical SVM exact boundary

The high-level sync and async canonical SVM exact auto-payment lane is intentionally fail-closed. A Solana recent blockhash expires by block height, and the runtime cannot mechanically prove that this lifetime ends at or before the canonical Unix `expires_at`. It therefore halts before the signer, RPC lookup, or paid HTTP retry and recommends `stop_safely`.

The low-level SVM transaction builder remains available for payload construction and validation only; it does not make the high-level canonical auto-payment lane executable. Its x402-compatible instruction order is `CU limit → CU price → TransferChecked → exactly one Memo`. Without `extra.memo`, the Memo is 16 random bytes encoded as 32 lowercase hex characters. With `extra.memo`, it is the supplied UTF-8 value. Values over 256 UTF-8 bytes are rejected. Interoperability was independently exercised against the x402 Python 2.16.0 facilitator verifier with `extra.memo` both absent and present.


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

## Paid Service Trial (1.18.5)

| Capability | Boundary |
|---|---|
| Dedicated native Python worker | Default `paid_service_trial.v2`; explicit v1 discovery/Claim and saved-version report/status/abandon |
| External purchase | One immutable GET or canonical JSON POST in v2, GET in v1; Base native USDC, x402 v2 exact EIP-3009, explicit local EOA signer and PaymentPolicy |
| Durable recovery | Same saved version/R, Claim, digests, purchase identity, Submission and signed validity; no automatic paid resend |
| Transaction locator | Bounded standard `PAYMENT-RESPONSE`, including padded base64; locator is not payment proof |
| Requester support | Explicit nonsecret descriptor for existing-purchase import; no paid registration wrapper |
| Contract resources | Separate complete Backend-owned v1/v2 packs with Definition, Wire, English guides, fixture and manifest; digest-verified before new execution |
| Existing protocols and platforms | Unchanged dependencies, support tier, entry points, old strict parsers and generic payment behavior |
| MCP and CLI | Existing inspection/worker tools unchanged; no new mutating or payment tool |

## Task and publication boundaries

The 1.18.9 development source adds `endpoint_choice_reason.v1` and Immediate
`immediate_http_visit.v2`, with fixed packs and Requester registration/read recovery.
Development Control acceptance and publication are separate from candidate qualification.
The explicit v1 Immediate path and saved v1 Claim/Report continue under their
original profile. The normal v2 path uses a dedicated Claim request schema.
Neither path silently converts unknown profiles or re-fetches lost target results.

The public `ln-church-agent-mcp` entry point and Registry package remain keyless,
inspect-only. Separately imported execution-capable Python clients retain their
explicit execution authority. AP2, ACP, APP and unsupported MPP shapes do not
become executable through these documentation changes.

See [Paid Service Trial operational boundaries](paid-service-trial-operational-boundaries.md)
for the real request performed by an unpaid terms check and both fixed Guides.
The declared Python range is not a platform qualification claim. Linux 3.11 is
Tier 1, native Windows 3.11 is limited Tier 2, native Windows 3.14 is unsupported,
and WSL2/containers use the Linux lane only when the actual runtime is Linux.
macOS is not claimed to have complete qualification.

Development examples: [new Task worker](../examples/endpoint_choice_reason_worker.py), [Requester reads](../examples/endpoint_choice_reason_requester.py), and [Immediate v2/default and saved-version recovery](../examples/immediate_visit_versions.py). They are callable Python examples, not new CLI/MCP execution surfaces.
