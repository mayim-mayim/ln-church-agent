# Access quota: opt-in purchase and same-operation recovery

SDK 1.18.8 publication candidate, based on Charter
`563300b09e9d7ae736ea86d904b7c0077da2ce74` (index R5/R6, wire W2/W3/W6).
Development Control accepted the c3 source. On 2026-09-26 it received, via the
Human, Release's report of deployed Hondō and OpenClaw's passing live mainnet
access-purchase/GET-continuation E2E. This is a reported result, not an independent
verification here. The c4 documentation artifacts have not been live-payment
retested; publication remains a separate Release step.

## Default and explicit permission

All four Task clients identify a genuine LN HTTPS access 402 before their Task
error parser. Success models and ordinary Origin/seller 402 handling are unchanged.
The default `AccessQuotaPolicy()` has `allow=False`, `budget_atomic=0`, no signer,
and network `eip155:8453`. A wallet, Task `PaymentPolicy`, or available balance
never enables access spending. One native USDC access purchase costs 10,000
atomic units (0.01 USDC).

Share **one policy object** across the four clients to share one access budget:

```python
from ln_church_agent import AccessQuotaPolicy, AccessQuotaError
from ln_church_agent.task_client import AgentTaskClient
from ln_church_agent.task_v2_client import AgentTaskV2Client
from ln_church_agent.immediate_visit_client import AgentImmediateVisitClient
from ln_church_agent.paid_service_trial_client import PaidServiceTrialTaskClient

# existing_signer is an explicitly supplied EIP-3009 signer, e.g. the SDK's
# LocalKeyAdapter already held by the application. Never log its key or payload.
access = AccessQuotaPolicy(allow=True, budget_atomic=20_000, signer=existing_signer)
v17 = AgentTaskClient(access_quota=access)
scheduled = AgentTaskV2Client(access_quota=access)
immediate = AgentImmediateVisitClient(access_quota=access)
paid = PaidServiceTrialTaskClient(access_quota=access, claim_directory=private_directory)
```

When supplying an existing transport, put `access_quota=access` on that transport.
Each independent policy has an independent budget; creating another object or
process does not share or restore the first object's reservations.

`reserved_atomic` includes unresolved purchases. `spent_atomic` counts PAID once.
Both are USDC atomic-unit accounting for this live policy, **not remaining API
access counts**.
A lock reserves budget before signing, including across distinct parallel requests.
Only the same purchase's `FAILED_FINAL` releases its unused reservation. Signing
failure, transport loss, timeout, 503, expired results and unknown state do not.
No balance query, transfer, payment broadcast, automatic wait or background poll
is performed by policy construction.

## Pending GET: keep the session and explicitly continue

Keep the **same process, client, policy and original arguments** from the first
call through recovery. The example below is one live session. `existing_signer`
is the application's explicitly supplied signer; `check_status` and
`continue_original_request` are explicit caller decisions (booleans), not an
automatic polling policy. Each selected step runs at most once. Do not rerun the
setup, close the client or replace the policy between these steps.

<!-- c4-get-example:start -->
```python
from ln_church_agent import AccessQuotaPolicy, AccessQuotaError
from ln_church_agent.task_client import AgentTaskClient

access = AccessQuotaPolicy(allow=True, budget_atomic=10_000, signer=existing_signer)
client = AgentTaskClient(access_quota=access)
page = None
pending_purchase_id = None
pending_code = None

# First call, with fixed original arguments.
try:
    page = client.list_tasks(limit=1)
except AccessQuotaError as problem:
    if problem.code != "ACCESS_PENDING":
        raise
    # Python deletes `problem` after except; retain the fields needed later.
    pending_purchase_id = problem.operation_id
    pending_code = problem.code

# Optional caller-selected status / saved-result check in this same session.
if pending_purchase_id is not None and check_status:
    try:
        with access.read_only(pending_purchase_id):
            page = client.list_tasks(limit=1)
    except AccessQuotaError as problem:
        if problem.code != "ACCESS_PENDING":
            raise
        pending_purchase_id = problem.operation_id
        pending_code = problem.code
    else:
        # Saved result obtained: complete. Do not issue another GET as recovery.
        pending_purchase_id = None
        pending_code = None

# Caller explicitly selects continuation; this is OUTSIDE read_only.
if pending_purchase_id is not None and continue_original_request:
    try:
        page = client.list_tasks(limit=1)
    except AccessQuotaError as problem:
        if problem.code != "ACCESS_PENDING":
            raise
        pending_purchase_id = problem.operation_id
        pending_code = problem.code
    else:
        pending_purchase_id = None
        pending_code = None

if pending_purchase_id is not None:
    purchase_snapshot = access.snapshot(pending_purchase_id)
    # Still pending: return control and these fields to the caller, retaining
    # client, access and limit=1 in this process for its later decision.
    # No loop, new policy, new purchase, budget increase or client.close().
else:
    # `page` is the completed result. Close only when done with the session.
    client.close()
```
<!-- c4-get-example:end -->

`read_only` checks the purchase status and any saved result. If the original GET
has not executed, this check does **not** start it. Repeating read-only checks
cannot substitute for normal continuation. If a saved result is returned, the
request is complete: the example skips ordinary continuation even when
`continue_original_request` is true. If still pending, an explicit ordinary
`client.list_tasks(limit=1)` outside the context continues the existing operation
with its saved proof. A further pending response returns control with the same
live state; it is not a reason to repurchase or generate a new signature.

A success receipt, Tx or `spent_atomic` entry can coexist with `ACCESS_PENDING`:
**payment confirmed; original request result unconfirmed**
（支払い確認済み・元要求の結果未確認）. A receipt alone does not tell you that
the GET is unexecuted. Continue the existing operation, without a separate policy,
new purchase or new signature. Completion requires obtaining the original result
or handling its explicit terminal result error as described below.

`access.snapshot(purchase_id)` exposes whitelisted receipt and quota observations
saved at that purchase/response time. They do **not** guarantee the latest remaining
credits after later accesses. Missing counts are not invented, and the snapshot
is not automatically refreshed into a live counter. `spent_atomic` and
`reserved_atomic` account for USDC atomic units in the retained policy, not API
credits. Only Edge owns current admission and remaining credits.

Recovery state is memory-only. Ending the process loses that state; creating a
new policy after restart does **not** recover the existing purchase. Keep this
session while pending. The GET example does not authorize new resubmission of a
sent/unknown Claim; the Claim-specific recovery rules below still apply.

## Conditions and same operation

```python
try:
    claim = paid.claim_task(task_id, agent_id, reward_address,
                            idempotency_key=original_key)
except AccessQuotaError as problem:
    # Safe fields: code, operation_id, terms, origin_not_sent,
    # retry_after_seconds. terms includes reset_at, price in amount_atomic,
    # network, asset, pay_to, purchased_requests, purchase_id.
    # Return these to the caller; do not loop automatically.
    access_problem = problem
```

After explicit caller re-entry, invoke the **same client method with identical
arguments and the same policy object**. It retains method, public URL/query,
original body bytes, Content-Type, Claim key, purchase ID, challenge and proof.
Unsigned requests may continue after the free reset. Signed pending requests use
the original payment proof; no new nonce or signature is generated. One attempt
uses the existing absolute transport deadline, with at most an initial request
and its access continuation. A later caller invocation has its normal finite
attempt budget; it does not extend the Task Claim/report deadline.

For a read-only purchase check, use the original call in this context:

```python
with access.read_only(access_problem.operation_id):
    # Same original request; sends X-LN-Access-Recovery: 1 + saved challenge.
    # No PAYMENT-SIGNATURE, new settle, new purchase, or new Origin operation.
    claim = paid.claim_task(task_id, agent_id, reward_address,
                            idempotency_key=original_key)
```

The context is thread/context-local. A different request binding is rejected.
A read miss remains pending. Normal pending continuation may deliver the original
operation only when the Edge's durable dispatch fence allows it.

`ACCESS_RESULT_EXPIRED` / `ACCESS_RESULT_UNAVAILABLE` describe the result, not a
failed payment. PAID remains charged even when Origin returns 402/409/429/5xx or
its result cannot be retrieved. `access.snapshot(purchase_id)` exposes only
whitelisted receipt and quota fields; absent/unknown counts are not fabricated.
An `ACCESS_FAILED_FINAL` stops the operation. If the caller explicitly wants a
new API attempt, `access.finish_failed(purchase_id)` removes only that terminal
request binding; the next request may receive a new challenge within the budget.

### Explicit use after terminal recovery (c2)

For a **public GET**, when a confirmed PAID purchase returns either
`ACCESS_RESULT_EXPIRED` or `ACCESS_RESULT_UNAVAILABLE`, that call returns the
error and ends its saved-result recovery. It sends no fresh GET or purchase.
The next explicit call to the same GET method on the same client/policy is a
normal request: no old payment proof or challenge is sent, and Edge applies
normal admission/credit consumption. No separate reset API is needed.

```python
try:
    page = paid.list_tasks()
except AccessQuotaError as problem:
    if problem.code not in {"ACCESS_RESULT_EXPIRED", "ACCESS_RESULT_UNAVAILABLE"}:
        raise
    ended_purchase = problem.operation_id
    purchase_receipt = access.snapshot(ended_purchase)
    # Return the terminal result to the caller. Do not automatically loop.

# Later, when the caller explicitly requests current results:
page = paid.list_tasks()  # same policy, ordinary admission
```

The PAID purchase and its last receipt/quota snapshot remain available; this
historical purchase snapshot is not a live counter for later ordinary requests.
Only Edge owns the current remaining credits. Spending is counted once and
`finish_failed` still rejects PAID. A read-only lookup of the ended GET cannot
reuse its proof to fetch fresh results. Pending GETs and Claim result errors
retain their original operation; they do not take this GET-only exit.

For a **Paid Claim**, a genuine access challenge followed by `FAILED_FINAL`
establishes that its purchase cannot dispatch the original Claim. The existing
private request journal records `NOT_SENT` via `origin_not_sent=True`. The
failed access operation remains blocked until the caller explicitly finishes it:

```python
try:
    claim = paid.claim_task(task_id, agent_id, reward_address,
                            idempotency_key=original_key)
except AccessQuotaError as problem:
    if problem.code != "ACCESS_FAILED_FINAL":
        raise
    failed_purchase = problem.operation_id
    # Return to the caller for its decision; no automatic new purchase.

# Only after the caller chooses another purchase within the existing budget:
access.finish_failed(failed_purchase)  # no network call or signature
claim = paid.claim_task(task_id, agent_id, reward_address,
                        idempotency_key=original_key)
```

Use the same Task, agent, reward address and Idempotency-Key. The journal keeps
the exact original body and rejects changed inputs. The new call can receive
a new challenge and sign a new purchase; `finish_failed` itself cannot do so.
PENDING/unknown purchases cannot be finished, PAID cannot be rolled back, and
ordinary sent/unknown Claims still use readonly recovery. A readonly MISS never
authorizes a new Claim or purchase. These changes add no restart restoration.

## Claim safety and private lifetime

v17/Scheduled continue automatically only after the complete genuine access
challenge proves Origin `not_sent`. Their ordinary sent/unknown errors retain
existing UNKNOWN behavior and are not retried automatically.

Immediate `recover_claim(task_id, agent_id, reward_address,
idempotency_key=original_key)` performs a read-only lookup with the original body
and key; a missing binding never falls back to creating a Claim. Paid retains its
existing private request journal; UNKNOWN without this session's access operation
uses read-only server recovery. Pending access purchases with saved proof continue
through their original purchase. Neither path introduces a new Claim key.

Challenges/proofs are memory-only. They are not journaled, logged, included in
public exceptions, or put in package evidence. Keep the live policy object while
an access purchase is unresolved. This candidate does **not** implement restart
serialization of access purchases. After losing the policy object, do not assume
its budget was unused or recreate a purchase as recovery; use existing Claim
readonly recovery when available. v17/Scheduled cannot recover a lost Claim token
by creating a new authentication mechanism.

## Isolated testnet

An explicitly separate `AccessQuotaPolicy(network="eip155:84532", ...)` accepts
only the Architecture's Base Sepolia native USDC. This lane uses a supplied
`LocalKeyAdapter` signing account (or an account implementing `address` and
`sign_message`) and verifies its EIP-712 signature. It does not extend the generic
SDK payment trust table or silently switch a mainnet policy. Local evidence uses
synthetic signing accounts and mocked responses; no on-chain purchase is claimed.

## Wire boundary and signing deadline

Challenge parsing uses `base64(JSON payload).hex-HMAC`, with the W2 fields and
request digest `{version,method,url,content_type,body_sha256,idempotency_key}`;
GET's absent body hash is null. HMAC verification belongs to AWS. SDK validation
checks the trusted LN endpoint, matching body/PAYMENT-REQUIRED, v2 requirements,
resource URL, purchase identifier, exact request binding, fixed terms and Origin
`not_sent`. These checks remain required alongside network, token, recipient and nonce
validation. For the signing-expiry boundary, the server requires
`current_time < validBefore <= expires_at`; the SDK generates
`validBefore = expires_at`. Equality is the SDK's choice, not the server's only
permitted value or the entirety of signature validation.

The reported live E2E used the accepted c3 SDK source and deployed Hondō source;
local synthetic example checks below that boundary are not independent proof of
that live result, nor a live test of the rebuilt c4 artifacts.
