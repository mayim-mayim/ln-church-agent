# v1.17.0 Agent SDK release-tool archive

This directory preserves the exact PowerShell wrappers and Python runners that reached verified terminal states during the v1.17.0 release. They remain version-specific recovery assets; they are not automatically qualified for another candidate, SDK version, task, or production environment.

## Qualification record

| File | SHA-256 | Qualification |
|---|---|---|
| `V17_SDK_Candidate_50b334f0_Fresh_Reward_E2E_PS51.ps1` | `fc6f64784ee7b517312c81a5f0aaa03480f3463fc1486a41b90c2d084c3fa09e` | `PS51_EXECUTED_PASS` |
| `V17_SDK_Candidate_50b334f0_Fresh_Reward_E2E.py` | `0ffd60a11a5292a5b1dd88d5e4a7c8b9cb8390fe4e7d8f5838302aa7a470a7a2` | Python 3.11 executed PASS |
| `V17_SDK_Candidate_50b334f0_Windows_Checkpoint_Smoke_PS51.ps1` | `332b800de1d2232b189997613df9caf2a3472f19d7b935f21bf1d5fb0ce5150c` | `PS51_EXECUTED_PASS` |
| `V17_SDK_Candidate_50b334f0_Windows_Checkpoint_Smoke.py` | `8b0dca678b3c2b74f09543689e684a247ab6921f9755d638c0291a90937d7d4f` | Python 3.11 executed PASS |

Observed reward E2E terminal facts:

```text
task_status=REWARDED
reward_state=paid
amount_atomic=10000
```

Observed checkpoint terminal facts:

```text
CHECKPOINT_FIRST_WRITE=PASS
CHECKPOINT_SECOND_WRITE=PASS
CHECKPOINT_REOPEN=PASS
V17_SDK_CANDIDATE_WINDOWS_CHECKPOINT_GATE=PASS
```

## Use boundary

- Preserve all four files byte-for-byte. Any edit requires a new qualification record.
- The wrapper and runner in each pair are one qualification unit; do not mix one archived file with a regenerated counterpart.
- Reward E2E contains candidate-, wheel-, Task-, and environment-specific assumptions. A fresh claim remains a real external mutation and requires explicit Human authority.
- Resume must use the same run directory. Do not create another claim after an ambiguous interruption until read-only reconciliation establishes the prior run state.
- Checkpoint smoke is local and claim-free, but it still validates the archived candidate assumptions rather than an arbitrary future SDK.
- No claim token, wallet secret, authorization header, or raw private receipt is stored here.

Cross-project qualification rules and the current registry are maintained in `mayim-mayim/LN_Church_Development-Charter`.
