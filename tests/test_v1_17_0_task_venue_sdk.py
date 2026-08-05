import hashlib
import inspect
import json
import os
import stat
import sys
import traceback
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from ln_church_agent.task_client import AgentTaskClient
from ln_church_agent.task_contract import (
    MAXIMUM_JSON_BYTES,
    PUBLIC_API_ORIGIN,
    canonical_submission_digest_hex,
    claim_token_storage_digest_hex,
    task_claim_path,
    task_completion_path,
    task_detail_path,
    task_observation_path,
    task_submission_status_path,
    to_eip55_checksum_address,
    validate_public_domain,
)
from ln_church_agent.task_models import (
    AgentTask,
    AgentTaskClaim,
    AgentTaskClaimResponse,
    AgentTaskCompletionResponse,
    AgentTaskDetailQuery,
    AgentTaskExecutionSummary,
    AgentTaskListItem,
    AgentTaskPage,
    AgentTaskPocTerms,
    AgentTaskRewardTerms,
    AgentTaskRewardStatus,
    TaskDefinitionReference,
    TaskClaimCredential,
    TaskDiscoveredSurfaceEntry,
    TaskDomainObservationCheckpoint,
    TaskDomainObservationCheckpointState,
    TaskDomainObservationGuidedResult,
    TaskDomainObservationResponse,
    TaskDomainObservationSubmission,
    TaskObservationErrorEntry,
    TaskObservedUrlEntry,
    TaskVerificationCostVector,
    verify_reward_status_transition,
    verify_task_execution_summary,
)
from ln_church_agent.task_transport import (
    TASK_API_HOST,
    TASK_API_PORT,
    TaskAPIError,
    TaskAmbiguousOutcomeError,
    TaskTransport,
    TaskTransportError,
    TaskTransportResponse,
    _TaskExchangeBudget,
    _encode_body,
    _new_pinned_httpx_transport,
    _resolve_addresses_bounded,
    _validate_query,
)


CLAIM_TOKEN = "A" * 43
FIXTURE_SHA256 = (
    "a2ec940297ad4a342596b06ef3024a4c3799f64c4a72fdb5d91c690e9fab47f1"
)
REWARD_ADDRESS = "0x1111111111111111111111111111111111111111"
TASK_TYPE = "payment_surface_discovery.v1"
TASK_DEFINITION_VERSION = "1.0.0"
TASK_DEFINITION_DIGEST = (
    "9e5d340f746c957ac9e9363c0af8ef72f0fe2bc8ea4bc4b55d1f7006b5448406"
)
MANIFEST_URL = (
    "https://kari.mayim-mayim.com/agent-task-specs/"
    "payment_surface_discovery.v1/1.0.0/"
    "9e5d340f746c957ac9e9363c0af8ef72f0fe2bc8ea4bc4b55d1f7006b5448406/"
    "manifest.json"
)
MANIFEST_SHA256 = (
    "77d6960e6ecb45c85cc63728cf930ad8977026083253280e64153be48b92e1f9"
)
SUBMISSION_ID = "sub_" + "0" * 32
OBSERVATION_ID = "obs_example"


def _definition_payload(**overrides):
    payload = {
        "task_definition_version": TASK_DEFINITION_VERSION,
        "task_definition_digest": TASK_DEFINITION_DIGEST,
        "manifest_url": MANIFEST_URL,
        "manifest_sha256": MANIFEST_SHA256,
    }
    payload.update(overrides)
    return payload


def _definition():
    return TaskDefinitionReference(**_definition_payload())


def _assert_finite_exception_graph(error, *forbidden_values):
    seen = set()
    current = error
    graph = []
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        graph.append(current)
        current = current.__cause__ or current.__context__
    assert graph == [error]
    assert error.__cause__ is None
    assert error.__context__ is None
    for item in graph:
        surfaces = [str(item), repr(item), repr(vars(item))]
        structured = getattr(item, "errors", None)
        if callable(structured):
            surfaces.append(repr(structured()))
        for forbidden in forbidden_values:
            assert all(forbidden not in surface for surface in surfaces)


def _reward(amount_atomic="10000", **overrides):
    payload = {
        "network": "eip155:8453",
        "asset": "USDC",
        "asset_address": (
            "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
        ),
        "amount_atomic": amount_atomic,
    }
    payload.update(overrides)
    return payload


def _reward_terms(amount_atomic="10000"):
    return AgentTaskRewardTerms.model_validate(_reward(amount_atomic))


def _poc_terms():
    return {
        "completion_2xx_meaning": "durable_receipt_only",
        "completion_2xx_implies_evaluation_approval": False,
        "completion_2xx_implies_payment_completion": False,
        "payout_mode": (
            "automatic_best_effort_with_finite_retry_and_recorded_evidence"
        ),
        "payment_completion_sla": False,
        "individual_investigation": False,
        "manual_resend": False,
        "compensation": False,
        "alternative_payment": False,
        "arbitrary_non_payment_authorized": False,
        "required_public_surfaces": [
            "task_get",
            "task_definition",
            "openapi_and_agent_documentation",
            "taskboard",
            "sdk_documentation",
        ],
    }


def _task(
    status="OPEN",
    *,
    capacity_total=7,
    capacity_remaining=5,
    reward_amount="271",
    active_execution_count=1,
    claim_count_total=23,
    rewarded_execution_count=3,
    reward_paid_total_minor=19,
    maximum_reward_principal_atomic="17",
    claimable=True,
    detail=True,
    execution_summaries=None,
    execution_summaries_next_cursor=None,
):
    payload = {
        "schema_version": "ln_church.agent_task.v1",
        "task_id": "task_example",
        "task_type": TASK_TYPE,
        **_definition_payload(),
        "status": status,
        "seed_urls": [],
        "observation_profile": "public_safe_light",
        "constraints": {
            "allowed_methods": ["GET", "HEAD"],
            "no_login": True,
            "no_forms": True,
            "no_vulnerability_scan": True,
            "no_payment_to_target": True,
        },
        "reward": _reward(reward_amount),
        "created_at": "2026-07-27T00:00:00Z",
        "active_execution_count": active_execution_count,
        "claim_count_total": claim_count_total,
        "rewarded_execution_count": rewarded_execution_count,
        "reward_paid_total_minor": reward_paid_total_minor,
        "capacity_total": capacity_total,
        "capacity_remaining": capacity_remaining,
        "maximum_reward_principal_atomic": maximum_reward_principal_atomic,
        "claimable": claimable,
        "poc_terms": _poc_terms(),
        "expires_at": "2026-07-28T00:00:00Z",
    }
    if detail:
        payload["execution_summaries"] = (
            [] if execution_summaries is None else execution_summaries
        )
        payload["execution_summaries_next_cursor"] = (
            execution_summaries_next_cursor
        )
    return payload


def _execution_summary(
    *,
    task_status="SUBMITTED",
    reward_state=None,
    submission_id=SUBMISSION_ID,
    observation_id=OBSERVATION_ID,
    reward_tx_hash=None,
    rewarded_at=None,
    evaluated_at=None,
    failure_code=None,
    amount_atomic="10000",
):
    if reward_state is None:
        reward_state = {
            "SUBMITTED": "pending",
            "EVALUATION_REJECTED": "not_eligible",
            "REWARD_PENDING": "approved_pending",
            "REWARDED": "paid",
            "REWARD_FAILED": "failed",
            "REWARD_AMBIGUOUS": "ambiguous",
        }[task_status]
    if task_status != "SUBMITTED" and evaluated_at is None:
        evaluated_at = "2026-07-27T01:30:00Z"
    if task_status == "EVALUATION_REJECTED" and failure_code is None:
        failure_code = "observation_not_found"
    elif task_status == "REWARD_FAILED" and failure_code is None:
        failure_code = "settlement_unavailable"
    elif task_status == "REWARD_AMBIGUOUS" and failure_code is None:
        failure_code = "settlement_ambiguous"
    return {
        "submission_id": submission_id,
        "observation_id": observation_id,
        "task_status": task_status,
        "reward_state": reward_state,
        **_reward(amount_atomic),
        "evaluated_at": evaluated_at,
        "reward_tx_hash": reward_tx_hash,
        "rewarded_at": rewarded_at,
        "failure_code": failure_code,
    }


class _FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.closed = False

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return TaskTransportResponse(200, value)

    def close(self):
        self.closed = True


def _credential(
    *,
    task_id="task_example",
    agent_id="external-agent",
    claim_token=CLAIM_TOKEN,
    reward_amount="10000",
    manifest_url=MANIFEST_URL,
):
    return TaskClaimCredential(
        api_origin=PUBLIC_API_ORIGIN,
        task_id=task_id,
        task_type=TASK_TYPE,
        **_definition_payload(manifest_url=manifest_url),
        agent_id=agent_id,
        reward_address=REWARD_ADDRESS,
        reward=_reward(reward_amount),
        lease_expires_at="2099-07-27T01:00:00Z",
        claim_token=claim_token,
    )


def _claim_response(
    *,
    task_id="task_example",
    claim_token=CLAIM_TOKEN,
    reward_amount="10000",
):
    return {
        "schema_version": "ln_church.agent_task_claim_response.v1",
        "task_id": task_id,
        "task_type": TASK_TYPE,
        **_definition_payload(),
        "status": "CLAIMED",
        "claim_token": claim_token,
        "lease_duration_seconds": 3600,
        "lease_expires_at": "2099-07-27T01:00:00Z",
        "reward_address": REWARD_ADDRESS,
        "reward_address_control_verified": False,
        "reward": _reward(reward_amount),
    }


def _reward_status(
    *,
    task_status="SUBMITTED",
    reward_state=None,
    task_id="task_example",
    submission_id=SUBMISSION_ID,
    observation_id=OBSERVATION_ID,
    reward_tx_hash=None,
    rewarded_at=None,
    failure_code=None,
    network="eip155:8453",
    asset="USDC",
    asset_address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    amount_atomic="10000",
    **definition_overrides,
):
    if reward_state is None:
        reward_state = {
            "SUBMITTED": "pending",
            "EVALUATION_REJECTED": "not_eligible",
            "REWARD_PENDING": "approved_pending",
            "REWARDED": "paid",
            "REWARD_FAILED": "failed",
            "REWARD_AMBIGUOUS": "ambiguous",
        }[task_status]
    if task_status == "EVALUATION_REJECTED" and failure_code is None:
        failure_code = "observation_not_found"
    elif task_status == "REWARD_FAILED" and failure_code is None:
        failure_code = "settlement_unavailable"
    elif task_status == "REWARD_AMBIGUOUS" and failure_code is None:
        failure_code = "settlement_ambiguous"
    return {
        "schema_version": "ln_church.agent_task_reward_status.v1",
        "task_id": task_id,
        "submission_id": submission_id,
        "observation_id": observation_id,
        **_definition_payload(**definition_overrides),
        "task_status": task_status,
        "reward_state": reward_state,
        "network": network,
        "asset": asset,
        "asset_address": asset_address,
        "amount_atomic": amount_atomic,
        "reward_tx_hash": reward_tx_hash,
        "rewarded_at": rewarded_at,
        "failure_code": failure_code,
    }


def _submission_payload(
    *,
    submission_id=SUBMISSION_ID,
    include_submission_id=True,
):
    payload = {
        "observed_domain": "example.com",
        "observed_urls": [_observed_url()],
        "discovered_surfaces": [_surface()],
    }
    if include_submission_id:
        payload["submission_id"] = submission_id
    return payload


def _register_response(
    *,
    task_id="task_example",
    submission_id=SUBMISSION_ID,
    observation_id=OBSERVATION_ID,
):
    return {
        "schema_version": (
            "ln_church.task_domain_observation_response.v1"
        ),
        "accepted": True,
        "task_id": task_id,
        "submission_id": submission_id,
        "observation_id": observation_id,
        "status": "recorded",
    }


def _completion_response(
    *,
    task_id="task_example",
    submission_id=SUBMISSION_ID,
    observation_id=OBSERVATION_ID,
):
    return {
        "schema_version": (
            "ln_church.agent_task_completion_response.v1"
        ),
        "accepted": True,
        "task_id": task_id,
        "submission_id": submission_id,
        "observation_id": observation_id,
        "status": "SUBMITTED",
    }


def _pending_checkpoint(credential=None, submission=None):
    credential = credential or _credential()
    submission = submission or TaskDomainObservationSubmission(
        **_submission_payload()
    )
    return TaskDomainObservationCheckpoint(
        state=TaskDomainObservationCheckpointState.REGISTER_PENDING,
        api_origin=credential.api_origin,
        task_id=credential.task_id,
        task_type=credential.task_type,
        **credential.task_definition.model_dump(mode="python"),
        agent_id=credential.agent_id,
        reward_address=credential.reward_address,
        reward=credential.reward.model_dump(mode="python"),
        lease_expires_at=credential.lease_expires_at,
        submission=submission,
        submission_id=submission.submission_id,
        submission_sha256=submission.canonical_digest_hex(),
        credential_fingerprint=credential._local_fingerprint(),
    )


def _registered_checkpoint(credential=None, submission=None):
    pending = _pending_checkpoint(credential, submission)
    receipt = TaskDomainObservationResponse.model_validate(
        _register_response(
            task_id=pending.task_id,
            submission_id=pending.submission_id,
        )
    )
    return TaskDomainObservationCheckpoint(
        **{
            **pending.model_dump(mode="python", exclude_none=True),
            "state": TaskDomainObservationCheckpointState.REGISTERED,
            "register_receipt": receipt,
            "observation_id": receipt.observation_id,
        }
    )


def _observed_url(url="https://example.com/"):
    return {
        "url": url,
        "method": "GET",
        "status_code": 200,
        "media_family": "html",
        "observed_at": "2026-07-27T00:10:00Z",
    }


def _surface(url="https://example.com/paid"):
    return {
        "url": url,
        "method": "GET",
        "status_code": 402,
        "surface_type": "x402",
        "observed_at": "2026-07-27T00:10:00Z",
    }


def _observation_error(url="https://example.com/"):
    return {
        "url": url,
        "stage": "request",
        "error_code": "timeout",
        "observed_at": "2026-07-27T00:10:00Z",
    }


def _checkpoint_envelope_boundary_inputs():
    url_prefix = "https://example.com/"
    maximum_url = url_prefix + (
        "a" * (2048 - len(url_prefix.encode("utf-8")))
    )
    manifest_prefix = "https://kari.mayim-mayim.com/"
    manifest_url = manifest_prefix + (
        "m" * (4000 - len(manifest_prefix.encode("utf-8")))
    )
    submission = TaskDomainObservationSubmission.model_validate(
        {
            "submission_id": SUBMISSION_ID,
            "observed_domain": "example.com",
            "observed_urls": [
                _observed_url(maximum_url) for _ in range(50)
            ],
            "discovered_surfaces": [
                _surface(maximum_url) for _ in range(50)
            ],
            "errors": [
                _observation_error(maximum_url) for _ in range(20)
            ],
        },
        strict=True,
    )
    credential = _credential(manifest_url=manifest_url)
    return credential, submission, maximum_url, manifest_url


def _error_body(code, **extra):
    body = {
        "schema_version": "ln_church.agent_task_error.v1",
        "error_code": code,
    }
    body.update(extra)
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def test_canonical_fixture_bytes_and_hash():
    path = Path(__file__).parent / "fixtures" / "agent-task-venue-contract-v1.json"
    data = path.read_bytes()
    assert data.startswith(b"{\n")
    assert data.endswith(b"\n")
    assert hashlib.sha256(data).hexdigest() == FIXTURE_SHA256
    fixture = json.loads(data)
    assert fixture["contract_revision"] == (
        "payment_surface_discovery_capacity_only_parallel_20260803"
    )
    assert fixture["task_type"] == TASK_TYPE
    assert fixture["task_definition_version"] == TASK_DEFINITION_VERSION
    assert fixture["evaluator_id"] == (
        "ln_church.payment_surface_discovery.read_only.v1"
    )
    assert fixture["evaluator_version"] == "1.0.0"
    assert fixture["task_semantics"]["parameters"] == {}
    assert fixture["task_semantics"]["domain_anchor_present"] is False
    assert fixture["task_semantics"]["seed_urls"] == []
    assert fixture["task_semantics"][
        "task_level_domain_allowed_in_offer_task_claim_or_execution"
    ] is False
    assert "domain" not in fixture["required_task_fields"]
    assert "parameters" not in fixture["required_task_fields"]
    assert "domain" not in fixture["required_claim_response_fields"]
    assert "domain" not in fixture["claim_credential"][
        "bound_snapshot_fields"
    ]
    assert "domain" not in fixture["credential_file"][
        "active_required_fields"
    ]
    assert fixture["public_safe_constraints"][
        "minimum_actual_status_402_surfaces"
    ] == 1
    assert fixture["public_safe_constraints"][
        "classification_precision_is_eligibility_gate"
    ] is False
    assert fixture["discovered_surface_entry"][
        "unknown_surface_type_with_status_402_is_eligible"
    ] is True
    assert fixture["failure_code_values_by_status"][
        "EVALUATION_REJECTED"
    ] == [
        "observation_not_found",
        "claim_task_or_observation_binding_mismatch",
        "declared_agent_id_mismatch",
        "proven_observation_reuse",
    ]
    assert fixture["internal_interfaces_unchanged"] == {
        "claim_path": "/api/agent/external/observation-targets",
        "submit_path": "/api/agent/external/domain-observation-results",
        "header": "X-Internal-Secret",
    }
    assert fixture["routes"]["get_submission_status"] == {
        "method": "GET",
        "path": (
            "/api/agent/tasks/{task_id}/submissions/"
            "{submission_id}/status"
        ),
        "payment": "none",
        "claim_header_required": False,
    }
    assert fixture["task_definition_reference"][
        "sdk_model_frozen"
    ] is True
    assert fixture["completion_semantics"]["success_meaning"] == (
        "durable_receipt_only"
    )
    assert fixture["reward_polling"][
        "bounded_exhaustion_after_valid_pending_or_approved_pending"
    ] == "return_last_valid_nonterminal_status"
    assert fixture["interface_authority"] == {
        "canonical_interface": "public_hon_den_api",
        "sdk_role": "optional_supporting_client",
        "sdk_source_of_truth": False,
        "sdk_hardcodes_or_derives_A_B_N_or_remaining_capacity": False,
    }
    assert fixture["owner_policy_example"] == {
        "policy_owner": "hon_den",
        "task_offer_create_amount_atomic_A": "1000000",
        "per_eligible_execution_reward_atomic_B": "10000",
        "task_offer_capacity_N": 50,
        "maximum_reward_principal_atomic": "500000",
        "sdk_hardcodes_or_derives_A_B_N": False,
    }
    assert fixture["capacity_snapshot"]["claim_guarantee"] is False
    assert fixture["capacity_snapshot"][
        "sdk_or_taskboard_decrements_or_reconstructs"
    ] is False
    offer_capacity = fixture["offer_execution_capacity"]
    assert offer_capacity["separate_concurrency_limit_exists"] is False
    assert offer_capacity["active_execution_count_range"] == (
        "integer_0_through_50"
    )
    assert offer_capacity["maximum_active_formula"] == (
        "capacity_total - rewarded_execution_count"
    )
    assert offer_capacity[
        "same_agent_id_multiple_active_claims_allowed"
    ] is True
    assert offer_capacity[
        "same_reward_address_multiple_active_claims_allowed"
    ] is True
    assert offer_capacity[
        "reward_address_agent_id_or_ip_uniqueness_condition_allowed"
    ] is False
    assert offer_capacity[
        "claim_uses_expected_active_execution_count_compare"
    ] is False
    assert offer_capacity["new_claim_writes_active_execution_id"] is False
    assert offer_capacity[
        "new_claim_expires_supersedes_or_terminalizes_sibling"
    ] is False
    assert "capacity_remaining_above_0" in offer_capacity[
        "claimable_formula"
    ]
    assert "active_execution_count" not in offer_capacity[
        "claimable_formula"
    ]
    claim_transition = fixture["lifecycle_atomic_transition_sets"]["claim"]
    assert claim_transition["expected_active_execution_count_compare"] is False
    assert claim_transition["active_execution_id_write"] is False
    assert claim_transition["sibling_execution_write"] is False
    assert fixture["lifecycle_atomic_transition_sets"][
        "expiry_or_abandonment"
    ]["sibling_execution_write"] is False
    assert fixture["lifecycle_atomic_transition_sets"][
        "evaluation_approval"
    ]["sibling_execution_write"] is False
    public_aggregates = fixture["public_task_aggregate_invariants"]
    assert public_aggregates["active_execution_count"] == (
        "integer_0_through_50"
    )
    assert public_aggregates[
        "active_plus_rewarded_not_above_capacity_total"
    ] is True
    assert fixture["taskboard"][
        "active_execution_count_values_above_one_render_without_clamping"
    ] is True
    assert fixture["reward_delivery_disclosure"]["sending"] == (
        "automatic_best_effort"
    )
    assert fixture["offer_statuses"] == ["OPEN"]
    assert fixture["public_claim_response_statuses"] == ["CLAIMED"]
    assert fixture["public_submission_statuses"] == [
        "SUBMITTED",
        "EVALUATION_REJECTED",
        "REWARD_PENDING",
        "REWARDED",
        "REWARD_FAILED",
        "REWARD_AMBIGUOUS",
    ]
    assert fixture["reward_states"] == [
        "pending",
        "not_eligible",
        "approved_pending",
        "paid",
        "failed",
        "ambiguous",
    ]
    assert fixture["poc_terms"] == _poc_terms()
    assert fixture["task_detail_query"] == {
        "default_limit": 20,
        "minimum_limit": 1,
        "maximum_limit": 50,
        "cursor": "opaque_optional",
        "pagination_target": "execution_summaries",
    }
    assert fixture["failure_code_values_by_status"][
        "REWARD_AMBIGUOUS"
    ] == ["settlement_ambiguous"]


@pytest.mark.parametrize("amount_atomic", ["1", "37", "263", "271828"])
def test_reward_amount_accepts_canonical_positive_integer_strings(amount_atomic):
    terms = AgentTaskRewardTerms.model_validate(_reward(amount_atomic))
    assert terms.amount_atomic == amount_atomic
    assert AgentTask.model_validate(
        _task(reward_amount=amount_atomic)
    ).reward.amount_atomic == amount_atomic
    assert AgentTaskClaimResponse.model_validate(
        _claim_response(reward_amount=amount_atomic)
    ).reward.amount_atomic == amount_atomic
    assert AgentTaskRewardStatus.model_validate(
        _reward_status(amount_atomic=amount_atomic)
    ).amount_atomic == amount_atomic


def test_task_reward_aggregates_accept_canonical_values_over_int_digit_limit():
    amount_atomic = "1" + ("0" * 4999)
    reward_paid_total_minor = 10 ** 4999
    task = AgentTask.model_validate(
        _task(
            capacity_total=1,
            capacity_remaining=0,
            active_execution_count=0,
            rewarded_execution_count=1,
            claim_count_total=1,
            reward_paid_total_minor=reward_paid_total_minor,
            reward_amount=amount_atomic,
            maximum_reward_principal_atomic=amount_atomic,
        )
    )
    assert task.reward.amount_atomic == amount_atomic
    assert task.maximum_reward_principal_atomic == amount_atomic
    assert task.reward_paid_total_minor == reward_paid_total_minor


@pytest.mark.parametrize(
    "invalid_amount",
    [
        "0",
        "-1",
        "+1",
        "01",
        "1.0",
        " 1",
        "1 ",
        1,
        None,
    ],
)
def test_reward_amount_rejects_noncanonical_or_nonstring_values(invalid_amount):
    payload = _reward(invalid_amount)
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTaskRewardTerms.model_validate(payload)
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTask.model_validate(
            {**_task(), "reward": payload}
        )
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTaskClaimResponse.model_validate(
            {**_claim_response(), "reward": payload}
        )
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTaskRewardStatus.model_validate(
            {**_reward_status(), "amount_atomic": invalid_amount}
        )


def test_reward_amount_is_required_in_every_reward_snapshot():
    reward_without_amount = _reward()
    reward_without_amount.pop("amount_atomic")
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTaskRewardTerms.model_validate(reward_without_amount)
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTask.model_validate(
            {**_task(), "reward": reward_without_amount}
        )
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTaskClaimResponse.model_validate(
            {**_claim_response(), "reward": reward_without_amount}
        )
    status = _reward_status()
    status.pop("amount_atomic")
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTaskRewardStatus.model_validate(status)


def test_taskget_and_claim_reward_snapshots_remain_distinct_and_not_derived():
    task_get = AgentTask.model_validate(_task(reward_amount="271"))
    claim = AgentTaskClaimResponse.model_validate(
        _claim_response(reward_amount="263")
    ).to_claim("external-agent")
    assert task_get.reward.amount_atomic == "271"
    assert claim.reward.amount_atomic == "263"
    assert claim.credential.reward.amount_atomic == "263"
    assert task_get.reward != claim.reward


def test_hondo_snapshot_round_trip_preserves_capacity_remaining_above_total():
    payload = _task(
        capacity_total=3,
        capacity_remaining=4,
        reward_amount="37",
        active_execution_count=1,
        claim_count_total=73,
        rewarded_execution_count=2,
        reward_paid_total_minor=251,
        maximum_reward_principal_atomic="41",
    )
    task = AgentTask.model_validate_json(json.dumps(payload))
    assert task.model_dump(mode="json") == payload
    serialized = task.model_dump_json()
    assert json.loads(serialized) == payload
    reparsed = AgentTask.model_validate_json(serialized)
    assert reparsed.model_dump(mode="json") == payload
    assert (
        reparsed.capacity_total,
        reparsed.capacity_remaining,
        reparsed.rewarded_execution_count,
    ) == (3, 4, 2)


def test_hondo_snapshot_round_trip_preserves_rewarded_count_above_total():
    payload = _task(
        capacity_total=3,
        capacity_remaining=2,
        reward_amount="37",
        active_execution_count=1,
        claim_count_total=73,
        rewarded_execution_count=4,
        reward_paid_total_minor=251,
        maximum_reward_principal_atomic="41",
    )
    task = AgentTask.model_validate_json(json.dumps(payload))
    assert task.model_dump(mode="json") == payload
    serialized = task.model_dump_json()
    assert json.loads(serialized) == payload
    reparsed = AgentTask.model_validate_json(serialized)
    assert reparsed.model_dump(mode="json") == payload
    assert (
        reparsed.capacity_total,
        reparsed.capacity_remaining,
        reparsed.rewarded_execution_count,
    ) == (3, 2, 4)


def test_hondo_snapshot_round_trip_preserves_parallel_active_execution_count_without_cross_field_inference():
    detail_payload = _task(
        capacity_total=3,
        capacity_remaining=4,
        reward_amount="37",
        active_execution_count=7,
        claim_count_total=73,
        rewarded_execution_count=5,
        reward_paid_total_minor=251,
        maximum_reward_principal_atomic="41",
        claimable=False,
    )
    list_payload = _task(
        capacity_total=3,
        capacity_remaining=4,
        reward_amount="37",
        active_execution_count=7,
        claim_count_total=73,
        rewarded_execution_count=5,
        reward_paid_total_minor=251,
        maximum_reward_principal_atomic="41",
        claimable=False,
        detail=False,
    )

    for model, payload in (
        (AgentTask, detail_payload),
        (AgentTaskListItem, list_payload),
    ):
        task = model.model_validate(payload)
        assert task.active_execution_count == 7
        assert task.model_dump(mode="json") == payload
        serialized = task.model_dump_json()
        assert json.loads(serialized) == payload
        reparsed = model.model_validate_json(serialized)
        assert reparsed.model_dump(mode="json") == payload
        assert (
            reparsed.capacity_total,
            reparsed.active_execution_count,
            reparsed.rewarded_execution_count,
            reparsed.capacity_remaining,
            reparsed.claimable,
        ) == (3, 7, 5, 4, False)


@pytest.mark.parametrize(
    ("capacity_total", "capacity_remaining"),
    [
        (True, 1),
        (3, False),
        (0, 0),
        (-1, 0),
        (3, -1),
        ("3", 2),
        (3, 2.0),
    ],
)
def test_task_rejects_invalid_capacity_snapshot(
    capacity_total, capacity_remaining
):
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTask.model_validate(
            _task(
                capacity_total=capacity_total,
                capacity_remaining=capacity_remaining,
            )
        )


def test_task_preserves_server_aggregates_claimable_and_poc_terms():
    task = AgentTask.model_validate(
        _task(
            capacity_total=3,
            capacity_remaining=2,
            active_execution_count=1,
            rewarded_execution_count=0,
            claim_count_total=73,
            reward_paid_total_minor=0,
            maximum_reward_principal_atomic="30000",
            claimable=False,
        )
    )
    assert task.status == "OPEN"
    assert task.active_execution_count == 1
    assert task.claim_count_total == 73
    assert task.rewarded_execution_count == 0
    assert task.reward_paid_total_minor == 0
    assert task.capacity_total == 3
    assert task.capacity_remaining == 2
    assert task.maximum_reward_principal_atomic == "30000"
    assert task.claimable is False
    assert task.poc_terms == AgentTaskPocTerms.model_validate(_poc_terms())


@pytest.mark.parametrize(
    "overrides",
    [
        {"active_execution_count": True},
        {"active_execution_count": False},
        {"active_execution_count": -1},
        {"active_execution_count": "2"},
        {"active_execution_count": 2.0},
        {"active_execution_count": None},
        {"claim_count_total": False},
        {"claim_count_total": -1},
        {"rewarded_execution_count": -1},
        {"reward_paid_total_minor": True},
        {"reward_paid_total_minor": -1},
        {"maximum_reward_principal_atomic": "-1"},
        {"maximum_reward_principal_atomic": "030000"},
        {"maximum_reward_principal_atomic": 30000},
        {"claimable": 1},
    ],
)
def test_task_offer_wire_invariants_fail_closed(overrides):
    payload = _task(
        capacity_total=3,
        capacity_remaining=2,
        active_execution_count=1,
        rewarded_execution_count=0,
        claim_count_total=1,
        reward_paid_total_minor=0,
        maximum_reward_principal_atomic="30000",
        claimable=False,
    )
    payload.update(overrides)
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTask.model_validate(payload)


def test_open_offer_can_be_nonclaimable_without_local_inference():
    payload = _task(
        capacity_total=3,
        capacity_remaining=3,
        active_execution_count=0,
        rewarded_execution_count=0,
        claim_count_total=0,
        claimable=False,
    )
    task = AgentTask.model_validate(payload)
    assert task.status == "OPEN"
    assert task.capacity_remaining == 3
    assert task.claimable is False


def test_public_task_claim_and_credential_are_domainless_and_seedless():
    task = AgentTask.model_validate(
        {
            **_task(),
            "domain": "untrusted.example.com",
            "domain_anchor": "untrusted.example.com",
            "parameters": {"domain": "untrusted.example.com"},
        }
    )
    task_wire = task.model_dump(mode="json")
    assert task.task_type == TASK_TYPE
    assert task.seed_urls == []
    assert "domain" not in task_wire
    assert "domain_anchor" not in task_wire
    assert "parameters" not in task_wire

    claim_response = AgentTaskClaimResponse.model_validate(
        {**_claim_response(), "domain": "untrusted.example.com"}
    )
    claim = claim_response.to_claim("external-agent")
    assert "domain" not in claim.model_dump(mode="json")
    assert "domain" not in claim.credential._to_private_file_payload()

    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTask.model_validate(
            {**_task(), "seed_urls": ["https://example.com/"]}
        )
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTask.model_validate(
            {**_task(), "task_type": "domain_observation.v1"}
        )
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTaskClaimResponse.model_validate(
            {**_claim_response(), "task_type": "domain_observation.v1"}
        )


def test_task_list_and_detail_summary_fields_are_separate():
    summary = _execution_summary()
    payload = _task(
        execution_summaries=[summary],
        execution_summaries_next_cursor="opaque-next",
    )
    list_item = AgentTaskListItem.model_validate(payload)
    list_payload = list_item.model_dump(mode="json")
    assert "execution_summaries" not in list_payload
    assert "execution_summaries_next_cursor" not in list_payload

    detail = AgentTask.model_validate(payload)
    assert detail.execution_summaries == [
        AgentTaskExecutionSummary.model_validate(summary)
    ]
    assert detail.execution_summaries_next_cursor == "opaque-next"

    detail_missing_page = dict(payload)
    detail_missing_page.pop("execution_summaries")
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTask.model_validate(detail_missing_page)

    page = AgentTaskPage.model_validate(
        {
            "schema_version": "ln_church.agent_task_page.v1",
            "tasks": [payload],
            "next_cursor": None,
        }
    )
    assert type(page.tasks[0]) is AgentTaskListItem
    assert "execution_summaries" not in page.model_dump(mode="json")["tasks"][0]


@pytest.mark.parametrize(
    ("task_status", "reward_state", "extra"),
    [
        ("SUBMITTED", "pending", {}),
        (
            "EVALUATION_REJECTED",
            "not_eligible",
            {"failure_code": "observation_not_found"},
        ),
        ("REWARD_PENDING", "approved_pending", {}),
        (
            "REWARDED",
            "paid",
            {
                "reward_tx_hash": "0x" + ("a" * 64),
                "rewarded_at": "2026-07-27T02:00:00Z",
            },
        ),
        (
            "REWARD_FAILED",
            "failed",
            {"failure_code": "settlement_retry_exhausted"},
        ),
        (
            "REWARD_AMBIGUOUS",
            "ambiguous",
            {"failure_code": "settlement_ambiguous"},
        ),
        (
            "REWARD_AMBIGUOUS",
            "ambiguous",
            {
                "failure_code": "settlement_ambiguous",
                "reward_tx_hash": "0x" + ("b" * 64),
            },
        ),
    ],
)
def test_all_public_submission_statuses_validate_exactly(
    task_status, reward_state, extra
):
    summary = _execution_summary(
        task_status=task_status,
        reward_state=reward_state,
        **extra,
    )
    status = _reward_status(
        task_status=task_status,
        reward_state=reward_state,
        **extra,
    )
    assert (
        AgentTaskExecutionSummary.model_validate(summary).reward_state
        == reward_state
    )
    assert (
        AgentTaskRewardStatus.model_validate(status).reward_state
        == reward_state
    )


def test_observation_binding_failure_code_replaces_task_domain_code():
    accepted = {
        "task_status": "EVALUATION_REJECTED",
        "reward_state": "not_eligible",
        "failure_code": "claim_task_or_observation_binding_mismatch",
    }
    assert AgentTaskExecutionSummary.model_validate(
        _execution_summary(**accepted)
    ).failure_code == accepted["failure_code"]
    assert AgentTaskRewardStatus.model_validate(
        _reward_status(**accepted)
    ).failure_code == accepted["failure_code"]

    rejected = {
        **accepted,
        "failure_code": "claim_task_or_domain_binding_mismatch",
    }
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTaskExecutionSummary.model_validate(
            _execution_summary(**rejected)
        )
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTaskRewardStatus.model_validate(_reward_status(**rejected))


@pytest.mark.parametrize(
    ("model_type", "payload"),
    [
        (
            AgentTaskExecutionSummary,
            _execution_summary(
                task_status="REWARDED",
                reward_state="paid",
                reward_tx_hash="0x" + ("0123456789abcdef" * 4),
                rewarded_at="2026-07-27T02:00:00Z",
            ),
        ),
        (
            AgentTaskRewardStatus,
            _reward_status(
                task_status="REWARDED",
                reward_state="paid",
                reward_tx_hash="0x" + ("0123456789abcdef" * 4),
                rewarded_at="2026-07-27T02:00:00Z",
            ),
        ),
    ],
)
def test_reward_transaction_hash_accepts_exact_lowercase_format(
    model_type, payload
):
    parsed = model_type.model_validate(payload)
    assert parsed.reward_tx_hash == "0x" + ("0123456789abcdef" * 4)


@pytest.mark.parametrize(
    "invalid_hash",
    [
        "0x" + ("A" * 64),
        "0x" + ("0123456789abcdeF" * 4),
        "0X" + ("a" * 64),
    ],
)
@pytest.mark.parametrize(
    ("model_type", "payload_factory"),
    [
        (AgentTaskExecutionSummary, _execution_summary),
        (AgentTaskRewardStatus, _reward_status),
    ],
)
def test_reward_transaction_hash_rejects_uppercase_format(
    model_type, payload_factory, invalid_hash
):
    payload = payload_factory(
        task_status="REWARDED",
        reward_state="paid",
        reward_tx_hash=invalid_hash,
        rewarded_at="2026-07-27T02:00:00Z",
    )
    with pytest.raises((TypeError, ValueError, ValidationError)):
        model_type.model_validate(payload)


@pytest.mark.parametrize(
    "overrides",
    [
        {"task_status": "CLAIMED", "reward_state": "pending"},
        {"task_status": "EXPIRED", "reward_state": "pending"},
        {"task_status": "ABANDONED", "reward_state": "pending"},
        {"task_status": "SUBMITTED", "reward_state": "approved_pending"},
        {
            "task_status": "SUBMITTED",
            "reward_state": "pending",
            "failure_code": "observation_not_found",
        },
        {
            "task_status": "EVALUATION_REJECTED",
            "reward_state": "not_eligible",
            "failure_code": "settlement_unavailable",
        },
        {
            "task_status": "REWARD_FAILED",
            "reward_state": "failed",
            "failure_code": "settlement_ambiguous",
        },
        {
            "task_status": "REWARD_AMBIGUOUS",
            "reward_state": "ambiguous",
            "failure_code": "free_form",
        },
        {
            "task_status": "REWARD_PENDING",
            "reward_state": "approved_pending",
            "reward_tx_hash": "0x" + ("a" * 64),
        },
        {
            "task_status": "REWARD_AMBIGUOUS",
            "reward_state": "ambiguous",
            "failure_code": "settlement_ambiguous",
            "rewarded_at": "2026-07-27T02:00:00Z",
        },
    ],
)
def test_submission_status_reward_and_failure_scope_rejects_mismatch(overrides):
    payload = _execution_summary()
    payload.update(overrides)
    if payload["task_status"] != "SUBMITTED" and payload["evaluated_at"] is None:
        payload["evaluated_at"] = "2026-07-27T01:30:00Z"
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTaskExecutionSummary.model_validate(payload)

    status_payload = {
        **_reward_status(),
        **overrides,
    }
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTaskRewardStatus.model_validate(status_payload)


@pytest.mark.parametrize(
    "model_payload",
    [
        {"task_status": "SUBMITTED", "evaluated_at": "2026-07-27T01:30:00Z"},
        {"task_status": "REWARD_PENDING", "evaluated_at": None},
        {
            "task_status": "REWARDED",
            "evaluated_at": "2026-07-27T01:30:00Z",
            "reward_tx_hash": None,
            "rewarded_at": "2026-07-27T02:00:00Z",
        },
        {
            "task_status": "REWARDED",
            "evaluated_at": "2026-07-27T01:30:00Z",
            "reward_tx_hash": "0x" + ("a" * 64),
            "rewarded_at": None,
        },
    ],
)
def test_submission_status_timestamp_invariants_fail_closed(model_payload):
    task_status = model_payload["task_status"]
    reward_state = {
        "SUBMITTED": "pending",
        "REWARD_PENDING": "approved_pending",
        "REWARDED": "paid",
    }[task_status]
    summary = _execution_summary(
        task_status=task_status,
        reward_state=reward_state,
        reward_tx_hash=(
            "0x" + ("a" * 64) if task_status == "REWARDED" else None
        ),
        rewarded_at=(
            "2026-07-27T02:00:00Z"
            if task_status == "REWARDED"
            else None
        ),
    )
    summary.update(model_payload)
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTaskExecutionSummary.model_validate(summary)
def test_execution_summary_rejects_private_fields_and_aliases():
    for field in (
        "execution_id",
        "claim_id",
        "claim_token",
        "claim_token_hash",
        "agent_id",
        "reward_address",
        "secret",
        "free_form_error",
        "status",
        "reward",
    ):
        with pytest.raises((TypeError, ValueError, ValidationError)):
            AgentTaskExecutionSummary.model_validate(
                {**_execution_summary(), field: "private"}
            )


def test_task_detail_query_and_transport_route_query_allowlists():
    assert AgentTaskDetailQuery().model_dump(mode="json") == {
        "limit": 20,
        "cursor": None,
    }
    assert AgentTaskDetailQuery(
        limit=50,
        cursor="opaque+cursor",
    ).cursor == "opaque+cursor"
    for invalid_limit in (True, 0, 51, "20"):
        with pytest.raises((TypeError, ValueError, ValidationError)):
            AgentTaskDetailQuery(limit=invalid_limit)

    assert _validate_query(
        "detail",
        {"limit": 50, "cursor": "opaque+cursor"},
    ) == {"limit": 50, "cursor": "opaque+cursor"}
    assert _validate_query(
        "list",
        {
            "task_type": TASK_TYPE,
            "status": "OPEN",
            "limit": 20,
        },
    ) == {
        "task_type": TASK_TYPE,
        "status": "OPEN",
        "limit": 20,
    }
    for operation, params in (
        ("detail", {"status": "OPEN"}),
        ("detail", {"task_type": TASK_TYPE}),
        ("status", {"limit": 20}),
        ("claim", {"cursor": "opaque"}),
        ("list", {"status": "CLAIMED"}),
        ("list", {"execution_id": "private"}),
    ):
        with pytest.raises(TaskTransportError, match="TASK_ORIGIN_INVALID"):
            _validate_query(operation, params)


def test_network_free_summary_verifier_uses_claim_not_taskget_reward():
    summary_payload = _execution_summary(amount_atomic="263")
    task = AgentTask.model_validate(
        _task(
            reward_amount="271",
            maximum_reward_principal_atomic="41",
            execution_summaries=[summary_payload],
        )
    )
    credential = _credential(reward_amount="263")
    summary = task.execution_summaries[0]
    verified = verify_task_execution_summary(
        credential,
        task,
        summary,
        submission_id=SUBMISSION_ID,
        observation_id=OBSERVATION_ID,
    )
    assert verified == summary
    assert task.reward.amount_atomic == "271"
    assert verified.amount_atomic == credential.reward.amount_atomic == "263"

    for kwargs in (
        {"submission_id": "sub_" + ("1" * 32)},
        {"observation_id": "obs_other"},
    ):
        call = {
            "submission_id": SUBMISSION_ID,
            "observation_id": OBSERVATION_ID,
            **kwargs,
        }
        with pytest.raises(ValueError, match="Invalid Task Execution summary"):
            verify_task_execution_summary(
                credential,
                task,
                summary,
                **call,
            )

    mismatched_summary = AgentTaskExecutionSummary.model_validate(
        _execution_summary(amount_atomic="269")
    )
    mismatched_task = AgentTask.model_validate(
        _task(
            reward_amount="271",
            maximum_reward_principal_atomic="41",
            execution_summaries=[
                mismatched_summary.model_dump(mode="json")
            ],
        )
    )
    with pytest.raises(ValueError, match="Invalid Task Execution summary"):
        verify_task_execution_summary(
            credential,
            mismatched_task,
            mismatched_task.execution_summaries[0],
            submission_id=SUBMISSION_ID,
            observation_id=OBSERVATION_ID,
        )


def test_ambiguous_to_rewarded_transition_requires_same_transaction():
    first_hash = "0x" + ("a" * 64)
    ambiguous = AgentTaskRewardStatus.model_validate(
        _reward_status(
            task_status="REWARD_AMBIGUOUS",
            reward_tx_hash=first_hash,
        )
    )
    rewarded = AgentTaskRewardStatus.model_validate(
        _reward_status(
            task_status="REWARDED",
            reward_tx_hash=first_hash,
            rewarded_at="2026-07-27T02:00:00Z",
        )
    )
    assert verify_reward_status_transition(ambiguous, rewarded) == rewarded

    conflicting = AgentTaskRewardStatus.model_validate(
        _reward_status(
            task_status="REWARDED",
            reward_tx_hash="0x" + ("b" * 64),
            rewarded_at="2026-07-27T02:00:00Z",
        )
    )
    with pytest.raises(ValueError, match="Invalid Task reward status"):
        verify_reward_status_transition(ambiguous, conflicting)


@pytest.mark.parametrize(
    ("task_status", "reward_state"),
    [
        ("EVALUATION_REJECTED", "not_eligible"),
        ("REWARDED", "paid"),
        ("REWARD_FAILED", "failed"),
        ("REWARD_AMBIGUOUS", "ambiguous"),
    ],
)
def test_reward_polling_returns_each_terminal_reward_state(
    task_status, reward_state
):
    kwargs = {}
    if task_status == "REWARDED":
        kwargs = {
            "reward_tx_hash": "0x" + ("a" * 64),
            "rewarded_at": "2026-07-27T02:00:00Z",
        }
    transport = _FakeTransport(
        [
            _reward_status(
                task_status=task_status,
                reward_state=reward_state,
                **kwargs,
            )
        ]
    )
    status = AgentTaskClient(
        _transport=transport,
        _monotonic=lambda: 0.0,
    ).wait_for_reward(
        "task_example",
        submission_id=SUBMISSION_ID,
        observation_id=OBSERVATION_ID,
        task_definition=_definition(),
        reward=_reward_terms(),
        timeout_seconds=10,
        max_attempts=2,
    )
    assert status.task_status == task_status
    assert status.reward_state == reward_state
    assert len(transport.calls) == 1


def test_reward_polling_preserves_last_approved_pending_at_bound():
    transport = _FakeTransport(
        [
            _reward_status(
                task_status="REWARD_PENDING",
                reward_state="approved_pending",
            ),
            _reward_status(
                task_status="REWARD_PENDING",
                reward_state="approved_pending",
            ),
        ]
    )
    status = AgentTaskClient(
        _transport=transport,
        _sleep=lambda _seconds: None,
        _monotonic=lambda: 0.0,
        _random=lambda: 0.0,
    ).wait_for_reward(
        "task_example",
        submission_id=SUBMISSION_ID,
        observation_id=OBSERVATION_ID,
        task_definition=_definition(),
        reward=_reward_terms(),
        timeout_seconds=10,
        max_attempts=2,
    )
    assert status.task_status == "REWARD_PENDING"
    assert status.reward_state == "approved_pending"
    assert len(transport.calls) == 2


@pytest.mark.parametrize(
    ("task_status", "reward_state"),
    [
        ("SUBMITTED", "pending"),
        ("EVALUATION_REJECTED", "not_eligible"),
        ("REWARD_PENDING", "approved_pending"),
        ("REWARDED", "paid"),
        ("REWARD_FAILED", "failed"),
        ("REWARD_AMBIGUOUS", "ambiguous"),
    ],
)
def test_guided_completion_reconciliation_preserves_every_public_status(
    task_status, reward_state
):
    status_kwargs = {}
    if task_status == "REWARDED":
        status_kwargs = {
            "reward_tx_hash": "0x" + ("a" * 64),
            "rewarded_at": "2026-07-27T02:00:00Z",
        }
    transport = _FakeTransport(
        [
            _register_response(),
            TaskAmbiguousOutcomeError(
                "COMPLETION_OUTCOME_UNKNOWN",
                request_bytes_sent=True,
            ),
            _reward_status(
                task_status=task_status,
                reward_state=reward_state,
                **status_kwargs,
            ),
        ]
    )
    result = AgentTaskClient(
        _transport=transport
    ).submit_and_complete_domain_observation(
        _credential(),
        _submission_payload(),
    )
    assert result.completion_receipt is None
    assert result.matched_status.task_status == task_status
    assert result.matched_status.reward_state == reward_state
    assert len(transport.calls) == 3
    assert "claim_token" not in transport.calls[-1][2]


def test_task_offer_exposes_no_singular_execution_state():
    payload = {
        **_task(capacity_total=3, capacity_remaining=2),
        "claim_lease_expires_at": "2026-07-27T01:00:00Z",
        "observation_id": OBSERVATION_ID,
        "reward_tx_hash": "0x" + ("a" * 64),
        "rewarded_at": "2026-07-27T02:00:00Z",
    }
    task = AgentTask.model_validate(payload)
    public = task.model_dump(mode="json")
    for field in (
        "claim_lease_expires_at",
        "observation_id",
        "reward_tx_hash",
        "rewarded_at",
        "claim_id",
        "execution_id",
        "order_id",
    ):
        assert field not in AgentTask.model_fields
        assert field not in public


def test_taskget_snapshot_is_preserved_and_claim_response_is_authoritative():
    stale_task = _task(
        capacity_total=3,
        capacity_remaining=0,
        reward_amount="271",
    )
    transport = _FakeTransport(
        [stale_task, _claim_response(reward_amount="263")]
    )
    client = AgentTaskClient(_transport=transport)
    task = client.get_task("task_example")
    claim = client.claim_task(
        "task_example",
        agent_id="external-agent",
        reward_address=REWARD_ADDRESS,
    )
    assert (task.capacity_total, task.capacity_remaining) == (3, 0)
    assert task.reward.amount_atomic == "271"
    assert claim.reward.amount_atomic == "263"
    assert claim.credential.reward.amount_atomic == "263"
    assert (task.capacity_total, task.capacity_remaining) == (3, 0)
    assert [call[:2] for call in transport.calls] == [
        ("GET", task_detail_path("task_example")),
        ("POST", task_claim_path("task_example")),
    ]


def test_claim_reward_round_trip_and_nested_immutability():
    response = AgentTaskClaimResponse.model_validate(
        _claim_response(reward_amount="9999")
    )
    claim = response.to_claim("external-agent")
    payload = claim.credential._to_private_file_payload()
    restored = TaskClaimCredential._from_private_file_payload(payload)
    assert response.reward == _reward_terms("9999")
    assert claim.reward == response.reward
    assert claim.credential.reward == response.reward
    assert restored.reward == response.reward
    with pytest.raises((AttributeError, TypeError, ValueError)):
        claim.reward.amount_atomic = "1"
    with pytest.raises((AttributeError, TypeError, ValueError)):
        claim.credential.reward.amount_atomic = "1"


def test_pre_correction_credential_without_reward_fails_closed():
    payload = _credential()._to_private_file_payload()
    payload.pop("reward")
    with pytest.raises(ValueError, match="Invalid task claim credential"):
        TaskClaimCredential._from_private_file_payload(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("network", "eip155:1"),
        ("asset", "USDT"),
        (
            "asset_address",
            "0x1111111111111111111111111111111111111111",
        ),
        ("amount_atomic", "9999"),
    ],
)
def test_status_reward_mismatch_against_claim_snapshot_fails_closed(
    field, value
):
    status = _reward_status(**{field: value})
    transport = _FakeTransport([status])
    with pytest.raises(TaskTransportError, match="TASK_RESPONSE_INVALID"):
        AgentTaskClient(_transport=transport).get_reward_status(
            "task_example",
            submission_id=SUBMISSION_ID,
            observation_id=OBSERVATION_ID,
            task_definition=_definition(),
            reward=_reward_terms("10000"),
        )
    assert len(transport.calls) == 1


def test_matching_status_uses_claim_reward_when_taskget_advertisement_differs():
    task_get = AgentTask.model_validate(_task(reward_amount="271"))
    claim = AgentTaskClaimResponse.model_validate(
        _claim_response(reward_amount="263")
    ).to_claim("external-agent")
    transport = _FakeTransport([_reward_status(amount_atomic="263")])
    status = AgentTaskClient(_transport=transport).get_reward_status(
        "task_example",
        submission_id=SUBMISSION_ID,
        observation_id=OBSERVATION_ID,
        task_definition=claim.credential.task_definition,
        reward=claim.credential.reward,
    )
    assert task_get.reward.amount_atomic == "271"
    assert status.amount_atomic == claim.reward.amount_atomic == "263"


def test_completion_fallback_verifies_claim_reward_snapshot():
    transport = _FakeTransport(
        [
            TaskAmbiguousOutcomeError(
                "COMPLETION_OUTCOME_UNKNOWN", request_bytes_sent=True
            ),
            _reward_status(amount_atomic="9999"),
        ]
    )
    with pytest.raises(
        TaskAmbiguousOutcomeError, match="COMPLETION_OUTCOME_UNKNOWN"
    ):
        AgentTaskClient(_transport=transport).complete_task(
            _credential(reward_amount="10000"),
            submission_id=SUBMISSION_ID,
            observation_id=OBSERVATION_ID,
        )
    assert len(transport.calls) == 2


def test_sibling_claims_keep_independent_credentials_submissions_and_statuses():
    first_token = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
    second_token = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
    first_submission = "sub_" + ("1" * 32)
    second_submission = "sub_" + ("2" * 32)
    transport = _FakeTransport(
        [
            _claim_response(claim_token=first_token, reward_amount="1"),
            _claim_response(claim_token=second_token, reward_amount="9999"),
            _reward_status(
                submission_id=first_submission,
                observation_id="obs_first",
                amount_atomic="1",
            ),
            _reward_status(
                submission_id=second_submission,
                observation_id="obs_second",
                amount_atomic="9999",
                task_status="REWARD_FAILED",
                reward_state="failed",
            ),
        ]
    )
    client = AgentTaskClient(_transport=transport)
    first = client.claim_task(
        "task_example",
        agent_id="external-agent",
        reward_address=REWARD_ADDRESS,
    )
    first_snapshot = first.credential._validated_snapshot()
    second = client.claim_task(
        "task_example",
        agent_id="external-agent",
        reward_address=REWARD_ADDRESS,
    )
    assert [(call[0], call[1]) for call in transport.calls[:2]] == [
        ("POST", task_claim_path("task_example")),
        ("POST", task_claim_path("task_example")),
    ]
    assert [call[2]["json_body"] for call in transport.calls[:2]] == [
        {
            "schema_version": "ln_church.agent_task_claim_request.v1",
            "agent_id": "external-agent",
            "reward_address": REWARD_ADDRESS,
        },
        {
            "schema_version": "ln_church.agent_task_claim_request.v1",
            "agent_id": "external-agent",
            "reward_address": REWARD_ADDRESS,
        },
    ]
    assert first.credential._validated_snapshot() == first_snapshot
    assert first.credential._claim_token_value() == first_token
    assert second.credential._claim_token_value() == second_token
    assert first.credential.reward.amount_atomic == "1"
    assert second.credential.reward.amount_atomic == "9999"

    first_status = client.get_reward_status(
        "task_example",
        submission_id=first_submission,
        observation_id="obs_first",
        task_definition=first.credential.task_definition,
        reward=first.credential.reward,
    )
    second_status = client.get_reward_status(
        "task_example",
        submission_id=second_submission,
        observation_id="obs_second",
        task_definition=second.credential.task_definition,
        reward=second.credential.reward,
    )
    assert first_status.reward_state == "pending"
    assert second_status.reward_state == "failed"
    assert [call[1] for call in transport.calls[-2:]] == [
        task_submission_status_path("task_example", first_submission),
        task_submission_status_path("task_example", second_submission),
    ]
    assert all(
        "claim_token" not in call[2] for call in transport.calls[-2:]
    )
    assert len(transport.calls) == 4


@pytest.mark.parametrize(
    ("second_domain", "second_url"),
    [
        ("example.org", "https://example.org/paid"),
        ("example.com", "https://example.com/paid"),
    ],
)
def test_sibling_claims_can_report_different_or_repeated_observed_domains(
    second_domain, second_url
):
    first_submission_id = "sub_" + ("1" * 32)
    second_submission_id = "sub_" + ("2" * 32)
    transport = _FakeTransport(
        [
            _claim_response(
                claim_token="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
            ),
            _claim_response(
                claim_token="AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
            ),
            _register_response(
                submission_id=first_submission_id,
                observation_id="obs_first",
            ),
            _register_response(
                submission_id=second_submission_id,
                observation_id="obs_second",
            ),
        ]
    )
    client = AgentTaskClient(_transport=transport)
    first_claim = client.claim_task(
        "task_example",
        agent_id="external-agent-one",
        reward_address=REWARD_ADDRESS,
    )
    second_claim = client.claim_task(
        "task_example",
        agent_id="external-agent-two",
        reward_address=REWARD_ADDRESS,
    )
    first_submission = TaskDomainObservationSubmission(
        submission_id=first_submission_id,
        observed_domain="example.com",
        discovered_surfaces=[_surface()],
    )
    second_submission = TaskDomainObservationSubmission(
        submission_id=second_submission_id,
        observed_domain=second_domain,
        discovered_surfaces=[_surface(second_url)],
    )

    client.submit_domain_observation(
        first_claim.credential, first_submission
    )
    client.submit_domain_observation(
        second_claim.credential, second_submission
    )

    assert not hasattr(first_claim.credential, "domain")
    assert not hasattr(second_claim.credential, "domain")
    assert transport.calls[2][2]["json_body"]["observed_domain"] == (
        "example.com"
    )
    assert transport.calls[3][2]["json_body"]["observed_domain"] == (
        second_domain
    )


def test_task_definition_reference_is_frozen_strict_and_wire_flattened():
    reference = _definition()
    assert reference.task_definition_version == TASK_DEFINITION_VERSION
    with pytest.raises((TypeError, ValueError, ValidationError)):
        reference.task_definition_digest = "c" * 64
    with pytest.raises((TypeError, ValueError, ValidationError)):
        TaskDefinitionReference(
            **_definition_payload(),
            future_field="not-authorized",
        )

    task = AgentTask.model_validate(_task())
    assert task.task_definition == reference
    wire = task.model_dump(mode="json")
    assert wire["task_definition_version"] == TASK_DEFINITION_VERSION
    assert wire["task_definition_digest"] == TASK_DEFINITION_DIGEST
    assert wire["manifest_url"] == MANIFEST_URL
    assert wire["manifest_sha256"] == MANIFEST_SHA256
    assert "task_definition" not in wire


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("task_definition_version", ""),
        ("task_definition_version", "e\u0301"),
        ("task_definition_version", "1\n"),
        ("task_definition_digest", "A" * 64),
        ("task_definition_digest", "a" * 63),
        ("manifest_url", "http://kari.mayim-mayim.com/manifest.json"),
        ("manifest_url", "/agent-task-specs/manifest.json"),
        ("manifest_sha256", "B" * 64),
        ("manifest_sha256", "b" * 65),
    ],
)
def test_task_definition_reference_rejects_invalid_values(field, value):
    payload = _definition_payload(**{field: value})
    with pytest.raises((TypeError, ValueError, ValidationError)):
        TaskDefinitionReference(**payload)
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTask.model_validate({**_task(), **payload})
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTaskClaimResponse.model_validate(
            {**_claim_response(), **payload}
        )


@pytest.mark.parametrize(
    "field",
    [
        "task_definition_version",
        "task_definition_digest",
        "manifest_url",
        "manifest_sha256",
    ],
)
def test_task_and_claim_require_every_definition_field(field):
    task_payload = _task()
    task_payload.pop(field)
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTask.model_validate(task_payload)

    claim_payload = _claim_response()
    claim_payload.pop(field)
    with pytest.raises((TypeError, ValueError, ValidationError)):
        AgentTaskClaimResponse.model_validate(claim_payload)


def test_claim_definition_and_credential_file_round_trip_are_exact():
    claim = AgentTaskClaimResponse.model_validate(_claim_response()).to_claim(
        "external-agent"
    )
    assert isinstance(claim, AgentTaskClaim)
    assert claim.task_definition == _definition()
    assert claim.credential.task_definition == _definition()
    payload = claim.credential._to_private_file_payload()
    assert set(payload) == {
        "schema_version",
        "state",
        "api_origin",
        "task_id",
        "task_type",
        "task_definition_version",
        "task_definition_digest",
        "manifest_url",
        "manifest_sha256",
        "agent_id",
        "reward_address",
        "reward",
        "lease_expires_at",
        "claim_token",
    }
    restored = TaskClaimCredential._from_private_file_payload(payload)
    assert restored.task_definition == _definition()
    assert restored.reward == _reward_terms()
    assert restored.task_type == TASK_TYPE
    assert restored._claim_token_value() == CLAIM_TOKEN
    assert "domain" not in payload
    assert not hasattr(claim, "domain")
    assert not hasattr(claim.credential, "domain")

    legacy_domain_payload = {**payload, "domain": "example.com"}
    with pytest.raises(ValueError, match="Invalid task claim credential"):
        TaskClaimCredential._from_private_file_payload(
            legacy_domain_payload
        )

    for field in (
        "task_type",
        "task_definition_version",
        "task_definition_digest",
        "manifest_url",
        "manifest_sha256",
    ):
        malformed = dict(payload)
        malformed.pop(field)
        with pytest.raises(ValueError, match="Invalid task claim credential"):
            TaskClaimCredential._from_private_file_payload(malformed)
    with pytest.raises(ValueError, match="Invalid task claim credential"):
        TaskClaimCredential._from_private_file_payload(
            {**payload, "future": "not-authorized"}
        )


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("task_id", "task_other"),
        ("task_definition_digest", "c" * 64),
        ("manifest_sha256", "d" * 64),
        ("_claim_token", "B" * 43),
    ],
)
def test_post_claim_credential_mutation_fails_before_network(attribute, value):
    transport = _FakeTransport([])
    credential = _credential()
    with pytest.raises((AttributeError, TypeError, ValueError, ValidationError)):
        setattr(credential, attribute, value)
    assert transport.calls == []


def test_public_domain_uses_idna2008_and_rejects_special_use_suffixes():
    assert validate_public_domain("xn--fa-hia.de") == "xn--fa-hia.de"
    for domain in ("foo.example", "home.arpa"):
        with pytest.raises(ValueError):
            validate_public_domain(domain)


def test_claim_digest_vector_and_token_canonicality():
    assert claim_token_storage_digest_hex(CLAIM_TOKEN) == (
        "418e992265b709de7a6b9261be3d68da4bec997ca6b9657744b76028d30a29cb"
    )
    with pytest.raises(ValueError):
        _credential(claim_token=CLAIM_TOKEN + "=")


def test_claim_credential_token_never_appears_in_normal_serialization():
    credential = _credential()
    surfaces = [
        repr(credential),
        str(credential),
        repr(credential.model_dump()),
        credential.model_dump_json(),
        repr(credential.__dict__),
    ]
    assert all(CLAIM_TOKEN not in surface for surface in surfaces)
    assert "claim_token" not in credential.model_dump()


def test_claim_token_is_hidden_from_transport_response_and_validation_errors():
    response = TaskTransportResponse(200, _claim_response())
    assert CLAIM_TOKEN not in repr(response)
    assert CLAIM_TOKEN not in repr(response.data)
    assert "claim_token" not in response.data

    malformed = _claim_response()
    malformed["lease_duration_seconds"] = 7
    with pytest.raises((ValueError, ValidationError)) as caught:
        AgentTaskClaimResponse.model_validate(malformed)
    failure_surfaces = [
        str(caught.value),
        repr(caught.value),
        repr(vars(caught.value)),
    ]
    assert all(CLAIM_TOKEN not in surface for surface in failure_surfaces)


def test_transport_response_recursively_strips_claim_secret_variants():
    payload = {
        **_claim_response(),
        "claimToken": CLAIM_TOKEN,
        "X-LN-Task-Claim-Token": CLAIM_TOKEN,
        "nested": {
            "task_claim_token": CLAIM_TOKEN,
            "safe": "prefix-" + CLAIM_TOKEN + "-suffix",
        },
    }
    response = TaskTransportResponse(200, payload)
    rendered = repr(response.data)
    assert CLAIM_TOKEN not in rendered
    assert "claimToken" not in response.data
    assert "X-LN-Task-Claim-Token" not in response.data
    assert response.data["nested"] == {"safe": "[REDACTED]"}

    variant_only = TaskTransportResponse(
        200,
        {
            "claimToken": CLAIM_TOKEN,
            "safe": "prefix-" + CLAIM_TOKEN,
        },
    )
    assert variant_only.data == {"safe": "[REDACTED]"}
    assert CLAIM_TOKEN not in repr(variant_only.data)


def test_reward_address_eip55_rules():
    canonical = "0x52908400098527886E0F7030069857D2E4169EE7"
    assert to_eip55_checksum_address(canonical.lower()) == canonical
    assert to_eip55_checksum_address(canonical.upper().replace("0X", "0x")) == canonical
    assert to_eip55_checksum_address(canonical) == canonical
    with pytest.raises(ValueError):
        to_eip55_checksum_address(
            "0x52908400098527886e0F7030069857D2E4169EE7"
        )
    with pytest.raises(ValueError):
        to_eip55_checksum_address("0x" + "0" * 40)


def test_observation_schema_rejects_hostile_and_out_of_scope_fields():
    with pytest.raises(ValidationError):
        TaskDomainObservationSubmission(
            observed_domain="example.com",
            discovered_surfaces=[_surface()],
            observer={"name": "caller-selected"},
        )
    with pytest.raises(ValidationError):
        TaskDomainObservationSubmission(
            observed_domain="example.com",
            discovered_surfaces=[_surface()],
            verification_cost_vector={"payment_attempts": 1},
        )
    with pytest.raises(ValidationError):
        TaskDomainObservationSubmission(
            observed_domain="example.com",
            observed_urls=[
                {
                    "url": "https://evil.example/",
                    "method": "GET",
                    "status_code": 200,
                    "media_family": "html",
                    "observed_at": "2026-07-27T00:00:00Z",
                }
            ],
            discovered_surfaces=[_surface()],
        )
    with pytest.raises(ValidationError):
        TaskDomainObservationSubmission(
            observed_domain="example.com",
            errors=[
                {
                    "url": "https://example.com/",
                    "stage": "request",
                    "error_code": "timeout",
                    "observed_at": "2026-07-27T00:00:00Z",
                    "message": "raw exception",
                }
            ],
            discovered_surfaces=[_surface()],
        )


@pytest.mark.parametrize(
    ("field", "entry", "maximum"),
    [
        ("observed_urls", _observed_url(), 50),
        ("discovered_surfaces", _surface(), 50),
        ("errors", _observation_error(), 20),
    ],
)
def test_observation_nested_array_bounds(field, entry, maximum):
    payload = {
        "observed_domain": "example.com",
        "discovered_surfaces": [_surface()],
        field: [entry] * maximum,
    }
    accepted = TaskDomainObservationSubmission(**payload)
    assert len(getattr(accepted, field)) == maximum
    with pytest.raises(ValidationError):
        TaskDomainObservationSubmission(
            **{
                **payload,
                field: [entry] * (maximum + 1),
            }
        )


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (
            TaskObservedUrlEntry,
            {**_observed_url(), "status_code": True},
        ),
        (
            TaskObservedUrlEntry,
            {**_observed_url(), "method": "POST"},
        ),
        (
            TaskDiscoveredSurfaceEntry,
            {**_surface(), "surface_type": "raw_invoice"},
        ),
        (
            TaskObservationErrorEntry,
            {**_observation_error(), "message": "raw failure"},
        ),
        (
            TaskVerificationCostVector,
            {"http_requests": 101},
        ),
        (
            TaskVerificationCostVector,
            {"payment_attempts": 1},
        ),
        (
            TaskVerificationCostVector,
            {"personal_data_required": True},
        ),
    ],
)
def test_observation_nested_entries_reject_wrong_type_enum_and_unknowns(
    model, payload
):
    with pytest.raises(ValidationError):
        model.model_validate(payload)


@pytest.mark.parametrize(
    "surface_type",
    ["http_402", "x402", "l402", "mpp", "agent_commerce", "unknown"],
)
def test_actual_402_is_required_but_surface_classification_is_not_a_gate(
    surface_type,
):
    accepted = TaskDomainObservationSubmission(
        observed_domain="example.com",
        discovered_surfaces=[
            {**_surface(), "surface_type": surface_type}
        ],
    )
    assert accepted.discovered_surfaces[0].status_code == 402
    assert accepted.discovered_surfaces[0].surface_type == surface_type

    for surfaces in (
        [],
        [{**_surface(), "status_code": 200, "surface_type": "x402"}],
    ):
        with pytest.raises(ValidationError):
            TaskDomainObservationSubmission(
                observed_domain="example.com",
                discovered_surfaces=surfaces,
            )


@pytest.mark.parametrize(
    "overrides",
    [
        {"no_payment_to_target": False},
        {"not_a_security_scan": False},
        {"verification_cost_vector": {"payment_attempts": 1}},
        {"verification_cost_vector": {"personal_data_required": True}},
        {"verification_cost_vector": {"login_attempted": True}},
        {"verification_cost_vector": {"form_submission_attempted": True}},
        {"verification_cost_vector": {"vulnerability_scan_attempted": True}},
        {"verification_cost_vector": {"irreversible_action_attempted": True}},
    ],
)
def test_eligible_402_submission_rejects_every_unsafe_action(overrides):
    with pytest.raises(ValidationError):
        TaskDomainObservationSubmission.model_validate(
            {**_submission_payload(), **overrides}
        )


def test_observation_url_utf8_bound_is_exact_and_domain_scoped():
    prefix = "https://example.com/"
    exact = prefix + ("a" * (2048 - len(prefix.encode("utf-8"))))
    entry = TaskObservedUrlEntry.model_validate(_observed_url(exact))
    assert len(entry.url.encode("utf-8")) == 2048
    with pytest.raises(ValidationError):
        TaskObservedUrlEntry.model_validate(_observed_url(exact + "a"))
    with pytest.raises(ValidationError):
        TaskDomainObservationSubmission(
            observed_domain="example.com",
            observed_urls=[_observed_url("https://other.example/")],
            discovered_surfaces=[_surface()],
        )


def test_submission_digest_is_stable_and_content_bound():
    one = TaskDomainObservationSubmission(
        submission_id="sub_" + "0" * 32,
        observed_domain="example.com",
        discovered_surfaces=[_surface()],
    )
    two = TaskDomainObservationSubmission(
        submission_id="sub_" + "0" * 32,
        observed_domain="example.com",
        discovered_surfaces=[_surface()],
    )
    changed = TaskDomainObservationSubmission(
        submission_id="sub_" + "1" * 32,
        observed_domain="example.com",
        discovered_surfaces=[_surface()],
    )
    assert one.canonical_digest_hex() == two.canonical_digest_hex()
    assert one.canonical_digest_hex() != changed.canonical_digest_hex()
    assert canonical_submission_digest_hex(one) == one.canonical_digest_hex()


def test_submission_rfc8785_digest_binds_array_order_and_exact_content():
    submission_id = "sub_" + "2" * 32
    first = TaskDomainObservationSubmission(
        submission_id=submission_id,
        observed_domain="example.com",
        observed_urls=[
            _observed_url("https://example.com/a"),
            _observed_url("https://example.com/b"),
        ],
        discovered_surfaces=[_surface()],
        verification_cost_vector={
            "http_requests": 2,
            "tool_calls": 1,
            "payment_attempts": 0,
            "personal_data_required": False,
            "human_confirmation_required": True,
            "irreversible_action_attempted": False,
            "login_attempted": False,
            "form_submission_attempted": False,
            "vulnerability_scan_attempted": False,
        },
    )
    repeated = TaskDomainObservationSubmission.model_validate(
        first.model_dump(mode="json")
    )
    reordered = TaskDomainObservationSubmission(
        **{
            **first.model_dump(mode="json"),
            "observed_urls": list(
                reversed(first.model_dump(mode="json")["observed_urls"])
            ),
        }
    )
    assert first.canonical_bytes() == repeated.canonical_bytes()
    assert first.canonical_digest_hex() == repeated.canonical_digest_hex()
    assert first.canonical_digest_hex() != reordered.canonical_digest_hex()
    assert first.canonical_digest_hex() == (
        "ab477d3a315c6f69c72627541c0c8335092a17763d64c3d4d9ab93e14b6a2f96"
    )


def test_client_uses_exact_public_routes_and_claim_attempt_bound():
    transport = _FakeTransport(
        [
            {
                "schema_version": "ln_church.agent_task_page.v1",
                "tasks": [_task()],
                "next_cursor": None,
            },
            _task(),
            _claim_response(),
            {
                "schema_version": (
                    "ln_church.task_domain_observation_response.v1"
                ),
                "accepted": True,
                "task_id": "task_example",
                "submission_id": "sub_" + "0" * 32,
                "observation_id": "obs_example",
                "status": "recorded",
            },
            {
                "schema_version": (
                    "ln_church.agent_task_completion_response.v1"
                ),
                "accepted": True,
                "task_id": "task_example",
                "submission_id": "sub_" + "0" * 32,
                "observation_id": "obs_example",
                "status": "SUBMITTED",
            },
        ]
    )
    client = AgentTaskClient(_transport=transport)
    client.list_tasks(status="OPEN", limit=50, cursor="opaque+cursor")
    client.get_task("task_example", limit=40, cursor="detail+cursor")
    claim = client.claim_task(
        "task_example",
        agent_id="external-agent",
        reward_address=REWARD_ADDRESS,
    )
    submission = TaskDomainObservationSubmission(
        submission_id="sub_" + "0" * 32,
        observed_domain="example.com",
        discovered_surfaces=[_surface()],
    )
    observed = client.submit_domain_observation(claim.credential, submission)
    client.complete_task(
        claim.credential,
        submission_id=submission.submission_id,
        observation_id=observed.observation_id,
    )

    assert [(call[0], call[1]) for call in transport.calls] == [
        ("GET", "/api/agent/tasks"),
        ("GET", "/api/agent/tasks/task_example"),
        ("POST", "/api/agent/tasks/task_example/claim"),
        ("POST", "/api/agent/tasks/task_example/domain-observations"),
        ("POST", "/api/agent/tasks/task_example/completion"),
    ]
    assert transport.calls[2][2]["maximum_attempts"] == 1
    assert transport.calls[0][2]["params"] == {
        "task_type": TASK_TYPE,
        "status": "OPEN",
        "limit": 50,
        "cursor": "opaque+cursor",
    }
    assert transport.calls[1][2]["params"] == {
        "limit": 40,
        "cursor": "detail+cursor",
    }
    assert transport.calls[0][2]["maximum_attempts"] == 3
    assert transport.calls[1][2]["maximum_attempts"] == 3
    assert transport.calls[2][2]["json_body"] == {
        "schema_version": "ln_church.agent_task_claim_request.v1",
        "agent_id": "external-agent",
        "reward_address": REWARD_ADDRESS,
    }
    assert transport.calls[3][2]["json_body"] == submission.model_dump(
        mode="json"
    )
    assert transport.calls[3][2]["maximum_attempts"] == 2
    assert transport.calls[3][2]["ambiguous_delivery_code"] == (
        "SUBMISSION_OUTCOME_UNKNOWN"
    )
    assert transport.calls[4][2]["json_body"] == {
        "schema_version": "ln_church.agent_task_completion_request.v1",
        "submission_id": submission.submission_id,
        "observation_id": "obs_example",
    }
    assert transport.calls[4][2]["maximum_attempts"] == 2
    assert transport.calls[4][2]["ambiguous_delivery_code"] == (
        "COMPLETION_OUTCOME_UNKNOWN"
    )
    assert transport.calls[3][2]["claim_token"] == CLAIM_TOKEN
    assert transport.calls[4][2]["claim_token"] == CLAIM_TOKEN
    assert all(
        "claim_token" not in call[2]
        for call in transport.calls[:3]
    )
    assert all(
        "X-Internal-Secret" not in repr(call) for call in transport.calls
    )


def test_response_models_bound_arrays_require_schema_and_discard_unknown_fields():
    task = _task()
    task["private_server_field"] = CLAIM_TOKEN
    task["constraints"]["future_server_field"] = CLAIM_TOKEN
    task["reward"]["future_server_field"] = CLAIM_TOKEN
    parsed = AgentTask.model_validate(task)
    public = parsed.model_dump(mode="json")
    assert "private_server_field" not in public
    assert "future_server_field" not in public["constraints"]
    assert "future_server_field" not in public["reward"]
    assert CLAIM_TOKEN not in repr(parsed)

    page = {
        "schema_version": "ln_church.agent_task_page.v1",
        "tasks": [task],
        "next_cursor": None,
        "private_server_field": CLAIM_TOKEN,
    }
    assert "private_server_field" not in AgentTaskPage.model_validate(
        page
    ).model_dump()
    with pytest.raises(ValidationError):
        AgentTaskPage.model_validate(
            {
                **page,
                "schema_version": "ln_church.agent_task_page.v2",
            }
        )
    with pytest.raises(ValidationError):
        AgentTaskPage.model_validate({**page, "tasks": [_task()] * 51})


@pytest.mark.parametrize(
    ("body", "expected_code"),
    [
        (b"[]", "TASK_RESPONSE_INVALID"),
        (b"null", "TASK_RESPONSE_INVALID"),
        (b'"scalar"', "TASK_RESPONSE_INVALID"),
        (b'{"one":1,"one":2}', "TASK_RESPONSE_INVALID"),
        (b'{"value":NaN}', "TASK_RESPONSE_INVALID"),
        (b'{"value":Infinity}', "TASK_RESPONSE_INVALID"),
        (b"\xff", "TASK_RESPONSE_INVALID"),
        (b"{" + (b"x" * MAXIMUM_JSON_BYTES) + b"}", "TASK_RESPONSE_TOO_LARGE"),
    ],
)
def test_transport_rejects_non_object_duplicate_invalid_and_oversized_json(
    body, expected_code
):
    transport = TaskTransport(
        _resolver=lambda host, port: ("93.184.216.34",),
        _exchange=lambda **kwargs: (200, {}, body),
    )
    with pytest.raises(TaskTransportError) as caught:
        transport.request("GET", "/api/agent/tasks", maximum_attempts=1)
    assert caught.value.code == expected_code
    assert str(caught.value) == expected_code


def test_malformed_json_public_error_drops_raw_body_exception_graph():
    reflected = '{"reflected":"' + CLAIM_TOKEN + '"'
    transport = TaskTransport(
        _resolver=lambda host, port: ("93.184.216.34",),
        _exchange=lambda **kwargs: (
            200,
            {},
            reflected.encode("utf-8"),
        ),
    )
    with pytest.raises(TaskTransportError) as caught:
        transport.request(
            "GET", "/api/agent/tasks", maximum_attempts=1
        )
    assert caught.value.code == "TASK_RESPONSE_INVALID"
    _assert_finite_exception_graph(
        caught.value, CLAIM_TOKEN, reflected
    )


def test_transport_accepts_exact_256_kib_object_response():
    prefix = b'{"value":"'
    suffix = b'"}'
    body = prefix + (b"x" * (MAXIMUM_JSON_BYTES - len(prefix) - len(suffix))) + suffix
    transport = TaskTransport(
        _resolver=lambda host, port: ("93.184.216.34",),
        _exchange=lambda **kwargs: (
            200,
            {"content-length": str(MAXIMUM_JSON_BYTES)},
            body,
        ),
    )
    response = transport.request(
        "GET", "/api/agent/tasks", maximum_attempts=1
    )
    assert len(response.data["value"]) == (
        MAXIMUM_JSON_BYTES - len(prefix) - len(suffix)
    )


def test_task_errors_are_finite_and_discard_remote_secret_text():
    def exchange(**kwargs):
        kwargs["tracker"].request_bytes_sent = True
        return (
            500,
            {"x-remote-secret": CLAIM_TOKEN},
            _error_body(
                "internal_error",
                message=CLAIM_TOKEN,
                stack=CLAIM_TOKEN,
            ),
        )

    transport = TaskTransport(
        _resolver=lambda host, port: ("93.184.216.34",),
        _exchange=exchange,
    )
    with pytest.raises(TaskAPIError) as caught:
        transport.request("GET", "/api/agent/tasks", maximum_attempts=1)
    error = caught.value
    surfaces = [str(error), repr(error), repr(vars(error))]
    assert error.code == "TASK_API_ERROR"
    assert error.public_error_code == "internal_error"
    assert error.status_code == 500
    assert all(CLAIM_TOKEN not in surface for surface in surfaces)
    assert all("message" not in surface for surface in surfaces)


def test_mock_transport_failure_text_is_not_retained_or_logged(
    caplog,
):
    def exchange(**kwargs):
        raise RuntimeError("mock failed with " + CLAIM_TOKEN)

    transport = TaskTransport(
        _resolver=lambda host, port: ("93.184.216.34",),
        _exchange=exchange,
    )
    with pytest.raises(TaskTransportError) as caught:
        transport.request("GET", "/api/agent/tasks", maximum_attempts=1)
    rendered = "".join(
        traceback.format_exception(
            type(caught.value),
            caught.value,
            caught.value.__traceback__,
        )
    )
    surfaces = [
        str(caught.value),
        repr(caught.value),
        repr(vars(caught.value)),
        rendered,
        caplog.text,
    ]
    assert caught.value.code == "TASK_TRANSPORT_ERROR"
    assert all(CLAIM_TOKEN not in surface for surface in surfaces)


def test_malformed_claim_success_is_ambiguous_and_not_retried():
    transport = _FakeTransport(
        [{"schema_version": "ln_church.agent_task_claim_response.v1"}]
    )
    client = AgentTaskClient(_transport=transport)
    with pytest.raises(
        TaskAmbiguousOutcomeError, match="CLAIM_OUTCOME_UNKNOWN"
    ):
        client.claim_task(
            "task_example",
            agent_id="external-agent",
            reward_address=REWARD_ADDRESS,
        )
    assert len(transport.calls) == 1
    assert transport.calls[0][2]["maximum_attempts"] == 1


@pytest.mark.parametrize(
    ("status_code", "public_code"),
    [
        (400, "invalid_request"),
        (404, "task_not_found"),
        (409, "task_not_open"),
        (409, "task_state_conflict"),
        (429, "rate_limited"),
    ],
)
def test_complete_claim_mutation_free_matrix(status_code, public_code):
    def exchange(**kwargs):
        kwargs["tracker"].request_bytes_sent = True
        return status_code, {}, _error_body(public_code)

    transport = TaskTransport(
        _resolver=lambda host, port: ("93.184.216.34",),
        _exchange=exchange,
    )
    with pytest.raises(TaskAPIError) as caught:
        transport.request(
            "POST",
            "/api/agent/tasks/task_example/claim",
            json_body={
                "schema_version": "ln_church.agent_task_claim_request.v1",
                "agent_id": "external-agent",
                "reward_address": REWARD_ADDRESS,
            },
            maximum_attempts=1,
        )
    assert caught.value.public_error_code == public_code
    assert caught.value.mutation_free is True
    assert caught.value.request_bytes_sent is True


@pytest.mark.parametrize(
    ("status_code", "public_code"),
    [
        (401, "claim_token_invalid"),
        (409, "submission_conflict"),
        (410, "claim_lease_expired"),
        (500, "internal_error"),
    ],
)
def test_non_matrix_claim_failures_are_not_classified_mutation_free(
    status_code, public_code
):
    transport = TaskTransport(
        _resolver=lambda host, port: ("93.184.216.34",),
        _exchange=lambda **kwargs: (
            status_code,
            {},
            _error_body(public_code),
        ),
    )
    with pytest.raises(TaskAPIError) as caught:
        transport.request(
            "POST",
            "/api/agent/tasks/task_example/claim",
            json_body={
                "schema_version": "ln_church.agent_task_claim_request.v1",
                "agent_id": "external-agent",
                "reward_address": REWARD_ADDRESS,
            },
            maximum_attempts=1,
        )
    assert caught.value.mutation_free is False


def test_invalid_claim_status_error_pair_is_rejected_as_malformed_response():
    transport = TaskTransport(
        _resolver=lambda host, port: ("93.184.216.34",),
        _exchange=lambda **kwargs: (
            400,
            {},
            _error_body("task_not_found"),
        ),
    )
    with pytest.raises(TaskTransportError) as caught:
        transport.request(
            "POST",
            "/api/agent/tasks/task_example/claim",
            json_body={
                "schema_version": "ln_church.agent_task_claim_request.v1",
                "agent_id": "external-agent",
                "reward_address": REWARD_ADDRESS,
            },
            maximum_attempts=1,
        )
    assert caught.value.code == "TASK_RESPONSE_INVALID"
    assert caught.value.request_bytes_sent is True


def test_reward_status_uses_claim_specific_route_and_exact_binding():
    transaction_hash = "0x" + "a" * 64
    transport = _FakeTransport(
        [
            _reward_status(),
            _reward_status(
                task_status="REWARDED",
                reward_state="paid",
                reward_tx_hash=transaction_hash,
                rewarded_at="2026-07-27T02:00:00Z",
            ),
        ]
    )
    client = AgentTaskClient(
        _transport=transport, _sleep=lambda _: None, _random=lambda: 0.0
    )
    assert client.get_reward_status(
        "task_example",
        submission_id=SUBMISSION_ID,
        observation_id=OBSERVATION_ID,
        task_definition=_definition(),
        reward=_reward_terms(),
    ).reward_state == "pending"
    paid = client.wait_for_reward(
        "task_example",
        submission_id=SUBMISSION_ID,
        observation_id=OBSERVATION_ID,
        task_definition=_definition(),
        reward=_reward_terms(),
        timeout_seconds=10,
        max_attempts=2,
    )
    assert paid.reward_state == "paid"
    assert paid.reward_tx_hash == transaction_hash
    expected_path = task_submission_status_path(
        "task_example", SUBMISSION_ID
    )
    assert [(method, path) for method, path, _ in transport.calls] == [
        ("GET", expected_path),
        ("GET", expected_path),
    ]
    assert all("claim_token" not in call[2] for call in transport.calls)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("task_id", "task_other"),
        ("submission_id", "sub_" + "1" * 32),
        ("observation_id", "obs_other"),
        ("task_definition_version", "2"),
        ("task_definition_digest", "c" * 64),
        (
            "manifest_url",
            "https://kari.mayim-mayim.com/"
            "agent-task-specs/payment_surface_discovery.v1/2/"
            + ("c" * 64)
            + "/manifest.json",
        ),
        ("manifest_sha256", "d" * 64),
    ],
)
def test_reward_status_rejects_identifier_or_definition_mismatch(field, value):
    transport = _FakeTransport([_reward_status(**{field: value})])
    with pytest.raises(TaskTransportError, match="TASK_RESPONSE_INVALID"):
        AgentTaskClient(_transport=transport).get_reward_status(
            "task_example",
            submission_id=SUBMISSION_ID,
            observation_id=OBSERVATION_ID,
            task_definition=_definition(),
            reward=_reward_terms(),
        )
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "field",
    [
        "schema_version",
        "task_id",
        "submission_id",
        "observation_id",
        "task_definition_version",
        "task_definition_digest",
        "manifest_url",
        "manifest_sha256",
        "network",
        "asset",
        "asset_address",
        "amount_atomic",
        "task_status",
        "reward_state",
        "reward_tx_hash",
        "rewarded_at",
        "failure_code",
    ],
)
def test_reward_status_rejects_missing_required_fields(field):
    payload = _reward_status()
    payload.pop(field)
    transport = _FakeTransport([payload])
    with pytest.raises(TaskTransportError, match="TASK_RESPONSE_INVALID"):
        AgentTaskClient(_transport=transport).get_reward_status(
            "task_example",
            submission_id=SUBMISSION_ID,
            observation_id=OBSERVATION_ID,
            task_definition=_definition(),
            reward=_reward_terms(),
        )


def test_completion_ambiguous_outcome_falls_back_to_one_submission_status():
    ambiguous = TaskAmbiguousOutcomeError(
        "COMPLETION_OUTCOME_UNKNOWN", request_bytes_sent=True
    )
    transport = _FakeTransport(
        [
            ambiguous,
            _reward_status(),
        ]
    )
    result = AgentTaskClient(_transport=transport).complete_task(
        _credential(),
        submission_id=SUBMISSION_ID,
        observation_id=OBSERVATION_ID,
    )
    assert result.status == "SUBMITTED"
    assert [(method, path) for method, path, _ in transport.calls] == [
        ("POST", "/api/agent/tasks/task_example/completion"),
        (
            "GET",
            task_submission_status_path("task_example", SUBMISSION_ID),
        ),
    ]
    assert "claim_token" not in transport.calls[1][2]


def test_completion_2xx_is_only_a_durable_pending_receipt():
    transport = _FakeTransport(
        [
            {
                "schema_version": (
                    "ln_church.agent_task_completion_response.v1"
                ),
                "accepted": True,
                "task_id": "task_example",
                "submission_id": SUBMISSION_ID,
                "observation_id": OBSERVATION_ID,
                "status": "SUBMITTED",
            }
        ]
    )
    completed = AgentTaskClient(_transport=transport).complete_task(
        _credential(),
        submission_id=SUBMISSION_ID,
        observation_id=OBSERVATION_ID,
    )
    assert completed.accepted is True
    assert completed.status == "SUBMITTED"
    assert not hasattr(completed, "reward_state")
    assert len(transport.calls) == 1


def test_completion_fallback_mismatch_preserves_ambiguous_outcome():
    ambiguous = TaskAmbiguousOutcomeError(
        "COMPLETION_OUTCOME_UNKNOWN", request_bytes_sent=True
    )
    transport = _FakeTransport(
        [
            ambiguous,
            _reward_status(observation_id="obs_other"),
        ]
    )
    with pytest.raises(
        TaskAmbiguousOutcomeError, match="COMPLETION_OUTCOME_UNKNOWN"
    ):
        AgentTaskClient(_transport=transport).complete_task(
            _credential(),
            submission_id=SUBMISSION_ID,
            observation_id=OBSERVATION_ID,
        )
    assert len(transport.calls) == 2


def test_malformed_completion_success_uses_same_submission_status_fallback():
    transport = _FakeTransport(
        [
            {
                "schema_version": (
                    "ln_church.agent_task_completion_response.v1"
                ),
                "accepted": True,
            },
            _reward_status(),
        ]
    )
    completed = AgentTaskClient(_transport=transport).complete_task(
        _credential(),
        submission_id=SUBMISSION_ID,
        observation_id=OBSERVATION_ID,
    )
    assert completed.status == "SUBMITTED"
    assert len(transport.calls) == 2
    assert transport.calls[1][:2] == (
        "GET",
        task_submission_status_path("task_example", SUBMISSION_ID),
    )


def test_reward_polling_returns_last_valid_pending_on_bounded_exhaustion():
    sleeps = []
    transport = _FakeTransport([_reward_status()] * 5)
    client = AgentTaskClient(
        _transport=transport,
        _sleep=sleeps.append,
        _monotonic=lambda: 0.0,
        _random=lambda: 1.0,
    )
    pending = client.wait_for_reward(
        "task_example",
        submission_id=SUBMISSION_ID,
        observation_id=OBSERVATION_ID,
        task_definition=_definition(),
        reward=_reward_terms(),
        timeout_seconds=300,
        max_attempts=5,
    )
    assert pending.reward_state == "pending"
    assert len(transport.calls) == 5
    assert sleeps == [1.25, 2.25, 4.25, 8.25]
    assert all(
        call[2]["_total_timeout_seconds"] == 300.0
        for call in transport.calls
    )

    for invalid_timeout, invalid_attempts in [
        (0, 1),
        (float("inf"), 1),
        (300, 0),
        (300, 11),
        (300, True),
    ]:
        with pytest.raises(TaskTransportError) as caught:
            client.wait_for_reward(
                "task_example",
                submission_id=SUBMISSION_ID,
                observation_id=OBSERVATION_ID,
                task_definition=_definition(),
                reward=_reward_terms(),
                timeout_seconds=invalid_timeout,
                max_attempts=invalid_attempts,
            )
        assert caught.value.request_bytes_sent is False


def test_reward_polling_caps_retry_after_and_stops_at_terminal_failure():
    sleeps = []
    rate_limited = TaskAPIError(
        public_error_code="rate_limited",
        status_code=429,
        retry_after_seconds=999,
    )
    transport = _FakeTransport(
        [
            rate_limited,
            _reward_status(
                task_status="REWARD_FAILED",
                reward_state="failed",
            ),
        ]
    )
    client = AgentTaskClient(
        _transport=transport,
        _sleep=sleeps.append,
        _monotonic=lambda: 0.0,
        _random=lambda: 0.0,
    )
    failed = client.wait_for_reward(
        "task_example",
        submission_id=SUBMISSION_ID,
        observation_id=OBSERVATION_ID,
        task_definition=_definition(),
        reward=_reward_terms(),
        timeout_seconds=100,
        max_attempts=3,
    )
    assert failed.reward_state == "failed"
    assert sleeps == [30.0]
    assert len(transport.calls) == 2


def test_reward_wait_shares_ten_exchange_budget_with_transport_retries():
    exchanges = []
    resolver_calls = []
    transport_sleeps = []
    poll_sleeps = []

    def exchange(**kwargs):
        exchanges.append(kwargs)
        kwargs["tracker"].request_bytes_sent = True
        return 503, {}, b"{}"

    transport = TaskTransport(
        _resolver=lambda host, port: resolver_calls.append((host, port))
        or ("93.184.216.34",),
        _exchange=exchange,
        _sleep=transport_sleeps.append,
        _monotonic=lambda: 0.0,
    )
    client = AgentTaskClient(
        _transport=transport,
        _sleep=poll_sleeps.append,
        _monotonic=lambda: 0.0,
        _random=lambda: 0.0,
    )
    with pytest.raises(TaskTransportError, match="TASK_TIMEOUT"):
        client.wait_for_reward(
            "task_example",
            submission_id=SUBMISSION_ID,
            observation_id=OBSERVATION_ID,
            task_definition=_definition(),
            reward=_reward_terms(),
            timeout_seconds=300,
            max_attempts=10,
        )
    assert len(exchanges) == 10
    assert len(resolver_calls) == 10
    assert transport_sleeps == [0.25, 0.5] * 3
    assert poll_sleeps == [1.0, 2.0, 4.0]


def test_reward_polling_does_not_hide_later_nonretryable_mismatch():
    transport = _FakeTransport(
        [
            _reward_status(),
            _reward_status(task_definition_digest="c" * 64),
        ]
    )
    client = AgentTaskClient(
        _transport=transport,
        _sleep=lambda _: None,
        _monotonic=lambda: 0.0,
        _random=lambda: 0.0,
    )
    with pytest.raises(TaskTransportError, match="TASK_RESPONSE_INVALID"):
        client.wait_for_reward(
            "task_example",
            submission_id=SUBMISSION_ID,
            observation_id=OBSERVATION_ID,
            task_definition=_definition(),
            reward=_reward_terms(),
            timeout_seconds=10,
            max_attempts=2,
        )


def test_explicit_status_refresh_can_move_pending_to_terminal():
    transaction_hash = "0x" + "d" * 64
    transport = _FakeTransport(
        [
            _reward_status(),
            _reward_status(
                task_status="REWARDED",
                reward_state="paid",
                reward_tx_hash=transaction_hash,
                rewarded_at="2026-07-27T02:00:00Z",
            ),
        ]
    )
    client = AgentTaskClient(_transport=transport)
    first = client.get_reward_status(
        "task_example",
        submission_id=SUBMISSION_ID,
        observation_id=OBSERVATION_ID,
        task_definition=_definition(),
        reward=_reward_terms(),
    )
    second = client.get_reward_status(
        "task_example",
        submission_id=SUBMISSION_ID,
        observation_id=OBSERVATION_ID,
        task_definition=_definition(),
        reward=_reward_terms(),
    )
    assert first.reward_state == "pending"
    assert second.reward_state == "paid"


def test_transport_rejects_mixed_public_private_dns_answers():
    with pytest.raises(
        TaskTransportError, match="TASK_DNS_POLICY_REJECTED"
    ):
        _resolve_addresses_bounded(
            lambda host, port: ("93.184.216.34", "127.0.0.1"), 1.0
        )


@pytest.mark.parametrize(
    "address",
    [
        "192.0.0.11",
        "192.0.0.192",
        "192.88.99.2",
        "2002:7f00:1::",
        "3fff::1",
    ],
)
def test_transport_rejects_version_sensitive_special_addresses(address):
    with pytest.raises(
        TaskTransportError, match="TASK_DNS_POLICY_REJECTED"
    ):
        _resolve_addresses_bounded(
            lambda host, port: (address,), 1.0
        )


def test_transport_rejects_deprecated_6to4_relay_before_exchange():
    exchanges = []
    transport = TaskTransport(
        _resolver=lambda host, port: ("192.88.99.2",),
        _exchange=lambda **kwargs: exchanges.append(kwargs)
        or (200, {}, b"{}"),
    )
    with pytest.raises(
        TaskTransportError, match="TASK_DNS_POLICY_REJECTED"
    ) as caught:
        transport.request(
            "GET", "/api/agent/tasks", maximum_attempts=1
        )
    assert caught.value.request_bytes_sent is False
    assert exchanges == []


def test_transport_resolves_and_pins_again_before_every_get_retry():
    resolver_calls = []
    exchange_calls = []
    sleeps = []
    addresses = iter(
        [
            ("93.184.216.34",),
            ("93.184.216.35",),
            ("93.184.216.36",),
        ]
    )
    statuses = iter([503, 504, 200])

    def resolver(host, port):
        resolver_calls.append((host, port))
        return next(addresses)

    def exchange(**kwargs):
        exchange_calls.append(kwargs)
        kwargs["tracker"].request_bytes_sent = True
        status = next(statuses)
        if status == 200:
            return status, {}, b'{"ok":true}'
        return status, {}, b"{}"

    response = TaskTransport(
        _resolver=resolver,
        _exchange=exchange,
        _sleep=sleeps.append,
        _monotonic=lambda: 0.0,
    ).request("GET", "/api/agent/tasks", maximum_attempts=3)
    assert response.data == {"ok": True}
    assert resolver_calls == [(TASK_API_HOST, TASK_API_PORT)] * 3
    assert [call["address"] for call in exchange_calls] == [
        "93.184.216.34",
        "93.184.216.35",
        "93.184.216.36",
    ]
    assert all(call["url"].startswith(PUBLIC_API_ORIGIN) for call in exchange_calls)
    assert sleeps == [0.25, 0.5]


def test_transport_fixed_origin_query_path_and_token_boundaries():
    for origin in [
        "http://kari.mayim-mayim.com",
        "https://user@kari.mayim-mayim.com",
        "https://kari.mayim-mayim.com:444",
        "https://kari.mayim-mayim.com/path",
        "https://kari.mayim-mayim.com/?query=1",
        "https://evil.example",
    ]:
        with pytest.raises(TaskTransportError) as caught:
            TaskTransport(api_origin=origin)
        assert caught.value.code == "TASK_ORIGIN_INVALID"
        assert caught.value.request_bytes_sent is False

    transport = TaskTransport(
        _resolver=lambda host, port: ("93.184.216.34",),
        _exchange=lambda **kwargs: (200, {}, b"{}"),
    )
    invalid_calls = [
        ("GET", "https://evil.example/api/agent/tasks", {}),
        ("GET", "/api/agent/tasks/../claim", {}),
        ("POST", "/api/agent/tasks/task_example/claim", {"params": {"x": "1"}}),
        (
            "GET",
            "/api/agent/tasks",
            {"params": {"task_type": "other"}},
        ),
        (
            "GET",
            "/api/agent/tasks",
            {"claim_token": CLAIM_TOKEN},
        ),
    ]
    for method, path, kwargs in invalid_calls:
        with pytest.raises(TaskTransportError) as caught:
            transport.request(method, path, **kwargs)
        assert caught.value.request_bytes_sent is False


def test_submission_status_transport_is_public_free_and_read_only():
    exchanges = []

    def exchange(**kwargs):
        exchanges.append(kwargs)
        kwargs["tracker"].request_bytes_sent = True
        return (
            200,
            {},
            json.dumps(_reward_status(), separators=(",", ":")).encode(),
        )

    path = task_submission_status_path("task_example", SUBMISSION_ID)
    response = TaskTransport(
        _resolver=lambda host, port: ("93.184.216.34",),
        _exchange=exchange,
    ).request("GET", path, maximum_attempts=3)
    assert response.data["submission_id"] == SUBMISSION_ID
    assert len(exchanges) == 1
    assert exchanges[0]["claim_token"] is None
    assert exchanges[0]["body"] is None

    with pytest.raises(TaskTransportError) as caught:
        TaskTransport(
            _resolver=lambda host, port: ("93.184.216.34",),
            _exchange=exchange,
        ).request(
            "GET",
            path,
            claim_token=CLAIM_TOKEN,
            maximum_attempts=1,
        )
    assert caught.value.code == "TASK_CREDENTIAL_INVALID"
    assert caught.value.request_bytes_sent is False


@pytest.mark.parametrize("task_id", [".", ".."])
def test_dot_task_ids_are_percent_encoded_and_stay_below_task_prefix(task_id):
    import httpx

    expected_id = "%2E" if task_id == "." else "%2E%2E"
    expected = {
        "detail": "/api/agent/tasks/" + expected_id,
        "claim": "/api/agent/tasks/" + expected_id + "/claim",
        "observation": (
            "/api/agent/tasks/" + expected_id + "/domain-observations"
        ),
        "completion": (
            "/api/agent/tasks/" + expected_id + "/completion"
        ),
        "status": (
            "/api/agent/tasks/"
            + expected_id
            + "/submissions/"
            + SUBMISSION_ID
            + "/status"
        ),
    }
    actual = {
        "detail": task_detail_path(task_id),
        "claim": task_claim_path(task_id),
        "observation": task_observation_path(task_id),
        "completion": task_completion_path(task_id),
        "status": task_submission_status_path(task_id, SUBMISSION_ID),
    }
    assert actual == expected
    for path in actual.values():
        raw_path = httpx.URL(PUBLIC_API_ORIGIN + path).raw_path
        assert raw_path.startswith(b"/api/agent/tasks/%2E")
        assert b"/api/agent/tasks/../" not in raw_path
        assert b"/api/agent/tasks/./" not in raw_path


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("GET", "/api/agent/tasks/.", {}),
        ("GET", "/api/agent/tasks/..", {}),
        (
            "POST",
            "/api/agent/tasks/./claim",
            {"json_body": {}},
        ),
        (
            "POST",
            "/api/agent/tasks/../claim",
            {"json_body": {}},
        ),
        (
            "POST",
            "/api/agent/tasks/./domain-observations",
            {"json_body": {}, "claim_token": CLAIM_TOKEN},
        ),
        (
            "POST",
            "/api/agent/tasks/../domain-observations",
            {"json_body": {}, "claim_token": CLAIM_TOKEN},
        ),
        (
            "POST",
            "/api/agent/tasks/./completion",
            {"json_body": {}, "claim_token": CLAIM_TOKEN},
        ),
        (
            "POST",
            "/api/agent/tasks/../completion",
            {"json_body": {}, "claim_token": CLAIM_TOKEN},
        ),
        (
            "GET",
            "/api/agent/tasks/./submissions/sub_00000000000000000000000000000000/status",
            {},
        ),
        (
            "GET",
            "/api/agent/tasks/task_example/submissions/../status",
            {},
        ),
    ],
)
def test_raw_dot_task_paths_are_rejected_before_dns_exchange_or_token_dispatch(
    method, path, kwargs
):
    resolver_calls = []
    exchange_calls = []

    def resolver(host, port):
        resolver_calls.append((host, port))
        return ("93.184.216.34",)

    def exchange(**exchange_kwargs):
        exchange_calls.append(exchange_kwargs)
        return 200, {}, b"{}"

    transport = TaskTransport(_resolver=resolver, _exchange=exchange)
    with pytest.raises(TaskTransportError) as caught:
        transport.request(method, path, **kwargs)
    assert caught.value.code == "TASK_ORIGIN_INVALID"
    assert caught.value.request_bytes_sent is False
    assert resolver_calls == []
    assert exchange_calls == []
    assert CLAIM_TOKEN not in repr(caught.value)


def test_transport_httpx_configuration_has_no_ambient_credentials(monkeypatch):
    captured = {}

    class FakeHeaders:
        def multi_items(self):
            return []

    class FakeResponse:
        status_code = 200
        headers = FakeHeaders()

        def iter_raw(self):
            yield b'{"ok":true}'

    class StreamContext:
        def __enter__(self):
            return FakeResponse()

        def __exit__(self, exc_type, exc, traceback):
            return False

    class FakeClient:
        def __init__(self, **kwargs):
            captured["client"] = kwargs

        def stream(self, method, url, **kwargs):
            captured["stream"] = (method, url, kwargs)
            return StreamContext()

        def close(self):
            captured["closed"] = True

    monkeypatch.setattr(
        "ln_church_agent.task_transport._new_pinned_httpx_transport",
        lambda *args, **kwargs: object(),
    )
    monkeypatch.setattr(
        "ln_church_agent.task_transport.httpx.Client", FakeClient
    )
    response = TaskTransport(
        _resolver=lambda host, port: ("93.184.216.34",)
    ).request("GET", "/api/agent/tasks", maximum_attempts=1)
    assert response.data == {"ok": True}
    assert captured["client"]["trust_env"] is False
    assert captured["client"]["follow_redirects"] is False
    assert captured["client"]["cookies"] is None
    assert captured["client"]["auth"] is None
    method, url, stream_kwargs = captured["stream"]
    assert method == "GET"
    assert url == PUBLIC_API_ORIGIN + "/api/agent/tasks"
    assert stream_kwargs["headers"]["Accept-Encoding"] == "identity"
    assert (
        stream_kwargs["headers"]["User-Agent"]
        == "ln-church-agent-task/1.17.0"
    )
    assert "Cookie" not in stream_kwargs["headers"]
    assert "Authorization" not in stream_kwargs["headers"]
    assert captured["closed"] is True


def test_pinned_httpx_transport_forces_tls_verification(monkeypatch):
    captured = {}

    class FakePool:
        _network_backend = None

    class FakeHTTPTransport:
        def __init__(self, **kwargs):
            captured.update(kwargs)
            self._pool = FakePool()

        def close(self):
            pass

    monkeypatch.setattr(
        "ln_church_agent.task_transport.httpx.HTTPTransport",
        FakeHTTPTransport,
    )
    tracker = SimpleNamespace(request_bytes_sent=None)
    transport = _new_pinned_httpx_transport(
        "93.184.216.34",
        tracker,
        deadline=100.0,
        monotonic=lambda: 0.0,
    )
    assert captured == {
        "verify": True,
        "trust_env": False,
        "http1": True,
        "http2": False,
        "retries": 0,
    }
    assert tracker.request_bytes_sent is False
    assert transport._pool._network_backend._address == "93.184.216.34"


def test_transport_rejects_redirect_payment_and_encoded_response():
    cases = [
        (302, {}, b"{}", "TASK_REDIRECT_REJECTED"),
        (402, {}, b"{}", "TASK_PAYMENT_UNEXPECTED"),
        (
            200,
            {"content-encoding": "gzip"},
            b"{}",
            "TASK_RESPONSE_ENCODING_REJECTED",
        ),
    ]
    for status, headers, body, code in cases:
        calls = []

        def exchange(**kwargs):
            calls.append(kwargs)
            kwargs["tracker"].request_bytes_maybe_sent = True
            return status, headers, body

        transport = TaskTransport(
            _resolver=lambda host, port: ("93.184.216.34",),
            _exchange=exchange,
        )
        with pytest.raises(TaskTransportError, match=code):
            transport.request("GET", "/api/agent/tasks", maximum_attempts=1)
        assert len(calls) == 1


def test_worker_402_never_retries_or_enters_payment_execution(monkeypatch):
    calls = []

    def exchange(**kwargs):
        calls.append(kwargs)
        kwargs["tracker"].request_bytes_sent = True
        return 402, {}, b'{"payment":"challenge"}'

    def payment_forbidden(*args, **kwargs):
        raise AssertionError("payment execution must not be reached")

    monkeypatch.setattr(
        "ln_church_agent.client.LnChurchClient.execute_request",
        payment_forbidden,
    )
    transport = TaskTransport(
        _resolver=lambda host, port: ("93.184.216.34",),
        _exchange=exchange,
    )
    with pytest.raises(TaskTransportError) as caught:
        transport.request(
            "GET", "/api/agent/tasks", maximum_attempts=3
        )
    assert caught.value.code == "TASK_PAYMENT_UNEXPECTED"
    assert len(calls) == 1


def test_observation_retry_reuses_identical_submission_bytes_and_claim_token():
    calls = []
    sleeps = []

    def exchange(**kwargs):
        calls.append(kwargs)
        kwargs["tracker"].request_bytes_sent = True
        if len(calls) == 1:
            return 503, {}, b"{}"
        return (
            200,
            {},
            json.dumps(
                {
                    "schema_version": (
                        "ln_church.task_domain_observation_response.v1"
                    ),
                    "accepted": True,
                    "task_id": "task_example",
                    "submission_id": "sub_" + "0" * 32,
                    "observation_id": "obs_example",
                    "status": "recorded",
                },
                separators=(",", ":"),
            ).encode("utf-8"),
        )

    transport = TaskTransport(
        _resolver=lambda host, port: ("93.184.216.34",),
        _exchange=exchange,
        _sleep=sleeps.append,
        _monotonic=lambda: 0.0,
    )
    submission = TaskDomainObservationSubmission(
        submission_id="sub_" + "0" * 32,
        observed_domain="example.com",
        discovered_surfaces=[_surface()],
    )
    result = AgentTaskClient(_transport=transport).submit_domain_observation(
        _credential(), submission
    )
    assert result.observation_id == "obs_example"
    assert len(calls) == 2
    assert calls[0]["body"] == calls[1]["body"]
    assert calls[0]["claim_token"] == calls[1]["claim_token"] == CLAIM_TOKEN
    assert sleeps == [0.25]


@pytest.mark.parametrize(
    ("operation", "public_code", "status_code"),
    [
        ("submit", "claim_token_invalid", 401),
        ("submit", "submission_conflict", 409),
        ("complete", "claim_token_invalid", 401),
    ],
)
def test_old_or_cross_claim_credential_outcomes_remain_finite(
    operation, public_code, status_code
):
    transport = _FakeTransport(
        [
            TaskAPIError(
                public_error_code=public_code,
                status_code=status_code,
                request_bytes_sent=True,
                mutation_free=False,
            )
        ]
    )
    client = AgentTaskClient(_transport=transport)
    with pytest.raises(TaskAPIError) as caught:
        if operation == "submit":
            client.submit_domain_observation(
                _credential(),
                TaskDomainObservationSubmission(
                    submission_id=SUBMISSION_ID,
                    observed_domain="example.com",
                    discovered_surfaces=[_surface()],
                ),
            )
        else:
            client.complete_task(
                _credential(),
                submission_id=SUBMISSION_ID,
                observation_id=OBSERVATION_ID,
            )
    assert caught.value.public_error_code == public_code
    assert len(transport.calls) == 1
    assert transport.calls[0][2]["claim_token"] == CLAIM_TOKEN


def test_submission_is_snapshotted_and_strictly_revalidated_before_transport():
    transport = _FakeTransport([])
    client = AgentTaskClient(_transport=transport)

    over_limit = TaskDomainObservationSubmission(
        submission_id="sub_" + "0" * 32,
        observed_domain="example.com",
        observed_urls=[_observed_url()] * 50,
        discovered_surfaces=[_surface()],
    )
    over_limit.observed_urls.append(
        TaskObservedUrlEntry.model_validate(_observed_url())
    )
    with pytest.raises(TaskTransportError) as caught:
        client.submit_domain_observation(_credential(), over_limit)
    assert caught.value.code == "TASK_CREDENTIAL_INVALID"
    assert transport.calls == []

    hostile_nested_entry = TaskDomainObservationSubmission(
        submission_id="sub_" + "1" * 32,
        observed_domain="example.com",
        discovered_surfaces=[_surface()],
    )
    hostile_nested_entry.discovered_surfaces.append(
        {
            **_surface(),
            "raw_body": "must-not-cross-the-task-boundary",
        }
    )
    with pytest.raises(TaskTransportError) as caught:
        client.submit_domain_observation(
            _credential(), hostile_nested_entry
        )
    assert caught.value.code == "TASK_CREDENTIAL_INVALID"
    assert transport.calls == []

    constructed_nested_entry = TaskDomainObservationSubmission(
        submission_id="sub_" + "2" * 32,
        observed_domain="example.com",
        discovered_surfaces=[_surface()],
    )
    constructed_nested_entry.observed_urls.append(
        TaskObservedUrlEntry.model_construct(
            url="https://example.com/",
            method="POST",
            status_code=200,
            media_family="html",
            observed_at="2026-07-27T00:10:00Z",
        )
    )
    with pytest.raises(TaskTransportError) as caught:
        client.submit_domain_observation(
            _credential(), constructed_nested_entry
        )
    assert caught.value.code == "TASK_CREDENTIAL_INVALID"
    assert transport.calls == []


def test_submission_public_canonical_methods_strictly_revalidate_mutations():
    submission = TaskDomainObservationSubmission(
        submission_id="sub_" + "3" * 32,
        observed_domain="example.com",
        observed_urls=[_observed_url()] * 50,
        discovered_surfaces=[_surface()],
    )
    submission.observed_urls.append(
        TaskObservedUrlEntry.model_validate(_observed_url())
    )
    for method_name in (
        "canonical_bytes",
        "canonical_digest",
        "canonical_digest_hex",
    ):
        with pytest.raises(
            ValueError, match="Invalid Task domain observation submission"
        ):
            getattr(submission, method_name)()

    raw_body = "raw-body-must-never-be-canonicalized"
    hostile = TaskDomainObservationSubmission(
        submission_id="sub_" + "4" * 32,
        observed_domain="example.com",
        discovered_surfaces=[_surface()],
    )
    hostile.discovered_surfaces.append(
        {**_surface(), "raw_body": raw_body}
    )
    with pytest.raises(ValueError) as caught:
        hostile.canonical_bytes()
    assert raw_body not in str(caught.value)


def test_claim_token_cannot_enter_submission_or_completion_public_fields():
    transport = _FakeTransport([])
    client = AgentTaskClient(_transport=transport)
    submission = TaskDomainObservationSubmission(
        submission_id="sub_" + "5" * 32,
        observed_domain="example.com",
        observed_urls=[
            _observed_url("https://example.com/" + CLAIM_TOKEN)
        ],
        discovered_surfaces=[_surface()],
    )
    with pytest.raises(TaskTransportError) as caught:
        client.submit_domain_observation(_credential(), submission)
    assert caught.value.code == "TASK_CREDENTIAL_INVALID"

    with pytest.raises(TaskTransportError) as caught:
        client.complete_task(
            _credential(),
            submission_id="sub_" + "6" * 32,
            observation_id=CLAIM_TOKEN,
        )
    assert caught.value.code == "TASK_CREDENTIAL_INVALID"
    assert transport.calls == []


def test_claim_response_cannot_copy_token_into_public_result_fields():
    payload = _claim_response()
    payload["task_id"] = CLAIM_TOKEN
    transport = _FakeTransport([payload])
    client = AgentTaskClient(_transport=transport)
    with pytest.raises(
        TaskAmbiguousOutcomeError, match="CLAIM_OUTCOME_UNKNOWN"
    ) as caught:
        client.claim_task(
            "task_example",
            agent_id="external-agent",
            reward_address=REWARD_ADDRESS,
        )
    surfaces = [str(caught.value), repr(caught.value), repr(vars(caught.value))]
    assert all(CLAIM_TOKEN not in surface for surface in surfaces)
    assert len(transport.calls) == 1


def test_reflected_claim_token_is_absent_from_client_exception_graph():
    transport = _FakeTransport(
        [
            {
                "schema_version": (
                    "ln_church.task_domain_observation_response.v1"
                ),
                "accepted": True,
                "task_id": "task_example",
                "submission_id": CLAIM_TOKEN,
                "observation_id": "obs_example",
                "status": "recorded",
            }
        ]
    )
    submission = TaskDomainObservationSubmission(
        submission_id="sub_" + "7" * 32,
        observed_domain="example.com",
        discovered_surfaces=[_surface()],
    )
    with pytest.raises(
        TaskAmbiguousOutcomeError, match="SUBMISSION_OUTCOME_UNKNOWN"
    ) as caught:
        AgentTaskClient(
            _transport=transport
        ).submit_domain_observation(_credential(), submission)
    _assert_finite_exception_graph(caught.value, CLAIM_TOKEN)


def test_request_body_size_bound_is_checked_before_dns_or_exchange():
    resolver_calls = []
    exchange_calls = []
    transport = TaskTransport(
        _resolver=lambda host, port: resolver_calls.append((host, port))
        or ("93.184.216.34",),
        _exchange=lambda **kwargs: exchange_calls.append(kwargs)
        or (200, {}, b"{}"),
    )
    oversized = {"value": "x" * MAXIMUM_JSON_BYTES}
    with pytest.raises(TaskTransportError) as caught:
        transport.request(
            "POST",
            "/api/agent/tasks/task_example/claim",
            json_body=oversized,
            maximum_attempts=1,
        )
    assert caught.value.code == "TASK_RESPONSE_TOO_LARGE"
    assert caught.value.request_bytes_sent is False
    assert resolver_calls == []
    assert exchange_calls == []


def test_transport_treats_claim_timeout_after_write_as_ambiguous_once():
    calls = []

    def exchange(**kwargs):
        calls.append(kwargs)
        kwargs["tracker"].request_bytes_maybe_sent = True
        raise TimeoutError

    transport = TaskTransport(
        _resolver=lambda host, port: ("93.184.216.34",),
        _exchange=exchange,
    )
    with pytest.raises(
        TaskAmbiguousOutcomeError, match="CLAIM_OUTCOME_UNKNOWN"
    ):
        transport.request(
            "POST",
            "/api/agent/tasks/task_example/claim",
            json_body={
                "schema_version": "ln_church.agent_task_claim_request.v1",
                "agent_id": "external-agent",
                "reward_address": REWARD_ADDRESS,
            },
            maximum_attempts=1,
            ambiguous_delivery_code="CLAIM_OUTCOME_UNKNOWN",
        )
    assert len(calls) == 1


def test_complete_api_error_claim_mutation_free_classification():
    def exchange(**kwargs):
        kwargs["tracker"].request_bytes_maybe_sent = True
        return (
            409,
            {},
            json.dumps(
                {
                    "schema_version": "ln_church.agent_task_error.v1",
                    "error_code": "task_not_open",
                }
            ).encode(),
        )

    transport = TaskTransport(
        _resolver=lambda host, port: ("93.184.216.34",),
        _exchange=exchange,
    )
    with pytest.raises(TaskAPIError) as caught:
        transport.request(
            "POST",
            "/api/agent/tasks/task_example/claim",
            json_body={
                "schema_version": "ln_church.agent_task_claim_request.v1",
                "agent_id": "external-agent",
                "reward_address": REWARD_ADDRESS,
            },
            maximum_attempts=1,
            ambiguous_delivery_code="CLAIM_OUTCOME_UNKNOWN",
        )
    assert caught.value.public_error_code == "task_not_open"
    assert caught.value.mutation_free is True


@pytest.mark.parametrize(
    ("error", "expect_exists", "expected_stderr"),
    [
        (
            TaskTransportError(
                "TASK_TIMEOUT", request_bytes_sent=False
            ),
            False,
            "TASK_TIMEOUT",
        ),
        (
            TaskAPIError(
                public_error_code="task_not_open",
                status_code=409,
                request_bytes_sent=True,
                mutation_free=True,
            ),
            False,
            "TASK_API_ERROR",
        ),
        (
            TaskTransportError(
                "TASK_TIMEOUT", request_bytes_sent=None
            ),
            True,
            "CLAIM_OUTCOME_UNKNOWN",
        ),
        (
            TaskTransportError(
                "TASK_PAYMENT_UNEXPECTED",
                status_code=402,
                request_bytes_sent=True,
            ),
            True,
            "CLAIM_OUTCOME_UNKNOWN",
        ),
    ],
)
def test_cli_claim_removes_only_proven_safe_reservation_and_tombstones_unknown(
    tmp_path, capsys, error, expect_exists, expected_stderr
):
    class FakeClient:
        calls = 0

        def claim_task(self, *args, **kwargs):
            self.calls += 1
            raise error

        def close(self):
            pass

    output_path = tmp_path / "claim.json"
    argv = [
        "ln-church-agent",
        "task",
        "claim",
        "task_example",
        "--agent-id",
        "external-agent",
        "--reward-address",
        REWARD_ADDRESS,
        "--credential-file",
        str(output_path),
    ]
    fake = FakeClient()
    with patch(
        "ln_church_agent.task_client.AgentTaskClient",
        return_value=fake,
    ):
        with patch.object(sys, "argv", argv):
            from ln_church_agent.cli import main

            with pytest.raises(SystemExit) as caught:
                main()
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert expected_stderr in captured.err
    assert CLAIM_TOKEN not in captured.out + captured.err
    assert fake.calls == 1
    assert output_path.exists() is expect_exists
    if expect_exists:
        tombstone = json.loads(output_path.read_text(encoding="utf-8"))
        assert set(tombstone) == {
            "schema_version",
            "state",
            "api_origin",
            "task_id",
            "created_at",
        }
        assert tombstone["state"] == "CLAIM_OUTCOME_UNKNOWN"
        assert "claim_token" not in tombstone


def test_cli_claim_reserves_mode_0600_and_never_prints_token(tmp_path, capsys):
    claim = AgentTaskClaimResponse(
        schema_version="ln_church.agent_task_claim_response.v1",
        task_id="task_example",
        task_type=TASK_TYPE,
        **_definition_payload(),
        status="CLAIMED",
        claim_token=CLAIM_TOKEN,
        lease_duration_seconds=3600,
        lease_expires_at="2099-07-27T01:00:00Z",
        reward_address=REWARD_ADDRESS,
        reward_address_control_verified=False,
        reward=_reward(),
    ).to_claim("external-agent")

    class FakeClient:
        def claim_task(self, *args, **kwargs):
            return claim

        def close(self):
            pass

    output_path = tmp_path / "claim.json"
    argv = [
        "ln-church-agent",
        "task",
        "claim",
        "task_example",
        "--agent-id",
        "external-agent",
        "--reward-address",
        REWARD_ADDRESS,
        "--credential-file",
        str(output_path),
        "--json",
    ]
    with patch("ln_church_agent.task_client.AgentTaskClient", FakeClient):
        with patch.object(sys, "argv", argv):
            from ln_church_agent.cli import main

            main()
    captured = capsys.readouterr()
    assert CLAIM_TOKEN not in captured.out
    assert CLAIM_TOKEN not in captured.err
    public_data = json.loads(captured.out)
    assert public_data["task_type"] == TASK_TYPE
    assert "domain" not in public_data
    private_data = json.loads(output_path.read_text(encoding="utf-8"))
    assert private_data["claim_token"] == CLAIM_TOKEN
    assert "domain" not in private_data
    if os.name != "nt":
        assert stat.S_IMODE(output_path.stat().st_mode) == 0o600


def test_cli_claim_keeps_one_descriptor_through_write_and_fsync(
    tmp_path, capsys, monkeypatch
):
    claim = AgentTaskClaimResponse.model_validate(_claim_response()).to_claim(
        "external-agent"
    )

    class FakeClient:
        def claim_task(self, *args, **kwargs):
            return claim

        def close(self):
            pass

    from ln_church_agent import cli

    output_path = tmp_path / "same-fd.json"
    original_open = cli.os.open
    original_fsync = cli.os.fsync
    opened = []
    synced = []

    def tracked_open(path, flags, *args):
        descriptor = original_open(path, flags, *args)
        if os.path.abspath(str(path)) == os.path.abspath(str(output_path)):
            opened.append(descriptor)
        return descriptor

    def tracked_fsync(descriptor):
        synced.append(descriptor)
        return original_fsync(descriptor)

    monkeypatch.setattr(cli.os, "open", tracked_open)
    monkeypatch.setattr(cli.os, "fsync", tracked_fsync)
    argv = [
        "ln-church-agent",
        "task",
        "claim",
        "task_example",
        "--agent-id",
        "external-agent",
        "--reward-address",
        REWARD_ADDRESS,
        "--credential-file",
        str(output_path),
        "--json",
    ]
    with patch(
        "ln_church_agent.task_client.AgentTaskClient",
        FakeClient,
    ):
        with patch.object(sys, "argv", argv):
            cli.main()
    assert len(opened) == 1
    assert synced == [opened[0]]
    assert json.loads(output_path.read_text(encoding="utf-8"))[
        "claim_token"
    ] == CLAIM_TOKEN
    assert CLAIM_TOKEN not in "".join(capsys.readouterr())


@pytest.mark.skipif(os.name == "nt", reason="POSIX inode boundary")
def test_credential_reservation_rejects_symlink_parent_and_hardlink_change(
    tmp_path
):
    from ln_church_agent.cli import _TaskCredentialReservation

    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(ValueError, match="TASK_CREDENTIAL_INVALID"):
        _TaskCredentialReservation(str(linked_parent / "claim.json"))

    path = tmp_path / "claim.json"
    alias = tmp_path / "claim-alias.json"
    reservation = _TaskCredentialReservation(str(path))
    try:
        os.link(path, alias)
        with pytest.raises(ValueError, match="TASK_CREDENTIAL_INVALID"):
            reservation.write_payload({"state": "ACTIVE"})
    finally:
        reservation.close()
        if alias.exists():
            alias.unlink()
        if path.exists():
            path.unlink()


@pytest.mark.skipif(os.name == "nt", reason="POSIX inode boundary")
def test_credential_reservation_rejects_path_identity_replacement(tmp_path):
    from ln_church_agent.cli import _TaskCredentialReservation

    path = tmp_path / "claim.json"
    reservation = _TaskCredentialReservation(str(path))
    try:
        path.unlink()
        path.write_text("replacement", encoding="utf-8")
        os.chmod(path, 0o600)
        with pytest.raises(ValueError, match="TASK_CREDENTIAL_INVALID"):
            reservation.write_payload({"state": "ACTIVE"})
    finally:
        reservation.close()
        if path.exists():
            path.unlink()


def test_task_json_file_exact_size_limit_symlink_and_hardlink(tmp_path):
    from ln_church_agent.cli import _read_task_json_file

    prefix = b'{"value":"'
    suffix = b'"}'
    exact = tmp_path / "exact.json"
    exact.write_bytes(
        prefix
        + (b"x" * (MAXIMUM_JSON_BYTES - len(prefix) - len(suffix)))
        + suffix
    )
    assert len(_read_task_json_file(str(exact), require_private=False)["value"]) == (
        MAXIMUM_JSON_BYTES - len(prefix) - len(suffix)
    )

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(exact.read_bytes() + b" ")
    with pytest.raises(ValueError, match="TASK_CREDENTIAL_INVALID"):
        _read_task_json_file(str(oversized), require_private=False)

    symlink = tmp_path / "symlink.json"
    try:
        symlink.symlink_to(exact)
    except (NotImplementedError, OSError):
        pass
    else:
        with pytest.raises((OSError, ValueError)):
            _read_task_json_file(str(symlink), require_private=False)

    if os.name != "nt":
        os.chmod(exact, 0o600)
        hardlink = tmp_path / "hardlink.json"
        os.link(exact, hardlink)
        with pytest.raises(ValueError, match="TASK_CREDENTIAL_INVALID"):
            _read_task_json_file(str(exact), require_private=True)


@pytest.mark.parametrize(
    "content",
    [
        '{"submission_id":"first","submission_id":"second"}',
        '{"nested":{"url":"first","url":"second"}}',
        '{"value":NaN}',
        '{"value":Infinity}',
    ],
)
def test_task_json_file_rejects_duplicate_keys_and_non_json_numbers(
    tmp_path, content
):
    from ln_church_agent.cli import _read_task_json_file

    path = tmp_path / "observation.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="TASK_CREDENTIAL_INVALID"):
        _read_task_json_file(str(path), require_private=False)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission boundary")
def test_task_file_rejects_unsafe_intermediate_ancestor(tmp_path):
    from ln_church_agent.cli import _validated_task_file_path

    unsafe = tmp_path / "unsafe"
    safe_parent = unsafe / "safe"
    safe_parent.mkdir(parents=True)
    os.chmod(unsafe, 0o777)
    os.chmod(safe_parent, 0o700)
    try:
        with pytest.raises(ValueError, match="TASK_CREDENTIAL_INVALID"):
            _validated_task_file_path(str(safe_parent / "claim.json"))
    finally:
        os.chmod(unsafe, 0o700)


def test_task_json_file_claims_root_policy_depends_on_file_sensitivity(
    monkeypatch
):
    import ln_church_agent.cli as cli

    seen = []

    def fake_path_validation(path, *, require_claims_root):
        seen.append((path, require_claims_root))
        raise ValueError("sentinel")

    monkeypatch.setattr(
        cli, "_validated_task_file_path", fake_path_validation
    )
    for require_private in (False, True):
        with pytest.raises(ValueError, match="sentinel"):
            cli._read_task_json_file(
                "C:\\input.json",
                require_private=require_private,
            )
    assert [entry[1] for entry in seen] == [False, True]


@pytest.mark.parametrize("variant", ["expired", "unknown", "tombstone"])
def test_cli_credential_invalid_expired_or_unknown_never_reaches_network(
    tmp_path, capsys, variant
):
    credential_path = tmp_path / "credential.json"
    payload = _credential()._to_private_file_payload()
    if variant == "expired":
        payload["lease_expires_at"] = "2020-01-01T00:00:00Z"
    elif variant == "unknown":
        payload["future"] = "untrusted"
    else:
        payload = {
            "schema_version": "ln_church.task_claim_credential_file.v1",
            "state": "CLAIM_OUTCOME_UNKNOWN",
            "api_origin": PUBLIC_API_ORIGIN,
            "task_id": "task_example",
            "created_at": "2026-07-27T00:00:00Z",
        }
    credential_path.write_text(json.dumps(payload), encoding="utf-8")
    if os.name != "nt":
        os.chmod(credential_path, 0o600)

    class FakeClient:
        calls = 0

        def submit_domain_observation(self, *args, **kwargs):
            self.calls += 1
            raise AssertionError("network must not be reached")

        def close(self):
            pass

    observation_path = tmp_path / "observation.json"
    observation_path.write_text(
        json.dumps(
            TaskDomainObservationSubmission(
                observed_domain="example.com",
                discovered_surfaces=[_surface()],
            ).model_dump(mode="json")
        ),
        encoding="utf-8",
    )
    argv = [
        "ln-church-agent",
        "task",
        "submit",
        "task_example",
        "--credential-file",
        str(credential_path),
        "--file",
        str(observation_path),
    ]
    fake = FakeClient()
    with patch(
        "ln_church_agent.task_client.AgentTaskClient",
        return_value=fake,
    ):
        with patch.object(sys, "argv", argv):
            from ln_church_agent.cli import main

            with pytest.raises(SystemExit) as caught:
                main()
    assert caught.value.code == 2
    assert fake.calls == 0
    captured = capsys.readouterr()
    expected = (
        "TASK_CREDENTIAL_EXPIRED"
        if variant == "expired"
        else "TASK_CREDENTIAL_INVALID"
    )
    assert expected in captured.err
    assert CLAIM_TOKEN not in captured.out + captured.err


@pytest.mark.parametrize("command", ["status", "reward-wait"])
def test_cli_status_commands_use_expired_public_snapshot_without_token(
    tmp_path, capsys, command
):
    credential_path = tmp_path / "credential.json"
    payload = _credential()._to_private_file_payload()
    payload["lease_expires_at"] = "2020-01-01T00:00:00Z"
    credential_path.write_text(json.dumps(payload), encoding="utf-8")
    if os.name != "nt":
        os.chmod(credential_path, 0o600)

    seen = []

    class FakeClient:
        def get_reward_status(self, task_id, **kwargs):
            seen.append(("status", task_id, kwargs))
            return AgentTaskRewardStatus.model_validate(_reward_status())

        def wait_for_reward(self, task_id, **kwargs):
            seen.append(("reward-wait", task_id, kwargs))
            return AgentTaskRewardStatus.model_validate(_reward_status())

        def close(self):
            pass

    argv = [
        "ln-church-agent",
        "task",
        command,
        "task_example",
        "--credential-file",
        str(credential_path),
        "--submission-id",
        SUBMISSION_ID,
        "--observation-id",
        OBSERVATION_ID,
        "--json",
    ]
    with patch("ln_church_agent.task_client.AgentTaskClient", FakeClient):
        with patch.object(sys, "argv", argv):
            from ln_church_agent.cli import main

            main()
    captured = capsys.readouterr()
    assert len(seen) == 1
    assert seen[0][0] == command
    assert seen[0][1] == "task_example"
    assert seen[0][2]["submission_id"] == SUBMISSION_ID
    assert seen[0][2]["observation_id"] == OBSERVATION_ID
    assert seen[0][2]["task_definition"] == _definition()
    assert seen[0][2]["reward"] == _reward_terms()
    assert "credential" not in seen[0][2]
    assert CLAIM_TOKEN not in captured.out + captured.err + repr(seen)


def test_cli_status_task_mismatch_fails_before_client_call(tmp_path, capsys):
    credential_path = tmp_path / "credential.json"
    credential_path.write_text(
        json.dumps(_credential()._to_private_file_payload()),
        encoding="utf-8",
    )
    if os.name != "nt":
        os.chmod(credential_path, 0o600)

    class FakeClient:
        calls = 0

        def get_reward_status(self, *args, **kwargs):
            self.calls += 1
            raise AssertionError("network must not be reached")

        def close(self):
            pass

    fake = FakeClient()
    argv = [
        "ln-church-agent",
        "task",
        "status",
        "task_other",
        "--credential-file",
        str(credential_path),
        "--submission-id",
        SUBMISSION_ID,
        "--observation-id",
        OBSERVATION_ID,
    ]
    with patch(
        "ln_church_agent.task_client.AgentTaskClient",
        return_value=fake,
    ):
        with patch.object(sys, "argv", argv):
            from ln_church_agent.cli import main

            with pytest.raises(SystemExit) as caught:
                main()
    assert caught.value.code == 2
    assert fake.calls == 0
    captured = capsys.readouterr()
    assert "TASK_CREDENTIAL_INVALID" in captured.err
    assert CLAIM_TOKEN not in captured.out + captured.err


def test_cli_claim_never_overwrites_existing_credential(tmp_path, capsys):
    output_path = tmp_path / "claim.json"
    output_path.write_text("owner-data", encoding="utf-8")
    if os.name != "nt":
        os.chmod(output_path, 0o600)
    argv = [
        "ln-church-agent",
        "task",
        "claim",
        "task_example",
        "--agent-id",
        "external-agent",
        "--reward-address",
        REWARD_ADDRESS,
        "--credential-file",
        str(output_path),
    ]
    with patch.object(sys, "argv", argv):
        from ln_church_agent.cli import main

        with pytest.raises(SystemExit) as caught:
            main()
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert "TASK_CREDENTIAL_INVALID" in captured.err
    assert output_path.read_text(encoding="utf-8") == "owner-data"


def test_guided_operation_derives_completion_only_from_register_receipt():
    submission = TaskDomainObservationSubmission(
        **_submission_payload()
    )
    transport = _FakeTransport(
        [_register_response(), _completion_response()]
    )
    checkpoints = []

    result = AgentTaskClient(
        _transport=transport
    ).submit_and_complete_domain_observation(
        _credential(),
        submission,
        checkpoint_sink=checkpoints.append,
    )

    assert isinstance(result, TaskDomainObservationGuidedResult)
    assert result.register_receipt.model_dump(mode="json") == (
        _register_response()
    )
    assert result.completion_receipt.model_dump(mode="json") == (
        _completion_response()
    )
    assert result.matched_status is None
    assert [checkpoint.state for checkpoint in checkpoints] == [
        TaskDomainObservationCheckpointState.REGISTER_PENDING,
        TaskDomainObservationCheckpointState.REGISTERED,
    ]
    assert [
        (method, path) for method, path, _ in transport.calls
    ] == [
        (
            "POST",
            task_observation_path("task_example"),
        ),
        (
            "POST",
            task_completion_path("task_example"),
        ),
    ]
    completion_body = transport.calls[1][2]["json_body"]
    assert completion_body == {
        "schema_version": (
            "ln_church.agent_task_completion_request.v1"
        ),
        "submission_id": result.register_receipt.submission_id,
        "observation_id": result.register_receipt.observation_id,
    }
    assert len(
        {
            id(call[2]["_exchange_budget"])
            for call in transport.calls
        }
    ) == 1

    parameters = inspect.signature(
        AgentTaskClient.submit_and_complete_domain_observation
    ).parameters
    assert "submission_id" not in parameters
    assert "observation_id" not in parameters


def test_guided_checkpoint_and_result_are_strict_frozen_and_secret_free():
    credential = _credential()
    pending = _pending_checkpoint(credential)
    registered = _registered_checkpoint(credential)
    result = TaskDomainObservationGuidedResult(
        register_receipt=registered.register_receipt,
        completion_receipt=AgentTaskCompletionResponse.model_validate(
            _completion_response()
        ),
    )

    surfaces = [
        repr(pending),
        pending.model_dump_json(),
        repr(pending.model_dump(mode="json")),
        repr(registered),
        registered.model_dump_json(),
        repr(registered.model_dump(mode="json")),
        repr(result),
        result.model_dump_json(),
        repr(result.model_dump(mode="json")),
    ]
    assert all(CLAIM_TOKEN not in surface for surface in surfaces)
    assert pending.credential_fingerprint != hashlib.sha256(
        CLAIM_TOKEN.encode("utf-8")
    ).hexdigest()
    assert pending.credential_fingerprint != (
        claim_token_storage_digest_hex(CLAIM_TOKEN)
    )
    assert pending.credential_fingerprint not in {
        CLAIM_TOKEN,
        credential._claim_token_value(),
    }
    with pytest.raises(ValueError):
        pending.state = TaskDomainObservationCheckpointState.REGISTERED
    with pytest.raises(ValueError):
        result.matched_status = AgentTaskRewardStatus.model_validate(
            _reward_status()
        )
    with pytest.raises(ValueError):
        TaskDomainObservationGuidedResult(
            register_receipt=registered.register_receipt,
            completion_receipt=AgentTaskCompletionResponse.model_validate(
                _completion_response()
            ),
            matched_status=AgentTaskRewardStatus.model_validate(
                _reward_status()
            ),
        )


@pytest.mark.parametrize(
    "model",
    [
        pytest.param(_pending_checkpoint(), id="checkpoint"),
        pytest.param(
            TaskDomainObservationGuidedResult(
                register_receipt=(
                    TaskDomainObservationResponse.model_validate(
                        _register_response()
                    )
                ),
                completion_receipt=(
                    AgentTaskCompletionResponse.model_validate(
                        _completion_response()
                    )
                ),
            ),
            id="result",
        ),
    ],
)
def test_guided_frozen_assignment_drops_attempted_secret(model):
    with pytest.raises(ValueError) as caught:
        model.observation_id = CLAIM_TOKEN
    _assert_finite_exception_graph(caught.value, CLAIM_TOKEN)


def test_guided_checkpoint_and_result_detach_nested_models():
    checkpoint = _registered_checkpoint()
    detached_submission = checkpoint.submission
    detached_submission.observed_urls[0].url = (
        "https://example.com/" + CLAIM_TOKEN
    )
    detached_register = checkpoint.register_receipt
    detached_register.observation_id = CLAIM_TOKEN

    assert CLAIM_TOKEN not in repr(checkpoint)
    assert CLAIM_TOKEN not in checkpoint.model_dump_json()
    assert checkpoint.submission.observed_urls[0].url == (
        "https://example.com/"
    )
    assert checkpoint.register_receipt.observation_id == OBSERVATION_ID

    result = TaskDomainObservationGuidedResult(
        register_receipt=checkpoint.register_receipt,
        completion_receipt=AgentTaskCompletionResponse.model_validate(
            _completion_response()
        ),
    )
    result_register = result.register_receipt
    result_completion = result.completion_receipt
    result_register.observation_id = CLAIM_TOKEN
    result_completion.observation_id = CLAIM_TOKEN
    assert CLAIM_TOKEN not in repr(result)
    assert CLAIM_TOKEN not in result.model_dump_json()
    assert result.register_receipt.observation_id == OBSERVATION_ID
    assert result.completion_receipt.observation_id == OBSERVATION_ID


def test_guided_checkpoint_repr_fails_safe_after_private_nested_mutation():
    checkpoint = _pending_checkpoint()
    internal_submission = vars(checkpoint)["submission"]
    internal_submission.observed_urls[0].url = (
        "https://example.com/" + CLAIM_TOKEN
    )

    assert repr(checkpoint) == (
        "TaskDomainObservationCheckpoint(<invalid>)"
    )
    assert str(checkpoint) == (
        "TaskDomainObservationCheckpoint(<invalid>)"
    )
    assert CLAIM_TOKEN not in repr(checkpoint)
    with pytest.raises(ValueError) as access_error:
        _ = checkpoint.submission
    _assert_finite_exception_graph(access_error.value, CLAIM_TOKEN)
    with pytest.raises(ValueError) as caught:
        checkpoint.model_dump_json()
    _assert_finite_exception_graph(caught.value, CLAIM_TOKEN)


def test_guided_rejects_claim_token_before_checkpoint_or_network():
    submission = TaskDomainObservationSubmission(
        submission_id=SUBMISSION_ID,
        observed_domain="example.com",
        observed_urls=[
            _observed_url("https://example.com/" + CLAIM_TOKEN)
        ],
        discovered_surfaces=[_surface()],
    )
    transport = _FakeTransport(
        [_register_response(), _completion_response()]
    )
    checkpoints = []

    with pytest.raises(TaskTransportError) as caught:
        AgentTaskClient(
            _transport=transport
        ).submit_and_complete_domain_observation(
            _credential(),
            submission,
            checkpoint_sink=checkpoints.append,
        )

    assert caught.value.code == "TASK_CREDENTIAL_INVALID"
    assert checkpoints == []
    assert transport.calls == []
    _assert_finite_exception_graph(caught.value, CLAIM_TOKEN)


def test_guided_rejects_token_copied_from_credential_public_fields():
    credential = _credential(agent_id=CLAIM_TOKEN)
    transport = _FakeTransport(
        [
            _register_response(task_id=credential.task_id),
            _completion_response(task_id=credential.task_id),
        ]
    )
    checkpoints = []

    with pytest.raises(TaskTransportError) as caught:
        AgentTaskClient(
            _transport=transport
        ).submit_and_complete_domain_observation(
            credential,
            _submission_payload(),
            checkpoint_sink=checkpoints.append,
        )

    assert caught.value.code == "TASK_CREDENTIAL_INVALID"
    assert checkpoints == []
    assert transport.calls == []
    _assert_finite_exception_graph(caught.value, CLAIM_TOKEN)


def test_guided_rejects_secret_bearing_loaded_checkpoint_before_network():
    checkpoint = _registered_checkpoint().model_dump(mode="python")
    checkpoint["register_receipt"]["observation_id"] = CLAIM_TOKEN
    checkpoint["observation_id"] = CLAIM_TOKEN
    transport = _FakeTransport([_completion_response()])

    with pytest.raises(TaskTransportError) as caught:
        AgentTaskClient(
            _transport=transport
        ).submit_and_complete_domain_observation(
            _credential(),
            _submission_payload(),
            checkpoint=checkpoint,
        )

    assert caught.value.code == "TASK_CREDENTIAL_INVALID"
    assert transport.calls == []
    _assert_finite_exception_graph(caught.value, CLAIM_TOKEN)


@pytest.mark.parametrize(
    ("container", "key", "value"),
    [
        ("register_receipt", "claim_token", CLAIM_TOKEN),
        ("reward", "claim_token", CLAIM_TOKEN),
        ("register_receipt", "future_field", "safe-extra"),
        ("reward", "future_field", "safe-extra"),
    ],
)
def test_guided_loaded_checkpoint_rejects_nested_extras_before_network(
    container, key, value
):
    checkpoint = _registered_checkpoint().model_dump(mode="python")
    checkpoint[container][key] = value
    transport = _FakeTransport([_completion_response()])

    with pytest.raises(TaskTransportError) as caught:
        AgentTaskClient(
            _transport=transport
        ).submit_and_complete_domain_observation(
            _credential(),
            _submission_payload(),
            checkpoint=checkpoint,
        )

    assert caught.value.code == "TASK_CREDENTIAL_INVALID"
    assert transport.calls == []
    _assert_finite_exception_graph(caught.value, CLAIM_TOKEN)


def test_guided_loaded_checkpoint_rejects_legacy_task_domain_before_network():
    checkpoint = _pending_checkpoint().model_dump(mode="python")
    checkpoint["domain"] = "example.com"
    transport = _FakeTransport(
        [_register_response(), _completion_response()]
    )

    with pytest.raises(TaskTransportError) as caught:
        AgentTaskClient(
            _transport=transport
        ).submit_and_complete_domain_observation(
            _credential(),
            _submission_payload(),
            checkpoint=checkpoint,
        )

    assert caught.value.code == "TASK_CREDENTIAL_INVALID"
    assert transport.calls == []


@pytest.mark.parametrize(
    "model_type",
    [
        TaskDomainObservationCheckpoint,
        TaskDomainObservationGuidedResult,
    ],
)
@pytest.mark.parametrize("entry_point", ["constructor", "mapping", "json"])
def test_guided_models_sanitize_rejected_secret_bearing_inputs(
    model_type, entry_point
):
    if model_type is TaskDomainObservationCheckpoint:
        payload = _pending_checkpoint().model_dump(mode="python")
    else:
        payload = TaskDomainObservationGuidedResult(
            register_receipt=TaskDomainObservationResponse.model_validate(
                _register_response()
            ),
            completion_receipt=(
                AgentTaskCompletionResponse.model_validate(
                    _completion_response()
                )
            ),
        ).model_dump(mode="python")
    payload["claim_token"] = CLAIM_TOKEN

    with pytest.raises(ValueError) as caught:
        if entry_point == "constructor":
            model_type(**payload)
        elif entry_point == "mapping":
            model_type.model_validate(payload, strict=True)
        else:
            model_type.model_validate_json(
                json.dumps(payload), strict=True
            )

    error = caught.value
    surfaces = [
        str(error),
        repr(error),
        repr(vars(error)),
        repr(getattr(error, "errors", lambda: [])()),
        "".join(
            traceback.format_exception(
                type(error), error, error.__traceback__
            )
        ),
    ]
    assert all(CLAIM_TOKEN not in surface for surface in surfaces)
    _assert_finite_exception_graph(error, CLAIM_TOKEN)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("api_origin", "https://example.com"),
        ("task_id", "task_other"),
        ("agent_id", "other-agent"),
        (
            "reward_address",
            "0x2222222222222222222222222222222222222222",
        ),
        ("task_definition_version", "2"),
        ("task_definition_digest", "c" * 64),
        ("manifest_sha256", "c" * 64),
        ("reward", _reward("10001")),
        ("lease_expires_at", "2099-07-27T02:00:00Z"),
        ("submission_id", "sub_" + "1" * 32),
        ("submission_sha256", "c" * 64),
        ("credential_fingerprint", "d" * 64),
    ],
)
def test_guided_checkpoint_binding_mismatch_sends_no_http(
    field, replacement
):
    checkpoint = _pending_checkpoint().model_dump(
        mode="python", exclude_none=True
    )
    checkpoint[field] = replacement
    transport = _FakeTransport(
        [_register_response(), _completion_response()]
    )

    with pytest.raises(TaskTransportError) as caught:
        AgentTaskClient(
            _transport=transport
        ).submit_and_complete_domain_observation(
            _credential(),
            _submission_payload(),
            checkpoint=checkpoint,
        )

    assert caught.value.code == "TASK_CREDENTIAL_INVALID"
    assert transport.calls == []


@pytest.mark.parametrize(
    ("receipt_field", "replacement"),
    [
        ("task_id", "task_other"),
        ("submission_id", "sub_" + "1" * 32),
        ("observation_id", "obs_other"),
    ],
)
def test_guided_registered_receipt_mismatch_sends_no_completion(
    receipt_field, replacement
):
    checkpoint = _registered_checkpoint().model_dump(mode="python")
    checkpoint["register_receipt"][receipt_field] = replacement
    transport = _FakeTransport([_completion_response()])

    with pytest.raises(TaskTransportError) as caught:
        AgentTaskClient(
            _transport=transport
        ).submit_and_complete_domain_observation(
            _credential(),
            _submission_payload(),
            checkpoint=checkpoint,
        )

    assert caught.value.code == "TASK_CREDENTIAL_INVALID"
    assert transport.calls == []


def test_guided_pending_checkpoint_is_saved_before_register():
    transport = _FakeTransport([_register_response()])
    checkpoints = []

    def fail_pending(checkpoint):
        checkpoints.append(checkpoint)
        raise OSError("simulated durable write failure")

    with pytest.raises(TaskTransportError) as caught:
        AgentTaskClient(
            _transport=transport
        ).submit_and_complete_domain_observation(
            _credential(),
            _submission_payload(),
            checkpoint_sink=fail_pending,
        )

    assert caught.value.request_bytes_sent is False
    assert [item.state for item in checkpoints] == [
        TaskDomainObservationCheckpointState.REGISTER_PENDING
    ]
    assert transport.calls == []


def test_guided_registered_checkpoint_is_saved_before_completion():
    transport = _FakeTransport([_register_response()])
    checkpoints = []

    def fail_registered(checkpoint):
        checkpoints.append(checkpoint)
        if (
            checkpoint.state
            == TaskDomainObservationCheckpointState.REGISTERED
        ):
            raise OSError("simulated durable write failure")

    with pytest.raises(TaskTransportError) as caught:
        AgentTaskClient(
            _transport=transport
        ).submit_and_complete_domain_observation(
            _credential(),
            _submission_payload(),
            checkpoint_sink=fail_registered,
        )

    assert caught.value.request_bytes_sent is True
    assert [item.state for item in checkpoints] == [
        TaskDomainObservationCheckpointState.REGISTER_PENDING,
        TaskDomainObservationCheckpointState.REGISTERED,
    ]
    assert [
        path for _, path, _ in transport.calls
    ] == [task_observation_path("task_example")]


def test_guided_pending_resume_reuses_saved_body_id_and_digest():
    ambiguous = TaskAmbiguousOutcomeError(
        "SUBMISSION_OUTCOME_UNKNOWN",
        request_bytes_sent=True,
    )
    first_transport = _FakeTransport([ambiguous])
    first_checkpoints = []
    submission = _submission_payload()

    with pytest.raises(TaskAmbiguousOutcomeError):
        AgentTaskClient(
            _transport=first_transport
        ).submit_and_complete_domain_observation(
            _credential(),
            submission,
            checkpoint_sink=first_checkpoints.append,
        )

    pending = first_checkpoints[-1]
    assert pending.state == (
        TaskDomainObservationCheckpointState.REGISTER_PENDING
    )
    resumed_transport = _FakeTransport(
        [_register_response(), _completion_response()]
    )
    observation_without_id = _submission_payload(
        include_submission_id=False
    )
    resumed = AgentTaskClient(
        _transport=resumed_transport
    ).submit_and_complete_domain_observation(
        _credential(),
        observation_without_id,
        checkpoint=pending.model_dump(mode="json", exclude_none=True),
    )

    sent_submission = resumed_transport.calls[0][2]["json_body"]
    assert sent_submission == pending.submission.model_dump(mode="json")
    assert sent_submission["submission_id"] == pending.submission_id
    assert canonical_submission_digest_hex(sent_submission) == (
        pending.submission_sha256
    )
    assert resumed.register_receipt.submission_id == (
        pending.submission_id
    )


@pytest.mark.parametrize(
    "changed_field",
    ["observed_domain", "observed_url", "surface", "submission_id"],
)
def test_guided_pending_resume_rejects_changed_observation_snapshot(
    changed_field,
):
    pending = _pending_checkpoint()
    payload = _submission_payload()
    if changed_field == "observed_domain":
        payload.update(
            {
                "observed_domain": "example.org",
                "observed_urls": [_observed_url("https://example.org/")],
                "discovered_surfaces": [
                    _surface("https://example.org/paid")
                ],
            }
        )
    elif changed_field == "observed_url":
        payload["observed_urls"] = [
            _observed_url("https://example.com/changed")
        ]
    elif changed_field == "surface":
        payload["discovered_surfaces"] = [
            _surface("https://example.com/other-paid")
        ]
    else:
        payload["submission_id"] = "sub_" + ("1" * 32)

    transport = _FakeTransport(
        [_register_response(), _completion_response()]
    )
    with pytest.raises(TaskTransportError) as caught:
        AgentTaskClient(
            _transport=transport
        ).submit_and_complete_domain_observation(
            _credential(),
            payload,
            checkpoint=pending,
        )
    assert caught.value.code == "TASK_CREDENTIAL_INVALID"
    assert transport.calls == []


def test_guided_registered_resume_skips_register():
    registered = _registered_checkpoint()
    transport = _FakeTransport([_completion_response()])

    result = AgentTaskClient(
        _transport=transport
    ).submit_and_complete_domain_observation(
        _credential(),
        _submission_payload(),
        checkpoint=registered,
    )

    assert len(transport.calls) == 1
    assert transport.calls[0][:2] == (
        "POST",
        task_completion_path("task_example"),
    )
    assert result.register_receipt == registered.register_receipt
    assert result.completion_receipt is not None


def test_guided_ambiguous_completion_returns_exact_matching_status():
    ambiguous = TaskAmbiguousOutcomeError(
        "COMPLETION_OUTCOME_UNKNOWN",
        request_bytes_sent=True,
    )
    exact_status = _reward_status()
    transport = _FakeTransport(
        [_register_response(), ambiguous, exact_status]
    )

    result = AgentTaskClient(
        _transport=transport
    ).submit_and_complete_domain_observation(
        _credential(),
        _submission_payload(),
    )

    assert result.completion_receipt is None
    assert result.matched_status.model_dump(mode="json") == exact_status
    assert [
        (method, path) for method, path, _ in transport.calls
    ] == [
        ("POST", task_observation_path("task_example")),
        ("POST", task_completion_path("task_example")),
        (
            "GET",
            task_submission_status_path(
                "task_example", SUBMISSION_ID
            ),
        ),
    ]
    assert "claim_token" not in transport.calls[2][2]


def test_guided_rejects_claim_token_reflected_in_matching_status():
    reflected_token = ("a" * 42) + "A"
    transaction_hash = (
        "0x" + ("b" * 10) + reflected_token + ("c" * 11)
    )
    ambiguous = TaskAmbiguousOutcomeError(
        "COMPLETION_OUTCOME_UNKNOWN",
        request_bytes_sent=True,
    )
    transport = _FakeTransport(
        [
            _register_response(),
            ambiguous,
            _reward_status(
                task_status="REWARDED",
                reward_state="paid",
                reward_tx_hash=transaction_hash,
                rewarded_at="2026-07-27T02:00:00Z",
            ),
        ]
    )

    with pytest.raises(TaskTransportError) as caught:
        AgentTaskClient(
            _transport=transport
        ).submit_and_complete_domain_observation(
            _credential(claim_token=reflected_token),
            _submission_payload(),
        )

    assert caught.value.code == "COMPLETION_OUTCOME_UNKNOWN"
    assert caught.value.request_bytes_sent is True
    assert len(transport.calls) == 3
    _assert_finite_exception_graph(
        caught.value, reflected_token, transaction_hash
    )


def test_guided_shared_budget_covers_all_transport_retries_and_fallback():
    attempts = {
        "register": 0,
        "completion": 0,
        "status": 0,
    }

    def exchange(**kwargs):
        kwargs["tracker"].request_bytes_sent = True
        url = kwargs["url"]
        if url.endswith("/domain-observations"):
            key = "register"
            success = _register_response()
            transient_attempts = 1
        elif url.endswith("/completion"):
            key = "completion"
            success = None
            transient_attempts = 2
        else:
            key = "status"
            success = _reward_status()
            transient_attempts = 2
        attempts[key] += 1
        if attempts[key] <= transient_attempts:
            return 503, {}, _error_body("internal_error")
        assert success is not None
        return (
            200,
            {},
            json.dumps(
                success, separators=(",", ":")
            ).encode("utf-8"),
        )

    transport = TaskTransport(
        _resolver=lambda host, port: ("93.184.216.34",),
        _exchange=exchange,
        _sleep=lambda _delay: None,
        _monotonic=lambda: 0.0,
        _random=lambda: 0.0,
    )
    budget = _TaskExchangeBudget(10)
    with patch(
        "ln_church_agent.task_client._TaskExchangeBudget",
        return_value=budget,
    ):
        result = AgentTaskClient(
            _transport=transport
        ).submit_and_complete_domain_observation(
            _credential(),
            _submission_payload(),
        )

    assert attempts == {
        "register": 2,
        "completion": 2,
        "status": 3,
    }
    assert sum(attempts.values()) == 7
    assert budget.remaining == 3
    assert result.completion_receipt is None
    assert result.matched_status.task_status == "SUBMITTED"


def test_cli_submit_complete_has_no_manual_id_arguments(capsys):
    argv = [
        "ln-church-agent",
        "task",
        "submit-complete",
        "--help",
    ]
    with patch.object(sys, "argv", argv):
        from ln_church_agent.cli import main

        with pytest.raises(SystemExit) as caught:
            main()
    assert caught.value.code == 0
    captured = capsys.readouterr()
    assert "--credential-file" in captured.out
    assert "--file" in captured.out
    assert "--checkpoint-file" in captured.out
    assert "--submission-id" not in captured.out
    assert "--observation-id" not in captured.out


def test_cli_submit_complete_persists_secret_free_registered_checkpoint(
    tmp_path, capsys
):
    credential_path = tmp_path / "credential.json"
    observation_path = tmp_path / "observation.json"
    checkpoint_path = tmp_path / "checkpoint.json"
    credential_path.write_text(
        json.dumps(_credential()._to_private_file_payload()),
        encoding="utf-8",
    )
    observation_path.write_text(
        json.dumps(_submission_payload()),
        encoding="utf-8",
    )
    if os.name != "nt":
        os.chmod(credential_path, 0o600)
    transport = _FakeTransport(
        [_register_response(), _completion_response()]
    )
    client = AgentTaskClient(_transport=transport)
    argv = [
        "ln-church-agent",
        "task",
        "submit-complete",
        "task_example",
        "--credential-file",
        str(credential_path),
        "--file",
        str(observation_path),
        "--checkpoint-file",
        str(checkpoint_path),
        "--json",
    ]
    with patch(
        "ln_church_agent.task_client.AgentTaskClient",
        return_value=client,
    ):
        with patch.object(sys, "argv", argv):
            from ln_church_agent.cli import main

            main()

    captured = capsys.readouterr()
    checkpoint_text = checkpoint_path.read_text(encoding="utf-8")
    checkpoint = json.loads(checkpoint_text)
    assert checkpoint["state"] == "REGISTERED"
    assert checkpoint["submission_id"] == SUBMISSION_ID
    assert checkpoint["observation_id"] == OBSERVATION_ID
    assert checkpoint["register_receipt"] == _register_response()
    assert CLAIM_TOKEN not in (
        checkpoint_text + captured.out + captured.err
    )
    assert json.loads(captured.out)["completion_receipt"] == (
        _completion_response()
    )
    if os.name != "nt":
        assert stat.S_IMODE(checkpoint_path.stat().st_mode) == 0o600


def test_checkpoint_file_round_trips_wire_valid_boundary_envelopes(
    tmp_path,
):
    from ln_church_agent.cli import (
        _TASK_CHECKPOINT_FILE_MAX_BYTES,
        _TASK_FILE_MAX_BYTES,
        _TaskCheckpointFile,
    )

    credential, submission, maximum_url, manifest_url = (
        _checkpoint_envelope_boundary_inputs()
    )
    wire_payload = submission.model_dump(mode="json")
    wire_bytes = _encode_body("observation", wire_payload)
    credential_bytes = (
        json.dumps(
            credential._to_private_file_payload(),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    pending = _pending_checkpoint(credential, submission)
    registered = _registered_checkpoint(credential, submission)

    def encoded_checkpoint(value):
        return (
            json.dumps(
                value.model_dump(mode="json", exclude_none=True),
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")

    pending_bytes = encoded_checkpoint(pending)
    registered_bytes = encoded_checkpoint(registered)
    assert len(maximum_url.encode("utf-8")) == 2048
    assert len(manifest_url.encode("utf-8")) == 4000
    assert len(wire_bytes) == 258423
    assert _TASK_FILE_MAX_BYTES == MAXIMUM_JSON_BYTES == 256 * 1024
    assert len(wire_bytes) < _TASK_FILE_MAX_BYTES
    assert len(credential_bytes) < _TASK_FILE_MAX_BYTES
    assert _TASK_CHECKPOINT_FILE_MAX_BYTES == 3 * _TASK_FILE_MAX_BYTES
    assert len(pending_bytes) == 263375
    assert len(registered_bytes) == 263633
    assert _TASK_FILE_MAX_BYTES < len(pending_bytes)
    assert len(registered_bytes) <= _TASK_CHECKPOINT_FILE_MAX_BYTES

    path = tmp_path / "checkpoint.json"
    checkpoint_file = _TaskCheckpointFile(str(path))
    try:
        checkpoint_file.write_payload(
            pending.model_dump(mode="json", exclude_none=True)
        )
        assert checkpoint_file.read_payload() == pending.model_dump(
            mode="json", exclude_none=True
        )
        checkpoint_file.write_payload(
            registered.model_dump(mode="json", exclude_none=True)
        )
        assert checkpoint_file.read_payload() == registered.model_dump(
            mode="json", exclude_none=True
        )
        assert path.stat().st_size == len(registered_bytes)
        assert CLAIM_TOKEN not in path.read_text(encoding="utf-8")
        if os.name != "nt":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
    finally:
        checkpoint_file.close()


def test_checkpoint_file_rejects_above_checkpoint_only_cap(tmp_path):
    from ln_church_agent.cli import (
        _TASK_CHECKPOINT_FILE_MAX_BYTES,
        _TaskCheckpointFile,
    )

    write_path = tmp_path / "checkpoint-write.json"
    checkpoint_file = _TaskCheckpointFile(str(write_path))
    empty_payload_bytes = (
        json.dumps(
            {"padding": ""},
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    exact_cap_payload = {
        "padding": "x"
        * (
            _TASK_CHECKPOINT_FILE_MAX_BYTES
            - len(empty_payload_bytes)
        )
    }
    try:
        checkpoint_file.write_payload(exact_cap_payload)
        assert write_path.stat().st_size == (
            _TASK_CHECKPOINT_FILE_MAX_BYTES
        )
        assert checkpoint_file.read_payload() == exact_cap_payload
        with pytest.raises(ValueError) as caught:
            checkpoint_file.write_payload(
                {"padding": exact_cap_payload["padding"] + "x"}
            )
        assert write_path.stat().st_size == (
            _TASK_CHECKPOINT_FILE_MAX_BYTES
        )
        assert checkpoint_file.read_payload() == exact_cap_payload
    finally:
        checkpoint_file.close()
    _assert_finite_exception_graph(caught.value)

    read_path = tmp_path / "checkpoint-read.json"
    read_path.write_bytes(
        b'{"padding":"'
        + (b"x" * _TASK_CHECKPOINT_FILE_MAX_BYTES)
        + b'"}'
    )
    if os.name != "nt":
        os.chmod(read_path, 0o600)
    checkpoint_file = _TaskCheckpointFile(str(read_path))
    try:
        with pytest.raises(ValueError) as caught:
            checkpoint_file.read_payload()
    finally:
        checkpoint_file.close()
    _assert_finite_exception_graph(caught.value)


def test_cli_submit_complete_accepts_wire_valid_checkpoint_boundary(
    tmp_path, capsys
):
    from ln_church_agent.cli import (
        _TASK_CHECKPOINT_FILE_MAX_BYTES,
        _TASK_FILE_MAX_BYTES,
    )

    credential, submission, _, _ = (
        _checkpoint_envelope_boundary_inputs()
    )
    credential_path = tmp_path / "credential.json"
    observation_path = tmp_path / "observation.json"
    checkpoint_path = tmp_path / "checkpoint.json"
    credential_path.write_text(
        json.dumps(
            credential._to_private_file_payload(),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    observation_path.write_text(
        json.dumps(
            submission.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    if os.name != "nt":
        os.chmod(credential_path, 0o600)
    assert credential_path.stat().st_size < _TASK_FILE_MAX_BYTES
    assert observation_path.stat().st_size < _TASK_FILE_MAX_BYTES

    transport = _FakeTransport(
        [_register_response(), _completion_response()]
    )
    client = AgentTaskClient(_transport=transport)
    argv = [
        "ln-church-agent",
        "task",
        "submit-complete",
        "task_example",
        "--credential-file",
        str(credential_path),
        "--file",
        str(observation_path),
        "--checkpoint-file",
        str(checkpoint_path),
        "--json",
    ]
    with patch(
        "ln_church_agent.task_client.AgentTaskClient",
        return_value=client,
    ):
        with patch.object(sys, "argv", argv):
            from ln_church_agent.cli import main

            main()

    captured = capsys.readouterr()
    checkpoint_text = checkpoint_path.read_text(encoding="utf-8")
    checkpoint = json.loads(checkpoint_text)
    assert _TASK_FILE_MAX_BYTES < checkpoint_path.stat().st_size
    assert (
        checkpoint_path.stat().st_size
        <= _TASK_CHECKPOINT_FILE_MAX_BYTES
    )
    assert checkpoint["state"] == "REGISTERED"
    assert checkpoint["submission_id"] == SUBMISSION_ID
    assert checkpoint["observation_id"] == OBSERVATION_ID
    assert [
        (method, path) for method, path, _ in transport.calls
    ] == [
        ("POST", task_observation_path("task_example")),
        ("POST", task_completion_path("task_example")),
    ]
    assert transport.calls[1][2]["json_body"] == {
        "schema_version": (
            "ln_church.agent_task_completion_request.v1"
        ),
        "submission_id": SUBMISSION_ID,
        "observation_id": OBSERVATION_ID,
    }
    assert CLAIM_TOKEN not in (
        checkpoint_text + captured.out + captured.err
    )
    assert json.loads(captured.out)["completion_receipt"] == (
        _completion_response()
    )


def test_cli_rejected_checkpoint_never_leaks_secret_in_exception_graph(
    tmp_path, capsys
):
    credential_path = tmp_path / "credential.json"
    observation_path = tmp_path / "observation.json"
    checkpoint_path = tmp_path / "checkpoint.json"
    credential_path.write_text(
        json.dumps(_credential()._to_private_file_payload()),
        encoding="utf-8",
    )
    observation_path.write_text(
        json.dumps(_submission_payload()),
        encoding="utf-8",
    )
    hostile = _pending_checkpoint().model_dump(
        mode="json", exclude_none=True
    )
    hostile["claim_token"] = CLAIM_TOKEN
    checkpoint_path.write_text(
        json.dumps(hostile),
        encoding="utf-8",
    )
    if os.name != "nt":
        os.chmod(credential_path, 0o600)
        os.chmod(checkpoint_path, 0o600)

    class FakeClient:
        calls = 0

        def submit_and_complete_domain_observation(
            self, *args, **kwargs
        ):
            self.calls += 1
            raise AssertionError("network must not be reached")

        def close(self):
            pass

    client = FakeClient()
    argv = [
        "ln-church-agent",
        "task",
        "submit-complete",
        "task_example",
        "--credential-file",
        str(credential_path),
        "--file",
        str(observation_path),
        "--checkpoint-file",
        str(checkpoint_path),
    ]
    with patch(
        "ln_church_agent.task_client.AgentTaskClient",
        return_value=client,
    ):
        with patch.object(sys, "argv", argv):
            from ln_church_agent.cli import main

            with pytest.raises(SystemExit) as caught:
                main()

    assert caught.value.code == 2
    assert client.calls == 0
    captured = capsys.readouterr()
    current = caught.value
    seen = set()
    surfaces = [captured.out, captured.err]
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        surfaces.extend(
            [
                str(current),
                repr(current),
                repr(vars(current)),
                repr(getattr(current, "errors", lambda: [])()),
            ]
        )
        current = current.__cause__ or current.__context__
    assert all(CLAIM_TOKEN not in surface for surface in surfaces)


@pytest.mark.parametrize("malformed_file", ["credential", "observation"])
def test_cli_submit_complete_malformed_input_drops_secret_context(
    malformed_file, tmp_path, capsys
):
    credential_path = tmp_path / "credential.json"
    observation_path = tmp_path / "observation.json"
    checkpoint_path = tmp_path / "checkpoint.json"
    credential_text = json.dumps(
        _credential()._to_private_file_payload()
    )
    observation_text = json.dumps(_submission_payload())
    malformed = '{"broken":"' + CLAIM_TOKEN
    if malformed_file == "credential":
        credential_text = malformed
    else:
        observation_text = malformed
    credential_path.write_text(credential_text, encoding="utf-8")
    observation_path.write_text(observation_text, encoding="utf-8")
    if os.name != "nt":
        os.chmod(credential_path, 0o600)

    class FakeClient:
        calls = 0

        def submit_and_complete_domain_observation(
            self, *args, **kwargs
        ):
            self.calls += 1
            raise AssertionError("network must not be reached")

        def close(self):
            pass

    client = FakeClient()
    argv = [
        "ln-church-agent",
        "task",
        "submit-complete",
        "task_example",
        "--credential-file",
        str(credential_path),
        "--file",
        str(observation_path),
        "--checkpoint-file",
        str(checkpoint_path),
    ]
    with patch(
        "ln_church_agent.task_client.AgentTaskClient",
        return_value=client,
    ):
        with patch.object(sys, "argv", argv):
            from ln_church_agent.cli import main

            with pytest.raises(SystemExit) as caught:
                main()

    assert caught.value.code == 2
    assert client.calls == 0
    assert not checkpoint_path.exists()
    captured = capsys.readouterr()
    current = caught.value
    seen = set()
    surfaces = [captured.out, captured.err]
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        surfaces.extend(
            [
                str(current),
                repr(current),
                repr(vars(current)),
                repr(getattr(current, "errors", lambda: [])()),
            ]
        )
        current = current.__cause__ or current.__context__
    assert all(CLAIM_TOKEN not in surface for surface in surfaces)


def test_checkpoint_file_exclusive_lock_rejects_concurrent_writer(
    tmp_path,
):
    from ln_church_agent.cli import _TaskCheckpointFile

    path = tmp_path / "checkpoint.json"
    first = _TaskCheckpointFile(str(path))
    try:
        first.write_payload(
            _pending_checkpoint().model_dump(
                mode="json", exclude_none=True
            )
        )
        with pytest.raises((OSError, ValueError)):
            _TaskCheckpointFile(str(path))
        assert json.loads(path.read_text(encoding="utf-8"))[
            "state"
        ] == "REGISTER_PENDING"
    finally:
        first.close()


def test_checkpoint_file_malformed_json_drops_secret_exception_context(
    tmp_path,
):
    from ln_church_agent.cli import _TaskCheckpointFile

    path = tmp_path / "checkpoint.json"
    path.write_text(
        '{"broken":"' + CLAIM_TOKEN,
        encoding="utf-8",
    )
    if os.name != "nt":
        os.chmod(path, 0o600)
    checkpoint_file = _TaskCheckpointFile(str(path))
    try:
        with pytest.raises(ValueError) as caught:
            checkpoint_file.read_payload()
    finally:
        checkpoint_file.close()
    _assert_finite_exception_graph(caught.value, CLAIM_TOKEN)


def test_checkpoint_failed_update_preserves_last_good_pending_state(
    tmp_path,
):
    from ln_church_agent.cli import _TaskCheckpointFile

    path = tmp_path / "checkpoint.json"
    checkpoint_file = _TaskCheckpointFile(str(path))
    pending = _pending_checkpoint().model_dump(
        mode="json", exclude_none=True
    )
    registered = _registered_checkpoint().model_dump(
        mode="json", exclude_none=True
    )
    checkpoint_file.write_payload(pending)
    pending_bytes = path.read_bytes()
    real_write = os.write
    writes = 0

    def fail_after_partial_write(descriptor, content):
        nonlocal writes
        writes += 1
        if writes == 1:
            return real_write(descriptor, content[:17])
        raise OSError("simulated partial checkpoint write")

    try:
        with patch(
            "ln_church_agent.cli.os.write",
            side_effect=fail_after_partial_write,
        ):
            with pytest.raises(OSError):
                checkpoint_file.write_payload(registered)
        assert path.read_bytes() == pending_bytes
        assert checkpoint_file.read_payload()["state"] == (
            "REGISTER_PENDING"
        )
        assert list(tmp_path.glob(".*.tmp")) == []
    finally:
        checkpoint_file.close()


def test_checkpoint_atomic_update_transfers_exclusive_lock(
    tmp_path,
):
    from ln_church_agent.cli import _TaskCheckpointFile

    path = tmp_path / "checkpoint.json"
    checkpoint_file = _TaskCheckpointFile(str(path))
    try:
        checkpoint_file.write_payload(
            _pending_checkpoint().model_dump(
                mode="json", exclude_none=True
            )
        )
        pending_identity = (
            path.stat().st_dev,
            path.stat().st_ino,
        )
        checkpoint_file.write_payload(
            _registered_checkpoint().model_dump(
                mode="json", exclude_none=True
            )
        )
        registered_identity = (
            path.stat().st_dev,
            path.stat().st_ino,
        )
        assert registered_identity != pending_identity
        assert checkpoint_file.identity == registered_identity
        assert checkpoint_file.read_payload()["state"] == "REGISTERED"
        with pytest.raises((OSError, ValueError)):
            _TaskCheckpointFile(str(path))
    finally:
        checkpoint_file.close()


def test_inspect_only_mcp_exposes_no_task_mutation_tools():
    source = (
        Path(__file__).parents[1]
        / "ln_church_agent"
        / "integrations"
        / "mcp_inspect.py"
    ).read_text(encoding="utf-8")
    assert "AgentTaskClient" not in source
    assert "X-LN-Task-Claim-Token" not in source
    assert "claim_task" not in source


def test_task_public_api_exports_are_available_from_package_root():
    import ln_church_agent

    required = {
        "AgentTaskClient",
        "AgentTask",
        "AgentTaskPage",
        "TaskDefinitionReference",
        "AgentTaskClaim",
        "TaskClaimCredential",
        "TaskDomainObservationSubmission",
        "TaskDomainObservationResponse",
        "AgentTaskCompletionResponse",
        "AgentTaskRewardStatus",
        "TaskError",
        "TaskTransportError",
        "TaskAPIError",
        "TaskAmbiguousOutcomeError",
    }
    assert required <= set(ln_church_agent.__all__)
    assert all(hasattr(ln_church_agent, name) for name in required)


def test_old_public_task_offer_surface_is_absent_and_internal_interfaces_remain():
    import ln_church_agent
    from ln_church_agent import task_contract, task_models

    assert task_contract.TASK_TYPE_PAYMENT_SURFACE_DISCOVERY == TASK_TYPE
    assert not hasattr(task_contract, "TASK_TYPE_DOMAIN_OBSERVATION")
    for name in (
        "DomainObservationTaskOfferRequest",
        "DomainObservationTaskOfferResponse",
        "AgentTaskOfferRequest",
        "AgentTaskOfferResponse",
    ):
        assert not hasattr(task_models, name)
        assert name not in getattr(task_models, "__all__", ())
        assert name not in ln_church_agent.__all__
    assert not hasattr(AgentTaskClient, "create_task_offer")
    assert hasattr(ln_church_agent.LnChurchClient, "claim_domain_observation_targets")
    assert hasattr(ln_church_agent.LnChurchClient, "submit_domain_observation_result")
    assert TaskDomainObservationSubmission.model_fields["schema_version"].default == (
        "ln_church.task_domain_observation_submission.v1"
    )


def test_task_public_payload_redacts_claim_token_name_variants():
    from ln_church_agent.cli import _task_public_payload

    payload = {
        "claim_token": CLAIM_TOKEN,
        "claim-token": CLAIM_TOKEN,
        "claimToken": CLAIM_TOKEN,
        "X-LN-Task-Claim-Token": CLAIM_TOKEN,
        "x_ln_task_claim_token": CLAIM_TOKEN,
        "xLnTaskClaimToken": CLAIM_TOKEN,
        "safe": {"task_id": "task_example"},
    }
    public = _task_public_payload(payload)
    assert public == {"safe": {"task_id": "task_example"}}
    assert CLAIM_TOKEN not in repr(public)


@pytest.mark.parametrize(
    ("model_type", "payload"),
    [
        (
            TaskClaimCredential,
            {
                **_credential()._to_private_file_payload(),
                "domain": CLAIM_TOKEN,
            },
        ),
        (
            TaskClaimCredential,
            {
                **_credential()._to_private_file_payload(),
                "future_secret_field": CLAIM_TOKEN,
            },
        ),
    ],
)
def test_claim_validation_never_retains_token_in_structured_errors(
    model_type, payload
):
    with pytest.raises((TypeError, ValueError, ValidationError)) as caught:
        model_type.model_validate(payload)

    error = caught.value
    structured_errors = getattr(error, "errors", lambda: [])()
    rendered_traceback = "".join(
        traceback.format_exception(type(error), error, error.__traceback__)
    )
    surfaces = [
        str(error),
        repr(error),
        repr(vars(error)),
        repr(structured_errors),
        rendered_traceback,
    ]
    assert all(CLAIM_TOKEN not in surface for surface in surfaces)
    _assert_finite_exception_graph(error, CLAIM_TOKEN)


def test_claim_response_discards_unknown_legacy_domain_without_secret_exposure():
    legacy_secret = "legacy-domain-secret.invalid"
    response = AgentTaskClaimResponse.model_validate(
        {**_claim_response(), "domain": legacy_secret}
    )
    claim = response.to_claim("external-agent")
    surfaces = [
        repr(response),
        repr(response.model_dump(mode="json")),
        repr(claim),
        repr(claim.model_dump(mode="json")),
        repr(claim.credential._to_private_file_payload()),
    ]
    assert all(legacy_secret not in surface for surface in surfaces)
    assert all("domain" not in surface for surface in surfaces)


@pytest.mark.parametrize(
    "model_type",
    [TaskClaimCredential, AgentTaskClaimResponse],
)
@pytest.mark.parametrize(
    "json_data",
    ["null", "123", json.dumps(CLAIM_TOKEN), json.dumps([CLAIM_TOKEN])],
)
def test_claim_json_validation_sanitizes_non_object_payloads(
    model_type, json_data
):
    with pytest.raises(ValueError) as caught:
        model_type.model_validate_json(json_data)

    error = caught.value
    rendered_traceback = "".join(
        traceback.format_exception(type(error), error, error.__traceback__)
    )
    surfaces = [
        str(error),
        repr(error),
        repr(vars(error)),
        rendered_traceback,
    ]
    assert all(CLAIM_TOKEN not in surface for surface in surfaces)


def test_task_argparse_error_never_echoes_extra_canonical_claim_token(capsys):
    argv = [
        "ln-church-agent",
        "task",
        "get",
        "task_example",
        CLAIM_TOKEN,
    ]
    with patch.object(sys, "argv", argv):
        from ln_church_agent.cli import main

        with pytest.raises(SystemExit) as caught:
            main()

    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert CLAIM_TOKEN not in captured.out
    assert CLAIM_TOKEN not in captured.err
    assert captured.err.startswith("Task error: ")
    assert captured.err.count("\n") == 1


def test_task_cli_accepts_legitimate_43_character_task_id(capsys):
    task_id = "B" * 43
    seen = []
    task_payload = _task()
    task_payload["task_id"] = task_id
    task = AgentTask.model_validate(task_payload)

    class FakeClient:
        def get_task(self, requested_task_id, **kwargs):
            seen.append((requested_task_id, kwargs))
            return task

        def close(self):
            pass

    argv = ["ln-church-agent", "task", "get", task_id, "--json"]
    with patch("ln_church_agent.task_client.AgentTaskClient", FakeClient):
        with patch.object(sys, "argv", argv):
            from ln_church_agent.cli import main

            main()

    captured = capsys.readouterr()
    assert seen == [(task_id, {"limit": 20, "cursor": None})]
    assert "TASK_CREDENTIAL_INVALID" not in captured.err
    assert json.loads(captured.out)["task_id"] == task_id


def test_task_get_cli_json_preserves_all_summary_fields_and_nulls(capsys):
    task = AgentTask.model_validate(
        _task(execution_summaries=[_execution_summary()])
    )

    class FakeClient:
        def get_task(self, requested_task_id, **kwargs):
            return task

        def close(self):
            pass

    argv = [
        "ln-church-agent",
        "task",
        "get",
        "task_example",
        "--json",
    ]
    with patch("ln_church_agent.task_client.AgentTaskClient", FakeClient):
        with patch.object(sys, "argv", argv):
            from ln_church_agent.cli import main

            main()

    captured = capsys.readouterr()
    assert captured.err == ""
    summary = json.loads(captured.out)["execution_summaries"][0]
    assert set(summary) == {
        "submission_id",
        "observation_id",
        "task_status",
        "reward_state",
        "network",
        "asset",
        "asset_address",
        "amount_atomic",
        "evaluated_at",
        "reward_tx_hash",
        "rewarded_at",
        "failure_code",
    }
    assert summary["evaluated_at"] is None
    assert summary["reward_tx_hash"] is None
    assert summary["rewarded_at"] is None
    assert summary["failure_code"] is None


def test_task_get_cli_displays_exact_server_page_and_disclosure(capsys):
    seen = []
    task = AgentTask.model_validate(
        _task(
            capacity_total=3,
            capacity_remaining=2,
            active_execution_count=2,
            rewarded_execution_count=0,
            claim_count_total=73,
            reward_paid_total_minor=0,
            maximum_reward_principal_atomic="30000",
            claimable=False,
            execution_summaries=[
                _execution_summary(
                    task_status="REWARD_PENDING",
                    amount_atomic="10000",
                )
            ],
            execution_summaries_next_cursor="next-page",
        )
    )

    class FakeClient:
        def get_task(self, requested_task_id, **kwargs):
            seen.append((requested_task_id, kwargs))
            return task

        def close(self):
            pass

    argv = [
        "ln-church-agent",
        "task",
        "get",
        "task_example",
        "--limit",
        "1",
        "--cursor",
        "opaque-page",
    ]
    with patch("ln_church_agent.task_client.AgentTaskClient", FakeClient):
        with patch.object(sys, "argv", argv):
            from ln_church_agent.cli import main

            main()

    captured = capsys.readouterr()
    assert captured.err == ""
    assert seen == [
        (
            "task_example",
            {"limit": 1, "cursor": "opaque-page"},
        )
    ]
    for exact_server_value in (
        "Active executions       : 2",
        "Successful claims       : 73",
        "Rewarded executions     : 0",
        "Paid total (atomic)     : 0",
        "Capacity total          : 3",
        "Capacity remaining      : 2",
        "Maximum reward principal: 30000",
        "Claimable               : False",
        "Completion 2xx      : durable_receipt_only",
        "Payout mode          : "
        "automatic_best_effort_with_finite_retry_and_recorded_evidence",
        "Execution summaries: 1",
        SUBMISSION_ID,
        "REWARD_PENDING",
        "approved_pending",
        "Next cursor        : next-page",
    ):
        assert exact_server_value in captured.out


def test_windows_reparse_scan_keeps_original_root_and_every_ancestor():
    from pathlib import PureWindowsPath

    from ln_church_agent.cli import _windows_original_ancestors

    local_app_data = PureWindowsPath(
        r"C:\Users\agent\AppData\Local"
    )
    required_root = (
        local_app_data / "ln-church-agent" / "claims"
    )
    candidate_parent = required_root / "nested"

    required_ancestors = _windows_original_ancestors(required_root)
    candidate_ancestors = _windows_original_ancestors(candidate_parent)

    assert required_ancestors == (
        PureWindowsPath("C:/"),
        PureWindowsPath("C:/Users"),
        PureWindowsPath("C:/Users/agent"),
        PureWindowsPath("C:/Users/agent/AppData"),
        local_app_data,
        local_app_data / "ln-church-agent",
        required_root,
    )
    assert candidate_ancestors[: len(required_ancestors)] == required_ancestors
    assert candidate_ancestors[-1] == candidate_parent
