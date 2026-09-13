import copy
import io
import json
import pickle

import pytest
from pydantic import ValidationError

from ln_church_agent.task_v2_models import (
    ManifestFetchResult,
    ScheduledCompletionReport,
    ScheduledRewardStatus,
    ScheduledTargetResult,
    ScheduledTaskClaimCredential,
    ScheduledTaskClaimRequest,
    ScheduledTaskClaimResponse,
    ScheduledTaskReadiness,
)


TOKEN = "A" * 43
SIGNED_URL = (
    "https://tasks-release.mayim-mayim.com/opaque"
    "?Policy=secret&Signature=hidden&Key-Pair-Id=K"
)
ADDRESS = "0x0000000000000000000000000000000000000001"
DIGEST = "a" * 64
PICKLE_ERROR = "Secret-bearing scheduled Task models cannot be pickled."


def _claim_payload():
    return {
        "schema_version": "ln_church.agent_task_claim_response.v2",
        "task_id": "task_1",
        "task_type": "scheduled_http_get_batch.v1",
        "task_definition_version": "1.0.0",
        "task_definition_digest": DIGEST,
        "claim_token": TOKEN,
        "claim_expires_at": "2026-08-20T03:10:00Z",
        "scheduled_at": "2026-08-20T03:00:00Z",
        "report_close_at": "2026-08-20T03:10:00Z",
        "manifest_url": SIGNED_URL,
        "manifest_url_not_before": "2026-08-20T03:00:00Z",
        "manifest_url_expires_at": "2026-08-20T03:10:00Z",
        "reward_address": ADDRESS,
        "reward_address_control_verified": False,
        "reward": {
            "network": "eip155:8453",
            "asset": "USDC",
            "asset_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "amount_atomic": "10000",
        },
    }


def _credential():
    return ScheduledTaskClaimResponse.model_validate(_claim_payload()).to_credential(
        agent_id="agent_1"
    )


def _readiness():
    return ScheduledTaskReadiness.model_validate(
        {
            "schema_version": "ln_church.agent_task_readiness.v1",
            "task_id": "task_1",
            "offer_status": "RUNNING",
            "execution_available": True,
            "release_state": "READY",
            "manifest_sha256": "c" * 64,
            "manifest_url": SIGNED_URL,
            "manifest_url_expires_at": "2026-08-20T03:10:00Z",
            "new_target_start_before": "2026-08-20T03:05:00Z",
            "report_close_at": "2026-08-20T03:10:00Z",
        }
    )


def _report():
    return ScheduledCompletionReport(
        submission_id="sub_" + "b" * 32,
        task_definition_digest=DIGEST,
        manifest_sha256="c" * 64,
        manifest_fetch=ManifestFetchResult(
            outcome="retrieved",
            http_status=200,
            observed_sha256="c" * 64,
            elapsed_ms=23,
        ),
        results=[
            ScheduledTargetResult(
                position=0,
                target_url="https://example.com/a",
                outcome="http_response",
                http_status=200,
                elapsed_ms=10,
            )
        ],
        completed_at="2026-08-20T03:04:40Z",
    )


def _status_payload():
    return {
        "schema_version": "ln_church.agent_task_reward_status.v2",
        "task_id": "task_1",
        "task_type": "scheduled_http_get_batch.v1",
        "task_definition_version": "1.0.0",
        "task_definition_digest": DIGEST,
        "manifest_sha256": "c" * 64,
        "submission_id": "sub_" + "b" * 32,
        "report_id": "report_1",
        "report_sha256": "d" * 64,
        "accepted_at": "2026-08-20T03:04:41Z",
        "receipt_state": "DURABLY_ACCEPTED",
        "evaluation": {"state": "PENDING"},
        "base_reward": {
            "entitlement_state": "NOT_CREATED",
            "settlement_state": "NOT_CREATED",
        },
        "reference_bonus": {
            "candidate": True,
            "decision_state": "PENDING",
        },
        "terminal": False,
        "retry_after_seconds": 30,
    }


def test_agent_and_reward_address_validation_are_exact():
    request = ScheduledTaskClaimRequest(
        agent_id="agent.name-1", reward_address=ADDRESS
    )
    assert request.agent_id == "agent.name-1"
    with pytest.raises(ValidationError):
        ScheduledTaskClaimRequest(agent_id="bad value", reward_address=ADDRESS)
    with pytest.raises(ValidationError):
        ScheduledTaskClaimRequest(
            agent_id="agent", reward_address="0x0000000000000000000000000000000000000000"
        )


def test_claim_token_and_signed_url_never_enter_ordinary_serialization_or_repr():
    response = ScheduledTaskClaimResponse.model_validate(_claim_payload())
    for rendered in (
        repr(response),
        str(response),
        response.model_dump_json(),
        json.dumps(response.model_dump(mode="json")),
    ):
        assert TOKEN not in rendered
        assert SIGNED_URL not in rendered
        assert "Policy=secret" not in rendered
    assert response._claim_token_value() == TOKEN
    assert response._manifest_url_value() == SIGNED_URL


def test_private_credential_file_is_only_secret_serialization_boundary():
    credential = _credential()
    public_dump = credential.model_dump_json()
    assert TOKEN not in public_dump
    assert SIGNED_URL not in public_dump
    assert len(credential._local_fingerprint()) == 64
    assert credential.local_claim_credential_handle == credential._local_fingerprint()
    assert credential.local_claim_credential_handle not in public_dump

    private_payload = credential._to_private_file_payload()
    assert private_payload["claim_token"] == TOKEN
    assert private_payload["manifest_url"] == SIGNED_URL
    restored = ScheduledTaskClaimCredential._from_private_file_payload(
        private_payload
    )
    assert restored._claim_token_value() == TOKEN
    assert restored._manifest_url_value() == SIGNED_URL
    assert restored._local_fingerprint() == credential._local_fingerprint()


def test_credential_owns_reward_and_revalidates_unchecked_external_dto():
    payload = _credential()._to_private_file_payload()
    payload.pop("schema_version")
    payload.pop("state")
    payload["reward"] = _credential().reward
    credential = ScheduledTaskClaimCredential(**payload)
    public = credential.model_dump(mode="json")
    public["reward"]["amount_atomic"] = "1"
    assert credential.reward.amount_atomic == "10000"
    payload["reward"] = payload["reward"].model_copy(update={"amount_atomic": "1"})
    with pytest.raises(ValueError):
        ScheduledTaskClaimCredential(**payload)


@pytest.mark.parametrize(
    "model_factory",
    [
        lambda: ScheduledTaskClaimResponse.model_validate(_claim_payload()),
        _credential,
        _readiness,
    ],
    ids=["claim-response", "claim-credential", "readiness"],
)
@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
def test_secret_bearing_models_fail_closed_for_every_pickle_protocol(
    model_factory, protocol, caplog, capsys
):
    model = model_factory()
    secrets = (TOKEN, SIGNED_URL, "Policy=secret")

    for rendered in (
        repr(model),
        str(model),
        model.model_dump_json(),
        json.dumps(model.model_dump(mode="json")),
    ):
        for secret in secrets:
            assert secret not in rendered

    with pytest.raises(TypeError) as dumps_error:
        pickle.dumps(model, protocol=protocol)
    assert str(dumps_error.value) == PICKLE_ERROR

    sink = io.BytesIO()
    with pytest.raises(TypeError) as pickler_error:
        pickle.Pickler(sink, protocol=protocol).dump(model)
    assert str(pickler_error.value) == PICKLE_ERROR

    partial = sink.getvalue()
    for secret in secrets:
        encoded = secret.encode("utf-8")
        assert encoded not in partial
        assert secret not in str(dumps_error.value)
        assert secret not in str(pickler_error.value)

    with pytest.raises((EOFError, pickle.UnpicklingError)):
        pickle.loads(partial)

    captured = capsys.readouterr()
    logged = "\n".join(record.getMessage() for record in caplog.records)
    for rendered in (captured.out, captured.err, logged):
        for secret in secrets:
            assert secret not in rendered


@pytest.mark.parametrize(
    "model_factory",
    [
        lambda: ScheduledTaskClaimResponse.model_validate(_claim_payload()),
        _credential,
        _readiness,
    ],
    ids=["claim-response", "claim-credential", "readiness"],
)
def test_secret_bearing_models_reject_every_pickle_state_hook(model_factory):
    model = model_factory()
    operations = (
        lambda: model.__reduce_ex__(pickle.HIGHEST_PROTOCOL),
        model.__reduce__,
        model.__getstate__,
        lambda: model.__setstate__({}),
    )
    for operation in operations:
        with pytest.raises(TypeError) as error:
            operation()
        assert str(error.value) == PICKLE_ERROR
        assert TOKEN not in str(error.value)
        assert SIGNED_URL not in str(error.value)
        assert "Policy=secret" not in str(error.value)


def test_nonsecret_frozen_models_retain_pickle_and_copy_compatibility():
    models = (
        ScheduledTaskClaimRequest(agent_id="agent_1", reward_address=ADDRESS),
        _report(),
    )
    for model in models:
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            restored = pickle.loads(pickle.dumps(model, protocol=protocol))
            assert restored == model
            assert restored is not model
        for cloned in (copy.copy(model), copy.deepcopy(model), model.model_copy()):
            assert cloned == model
            assert cloned is not model


def test_readiness_matrix_withholds_digest_pre_t_and_requires_it_at_t():
    pending = ScheduledTaskReadiness.model_validate(
        {
            "schema_version": "ln_church.agent_task_readiness.v1",
            "task_id": "task_1",
            "offer_status": "ESTABLISHED",
            "execution_available": False,
            "release_state": "READY",
            "manifest_url": SIGNED_URL,
            "manifest_url_not_before": "2026-08-20T03:00:00Z",
            "manifest_url_expires_at": "2026-08-20T03:10:00Z",
            "retry_at": "2026-08-20T03:00:00Z",
        }
    )
    assert pending.manifest_sha256 is None
    assert SIGNED_URL not in pending.model_dump_json()

    ready = ScheduledTaskReadiness.model_validate(
        {
            "schema_version": "ln_church.agent_task_readiness.v1",
            "task_id": "task_1",
            "offer_status": "RUNNING",
            "execution_available": True,
            "release_state": "READY",
            "manifest_sha256": "c" * 64,
            "manifest_url": SIGNED_URL,
            "manifest_url_expires_at": "2026-08-20T03:10:00Z",
            "new_target_start_before": "2026-08-20T03:05:00Z",
            "report_close_at": "2026-08-20T03:10:00Z",
        }
    )
    assert ready.manifest_sha256 == "c" * 64
    readiness_dump = ready.model_dump(mode="json")
    assert readiness_dump["manifest_sha256"] == "c" * 64
    for rendered in (
        repr(ready),
        ready.model_dump_json(),
        json.dumps(readiness_dump),
    ):
        assert SIGNED_URL not in rendered
        assert "Policy=secret" not in rendered

    with pytest.raises(ValueError, match="Invalid scheduled Task readiness"):
        ScheduledTaskReadiness.model_validate(
            {
                "schema_version": "ln_church.agent_task_readiness.v1",
                "task_id": "task_1",
                "offer_status": "CLOSED",
                "execution_available": False,
                "release_state": "READY",
                "manifest_url": SIGNED_URL,
                "manifest_url_not_before": "2026-08-20T03:00:00Z",
                "manifest_url_expires_at": "2026-08-20T03:10:00Z",
                "retry_at": "2026-08-20T03:00:00Z",
            }
        )

    invalid_post = {
        "schema_version": "ln_church.agent_task_readiness.v1",
        "task_id": "task_1",
        "offer_status": "RUNNING",
        "execution_available": True,
        "release_state": "READY",
        "manifest_sha256": "c" * 64,
        "manifest_url": SIGNED_URL,
        "manifest_url_expires_at": "2026-08-20T03:10:00Z",
        "new_target_start_before": "2026-08-20T03:10:00Z",
        "report_close_at": "2026-08-20T03:10:00Z",
    }
    with pytest.raises(ValueError, match="Invalid scheduled Task readiness"):
        ScheduledTaskReadiness.model_validate(invalid_post)


def test_completion_report_canonicalizes_and_freezes_exact_fields():
    report = _report()
    frozen = report.canonical_bytes()
    assert len(frozen) <= 65536
    assert json.loads(frozen)["submission_id"] == "sub_" + "b" * 32
    assert len(report.canonical_digest()) == 64
    with pytest.raises(ValidationError):
        ScheduledCompletionReport.model_validate(
            {**report.model_dump(mode="python"), "claim_token": TOKEN}
        )


def test_completion_field_presence_and_full_coverage_are_strict():
    with pytest.raises(ValidationError):
        ManifestFetchResult(outcome="release_timeout", http_status=503)
    with pytest.raises(ValidationError):
        ScheduledTargetResult(
            position=0,
            target_url="https://example.com/a",
            outcome="timeout",
            http_status=500,
        )
    report = _report()
    with pytest.raises(ValidationError):
        ScheduledCompletionReport.model_validate(
            {
                **report.model_dump(mode="python"),
                "manifest_fetch": {"outcome": "release_timeout"},
            }
        )


def test_pending_status_accepts_omitted_reason_without_synthesizing_one():
    status = ScheduledRewardStatus.model_validate(_status_payload())
    assert status.evaluation.state == "PENDING"
    assert status.evaluation.reason is None
    assert "reason" not in status.evaluation.model_fields_set
    assert "reason" not in status.evaluation.model_dump(exclude_none=True)


@pytest.mark.parametrize("reason", [None, "", "x" * 129])
def test_status_rejects_present_invalid_evaluation_reason(reason):
    payload = _status_payload()
    payload["evaluation"]["reason"] = reason
    with pytest.raises(ValidationError):
        ScheduledRewardStatus.model_validate(payload)


def test_status_accepts_present_bounded_reason_and_rejects_unknown_fields():
    payload = _status_payload()
    payload["evaluation"] = {"state": "BLOCKED", "reason": "policy_blocked"}
    status = ScheduledRewardStatus.model_validate(payload)
    assert status.evaluation.reason == "policy_blocked"

    for target in ("evaluation", "base_reward", "reference_bonus"):
        malformed = copy.deepcopy(payload)
        malformed[target]["unknown"] = True
        with pytest.raises(ValidationError):
            ScheduledRewardStatus.model_validate(malformed)


def test_status_accepts_exact_base_and_reference_bonus_shapes():
    approved = _status_payload()
    approved["evaluation"] = {"state": "APPROVED", "reason": "accepted"}
    approved["base_reward"] = {
        "entitlement_state": "DUE",
        "settlement_state": "CONFIRMING",
    }
    approved["reference_bonus"] = {
        "candidate": True,
        "decision_state": "AWARDED",
        "settlement_state": "DUE",
    }
    status = ScheduledRewardStatus.model_validate(approved)
    assert status.base_reward.entitlement_state == "DUE"
    assert status.base_reward.settlement_state == "CONFIRMING"
    assert status.reference_bonus.decision_state == "AWARDED"
    assert status.reference_bonus.settlement_state == "DUE"

    terminal = copy.deepcopy(approved)
    terminal["base_reward"] = {
        "entitlement_state": "TERMINAL",
        "settlement_state": "PAID_CONFIRMED",
    }
    terminal["reference_bonus"] = {
        "candidate": False,
        "decision_state": "NOT_AWARDED",
    }
    terminal["terminal"] = True
    terminal["retry_after_seconds"] = 0
    parsed_terminal = ScheduledRewardStatus.model_validate(terminal)
    assert parsed_terminal.terminal is True
    assert parsed_terminal.reference_bonus.settlement_state is None


def test_status_does_not_infer_terminal_before_reference_bonus_is_final():
    payload = _status_payload()
    payload["evaluation"] = {"state": "APPROVED", "reason": "STRUCTURALLY_VALID"}
    payload["base_reward"] = {
        "entitlement_state": "TERMINAL",
        "settlement_state": "PAID_CONFIRMED",
    }
    payload["reference_bonus"] = {
        "candidate": False,
        "decision_state": "PENDING",
    }
    payload["terminal"] = False
    payload["retry_after_seconds"] = 15

    status = ScheduledRewardStatus.model_validate(payload)
    assert status.base_reward.entitlement_state == "TERMINAL"
    assert status.reference_bonus.decision_state == "PENDING"
    assert status.terminal is False
    assert status.retry_after_seconds == 15


@pytest.mark.parametrize(
    ("reference_bonus", "base_reward"),
    [
        (
            {"candidate": True, "decision_state": "AWARDED"},
            {"entitlement_state": "DUE", "settlement_state": "DUE"},
        ),
        (
            {
                "candidate": True,
                "decision_state": "PENDING",
                "settlement_state": "NOT_CREATED",
            },
            {"entitlement_state": "DUE", "settlement_state": "DUE"},
        ),
        (
            {
                "candidate": True,
                "decision_state": "AWARDED",
                "settlement_state": None,
            },
            {"entitlement_state": "DUE", "settlement_state": "DUE"},
        ),
        (
            {"candidate": True, "decision_state": "UNKNOWN"},
            {"entitlement_state": "DUE", "settlement_state": "DUE"},
        ),
        (
            {"candidate": True, "decision_state": "PENDING"},
            {"entitlement_state": "PAID_CONFIRMED", "settlement_state": "DUE"},
        ),
    ],
)
def test_status_rejects_noncanonical_nested_reward_shapes(
    reference_bonus, base_reward
):
    payload = _status_payload()
    payload["reference_bonus"] = reference_bonus
    payload["base_reward"] = base_reward
    with pytest.raises(ValidationError):
        ScheduledRewardStatus.model_validate(payload)


@pytest.mark.parametrize(
    ("terminal", "retry_after_seconds", "accepted"),
    [
        (False, 1, True),
        (False, 3600, True),
        (False, 0, False),
        (False, 3601, False),
        (True, 0, True),
        (True, 1, False),
        (True, 3600, False),
        (True, None, False),
    ],
)
def test_status_retry_value_is_bound_to_server_terminal_flag(
    terminal, retry_after_seconds, accepted
):
    payload = _status_payload()
    payload["terminal"] = terminal
    payload["retry_after_seconds"] = retry_after_seconds
    if accepted:
        assert ScheduledRewardStatus.model_validate(payload).terminal is terminal
    else:
        with pytest.raises(ValidationError):
            ScheduledRewardStatus.model_validate(payload)


def test_status_requires_retry_after_seconds():
    payload = _status_payload()
    del payload["retry_after_seconds"]
    with pytest.raises(ValidationError):
        ScheduledRewardStatus.model_validate(payload)
