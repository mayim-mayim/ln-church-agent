"""Focused checks derived from audited Wire W1-W5 and SDK-R1/R2/R4/R5."""
import hashlib
import json
import pickle
from pathlib import Path

import pytest

from ln_church_agent.immediate_visit_contract import STATUS_REASONS, validate_endpoint_url
from ln_church_agent.immediate_visit_models import (
    FrozenImmediateVisitReport, ImmediateVisitClaimCredential, ImmediateVisitTask,
    ImmediateVisitTaskPage, ImmediateVisitSubmissionStatus,
)

TASK = "task_" + "1" * 32
EXECUTION = "exec_" + "2" * 32
SUBMISSION = "sub_" + "3" * 32
URL = "https://example.com/"
ENDPOINT = "ep_" + hashlib.sha256(URL.encode()).hexdigest()
TOKEN = "A" * 43
ADDRESS = "0x1111111111111111111111111111111111111111"
AT = "2026-09-14T00:00:00.000Z"
DEADLINE = "2026-09-14T00:10:00.000Z"
REWARD = dict(network="eip155:8453", asset="USDC", asset_address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
              base_amount_atomic="7500", bonus_amount_atomic="7500", maximum_amount_atomic="15000")


def claim_wire():
    return dict(schema_version="ln_church.agent_task_claim_response.immediate_visit.v1", task_id=TASK,
                task_type="immediate_http_visit.v1", execution_id=EXECUTION, claim_token=TOKEN,
                claimed_at=AT, report_deadline=DEADLINE, reward_address=ADDRESS,
                reward_address_control_verified=False, profile_id="immediate_visit_utf8.v1",
                endpoints=[dict(endpoint_id=ENDPOINT, url=URL)], repeat_policy="allow", reward=dict(REWARD))


def report_wire():
    return dict(schema_version="ln_church.task_completion.immediate_visit.v1", task_id=TASK,
                execution_id=EXECUTION, submission_id=SUBMISSION, endpoint_id=ENDPOINT,
                profile_id="immediate_visit_utf8.v1", observation=dict(outcome="comparable", status=404,
                media_family="json", body_bytes=15, fetch_started_at=AT,
                fetch_finished_at="2026-09-14T00:00:00.500Z", structure_sha256="4"*64, body_sha256="5"*64))


def task_wire():
    value = claim_wire()
    for name in ("claim_token", "execution_id", "claimed_at", "report_deadline", "reward_address", "reward_address_control_verified"):
        del value[name]
    value.update(schema_version="ln_church.agent_task.immediate_visit.v1", definition_version="1.0.0", status="OPEN",
                 published_at=AT, listing_ends_at="2026-09-16T00:00:00.000Z", plan_id="C50",
                 registration_amount_atomic="1000000", capacity_total=50, capacity_reserved=10,
                 capacity_consumed=20, capacity_available=20,
                 definition_url="https://kari.mayim-mayim.com/agent-task-specs/immediate_http_visit.v1/1.0.0/SKILL.md",
                 summary_url="https://kari.mayim-mayim.com/api/agent/task-offers/"+TASK+"/summary",
                 results_url="https://kari.mayim-mayim.com/agent-taskboard.html?task_id="+TASK+"&view=results")
    return value


def status_wire(state="pending", payment=None):
    report = FrozenImmediateVisitReport.from_report(report_wire())
    amount = {"base_approved":"7500", "base_bonus_approved":"15000"}.get(state,"0")
    payment = payment or ("not_applicable" if amount == "0" else "pending")
    return dict(schema_version="ln_church.task_submission_status.immediate_visit.v1", task_id=TASK,
                execution_id=EXECUTION, submission_id=SUBMISSION, endpoint_id=ENDPOINT,
                profile_id="immediate_visit_utf8.v1", report_sha256=report.report_sha256,
                received_at="2026-09-14T00:00:01.000Z", evaluation_state=state,
                decision_at=None if state == "pending" else "2026-09-14T00:00:02.000Z",
                approved_amount_atomic=amount, bonus_approved=state == "base_bonus_approved",
                payment_state=payment, transaction_hash="0x"+"6"*64 if payment == "paid_confirmed" else None,
                reason=None, updated_at="2026-09-14T00:00:03.000Z")


def test_full_report_freezes_diagnostics_and_separate_sha256():
    wire = report_wire()
    report = FrozenImmediateVisitReport.from_report(wire)
    expected = json.dumps(wire, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    assert report.canonical_bytes == expected
    assert report.report_sha256 == hashlib.sha256(expected).hexdigest()
    assert report.report_sha256 not in (wire["observation"]["body_sha256"], wire["observation"]["structure_sha256"])
    wire["observation"]["status"] = 200
    assert report.report.observation.status == 404
    with pytest.raises(Exception):
        report.canonical_bytes = b"{}"
    with pytest.raises(ValueError):
        FrozenImmediateVisitReport.from_bytes(b" " + expected)


@pytest.mark.parametrize("mutation", [
    lambda w: w.update(url="https://attacker.example/"),
    lambda w: w.update(profile_id="public_safe_light"),
    lambda w: w.update(schema_version="ln_church.scheduled_http_get_batch_completion.v1"),
    lambda w: w.update(submission_id="sub_"+"A"*32),
    lambda w: w["observation"].update(reason="body_empty"),
    lambda w: w["observation"].update(status=206),
    lambda w: w["observation"].update(status=304),
    lambda w: w["observation"].update(status=True),
    lambda w: w["observation"].update(body_bytes=2097153),
    lambda w: w["observation"].update(body_bytes=0),
    lambda w: w["observation"].update(fetch_started_at=None),
    lambda w: w["observation"].update(body_sha256="A"*64),
])
def test_invalid_comparable_reports_rejected(mutation):
    value = report_wire()
    mutation(value)
    with pytest.raises(ValueError, match="Invalid frozen"):
        FrozenImmediateVisitReport.from_report(value)


@pytest.mark.parametrize("status", [200, 301, 402, 403, 404, 500, 599])
def test_non_2xx_bodies_may_be_comparable(status):
    value = report_wire()
    value["observation"]["status"] = status
    assert FrozenImmediateVisitReport.from_report(value).report.observation.status == status


def test_inconclusive_has_nullable_diagnostics_but_no_hash_or_server_reason():
    value = report_wire()
    value["observation"] = dict(outcome="inconclusive", status=None, media_family=None, body_bytes=None,
                                fetch_started_at=None, fetch_finished_at=None, reason="fetch_outcome_lost")
    report = FrozenImmediateVisitReport.from_report(value)
    assert b"body_sha256" not in report.canonical_bytes
    for key, change in (("body_sha256", "0"*64), ("reason", "reference_outcome_lost"), ("reason", TOKEN)):
        candidate = report_wire()
        candidate["observation"] = dict(value["observation"], **{key:change})
        with pytest.raises(ValueError):
            FrozenImmediateVisitReport.from_report(candidate)


def test_claim_is_immutable_private_and_address_normalized():
    wire = claim_wire()
    claim = ImmediateVisitClaimCredential.model_validate(wire)
    wire["endpoints"][0]["url"] = "https://bad.example/"
    assert claim.endpoints[0].url == URL
    assert TOKEN not in repr(claim) and TOKEN not in claim.model_dump_json()
    assert "claim_token" not in claim.model_dump()
    assert claim._private_payload()["claim_token"] == TOKEN
    with pytest.raises(TypeError):
        pickle.dumps(claim)
    with pytest.raises(Exception):
        claim.endpoints[0].url = "https://bad.example/"
    tampered = claim.model_copy(update={"reward_address": "not-an-address"})
    with pytest.raises(ValueError):
        tampered._validated_snapshot()


@pytest.mark.parametrize("field,value", [("task_type","scheduled_http_get_batch.v1"),
    ("schema_version","ln_church.agent_task.v2"), ("profile_id","unknown"),
    ("definition_version","2.0.0"), ("published_at","2026-09-14T00:00:00Z"),
    ("capacity_total",True), ("capacity_available",-1)])
def test_task_profile_and_counts_are_strict(field,value):
    wire = task_wire()
    wire[field] = value
    with pytest.raises(ValueError):
        ImmediateVisitTask.model_validate(wire)


def test_task_page_snapshot_cursor_and_field_local_capacity():
    wire = task_wire()
    wire.update(capacity_total=5000, capacity_reserved=4999, capacity_consumed=2, capacity_available=1)
    page = ImmediateVisitTaskPage.model_validate(dict(schema_version="ln_church.agent_task_page.immediate_visit.v1",
                                                    tasks=[wire],next_cursor="opaque/+=="))
    assert page.tasks[0].capacity_total == 5000 and page.next_cursor == "opaque/+=="


@pytest.mark.parametrize("state", ["pending","repeat_drop","inconclusive","mismatch","base_approved","base_bonus_approved"])
def test_all_evaluation_states_keep_authoritative_amount(state):
    status = ImmediateVisitSubmissionStatus.model_validate(status_wire(state))
    assert status.approved_amount_atomic == {"base_approved":"7500","base_bonus_approved":"15000"}.get(state,"0")
    invalid = status_wire(state)
    invalid["approved_amount_atomic"] = "15000" if state != "base_bonus_approved" else "0"
    with pytest.raises(ValueError):
        ImmediateVisitSubmissionStatus.model_validate(invalid)


@pytest.mark.parametrize("payment", ["pending","ambiguous","paid_confirmed","failed"])
def test_approval_survives_every_payment_state(payment):
    status = ImmediateVisitSubmissionStatus.model_validate(status_wire("base_approved",payment))
    assert status.approved_amount_atomic == "7500"
    assert status.payment_state == payment


def test_status_reason_enum_matches_accepted_contract_and_retains_repeat_drop():
    resource = Path(__file__).parents[1] / "ln_church_agent/contracts/v183-immediate-visit/result.schema.json"
    accepted = json.loads(resource.read_bytes())["properties"]["reason"]["enum"]
    assert STATUS_REASONS == frozenset(value for value in accepted if value is not None)
    wire = dict(status_wire("repeat_drop"), reason="repeat_drop")
    status = ImmediateVisitSubmissionStatus.model_validate(wire)
    assert status.evaluation_state == status.reason == "repeat_drop"
    assert status.approved_amount_atomic == "0" and not status.bonus_approved
    assert status.payment_state == "not_applicable" and status.transaction_hash is None
    with pytest.raises(ValueError):
        ImmediateVisitSubmissionStatus.model_validate(dict(wire, reason="arbitrary-reason"))


def test_accepted_wire_decision_fixtures_preserve_all_fields():
    resource = Path(__file__).parents[1] / "ln_church_agent/contracts/v183-immediate-visit/wire-fixtures.json"
    fixtures = json.loads(resource.read_bytes())["fixtures"]
    decisions = [item for item in fixtures if item.get("schema") == "result.schema.json"]
    assert len(decisions) == 9
    for item in decisions:
        status = ImmediateVisitSubmissionStatus.model_validate(item["value"])
        assert status.model_dump(mode="json") == item["value"], item["id"]


@pytest.mark.parametrize("url", ["https://example.com/?", "https://example.com./", "https://example.com/%23", "https://example.com/%"])
def test_whatwg_canonical_url_forms_preserved(url):
    assert validate_endpoint_url(url) == url


@pytest.mark.parametrize("url", ["https://example.com/#", "https://127.0.0.1/", "https://0x7f000001/", "https://example.com:443/", "https://user@example.com/", "https://example.com/a/../", "http://example.com/"])
def test_noncanonical_or_forbidden_url_forms_rejected(url):
    with pytest.raises(ValueError):
        validate_endpoint_url(url)
