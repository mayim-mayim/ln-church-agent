"""Synthetic actual-request evidence for SDK-R4/W4/W5, with target I/O absent."""
import json

import pytest

from ln_church_agent.immediate_visit_client import AgentImmediateVisitClient
from ln_church_agent.immediate_visit_contract import PUBLIC_API_ORIGIN, task_status_path
from ln_church_agent.immediate_visit_journal import ImmediateVisitJournal
from ln_church_agent.immediate_visit_models import FrozenImmediateVisitReport, ImmediateVisitClaimCredential
from ln_church_agent.immediate_visit_transport import (
    ImmediateVisitRawResponse, ImmediateVisitTransport, ImmediateVisitTransportError,
    ImmediateVisitAPIError,
)
from test_v1_18_3_immediate_visit_contract import (
    claim_wire, report_wire, task_wire, status_wire, TASK, EXECUTION, SUBMISSION, ENDPOINT, TOKEN, ADDRESS,
)


def raw(value, status=200):
    return ImmediateVisitRawResponse(status, {"Content-Type":"application/json"}, json.dumps(value).encode())


def error(code="not_found", status=404):
    return raw(dict(schema_version="ln_church.task_error.immediate_visit.v1", code=code,
                    message="private-auth-body-secret", request_id="request-1"),status)


def receipt_wire():
    report = FrozenImmediateVisitReport.from_report(report_wire())
    return dict(schema_version="ln_church.task_completion_receipt.immediate_visit.v1", task_id=TASK,
                execution_id=EXECUTION, submission_id=SUBMISSION, endpoint_id=ENDPOINT,
                profile_id="immediate_visit_utf8.v1", report_sha256=report.report_sha256,
                received_at="2026-09-14T00:00:01.000Z",
                status_url=PUBLIC_API_ORIGIN+task_status_path(TASK,SUBMISSION), receipt_state="accepted")


def abandonment_wire():
    # Exact accepted Hondō c4 releaseUnreported response; Wire W2 permits only
    # unreported Claims and same-request replay, with no submission status ID.
    return dict(schema_version="ln_church.agent_task_abandon_response.immediate_visit.v1",
                task_id=TASK, execution_id=EXECUTION, state="abandoned",
                abandoned_at="2026-09-14T00:00:01.000Z")


class Exchange:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def __call__(self, method,path,query,headers,body,timeout_seconds):
        self.requests.append((method,path,query,dict(headers),body,timeout_seconds))
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


def fixture(tmp_path, responses):
    exchange = Exchange(responses)
    client = AgentImmediateVisitClient(transport=ImmediateVisitTransport(exchange=exchange))
    claim = ImmediateVisitClaimCredential.model_validate(claim_wire())
    report = FrozenImmediateVisitReport.from_report(report_wire())
    journal = ImmediateVisitJournal(tmp_path,claim)
    return client,claim,report,journal,exchange


def test_explicit_new_discovery_one_page_and_cursor():
    page = dict(schema_version="ln_church.agent_task_page.immediate_visit.v1", tasks=[task_wire()], next_cursor="opaque/+==")
    exchange = Exchange([raw(page), raw(dict(page,next_cursor=None))])
    client = AgentImmediateVisitClient(transport=ImmediateVisitTransport(exchange=exchange))
    first = client.list_tasks(limit=1)
    second = client.list_tasks(limit=1,cursor=first.next_cursor)
    assert second.next_cursor is None and len(exchange.requests) == 2
    assert "task_type=immediate_http_visit.v1&task_schema_version=ln_church.agent_task.immediate_visit.v1" in exchange.requests[0][2]
    assert "cursor=opaque%2F%2B%3D%3D" in exchange.requests[1][2]
    assert all(request[0] == "GET" for request in exchange.requests)


def test_claim_request_has_no_endpoint_and_normalizes_address_without_local_admission():
    wire = claim_wire()
    exchange = Exchange([raw(wire), raw(dict(wire,execution_id="other_execution"))])
    client = AgentImmediateVisitClient(transport=ImmediateVisitTransport(exchange=exchange))
    first = client.claim_task(TASK,"example-agent",ADDRESS.lower(),idempotency_key="claim-one")
    second = client.claim_task(TASK,"example-agent",ADDRESS.upper().replace("0X","0x"),idempotency_key="claim-two")
    assert first.reward_address == second.reward_address
    assert len(exchange.requests) == 2
    for _,_,_,headers,body,_ in exchange.requests:
        assert "endpoint_id" not in json.loads(body)
        assert "claim_token" not in json.loads(body)
        assert headers["Idempotency-Key"].startswith("claim-")


def test_unknown_claim_response_never_retried_and_hides_secret():
    exchange = Exchange([raw(dict(claim_wire(),private_body="raw-secret-from-response"))])
    client = AgentImmediateVisitClient(transport=ImmediateVisitTransport(exchange=exchange))
    with pytest.raises(ImmediateVisitTransportError) as caught:
        client.claim_task(TASK,"example-agent",ADDRESS,idempotency_key="claim-one")
    assert str(caught.value) == "CLAIM_OUTCOME_UNKNOWN"
    assert "raw-secret" not in repr(caught.value) and TOKEN not in repr(caught.value)
    assert len(exchange.requests) == 1


def test_durable_report_saved_before_post_and_received_not_paid(tmp_path):
    client,claim,report,journal,exchange = fixture(tmp_path,[raw(receipt_wire(),202)])
    original = exchange.__call__
    def inspect(method,path,query,headers,body,timeout):
        assert journal.load_report(claim).canonical_bytes == body
        assert journal.completion_started(claim,report)
        return original(method,path,query,headers,body,timeout)
    client._transport._exchange = inspect
    result = client.complete_task(claim,report,journal=journal)
    assert result.state == "accepted" and result.receipt.receipt_state == "accepted"
    assert result.status is None and result.post_requests == 1 and result.status_requests == 0
    assert exchange.requests[0][3]["Idempotency-Key"] == SUBMISSION
    assert exchange.requests[0][3]["X-LN-Task-Claim-Token"] == TOKEN
    assert TOKEN.encode() not in exchange.requests[0][4]


def test_response_loss_checks_status_first_and_recovers_after_deadline(tmp_path):
    lost = ImmediateVisitTransportError("TIMEOUT", request_bytes_sent=True)
    client,claim,report,journal,exchange = fixture(tmp_path,[lost,raw(status_wire("base_approved","ambiguous"))])
    result = client.complete_task(claim,report,journal=journal)
    assert result.state == "accepted" and result.status.payment_state == "ambiguous"
    assert result.post_requests == 1 and result.status_requests == 1
    assert [request[0] for request in exchange.requests] == ["POST","GET"]
    assert exchange.requests[1][3]["X-LN-Task-Claim-Token"] == TOKEN
    assert TOKEN not in exchange.requests[1][1]
    # Recovery uses only report binding and receipt witness, never current clock.
    another = Exchange([raw(status_wire("base_approved","paid_confirmed"))])
    client._transport._exchange = another
    resumed = client.recover_completion(claim,report,journal=journal)
    assert resumed.status.payment_state == "paid_confirmed" and resumed.post_requests == 0
    assert len(another.requests) == 1


def test_unknown_completion_maximum_three_actual_posts_and_same_bytes(tmp_path):
    lost = ImmediateVisitTransportError("TIMEOUT", request_bytes_sent=True)
    client,claim,report,journal,exchange = fixture(tmp_path,[lost,error(),lost,error(),lost,error()])
    result = client.complete_task(claim,report,journal=journal)
    assert result.state == "unknown" and result.post_requests == 3 and result.status_requests == 3
    assert [r[0] for r in exchange.requests] == ["POST","GET","POST","GET","POST","GET"]
    posts = [r for r in exchange.requests if r[0] == "POST"]
    assert {r[4] for r in posts} == {report.canonical_bytes}
    assert {r[3]["Idempotency-Key"] for r in posts} == {SUBMISSION}
    assert all(0 < r[5] <= 20 for r in exchange.requests)


@pytest.mark.parametrize("change", [{"report_sha256":"0"*64}, {"endpoint_id":"ep_"+"f"*64},
                                    {"execution_id":"other-execution"}, {"submission_id":"sub_"+"a"*32},
                                    {"received_at":"2026-09-14T00:10:00.000Z"}, {"body":TOKEN}])
def test_wrong_or_malformed_receipt_is_unknown_not_success(tmp_path,change):
    value = dict(receipt_wire(),**change)
    client,claim,report,journal,exchange = fixture(tmp_path,[raw(value,202),error()])
    result = client.complete_task(claim,report,journal=journal,max_post_requests=1)
    assert result.state == "unknown" and result.receipt is None and result.status is None
    assert [r[0] for r in exchange.requests] == ["POST","GET"]
    assert TOKEN not in repr(result)


def test_malformed_json_2xx_unknown_and_no_raw_exception(tmp_path):
    client,claim,report,journal,exchange = fixture(tmp_path,[ImmediateVisitRawResponse(202,{},b"raw-secret"),error()])
    result = client.complete_task(claim,report,journal=journal,max_post_requests=1)
    assert result.state == "unknown" and "raw-secret" not in repr(result)


def test_definite_first_invalid_request_rejected_but_unknown_then_error_stays_unknown(tmp_path):
    client,claim,report,journal,exchange = fixture(tmp_path,[error("invalid_request",400)])
    rejected = client.complete_task(claim,report,journal=journal)
    assert rejected.state == "rejected" and rejected.error_code == "invalid_request"
    second_dir = tmp_path/"unknown"
    second_dir.mkdir(mode=0o700)
    client,claim,report,journal,exchange = fixture(second_dir,[ImmediateVisitTransportError("TIMEOUT"),error(),error("invalid_request",400)])
    unknown = client.complete_task(claim,report,journal=journal)
    assert unknown.state == "unknown" and unknown.error_code == "invalid_request"


def test_conflict_does_not_replace_accepted_report(tmp_path):
    client,claim,report,journal,exchange = fixture(tmp_path,[raw(receipt_wire(),202),error(),error("report_conflict",409)])
    assert client.complete_task(claim,report,journal=journal).state == "accepted"
    result = client.recover_completion(claim,report,journal=journal)
    assert result.state == "unknown" and result.error_code == "report_conflict"
    assert journal.load_report(claim).canonical_bytes == report.canonical_bytes
    changed = report_wire()
    changed["observation"]["body_bytes"] = 16
    with pytest.raises(Exception):
        client.complete_task(claim,FrozenImmediateVisitReport.from_report(changed),journal=journal)
    assert len(exchange.requests) == 3


@pytest.mark.parametrize("code,status", [("invalid_claim_token",401),("not_found",404)])
def test_status_credentials_and_finite_non_disclosure_error(tmp_path,code,status):
    client,claim,report,journal,exchange = fixture(tmp_path,[error(code,status)])
    with pytest.raises(ImmediateVisitAPIError) as caught:
        client.get_submission_status(claim,report)
    assert caught.value.status_code == status and caught.value.public_error_code == code
    assert "private-auth" not in repr(caught.value)
    assert len(exchange.requests) == 1
    assert exchange.requests[0][3]["X-LN-Task-Claim-Token"] == TOKEN


def test_explicit_default_poll_five_actual_requests_and_four_one_second_waits(tmp_path):
    client,claim,report,journal,exchange = fixture(tmp_path,[raw(status_wire())]*5)
    waits = []
    client._sleep = waits.append
    result = client.poll_submission_status(claim,report)
    assert result.state == "accepted" and result.status.evaluation_state == "pending"
    assert result.status.approved_amount_atomic == "0" and result.status.payment_state == "not_applicable"
    assert result.status_requests == 5 and len(exchange.requests) == 5 and waits == [1.0]*4
    assert all(r[0] == "GET" for r in exchange.requests)


def test_poll_preserves_last_known_pending_across_later_unknown(tmp_path):
    client,claim,report,journal,exchange = fixture(tmp_path,[raw(status_wire()),error()])
    client._sleep = lambda _:None
    result = client.poll_submission_status(claim,report,max_requests=2)
    assert result.state == "accepted" and result.status.evaluation_state == "pending" and result.status_requests == 2


@pytest.mark.parametrize("invalid", [True,False,0,-1,float("nan"),float("inf"),float("-inf")])
def test_invalid_finite_bounds_rejected_before_any_request(tmp_path,invalid):
    client,claim,report,journal,exchange = fixture(tmp_path,[])
    for kwargs in ({"max_post_requests":invalid},{"timeout_seconds":invalid}):
        with pytest.raises(ValueError):
            client.complete_task(claim,report,journal=journal,**kwargs)
    for kwargs in ({"max_requests":invalid},{"interval_seconds":invalid},{"timeout_seconds":invalid}):
        with pytest.raises(ValueError):
            client.poll_submission_status(claim,report,**kwargs)
    assert not exchange.requests


def test_post_bound_cannot_expand_and_poll_bound_can_shorten(tmp_path):
    client,claim,report,journal,exchange = fixture(tmp_path,[raw(status_wire())])
    with pytest.raises(ValueError):
        client.complete_task(claim,report,journal=journal,max_post_requests=4)
    assert client.poll_submission_status(claim,report,max_requests=1).status_requests == 1
    assert len(exchange.requests) == 1


def test_time_budget_exhaustion_prevents_next_request(tmp_path):
    client,claim,report,journal,exchange = fixture(tmp_path,[raw(status_wire())]*5)
    clock = [0.0]
    client._monotonic = lambda:clock[0]
    client._sleep = lambda duration:clock.__setitem__(0,clock[0]+duration)
    result = client.poll_submission_status(claim,report,timeout_seconds=2.0)
    assert result.status_requests == 2 and len(exchange.requests) == 2


def test_venue_transport_is_no_retry_and_closes_redirects():
    exchange = Exchange([ImmediateVisitRawResponse(302,{"Location":"http://127.0.0.1/"},b"{}")])
    transport = ImmediateVisitTransport(exchange=exchange)
    with pytest.raises(ImmediateVisitTransportError):
        transport.get_task(TASK)
    assert len(exchange.requests) == 1


def _assert_detached(error):
    assert error.__context__ is None
    assert error.__cause__ is None
    assert "private-auth-body-secret" not in repr(error)
    assert "secret-response" not in repr(error)
    assert not hasattr(error, "errors")


def test_malformed_json_and_throwing_exchange_detach_full_error_graph():
    for response in (ImmediateVisitRawResponse(200,{},b'{"private":"secret-response"'),
                     RuntimeError("secret-response")):
        exchange = Exchange([response])
        client = AgentImmediateVisitClient(transport=ImmediateVisitTransport(exchange=exchange))
        with pytest.raises(ImmediateVisitTransportError) as caught:
            client.get_task(TASK)
        _assert_detached(caught.value)


def test_invalid_claim_and_error_envelopes_detach_raw_input_graph():
    values = [raw(dict(claim_wire(),raw_body="secret-response")),
              raw(dict(schema_version="bad",code="not_found",message="secret-response",request_id="secret-response"),404)]
    for response in values:
        client = AgentImmediateVisitClient(transport=ImmediateVisitTransport(exchange=Exchange([response])))
        with pytest.raises(ImmediateVisitTransportError) as caught:
            client.claim_task(TASK,"agent",ADDRESS,idempotency_key="claim-one")
        _assert_detached(caught.value)


def test_transport_and_model_direct_validation_exceptions_are_detached():
    transport = ImmediateVisitTransport(exchange=Exchange([ImmediateVisitRawResponse(200,{},b'{"secret-response"')]))
    with pytest.raises(ImmediateVisitTransportError) as caught:
        transport.get_task(TASK)
    _assert_detached(caught.value)
    with pytest.raises(ValueError) as caught:
        ImmediateVisitClaimCredential.model_validate(dict(claim_wire(),claim_token="secret-response"))
    _assert_detached(caught.value)
    with pytest.raises(ValueError) as caught:
        FrozenImmediateVisitReport.from_bytes(b'{"secret-response"')
    _assert_detached(caught.value)


def test_abandon_auth_and_idempotency_preserve_finite_response_observation():
    exchange = Exchange([raw(abandonment_wire())])
    client = AgentImmediateVisitClient(transport=ImmediateVisitTransport(exchange=exchange))
    claim = ImmediateVisitClaimCredential.model_validate(claim_wire())
    result = client.abandon_claim(claim,idempotency_key="abandon-one")
    assert result.transport_state == "response_received" and "secret-response" not in repr(result)
    assert exchange.requests[0][0:2] == ("POST", "/api/agent/tasks/"+TASK+"/claim/abandon")
    assert exchange.requests[0][3]["X-LN-Task-Claim-Token"] == TOKEN
    assert exchange.requests[0][3]["Idempotency-Key"] == "abandon-one"
    assert json.loads(exchange.requests[0][4]) == dict(schema_version="ln_church.agent_task_abandon_request.immediate_visit.v1",execution_id=EXECUTION)


@pytest.mark.parametrize("change", [
    {"task_id":"task_"+"f"*32}, {"execution_id":"exec_"+"f"*32},
    {"schema_version":"ln_church.agent_task_abandon_response.v2"}, {"state":"paid_confirmed"},
    {"abandoned_at":"2026-09-14T00:00:01Z"}, {"abandoned_at":None}, {"private":TOKEN},
])
def test_unbound_or_malformed_abandonment_stays_unknown_without_new_request(change):
    exchange = Exchange([raw(dict(abandonment_wire(), **change))])
    client = AgentImmediateVisitClient(transport=ImmediateVisitTransport(exchange=exchange))
    claim = ImmediateVisitClaimCredential.model_validate(claim_wire())
    result = client.abandon_claim(claim, idempotency_key="abandon-one")
    assert result.transport_state == "unknown" and len(exchange.requests) == 1
    assert result.task_id == TASK and result.execution_id == EXECUTION
    assert TOKEN not in repr(result)


def test_unknown_abandonment_can_replay_same_request_without_synthetic_status():
    exchange = Exchange([ImmediateVisitTransportError("TIMEOUT", request_bytes_sent=True),
                         raw(abandonment_wire())])
    client = AgentImmediateVisitClient(transport=ImmediateVisitTransport(exchange=exchange))
    claim = ImmediateVisitClaimCredential.model_validate(claim_wire())
    assert client.abandon_claim(claim, idempotency_key="abandon-one").transport_state == "unknown"
    assert len(exchange.requests) == 1
    assert client.abandon_claim(claim, idempotency_key="abandon-one").transport_state == "response_received"
    assert exchange.requests[0][:5] == exchange.requests[1][:5]


def test_rejected_abandonment_preserves_accepted_report_and_status_recovery(tmp_path):
    client,claim,report,journal,exchange = fixture(tmp_path, [raw(receipt_wire(),202),
        error("report_already_accepted",409), raw(status_wire("base_approved","ambiguous"))])
    assert client.complete_task(claim,report,journal=journal).state == "accepted"
    rejected = client.abandon_claim(claim,idempotency_key="abandon-one")
    assert rejected.transport_state == "rejected" and rejected.error_code == "report_already_accepted"
    recovered = client.recover_completion(claim,report,journal=journal)
    assert recovered.status.payment_state == "ambiguous" and recovered.post_requests == 0
    assert journal.load_report(claim).canonical_bytes == report.canonical_bytes
    assert [r[0] for r in exchange.requests] == ["POST","POST","GET"]


@pytest.mark.parametrize("capacity", [50, 500, 5000])
def test_v17_capacity_snapshot_retained_and_claim_has_no_local_capacity_fence(capacity):
    from ln_church_agent.task_client import AgentTaskClient
    from test_v1_17_0_task_venue_sdk import _task, _claim_response, _FakeTransport
    # Deliberately noncoherent samples; SDK-A12 requires field-local retention.
    wire = _task(capacity_total=capacity, capacity_remaining=capacity+1,
                 active_execution_count=capacity+3, rewarded_execution_count=capacity+2,
                 reward_amount="10000", claimable=False)
    transport = _FakeTransport([wire,_claim_response(reward_amount="10000")])
    client = AgentTaskClient(_transport=transport)
    snapshot = client.get_task("task_example")
    assert snapshot.model_dump(mode="json") == wire
    assert snapshot.capacity_total == capacity and snapshot.reward.amount_atomic == "10000"
    claim = client.claim_task("task_example",agent_id="external-agent",reward_address=ADDRESS)
    assert claim.reward.amount_atomic == "10000"
    assert [call[0] for call in transport.calls] == ["GET","POST"]


def test_definitely_unaccepted_correction_reuses_one_target_get(tmp_path,monkeypatch):
    from types import SimpleNamespace
    import ln_church_agent.immediate_visit as executor_module
    from ln_church_agent.immediate_visit import ImmediateVisitExecutor
    target_calls = []
    def target(url):
        target_calls.append(url)
        return SimpleNamespace(status_code=404,headers=(("content-type","application/json"),),body=b'{"a":1}')
    monkeypatch.setattr(executor_module,"fetch_immediate_visit_once",target)
    claim = ImmediateVisitClaimCredential.model_validate(claim_wire())
    journal = ImmediateVisitJournal(tmp_path,claim)
    original = ImmediateVisitExecutor(journal=journal).execute(claim,ENDPOINT)
    exchange = Exchange([error("invalid_request",400)])
    client = AgentImmediateVisitClient(transport=ImmediateVisitTransport(exchange=exchange))
    assert client.complete_task(claim,original,journal=journal).state == "rejected"
    corrected_wire = original.report.model_dump(mode="json")
    corrected_wire["submission_id"] = "sub_"+"b"*32
    corrected = FrozenImmediateVisitReport.from_report(corrected_wire)
    journal.correct_unaccepted_report(claim,corrected)
    receipt = dict(receipt_wire(),submission_id=corrected.submission_id,report_sha256=corrected.report_sha256,
                   status_url=PUBLIC_API_ORIGIN+task_status_path(TASK,corrected.submission_id))
    accepted = Exchange([raw(receipt,202)])
    client._transport._exchange = accepted
    result = client.complete_task(claim,corrected,journal=journal)
    assert result.state == "accepted" and result.post_requests == 1 and result.status_requests == 0
    assert target_calls == [claim.endpoints[0].url]
    assert original.report.observation == corrected.report.observation
    assert ImmediateVisitExecutor(journal=journal).execute(claim,ENDPOINT).canonical_bytes == corrected.canonical_bytes
    assert len(target_calls) == 1


@pytest.mark.parametrize("value", ['{"claim_token":"secret-response"}', '{"claim_token":"secret-response"'])
def test_claim_json_parser_does_not_retain_validation_input(value):
    with pytest.raises(ValueError) as caught:
        ImmediateVisitClaimCredential.model_validate_json(value)
    _assert_detached(caught.value)
