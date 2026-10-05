"""Finite new-family operations. Every mutation retains its original binding."""
from __future__ import annotations
import secrets
import time

from . import endpoint_choice_reason_contract as c
from .endpoint_choice_reason_models import (
    EndpointChoiceTask, EndpointChoiceTaskPage, EndpointChoiceClaimCredential,
    FrozenEndpointChoiceReport, EndpointChoiceCompletionReceipt, EndpointChoiceSubmissionStatus,
    EndpointChoicePublicResults, EndpointChoiceAbandonment, EndpointChoiceCompletionResult,
)
from .endpoint_choice_reason_journal import EndpointChoiceJournal
from .endpoint_choice_reason_transport import (
    EndpointChoiceTransport, EndpointChoiceError, EndpointChoiceAPIError, public_boundary,
)


def _model(cls, payload):
    try:
        return cls.model_validate(payload)
    except Exception:
        raise EndpointChoiceError('RESPONSE_INVALID', request_bytes_sent=True) from None


class AgentEndpointChoiceReasonClient:
    def __init__(self, *, version="v2", transport=None, access_quota=None, monotonic=time.monotonic):
        self.version = c.validate_version(version)
        if transport is not None and not isinstance(transport, EndpointChoiceTransport):
            raise ValueError('Invalid endpoint choice transport.')
        self._transport = transport or EndpointChoiceTransport(version=version, access_quota=access_quota)
        self._owns_transport = transport is None
        self._clock = monotonic
        self._closed = False

    def __enter__(self):
        self._open(); return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self._closed = True
        if self._owns_transport: self._transport.close()

    def _open(self):
        if self._closed: raise EndpointChoiceError('CLIENT_CLOSED', request_bytes_sent=False)

    def _journal(self, value):
        self._open()
        if not isinstance(value, EndpointChoiceJournal):
            raise ValueError('A private endpoint choice journal is required.')
        if value.version != self.version:
            raise ValueError("Client and saved journal versions differ.")
        return value

    @public_boundary
    def list_tasks(self, limit=25, cursor=None, *, timeout_seconds=20.0):
        self._open()
        page = _model(EndpointChoiceTaskPage, self._transport.list_tasks(limit=limit, cursor=cursor, timeout_seconds=timeout_seconds, version=self.version))
        if page.schema_version != c.schema('agent_task_page', self.version):
            raise EndpointChoiceError('RESPONSE_BINDING_INVALID', request_bytes_sent=True)
        return page

    @public_boundary
    def get_task(self, task_id, *, timeout_seconds=20.0):
        self._open(); c.validate_task_id(task_id)
        value = _model(EndpointChoiceTask, self._transport.get_task(task_id, timeout_seconds=timeout_seconds))
        if value.task_id != task_id: raise EndpointChoiceError('RESPONSE_BINDING_INVALID', request_bytes_sent=True)
        return value

    @public_boundary
    def claim_task(self, *, journal, timeout_seconds=20.0):
        journal = self._journal(journal)
        # No new-family mutation until the fixed definition is installed.
        c.load_contract_pack(journal.version)
        with journal.operation_guard():
            old = journal.load_claim()
            if old is not None: return old
            task_id, key, body, started = journal.claim_request()
            journal.begin_claim()
            # A live access operation still owns the original quota proof and
            # request. Normal re-entry continues that same operation. After
            # restart (or ordinary Claim transport loss), only the durable
            # Claim binding remains and recovery must be read-only.
            live_access = self._transport.access_quota.has_operation(
                'POST', c.PUBLIC_API_ORIGIN + c.task_claim_path(task_id),
                {'Content-Type': 'application/json', 'Idempotency-Key': key}, body)
            operation = (self._transport.recover_claim if started and not live_access
                         else self._transport.claim_task)
            try:
                claim = _model(EndpointChoiceClaimCredential, operation(task_id, body,
                        idempotency_key=key, timeout_seconds=timeout_seconds))
                return journal.save_claim(claim)
            except EndpointChoiceError as error:
                if isinstance(error, EndpointChoiceAPIError): raise
                raise EndpointChoiceError('CLAIM_OUTCOME_UNKNOWN', request_bytes_sent=error.request_bytes_sent) from None

    @public_boundary
    def recover_claim(self, *, journal, timeout_seconds=20.0):
        journal = self._journal(journal)
        with journal.operation_guard():
            task_id, key, body, _ = journal.claim_request()
            # This route can only read an existing binding, even if no local dispatch occurred.
            journal.begin_claim()
            claim = _model(EndpointChoiceClaimCredential, self._transport.recover_claim(task_id, body,
                        idempotency_key=key, timeout_seconds=timeout_seconds))
            return journal.save_claim(claim)

    @public_boundary
    def prepare_answer(self, *, journal, selected_candidate_id, answer_reason, submission_id=None, correction=False):
        journal = self._journal(journal)
        with journal.operation_guard():
            claim = journal.load_claim()
            if claim is None: raise ValueError('Missing saved Claim.')
            report = {k: getattr(claim, k) for k in ('task_id', 'task_type', 'task_definition_version',
                      'task_definition_digest', 'terms_digest', 'execution_id')}
            report.update(schema_version=c.schema('task_completion', c.version_of(claim)), submission_id=submission_id or 'sub_' + secrets.token_hex(16),
                          selected_candidate_id=selected_candidate_id, answer_reason=answer_reason)
            return journal.prepare_report(FrozenEndpointChoiceReport.from_report(report), correction=correction)

    @public_boundary
    def abandon_claim(self, *, journal, idempotency_key, timeout_seconds=20.0):
        journal = self._journal(journal)
        with journal.operation_guard():
            claim = journal.load_claim()
            if claim is None: raise ValueError('Missing saved Claim.')
            key = journal.abandon_key(idempotency_key)
            body = c.canonical_bytes(dict(schema_version=c.schema('agent_task_abandon_request', c.version_of(claim)), execution_id=claim.execution_id))
            result = _model(EndpointChoiceAbandonment, self._transport.abandon_claim(claim.task_id,
                claim._claim_token_value(), body, idempotency_key=key, timeout_seconds=timeout_seconds))
            if result.schema_version != c.schema('agent_task_abandon_response', c.version_of(claim)) or result.task_id != claim.task_id or result.execution_id != claim.execution_id:
                raise EndpointChoiceError('RESPONSE_BINDING_INVALID', request_bytes_sent=True)
            return result

    def _bound(self, cls, payload, claim, report):
        result = _model(cls, payload)
        if not result.matches(report) or c.parse_timestamp(result.received_at) >= c.parse_timestamp(claim.report_deadline):
            raise EndpointChoiceError('RESPONSE_BINDING_INVALID', request_bytes_sent=True)
        if isinstance(result, EndpointChoiceSubmissionStatus):
            original = report.report
            if result.selected_candidate_id != original.selected_candidate_id or result.answer_reason != original.answer_reason:
                raise EndpointChoiceError('RESPONSE_BINDING_INVALID', request_bytes_sent=True)
            if not claim.reveal_correct_set_after_answer and result.correct_candidate_ids is not None:
                raise EndpointChoiceError('RESPONSE_BINDING_INVALID', request_bytes_sent=True)
            if result.correct_candidate_ids is not None and not set(result.correct_candidate_ids) <= {x.candidate_id for x in claim.candidates}:
                raise EndpointChoiceError('RESPONSE_BINDING_INVALID', request_bytes_sent=True)
        return result

    def _status(self, claim, report, timeout_seconds):
        return self._bound(EndpointChoiceSubmissionStatus, self._transport.get_submission_status(
            claim.task_id, report.report.submission_id, claim._claim_token_value(), timeout_seconds=timeout_seconds), claim, report)

    @public_boundary
    def get_submission_status(self, *, journal, timeout_seconds=20.0):
        journal = self._journal(journal)
        claim, report = journal.load_claim(), journal.load_report()
        if claim is None or report is None: raise ValueError('Missing saved answer binding.')
        result = self._status(claim, report, timeout_seconds)
        journal.record_result(EndpointChoiceCompletionResult('accepted', status=result))
        return result

    @public_boundary
    def complete_task(self, *, journal, max_post_requests=3, timeout_seconds=90.0):
        return self._complete(journal, False, max_post_requests, timeout_seconds)

    @public_boundary
    def recover_completion(self, *, journal, max_post_requests=3, timeout_seconds=90.0):
        return self._complete(journal, True, max_post_requests, timeout_seconds)

    def _complete(self, journal, status_first, max_posts, timeout):
        journal = self._journal(journal)
        c.positive_bound(max_posts, 'max_post_requests', integer=True, maximum=3)
        c.positive_bound(timeout, 'timeout_seconds')
        deadline = self._clock() + timeout
        posts = statuses = 0
        result = EndpointChoiceCompletionResult('unknown')
        with journal.operation_guard():
            claim, report = journal.load_claim(), journal.load_report()
            if claim is None or report is None: raise ValueError('Missing saved answer binding.')
            prior_unknown = journal.completion_started()
            need_status = status_first or prior_unknown
            while self._clock() < deadline:
                if need_status:
                    statuses += 1
                    try:
                        status = self._status(claim, report, min(20, deadline - self._clock()))
                        result = EndpointChoiceCompletionResult('accepted', status=status, post_requests=posts, status_requests=statuses)
                        break
                    except EndpointChoiceAPIError as error:
                        result = EndpointChoiceCompletionResult('unknown', error_code=error.public_error_code, post_requests=posts, status_requests=statuses)
                        if error.status_code == 401: break
                    except EndpointChoiceError as error:
                        result = EndpointChoiceCompletionResult('unknown', error_code=error.code, post_requests=posts, status_requests=statuses)
                    # A miss does not authorize changing the saved body or ID.
                    need_status = False
                if posts >= max_posts or self._clock() >= deadline: break
                journal.record_dispatch()
                posts += 1
                try:
                    payload = self._transport.post_completion_bytes(claim.task_id, claim._claim_token_value(),
                        report.report.submission_id, report.canonical_bytes, timeout_seconds=min(20, deadline - self._clock()))
                    receipt = self._bound(EndpointChoiceCompletionReceipt, payload, claim, report)
                    result = EndpointChoiceCompletionResult('accepted', receipt=receipt, post_requests=posts, status_requests=statuses)
                    break
                except EndpointChoiceAPIError as error:
                    result = EndpointChoiceCompletionResult('unknown' if prior_unknown else 'rejected',
                        error_code=error.public_error_code, post_requests=posts, status_requests=statuses)
                    break
                except EndpointChoiceError as error:
                    prior_unknown = prior_unknown or error.request_bytes_sent is not False
                    result = EndpointChoiceCompletionResult('unknown', error_code=error.code, post_requests=posts, status_requests=statuses)
                    need_status = True
            journal.record_result(result, first_definite=not prior_unknown)
        return result

    @public_boundary
    def get_public_results(self, task_id, *, limit=20, cursor=None, timeout_seconds=20.0):
        self._open(); c.validate_task_id(task_id)
        result = _model(EndpointChoicePublicResults, self._transport.public_results(task_id, limit=limit,
                                                                                  cursor=cursor, timeout_seconds=timeout_seconds))
        if result.task_id != task_id: raise EndpointChoiceError('RESPONSE_BINDING_INVALID', request_bytes_sent=True)
        return result
