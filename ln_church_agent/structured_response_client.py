"""Explicit v3 responder actions and finite recovery of the saved operation."""
from __future__ import annotations
from dataclasses import dataclass
import secrets
import time

from . import structured_response_contract as c
from .structured_response_models import (
    StructuredResponseTask,StructuredResponseTaskPage,StructuredResponseClaimCredential,
    StructuredResponseContext,FrozenStructuredResponseReport,StructuredResponseCompletionReceipt,
    StructuredResponseSubmissionStatus,StructuredResponseCompletionResult,
)
from .structured_response_journal import StructuredResponseJournal
from .structured_response_transport import StructuredResponseTransport,StructuredResponseError,StructuredResponseAPIError,public_boundary


def _model(cls,payload):
    invalid=False
    try:
        return cls.model_validate(payload)
    except Exception:
        invalid=True
    if invalid:
        raise StructuredResponseError('RESPONSE_INVALID',request_bytes_sent=True)


@dataclass(frozen=True)
class StructuredResponseClaim:
    claim: StructuredResponseClaimCredential
    journal: StructuredResponseJournal

    def model_dump(self,**kwargs):
        return dict(claim=self.claim.model_dump(),journal_handle=self.journal.handle)


class StructuredResponseClient:
    def __init__(self,*,transport=None,access_quota=None,monotonic=time.monotonic,sleep=time.sleep):
        if transport is not None and not isinstance(transport,StructuredResponseTransport):
            raise ValueError('Invalid structured response transport.')
        self._transport=transport or StructuredResponseTransport(access_quota=access_quota)
        self._owns_transport=transport is None
        self._clock=monotonic
        self._sleep=sleep
        self._closed=False

    def __enter__(self):
        self._open();return self

    def __exit__(self,*args):
        self.close()

    def close(self):
        self._closed=True
        if self._owns_transport:
            self._transport.close()

    def _open(self):
        if self._closed:
            raise StructuredResponseError('CLIENT_CLOSED',request_bytes_sent=False)

    def _journal(self,value):
        self._open()
        if not isinstance(value,StructuredResponseJournal):
            raise ValueError('Expected private structured response journal.')
        return value

    @public_boundary
    def list_tasks(self,limit=25,cursor=None,*,timeout_seconds=20.0):
        self._open()
        return _model(StructuredResponseTaskPage,self._transport.list_tasks(limit=limit,cursor=cursor,timeout_seconds=timeout_seconds))

    @public_boundary
    def get_task(self,task_id,*,timeout_seconds=20.0):
        self._open();c.validate_task_id(task_id)
        task=_model(StructuredResponseTask,self._transport.get_task(task_id,timeout_seconds=timeout_seconds))
        if task.task_id!=task_id:
            raise StructuredResponseError('RESPONSE_BINDING_INVALID',request_bytes_sent=True)
        return task

    @public_boundary
    def claim(self,task_id,agent_id,reward_address,idempotency_key,*,journal_directory,timeout_seconds=20.0):
        self._open()
        journal=StructuredResponseJournal(journal_directory,task_id=task_id,agent_id=agent_id,reward_address=reward_address,idempotency_key=idempotency_key)
        with journal.operation_guard():
            old=journal.load_claim()
            if old is not None:
                return StructuredResponseClaim(old,journal)
            task=journal.load_task()
            if task is None:
                task=self.get_task(task_id,timeout_seconds=timeout_seconds)
                if not task.supported:
                    raise StructuredResponseError('UNSUPPORTED_TUPLE',request_bytes_sent=False)
                journal.save_task(task)
            c.require_tuple(task.model_dump())
            task_id,key,body,started=journal.claim_request()
            journal.begin_claim()
            live_access=self._transport.access_quota.has_operation('POST',c.PUBLIC_API_ORIGIN+c.task_claim_path(task_id),
                {'Content-Type':'application/json','Idempotency-Key':key},body)
            operation=self._transport.recover_claim if started and not live_access else self._transport.claim_task
            try:
                claim=_model(StructuredResponseClaimCredential,operation(task_id,body,idempotency_key=key,timeout_seconds=timeout_seconds))
                return StructuredResponseClaim(journal.save_claim(claim),journal)
            except StructuredResponseAPIError:
                raise
            except StructuredResponseError as e:
                raise StructuredResponseError('CLAIM_OUTCOME_UNKNOWN',request_bytes_sent=e.request_bytes_sent,journal_handle=journal.handle) from None

    @public_boundary
    def recover_claim(self,*,journal,timeout_seconds=20.0):
        journal=self._journal(journal)
        with journal.operation_guard():
            old=journal.load_claim()
            if old is not None:
                return old
            task_id,key,body,_=journal.claim_request()
            journal.begin_claim()
            claim=_model(StructuredResponseClaimCredential,self._transport.recover_claim(task_id,body,idempotency_key=key,timeout_seconds=timeout_seconds))
            return journal.save_claim(claim)

    @public_boundary
    def get_context(self,*,journal,timeout_seconds=20.0):
        journal=self._journal(journal)
        claim=journal.load_claim();task=journal.load_task()
        if claim is None or task is None:
            raise ValueError('Missing saved Claim.')
        result=_model(StructuredResponseContext,self._transport.get_context(claim.task_id,claim._claim_token_value(),timeout_seconds=timeout_seconds))
        if result.task_id!=claim.task_id or result.execution_id!=claim.execution_id or result.context_id!=task.model_dump().get('context_id'):
            raise StructuredResponseError('RESPONSE_BINDING_INVALID',request_bytes_sent=True)
        return result

    @public_boundary
    def prepare_answer(self,*,journal,shared_assumptions,items,submission_id=None,correction=False):
        journal=self._journal(journal)
        with journal.operation_guard():
            task=journal.load_task();claim=journal.load_claim()
            if task is None or claim is None:
                raise ValueError('Missing saved Claim.')
            c.require_tuple(task.model_dump())
            answer=c.validate_answer(shared_assumptions,items,task.items)
            saved=journal.load_report()
            # Repeating an identical local preparation retains its original ID.
            if saved is not None and submission_id is None and not correction:
                submission_id=saved.report['submission_id']
            submission_id=submission_id or 'sub_'+secrets.token_hex(16)
            payload={k:getattr(claim,k) for k in ('task_id','task_type','task_definition_version','task_definition_digest','terms_digest','execution_id')}
            payload.update(schema_version=c.schema('task_completion'),submission_id=submission_id,
                context_id=task.model_dump().get('context_id'),**answer)
            return journal.prepare_report(FrozenStructuredResponseReport.from_report(payload),correction=correction)

    def _bound(self,cls,payload,claim,report):
        value=_model(cls,payload)
        if not value.matches(report) or c.parse_timestamp(value.received_at)>=c.parse_timestamp(claim.report_deadline):
            raise StructuredResponseError('RESPONSE_BINDING_INVALID',request_bytes_sent=True)
        return value

    def _status(self,claim,report,timeout_seconds):
        return self._bound(StructuredResponseSubmissionStatus,self._transport.get_submission_status(claim.task_id,
            report.report['submission_id'],claim._claim_token_value(),timeout_seconds=timeout_seconds),claim,report)

    @public_boundary
    def get_submission_status(self,*,journal,timeout_seconds=20.0):
        journal=self._journal(journal)
        with journal.operation_guard():
            claim=journal.load_claim();report=journal.load_report()
            if claim is None or report is None:
                raise ValueError('Missing saved answer binding.')
            value=self._status(claim,report,timeout_seconds)
            journal.record_result(StructuredResponseCompletionResult('accepted',status=value))
            return value

    @public_boundary
    def submit(self,*,journal,max_post_requests=3,timeout_seconds=90.0):
        return self._complete(journal,False,max_post_requests,timeout_seconds)

    @public_boundary
    def recover_completion(self,*,journal,max_post_requests=3,timeout_seconds=90.0):
        return self._complete(journal,True,max_post_requests,timeout_seconds)

    def _complete(self,journal,status_first,max_posts,timeout):
        journal=self._journal(journal)
        c.positive_bound(max_posts,'max_post_requests',integer=True,maximum=c.MAX_RECOVERY_POSTS)
        c.positive_bound(timeout,'timeout_seconds',maximum=c.MAX_RECOVERY_SECONDS)
        deadline=self._clock()+timeout
        posts=statuses=0
        result=StructuredResponseCompletionResult('unknown')
        def remaining():
            return min(20.0,deadline-self._clock())
        def pause(error):
            delay=error.retry_after_seconds or 0
            if delay>=deadline-self._clock() or delay>60:
                return False
            if delay:
                self._sleep(delay)
            return self._clock()<deadline
        with journal.operation_guard():
            task=journal.load_task();claim=journal.load_claim();report=journal.load_report()
            if task is None or claim is None or report is None:
                raise ValueError('Missing saved answer binding.')
            prior_unknown=journal.completion_started()
            need_status=status_first or prior_unknown
            while self._clock()<deadline:
                if need_status:
                    statuses+=1
                    try:
                        status=self._status(claim,report,remaining())
                        result=StructuredResponseCompletionResult('accepted',status=status,post_requests=posts,status_requests=statuses)
                        break
                    except StructuredResponseAPIError as e:
                        result=StructuredResponseCompletionResult('unknown',error_code=e.public_error_code,post_requests=posts,status_requests=statuses)
                        if journal.accepted() or e.status_code not in (404,429,503) or not pause(e):
                            break
                    except StructuredResponseError as e:
                        result=StructuredResponseCompletionResult('unknown',error_code=e.code,post_requests=posts,status_requests=statuses)
                        if journal.accepted():
                            break
                    need_status=False
                if posts>=max_posts or self._clock()>=deadline:
                    break
                # Mutation requires the fixed pack; read recovery remains possible after expiry.
                c.require_tuple(task.model_dump())
                journal.record_dispatch();posts+=1
                try:
                    payload=self._transport.post_completion_bytes(claim.task_id,claim._claim_token_value(),report.report['submission_id'],report.canonical_bytes,timeout_seconds=remaining())
                    receipt=self._bound(StructuredResponseCompletionReceipt,payload,claim,report)
                    result=StructuredResponseCompletionResult('accepted',receipt=receipt,post_requests=posts,status_requests=statuses)
                    break
                except StructuredResponseAPIError as e:
                    result=StructuredResponseCompletionResult('unknown' if prior_unknown else 'rejected',error_code=e.public_error_code,post_requests=posts,status_requests=statuses)
                    if e.status_code in (429,503):
                        prior_unknown=True
                        result=StructuredResponseCompletionResult('unknown',error_code=e.public_error_code,post_requests=posts,status_requests=statuses)
                        if pause(e):
                            need_status=True;continue
                    break
                except StructuredResponseError as e:
                    prior_unknown=prior_unknown or e.request_bytes_sent is not False
                    result=StructuredResponseCompletionResult('unknown',error_code=e.code,post_requests=posts,status_requests=statuses)
                    need_status=True
            journal.record_result(result,first_definite=not prior_unknown)
        return result

    @public_boundary
    def abandon(self,*,journal,idempotency_key,timeout_seconds=20.0):
        journal=self._journal(journal)
        with journal.operation_guard():
            claim=journal.load_claim()
            if claim is None:
                raise ValueError('Missing saved Claim.')
            key=journal.abandon_key(idempotency_key)
            body=c.canonical_bytes(dict(schema_version=c.schema('agent_task_abandon_request'),execution_id=claim.execution_id))
            value=self._transport.abandon_claim(claim.task_id,claim._claim_token_value(),body,idempotency_key=key,timeout_seconds=timeout_seconds)
            c.validate_wire('abandon_response', value)
            if (value.get('schema_version')!=c.schema('agent_task_abandon_response')
                    or value.get('task_id')!=claim.task_id or value.get('execution_id')!=claim.execution_id):
                raise StructuredResponseError('RESPONSE_BINDING_INVALID',request_bytes_sent=True)
            journal.record_abandoned()
            return value
