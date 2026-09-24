"""Explicit fourth-family Task client; status-first bounded same-report recovery."""
from __future__ import annotations

import time
from typing import Any

from . import paid_service_trial_contract as c
from .paid_service_trial_models import (
    PaidServiceTrialTask, PaidServiceTrialTaskPage, PaidServiceTrialClaim, model_for, parse_claim,
    PaidServiceTrialAbandonment, PaidServiceTrialCompletionReceipt,
    PaidServiceTrialSubmissionStatus, FrozenPaidServiceTrialReport,
)
from .paid_service_trial_transport import (
    PaidServiceTrialTransport, PaidServiceTrialError, PaidServiceTrialAPIError,
    PaidServiceTrialTransportError, _public_boundary,
)


class PaidServiceTrialTaskClient:
    def __init__(self, *, version: str='v2', transport: Any=None, monotonic: Any=time.monotonic) -> None:
        self.version=c.validate_version(version)
        self._transport=transport or PaidServiceTrialTransport(version=version)
        if isinstance(self._transport, PaidServiceTrialTransport) and self._transport.version!=version:
            raise ValueError('Incompatible Paid Service Trial transport version.')
        self._monotonic=monotonic

    def __enter__(self) -> Any:
        return self

    def close(self) -> None:
        self._transport.close()

    def __exit__(self,*args: Any) -> None:
        self.close()

    def _definition(self, value: Any) -> Any:
        bundle=c.load_contract_bundle(c.version_of(value))
        if value.task_definition_digest!=bundle['manifest']['task_definition_digest']:
            raise ValueError('Invalid Paid Service Trial Definition binding.')
        return value

    @_public_boundary
    def list_tasks(self,limit: int=25,cursor: Any=None) -> PaidServiceTrialTaskPage:
        c.positive_bound(limit,'limit',integer=True,maximum=50)
        page=model_for('page',self.version).model_validate(self._transport.list_tasks(limit=limit,cursor=cursor))
        if len(page.tasks)>limit:
            raise ValueError
        for task in page.tasks:self._definition(task)
        return page

    @_public_boundary
    def get_task(self,task_id: str) -> PaidServiceTrialTask:
        task=model_for('task',self.version).model_validate(self._transport.get_task(c.validate_task_id(task_id)))
        if task.task_id!=task_id:
            raise ValueError
        return self._definition(task)

    @_public_boundary
    def claim_task(self,task_id: str,agent_id: str,reward_address: str,*,idempotency_key: str) -> PaidServiceTrialClaim:
        c.validate_task_id(task_id);c.validate_opaque_id(idempotency_key,'idempotency_key')
        body=c.canonical_bytes(dict(schema_version='ln_church.agent_task_claim_request.v1',
                                    agent_id=c.validate_agent_id(agent_id),reward_address=c.address(reward_address)))
        claim=model_for('claim',self.version).model_validate(self._transport.claim_task(task_id,body,idempotency_key=idempotency_key))
        if claim.task_id!=task_id or claim.reward_address!=c.address(reward_address):
            raise ValueError
        return self._definition(claim)

    @_public_boundary
    def abandon_claim(self,claim: PaidServiceTrialClaim,*,idempotency_key: str) -> PaidServiceTrialAbandonment:
        claim=parse_claim(claim)
        body=c.canonical_bytes(dict(schema_version='ln_church.agent_task_abandon_request.paid_service_trial.'+c.version_of(claim),execution_id=claim.execution_id))
        result=model_for('abandon',c.version_of(claim)).model_validate(self._transport.abandon_claim(
            claim.task_id,claim._claim_token_value(),body,idempotency_key=c.validate_opaque_id(idempotency_key,'idempotency_key'),version=c.version_of(claim)))
        if result.task_id!=claim.task_id or result.execution_id!=claim.execution_id:
            raise ValueError
        return result

    @_public_boundary
    def get_submission_status(self,claim: PaidServiceTrialClaim,frozen_report: FrozenPaidServiceTrialReport,*,timeout_seconds: float=20.0) -> PaidServiceTrialSubmissionStatus:
        claim=parse_claim(claim);frozen_report.model.require_claim(claim)
        result=model_for('status',c.version_of(claim)).model_validate(self._transport.get_submission_status(
            claim.task_id,frozen_report.submission_id,claim._claim_token_value(),timeout_seconds=timeout_seconds,version=c.version_of(claim)))
        result.require_report(claim,frozen_report)
        return result

    def complete_task(self,claim: PaidServiceTrialClaim,frozen_report: FrozenPaidServiceTrialReport,*,journal: Any) -> Any:
        return self._complete(claim,frozen_report,journal=journal,explicit=False,supplement=False)

    def recover_completion(self,claim: PaidServiceTrialClaim,frozen_report: FrozenPaidServiceTrialReport,*,journal: Any) -> Any:
        return self._complete(claim,frozen_report,journal=journal,explicit=True,supplement=False)

    def supplement_transaction(self,claim: PaidServiceTrialClaim,frozen_report: FrozenPaidServiceTrialReport,transaction_hash: str,*,journal: Any) -> Any:
        return self._complete(claim,frozen_report.supplement(transaction_hash),journal=journal,explicit=True,supplement=True)

    @_public_boundary
    def _complete(self,claim: PaidServiceTrialClaim,report: FrozenPaidServiceTrialReport,*,journal: Any,explicit: bool,supplement: bool) -> Any:
        claim=parse_claim(claim)
        journal.require_binding(claim);journal.require_report(report)
        deadline=self._monotonic()+90.0
        with journal.operation_guard():
            data=journal.require_report(report)
            if data['rejection'] is not None and not explicit:
                raise PaidServiceTrialTransportError('REPORT_INVALID')
            # The original receipt/result survives expiry and never needs a
            # new Submission. Explicit recovery still makes one saved read.
            if data['result'] is not None and not explicit:
                return journal._result_model(data['result'])
            needs_status=explicit or data['completion_attempts']>0
            posts=0
            while self._monotonic()<deadline:
                data=journal.snapshot()
                if needs_status:
                    try:
                        status=self.get_submission_status(claim,report,timeout_seconds=min(20.0,deadline-self._monotonic()))
                        # Status validates the immutable core, but it does not
                        # acknowledge a new locator; retain the prior locator.
                        journal.save_result(status,journal.load_report())
                        if not supplement or status.evaluation.state!='PENDING':return status
                    except PaidServiceTrialAPIError as error:
                        if error.public_error_code!='not_found':raise
                    except PaidServiceTrialError:
                        raise PaidServiceTrialTransportError('COMPLETION_OUTCOME_UNKNOWN')
                if data['rejection'] is not None:
                    raise PaidServiceTrialTransportError('REPORT_INVALID')
                if explicit:
                    if posts>=1:break
                elif data['completion_attempts']>=3:break
                remaining=deadline-self._monotonic()
                if remaining<=0:break
                # Reserve before I/O: a crash consumes this client attempt.
                journal.reserve_report(report,explicit=explicit and data['completion_attempts']>=3)
                key=report.submission_id
                if report.model.transaction_hash:
                    key='tx_'+c.digest([report.submission_id,report.model.transaction_hash])
                try:
                    raw=self._transport.post_completion_bytes(claim.task_id,claim._claim_token_value(),
                            report.submission_id,report.to_bytes(),idempotency_key=key,timeout_seconds=min(20.0,remaining),version=c.version_of(claim))
                    result=model_for('receipt',c.version_of(claim)).model_validate(raw)
                    result.require_report(claim,report);journal.save_result(result,report)
                    return result
                except PaidServiceTrialAPIError as error:
                    if error.public_error_code in {'report_conflict','idempotency_conflict','report_binding_invalid','claim_expired','claim_not_active','report_already_accepted'}:
                        journal.save_rejection(error.public_error_code)
                        raise
                    if error.status_code!=503:raise
                except PaidServiceTrialError:
                    pass
                posts+=1;needs_status=True
            raise PaidServiceTrialTransportError('COMPLETION_OUTCOME_UNKNOWN')
