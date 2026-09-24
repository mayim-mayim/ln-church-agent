"""Durable per-Claim purchase fence and completion recovery budget."""
from __future__ import annotations

import hashlib
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from . import paid_service_trial_contract as c
from .paid_service_trial_models import (
    PaidServiceTrialClaim, FrozenPaidServiceTrialReport, parse_claim, model_for,
    PaidServiceTrialCompletionReceipt, PaidServiceTrialSubmissionStatus,
)
from .immediate_visit_journal import _read, _write, _private_boundary
from .task_journal import JournalError, _StableLock, _validate_journal_path

_SCHEMA = 'ln_church.paid_service_trial_journal.v1'
_STATES = {'CLAIMED','PREPARED','DISPATCH_RESERVED','OUTCOME_CAPTURED','REPORT_RESERVED','ACCEPTED','FINAL'}


class PaidServiceTrialJournal:
    """Keep one stable private directory for a Claim across every process.

    Claim credentials use a separate private file. The ordinary journal never
    stores a signature, signed payload, header or provider response body.
    """
    @_private_boundary
    def __init__(self, directory: Any, claim: PaidServiceTrialClaim) -> None:
        self._claim = parse_claim(claim)
        self._version = c.version_of(self._claim)
        self._binding = c.version_digest(dict(origin=c.PUBLIC_API_ORIGIN, claim=self._claim._private_payload()), self._version)
        self.path, self.credential_path = self._paths(directory, claim.task_id, claim.execution_id, version=self._version)
        self.lock_path = _validate_journal_path(str(self.path)+'.lock')
        self.operation_lock_path = _validate_journal_path(str(self.path)+'.operation.lock')
        with _StableLock(self.lock_path):
            saved = _read(self.path,missing=True)
            credential = _read(self.credential_path,missing=True)
            if saved is None:
                if credential is not None:
                    raise JournalError('JOURNAL_MISSING')
                saved = self._initial()
                _write(self.path,saved)
            self._validate(saved)
            if credential is None:
                if saved['state']!='CLAIMED':
                    raise JournalError('JOURNAL_MISSING')
                _write(self.credential_path,self._claim._private_payload())
            elif c.version_digest(credential,self._version)!=c.version_digest(self._claim._private_payload(),self._version):
                raise JournalError('JOURNAL_STATE_CONFLICT')

    def __repr__(self) -> str:
        return 'PaidServiceTrialJournal(<private>)'

    @staticmethod
    def _paths(directory: Any, task_id: str, execution_id: str, *, version: str='v1') -> Any:
        c.validate_task_id(task_id); c.validate_opaque_id(execution_id,'execution_id')
        key = c.digest([c.TASK_TYPE if c.validate_version(version)=='v1' else c.V2_TASK_TYPE,task_id,execution_id])
        root = Path(directory)
        return (_validate_journal_path(root/(key+'.json')),
                _validate_journal_path(root/(key+'.credential.json')))

    @classmethod
    @_private_boundary
    def load_claim(cls, directory: Any, task_id: str, execution_id: str) -> PaidServiceTrialClaim:
        # Read saved versions, never infer one from today's client default.
        matches = []
        for version in ('v1', 'v2'):
            path, credential = cls._paths(directory, task_id, execution_id, version=version)
            if path.exists() or credential.exists():
                with _StableLock(_validate_journal_path(str(path)+'.lock')):
                    claim = parse_claim(_read(credential))
                    data = _read(path)
                    if (c.version_of(claim) != version or claim.task_id != task_id
                            or claim.execution_id != execution_id
                            or data.get('claim_binding') != c.version_digest(dict(origin=c.PUBLIC_API_ORIGIN, claim=claim._private_payload()), version)):
                        raise JournalError('JOURNAL_STATE_CONFLICT')
                    matches.append(claim)
        if len(matches) != 1:
            raise JournalError('JOURNAL_MISSING' if not matches else 'JOURNAL_STATE_CONFLICT')
        # Full durable state validation is required even for credential recovery.
        cls(directory, matches[0]).snapshot()
        return matches[0]

    def _initial(self) -> dict:
        data = dict(schema_version=_SCHEMA if self._version=='v1' else 'ln_church.paid_service_trial_journal.v2', origin=c.PUBLIC_API_ORIGIN,
                    claim_binding=self._binding, operation_id=str(uuid.uuid4()),
                    state='CLAIMED', report=None, report_sha256=None, payload_digest=None,
                    paid_dispatch_reserved=False, http_outcome='NOT_OBSERVED', http_status=None,
                    transaction_hash=None, completion_attempts=0, result=None, rejection=None)
        if self._version=='v2':
            data['claim'] = self._claim.model_dump(mode='json')
        return data

    def _validate(self, data: dict) -> dict:
        if (set(data)!=set(self._initial()) or data['schema_version']!=self._initial()['schema_version']
                or (self._version=='v2' and data['claim']!=self._claim.model_dump(mode='json'))
                or data['origin']!=c.PUBLIC_API_ORIGIN or data['claim_binding']!=self._binding
                or data['state'] not in _STATES or str(uuid.UUID(data['operation_id'],version=4))!=data['operation_id']
                or type(data['paid_dispatch_reserved']) is not bool
                or type(data['completion_attempts']) is not int or not 0<=data['completion_attempts']<=3
                or data['http_outcome'] not in {'NOT_OBSERVED','RESPONSE_RECEIVED','FAILED','UNKNOWN'}
                or (data['http_status'] is not None and (type(data['http_status']) is not int or not 100<=data['http_status']<=599))
                or data['rejection'] not in {None,'report_conflict','idempotency_conflict','report_binding_invalid','claim_expired','claim_not_active','report_already_accepted'}):
            raise JournalError('JOURNAL_INVALID')
        if data['report'] is None:
            if data['state']!='CLAIMED' or data['paid_dispatch_reserved'] or any(data[k] is not None for k in ('report_sha256','payload_digest','transaction_hash','result')) or data['completion_attempts']:
                raise JournalError('JOURNAL_INVALID')
        else:
            report = FrozenPaidServiceTrialReport(data['report'].encode())
            report.model.require_claim(self._claim)
            c.validate_sha256(data['payload_digest'])
            if report.report_sha256!=data['report_sha256'] or report.model.transaction_hash is not None:
                raise JournalError('JOURNAL_INVALID')
            if data['state']=='CLAIMED' or (data['state'] not in {'PREPARED'} and not data['paid_dispatch_reserved']):
                raise JournalError('JOURNAL_INVALID')
            if data['transaction_hash'] is not None:
                c.hash32(data['transaction_hash'])
            if data['result'] is not None:
                result = self._result_model(data['result'])
                result.require_report(self._claim,report)
            elif data['state'] in {'ACCEPTED','FINAL'}:
                raise JournalError('JOURNAL_INVALID')
        return data

    def _result_model(self, value: dict) -> Any:
        surface = 'receipt' if value.get('schema_version') == 'ln_church.task_completion_receipt.paid_service_trial.'+self._version else 'status'
        return model_for(surface, self._version).model_validate(value)

    def _load(self) -> dict:
        data = self._validate(_read(self.path))
        if c.version_digest(_read(self.credential_path),self._version) != c.version_digest(self._claim._private_payload(),self._version):
            raise JournalError('JOURNAL_STATE_CONFLICT')
        return data

    @_private_boundary
    def require_binding(self,claim: PaidServiceTrialClaim) -> None:
        if c.version_digest(dict(origin=c.PUBLIC_API_ORIGIN,claim=parse_claim(claim)._private_payload()),self._version)!=self._binding:
            raise JournalError('JOURNAL_STATE_CONFLICT')
        with _StableLock(self.lock_path):
            self._load()

    @contextmanager
    def operation_guard(self) -> Any:
        with _StableLock(self.operation_lock_path):
            yield

    @_private_boundary
    def snapshot(self) -> dict:
        with _StableLock(self.lock_path):
            return self._load()

    @_private_boundary
    def _change(self, update: Any) -> dict:
        with _StableLock(self.lock_path):
            data=self._load();update(data);self._validate(data);_write(self.path,data)
            return data

    def load_report(self) -> Any:
        data=self.snapshot()
        if data['report'] is None:
            return None
        report=FrozenPaidServiceTrialReport(data['report'].encode())
        return report.supplement(data['transaction_hash']) if data['transaction_hash'] else report

    def prepare(self, report: FrozenPaidServiceTrialReport, payload_digest: str) -> None:
        report.model.require_claim(self._claim)
        core=report.model.wire();core.pop('transaction_hash',None)
        def update(data: dict) -> None:
            if data['report'] is not None:
                if data['report_sha256']!=report.report_sha256 or data['payload_digest']!=payload_digest:
                    raise JournalError('JOURNAL_STATE_CONFLICT')
                return
            data.update(state='PREPARED',report=c.version_bytes(core,self._version).decode(),
                        report_sha256=report.report_sha256,payload_digest=c.validate_sha256(payload_digest))
        self._change(update)

    def reserve_paid_dispatch(self) -> None:
        def update(data: dict) -> None:
            if data['state']!='PREPARED' or data['paid_dispatch_reserved']:
                raise JournalError('JOURNAL_STATE_CONFLICT')
            data.update(state='DISPATCH_RESERVED',paid_dispatch_reserved=True,http_outcome='UNKNOWN')
        self._change(update)

    def save_outcome(self, outcome: str, status: Any, transaction_hash: Any) -> None:
        def update(data: dict) -> None:
            if data['state']!='DISPATCH_RESERVED':
                raise JournalError('JOURNAL_STATE_CONFLICT')
            data.update(state='OUTCOME_CAPTURED',http_outcome=outcome,http_status=status,transaction_hash=transaction_hash)
        self._change(update)

    def require_report(self,report: FrozenPaidServiceTrialReport) -> dict:
        data=self.snapshot()
        if not data['paid_dispatch_reserved'] or data['report_sha256']!=report.report_sha256:
            raise JournalError('JOURNAL_STATE_CONFLICT')
        report.model.require_claim(self._claim)
        return data

    def reserve_report(self,report: FrozenPaidServiceTrialReport,*,explicit: bool=False) -> None:
        self.require_report(report)
        def update(data: dict) -> None:
            if data['rejection'] is not None:
                raise JournalError('JOURNAL_STATE_CONFLICT')
            if not explicit:
                if data['completion_attempts']>=3:
                    raise JournalError('JOURNAL_STATE_CONFLICT')
                data['completion_attempts']+=1
            if data['result'] is None:
                data['state']='REPORT_RESERVED'
        self._change(update)

    def save_result(self,result: Any,report: FrozenPaidServiceTrialReport) -> None:
        result.require_report(self._claim,report)
        def update(data: dict) -> None:
            if data['report_sha256']!=report.report_sha256:
                raise JournalError('JOURNAL_STATE_CONFLICT')
            old=data['result']
            if old and (old['received_at']!=result.received_at or old['verification_deadline']!=result.verification_deadline):
                raise JournalError('JOURNAL_STATE_CONFLICT')
            if data['state']=='FINAL':
                if isinstance(result,PaidServiceTrialCompletionReceipt):
                    return
                if old['evaluation']!=result.evaluation.model_dump(mode='json'):
                    raise JournalError('JOURNAL_STATE_CONFLICT')
            data['result']=result.model_dump(mode='json')
            data['state']='FINAL' if isinstance(result,PaidServiceTrialSubmissionStatus) and result.evaluation.state!='PENDING' else 'ACCEPTED'
            # Only save a replacement locator after a server-bound same-report
            # acknowledgement. A conflict keeps the first report/locator.
            if report.model.transaction_hash:
                data['transaction_hash']=report.model.transaction_hash
        self._change(update)

    def save_rejection(self,code: str) -> None:
        def update(data: dict) -> None:
            data['rejection']=code
        self._change(update)


class _ClaimRequest:
    """Private request/credential bridge before an execution ID is known."""
    @_private_boundary
    def __init__(self, directory: Any, version: str, task_id: str, key: str) -> None:
        self.version=c.validate_version(version)
        self.task_id=c.validate_task_id(task_id)
        self.key=c.validate_opaque_id(key,'idempotency_key')
        self.directory=Path(directory)
        self.directory.mkdir(mode=0o700,parents=True,exist_ok=True)
        name=c.digest([c.PUBLIC_API_ORIGIN,version,task_id,key])
        self.path=_validate_journal_path(self.directory/('claim-request-'+name+'.private.json'))
        self.lock_path=_validate_journal_path(str(self.path)+'.lock')

    def __repr__(self) -> str:
        return '_ClaimRequest(<private>)'

    def guard(self) -> Any:
        return _StableLock(self.lock_path)

    @_private_boundary
    def read(self, body: Any=None) -> dict:
        saved=_read(self.path,missing=body is not None)
        if saved is None:
            saved=dict(schema_version='ln_church.paid_service_trial_claim_request.local.v1',
                origin=c.PUBLIC_API_ORIGIN,version=self.version,task_id=self.task_id,
                idempotency_key=self.key,body=body.decode('utf-8'),state='NOT_SENT',claim=None,rejection=None)
            _write(self.path,saved)
        if (set(saved)!={'schema_version','origin','version','task_id','idempotency_key','body','state','claim','rejection'}
                or saved['schema_version']!='ln_church.paid_service_trial_claim_request.local.v1'
                or saved['origin']!=c.PUBLIC_API_ORIGIN or saved['version']!=self.version
                or saved['task_id']!=self.task_id or saved['idempotency_key']!=self.key
                or saved['state'] not in {'NOT_SENT','UNKNOWN','RECEIVED','READY','REJECTED'}):
            raise JournalError('JOURNAL_INVALID')
        raw=saved['body'].encode('utf-8')
        request=c.decode_json_object(raw,65536)
        expected=dict(schema_version='ln_church.agent_task_claim_request.v1',
            agent_id=c.validate_agent_id(request['agent_id']),reward_address=c.address(request['reward_address']))
        if raw!=c.canonical_bytes(expected) or (body is not None and body!=raw):
            raise JournalError('JOURNAL_STATE_CONFLICT')
        if saved['state'] in {'RECEIVED','READY'}:
            claim=parse_claim(saved['claim'])
            if (c.version_of(claim)!=self.version or claim.task_id!=self.task_id
                    or claim.reward_address!=expected['reward_address']):
                raise JournalError('JOURNAL_STATE_CONFLICT')
        elif saved['claim'] is not None:
            raise JournalError('JOURNAL_INVALID')
        if saved['state']=='REJECTED':
            error=saved['rejection']
            if (type(error) is not dict or set(error)!={'code','status'}
                    or type(error['status']) is not int or not 400<=error['status']<500
                    or error['code'] not in c.ERROR_CODES_BY_STATUS.get(error['status'],())):
                raise JournalError('JOURNAL_INVALID')
        elif saved['rejection'] is not None:
            raise JournalError('JOURNAL_INVALID')
        return saved

    @_private_boundary
    def save(self, saved: dict) -> None:
        _write(self.path,saved)
