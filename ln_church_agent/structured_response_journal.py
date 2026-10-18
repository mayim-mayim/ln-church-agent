"""Encrypted durable v3 binding over the existing private file/lock primitives."""
from __future__ import annotations
from contextlib import contextmanager
from pathlib import Path
import re

from . import structured_response_contract as c
from .structured_response_models import (
    StructuredResponseTask, StructuredResponseClaimCredential, FrozenStructuredResponseReport,
)
from .immediate_visit_journal import _read, _write, _private_boundary
from .task_journal import _StableLock, _validate_journal_path, JournalError
from ._structured_response_crypto import seal, unseal

MAX_JOURNAL_BYTES = 2 * 1024 * 1024


class StructuredResponseJournal:
    @_private_boundary
    def __init__(self, directory, *, task_id, agent_id, reward_address, idempotency_key):
        self.task_id = c.validate_task_id(task_id)
        self.key = c.validate_opaque_id(idempotency_key, 'idempotency_key')
        self._body = c.canonical_bytes(dict(schema_version='ln_church.agent_task_claim_request.v1',
            agent_id=c.validate_agent_id(agent_id), reward_address=c.address(reward_address)))
        self.handle = c.digest([self.task_id,self.key])
        self.path = _validate_journal_path(Path(directory)/(self.handle+'.structured-response.json'))
        self.lock_path = _validate_journal_path(str(self.path)+'.lock')
        self.operation_lock_path = _validate_journal_path(str(self.path)+'.operation.lock')
        with _StableLock(self.lock_path):
            d = _read(self.path, missing=True, maximum_bytes=MAX_JOURNAL_BYTES)
            if d is None:
                self._write(self._initial())
            else:
                d, legacy = unseal(d, self.handle, self.path)
                self._validate(d)
                if legacy:
                    self._write(d)

    def __repr__(self):
        return 'StructuredResponseJournal(<private>)'

    @classmethod
    @_private_boundary
    def open(cls, directory, handle):
        if type(handle) is not str or re.fullmatch(r'[0-9a-f]{64}',handle) is None:
            raise JournalError('JOURNAL_INVALID')
        path = _validate_journal_path(Path(directory)/(handle+'.structured-response.json'))
        with _StableLock(_validate_journal_path(str(path)+'.lock')):
            d = _read(path, maximum_bytes=MAX_JOURNAL_BYTES)
            d, _ = unseal(d, handle, path)
        body = c.decode_json_object(d['claim_body'].encode(),c.MAX_REPORT_BYTES)
        obj = cls(directory,task_id=d['task_id'],agent_id=body['agent_id'],
                  reward_address=body['reward_address'],idempotency_key=d['claim_key'])
        if obj.handle != handle:
            raise JournalError('JOURNAL_STATE_CONFLICT')
        return obj

    def _initial(self):
        return dict(schema_version='ln_church.structured_response_journal.v3',task_id=self.task_id,
            claim_key=self.key,claim_body=self._body.decode(),claim_started=False,task=None,
            credential=None,report=None,report_sha256=None,completion_started=False,
            completion_unknown=False,accepted=False,rejection=None,last_result=None,abandon_key=None,abandoned=False)

    def _write(self,d):
        _write(self.path,seal(d,self.handle,self.path),maximum_bytes=MAX_JOURNAL_BYTES)

    def _validate(self,d):
        initial = self._initial()
        if set(d) != set(initial) or any(d[k] != initial[k] for k in ('schema_version','task_id','claim_key','claim_body')):
            raise JournalError('JOURNAL_STATE_CONFLICT')
        if any(type(d[k]) is not bool for k in ('claim_started','completion_started','completion_unknown','accepted','abandoned')):
            raise JournalError('JOURNAL_INVALID')
        task = StructuredResponseTask(d['task']) if d['task'] is not None else None
        claim = StructuredResponseClaimCredential(d['credential']) if d['credential'] is not None else None
        if task is not None and task.task_id != self.task_id:
            raise JournalError('JOURNAL_STATE_CONFLICT')
        if claim is not None:
            if task is None or claim.task_id != self.task_id or c.address(claim.reward_address) != c.decode_json_object(self._body,c.MAX_REPORT_BYTES)['reward_address']:
                raise JournalError('JOURNAL_STATE_CONFLICT')
            for k in ('task_type','task_definition_version','task_definition_digest','terms_digest'):
                if getattr(claim,k) != getattr(task,k):
                    raise JournalError('JOURNAL_STATE_CONFLICT')
            claim_wire = claim.model_dump()
            if ('context_id' in claim_wire
                    and claim_wire['context_id'] != task.model_dump().get('context_id')):
                raise JournalError('JOURNAL_STATE_CONFLICT')
        if d['report'] is not None:
            if task is None or claim is None:
                raise JournalError('JOURNAL_INVALID')
            report = FrozenStructuredResponseReport.from_bytes(d['report'].encode()).validate_binding(task,claim)
            if report.report_sha256 != d['report_sha256']:
                raise JournalError('JOURNAL_INVALID')
        elif d['report_sha256'] is not None or d['completion_started'] or d['completion_unknown'] or d['accepted']:
            raise JournalError('JOURNAL_INVALID')
        if d['rejection'] not in (None,'invalid_request','invalid_structure'):
            raise JournalError('JOURNAL_INVALID')
        return d

    def _load(self):
        stored = _read(self.path,maximum_bytes=MAX_JOURNAL_BYTES)
        d, legacy = unseal(stored,self.handle,self.path)
        self._validate(d)
        if legacy:
            self._write(d)
        return d

    @contextmanager
    def operation_guard(self):
        with _StableLock(self.operation_lock_path):
            yield

    @_private_boundary
    def save_task(self,task):
        task = StructuredResponseTask.model_validate(task)
        c.require_tuple(task.model_dump())
        with _StableLock(self.lock_path):
            d = self._load()
            if task.task_id != self.task_id or d['task'] is not None and d['task'] != task.model_dump():
                raise JournalError('JOURNAL_STATE_CONFLICT')
            d['task'] = task.model_dump(); self._write(d)

    @_private_boundary
    def load_task(self):
        with _StableLock(self.lock_path):
            d = self._load()
            return StructuredResponseTask(d['task']) if d['task'] else None

    @_private_boundary
    def claim_request(self):
        with _StableLock(self.lock_path):
            d = self._load()
            return self.task_id,self.key,self._body,d['claim_started']

    @_private_boundary
    def begin_claim(self):
        with _StableLock(self.lock_path):
            d=self._load()
            if d['task'] is None or d['abandoned']:
                raise JournalError('JOURNAL_STATE_CONFLICT')
            d['claim_started']=True;self._write(d)

    @_private_boundary
    def save_claim(self,value):
        claim=StructuredResponseClaimCredential.model_validate(value)
        with _StableLock(self.lock_path):
            d=self._load()
            if d['credential'] is not None and d['credential'] != claim._private_payload():
                raise JournalError('JOURNAL_STATE_CONFLICT')
            d['credential']=claim._private_payload();self._validate(d);self._write(d)
        return claim

    @_private_boundary
    def load_claim(self):
        with _StableLock(self.lock_path):
            d=self._load()
            return StructuredResponseClaimCredential(d['credential']) if d['credential'] else None

    @_private_boundary
    def prepare_report(self,report,*,correction=False):
        with _StableLock(self.lock_path):
            d=self._load()
            if d['abandoned'] or d['task'] is None or d['credential'] is None:
                raise JournalError('JOURNAL_STATE_CONFLICT')
            report=FrozenStructuredResponseReport.from_bytes(report.canonical_bytes).validate_binding(
                StructuredResponseTask(d['task']),StructuredResponseClaimCredential(d['credential']))
            if d['report'] is not None and d['report'].encode()!=report.canonical_bytes:
                if (not correction or d['accepted'] or d['completion_unknown'] or d['rejection'] not in ('invalid_request','invalid_structure')
                        or report.report['submission_id']==FrozenStructuredResponseReport.from_bytes(d['report'].encode()).report['submission_id']):
                    raise JournalError('JOURNAL_STATE_CONFLICT')
                d.update(completion_started=False,rejection=None,last_result=None)
            d.update(report=report.canonical_bytes.decode(),report_sha256=report.report_sha256);self._write(d)
        return report

    @_private_boundary
    def load_report(self):
        with _StableLock(self.lock_path):
            d=self._load()
            return FrozenStructuredResponseReport.from_bytes(d['report'].encode()) if d['report'] else None

    @_private_boundary
    def completion_started(self):
        with _StableLock(self.lock_path):
            d=self._load()
            return d['completion_started'] or d['completion_unknown'] or d['accepted']

    @_private_boundary
    def accepted(self):
        with _StableLock(self.lock_path):
            return self._load()['accepted']

    @_private_boundary
    def record_dispatch(self):
        with _StableLock(self.lock_path):
            d=self._load()
            if d['report'] is None or d['abandoned']:
                raise JournalError('JOURNAL_STATE_CONFLICT')
            d.update(completion_started=True,completion_unknown=True,rejection=None);self._write(d)

    @_private_boundary
    def record_result(self,result,*,first_definite=False):
        with _StableLock(self.lock_path):
            d=self._load()
            if result.state=='accepted':
                d.update(accepted=True,rejection=None)
            elif result.state=='rejected' and first_definite and not d['accepted']:
                d.update(completion_unknown=False,completion_started=False,
                    rejection=result.error_code if result.error_code in ('invalid_request','invalid_structure') else None)
            d['last_result']=result.model_dump();self._write(d)

    @_private_boundary
    def abandon_key(self,key):
        key=c.validate_opaque_id(key,'idempotency_key')
        with _StableLock(self.lock_path):
            d=self._load()
            if d['accepted'] or d['completion_unknown'] or d['abandon_key'] is not None and d['abandon_key']!=key:
                raise JournalError('JOURNAL_STATE_CONFLICT')
            d['abandon_key']=key;self._write(d)
        return key

    @_private_boundary
    def record_abandoned(self):
        with _StableLock(self.lock_path):
            d=self._load();d['abandoned']=True;self._write(d)
