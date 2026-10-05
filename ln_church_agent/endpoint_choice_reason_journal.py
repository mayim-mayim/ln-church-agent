"""Private durable Claim and answer binding, using the existing file/lock primitives."""
from __future__ import annotations
from pathlib import Path
from contextlib import contextmanager

from . import endpoint_choice_reason_contract as c
from .endpoint_choice_reason_models import EndpointChoiceClaimCredential, FrozenEndpointChoiceReport
from .immediate_visit_journal import _read, _write, _private_boundary
from .task_journal import _StableLock, _validate_journal_path, JournalError


class EndpointChoiceJournal:
    """One operation per task/key; callers create a private directory first.

    All processes handling this operation must use the same directory. The
    journal includes the original answer and credential and is never a public
    artifact or an AccessQuotaPolicy checkpoint.
    """
    @_private_boundary
    def __init__(self, directory, *, task_id, agent_id, reward_address, idempotency_key, version="v2"):
        self.version = c.validate_version(version)
        self.task_id = c.validate_task_id(task_id)
        self.key = c.validate_opaque_id(idempotency_key, 'idempotency_key')
        self._body = c.canonical_bytes(dict(schema_version='ln_church.agent_task_claim_request.v1',
                         agent_id=c.validate_agent_id(agent_id), reward_address=c.address(reward_address)))
        name = c.digest([self.task_id, self.key]) + '.endpoint-choice.json'
        self.path = _validate_journal_path(Path(directory) / name)
        self.lock_path = _validate_journal_path(str(self.path) + '.lock')
        self.operation_lock_path = _validate_journal_path(str(self.path) + '.operation.lock')
        with _StableLock(self.lock_path):
            data = _read(self.path, missing=True)
            if data is None:
                _write(self.path, self._initial())
            else:
                self._validate(data)

    def __repr__(self):
        return 'EndpointChoiceJournal(<private>)'

    def _initial(self):
        return dict(schema_version='ln_church.endpoint_choice_reason_journal.'+self.version, task_id=self.task_id,
                    claim_key=self.key, claim_body=self._body.decode(), claim_started=False,
                    credential=None, report=None, report_sha256=None, completion_started=False,
                    completion_unknown=False, accepted=False, rejection=None, abandon_key=None)

    def _validate(self, data):
        initial = self._initial()
        if set(data) != set(initial) or any(data[k] != initial[k] for k in ('schema_version', 'task_id', 'claim_key', 'claim_body')):
            raise JournalError('JOURNAL_STATE_CONFLICT')
        if any(type(data[k]) is not bool for k in ('claim_started', 'completion_started', 'completion_unknown', 'accepted')):
            raise JournalError('JOURNAL_INVALID')
        claim = None
        if data['credential'] is not None:
            claim = EndpointChoiceClaimCredential.model_validate(data['credential'])
            if c.version_of(claim) != self.version or claim.task_id != self.task_id or claim.reward_address != c.decode_json_object(self._body, c.MAX_REPORT_BYTES)['reward_address']:
                raise JournalError('JOURNAL_STATE_CONFLICT')
        if data['report'] is not None:
            if claim is None:
                raise JournalError('JOURNAL_INVALID')
            report = FrozenEndpointChoiceReport.from_bytes(data['report'].encode()).validate_claim(claim)
            if report.report_sha256 != data['report_sha256']:
                raise JournalError('JOURNAL_INVALID')
        elif data['report_sha256'] is not None or data['completion_started'] or data['completion_unknown'] or data['accepted']:
            raise JournalError('JOURNAL_INVALID')
        if data['rejection'] not in (None, 'invalid_request', 'report_binding_invalid'):
            raise JournalError('JOURNAL_INVALID')
        if data['abandon_key'] is not None:
            c.validate_opaque_id(data['abandon_key'], 'idempotency_key')
        return data

    def _load(self):
        return self._validate(_read(self.path))

    @contextmanager
    def operation_guard(self):
        with _StableLock(self.operation_lock_path):
            yield

    @_private_boundary
    def claim_request(self):
        with _StableLock(self.lock_path):
            d = self._load()
            return self.task_id, self.key, self._body, d['claim_started']

    @_private_boundary
    def begin_claim(self):
        with _StableLock(self.lock_path):
            d = self._load(); d['claim_started'] = True; _write(self.path, d)

    @_private_boundary
    def save_claim(self, value):
        claim = EndpointChoiceClaimCredential.model_validate(value)
        with _StableLock(self.lock_path):
            d = self._load()
            if c.version_of(claim) != self.version or claim.task_id != self.task_id or claim.reward_address != c.decode_json_object(self._body, c.MAX_REPORT_BYTES)['reward_address']:
                raise JournalError('JOURNAL_STATE_CONFLICT')
            if d['credential'] is not None and c.digest(d['credential']) != c.digest(claim._private_payload()):
                raise JournalError('JOURNAL_STATE_CONFLICT')
            d['credential'] = claim._private_payload(); _write(self.path, d)
        return claim

    @_private_boundary
    def load_claim(self):
        with _StableLock(self.lock_path):
            d = self._load()
            return None if d['credential'] is None else EndpointChoiceClaimCredential.model_validate(d['credential'])

    @_private_boundary
    def prepare_report(self, report, *, correction=False):
        with _StableLock(self.lock_path):
            d = self._load()
            if d['credential'] is None:
                raise JournalError('JOURNAL_STATE_CONFLICT')
            claim = EndpointChoiceClaimCredential.model_validate(d['credential'])
            report = FrozenEndpointChoiceReport.from_bytes(report.canonical_bytes).validate_claim(claim)
            if d['report'] is not None and d['report'].encode() != report.canonical_bytes:
                if not correction or d['accepted'] or d['completion_unknown'] or d['rejection'] not in ('invalid_request', 'report_binding_invalid'):
                    raise JournalError('JOURNAL_STATE_CONFLICT')
                d.update(completion_started=False, rejection=None)
            d.update(report=report.canonical_bytes.decode(), report_sha256=report.report_sha256)
            _write(self.path, d)
        return report

    @_private_boundary
    def load_report(self):
        with _StableLock(self.lock_path):
            d = self._load()
            return None if d['report'] is None else FrozenEndpointChoiceReport.from_bytes(d['report'].encode())

    @_private_boundary
    def completion_started(self):
        with _StableLock(self.lock_path):
            d = self._load()
            return d['completion_started'] or d['accepted'] or d['completion_unknown']

    @_private_boundary
    def record_dispatch(self):
        with _StableLock(self.lock_path):
            d = self._load()
            if d['report'] is None: raise JournalError('JOURNAL_STATE_CONFLICT')
            d.update(completion_started=True, completion_unknown=True, rejection=None)
            _write(self.path, d)

    @_private_boundary
    def record_result(self, result, *, first_definite=False):
        with _StableLock(self.lock_path):
            d = self._load()
            if result.state == 'accepted':
                d.update(accepted=True, rejection=None)
            elif result.state == 'rejected' and first_definite and not d['accepted']:
                d.update(completion_unknown=False, completion_started=False,
                         rejection=result.error_code if result.error_code in ('invalid_request', 'report_binding_invalid') else None)
            _write(self.path, d)

    @_private_boundary
    def abandon_key(self, key):
        key = c.validate_opaque_id(key, 'idempotency_key')
        with _StableLock(self.lock_path):
            d = self._load()
            if d['accepted'] or d['completion_unknown'] or (d['abandon_key'] is not None and d['abandon_key'] != key):
                raise JournalError('JOURNAL_STATE_CONFLICT')
            d['abandon_key'] = key; _write(self.path, d)
        return key
