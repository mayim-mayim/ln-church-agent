"""Immutable responder views; credentials and original bytes remain private."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
import hashlib
import json

from . import structured_response_contract as c


def _public(value):
    if isinstance(value, dict):
        return {k: ('<redacted>' if any(s in k.lower() for s in
                ('token','authorization','secret','credential','private_key')) else _public(v))
                for k,v in value.items()}
    if isinstance(value, list):
        return [_public(v) for v in value]
    return value


class _View:
    __slots__ = ('_bytes',)

    def __init__(self, payload):
        failed = False
        try:
            owned = c.decode_json_object(c.canonical_bytes(payload, 4194304),4194304)
            self._validate(owned)
            object.__setattr__(self, '_bytes', c.canonical_bytes(owned,4194304))
        except Exception:
            failed = True
        if failed:
            raise ValueError('Invalid structured response wire value.')

    def __setattr__(self, key, value):
        raise TypeError('Immutable structured response view.')

    def __repr__(self):
        return type(self).__name__ + '(<redacted>)'

    def _validate(self, payload):
        pass

    @classmethod
    def model_validate(cls, payload):
        if isinstance(payload, cls):
            payload = payload._private_payload()
        return cls(payload)

    def _private_payload(self):
        return c.decode_json_object(self._bytes,4194304)

    def model_dump(self, **kwargs):
        return _public(self._private_payload())

    def model_dump_json(self, **kwargs):
        return json.dumps(self.model_dump(), ensure_ascii=False)

    def __getattr__(self, key):
        if key.startswith('_'):
            raise AttributeError(key)
        payload = self.model_dump()
        if key not in payload:
            raise AttributeError(key)
        return payload[key]


class StructuredResponseTask(_View):
    def _validate(self, p):
        c.validate_task_id(p['task_id'])
        for key in ('schema_version','task_type','task_definition_version'):
            c.text(p[key], 256, nonempty=True)
        c.validate_sha256(p['task_definition_digest'])
        if c.supported_tuple(p):
            c.validate_wire('task', p)
            c.validate_sha256(p['terms_digest'])
            c.validate_terms(p)
            c.validate_definition_items(p['items'])
            if p.get('context_id') is not None:
                c.validate_opaque_id(p['context_id'], 'context_id')
            c.validate_participation(p['participation'])
            if (p['capacity_total'] != p['capacity_reserved'] + p['capacity_quality_pending']
                    + p['capacity_consumed'] + p['capacity_available']
                    or p['capacity_compensated'] > p['capacity_consumed']):
                raise ValueError('Invalid structured response capacity snapshot.')

    @property
    def supported(self):
        return c.supported_tuple(self._private_payload())

    @property
    def update_required(self):
        return not self.supported

    def model_dump(self, **kwargs):
        # Preserve the read-only wire view; do not synthesize old-family fields.
        return super().model_dump(**kwargs)


class StructuredResponseTaskPage(_View):
    def _validate(self, p):
        if set(p) != {'schema_version', 'tasks', 'next_cursor'} or p['schema_version'] != c.schema('agent_task_page'):
            raise ValueError('Invalid discovery envelope.')
        if type(p.get('tasks')) is not list or len(p['tasks']) > 100:
            raise ValueError('Invalid discovery page.')
        for item in p['tasks']:
            StructuredResponseTask(item)
        c.cursor(p.get('next_cursor'))

    @property
    def tasks(self):
        return tuple(StructuredResponseTask(p) for p in self._private_payload()['tasks'])


class StructuredResponseClaimCredential(_View):
    def _validate(self, p):
        c.validate_wire('claim', p)
        if (p['schema_version'] != c.schema('agent_task_claim_response')
                or p['task_type'] != c.TASK_TYPE or p['task_definition_version'] != c.TASK_DEFINITION_VERSION):
            raise ValueError('Invalid Claim tuple.')
        c.validate_task_id(p['task_id']); c.execution_id(p['execution_id'])
        c.validate_sha256(p['task_definition_digest']); c.validate_sha256(p['terms_digest'])
        c.address(p['reward_address']); c.validate_claim_token(p['claim_token'])
        if p.get('context_id') is not None:
            c.validate_opaque_id(p['context_id'], 'context_id')
        if c.parse_timestamp(p['report_deadline']) - c.parse_timestamp(p['claim_accepted_at']) != timedelta(minutes=10):
            raise ValueError('Invalid Claim window.')
        if p.get('reward_address_control_verified') not in (None, False):
            raise ValueError('Claim is not wallet control authentication.')

    def model_dump(self, **kwargs):
        p = super().model_dump(**kwargs)
        p.pop('claim_token', None)
        return p

    def _claim_token_value(self):
        return self._private_payload()['claim_token']

    def __reduce_ex__(self, protocol):
        raise TypeError('Private credentials cannot be pickled.')

    def __getstate__(self):
        raise TypeError('Private credentials cannot be pickled.')


@dataclass(frozen=True, repr=False)
class FrozenStructuredResponseReport:
    canonical_bytes: bytes = field(repr=False)
    report_sha256: str

    def __repr__(self):
        return 'FrozenStructuredResponseReport(<private>, sha256=' + self.report_sha256 + ')'

    @property
    def report(self):
        return c.decode_json_object(self.canonical_bytes, c.MAX_REPORT_BYTES)

    @classmethod
    def from_report(cls, report):
        raw = c.canonical_bytes(report)
        return cls.from_bytes(raw)

    @classmethod
    def from_bytes(cls, raw):
        p = c.decode_json_object(raw, c.MAX_REPORT_BYTES)
        c.validate_wire('completion', p)
        fields = {'schema_version','task_id','task_type','task_definition_version','task_definition_digest',
                  'terms_digest','execution_id','submission_id','context_id','shared_assumptions','items'}
        if (set(p) != fields or p['schema_version'] != c.schema('task_completion')
                or p['task_type'] != c.TASK_TYPE or p['task_definition_version'] != c.TASK_DEFINITION_VERSION):
            raise ValueError('Invalid completion fields.')
        c.validate_task_id(p['task_id']); c.execution_id(p['execution_id'])
        c.validate_submission_id(p['submission_id'])
        c.validate_sha256(p['task_definition_digest']); c.validate_sha256(p['terms_digest'])
        if p['context_id'] is not None:
            c.validate_opaque_id(p['context_id'], 'context_id')
        canonical = c.canonical_bytes(p)
        if canonical != raw:
            raise ValueError('Expected canonical completion bytes.')
        return cls(canonical, hashlib.sha256(canonical).hexdigest())

    def validate_binding(self, task, claim):
        p = self.report
        for key in ('task_id','task_type','task_definition_version','task_definition_digest','terms_digest'):
            if p[key] != getattr(task,key) or p[key] != getattr(claim,key):
                raise ValueError('Answer binding mismatch.')
        if p['execution_id'] != claim.execution_id or p['context_id'] != task.model_dump().get('context_id'):
            raise ValueError('Answer context binding mismatch.')
        claim_wire = claim.model_dump()
        if 'context_id' in claim_wire and claim_wire['context_id'] != p['context_id']:
            raise ValueError('Answer Claim context binding mismatch.')
        answer = c.validate_answer(p['shared_assumptions'], p['items'], task.items)
        if answer['items'] != p['items']:
            raise ValueError('Answer item order mismatch.')
        return self


class StructuredResponseCompletionReceipt(_View):
    def _validate(self, p):
        c.validate_wire('receipt', p)
        fields = {'schema_version','task_id','execution_id','submission_id','report_sha256',
                  'received_at','evaluation_deadline','state'}
        if set(p) != fields or p['schema_version'] != c.schema('task_completion_receipt') or p['state'] != 'accepted':
            raise ValueError('Invalid completion receipt.')
        c.validate_task_id(p['task_id']); c.execution_id(p['execution_id'])
        c.validate_submission_id(p['submission_id']); c.validate_sha256(p['report_sha256'])
        if c.parse_timestamp(p['evaluation_deadline']) - c.parse_timestamp(p['received_at']) != timedelta(minutes=30):
            raise ValueError('Invalid evaluation deadline.')

    def matches(self, report):
        p = report.report
        return (all(getattr(self,k) == p[k] for k in ('task_id','execution_id','submission_id'))
                and self.report_sha256 == report.report_sha256)


class StructuredResponseSubmissionStatus(StructuredResponseCompletionReceipt):
    def _validate(self, p):
        c.validate_wire('status', p)
        receipt = {k:p[k] for k in ('task_id','execution_id','submission_id','report_sha256',
                                   'received_at','evaluation_deadline')}
        receipt['state'] = 'accepted'
        receipt['schema_version'] = c.schema('task_completion_receipt')
        super()._validate(receipt)
        if p['schema_version'] != c.schema('task_submission_status'):
            raise ValueError('Invalid status schema.')
        for field in ('quality','content','entitlement','payout'):
            if type(p[field]) is not dict or type(p[field].get('state')) is not str:
                raise ValueError('Missing independent status.')
        if type(p['analysis_eligible']) is not bool or p['analysis_exclusion_reason'] is not None and type(p['analysis_exclusion_reason']) is not str:
            raise ValueError('Invalid analysis eligibility.')
        amount = p['entitlement']['amount_atomic']
        if amount is not None and (type(amount) is not str or not amount.isascii() or not amount.isdecimal()):
            raise ValueError('Invalid atomic entitlement amount.')
        original = FrozenStructuredResponseReport.from_report(p['report'])
        if original.report_sha256 != p['report_sha256'] or original.report['context_id'] != p['context_id']:
            raise ValueError('Invalid original submission binding.')

    @property
    def state(self):
        # A bound status proves receipt; this is not an added wire field.
        return 'accepted'


class StructuredResponseContext(_View):
    def _validate(self, p):
        c.validate_wire('context', p)
        if p['schema_version'] != c.schema('task_context'):
            raise ValueError('Invalid context schema.')
        c.validate_task_id(p['task_id']); c.execution_id(p['execution_id'])
        if p['context_id'] is not None:
            c.validate_opaque_id(p['context_id'], 'context_id')


@dataclass(frozen=True)
class StructuredResponseCompletionResult:
    state: str
    receipt: object = None
    status: object = None
    error_code: str = None
    post_requests: int = 0
    status_requests: int = 0

    def model_dump(self, **kwargs):
        return dict(state=self.state, receipt=self.receipt.model_dump() if self.receipt else None,
                    status=self.status.model_dump() if self.status else None, error_code=self.error_code,
                    post_requests=self.post_requests,status_requests=self.status_requests)
