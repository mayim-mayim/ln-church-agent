"""Exact worker dispatch identities; unknown profiles remain read-only."""
from __future__ import annotations
from dataclasses import dataclass,field
import json

from .task_v2_contract import decode_json_object,validate_task_id
from .immediate_visit_profile import jcs_bytes

RESPONDER_TUPLES = (
    ('structured_response.v3','3.0.0','ln_church.agent_task.structured_response.v3'),
    ('endpoint_choice_reason.v2','2.1.0','ln_church.agent_task.endpoint_choice_reason.v2_1'),
    ('endpoint_choice_reason.v2','2.0.0','ln_church.agent_task.endpoint_choice_reason.v2'),
    ('endpoint_choice_reason.v1','1.0.0','ln_church.agent_task.endpoint_choice_reason.v1'),
)


def tuple_of(value):
    return tuple(value.get(k) for k in ('task_type','task_definition_version','schema_version'))


@dataclass(frozen=True)
class ReadOnlyTask:
    """A copied public wire projection; never a Claim/execution credential."""
    _bytes: bytes=field(repr=False)
    supported: bool=field(default=False,init=False)
    update_required: bool=field(default=True,init=False)

    @classmethod
    def from_payload(cls,payload):
        validate_task_id(payload['task_id'])
        from .structured_response_models import _public
        return cls(jcs_bytes(_public(payload)))

    def model_dump(self,**kwargs):
        return decode_json_object(self._bytes,4194304)

    def model_dump_json(self,**kwargs):
        return json.dumps(self.model_dump())

    @property
    def task_id(self):
        return self.model_dump()['task_id']
