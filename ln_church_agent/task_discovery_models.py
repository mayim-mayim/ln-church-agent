"""Public, read-only discovery DTOs, separate from every execution model.

Oracle: Charter 87a1027f, Task Discovery specification c1 sections 2-3/6.
These observations neither reserve capacity nor authorize a Claim. Unknown
response fields are discarded rather than retained as private META or terms.
"""

import base64
import json
import re
from typing import Any, List, Literal, Optional
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .task_contract import (
    PUBLIC_API_ORIGIN,
    task_detail_path,
    validate_rfc3339_utc,
    validate_task_definition_digest,
    validate_task_id,
)


# Type / Definition -> (Task schema, original published Definition digest).
# Pins come from the existing immutable manifests, not a discovery response.
# Discovery does not load packs or rebuild digests from the public summary.
_TUPLES = {
    ('payment_surface_discovery.v1', '1.0.0'): (
        'ln_church.agent_task.v1',
        '9e5d340f746c957ac9e9363c0af8ef72f0fe2bc8ea4bc4b55d1f7006b5448406'),
    ('scheduled_http_get_batch.v1', '1.0.0'): (
        'ln_church.agent_task.v2',
        '24c90c221a111881cfcd455811b7de568c93f7be6950744f05423c42e3e4f22d'),
    ('immediate_http_visit.v1', '1.0.0'): (
        'ln_church.agent_task.immediate_visit.v1',
        '25996fb28b531a8892ef39c9e98899d94a31bef2628ddeb437b0e8fd673b6e43'),
    ('immediate_http_visit.v2', '2.0.0'): (
        'ln_church.agent_task.immediate_visit.v2',
        '3ef4d211aa66ef7972e5c4fd861d5afd83219759e2eaebf926694936bd5a532f'),
    ('immediate_http_visit.v3', '3.0.0'): (
        'ln_church.agent_task.immediate_visit.v3',
        '070780402e97d8b2840ecc91ce66bc42aa1ef529aebfbbb2a0ab7845f24b9a41'),
    ('paid_service_trial.v1', '1.0.0'): (
        'ln_church.agent_task.paid_service_trial.v1',
        'f9464a5b2ca01c38df971b74b3d855be7e0fc1dd2f09d8b526d5e74539c85095'),
    ('paid_service_trial.v2', '2.0.0'): (
        'ln_church.agent_task.paid_service_trial.v2',
        '08723b869949844b04319bd395ba5f6f91c1aa9155e710929f1dc4168895da14'),
    ('paid_service_trial.v3', '3.0.0'): (
        'ln_church.agent_task.paid_service_trial.v3',
        '5ada2a522eb7d3eb500c1e893c8e7387814882a334930d48ca5ae2bebdc2a6e5'),
    ('endpoint_choice_reason.v1', '1.0.0'): (
        'ln_church.agent_task.endpoint_choice_reason.v1',
        'a74586b704dd87eb819780481ad7347ce9fcdfdaa4684726da32e4e1ed9e1d93'),
    ('endpoint_choice_reason.v2', '2.0.0'): (
        'ln_church.agent_task.endpoint_choice_reason.v2',
        'c777eb006645196e9bbd1c6b6cf410f628a5580cb8e20ee32f2ae4f96afb8de7'),
    ('endpoint_choice_reason.v2', '2.1.0'): (
        'ln_church.agent_task.endpoint_choice_reason.v2_1',
        '4d7cb9d024ae41f60898146e4dbcd7ea3be63a33a9e8c0d01696192abe8f1b56'),
    ('structured_response.v3', '3.0.0'): (
        'ln_church.agent_task.structured_response.v3',
        '4d2b8f711b2273fba5215bbcfd767df1145d30a91ee9ea5711437e791616b274'),
}


def _bounded_json(value: Any, maximum: int) -> Any:
    if type(value) is not dict:
        raise ValueError("Invalid discovery object.")
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False,
                     separators=(",", ":")).encode("utf-8")
    if len(raw) > maximum:
        raise ValueError("Discovery object exceeds its bound.")
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Invalid discovery cursor.")
        result[key] = value
    return result


def _discovery_cursor(value: Any) -> str:
    """Validate the new namespace without turning it into an old cursor."""
    if (type(value) is not str or len(value) > 1024
            or re.fullmatch(r"td1\.[A-Za-z0-9_-]+", value) is None):
        raise ValueError("Invalid discovery cursor.")
    encoded = value[4:]
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != encoded:
        raise ValueError("Invalid discovery cursor.")
    payload = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object)
    if (type(payload) is not dict or set(payload) != {"generation", "after"}
            or payload["generation"] != "v1" or type(payload["after"]) is not str
            or json.dumps(payload, separators=(",", ":")).encode("ascii") != raw):
        raise ValueError("Invalid discovery cursor.")
    deadline, separator, task_id = payload["after"].partition("#")
    if separator != "#" or len(deadline) != 24:
        raise ValueError("Invalid discovery cursor.")
    validate_rfc3339_utc(deadline)
    validate_task_id(task_id)
    return value


def _discovery_query(limit: Any, cursor: Any) -> dict:
    if type(limit) is not int or not 1 <= limit <= 50:
        raise ValueError("Invalid discovery limit.")
    params = {"limit": limit}
    if cursor is not None:
        params["cursor"] = _discovery_cursor(cursor)
    return params


class _DiscoveryResponse(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore", frozen=True,
                              hide_input_in_errors=True)


class TaskDiscoveryCandidate(_DiscoveryResponse):
    """One public recruitment observation; use its official detail and Guide."""

    task_id: str
    task_type: str
    task_schema_version: str
    task_definition_version: str
    task_definition_digest: str
    title: str
    summary: str
    recruitment_state: Literal["candidate"]
    capacity_available: int = Field(gt=0)
    claim_before: str
    scheduled_at: Optional[str]
    eligibility: Literal["check_task_details"]
    detail_url: str
    definition_url: str
    projection_updated_at: str

    @model_validator(mode="before")
    @classmethod
    def _size(cls, value):
        return _bounded_json(value, 3072)

    @field_validator("task_id")
    @classmethod
    def _id(cls, value):
        return validate_task_id(value)

    @field_validator("task_definition_digest")
    @classmethod
    def _digest(cls, value):
        return validate_task_definition_digest(value)

    @field_validator("title", "summary")
    @classmethod
    def _short_text(cls, value):
        if len(value.encode("utf-8")) > 256:
            raise ValueError("Invalid discovery text length.")
        return value

    @field_validator("claim_before", "projection_updated_at", "scheduled_at")
    @classmethod
    def _time(cls, value):
        return None if value is None else validate_rfc3339_utc(value)

    @model_validator(mode="after")
    def _binding(self):
        if _TUPLES.get((self.task_type, self.task_definition_version)) != (
                self.task_schema_version, self.task_definition_digest):
            raise ValueError("Invalid discovery tuple.")
        scheduled = self.task_type == "scheduled_http_get_batch.v1"
        if scheduled != (self.scheduled_at is not None):
            raise ValueError("Invalid discovery execution schedule.")
        for value in (self.detail_url, self.definition_url):
            if (not value.startswith(PUBLIC_API_ORIGIN + "/") or "\\" in value
                    or any(ord(char) <= 32 or ord(char) == 127 for char in value)):
                raise ValueError("Invalid discovery link.")
        detail = urlsplit(self.detail_url)
        pairs = parse_qsl(detail.query, keep_blank_values=True, strict_parsing=True)
        selectors = {}
        if scheduled or self.task_type.startswith("paid_service_trial."):
            selectors = {"task_schema_version": self.task_schema_version}
        elif self.task_type.startswith(("endpoint_choice_reason.", "structured_response.")):
            selectors = {"task_type": self.task_type,
                         "task_schema_version": self.task_schema_version}
        if (detail.scheme != "https" or detail.netloc != "kari.mayim-mayim.com"
                or detail.path != task_detail_path(self.task_id) or detail.fragment
                or len(pairs) != len(selectors) or dict(pairs) != selectors):
            raise ValueError("Invalid discovery detail binding.")
        guide = (PUBLIC_API_ORIGIN + "/agent-task-specs/" + self.task_type
                 + "/" + self.task_definition_version + "/")
        if self.task_type == "payment_surface_discovery.v1":
            guide += self.task_definition_digest + "/"
        guide += "SKILL.md"
        if self.definition_url != guide:
            raise ValueError("Invalid discovery Guide binding.")
        return self


class TaskDiscoveryPage(_DiscoveryResponse):
    """One checked key range, with explicit continuation and empty semantics."""

    schema_version: Literal["ln_church.task_discovery_page.v1"]
    selection: Literal["recruiting_candidates"]
    coverage: Literal["all_supported_families"]
    checked_at: str
    page_scope: Literal["initial", "continuation"]
    tasks: List[TaskDiscoveryCandidate] = Field(max_length=50)
    next_cursor: Optional[str]
    empty_reason: Optional[Literal["no_candidates_observed_in_range"]]
    claim_authority: Literal["task_claim_endpoint"]

    @model_validator(mode="before")
    @classmethod
    def _size(cls, value):
        return _bounded_json(value, 160 * 1024)

    @field_validator("checked_at")
    @classmethod
    def _time(cls, value):
        return validate_rfc3339_utc(value)

    @field_validator("next_cursor")
    @classmethod
    def _cursor(cls, value):
        return None if value is None else _discovery_cursor(value)

    @model_validator(mode="after")
    def _range(self):
        if (not self.tasks) != (self.empty_reason == "no_candidates_observed_in_range"):
            raise ValueError("Invalid discovery empty range.")
        return self


__all__ = ["TaskDiscoveryCandidate", "TaskDiscoveryPage"]
