import ast
import hashlib
from pathlib import Path

import pytest

import ln_church_agent
from ln_church_agent import task_contract
from ln_church_agent import task_transport
from ln_church_agent.task_client import AgentTaskClient
from ln_church_agent.task_models import AgentTask, TaskClaimCredential


ROOT = Path(__file__).resolve().parents[1]
V1_FIXTURE = ROOT / "tests/fixtures/agent-task-venue-contract-v1.json"
V1_FIXTURE_SHA256 = (
    "de12773c0a49dd65815f743bc3b579373874bb02b69b56116469908a40242dbe"
)


def _imported_modules(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.append(node.module or "")
    return tuple(modules)


def test_protected_v1_contract_fixture_and_modules_remain_isolated():
    assert hashlib.sha256(V1_FIXTURE.read_bytes()).hexdigest() == (
        V1_FIXTURE_SHA256
    )
    for relative in (
        "ln_church_agent/task_client.py",
        "ln_church_agent/task_contract.py",
        "ln_church_agent/task_models.py",
    ):
        imported = _imported_modules(ROOT / relative)
        assert not any("task_v2" in module for module in imported)
        assert not any("scheduled_http_get_batch" in module for module in imported)
        assert not any("task_journal" in module for module in imported)
        assert not any("network_fetch" in module for module in imported)


def test_v1_routes_schema_retry_and_error_sets_are_unchanged():
    assert task_contract.CONTRACT_ID == "ln_church.agent_task_venue.v1"
    assert task_contract.TASK_SCHEMA_VERSION == "ln_church.agent_task.v1"
    assert task_contract.ERROR_SCHEMA_VERSION == "ln_church.agent_task_error.v1"
    assert task_contract.TASK_TYPE_PAYMENT_SURFACE_DISCOVERY == (
        "payment_surface_discovery.v1"
    )
    assert task_contract.TASK_LIST_PATH == "/api/agent/tasks"
    assert task_contract.task_detail_path("task_1") == (
        "/api/agent/tasks/task_1"
    )
    assert task_contract.task_claim_path("task_1") == (
        "/api/agent/tasks/task_1/claim"
    )
    assert task_contract.task_observation_path("task_1") == (
        "/api/agent/tasks/task_1/domain-observations"
    )
    assert task_contract.task_completion_path("task_1") == (
        "/api/agent/tasks/task_1/completion"
    )
    assert task_contract.task_submission_status_path(
        "task_1", "sub_" + "0" * 32
    ) == (
        "/api/agent/tasks/task_1/submissions/"
        + "sub_"
        + "0" * 32
        + "/status"
    )
    assert task_contract.LIST_DETAIL_MAXIMUM_ATTEMPTS == 3
    assert task_contract.CLAIM_MAXIMUM_ATTEMPTS == 1
    assert task_contract.OBSERVATION_MAXIMUM_ATTEMPTS == 2
    assert task_contract.COMPLETION_MAXIMUM_ATTEMPTS == 2
    assert task_contract.RETRYABLE_HTTP_STATUSES == frozenset(
        {429, 502, 503, 504}
    )


def test_v1_transport_keeps_flat_error_envelope_and_legacy_codes():
    error = task_transport._validate_api_error(
        "claim",
        404,
        {
            "schema_version": "ln_church.agent_task_error.v1",
            "error_code": "task_not_found",
        },
        None,
    )
    assert type(error) is task_transport.TaskAPIError
    assert str(error) == "TASK_API_ERROR"
    assert error.public_error_code == "task_not_found"
    assert error.status_code == 404
    assert error.mutation_free is True

    with pytest.raises(task_transport.TaskTransportError) as caught:
        task_transport._validate_api_error(
            "claim",
            404,
            {
                "error": {
                    "schema_version": "ln_church.agent_task_error.v1",
                    "error_code": "task_not_found",
                }
            },
            None,
        )
    assert caught.value.code == "TASK_RESPONSE_INVALID"


def test_v1_public_exports_remain_available_with_original_owners():
    assert ln_church_agent.AgentTaskClient is AgentTaskClient
    assert ln_church_agent.AgentTask is AgentTask
    assert ln_church_agent.TaskClaimCredential is TaskClaimCredential
    assert ln_church_agent.TaskAPIError is task_transport.TaskAPIError
    assert ln_church_agent.TaskTransportError is (
        task_transport.TaskTransportError
    )
    for name in (
        "AgentTaskClient",
        "AgentTask",
        "TaskClaimCredential",
        "TaskAPIError",
        "TaskTransportError",
        "TaskAmbiguousOutcomeError",
    ):
        assert name in ln_church_agent.__all__


def test_v1_task_transport_identity_only_change_is_current_version():
    source = (ROOT / "ln_church_agent/task_transport.py").read_text(
        encoding="utf-8"
    )
    assert '"User-Agent": "ln-church-agent-task/1.18.0"' in source
    for protected in (
        '"claim": 1',
        '"observation": 2',
        '"completion": 2',
        '"claim": "CLAIM_OUTCOME_UNKNOWN"',
        '"observation": "SUBMISSION_OUTCOME_UNKNOWN"',
        '"completion": "COMPLETION_OUTCOME_UNKNOWN"',
    ):
        assert protected in source
