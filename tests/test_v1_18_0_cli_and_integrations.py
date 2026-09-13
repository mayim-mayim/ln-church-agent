import ast
from datetime import datetime, timezone
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import stat
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

import ln_church_agent
from ln_church_agent import cli
from ln_church_agent.scheduled_http_get_batch import ScheduledExecutionContext
from ln_church_agent.task_v2_models import (
    ScheduledTaskClaimCredential,
    ScheduledTaskReadiness,
)


ROOT = Path(__file__).resolve().parents[1]
CLAIM_TOKEN = "A" * 43
SIGNED_MANIFEST_URL = (
    "https://tasks-release.mayim-mayim.com/manifests/task_cli.json"
    "?Key-Pair-Id=SIGNED_QUERY_SENTINEL&Signature=SIGNED_VALUE_SENTINEL"
)


def _credential():
    return ScheduledTaskClaimCredential(
        task_id="task_cli_v2",
        task_definition_digest="a" * 64,
        agent_id="agent_cli",
        reward_address="0x0000000000000000000000000000000000000001",
        reward={
            "network": "eip155:8453",
            "asset": "USDC",
            "asset_address": (
                "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
            ),
            "amount_atomic": "10000",
        },
        claim_expires_at="2030-01-01T00:10:00Z",
        scheduled_at="2030-01-01T00:00:00Z",
        report_close_at="2030-01-01T00:10:00Z",
        manifest_url_not_before="2030-01-01T00:00:00Z",
        manifest_url_expires_at="2030-01-01T00:10:00Z",
        claim_token=CLAIM_TOKEN,
        manifest_url=SIGNED_MANIFEST_URL,
    )


def _readiness():
    return ScheduledTaskReadiness(
        task_id="task_cli_v2",
        offer_status="RUNNING",
        execution_available=True,
        release_state="READY",
        manifest_sha256="b" * 64,
        manifest_url_not_before="2030-01-01T00:00:00Z",
        manifest_url_expires_at="2030-01-01T00:10:00Z",
        new_target_start_before="2030-01-01T00:05:00Z",
        report_close_at="2030-01-01T00:10:00Z",
        manifest_url=SIGNED_MANIFEST_URL,
    )


def _write_private_credential(path, credential):
    path.write_text(
        json.dumps(
            credential._to_private_file_payload(),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    if os.name != "nt":
        os.chmod(path, 0o600)


def _manifest_fetch_started_journal(path, credential, *, fault_hook=None):
    from ln_church_agent.task_journal import TaskJournal

    credential_handle = credential.local_claim_credential_handle
    journal = TaskJournal(
        path,
        task_id=credential.task_id,
        local_claim_credential_handle=credential_handle,
        task_type=credential.task_type,
        task_definition_version=credential.task_definition_version,
        task_definition_digest=credential.task_definition_digest,
        fault_hook=fault_hook,
    )
    journal.create()
    journal.mark_offer_rechecked("b" * 64)
    journal.start_manifest_attempt()
    assert journal.load().state == "MANIFEST_FETCH_STARTED"
    return journal


def _forbid_scheduled_connector_io(monkeypatch, calls):
    from ln_church_agent.network_fetch import ControlledHTTPSConnector

    def fail_manifest(*args, **kwargs):
        calls["manifest"] += 1
        raise AssertionError("Manifest connector must not be called")

    def fail_target(*args, **kwargs):
        calls["target"] += 1
        raise AssertionError("target connector must not be called")

    monkeypatch.setattr(
        ControlledHTTPSConnector, "fetch_manifest", fail_manifest
    )
    monkeypatch.setattr(ControlledHTTPSConnector, "fetch_target", fail_target)


def _v2_raw_response(status, payload):
    from ln_church_agent.task_v2_transport import TaskV2RawResponse

    return TaskV2RawResponse(
        status_code=status,
        headers={"content-type": "application/json"},
        body=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    )


def _v2_receipt(credential, report_bytes):
    from ln_church_agent.task_v2_models import ScheduledCompletionReport

    report = ScheduledCompletionReport.model_validate_json(report_bytes)
    return {
        "schema_version": "ln_church.agent_task_completion_receipt.v2",
        "task_id": credential.task_id,
        "task_type": credential.task_type,
        "task_definition_version": credential.task_definition_version,
        "task_definition_digest": credential.task_definition_digest,
        "manifest_sha256": report.manifest_sha256,
        "submission_id": report.submission_id,
        "report_id": "report_cli_official",
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "completion_id": "completion_cli_official",
        "accepted_at": "2030-01-01T00:02:00Z",
        "receipt_state": "DURABLY_ACCEPTED",
        "evaluation_state": "PENDING",
    }


def _v2_status(credential, report_bytes, *, terminal=False):
    receipt = _v2_receipt(credential, report_bytes)
    evaluation = {"state": "PENDING", "reason": "STRUCTURALLY_VALID"}
    base_reward = {
        "entitlement_state": "DUE",
        "settlement_state": "CONFIRMING",
    }
    reference_bonus = {"candidate": True, "decision_state": "PENDING"}
    retry_after_seconds = 15
    if terminal:
        evaluation = {"state": "APPROVED", "reason": "STRUCTURALLY_VALID"}
        base_reward = {
            "entitlement_state": "TERMINAL",
            "settlement_state": "PAID_CONFIRMED",
        }
        reference_bonus = {"candidate": False, "decision_state": "NOT_AWARDED"}
        retry_after_seconds = 0
    return {
        "schema_version": "ln_church.agent_task_reward_status.v2",
        "task_id": receipt["task_id"],
        "task_type": receipt["task_type"],
        "task_definition_version": receipt["task_definition_version"],
        "task_definition_digest": receipt["task_definition_digest"],
        "manifest_sha256": receipt["manifest_sha256"],
        "submission_id": receipt["submission_id"],
        "report_id": receipt["report_id"],
        "report_sha256": receipt["report_sha256"],
        "accepted_at": receipt["accepted_at"],
        "receipt_state": "DURABLY_ACCEPTED",
        "evaluation": evaluation,
        "base_reward": base_reward,
        "reference_bonus": reference_bonus,
        "terminal": terminal,
        "retry_after_seconds": retry_after_seconds,
    }


def _real_v2_client_factory(exchange):
    from ln_church_agent.task_v2_client import AgentTaskV2Client
    from ln_church_agent.task_v2_transport import TaskV2Transport

    clients = []

    class InjectedTransportClient(AgentTaskV2Client):
        def __init__(self):
            super().__init__(
                transport=TaskV2Transport(exchange=exchange),
                utcnow=lambda: datetime(
                    2030, 1, 1, 0, 1, tzinfo=timezone.utc
                ),
            )
            clients.append(self)

    InjectedTransportClient.clients = clients
    return InjectedTransportClient


def _official_v2_invocation(
    official_path,
    credential,
    credential_path,
    journal_path,
    client_type,
    monkeypatch,
):
    if official_path == "cli":
        from ln_church_agent import task_v2_client

        monkeypatch.setattr(
            task_v2_client, "AgentTaskV2Client", client_type
        )
        monkeypatch.setattr(
            cli._task_sys,
            "argv",
            [
                "ln-church-agent",
                "task",
                "run-scheduled-http-get-batch",
                "--credential-file",
                str(credential_path),
                "--journal-file",
                str(journal_path),
                "--json",
            ],
        )
        return cli.main

    from examples import scheduled_http_get_batch as example

    monkeypatch.setattr(example, "AgentTaskV2Client", client_type)
    return lambda: example.run_claimed_batch(credential, journal_path)


def _invoke_official_v2_path(*args):
    return _official_v2_invocation(*args)()


def _freeze_interrupted_report(journal_path, credential):
    from ln_church_agent.task_v2_client import AgentTaskV2Client
    from ln_church_agent.task_v2_transport import TaskV2Transport

    journal = _manifest_fetch_started_journal(journal_path, credential)
    client = AgentTaskV2Client(
        transport=TaskV2Transport(
            exchange=lambda *args: pytest.fail(
                "interrupted freeze must be network-free"
            )
        ),
        utcnow=lambda: datetime(
            2030, 1, 1, 0, 1, tzinfo=timezone.utc
        ),
    )
    frozen = client.recover_interrupted_manifest_fetch(
        credential, journal=journal
    )
    assert journal.load().state == "REPORT_FROZEN"
    return journal, frozen


def _acknowledged_journal(journal_path, credential, *, terminal=False):
    from ln_church_agent.task_v2_models import (
        ScheduledCompletionAcknowledgement,
        ScheduledCompletionReceipt,
        ScheduledRewardStatus,
    )

    journal, frozen = _freeze_interrupted_report(journal_path, credential)
    journal.mark_completion_dispatch_attempted()
    journal.mark_compound_completion_acked(
        ScheduledCompletionAcknowledgement(
            source="receipt",
            receipt=ScheduledCompletionReceipt.model_validate(
                _v2_receipt(credential, frozen.exact_bytes)
            ),
        )
    )
    status_payload = _v2_status(
        credential, frozen.exact_bytes, terminal=terminal
    )
    if terminal:
        journal.mark_terminal_status(
            ScheduledRewardStatus.model_validate(status_payload)
        )
    return journal, frozen, status_payload


def _mcp_tool_names(source):
    tree = ast.parse(source)
    names = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and isinstance(decorator.func.value, ast.Name)
                and decorator.func.value.id == "mcp"
                and decorator.func.attr == "tool"
            ):
                names.append(node.name)
    return tuple(names)


def test_v18_public_exports_are_lazy_complete_and_owned_by_v18_modules():
    expected = {
        "AgentTaskV2Client",
        "ScheduledTaskClaimCredential",
        "ScheduledTaskReadiness",
        "ScheduledCompletionReport",
        "ScheduledCompletionReceipt",
        "ScheduledRewardStatus",
        "ScheduledCompletionAcknowledgement",
        "TaskV2Error",
        "TaskV2TransportError",
        "TaskV2APIError",
        "ClaimOutcomeUnknownError",
        "CompletionOutcomeUnknownError",
        "ScheduledExecutionContext",
        "FrozenCompletionReport",
        "ScheduledExecutionError",
        "ScheduledHTTPGetBatchExecutor",
        "ScheduledHttpGetBatchExecutor",
        "TaskJournal",
        "JournalError",
    }
    assert expected.issubset(set(ln_church_agent.__all__))
    for name in expected:
        value = getattr(ln_church_agent, name)
        assert value.__module__.startswith("ln_church_agent.")

    init_source = (ROOT / "ln_church_agent/__init__.py").read_text(
        encoding="utf-8"
    )
    assert "_V18_LAZY_EXPORTS" in init_source
    assert "def __getattr__(name):" in init_source
    tree = ast.parse(init_source)
    top_level_v2_imports = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            if any(
                token in node.module
                for token in ("task_v2", "scheduled_http_get_batch", "task_journal")
            ):
                top_level_v2_imports.append(node.module)
    assert top_level_v2_imports == []


def test_inspect_mcp_import_is_lazy_and_exposes_no_task_mutation_tools():
    source = (
        ROOT / "ln_church_agent/integrations/mcp_inspect.py"
    ).read_text(encoding="utf-8")
    assert _mcp_tool_names(source) == (
        "inspect_paid_surface",
        "explain_recommended_action",
        "build_mcp_observation_payload",
        "submit_mcp_observation",
    )
    for forbidden in (
        "AgentTaskV2Client",
        "ScheduledTaskClaimCredential",
        "ScheduledHTTPGetBatchExecutor",
        "TaskJournal",
        "claim_task",
        "X-LN-Task-Claim-Token",
    ):
        assert forbidden not in source

    script = (
        "import json,sys; "
        "import ln_church_agent.integrations.mcp_inspect; "
        "print(json.dumps(sorted(name for name in sys.modules "
        "if name.startswith('ln_church_agent.task_v2') "
        "or name in {'ln_church_agent.scheduled_http_get_batch',"
        "'ln_church_agent.task_journal','ln_church_agent.network_fetch'})))"
    )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT) + os.pathsep + environment.get(
        "PYTHONPATH", ""
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(ROOT),
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert json.loads(completed.stdout) == []


def test_claim_credential_readiness_and_context_never_serialize_secrets():
    credential = _credential()
    readiness = _readiness()
    context = ScheduledExecutionContext.from_credential_readiness(
        credential, readiness
    )
    public_values = (
        credential.model_dump(mode="json"),
        readiness.model_dump(mode="json"),
        repr(credential),
        repr(readiness),
        repr(context),
        str(context),
        cli._task_public_payload(credential),
        cli._task_public_payload(readiness),
    )
    rendered = json.dumps(public_values, default=str, ensure_ascii=False)
    assert CLAIM_TOKEN not in rendered
    assert SIGNED_MANIFEST_URL not in rendered
    assert "SIGNED_QUERY_SENTINEL" not in rendered
    assert context.local_claim_credential_handle == credential._local_fingerprint()
    assert context.execution_id.startswith("exec_")
    assert len(context.execution_id) == 37

    private_payload = credential._to_private_file_payload()
    assert private_payload["claim_token"] == CLAIM_TOKEN
    assert private_payload["manifest_url"] == SIGNED_MANIFEST_URL


def test_cli_has_additive_v2_commands_and_no_secret_arguments(
    monkeypatch, capsys
):
    for command, required in (
        (
            ["ln-church-agent", "task", "claim-v2", "--help"],
            (
                "--agent-id",
                "--reward-address",
                "--credential-file",
                "--journal-file",
            ),
        ),
        (
            [
                "ln-church-agent",
                "task",
                "run-scheduled-http-get-batch",
                "--help",
            ],
            ("--credential-file", "--journal-file"),
        ),
    ):
        monkeypatch.setattr(cli._task_sys, "argv", command)
        with pytest.raises(SystemExit) as caught:
            cli.main()
        assert caught.value.code == 0
        output = capsys.readouterr().out
        for option in required:
            assert option in output
        assert "--claim-token" not in output
        assert "--manifest-url" not in output
        assert "--signed-manifest-url" not in output

    monkeypatch.setattr(
        cli._task_sys,
        "argv",
        [
            "ln-church-agent",
            "task",
            "run-scheduled-http-get-batch",
            "--manifest-url=" + SIGNED_MANIFEST_URL,
        ],
    )
    with pytest.raises(SystemExit) as caught:
        cli.main()
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert "TASK_CREDENTIAL_INVALID" in captured.err
    assert SIGNED_MANIFEST_URL not in captured.out + captured.err
    assert "SIGNED_QUERY_SENTINEL" not in captured.out + captured.err


def test_claim_v2_cli_writes_only_private_file_and_prints_public_fields(
    tmp_path, monkeypatch, capsys
):
    credential = _credential()

    class FakeClient:
        def claim_task(self, task_id, *, agent_id, reward_address):
            assert task_id == credential.task_id
            assert agent_id == credential.agent_id
            assert reward_address == credential.reward_address
            return credential

        def close(self):
            return None

    from ln_church_agent import task_v2_client

    monkeypatch.setattr(task_v2_client, "AgentTaskV2Client", FakeClient)
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "claim-v2.journal"
    monkeypatch.setattr(
        cli._task_sys,
        "argv",
        [
            "ln-church-agent",
            "task",
            "claim-v2",
            credential.task_id,
            "--agent-id",
            credential.agent_id,
            "--reward-address",
            credential.reward_address,
            "--credential-file",
            str(credential_path),
            "--journal-file",
            str(journal_path),
            "--json",
        ],
    )
    cli.main()
    captured = capsys.readouterr()
    public = json.loads(captured.out)
    assert public["task_id"] == credential.task_id
    assert public["credential_file_written"] is True
    assert public["journal_initialized"] is True
    assert CLAIM_TOKEN not in captured.out + captured.err
    assert SIGNED_MANIFEST_URL not in captured.out + captured.err
    assert "claim_token" not in public
    assert "manifest_url" not in public

    stored = json.loads(credential_path.read_text(encoding="utf-8"))
    assert stored["claim_token"] == CLAIM_TOKEN
    assert stored["manifest_url"] == SIGNED_MANIFEST_URL
    journal = json.loads(journal_path.read_text(encoding="utf-8"))["payload"]
    assert journal["state"] == "INIT"
    assert journal["task_type"] == credential.task_type
    assert journal["task_definition_version"] == (
        credential.task_definition_version
    )
    assert journal["task_definition_digest"] == (
        credential.task_definition_digest
    )
    assert CLAIM_TOKEN not in json.dumps(journal)
    assert SIGNED_MANIFEST_URL not in json.dumps(journal)
    if os.name != "nt":
        assert stat.S_IMODE(credential_path.stat().st_mode) == 0o600


def test_claim_v2_local_credential_save_failure_never_resends_claim(
    tmp_path, monkeypatch, capsys
):
    credential = _credential()
    calls = {"claim": 0}

    class FakeClient:
        def claim_task(self, task_id, *, agent_id, reward_address):
            calls["claim"] += 1
            return credential

        def close(self):
            return None

    def fail_active_write(self, payload):
        del self, payload
        raise OSError("injected local credential failure")

    from ln_church_agent import task_v2_client

    monkeypatch.setattr(task_v2_client, "AgentTaskV2Client", FakeClient)
    monkeypatch.setattr(
        cli._TaskCredentialReservation, "write_payload", fail_active_write
    )
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "claim-v2.journal"
    monkeypatch.setattr(
        cli._task_sys,
        "argv",
        [
            "ln-church-agent",
            "task",
            "claim-v2",
            credential.task_id,
            "--agent-id",
            credential.agent_id,
            "--reward-address",
            credential.reward_address,
            "--credential-file",
            str(credential_path),
            "--journal-file",
            str(journal_path),
            "--json",
        ],
    )
    with pytest.raises(SystemExit) as caught:
        cli.main()
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Task error: TASK_CREDENTIAL_INVALID\n"
    assert calls == {"claim": 1}
    tombstone = json.loads(credential_path.read_text(encoding="utf-8"))
    assert tombstone["state"] == "CLAIM_OUTCOME_UNKNOWN"
    assert CLAIM_TOKEN not in json.dumps(tombstone)
    journal_payload = json.loads(
        journal_path.read_text(encoding="utf-8")
    )["payload"]
    assert journal_payload["state"] == "INIT"


def test_library_journal_initializer_is_network_free_and_create_once(
    tmp_path, monkeypatch
):
    credential = _credential()
    calls = {"client": 0}

    class ForbiddenClient:
        def __init__(self):
            calls["client"] += 1
            raise AssertionError("journal genesis must be network-free")

    from examples import scheduled_http_get_batch as example

    monkeypatch.setattr(example, "AgentTaskV2Client", ForbiddenClient)
    journal_path = tmp_path / "library.journal"
    journal = example.initialize_claim_journal(credential, journal_path)
    payload = journal.load().payload
    assert payload["state"] == "INIT"
    assert payload["task_definition_digest"] == (
        credential.task_definition_digest
    )
    assert CLAIM_TOKEN not in journal_path.read_text(encoding="utf-8")
    assert SIGNED_MANIFEST_URL not in journal_path.read_text(encoding="utf-8")
    with pytest.raises(Exception) as caught:
        example.initialize_claim_journal(credential, journal_path)
    assert getattr(caught.value, "code", None) == "JOURNAL_STATE_CONFLICT"
    assert calls == {"client": 0}


@pytest.mark.parametrize("official_path", ("cli", "example"))
def test_official_run_missing_journal_is_zero_network_and_never_recreated(
    tmp_path, monkeypatch, capsys, official_path
):
    credential = _credential()
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "lost.journal"
    _write_private_credential(credential_path, credential)
    calls = {
        "client": 0,
        "readiness": 0,
        "manifest": 0,
        "target": 0,
        "completion": 0,
        "status": 0,
    }
    _forbid_scheduled_connector_io(monkeypatch, calls)

    class ForbiddenClient:
        def __init__(self):
            calls["client"] += 1
            raise AssertionError("client must not exist without a journal")

    if official_path == "cli":
        from ln_church_agent import task_v2_client

        monkeypatch.setattr(
            task_v2_client, "AgentTaskV2Client", ForbiddenClient
        )
        monkeypatch.setattr(
            cli._task_sys,
            "argv",
            [
                "ln-church-agent",
                "task",
                "run-scheduled-http-get-batch",
                "--credential-file",
                str(credential_path),
                "--journal-file",
                str(journal_path),
                "--json",
            ],
        )
        with pytest.raises(SystemExit) as caught:
            cli.main()
        assert caught.value.code == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "Task error: JOURNAL_MISSING\n"
    else:
        from examples import scheduled_http_get_batch as example
        from ln_church_agent.task_journal import JournalError

        monkeypatch.setattr(example, "AgentTaskV2Client", ForbiddenClient)
        with pytest.raises(JournalError) as caught:
            example.run_claimed_batch(credential, journal_path)
        assert caught.value.code == "JOURNAL_MISSING"

    assert not journal_path.exists()
    assert calls == {
        "client": 0,
        "readiness": 0,
        "manifest": 0,
        "target": 0,
        "completion": 0,
        "status": 0,
    }


@pytest.mark.parametrize("official_path", ("cli", "example"))
def test_definition_tuple_mismatch_fails_before_any_network_io(
    tmp_path, monkeypatch, capsys, official_path
):
    original = _credential()
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "definition-bound.journal"
    from examples import scheduled_http_get_batch as example

    journal = example.initialize_claim_journal(original, journal_path)
    before = journal_path.read_bytes()
    changed_payload = original._to_private_file_payload()
    changed_payload["task_definition_digest"] = "d" * 64
    changed = ScheduledTaskClaimCredential._from_private_file_payload(
        changed_payload
    )
    assert changed.local_claim_credential_handle == (
        original.local_claim_credential_handle
    )
    _write_private_credential(credential_path, changed)
    calls = {"client": 0, "manifest": 0, "target": 0}
    _forbid_scheduled_connector_io(monkeypatch, calls)

    class ForbiddenClient:
        def __init__(self):
            calls["client"] += 1
            raise AssertionError("definition mismatch must precede client I/O")

    if official_path == "cli":
        from ln_church_agent import task_v2_client

        monkeypatch.setattr(
            task_v2_client, "AgentTaskV2Client", ForbiddenClient
        )
        monkeypatch.setattr(
            cli._task_sys,
            "argv",
            [
                "ln-church-agent",
                "task",
                "run-scheduled-http-get-batch",
                "--credential-file",
                str(credential_path),
                "--journal-file",
                str(journal_path),
                "--json",
            ],
        )
        with pytest.raises(SystemExit) as caught:
            cli.main()
        assert caught.value.code == 2
        assert capsys.readouterr().err == "Task error: JOURNAL_INVALID\n"
    else:
        monkeypatch.setattr(example, "AgentTaskV2Client", ForbiddenClient)
        from ln_church_agent.task_journal import JournalError

        with pytest.raises(JournalError) as caught:
            example.run_claimed_batch(changed, journal_path)
        assert caught.value.code == "JOURNAL_INVALID"

    assert journal_path.read_bytes() == before
    assert calls == {"client": 0, "manifest": 0, "target": 0}


@pytest.mark.parametrize("prebound_mismatch", (False, True))
def test_run_v2_cli_durably_binds_readiness_before_manifest_io(
    tmp_path, monkeypatch, capsys, prebound_mismatch
):
    credential = _credential()
    readiness = _readiness()
    credential_path = tmp_path / "claim-v2.json"
    credential_path.write_text(
        json.dumps(
            credential._to_private_file_payload(),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    if os.name != "nt":
        os.chmod(credential_path, 0o600)

    from ln_church_agent.task_journal import TaskJournal

    credential_handle = credential.local_claim_credential_handle
    journal_path = tmp_path / "journal.json"
    journal = TaskJournal(
        journal_path,
        task_id=credential.task_id,
        local_claim_credential_handle=credential_handle,
        task_type=credential.task_type,
        task_definition_version=credential.task_definition_version,
        task_definition_digest=credential.task_definition_digest,
    )
    journal.create()
    mismatch_digest = "c" * 64
    if prebound_mismatch:
        journal.mark_offer_rechecked(mismatch_digest)

    calls = []

    def exchange(method, path, query, headers, body):
        del query, headers
        if method == "GET":
            assert path == "/api/agent/tasks/task_cli_v2/readiness"
            calls.append("readiness")
            payload = readiness.model_dump(mode="json")
            payload["manifest_url"] = SIGNED_MANIFEST_URL
            return _v2_raw_response(
                200, payload
            )
        assert method == "POST"
        assert path == "/api/agent/tasks/task_cli_v2/completion"
        calls.append("completion")
        return _v2_raw_response(202, _v2_receipt(credential, bytes(body)))

    client_factory = _real_v2_client_factory(exchange)

    from ln_church_agent.scheduled_http_get_batch import (
        ScheduledHTTPGetBatchExecutor as RealExecutor,
    )
    from ln_church_agent.task_v2_models import ManifestFetchResult

    class FakeExecutor:
        def execute(self, context, *, journal):
            snapshot = journal.load()
            assert snapshot.state == "OFFER_RECHECKED"
            assert snapshot.payload["manifest_sha256"] == (
                readiness.manifest_sha256
            )
            assert context.manifest_sha256 == readiness.manifest_sha256
            calls.append("manifest_io")
            return RealExecutor(
                utcnow=lambda: datetime(
                    2030, 1, 1, 0, 1, 30, tzinfo=timezone.utc
                )
            )._freeze(
                context,
                journal,
                ManifestFetchResult(outcome="release_timeout"),
                [],
            )

    from ln_church_agent import scheduled_http_get_batch
    from ln_church_agent import task_v2_client

    monkeypatch.setattr(
        task_v2_client, "AgentTaskV2Client", client_factory
    )
    monkeypatch.setattr(
        scheduled_http_get_batch,
        "ScheduledHTTPGetBatchExecutor",
        FakeExecutor,
    )
    monkeypatch.setattr(
        cli._task_sys,
        "argv",
        [
            "ln-church-agent",
            "task",
            "run-scheduled-http-get-batch",
            "--credential-file",
            str(credential_path),
            "--journal-file",
            str(journal_path),
            "--json",
        ],
    )

    if prebound_mismatch:
        with pytest.raises(SystemExit) as caught:
            cli.main()
        assert caught.value.code == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "Task error: JOURNAL_STATE_CONFLICT\n"
        assert calls == ["readiness"]
        assert journal.load().payload["manifest_sha256"] == mismatch_digest
    else:
        cli.main()
        captured = capsys.readouterr()
        assert captured.err == ""
        assert json.loads(captured.out)["receipt"]["receipt_state"] == (
            "DURABLY_ACCEPTED"
        )
        assert calls == ["readiness", "manifest_io", "completion"]
        assert journal.load().state == "COMPOUND_COMPLETION_ACKED"
        assert journal.load().payload["manifest_sha256"] == (
            readiness.manifest_sha256
        )

    persisted = journal_path.read_text(encoding="utf-8")
    combined_output = captured.out + captured.err
    for secret in (
        CLAIM_TOKEN,
        SIGNED_MANIFEST_URL,
        "SIGNED_QUERY_SENTINEL",
        "SIGNED_VALUE_SENTINEL",
    ):
        assert secret not in persisted
        assert secret not in combined_output


@pytest.mark.parametrize("official_path", ("cli", "example"))
def test_official_paths_recover_manifest_fetch_started_without_rechecking_readiness(
    tmp_path, monkeypatch, capsys, official_path
):
    credential = _credential()
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "journal.json"
    _write_private_credential(credential_path, credential)
    journal = _manifest_fetch_started_journal(journal_path, credential)
    calls = {
        "readiness": 0,
        "manifest": 0,
        "target": 0,
        "completion": 0,
        "status": 0,
    }
    _forbid_scheduled_connector_io(monkeypatch, calls)

    def exchange(method, path, query, headers, body):
        del query, headers
        if method == "GET":
            if path.endswith("/readiness"):
                calls["readiness"] += 1
            else:
                calls["status"] += 1
            raise AssertionError("recovery must dispatch Completion directly")
        assert path == "/api/agent/tasks/task_cli_v2/completion"
        calls["completion"] += 1
        exact = journal.frozen_report_bytes()
        report = json.loads(exact)
        assert bytes(body) == exact
        assert journal.load().state == "REPORT_FROZEN"
        assert journal.load().payload["completion_dispatch_attempts"] == 1
        assert report["manifest_sha256"] == "b" * 64
        assert report["manifest_fetch"]["outcome"] == "release_interrupted"
        assert report["results"] == []
        return _v2_raw_response(202, _v2_receipt(credential, bytes(body)))

    client_factory = _real_v2_client_factory(exchange)

    if official_path == "cli":
        from ln_church_agent import task_v2_client

        monkeypatch.setattr(
            task_v2_client, "AgentTaskV2Client", client_factory
        )
        monkeypatch.setattr(
            cli._task_sys,
            "argv",
            [
                "ln-church-agent",
                "task",
                "run-scheduled-http-get-batch",
                "--credential-file",
                str(credential_path),
                "--journal-file",
                str(journal_path),
                "--json",
            ],
        )
        cli.main()
        captured = capsys.readouterr()
        assert captured.err == ""
        assert json.loads(captured.out)["receipt"]["receipt_state"] == (
            "DURABLY_ACCEPTED"
        )
    else:
        from examples import scheduled_http_get_batch as example

        monkeypatch.setattr(
            example, "AgentTaskV2Client", client_factory
        )
        result = example.run_claimed_batch(credential, journal_path)
        assert result.receipt.receipt_state == "DURABLY_ACCEPTED"

    snapshot = journal.load()
    report = json.loads(journal.frozen_report_bytes())
    assert snapshot.state == "COMPOUND_COMPLETION_ACKED"
    assert snapshot.payload["manifest_sha256"] == "b" * 64
    assert report["manifest_sha256"] == "b" * 64
    assert report["manifest_fetch"] == {
        "outcome": "release_interrupted",
    }
    assert report["results"] == []
    assert calls == {
        "readiness": 0,
        "manifest": 0,
        "target": 0,
        "completion": 1,
        "status": 0,
    }


@pytest.mark.parametrize("official_path", ("cli", "example"))
@pytest.mark.parametrize(
    "invalid_binding",
    (
        "task_mismatch",
        "credential_handle_mismatch",
        "execution_mismatch",
        "missing_digest",
        "null_digest",
        "corrupt_digest",
    ),
)
def test_official_manifest_fetch_started_recovery_rejects_invalid_binding_before_network(
    tmp_path, monkeypatch, capsys, official_path, invalid_binding
):
    credential = _credential()
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "journal.json"
    journal = _manifest_fetch_started_journal(journal_path, credential)
    supplied_credential = credential
    if invalid_binding in {"task_mismatch", "credential_handle_mismatch"}:
        payload = credential._to_private_file_payload()
        if invalid_binding == "task_mismatch":
            payload["task_id"] = "task_cli_v2_changed"
        else:
            payload["claim_token"] = "B" * 42 + "Q"
        supplied_credential = (
            ScheduledTaskClaimCredential._from_private_file_payload(payload)
        )
    else:
        from ln_church_agent.task_journal import _checksum

        envelope = json.loads(journal_path.read_text(encoding="utf-8"))
        if invalid_binding == "execution_mismatch":
            envelope["payload"]["execution_id"] = "exec_" + "9" * 32
        elif invalid_binding == "missing_digest":
            del envelope["payload"]["manifest_sha256"]
        elif invalid_binding == "null_digest":
            envelope["payload"]["manifest_sha256"] = None
        else:
            envelope["payload"]["manifest_sha256"] = "not-a-digest"
        envelope["checksum"] = _checksum(envelope["payload"])
        journal_path.write_text(
            json.dumps(envelope, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        if os.name != "nt":
            os.chmod(journal_path, 0o600)
    _write_private_credential(credential_path, supplied_credential)

    calls = {
        "readiness": 0,
        "manifest": 0,
        "target": 0,
        "completion": 0,
        "status": 0,
    }
    _forbid_scheduled_connector_io(monkeypatch, calls)

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

        def get_readiness(self, *args, **kwargs):
            calls["readiness"] += 1
            raise AssertionError("readiness must not be called")

        def recover_interrupted_manifest_fetch(self, *args, **kwargs):
            calls["manifest"] += 1
            raise AssertionError("invalid journal must fail during load")

        def get_submission_status(self, *args, **kwargs):
            calls["status"] += 1
            raise AssertionError("status must not be called")

        def close(self):
            return None

    if official_path == "cli":
        from ln_church_agent import task_v2_client

        monkeypatch.setattr(
            task_v2_client, "AgentTaskV2Client", FakeClient
        )
        monkeypatch.setattr(
            cli._task_sys,
            "argv",
            [
                "ln-church-agent",
                "task",
                "run-scheduled-http-get-batch",
                "--credential-file",
                str(credential_path),
                "--journal-file",
                str(journal_path),
                "--json",
            ],
        )
        with pytest.raises(SystemExit) as caught:
            cli.main()
        assert caught.value.code == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "Task error: JOURNAL_INVALID\n"
    else:
        from examples import scheduled_http_get_batch as example
        from ln_church_agent.task_journal import JournalError

        monkeypatch.setattr(example, "AgentTaskV2Client", FakeClient)
        with pytest.raises(JournalError) as caught:
            example.run_claimed_batch(supplied_credential, journal_path)
        assert caught.value.code == "JOURNAL_INVALID"

    assert calls == {
        "readiness": 0,
        "manifest": 0,
        "target": 0,
        "completion": 0,
        "status": 0,
    }


@pytest.mark.parametrize(
    "failure_mode",
    ("missing_digest", "null_digest", "corrupt_digest", "freeze_ambiguity"),
)
def test_client_interrupted_manifest_recovery_failures_are_zero_network(
    tmp_path, monkeypatch, failure_mode
):
    credential = _credential()
    journal_path = tmp_path / "journal.json"
    fail_writes = {"enabled": False}

    def fault_hook(stage):
        if fail_writes["enabled"] and stage == "before_temp_write":
            raise OSError("injected freeze ambiguity")

    journal = _manifest_fetch_started_journal(
        journal_path,
        credential,
        fault_hook=fault_hook if failure_mode == "freeze_ambiguity" else None,
    )
    if failure_mode == "freeze_ambiguity":
        fail_writes["enabled"] = True
    else:
        from ln_church_agent.task_journal import _checksum

        envelope = json.loads(journal_path.read_text(encoding="utf-8"))
        if failure_mode == "missing_digest":
            del envelope["payload"]["manifest_sha256"]
        elif failure_mode == "null_digest":
            envelope["payload"]["manifest_sha256"] = None
        else:
            envelope["payload"]["manifest_sha256"] = "not-a-digest"
        envelope["checksum"] = _checksum(envelope["payload"])
        journal_path.write_text(
            json.dumps(envelope, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        if os.name != "nt":
            os.chmod(journal_path, 0o600)

    calls = {
        "readiness": 0,
        "manifest": 0,
        "target": 0,
        "completion": 0,
        "status": 0,
    }
    _forbid_scheduled_connector_io(monkeypatch, calls)

    from ln_church_agent.task_v2_client import AgentTaskV2Client as RealClient

    class DirectClient(RealClient):
        def __init__(self):
            self._closed = False
            self._utcnow = lambda: datetime(
                2030, 1, 1, 0, 1, tzinfo=timezone.utc
            )

        def get_readiness(self, *args, **kwargs):
            calls["readiness"] += 1
            raise AssertionError("readiness must not be called")

        def get_submission_status(self, *args, **kwargs):
            calls["status"] += 1
            raise AssertionError("status must not be called")

    client = DirectClient()
    if failure_mode == "freeze_ambiguity":
        from ln_church_agent.scheduled_http_get_batch import (
            ScheduledExecutionError,
        )

        with pytest.raises(ScheduledExecutionError) as caught:
            client.recover_interrupted_manifest_fetch(
                credential, journal=journal
            )
        assert caught.value.code == (
            "EXECUTION_JOURNAL_PERSISTENCE_AMBIGUOUS"
        )
        fail_writes["enabled"] = False
        assert journal.load().state == "MANIFEST_FETCH_STARTED"
    else:
        from ln_church_agent.task_journal import JournalError

        with pytest.raises(JournalError) as caught:
            client.recover_interrupted_manifest_fetch(
                credential, journal=journal
            )
        assert caught.value.code == "JOURNAL_INVALID"

    assert calls == {
        "readiness": 0,
        "manifest": 0,
        "target": 0,
        "completion": 0,
        "status": 0,
    }


@pytest.mark.parametrize("official_path", ("cli", "example"))
def test_official_manifest_fetch_started_freeze_ambiguity_is_zero_network(
    tmp_path, monkeypatch, capsys, official_path
):
    credential = _credential()
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "journal.json"
    _write_private_credential(credential_path, credential)
    fail_writes = {"enabled": False}

    def fault_hook(stage):
        if fail_writes["enabled"] and stage == "before_temp_write":
            raise OSError("injected freeze ambiguity")

    journal = _manifest_fetch_started_journal(
        journal_path, credential, fault_hook=fault_hook
    )
    fail_writes["enabled"] = True
    calls = {
        "readiness": 0,
        "manifest": 0,
        "target": 0,
        "completion": 0,
        "status": 0,
    }
    _forbid_scheduled_connector_io(monkeypatch, calls)

    def exchange(method, path, query, headers, body):
        del query, headers, body
        if path.endswith("/readiness"):
            calls["readiness"] += 1
        elif path.endswith("/status"):
            calls["status"] += 1
        else:
            calls["completion"] += 1
        raise AssertionError("freeze ambiguity must precede all Venue I/O")

    client_type = _real_v2_client_factory(exchange)

    if official_path == "cli":
        from ln_church_agent import task_journal, task_v2_client

        def journal_factory(path, **binding):
            assert Path(path) == journal_path
            assert binding == {
                "task_id": journal.task_id,
                "local_claim_credential_handle": (
                    journal.local_claim_credential_handle
                ),
                "task_type": journal.task_type,
                "task_definition_version": (
                    journal.task_definition_version
                ),
                "task_definition_digest": journal.task_definition_digest,
            }
            return journal

        monkeypatch.setattr(task_journal, "TaskJournal", journal_factory)
        monkeypatch.setattr(
            task_v2_client, "AgentTaskV2Client", client_type
        )
        monkeypatch.setattr(
            cli._task_sys,
            "argv",
            [
                "ln-church-agent",
                "task",
                "run-scheduled-http-get-batch",
                "--credential-file",
                str(credential_path),
                "--journal-file",
                str(journal_path),
                "--json",
            ],
        )
        with pytest.raises(SystemExit) as caught:
            cli.main()
        assert caught.value.code == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == (
            "Task error: EXECUTION_JOURNAL_PERSISTENCE_AMBIGUOUS\n"
        )
    else:
        from examples import scheduled_http_get_batch as example
        from ln_church_agent.scheduled_http_get_batch import (
            ScheduledExecutionError,
        )

        monkeypatch.setattr(example, "AgentTaskV2Client", client_type)
        monkeypatch.setattr(example, "TaskJournal", lambda *args, **kwargs: journal)
        with pytest.raises(ScheduledExecutionError) as caught:
            example.run_claimed_batch(credential, journal_path)
        assert caught.value.code == (
            "EXECUTION_JOURNAL_PERSISTENCE_AMBIGUOUS"
        )

    fail_writes["enabled"] = False
    assert journal.load().state == "MANIFEST_FETCH_STARTED"
    assert calls == {
        "readiness": 0,
        "manifest": 0,
        "target": 0,
        "completion": 0,
        "status": 0,
    }


def test_run_v2_cli_frozen_without_dispatch_fact_posts_once_and_acks(
    tmp_path, monkeypatch, capsys
):
    credential = _credential()
    credential_path = tmp_path / "claim-v2.json"
    _write_private_credential(credential_path, credential)
    journal_path = tmp_path / "journal.json"
    journal = _manifest_fetch_started_journal(journal_path, credential)

    from ln_church_agent.task_v2_client import AgentTaskV2Client
    from ln_church_agent.task_v2_transport import TaskV2Transport

    pre_client = AgentTaskV2Client(
        transport=TaskV2Transport(
            exchange=lambda *args: pytest.fail("unexpected pre-freeze I/O")
        ),
        utcnow=lambda: datetime(
            2030, 1, 1, 0, 1, tzinfo=timezone.utc
        ),
    )
    frozen = pre_client.recover_interrupted_manifest_fetch(
        credential, journal=journal
    )
    assert journal.load().state == "REPORT_FROZEN"
    assert journal.load().payload["completion_dispatch_attempts"] == 0
    calls = []

    def exchange(method, path, query, headers, body):
        del query, headers
        calls.append((method, path, bytes(body)))
        assert method == "POST"
        assert bytes(body) == frozen.exact_bytes
        assert journal.load().payload["completion_dispatch_attempts"] == 1
        return _v2_raw_response(202, _v2_receipt(credential, bytes(body)))

    from ln_church_agent import task_v2_client

    monkeypatch.setattr(
        task_v2_client,
        "AgentTaskV2Client",
        _real_v2_client_factory(exchange),
    )
    monkeypatch.setattr(
        cli._task_sys,
        "argv",
        [
            "ln-church-agent",
            "task",
            "run-scheduled-http-get-batch",
            "--credential-file",
            str(credential_path),
            "--journal-file",
            str(journal_path),
            "--json",
        ],
    )
    cli.main()
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out)["receipt"]["receipt_state"] == (
        "DURABLY_ACCEPTED"
    )
    assert CLAIM_TOKEN not in captured.out
    assert SIGNED_MANIFEST_URL not in captured.out
    assert [item[0] for item in calls] == ["POST"]
    assert journal.load().state == "COMPOUND_COMPLETION_ACKED"


@pytest.mark.parametrize("official_path", ("cli", "example"))
@pytest.mark.parametrize("initial_state", ("acked", "terminal"))
def test_official_post_ack_paths_require_recover_completion(
    tmp_path, monkeypatch, capsys, official_path, initial_state
):
    credential = _credential()
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "journal.json"
    _write_private_credential(credential_path, credential)
    journal, frozen, status_payload = _acknowledged_journal(
        journal_path,
        credential,
        terminal=initial_state == "terminal",
    )
    calls = []

    from ln_church_agent.task_v2_models import (
        ScheduledCompletionAcknowledgement,
        ScheduledRewardStatus,
    )

    status = ScheduledRewardStatus.model_validate(status_payload)

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            self.close()

        def recover_completion(
            self, supplied_credential, report, *, journal
        ):
            assert supplied_credential is credential or (
                supplied_credential.task_id == credential.task_id
            )
            assert report.model_dump(mode="json") == json.loads(
                frozen.exact_bytes
            )
            assert journal.frozen_report_bytes() == frozen.exact_bytes
            assert journal.load().state == (
                "TERMINAL_STATUS"
                if initial_state == "terminal"
                else "COMPOUND_COMPLETION_ACKED"
            )
            calls.append("recover_completion")
            return ScheduledCompletionAcknowledgement(
                source="status", status=status
            )

        def get_submission_status(self, *args, **kwargs):
            raise AssertionError("official path bypassed Completion guard")

        def complete_task(self, *args, **kwargs):
            raise AssertionError("post-ACK must use explicit recovery")

        def close(self):
            calls.append("close")

    result = _invoke_official_v2_path(
        official_path,
        credential,
        credential_path,
        journal_path,
        FakeClient,
        monkeypatch,
    )
    if official_path == "cli":
        rendered = json.loads(capsys.readouterr().out)
        assert rendered == status.model_dump(mode="json")
    else:
        assert result == status
    assert calls == ["recover_completion", "close"]


@pytest.mark.parametrize("official_path", ("cli", "example"))
def test_official_post_ack_paths_reject_non_status_acknowledgement(
    tmp_path, monkeypatch, capsys, official_path
):
    credential = _credential()
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "journal.json"
    _write_private_credential(credential_path, credential)
    _journal, frozen, _status_payload = _acknowledged_journal(
        journal_path, credential
    )

    from ln_church_agent.task_v2_models import (
        ScheduledCompletionAcknowledgement,
        ScheduledCompletionReceipt,
    )

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return None

        def recover_completion(self, credential, report, *, journal):
            return ScheduledCompletionAcknowledgement(
                source="receipt",
                receipt=ScheduledCompletionReceipt.model_validate(
                    _v2_receipt(credential, frozen.exact_bytes)
                ),
            )

        def get_submission_status(self, *args, **kwargs):
            raise AssertionError("official path bypassed Completion guard")

        def close(self):
            return None

    if official_path == "cli":
        with pytest.raises(SystemExit) as caught:
            _invoke_official_v2_path(
                official_path,
                credential,
                credential_path,
                journal_path,
                FakeClient,
                monkeypatch,
            )
        assert caught.value.code == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "Task error: TASK_V2_RESPONSE_INVALID\n"
    else:
        with pytest.raises(
            RuntimeError, match="^Submission status binding changed\\.$"
        ):
            _invoke_official_v2_path(
                official_path,
                credential,
                credential_path,
                journal_path,
                FakeClient,
                monkeypatch,
            )


def test_fixture_forbids_a_separate_top_level_completion_dispatch_state():
    fixture = json.loads(
        (
            ROOT
            / "ln_church_agent/contracts/"
            "v18-scheduled-http-get-batch-contract-v1.json"
        ).read_text(encoding="utf-8")
    )
    assert fixture["sdk"]["separate_report_and_completion_ack_states"] is False


@pytest.mark.parametrize("official_path", ("cli", "example"))
def test_official_real_client_fresh_execution_freezes_then_posts_once(
    tmp_path, monkeypatch, capsys, official_path
):
    credential = _credential()
    readiness = _readiness()
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "journal.json"
    _write_private_credential(credential_path, credential)

    from ln_church_agent.task_journal import TaskJournal
    from ln_church_agent.scheduled_http_get_batch import (
        ScheduledHTTPGetBatchExecutor as RealExecutor,
    )
    from ln_church_agent.task_v2_models import ManifestFetchResult

    journal = TaskJournal(
        journal_path,
        task_id=credential.task_id,
        local_claim_credential_handle=(
            credential.local_claim_credential_handle
        ),
        task_type=credential.task_type,
        task_definition_version=credential.task_definition_version,
        task_definition_digest=credential.task_definition_digest,
    )
    journal.create()
    calls = []

    def exchange(method, path, query, headers, body):
        del query, headers
        calls.append((method, path, bytes(body)))
        if path.endswith("/readiness"):
            assert method == "GET"
            payload = readiness.model_dump(mode="json")
            payload["manifest_url"] = SIGNED_MANIFEST_URL
            return _v2_raw_response(200, payload)
        assert method == "POST"
        assert path.endswith("/completion")
        assert journal.load().state == "REPORT_FROZEN"
        assert journal.load().payload["completion_dispatch_attempts"] == 1
        report = json.loads(body)
        assert report["manifest_fetch"]["outcome"] == "release_timeout"
        assert report["results"] == []
        return _v2_raw_response(202, _v2_receipt(credential, bytes(body)))

    class FreezeOnlyExecutor:
        def execute(self, context, *, journal):
            return RealExecutor(
                utcnow=lambda: datetime(
                    2030, 1, 1, 0, 1, 30, tzinfo=timezone.utc
                )
            )._freeze(
                context,
                journal,
                ManifestFetchResult(outcome="release_timeout"),
                [],
            )

    from examples import scheduled_http_get_batch as example
    from ln_church_agent import scheduled_http_get_batch

    monkeypatch.setattr(
        scheduled_http_get_batch,
        "ScheduledHTTPGetBatchExecutor",
        FreezeOnlyExecutor,
    )
    monkeypatch.setattr(
        example, "ScheduledHTTPGetBatchExecutor", FreezeOnlyExecutor
    )
    result = _invoke_official_v2_path(
        official_path,
        credential,
        credential_path,
        journal_path,
        _real_v2_client_factory(exchange),
        monkeypatch,
    )
    if official_path == "cli":
        rendered = json.loads(capsys.readouterr().out)
        assert rendered["receipt"]["receipt_state"] == "DURABLY_ACCEPTED"
    else:
        assert result.receipt.receipt_state == "DURABLY_ACCEPTED"
    assert [item[0] for item in calls] == ["GET", "POST"]
    assert calls[0][1].endswith("/readiness")
    assert calls[1][1].endswith("/completion")
    assert journal.load().state == "COMPOUND_COMPLETION_ACKED"


@pytest.mark.parametrize("official_path", ("cli", "example"))
@pytest.mark.parametrize(
    ("scenario", "expected_methods"),
    (
        ("attempts_0", ["POST"]),
        ("attempts_1_status_found", ["GET"]),
        ("attempts_1_absent_retry", ["GET", "POST"]),
        ("attempts_2_status_only", ["GET"]),
    ),
)
def test_official_real_client_routes_frozen_dispatch_attempts(
    tmp_path,
    monkeypatch,
    capsys,
    official_path,
    scenario,
    expected_methods,
):
    credential = _credential()
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "journal.json"
    _write_private_credential(credential_path, credential)
    journal, frozen = _freeze_interrupted_report(journal_path, credential)
    if scenario != "attempts_0":
        journal.mark_completion_dispatch_attempted()
    if scenario == "attempts_2_status_only":
        journal.mark_completion_dispatch_attempted()
    calls = []

    def exchange(method, path, query, headers, body):
        del query
        calls.append((method, path, dict(headers), bytes(body)))
        if method == "GET":
            assert path.endswith("/status")
            assert "X-LN-Task-Claim-Token" not in headers
            if scenario == "attempts_1_status_found":
                return _v2_raw_response(
                    200,
                    _v2_status(credential, frozen.exact_bytes),
                )
            return _v2_raw_response(404, {"error_code": "not_found"})
        assert method == "POST"
        assert path.endswith("/completion")
        assert bytes(body) == frozen.exact_bytes
        assert json.loads(body)["submission_id"] == frozen.submission_id
        return _v2_raw_response(
            202, _v2_receipt(credential, frozen.exact_bytes)
        )

    if scenario == "attempts_2_status_only":
        if official_path == "cli":
            with pytest.raises(SystemExit) as caught:
                _invoke_official_v2_path(
                    official_path,
                    credential,
                    credential_path,
                    journal_path,
                    _real_v2_client_factory(exchange),
                    monkeypatch,
                )
            assert caught.value.code == 2
            assert "COMPLETION_OUTCOME_UNKNOWN" in capsys.readouterr().err
        else:
            from ln_church_agent.task_v2_transport import (
                CompletionOutcomeUnknownError,
            )

            with pytest.raises(CompletionOutcomeUnknownError):
                _invoke_official_v2_path(
                    official_path,
                    credential,
                    credential_path,
                    journal_path,
                    _real_v2_client_factory(exchange),
                    monkeypatch,
                )
        assert journal.load().state == "REPORT_FROZEN"
    else:
        result = _invoke_official_v2_path(
            official_path,
            credential,
            credential_path,
            journal_path,
            _real_v2_client_factory(exchange),
            monkeypatch,
        )
        if official_path == "cli":
            rendered = json.loads(capsys.readouterr().out)
            source = rendered["source"]
        else:
            source = result.source
        assert source == (
            "status" if scenario == "attempts_1_status_found" else "receipt"
        )
        assert journal.load().state == "COMPOUND_COMPLETION_ACKED"

    assert [item[0] for item in calls] == expected_methods
    assert sum(item[0] == "POST" for item in calls) <= 1
    for method, _path, _headers, body in calls:
        if method == "POST":
            assert body == frozen.exact_bytes


@pytest.mark.parametrize("official_path", ("cli", "example"))
@pytest.mark.parametrize(
    (
        "initial_state",
        "response_terminal",
        "expected_state",
        "fails_closed",
    ),
    (
        ("acked", False, "COMPOUND_COMPLETION_ACKED", False),
        ("acked", True, "TERMINAL_STATUS", False),
        ("terminal", True, "TERMINAL_STATUS", False),
        ("terminal", False, "TERMINAL_STATUS", True),
    ),
)
def test_official_post_ack_states_are_real_client_status_only(
    tmp_path,
    monkeypatch,
    capsys,
    official_path,
    initial_state,
    response_terminal,
    expected_state,
    fails_closed,
):
    credential = _credential()
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "journal.json"
    _write_private_credential(credential_path, credential)
    journal, frozen, _initial_status = _acknowledged_journal(
        journal_path,
        credential,
        terminal=initial_state == "terminal",
    )
    journal_bytes_before = journal_path.read_bytes()
    journal_payload_before = journal.load().payload
    status_payload = _v2_status(
        credential, frozen.exact_bytes, terminal=response_terminal
    )
    calls = []

    def exchange(method, path, query, headers, body):
        del query
        calls.append((method, path, dict(headers), bytes(body)))
        assert method == "GET"
        assert path.endswith("/status")
        assert "X-LN-Task-Claim-Token" not in headers
        return _v2_raw_response(200, status_payload)

    def invoke():
        return _invoke_official_v2_path(
            official_path,
            credential,
            credential_path,
            journal_path,
            _real_v2_client_factory(exchange),
            monkeypatch,
        )

    if fails_closed:
        if official_path == "cli":
            with pytest.raises(SystemExit) as caught:
                invoke()
            assert caught.value.code == 2
            captured = capsys.readouterr()
            assert captured.out == ""
            assert captured.err == (
                "Task error: TASK_V2_RESPONSE_INVALID\n"
            )
        else:
            from ln_church_agent.task_v2_transport import (
                TaskV2TransportError,
            )

            with pytest.raises(TaskV2TransportError) as caught:
                invoke()
            assert caught.value.code == "TASK_V2_RESPONSE_INVALID"
            assert caught.value.request_bytes_sent is True
        assert journal_path.read_bytes() == journal_bytes_before
        journal_payload_after = journal.load().payload
        assert journal_payload_after == journal_payload_before
        assert journal_payload_after["state"] == "TERMINAL_STATUS"
        assert journal_payload_after["terminal_status"]["terminal"] is True
    else:
        result = invoke()
        if official_path == "cli":
            rendered = json.loads(capsys.readouterr().out)
            assert rendered["terminal"] is response_terminal
            assert "source" not in rendered
        else:
            from ln_church_agent.task_v2_models import ScheduledRewardStatus

            assert isinstance(result, ScheduledRewardStatus)
            assert result.terminal is response_terminal
    assert [item[0] for item in calls] == ["GET"]
    assert all(item[0] != "POST" for item in calls)
    assert journal.load().state == expected_state
    if not (initial_state == "acked" and response_terminal):
        assert journal_path.read_bytes() == journal_bytes_before
        assert journal.load().payload == journal_payload_before


@pytest.mark.parametrize(
    "client_entrypoint", ("complete_task", "recover_completion")
)
@pytest.mark.parametrize(
    (
        "initial_state",
        "response_terminal",
        "expected_state",
        "fails_closed",
    ),
    (
        ("acked", False, "COMPOUND_COMPLETION_ACKED", False),
        ("acked", True, "TERMINAL_STATUS", False),
        ("terminal", True, "TERMINAL_STATUS", False),
        ("terminal", False, "TERMINAL_STATUS", True),
    ),
)
def test_direct_client_post_ack_terminal_regression_matrix(
    tmp_path,
    client_entrypoint,
    initial_state,
    response_terminal,
    expected_state,
    fails_closed,
):
    credential = _credential()
    journal_path = tmp_path / "journal.json"
    journal, frozen, _initial_status = _acknowledged_journal(
        journal_path,
        credential,
        terminal=initial_state == "terminal",
    )
    journal_bytes_before = journal_path.read_bytes()
    journal_payload_before = journal.load().payload
    status_payload = _v2_status(
        credential, frozen.exact_bytes, terminal=response_terminal
    )
    calls = []

    def exchange(method, path, query, headers, body):
        del query
        calls.append((method, path, dict(headers), bytes(body)))
        assert method == "GET"
        assert path.endswith("/status")
        assert "X-LN-Task-Claim-Token" not in headers
        return _v2_raw_response(200, status_payload)

    from ln_church_agent.task_v2_models import (
        ScheduledCompletionAcknowledgement,
        ScheduledCompletionReport,
    )
    from ln_church_agent.task_v2_transport import TaskV2TransportError

    client_type = _real_v2_client_factory(exchange)
    report = ScheduledCompletionReport.model_validate_json(
        frozen.exact_bytes, strict=True
    )
    with client_type() as client:
        invoke = lambda: getattr(client, client_entrypoint)(
            credential, report, journal=journal
        )
        if fails_closed:
            with pytest.raises(TaskV2TransportError) as caught:
                invoke()
            assert caught.value.code == "TASK_V2_RESPONSE_INVALID"
            assert caught.value.request_bytes_sent is True
        else:
            acknowledgement = invoke()
            assert isinstance(
                acknowledgement, ScheduledCompletionAcknowledgement
            )
            assert acknowledgement.source == "status"
            assert acknowledgement.status is not None
            assert acknowledgement.status.terminal is response_terminal

    assert [item[0] for item in calls] == ["GET"]
    assert all(item[0] != "POST" for item in calls)
    assert journal.load().state == expected_state
    if not (initial_state == "acked" and response_terminal):
        assert journal_path.read_bytes() == journal_bytes_before
        journal_payload_after = journal.load().payload
        assert journal_payload_after == journal_payload_before
        if initial_state == "terminal":
            assert journal_payload_after["terminal_status"]["terminal"] is True


@pytest.mark.parametrize("official_path", ("cli", "example"))
def test_official_post_ack_thread_loser_has_zero_network_io(
    tmp_path, monkeypatch, capsys, official_path
):
    credential = _credential()
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "journal.json"
    _write_private_credential(credential_path, credential)
    journal, frozen, status_payload = _acknowledged_journal(
        journal_path, credential
    )
    get_started = threading.Event()
    release_status = threading.Event()
    calls = []
    calls_lock = threading.Lock()

    def exchange(method, path, query, headers, body):
        del query, body
        with calls_lock:
            calls.append((method, path, dict(headers)))
        assert method == "GET"
        assert path.endswith("/status")
        assert "X-LN-Task-Claim-Token" not in headers
        get_started.set()
        assert release_status.wait(timeout=5)
        return _v2_raw_response(200, status_payload)

    invoke = _official_v2_invocation(
        official_path, credential, credential_path, journal_path,
        _real_v2_client_factory(exchange), monkeypatch,
    )

    winner_results = []
    winner_errors = []

    def winner():
        try:
            winner_results.append(invoke())
        except BaseException as error:
            winner_errors.append(error)

    worker = threading.Thread(
        target=winner, name="official-post-ack-winner"
    )
    worker.start()
    assert get_started.wait(timeout=5)
    try:
        if official_path == "cli":
            with pytest.raises(SystemExit) as caught:
                invoke()
            assert caught.value.code == 2
        else:
            from ln_church_agent.task_journal import JournalError

            with pytest.raises(JournalError, match="^JOURNAL_LOCKED$"):
                invoke()
        with calls_lock:
            assert [item[0] for item in calls] == ["GET"]
    finally:
        release_status.set()
        worker.join(timeout=5)

    assert not worker.is_alive()
    assert winner_errors == []
    assert len(winner_results) == 1
    assert journal.load().state == "COMPOUND_COMPLETION_ACKED"
    assert journal.frozen_report_bytes() == frozen.exact_bytes
    captured = capsys.readouterr()
    assert CLAIM_TOKEN not in captured.out + captured.err
    assert SIGNED_MANIFEST_URL not in captured.out + captured.err


@pytest.mark.parametrize("official_path", ("cli", "example"))
def test_official_post_ack_native_linux_process_loser_has_zero_network_io(
    tmp_path, monkeypatch, capsys, official_path
):
    if not sys.platform.startswith("linux"):
        pytest.skip("native Linux process qualification")
    context = multiprocessing.get_context("fork")
    credential = _credential()
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "journal.json"
    _write_private_credential(credential_path, credential)
    journal, frozen, status_payload = _acknowledged_journal(
        journal_path, credential
    )
    get_started = context.Event()
    release_status = context.Event()
    get_count = context.Value("i", 0)
    post_count = context.Value("i", 0)
    worker_result = context.Queue()

    def exchange(method, path, query, headers, body):
        del query, body
        if method == "GET":
            with get_count.get_lock():
                get_count.value += 1
        else:
            with post_count.get_lock():
                post_count.value += 1
        assert method == "GET"
        assert path.endswith("/status")
        assert "X-LN-Task-Claim-Token" not in headers
        get_started.set()
        assert release_status.wait(timeout=10)
        return _v2_raw_response(200, status_payload)

    invoke = _official_v2_invocation(
        official_path, credential, credential_path, journal_path,
        _real_v2_client_factory(exchange), monkeypatch,
    )

    def process_winner():
        try:
            invoke()
            worker_result.put(("ok", None))
        except BaseException as error:
            worker_result.put(("error", repr(error)))

    process = context.Process(target=process_winner)
    process.start()
    assert get_started.wait(timeout=10)
    try:
        if official_path == "cli":
            with pytest.raises(SystemExit) as caught:
                invoke()
            assert caught.value.code == 2
        else:
            from ln_church_agent.task_journal import JournalError

            with pytest.raises(JournalError, match="^JOURNAL_LOCKED$"):
                invoke()
        assert get_count.value == 1
        assert post_count.value == 0
    finally:
        release_status.set()
        process.join(timeout=10)

    assert not process.is_alive()
    assert process.exitcode == 0
    assert worker_result.get(timeout=5) == ("ok", None)
    assert get_count.value == 1
    assert post_count.value == 0
    assert journal.load().state == "COMPOUND_COMPLETION_ACKED"
    assert journal.frozen_report_bytes() == frozen.exact_bytes
    captured = capsys.readouterr()
    assert CLAIM_TOKEN not in captured.out + captured.err
    assert SIGNED_MANIFEST_URL not in captured.out + captured.err


@pytest.mark.parametrize("official_path", ("cli", "example"))
def test_official_post_ack_hard_exit_releases_guard_for_status_restart(
    tmp_path, monkeypatch, capsys, official_path
):
    if not sys.platform.startswith("linux"):
        pytest.skip("native Linux process qualification")
    context = multiprocessing.get_context("fork")
    credential = _credential()
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "journal.json"
    _write_private_credential(credential_path, credential)
    journal, frozen, _status_payload = _acknowledged_journal(
        journal_path, credential
    )
    terminal_status = _v2_status(
        credential, frozen.exact_bytes, terminal=True
    )
    get_count = context.Value("i", 0)
    post_count = context.Value("i", 0)
    terminal_write_reached = context.Event()

    def exchange(method, path, query, headers, body):
        del query, body
        if method == "GET":
            with get_count.get_lock():
                get_count.value += 1
        else:
            with post_count.get_lock():
                post_count.value += 1
        assert method == "GET"
        assert path.endswith("/status")
        assert "X-LN-Task-Claim-Token" not in headers
        return _v2_raw_response(200, terminal_status)

    invoke = _official_v2_invocation(
        official_path, credential, credential_path, journal_path,
        _real_v2_client_factory(exchange), monkeypatch,
    )

    from ln_church_agent.task_journal import TaskJournal

    original_mark_terminal = TaskJournal.mark_terminal_status

    def hard_exit_before_terminal_write(self, status):
        assert status.terminal is True
        terminal_write_reached.set()
        os._exit(73)

    monkeypatch.setattr(
        TaskJournal, "mark_terminal_status", hard_exit_before_terminal_write
    )

    process = context.Process(target=invoke)
    process.start()
    assert terminal_write_reached.wait(timeout=10)
    process.join(timeout=10)
    assert not process.is_alive()
    assert process.exitcode == 73
    assert get_count.value == 1
    assert post_count.value == 0
    assert journal.load().state == "COMPOUND_COMPLETION_ACKED"
    assert journal.completion_lock_path.exists()
    stable_lock_inode = journal.completion_lock_path.stat().st_ino

    monkeypatch.setattr(
        TaskJournal, "mark_terminal_status", original_mark_terminal
    )
    result = invoke()
    assert get_count.value == 2
    assert post_count.value == 0
    assert journal.load().state == "TERMINAL_STATUS"
    assert journal.completion_lock_path.exists()
    assert journal.completion_lock_path.stat().st_ino == stable_lock_inode
    if official_path == "cli":
        assert json.loads(capsys.readouterr().out)["terminal"] is True
    else:
        assert result.terminal is True


@pytest.mark.parametrize("official_path", ("cli", "example"))
def test_official_initial_ambiguity_is_status_first_and_never_third_post(
    tmp_path, monkeypatch, capsys, official_path
):
    credential = _credential()
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "journal.json"
    _write_private_credential(credential_path, credential)
    journal, frozen = _freeze_interrupted_report(journal_path, credential)
    calls = []

    from ln_church_agent.task_v2_transport import (
        CompletionOutcomeUnknownError,
    )

    def exchange(method, path, query, headers, body):
        del query
        calls.append((method, path, dict(headers), bytes(body)))
        if method == "POST":
            assert bytes(body) == frozen.exact_bytes
            assert json.loads(body)["submission_id"] == frozen.submission_id
            raise CompletionOutcomeUnknownError()
        assert path.endswith("/status")
        assert "X-LN-Task-Claim-Token" not in headers
        return _v2_raw_response(404, {"error_code": "not_found"})

    if official_path == "cli":
        with pytest.raises(SystemExit) as caught:
            _invoke_official_v2_path(
                official_path,
                credential,
                credential_path,
                journal_path,
                _real_v2_client_factory(exchange),
                monkeypatch,
            )
        assert caught.value.code == 2
        assert "COMPLETION_OUTCOME_UNKNOWN" in capsys.readouterr().err
    else:
        with pytest.raises(CompletionOutcomeUnknownError):
            _invoke_official_v2_path(
                official_path,
                credential,
                credential_path,
                journal_path,
                _real_v2_client_factory(exchange),
                monkeypatch,
            )

    assert [item[0] for item in calls] == ["POST", "GET", "POST", "GET"]
    post_bodies = [item[3] for item in calls if item[0] == "POST"]
    assert post_bodies == [frozen.exact_bytes, frozen.exact_bytes]
    assert journal.load().state == "REPORT_FROZEN"
    assert journal.load().payload["completion_dispatch_attempts"] == 2


@pytest.mark.parametrize("official_path", ("cli", "example"))
def test_official_thread_contention_has_no_late_post_after_ack(
    tmp_path, monkeypatch, capsys, official_path
):
    credential = _credential()
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "journal.json"
    _write_private_credential(credential_path, credential)
    journal, frozen = _freeze_interrupted_report(journal_path, credential)
    post_started = threading.Event()
    release_receipt = threading.Event()
    calls = []
    calls_lock = threading.Lock()

    def exchange(method, path, query, headers, body):
        del query
        with calls_lock:
            calls.append((method, path, dict(headers), bytes(body)))
        if method == "POST":
            assert bytes(body) == frozen.exact_bytes
            post_started.set()
            assert release_receipt.wait(timeout=5)
            return _v2_raw_response(
                202, _v2_receipt(credential, frozen.exact_bytes)
            )
        assert path.endswith("/status")
        assert "X-LN-Task-Claim-Token" not in headers
        return _v2_raw_response(
            200, _v2_status(credential, frozen.exact_bytes)
        )

    invoke = _official_v2_invocation(
        official_path, credential, credential_path, journal_path,
        _real_v2_client_factory(exchange), monkeypatch,
    )

    winner_results = []
    winner_errors = []

    def winner():
        try:
            winner_results.append(invoke())
        except BaseException as error:
            winner_errors.append(error)

    worker = threading.Thread(target=winner, name="official-completion-winner")
    worker.start()
    assert post_started.wait(timeout=5)
    try:
        if official_path == "cli":
            with pytest.raises(SystemExit) as caught:
                invoke()
            assert caught.value.code == 2
        else:
            from ln_church_agent.task_journal import JournalError

            with pytest.raises(JournalError, match="^JOURNAL_LOCKED$"):
                invoke()
        with calls_lock:
            assert [item[0] for item in calls] == ["POST"]
    finally:
        release_receipt.set()
        worker.join(timeout=5)

    assert not worker.is_alive()
    assert winner_errors == []
    assert len(winner_results) == 1
    assert journal.load().state == "COMPOUND_COMPLETION_ACKED"

    # A later official invocation observes durable acknowledgement and is
    # tokenless status-only; it cannot issue a late Completion POST.
    invoke()
    with calls_lock:
        assert [item[0] for item in calls] == ["POST", "GET"]
    captured = capsys.readouterr()
    assert CLAIM_TOKEN not in captured.out + captured.err
    assert SIGNED_MANIFEST_URL not in captured.out + captured.err


@pytest.mark.parametrize("official_path", ("cli", "example"))
def test_official_native_linux_process_contention_has_one_post(
    tmp_path, monkeypatch, capsys, official_path
):
    if not sys.platform.startswith("linux"):
        pytest.skip("native Linux process qualification")
    context = multiprocessing.get_context("fork")
    credential = _credential()
    credential_path = tmp_path / "claim-v2.json"
    journal_path = tmp_path / "journal.json"
    _write_private_credential(credential_path, credential)
    journal, frozen = _freeze_interrupted_report(journal_path, credential)
    post_started = context.Event()
    release_receipt = context.Event()
    network_calls = context.Queue()
    worker_result = context.Queue()

    def exchange(method, path, query, headers, body):
        del query
        network_calls.put((method, path, dict(headers), bytes(body)))
        if method == "POST":
            assert bytes(body) == frozen.exact_bytes
            post_started.set()
            assert release_receipt.wait(timeout=10)
            return _v2_raw_response(
                202, _v2_receipt(credential, frozen.exact_bytes)
            )
        assert path.endswith("/status")
        assert "X-LN-Task-Claim-Token" not in headers
        return _v2_raw_response(
            200, _v2_status(credential, frozen.exact_bytes)
        )

    invoke = _official_v2_invocation(
        official_path, credential, credential_path, journal_path,
        _real_v2_client_factory(exchange), monkeypatch,
    )

    def process_winner():
        try:
            invoke()
            worker_result.put(("ok", None))
        except BaseException as error:
            worker_result.put(("error", repr(error)))

    process = context.Process(target=process_winner)
    process.start()
    assert post_started.wait(timeout=10)
    try:
        if official_path == "cli":
            with pytest.raises(SystemExit) as caught:
                invoke()
            assert caught.value.code == 2
        else:
            from ln_church_agent.task_journal import JournalError

            with pytest.raises(JournalError, match="^JOURNAL_LOCKED$"):
                invoke()
        first_call = network_calls.get(timeout=5)
        assert first_call[0] == "POST"
        assert first_call[3] == frozen.exact_bytes
        assert network_calls.empty()
    finally:
        release_receipt.set()
        process.join(timeout=10)

    assert not process.is_alive()
    assert process.exitcode == 0
    assert worker_result.get(timeout=5) == ("ok", None)
    assert journal.load().state == "COMPOUND_COMPLETION_ACKED"

    # The parent process can only observe status after the child has durably
    # crossed the compound acknowledgement boundary.
    invoke()
    late_call = network_calls.get(timeout=5)
    assert late_call[0] == "GET"
    assert late_call[1].endswith("/status")
    assert network_calls.empty()
    captured = capsys.readouterr()
    assert CLAIM_TOKEN not in captured.out + captured.err
    assert SIGNED_MANIFEST_URL not in captured.out + captured.err
