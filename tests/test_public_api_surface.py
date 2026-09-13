import pytest
# 1. 完全に Public Stable な概念のみトップレベルからインポート
from ln_church_agent import (
    Payment402Client,
    LnChurchClient,
    ParsedChallenge,
    ExecutionResult,
    ExecutionContext,
    TrustDecision,
    OutcomeSummary,
    TrustEvidence,
    ChallengeSource
)
# 2. Experimental な概念は .models から明示的にインポート
from ln_church_agent.models import PaymentEvidenceRecord, EvidenceRepository

def test_public_api_imports_and_instantiation():
    """トップレベルからインポートした Stable なモデルがスキーマエラーなく生成できるか確認"""
    
    # 1. ParsedChallenge
    pc = ParsedChallenge(
        scheme="L402", 
        network="Lightning", 
        amount=10.0, 
        asset="SATS",
        parameters={},
        source=ChallengeSource.STANDARD_WWW
    )
    assert pc.scheme == "L402"
    assert pc.amount == 10.0

    # 2. ExecutionContext
    ctx = ExecutionContext(intent_label="test_intent", hints={"key": "value"})
    assert ctx.intent_label == "test_intent"
    assert ctx.session_id is not None
    assert ctx.hints["key"] == "value"

    # 3. TrustDecision
    td = TrustDecision(is_trusted=True, reason="ok")
    assert td.is_trusted is True

    # 4. TrustEvidence (ParsedChallengeをネスト)
    te = TrustEvidence(url="http://public.example", challenge=pc, agent_hints=ctx.hints)
    assert te.url == "http://public.example"
    assert te.challenge.scheme == "L402"
    assert te.agent_hints["key"] == "value"

    # 5. OutcomeSummary
    os_summary = OutcomeSummary(is_success=True, observed_state="done")
    assert os_summary.is_success is True

    # 6. ExecutionResult (OutcomeSummaryをネスト)
    er = ExecutionResult(
        response={"ok": True},
        final_url="http://public.example",
        outcome=os_summary
    )
    assert er.outcome is not None
    assert er.outcome.is_success is True

def test_experimental_evidence_models_instantiation():
    """v1.5.1 の Experimental 概念が依存関係エラーなく .models 経由で生成できるか確認"""
    
    # EvidenceRepository (抽象クラスのデフォルト挙動)
    repo = EvidenceRepository()
    assert repo.import_evidence("http://dummy", ExecutionContext()) == []

    # PaymentEvidenceRecord
    record = PaymentEvidenceRecord(
        session_id="sess_123",
        correlation_id="corr_123",
        target_url="http://dummy",
        method="POST"
    )
    assert record.session_id == "sess_123"
    assert record.timestamp > 0
    assert record.trust_decision is None


@pytest.fixture
def package_metadata():
    """Use the installed distribution's public metadata."""
    import importlib.metadata

    return importlib.metadata.distribution("ln-church-agent")


def test_current_package_and_runtime_identity(package_metadata):
    import importlib.metadata
    import json
    from pathlib import Path
    from ln_church_agent import client

    version = package_metadata.version
    assert importlib.metadata.version("ln-church-agent") == version
    assert client.get_sdk_version() == version
    assert client.SDK_VERSION == version
    assert client.CUSTOM_USER_AGENT == "ln-church-agent/" + version
    server = json.loads(
        (Path(__file__).resolve().parents[1] / "server.json").read_text("utf-8")
    )
    assert server["version"] == version
    assert [package["version"] for package in server["packages"]
            if package["identifier"] == package_metadata.metadata["Name"]] == [version]


def test_import_without_distribution_metadata_keeps_public_identity(package_metadata):
    import subprocess
    import sys
    from pathlib import Path

    # Keep the import-time fallback in a child: reloading the client in this
    # process would replace class objects used by other public entry tests.
    program = """
import importlib.metadata
import json
import socket
from eth_account import Account
def unexpected_io(*args, **kwargs):
    raise AssertionError("keyless import/checksum attempted wallet or network access")
socket.create_connection = unexpected_io
socket.socket.connect = unexpected_io
Account.from_key = unexpected_io
version = importlib.metadata.version
def missing(name):
    if name == 'ln-church-agent':
        raise importlib.metadata.PackageNotFoundError(name)
    return version(name)
importlib.metadata.version = missing
import ln_church_agent
from ln_church_agent import client
from ln_church_agent.task_contract import to_eip55_checksum_address
assert to_eip55_checksum_address("0x" + "1" * 40) == "0x" + "1" * 40
assert ln_church_agent.LnChurchClient is client.LnChurchClient
print(json.dumps([client.get_sdk_version(), client.SDK_VERSION,
                  client.CUSTOM_USER_AGENT]))
"""
    result = subprocess.run(
        [sys.executable, "-c", program],
        cwd=Path(__file__).resolve().parents[1],
        check=True, capture_output=True, text=True, timeout=30,
    )
    import json
    version = package_metadata.version
    assert json.loads(result.stdout) == [version, version, "ln-church-agent/" + version]


def test_package_declares_existing_crypto_and_optional_mcp(package_metadata):
    from packaging.requirements import Requirement
    from packaging.specifiers import SpecifierSet

    requirements = list(map(Requirement, package_metadata.requires))
    core = {requirement.name: requirement for requirement in requirements
            if requirement.marker is None or requirement.marker.evaluate({"extra": ""})}
    assert "eth-account" in core
    assert "pycryptodome" in core["eth-hash"].extras
    assert "mcp" not in core
    for extra in ("mcp", "all"):
        mcp = [requirement for requirement in requirements
               if requirement.name == "mcp" and requirement.marker.evaluate({"extra": extra})]
        assert len(mcp) == 1
        assert mcp[0].specifier == SpecifierSet(">=1.2.0,<2.0.0")
    scripts = {entry.name: entry for entry in package_metadata.entry_points
               if entry.group == "console_scripts"}
    from ln_church_agent import cli
    assert scripts["ln-church-agent"].load() is cli.main
    assert scripts["lnc-agent"].load() is cli.main
    assert callable(scripts["ln-church-agent-mcp"].load())


def test_mcp_observation_uses_current_public_identity(package_metadata):
    from ln_church_agent.integrations.mcp_inspect import build_mcp_observation_payload

    observation = build_mcp_observation_payload({
        "url": "https://public.example/", "method": "GET", "status_code": 200,
    })
    assert observation["sdk_version"] == package_metadata.version


@pytest.mark.parametrize("arguments", [
    [], ["task"],
    *[["task", command] for command in (
        "list", "get", "claim", "submit", "submit-complete", "complete",
        "status", "reward-wait", "claim-v2", "run-scheduled-http-get-batch",
    )],
])
def test_public_cli_help_needs_no_client_initialization(monkeypatch, capsys, arguments):
    import sys
    from ln_church_agent import cli, LnChurchClient, AgentTaskClient, AgentTaskV2Client

    def no_client(*args, **kwargs):
        pytest.fail("CLI help must not initialize a client")

    for client_type in (LnChurchClient, AgentTaskClient, AgentTaskV2Client):
        monkeypatch.setattr(client_type, "__init__", no_client)
    monkeypatch.setattr(sys, "argv", ["ln-church-agent", *arguments, "--help"])
    with pytest.raises(SystemExit) as caught:
        cli.main()
    assert caught.value.code == 0
    assert "usage:" in capsys.readouterr().out.lower()


# Published EIP-55 vectors: https://eips.ethereum.org/EIPS/eip-55#test-cases
@pytest.mark.parametrize("canonical", [
    "0x52908400098527886E0F7030069857D2E4169EE7",
    "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
    "0xde709f2102306220921060314715629080e2fb77",
    "0x27b1fdb04752bbc536007a920d24acb045561c26",
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
])
def test_task_checksum_canonicalizes_known_eip55_vectors(canonical):
    from ln_church_agent.task_contract import to_eip55_checksum_address

    for value in (canonical, canonical.lower(), "0x" + canonical[2:].upper()):
        assert to_eip55_checksum_address(value) == canonical


@pytest.mark.parametrize("address", [
    None, b"0x" + b"1" * 40, 1,
    "0x" + "0" * 40, "0X" + "1" * 40,
    "0x" + "1" * 39, "0x" + "1" * 41, "0x" + "g" * 40,
    "0x" + "1" * 39 + "\n", "0x" + "1" * 38 + "e\u0301",
    "0x52908400098527886e0F7030069857D2E4169EE7",
])
def test_task_checksum_rejects_inputs_outside_address_contract(address):
    from ln_church_agent.task_contract import to_eip55_checksum_address

    with pytest.raises(ValueError, match=r"^Invalid reward_address\.$"):
        to_eip55_checksum_address(address)
