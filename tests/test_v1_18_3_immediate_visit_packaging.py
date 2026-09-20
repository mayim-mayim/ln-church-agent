"""SDK-A14 / Wire W7 supporting checks; artifact installs run separately.

Copy identities come from the exact DC-accepted c4 source mapping. Profile
expectations remain the fixed audited specification, not SDK-generated output.
"""

import hashlib
import json
import os
from pathlib import Path
import pkgutil
import runpy
import subprocess
import sys
import stat


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PREFIX = "contracts/v183-immediate-visit/"
COPIED_NAMES = {
    "SKILL.md", "abandon-request.schema.json", "claim-request.schema.json",
    "claim.schema.json", "definition.json", "error.schema.json", "manifest.json",
    "observation.schema.json", "page.schema.json", "profile-fixtures.json",
    "profile.json", "receipt.schema.json", "registration-result.schema.json",
    "registration.schema.json", "requester-registration/SKILL.md",
    "result.schema.json", "submission.schema.json", "summary.schema.json",
    "task.schema.json", "wire-fixtures.json",
}


def test_accepted_contract_resources_preserve_all_twenty_mappings_and_provenance():
    provenance = json.loads(pkgutil.get_data(
        "ln_church_agent", CONTRACT_PREFIX + "source-provenance.json"))
    assert provenance["acceptance"] == {
        "repository": "mayim-mayim/LN_Church_Development-Charter",
        "commit": "11a263537e54f6ac9a30f73277c25c6d861ed7a5",
        "path": "handoffs/V18_3_Hondo_C4_Acceptance_and_Freeze_20260914.md",
        "blob": "fc2dac54eeb850f36a64032b18c0897b778cb66a",
        "disposition": "DEVELOPMENT_ACCEPTANCE_PASS_CANDIDATE_FREEZE_CONFIRMED",
    }
    assert provenance["source_repository"] == "mayim-mayim/LN_Church"
    assert provenance["source_commit"] == "3e322a1ac2842cc4f875566c70cafda648ec0f1c"
    assert provenance["source_tree"] == "ad3146dd36a25f9809e3e275191b7d9c477fa5bd"
    assert provenance["source_ref"] == "refs/heads/candidate/v1.18.3-hondo-c4"
    assert provenance["audited_specification_commit"] == (
        "6390b7fc657ee516476afe8013b3d25881dff224")
    assert len(provenance["entries"]) == 20
    assert {entry["sdk_path"][len("ln_church_agent/" + CONTRACT_PREFIX):]
            for entry in provenance["entries"]} == COPIED_NAMES
    for entry in provenance["entries"]:
        resource = entry["sdk_path"].split("/", 1)[1]
        name = resource[len(CONTRACT_PREFIX):]
        assert entry["source_path"] == (
            "frontend/agent-task-specs/immediate_http_visit.v1/1.0.0/" + name)
        body = pkgutil.get_data("ln_church_agent", resource)
        assert len(body) == entry["bytes"]
        assert hashlib.sha256(body).hexdigest() == entry["sha256"]
        assert hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest() == entry["blob"]
        assert entry["mode"] == "100644"
        if os.name != "nt":
            assert stat.S_IMODE((ROOT / entry["sdk_path"]).stat().st_mode) == 0o644
    manifest = pkgutil.get_data("ln_church_agent", CONTRACT_PREFIX + "manifest.json")
    assert b"implementation_candidate_not_source_accepted" in manifest


def test_bundled_profile_fixtures_match_fixed_specification_and_execute():
    from ln_church_agent.immediate_visit_profile import analyze_response

    fixed_bytes = (ROOT / "tests/fixtures/v183-immediate-visit/profile-fixtures.json").read_bytes()
    assert hashlib.sha256(fixed_bytes).hexdigest() == (
        "ee89b8f6c5969359b38245cd72d0f6b535228244b5e9e408ba0932cd5d0b93be")
    fixed = json.loads(fixed_bytes)
    bundled = json.loads(pkgutil.get_data(
        "ln_church_agent", CONTRACT_PREFIX + "profile-fixtures.json"))
    assert bundled == fixed
    assert len(bundled["vectors"]) == 27
    for vector in bundled["vectors"]:
        body = bytes.fromhex(vector["body_hex"])
        observed = analyze_response(vector["status"],
                                    [("Content-Type", vector["content_type"])], body)
        assert observed["outcome"] == vector["expected_outcome"], vector["id"]
        for expected, field in (("expected_structure_sha256", "structure_sha256"),
                                ("expected_body_sha256", "body_sha256"),
                                ("expected_reason", "reason")):
            if expected in vector:
                assert observed[field] == vector[expected], (vector["id"], field)
        if "expected_jcs_utf8" in vector:
            assert hashlib.sha256(vector["expected_jcs_utf8"].encode("utf-8")).hexdigest() == (
                vector["expected_structure_sha256"])
        if "expected_body_sha256" in vector:
            assert hashlib.sha256(body).hexdigest() == vector["expected_body_sha256"]


def test_new_public_worker_exports_and_previous_public_apis_import():
    from ln_church_agent import (
        AgentImmediateVisitClient,
        AgentTaskClient,
        AgentTaskV2Client,
        FrozenImmediateVisitReport,
        ImmediateVisitExecutor,
        ImmediateVisitJournal,
        LnChurchClient,
        Payment402Client,
    )
    from ln_church_agent.immediate_visit_client import (
        AgentImmediateVisitClient as ConcreteClient,
    )
    from ln_church_agent.immediate_visit import (
        FrozenImmediateVisitReport as ConcreteReport,
        ImmediateVisitExecutor as ConcreteExecutor,
    )
    from ln_church_agent.immediate_visit_journal import (
        ImmediateVisitJournal as ConcreteJournal,
    )

    assert AgentImmediateVisitClient is ConcreteClient
    assert ImmediateVisitExecutor is ConcreteExecutor
    assert FrozenImmediateVisitReport is ConcreteReport
    assert ImmediateVisitJournal is ConcreteJournal
    assert all(isinstance(cls, type) for cls in (
        AgentTaskClient, AgentTaskV2Client, LnChurchClient, Payment402Client,
    ))


def test_inspect_import_does_not_initialize_new_worker_or_parser():
    script = """
import sys
import ln_church_agent.integrations.mcp_inspect
assert not any(name.startswith('ln_church_agent.immediate_visit')
               for name in sys.modules)
assert not any(name.startswith('ln_church_agent._vendor.justhtml')
               for name in sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=str(ROOT),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


def test_vendor_license_and_compatibility_provenance_are_package_resources():
    package = "ln_church_agent._vendor.justhtml"
    license_bytes = pkgutil.get_data(package, "LICENSE")
    assert hashlib.sha256(license_bytes).hexdigest() == (
        "fc806f290894e4f219467135fb21f33048f8d5a817f0f8284246d72da29d572e"
    )
    assert b"3.11.2" in pkgutil.get_data(package, "UPSTREAM.md")
    assert pkgutil.get_data(package, "compatibility.patch")
    assert pkgutil.get_data(package, "py.typed") is not None


def test_distribution_metadata_keeps_python_extras_entry_points(monkeypatch):
    import setuptools

    captured = {}
    monkeypatch.setattr(setuptools, "setup", lambda **values: captured.update(values))
    monkeypatch.chdir(ROOT)
    runpy.run_path(str(ROOT / "setup.py"), run_name="__main__")
    assert captured["version"] == "1.18.4"
    assert captured["python_requires"] == ">=3.8.1"
    assert captured["entry_points"] == {"console_scripts": [
        "ln-church-agent=ln_church_agent.cli:main",
        "lnc-agent=ln_church_agent.cli:main",
        "ln-church-agent-mcp=ln_church_agent.integrations.mcp_inspect:main",
    ]}
    assert captured["extras_require"] == {
        "langchain": ["langchain-core>=0.1.0"],
        "mcp": ["mcp>=1.2.0,<2.0.0"],
        "solana": ["solana>=0.34.0,<0.40.0", "solders>=0.21.0,<0.28.0"],
        "svm": [
            "x402[svm]>=1.0.0,<3.0.0", "solana>=0.34.0,<0.40.0",
            "solders>=0.21.0,<0.28.0",
        ],
        "all": [
            "langchain-core>=0.1.0", "mcp>=1.2.0,<2.0.0",
            "solana>=0.34.0,<0.40.0", "solders>=0.21.0,<0.28.0",
            "x402[svm]>=1.0.0,<3.0.0",
        ],
    }
    assert "ln_church_agent._vendor.justhtml" in captured["packages"]
    manifest = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    assert manifest["version"] == "1.18.4"
    assert manifest["packages"][0]["version"] == "1.18.4"
