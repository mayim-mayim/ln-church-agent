import ast
import json
from pathlib import Path
import re

from ln_church_agent import client
from ln_church_agent import inspect_transport
from ln_church_agent.integrations import mcp_inspect


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "1.16.4"


def _setup_version() -> str:
    tree = ast.parse((ROOT / "setup.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "setup":
            continue
        for keyword in node.keywords:
            if keyword.arg == "version":
                assert isinstance(keyword.value, ast.Constant)
                assert isinstance(keyword.value.value, str)
                return keyword.value.value
    raise AssertionError("setup.py does not declare a literal setup(version=...)")


def test_release_version_identities_are_consistent(monkeypatch):
    server_metadata = json.loads(
        (ROOT / "server.json").read_text(encoding="utf-8")
    )
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    release_note = (
        ROOT / "docs" / "release_notes" / "v1.16.4.md"
    ).read_text(encoding="utf-8")

    def _missing_distribution(_name):
        raise client.importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(client.importlib.metadata, "version", _missing_distribution)

    assert _setup_version() == EXPECTED_VERSION
    assert client.get_sdk_version() == EXPECTED_VERSION
    assert server_metadata["version"] == EXPECTED_VERSION
    assert len(server_metadata["packages"]) == 1
    assert server_metadata["packages"][0]["identifier"] == "ln-church-agent"
    assert server_metadata["packages"][0]["version"] == EXPECTED_VERSION

    headings = re.findall(r"^## \[([^]]+)\].*$", changelog, re.MULTILINE)
    assert headings[0] == EXPECTED_VERSION
    candidate_section = changelog.split("## [1.16.3]", 1)[0]
    assert "Private candidate" in candidate_section
    assert "pending independent re-audit" in candidate_section
    assert "docs/release_notes/v1.16.4.md" in candidate_section

    assert release_note.startswith(
        "# Release v1.16.4 — Inspect MCP SSRF and Privacy Boundary"
    )
    assert "Private candidate behavior only" in release_note
    assert "does not claim formal independent-audit approval" in release_note

    observation = mcp_inspect.build_mcp_observation_payload(
        {
            "url": "https://public.example/",
            "method": "GET",
            "status_code": 200,
        }
    )
    assert mcp_inspect._OBSERVATION_SDK_VERSION == EXPECTED_VERSION
    assert observation["sdk_version"] == EXPECTED_VERSION

    target = inspect_transport._canonicalize_target(
        "https://public.example/"
    )
    inspect_user_agent = inspect_transport._fixed_headers(
        target,
        has_body=False,
    )["User-Agent"]
    assert inspect_user_agent == "ln-church-agent-inspect/" + EXPECTED_VERSION
    assert client.SDK_VERSION == EXPECTED_VERSION
    assert client.CUSTOM_USER_AGENT == "ln-church-agent/" + EXPECTED_VERSION
