import ast
import json
from pathlib import Path

from ln_church_agent import client


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "1.16.3"


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

    def _missing_distribution(_name):
        raise client.importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(client.importlib.metadata, "version", _missing_distribution)

    assert _setup_version() == EXPECTED_VERSION
    assert client.get_sdk_version() == EXPECTED_VERSION
    assert server_metadata["version"] == EXPECTED_VERSION
    assert len(server_metadata["packages"]) == 1
    assert server_metadata["packages"][0]["identifier"] == "ln-church-agent"
    assert server_metadata["packages"][0]["version"] == EXPECTED_VERSION
