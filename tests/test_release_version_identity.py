import ast
from email.parser import BytesParser
from email.policy import compat32
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import venv
import zipfile

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

import ln_church_agent
from ln_church_agent import client
from ln_church_agent import inspect_transport
from ln_church_agent.integrations import mcp_inspect


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "1.18.0"
EXPECTED_MCP_SPECIFIER = SpecifierSet(">=1.2.0,<2.0.0")
CONTRACT_FIXTURE_PATH = (
    "ln_church_agent/contracts/"
    "v18-scheduled-http-get-batch-contract-v1.json"
)
CONTRACT_FIXTURE_SHA256 = (
    "09eb478e30b56fec6efb462cfb43733b1e907bb247943f8fe6336af73d362785"
)
TASK_SUBCOMMANDS = (
    "list",
    "get",
    "claim",
    "submit",
    "submit-complete",
    "complete",
    "status",
    "reward-wait",
    "claim-v2",
    "run-scheduled-http-get-batch",
)


def _safe_process_output(value: str) -> str:
    value = re.sub(
        r"(https?://)[^/@\s]+@",
        r"\1***@",
        value,
        flags=re.IGNORECASE,
    )
    return value[-4000:]


def _run_checked(args, *, cwd: Path, env=None) -> str:
    result = subprocess.run(
        [str(arg) for arg in args],
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=900,
    )
    assert result.returncode == 0, (
        "command failed with exit %d: %s\nstdout:\n%s\nstderr:\n%s"
        % (
            result.returncode,
            " ".join(str(arg) for arg in args),
            _safe_process_output(result.stdout),
            _safe_process_output(result.stderr),
        )
    )
    return result.stdout


def _copy_clean_build_source(destination: Path) -> None:
    destination.mkdir()
    for name in (
        "setup.py",
        "README.md",
        "CHANGELOG.md",
        "server.json",
        "MANIFEST.in",
        "LICENSE",
    ):
        source = ROOT / name
        if source.exists():
            shutil.copy2(str(source), str(destination / name))
    ignored = shutil.ignore_patterns(
        "__pycache__",
        "*.pyc",
        "*.pyo",
        ".pytest_cache",
        "*.egg-info",
        "build",
        "dist",
    )
    for name in ("ln_church_agent", "docs", "examples", "tests"):
        source = ROOT / name
        if source.exists():
            shutil.copytree(
                str(source),
                str(destination / name),
                ignore=ignored,
            )


def _read_wheel_metadata(path: Path):
    with zipfile.ZipFile(str(path)) as archive:
        metadata_names = [
            name for name in archive.namelist()
            if name.endswith(".dist-info/METADATA")
        ]
        assert len(metadata_names) == 1
        return BytesParser(policy=compat32).parsebytes(
            archive.read(metadata_names[0])
        )


def _read_sdist_metadata(path: Path):
    with tarfile.open(str(path), mode="r:gz") as archive:
        members = [
            member for member in archive.getmembers()
            if (
                member.name.endswith("/PKG-INFO")
                and member.name.count("/") == 1
                and member.isfile()
            )
        ]
        assert len(members) == 1
        extracted = archive.extractfile(members[0])
        assert extracted is not None
        return BytesParser(policy=compat32).parsebytes(extracted.read())


def _read_wheel_member(path: Path, member_name: str) -> bytes:
    with zipfile.ZipFile(str(path)) as archive:
        assert archive.namelist().count(member_name) == 1
        return archive.read(member_name)


def _read_sdist_member(path: Path, member_suffix: str) -> bytes:
    with tarfile.open(str(path), mode="r:gz") as archive:
        members = [
            member
            for member in archive.getmembers()
            if member.isfile() and member.name.endswith("/" + member_suffix)
        ]
        assert len(members) == 1
        extracted = archive.extractfile(members[0])
        assert extracted is not None
        return extracted.read()


def _fresh_environment(path: Path):
    venv.EnvBuilder(with_pip=True, clear=True).create(str(path))
    scripts = path / ("Scripts" if os.name == "nt" else "bin")
    python_name = "python.exe" if os.name == "nt" else "python"
    cli_name = "ln-church-agent.exe" if os.name == "nt" else "ln-church-agent"
    return scripts / python_name, scripts / cli_name


def _unconstrained_install_environment():
    environment = os.environ.copy()
    for name in (
        "PIP_CONSTRAINT",
        "PIP_BUILD_CONSTRAINT",
        "PIP_REQUIREMENT",
        "PYTHONHOME",
        "PYTHONPATH",
        "VIRTUAL_ENV",
        "UV_CONSTRAINT",
        "UV_BUILD_CONSTRAINT",
    ):
        environment.pop(name, None)
    environment["PIP_CONFIG_FILE"] = os.devnull
    return environment


def _assert_origin_is_installed(origin: str, site_paths, source_root: Path):
    resolved_origin = os.path.realpath(origin)
    resolved_sites = [os.path.realpath(path) for path in site_paths]
    assert any(
        os.path.commonpath([resolved_origin, site_path]) == site_path
        for site_path in resolved_sites
    )
    resolved_source = os.path.realpath(str(source_root))
    try:
        shared_source = os.path.commonpath([resolved_origin, resolved_source])
    except ValueError:
        shared_source = None
    assert shared_source != resolved_source


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


def _client_fallback_version_literal() -> str:
    tree = ast.parse(
        (ROOT / "ln_church_agent" / "client.py").read_text(encoding="utf-8")
    )
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "get_sdk_version"
    ]
    assert len(functions) == 1
    handlers = [
        node
        for node in ast.walk(functions[0])
        if (
            isinstance(node, ast.ExceptHandler)
            and isinstance(node.type, ast.Attribute)
            and node.type.attr == "PackageNotFoundError"
        )
    ]
    assert len(handlers) == 1
    returns = [
        node.value.value
        for node in ast.walk(handlers[0])
        if (
            isinstance(node, ast.Return)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
    ]
    assert len(returns) == 1
    return returns[0]


def _assert_client_import_time_fallback_in_child_process() -> None:
    program = "\n".join(
        (
            "import importlib.metadata",
            "import sys",
            "sys.path.insert(0, %r)" % str(ROOT),
            "not_found = importlib.metadata.PackageNotFoundError",
            "metadata_version = importlib.metadata.version",
            "def missing_distribution(name):",
            "    if name == 'ln-church-agent':",
            "        raise not_found(name)",
            "    return metadata_version(name)",
            "importlib.metadata.version = missing_distribution",
            "import ln_church_agent",
            "from ln_church_agent import client",
            "assert client.get_sdk_version() == %r" % EXPECTED_VERSION,
            "assert client.SDK_VERSION == %r" % EXPECTED_VERSION,
            "assert client.CUSTOM_USER_AGENT == %r"
            % ("ln-church-agent/" + EXPECTED_VERSION),
            "assert ln_church_agent.LnChurchClient is client.LnChurchClient",
        )
    )
    _run_checked((sys.executable, "-c", program), cwd=ROOT)


def test_release_version_identities_are_consistent(monkeypatch):
    client_class_before = client.LnChurchClient
    package_client_class_before = ln_church_agent.LnChurchClient
    sdk_version_before = client.SDK_VERSION
    custom_user_agent_before = client.CUSTOM_USER_AGENT
    metadata_version_before = client.importlib.metadata.version
    assert client_class_before is package_client_class_before

    server_metadata = json.loads(
        (ROOT / "server.json").read_text(encoding="utf-8")
    )
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    release_note = (
        ROOT / "docs" / "release_notes" / "v1.18.0.md"
    ).read_text(encoding="utf-8")
    legacy_release_note = (
        ROOT / "docs" / "release_notes" / "v1.17.1.md"
    ).read_text(encoding="utf-8")

    def _missing_distribution(name):
        if name == "ln-church-agent":
            raise client.importlib.metadata.PackageNotFoundError(name)
        return metadata_version_before(name)

    with monkeypatch.context() as metadata_patch:
        metadata_patch.setattr(
            client.importlib.metadata,
            "version",
            _missing_distribution,
        )
        assert client.get_sdk_version() == EXPECTED_VERSION

    assert _setup_version() == EXPECTED_VERSION
    assert _client_fallback_version_literal() == EXPECTED_VERSION
    _assert_client_import_time_fallback_in_child_process()
    assert client.importlib.metadata.version is metadata_version_before
    assert client.SDK_VERSION == sdk_version_before
    assert client.CUSTOM_USER_AGENT == custom_user_agent_before
    assert client.LnChurchClient is client_class_before
    assert ln_church_agent.LnChurchClient is package_client_class_before
    assert ln_church_agent.LnChurchClient is client.LnChurchClient
    assert server_metadata["version"] == EXPECTED_VERSION
    assert len(server_metadata["packages"]) == 1
    assert server_metadata["packages"][0]["identifier"] == "ln-church-agent"
    assert server_metadata["packages"][0]["version"] == EXPECTED_VERSION

    headings = re.findall(r"^## \[([^]]+)\].*$", changelog, re.MULTILINE)
    assert headings[0] == EXPECTED_VERSION
    candidate_prefix, next_heading, _older_entries = changelog.partition(
        "## [1.16.4]"
    )
    assert next_heading == "## [1.16.4]"
    current_heading = (
        "## [1.18.0] - 2026-08-31 "
        "(Scheduled HTTP GET Batch SDK)"
    )
    current_start = candidate_prefix.index(current_heading)
    legacy_heading = (
        "## [1.17.1] - 2026-08-13 "
        "(Reward Destination Education and Agent-Earning Documentation)"
        ""
    )
    legacy_start = candidate_prefix.index(legacy_heading)
    current_section = candidate_prefix[current_start:legacy_start]
    assert current_section.startswith(current_heading)
    for required in (
        "scheduled_http_get_batch.v1",
        "one-attempt Claim",
        "CLAIM_OUTCOME_UNKNOWN",
        "Manifest",
        "ATTEMPT_STARTED",
        "COMPOUND_COMPLETION_ACKED",
        "32 KiB",
        "Linux",
        "macOS",
        "native Windows",
        "docs/release_notes/v1.18.0.md",
    ):
        assert required in current_section

    candidate_heading = (
        "## [1.17.0] - 2026-07-28 "
        "(Private Source Candidate — Agent Task Venue SDK)"
    )
    candidate_start = candidate_prefix.index(candidate_heading)
    legacy_section = candidate_prefix[legacy_start:candidate_start]
    assert legacy_section.startswith(legacy_heading)
    for required in (
        "reward_address",
        "Base (`eip155:8453`)",
        "wallet-control proof",
        "Agent-earning front",
        "JSON, wire, and Claim request payloads are unchanged",
        "Completion receipt, Evaluation, reward approval, and payout",
        "package, User-Agent, and MCP Observation identities",
        "Windows plus Python 3.14 remains unsupported",
        "docs/release_notes/v1.17.1.md",
    ):
        assert required in legacy_section
    candidate_section = candidate_prefix[candidate_start:]
    assert candidate_section.startswith(candidate_heading)
    assert (
        "This Private Source Candidate is pending independent audit and "
        "does not claim cross-repository compatibility, runtime acceptance, "
        "release readiness, deployment, or publication."
    ) in candidate_section
    assert "docs/release_notes/v1.17.0.md" in candidate_section
    assert "payment_surface_discovery.v1" in candidate_section
    assert "claim_task_or_observation_binding_mismatch" in candidate_section
    assert "pending independent re-audit" not in candidate_section
    assert "Public release candidate passed independent audit" not in (
        candidate_section
    )

    assert release_note.startswith(
        "# Release v1.18.0 — Scheduled HTTP GET Batch SDK"
    )
    for required in (
        "Public release of the Agent SDK",
        "Public release date: 2026-08-31.",
        "scheduled_http_get_batch.v1",
        "Claim is attempted exactly once",
        "CLAIM_OUTCOME_UNKNOWN",
        "same signed Manifest URL",
        "ATTEMPT_STARTED",
        "T+5",
        "COMPOUND_COMPLETION_ACKED",
        "claim token",
        "signed Manifest URL",
        "Linux",
        "macOS",
        "native Windows",
        "promotes the independently audited exact SDK candidate",
    ):
        assert required in release_note

    assert legacy_release_note.startswith(
        "# Release v1.17.1 — Reward Destination Education and "
        "Agent-Earning Documentation"
    )
    for required in (
        "Public release of the Agent SDK",
        "Public release date: 2026-08-13.",
        "reward_address",
        "wallet secret",
        "wallet-control proof",
        "Agent-earning front-documentation reframe",
        "JSON output, wire fields, and the Claim request payload are unchanged",
        "immutable Claim snapshot",
        "Completion receipt, Evaluation approval, reward approval, settlement "
        "initiation, and payout completion are distinct states",
        "Windows＋Python 3.14",
        "does not implement or deploy a Hondo runtime change",
        "Package publication remains a separate Human-operated release action",
    ):
        assert required in legacy_release_note

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
    task_transport_source = (
        ROOT / "ln_church_agent" / "task_transport.py"
    ).read_text(encoding="utf-8")
    assert (
        '"User-Agent": "ln-church-agent-task/' + EXPECTED_VERSION + '"'
        in task_transport_source
    )
    assert client.SDK_VERSION == sdk_version_before
    assert client.CUSTOM_USER_AGENT == custom_user_agent_before

    v2_model_source = (
        ROOT / "ln_church_agent" / "task_v2_models.py"
    ).read_text(encoding="utf-8")
    assert 'receipt_state: Literal["DURABLY_ACCEPTED"]' in v2_model_source
    for relative in (
        "ln_church_agent/task_v2_models.py",
        "ln_church_agent/task_journal.py",
        "ln_church_agent/scheduled_http_get_batch.py",
        "ln_church_agent/cli.py",
        "examples/scheduled_http_get_batch.py",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert '"REPORT_ACCEPTED"' not in source
        assert '"COMPLETION_DISPATCHED"' not in source

    assert client.LnChurchClient is client_class_before
    assert ln_church_agent.LnChurchClient is package_client_class_before
    assert ln_church_agent.LnChurchClient is client.LnChurchClient


def test_release_artifacts_resolve_supported_optional_mcp_extra(tmp_path):
    """Exercise the release artifacts in fresh, unconstrained environments."""
    source = tmp_path / "source"
    artifacts = tmp_path / "artifacts"
    runtime = tmp_path / "runtime"
    artifacts.mkdir()
    runtime.mkdir()
    _copy_clean_build_source(source)

    _run_checked(
        (
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--wheel",
            "--sdist",
            "--outdir",
            artifacts,
            source,
        ),
        cwd=runtime,
    )
    wheels = list(artifacts.glob("ln_church_agent-*.whl"))
    sdists = list(artifacts.glob("ln_church_agent-*.tar.gz"))
    assert len(wheels) == 1
    assert len(sdists) == 1
    wheel = wheels[0].resolve()

    wheel_metadata = _read_wheel_metadata(wheel)
    sdist_metadata = _read_sdist_metadata(sdists[0])
    for field in ("Name", "Version", "Requires-Python"):
        assert wheel_metadata[field] == sdist_metadata[field]
    for field in ("Provides-Extra", "Requires-Dist"):
        assert sorted(wheel_metadata.get_all(field, [])) == sorted(
            sdist_metadata.get_all(field, [])
        )
    assert wheel_metadata["Version"] == EXPECTED_VERSION

    source_fixture = (ROOT / CONTRACT_FIXTURE_PATH).read_bytes()
    wheel_fixture = _read_wheel_member(wheel, CONTRACT_FIXTURE_PATH)
    sdist_fixture = _read_sdist_member(sdists[0], CONTRACT_FIXTURE_PATH)
    assert wheel_fixture == source_fixture
    assert sdist_fixture == source_fixture
    assert source_fixture.endswith(b"\n")
    assert not source_fixture.endswith(b"\n\n")
    assert b"\r\n" not in source_fixture
    assert hashlib.sha256(source_fixture).hexdigest() == CONTRACT_FIXTURE_SHA256

    requirements = [
        Requirement(value)
        for value in wheel_metadata.get_all("Requires-Dist", [])
    ]
    mcp_requirements = [
        requirement for requirement in requirements
        if requirement.name.lower() == "mcp"
    ]
    assert len(mcp_requirements) == 2
    assert all(
        requirement.specifier == EXPECTED_MCP_SPECIFIER
        for requirement in mcp_requirements
    )
    assert all(requirement.marker is not None for requirement in mcp_requirements)
    assert all(
        not requirement.marker.evaluate({"extra": ""})
        for requirement in mcp_requirements
    )
    assert sum(
        requirement.marker.evaluate({"extra": "mcp"})
        for requirement in mcp_requirements
    ) == 1
    assert sum(
        requirement.marker.evaluate({"extra": "all"})
        for requirement in mcp_requirements
    ) == 1

    install_environment = _unconstrained_install_environment()

    core_python, _core_cli = _fresh_environment(tmp_path / "core-environment")
    _run_checked(
        (
            core_python,
            "-I",
            "-c",
            "import importlib.util; "
            "assert importlib.util.find_spec('mcp') is None; "
            "assert importlib.util.find_spec('ln_church_agent') is None",
        ),
        cwd=runtime,
        env=install_environment,
    )
    _run_checked(
        (
            core_python,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            wheel,
        ),
        cwd=runtime,
        env=install_environment,
    )
    _run_checked(
        (core_python, "-m", "pip", "check"),
        cwd=runtime,
        env=install_environment,
    )
    _run_checked(
        (
            core_python,
            "-I",
            "-c",
            "import importlib.metadata, importlib.util; "
            "assert importlib.metadata.version('ln-church-agent') == %r; "
            "assert importlib.util.find_spec('mcp') is None"
            % EXPECTED_VERSION,
        ),
        cwd=runtime,
        env=install_environment,
    )

    mcp_python, mcp_cli = _fresh_environment(tmp_path / "mcp-environment")
    _run_checked(
        (
            mcp_python,
            "-I",
            "-c",
            "import importlib.util; "
            "assert importlib.util.find_spec('mcp') is None; "
            "assert importlib.util.find_spec('ln_church_agent') is None",
        ),
        cwd=runtime,
        env=install_environment,
    )
    _run_checked(
        (
            mcp_python,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            str(wheel) + "[mcp]",
        ),
        cwd=runtime,
        env=install_environment,
    )
    _run_checked(
        (mcp_python, "-m", "pip", "check"),
        cwd=runtime,
        env=install_environment,
    )

    installed = json.loads(
        _run_checked(
            (
                mcp_python,
                "-I",
                "-c",
                (
                    "import importlib, importlib.metadata, json, sysconfig; "
                    "from mcp.server.fastmcp import FastMCP; "
                    "package = importlib.import_module('ln_church_agent'); "
                    "sdk_mcp = importlib.import_module("
                    "'ln_church_agent.integrations.mcp_inspect'); "
                    "fastmcp = importlib.import_module('mcp.server.fastmcp'); "
                    "print(json.dumps({"
                    "'mcp_version': importlib.metadata.version('mcp'), "
                    "'package_origin': package.__file__, "
                    "'sdk_mcp_origin': sdk_mcp.__file__, "
                    "'fastmcp_origin': fastmcp.__file__, "
                    "'fastmcp_class': FastMCP.__name__, "
                    "'site_paths': list({sysconfig.get_path('purelib'), "
                    "sysconfig.get_path('platlib')})"
                    "}))"
                ),
            ),
            cwd=runtime,
            env=install_environment,
        )
    )
    resolved_mcp = Version(installed["mcp_version"])
    assert resolved_mcp in EXPECTED_MCP_SPECIFIER
    assert installed["fastmcp_class"] == "FastMCP"
    for name in ("package_origin", "sdk_mcp_origin", "fastmcp_origin"):
        _assert_origin_is_installed(
            installed[name],
            installed["site_paths"],
            ROOT,
        )

    assert mcp_cli.is_file()
    help_commands = [
        (mcp_cli, "--help"),
        (mcp_cli, "task", "--help"),
    ]
    help_commands.extend(
        (mcp_cli, "task", subcommand, "--help")
        for subcommand in TASK_SUBCOMMANDS
    )
    for command in help_commands:
        output = _run_checked(
            command,
            cwd=runtime,
            env=install_environment,
        )
        assert "usage:" in output.lower()
