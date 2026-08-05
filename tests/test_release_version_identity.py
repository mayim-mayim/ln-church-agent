import ast
from email.parser import BytesParser
from email.policy import compat32
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

from ln_church_agent import client
from ln_church_agent import inspect_transport
from ln_church_agent.integrations import mcp_inspect


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "1.17.0"
EXPECTED_MCP_SPECIFIER = SpecifierSet(">=1.2.0,<2.0.0")
TASK_SUBCOMMANDS = (
    "list",
    "get",
    "claim",
    "submit",
    "submit-complete",
    "complete",
    "status",
    "reward-wait",
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


def test_release_version_identities_are_consistent(monkeypatch):
    server_metadata = json.loads(
        (ROOT / "server.json").read_text(encoding="utf-8")
    )
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    release_note = (
        ROOT / "docs" / "release_notes" / "v1.17.0.md"
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
    release_prefix, next_heading, _older_entries = changelog.partition(
        "## [1.16.4]"
    )
    assert next_heading == "## [1.16.4]"
    release_heading = "## [1.17.0] - 2026-08-05 (Agent Task Venue SDK)"
    release_start = release_prefix.index(release_heading)
    release_section = release_prefix[release_start:]
    assert release_section.startswith(release_heading)
    assert (
        "Public release promoted from the independently audited Private "
        "candidate"
    ) in release_section
    assert (
        "the two release-status documents are updated for Public release."
    ) in release_section
    assert "docs/release_notes/v1.17.0.md" in release_section
    assert "payment_surface_discovery.v1" in release_section
    assert "claim_task_or_observation_binding_mismatch" in release_section
    assert "Private Source Candidate is pending independent audit" not in (
        release_section
    )
    assert "pending independent re-audit" not in release_section

    assert release_note.startswith(
        "# Release v1.17.0 — Agent Task Venue SDK"
    )
    assert (
        "Version 1.17.0 is the public release of the Agent Task Venue SDK."
    ) in release_note
    assert "It promotes the independently audited Private candidate" in release_note
    assert "real-world SDK runtime acceptance is not inferred" in release_note
    assert "Private candidate behavior only" not in release_note
    assert "does not claim formal independent-audit approval" not in release_note
    assert "payment_surface_discovery.v1" in release_note
    assert "Host Agent" in release_note
    assert "claim_task_or_observation_binding_mismatch" in release_note

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
