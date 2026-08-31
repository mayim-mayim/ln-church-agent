import os
import stat
import subprocess
import sys
import textwrap
import time

import pytest

from ln_church_agent.task_journal import JournalError, TaskJournal


TASK_ID = "task_native_platform"
HANDLE = "cred_" + "1" * 64
MANIFEST_DIGEST = "3" * 64
DEFINITION_DIGEST = "4" * 64


def _journal(path):
    return TaskJournal(
        path,
        task_id=TASK_ID,
        local_claim_credential_handle=HANDLE,
        task_type="scheduled_http_get_batch.v1",
        task_definition_version="1.0.0",
        task_definition_digest=DEFINITION_DIGEST,
    )


@pytest.mark.skipif(os.name == "nt", reason="native POSIX qualification only")
def test_linux_or_macos_real_atomic_replace_file_and_directory_fsync(tmp_path):
    journal = _journal(tmp_path / "native.journal")
    journal.create()
    before = journal.path.stat()
    journal.mark_offer_rechecked(MANIFEST_DIGEST)
    after = journal.path.stat()
    assert before.st_ino != after.st_ino
    assert stat.S_IMODE(after.st_mode) == 0o600
    assert journal.load().state == "OFFER_RECHECKED"
    assert journal.load().payload["manifest_sha256"] == MANIFEST_DIGEST
    # Success is evidence from the real os.replace/file-fsync/directory-fsync
    # path; no os.name substitution or filesystem mock is used.


@pytest.mark.skipif(os.name == "nt", reason="native POSIX fcntl qualification only")
def test_native_stable_sibling_fcntl_lock_excludes_second_process(tmp_path):
    path = tmp_path / "locked.journal"
    journal = _journal(path)
    journal.create()
    ready = tmp_path / "ready"
    script = textwrap.dedent(
        """
        import sys
        import time
        from pathlib import Path
        from ln_church_agent.task_journal import _StableLock

        lock_path, ready = sys.argv[1:]
        with _StableLock(Path(lock_path)):
            Path(ready).write_text("ready", encoding="ascii")
            time.sleep(10)
        """
    )
    child = subprocess.Popen(
        [sys.executable, "-c", script, str(journal.lock_path), str(ready)],
        env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path)),
    )
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready.exists()
        with pytest.raises(JournalError, match="^JOURNAL_LOCKED$"):
            journal.load()
    finally:
        child.terminate()
        child.wait(timeout=5)
    assert journal.load().state == "INIT"


@pytest.mark.skipif(os.name == "nt", reason="native POSIX fcntl qualification only")
def test_native_completion_operation_guard_is_cross_process_and_crash_released(
    tmp_path,
):
    path = tmp_path / "completion-guard.journal"
    journal = _journal(path)
    journal.create()
    ready = tmp_path / "completion-ready"
    crash = tmp_path / "completion-crash"
    script = textwrap.dedent(
        """
        import os
        import sys
        import time
        from pathlib import Path
        from ln_church_agent.task_journal import TaskJournal

        path, ready, crash = sys.argv[1:]
        journal = TaskJournal(
            path,
            task_id=%r,
            local_claim_credential_handle=%r,
            task_type="scheduled_http_get_batch.v1",
            task_definition_version="1.0.0",
            task_definition_digest=%r,
        )
        with journal.completion_operation_guard():
            Path(ready).write_text("ready", encoding="ascii")
            while not Path(crash).exists():
                time.sleep(0.01)
            os._exit(75)
        """
        % (TASK_ID, HANDLE, DEFINITION_DIGEST)
    )
    child = subprocess.Popen(
        [sys.executable, "-c", script, str(path), str(ready), str(crash)],
        env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path)),
    )
    deadline = time.monotonic() + 5
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ready.exists()
    with pytest.raises(JournalError, match="^JOURNAL_LOCKED$"):
        with journal.completion_operation_guard():
            pass
    crash.write_text("crash", encoding="ascii")
    assert child.wait(timeout=5) == 75
    with journal.completion_operation_guard():
        assert journal.load().state == "INIT"
    if os.name != "nt":
        assert stat.S_IMODE(journal.completion_lock_path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "nt", reason="deferred native Windows qualification")
def test_native_windows_closed_handle_replace_and_msvcrt_lock(tmp_path):
    # This test must run on native Windows; a mock of os.name is not evidence.
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        pytest.fail("LOCALAPPDATA is required for native Windows qualification")
    claims = os.path.join(local, "ln-church-agent", "claims")
    os.makedirs(claims, exist_ok=True)
    path = os.path.join(claims, "native-v18-qualification.journal")
    if os.path.exists(path):
        os.unlink(path)
    journal = _journal(path)
    journal.create()
    journal.mark_offer_rechecked(MANIFEST_DIGEST)
    assert journal.load().state == "OFFER_RECHECKED"
    assert journal.load().payload["manifest_sha256"] == MANIFEST_DIGEST
    with journal.completion_operation_guard():
        contender = _journal(path)
        with pytest.raises(JournalError, match="^JOURNAL_LOCKED$"):
            with contender.completion_operation_guard():
                pass
