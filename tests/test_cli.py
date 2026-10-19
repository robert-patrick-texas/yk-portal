import os
import signal
import stat
import time

import pytest

from yk_portal import main


def run(monkeypatch, *args: str) -> int:
    monkeypatch.setattr("sys.argv", ["yk-portal", *args])
    with pytest.raises(SystemExit) as excinfo:
        main()
    code = excinfo.value.code
    assert isinstance(code, int)
    return code


def test_master_key_create_at_a_path(tmp_path, monkeypatch, capsys):
    path = tmp_path / "master.key"
    assert run(monkeypatch, "master-key-create", str(path)) == 0
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert f"Created the master key {path}" in capsys.readouterr().out


def test_master_key_create_uses_the_configured_path(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    key = tmp_path / "configured.key"
    config.write_text(
        '[application]\npublic_base_url = "https://yk.example.com"\n'
        f'[security]\nmaster_key_path = "{key}"\n'
    )
    monkeypatch.setenv("YK_PORTAL_CONFIG", str(config))
    assert run(monkeypatch, "master-key-create") == 0
    assert key.exists()


def test_master_key_create_never_replaces_a_key(tmp_path, monkeypatch, capsys):
    path = tmp_path / "master.key"
    path.write_text("existing")
    assert run(monkeypatch, "master-key-create", str(path)) == 1
    assert "already exists" in capsys.readouterr().err
    assert path.read_text() == "existing"


def test_master_key_create_usage(monkeypatch, capsys):
    assert run(monkeypatch, "master-key-create", "--help") == 0
    assert "usage: yk-portal master-key-create" in capsys.readouterr().out
    assert run(monkeypatch, "master-key-create", "a", "b") == 2


def test_a_command_stopped_by_sigterm_ends_as_after_ctrl_c(monkeypatch):
    """Its transactions roll back and the file it was writing is removed (with blocks
    and finally clauses run), as for KeyboardInterrupt."""
    cleaned = []

    def command(argv):
        try:
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(5)
        finally:
            cleaned.append(True)

    monkeypatch.setattr("django.core.management.execute_from_command_line", command)
    handler = signal.getsignal(signal.SIGTERM)
    try:
        assert run(monkeypatch, "backup-create", "x") == 128 + signal.SIGTERM
    finally:
        signal.signal(signal.SIGTERM, handler)
    assert cleaned == [True]
