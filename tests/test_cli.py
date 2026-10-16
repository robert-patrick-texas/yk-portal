import stat

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
