import errno
import os
import stat

import pytest

from yk_portal.core import files
from yk_portal.core.files import FileWriteError, new_file


def write(path, data=b"secret", force=False) -> None:
    with new_file(path, force) as file:
        file.write(data)


def test_mode_0600_and_no_temporary_file_left(tmp_path):
    path = tmp_path / "out"
    write(path)
    assert path.read_bytes() == b"secret"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert list(tmp_path.iterdir()) == [path]


def test_a_failure_in_the_block_leaves_nothing(tmp_path):
    with pytest.raises(RuntimeError), new_file(tmp_path / "out", force=False) as file:
        file.write(b"half")
        raise RuntimeError
    assert list(tmp_path.iterdir()) == []


def no_links(*args):
    raise OSError(errno.EPERM, "Operation not permitted")


def test_a_file_system_without_links(tmp_path, monkeypatch):
    """Such as FAT on a USB stick: a check, then a rename."""
    monkeypatch.setattr(os, "link", no_links)
    path = tmp_path / "out"
    write(path)
    assert path.read_bytes() == b"secret"
    with pytest.raises(FileWriteError, match="already exists"):
        write(path, b"other")
    assert path.read_bytes() == b"secret"
    assert list(tmp_path.iterdir()) == [path]


def test_another_link_error_is_reported(tmp_path, monkeypatch):
    def full(*args):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "link", full)
    with pytest.raises(FileWriteError, match="cannot write .*: No space left on device"):
        write(tmp_path / "out")
    assert list(tmp_path.iterdir()) == []


def test_a_directory_that_cant_be_synced(tmp_path, monkeypatch):
    real_open = os.open

    def refuse_directories(path, flags, *args):
        if flags & os.O_DIRECTORY:
            raise OSError(errno.EINVAL, "Invalid argument")
        return real_open(path, flags, *args)

    monkeypatch.setattr(files.os, "open", refuse_directories)
    write(tmp_path / "out")  # complete, so not a failure
    assert (tmp_path / "out").read_bytes() == b"secret"
