"""Writing a file that holds secrets: mode 0600, and all of it or nothing.

Used by radiator-export and backup-create.
"""

import errno
import os
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO


class FileWriteError(Exception):
    """The file can't be written. Nothing was written."""


@contextmanager
def new_file(path: Path, force: bool) -> Generator[BinaryIO]:
    """Write PATH in the block, mode 0600, replacing an existing file only if FORCE.

    The block writes to a temporary file in the same directory, which becomes PATH
    once the block ends. If the block raises, the temporary file is removed, so a
    failure leaves no partial file behind.

    Raises:
        FileWriteError: PATH exists (without FORCE), is a directory, or can't be written.
    """
    if path.is_dir():
        raise FileWriteError(f"{path} is a directory")
    if not force and (path.exists() or path.is_symlink()):
        raise FileWriteError(f"{path} already exists (use --force to replace it)")
    try:
        # mkstemp creates the file with mode 0600, whatever the umask.
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".yk-portal.")
    except OSError as e:
        raise FileWriteError(f"cannot write to the directory {path.parent}: {e.strerror}") from None
    try:
        with os.fdopen(fd, "wb") as file:
            yield file
            file.flush()
            os.fsync(file.fileno())
        if force:
            os.replace(temporary, path)
        else:
            _rename_unless_taken(Path(temporary), path)
    except FileExistsError:
        raise FileWriteError(f"{path} already exists (use --force to replace it)") from None
    except OSError as e:
        raise FileWriteError(f"cannot write {path}: {e.strerror}") from None
    finally:
        Path(temporary).unlink(missing_ok=True)
    _sync_directory(path.parent)


def _rename_unless_taken(temporary: Path, path: Path) -> None:
    """Give TEMPORARY the name PATH, unless PATH exists.

    A link fails if PATH appeared meanwhile, where a rename would replace it. File
    systems without links (FAT, some network ones) get a check, then a rename.
    """
    try:
        os.link(temporary, path)
    except FileExistsError:
        raise
    except OSError as e:
        if e.errno not in (errno.EPERM, errno.EOPNOTSUPP, errno.ENOTSUP):
            raise
        if path.exists() or path.is_symlink():
            raise FileExistsError(path) from None
        os.rename(temporary, path)


def _sync_directory(directory: Path) -> None:
    """Make the new name in DIRECTORY survive a power cut, where the file system can."""
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass  # the file is complete; some file systems can't sync a directory
