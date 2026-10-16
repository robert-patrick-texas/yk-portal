"""yk-portal: a web portal to manage user accounts and YubiKey OTP credentials."""

import os
import sys


def main() -> None:
    """Run the yk-portal command: Django's management commands, with production settings.

    master-key-create runs before Django starts, because the production settings
    derive Django's secret key from the master key it creates.
    """
    if sys.argv[1:2] == ["master-key-create"]:
        sys.exit(master_key_create(sys.argv[2:]))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "yk_portal.settings.production")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


def master_key_create(args: list[str]) -> int:
    """yk-portal master-key-create [PATH]: write a new master key (spec §22.4)."""
    from pathlib import Path

    from .core.config import ConfigError, load_config
    from .core.master_key import MasterKeyError, create_master_key

    usage = (
        "usage: yk-portal master-key-create [PATH]\n"
        "Writes a new master key to PATH (default: master_key_path in the configuration)."
    )
    if args[:1] in (["-h"], ["--help"]):
        print(usage)
        return 0
    if len(args) > 1:
        print(usage, file=sys.stderr)
        return 2
    try:
        path = Path(args[0]) if args else load_config().master_key_path
        create_master_key(path)
    except (ConfigError, MasterKeyError) as e:
        print(f"yk-portal: {e}", file=sys.stderr)
        return 1
    print(f"Created the master key {path} (mode 0600).")
    print("Back it up somewhere safe: without it, stored YubiKey secrets and backups are lost.")
    return 0
