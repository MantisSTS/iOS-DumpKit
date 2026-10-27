"""Runtime configuration models."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

DEFAULT_REMOTE_TEMP = "/tmp/ios-dumpkit-ng"
JAILBREAK_PATHS = (
    "/var/jb",
    "/private/preboot",
    "/cores/binpack",
    "/Applications",
    "/Library/MobileSubstrate",
    "/usr/lib/TweakInject",
)


@dataclass(slots=True)
class ConnectionConfig:
    """Frida connection settings."""

    usb: bool = True
    host: str | None = None
    device_id: str | None = None
    timeout: float = 30.0


@dataclass(slots=True)
class SshConfig:
    """SSH settings for filesystem operations."""

    host: str | None = None
    port: int = 22
    user: str | None = None
    password: str | None = None
    key_filename: Path | None = None
    timeout: float = 10.0

    @property
    def enabled(self) -> bool:
        return self.host is not None and self.user is not None


@dataclass(slots=True)
class DumpOptions:
    """Options controlling dump scope and output."""

    output: Path | None = None
    output_dir: Path = Path("dumps")
    main_only: bool = False
    include_extensions: bool = True
    include_frameworks: bool = True
    include_app_groups: bool = False
    analysis_artifacts: bool = False
    metadata_only: bool = False
    no_launch: bool = False
    attach_pid: int | None = None
    timeout: float = 60.0
    retry: int = 1
    keep_temp: bool = False
    remote_temp: str = DEFAULT_REMOTE_TEMP
    rootless: bool = False
    rootless_temp: str | None = None


@dataclass(slots=True)
class LogConfig:
    """Logging settings shared by CLI commands."""

    verbose: bool = False
    json_log: bool = False
    trace: Path | None = None
