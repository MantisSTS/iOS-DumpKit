from __future__ import annotations

import posixpath

import pytest

from ios_dumpkit.config import DumpOptions
from ios_dumpkit.dumper import ROOTLESS_STAGING_DIRNAME, build_remote_job_dir
from ios_dumpkit.errors import DumpKitError

DATA_CONTAINER = "/var/mobile/Containers/Data/Application/0000-DEAD-BEEF"


def test_default_staging_uses_remote_temp() -> None:
    options = DumpOptions(remote_temp="/tmp/ios-dumpkit-ng")
    job_dir = build_remote_job_dir(options, "com.example.app", DATA_CONTAINER)

    assert job_dir.startswith("/tmp/ios-dumpkit-ng/com.example.app/")
    # The app container is ignored unless --rootless is set.
    assert DATA_CONTAINER not in job_dir


def test_rootless_staging_lives_inside_app_container() -> None:
    options = DumpOptions(rootless=True, remote_temp="/tmp/ios-dumpkit-ng")
    job_dir = build_remote_job_dir(options, "com.example.app", DATA_CONTAINER)

    expected_prefix = posixpath.join(
        DATA_CONTAINER, "tmp", ROOTLESS_STAGING_DIRNAME, "com.example.app"
    )
    assert job_dir.startswith(expected_prefix + "/")
    # Must not fall back to the sandbox-unwritable global temp root.
    assert not job_dir.startswith("/tmp/")


def test_rootless_temp_override_is_used_without_container() -> None:
    # An explicit staging root must work even when the container cannot be resolved.
    options = DumpOptions(
        rootless=True, rootless_temp="/var/mobile/Containers/Data/Application/X/tmp"
    )
    job_dir = build_remote_job_dir(options, "com.example.app", None)

    expected_prefix = posixpath.join(
        "/var/mobile/Containers/Data/Application/X/tmp",
        ROOTLESS_STAGING_DIRNAME,
        "com.example.app",
    )
    assert job_dir.startswith(expected_prefix + "/")


def test_rootless_temp_override_takes_precedence_over_container() -> None:
    options = DumpOptions(rootless=True, rootless_temp="/override/tmp")
    job_dir = build_remote_job_dir(options, "com.example.app", DATA_CONTAINER)

    assert job_dir.startswith("/override/tmp/")
    assert DATA_CONTAINER not in job_dir


def test_rootless_staging_is_unique_per_call() -> None:
    options = DumpOptions(rootless=True)
    first = build_remote_job_dir(options, "com.example.app", DATA_CONTAINER)
    second = build_remote_job_dir(options, "com.example.app", DATA_CONTAINER)

    assert first != second


@pytest.mark.parametrize("container", [None, ""])
def test_rootless_without_resolved_container_raises(container: str | None) -> None:
    options = DumpOptions(rootless=True)
    with pytest.raises(DumpKitError, match="sandbox container"):
        build_remote_job_dir(options, "com.example.app", container)
