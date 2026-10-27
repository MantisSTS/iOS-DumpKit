"""Typer CLI for ios-dumpkit-ng."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .app_resolver import AppResolver
from .config import DEFAULT_REMOTE_TEMP, ConnectionConfig, DumpOptions, SshConfig
from .doctor import Doctor
from .dumper import IOSDumper, build_progress
from .errors import DumpKitError
from .frida_client import FridaClient
from .logging import configure_logging
from .ssh_client import SshClient
from .verifier import verify_ipa

console = Console()
app = typer.Typer(
    add_completion=False,
    help=(
        "Modern Frida iOS dump/decryption toolkit for authorised mobile security testing. "
        "Use only on devices and apps you own or have written permission to assess."
    ),
)


def _connection(
    usb: bool, host: str | None, device_id: str | None, timeout: float
) -> ConnectionConfig:
    return ConnectionConfig(
        usb=usb and host is None, host=host, device_id=device_id, timeout=timeout
    )


def _ssh(
    ssh_host: str | None,
    ssh_port: int,
    ssh_user: str | None,
    ssh_pass: str | None,
    ssh_key: Path | None,
    timeout: float,
) -> SshConfig:
    return SshConfig(
        host=ssh_host,
        port=ssh_port,
        user=ssh_user,
        password=ssh_pass,
        key_filename=ssh_key,
        timeout=timeout,
    )


def _setup_logging(verbose: bool, json_log: bool, trace: Path | None) -> None:
    configure_logging(
        verbose=verbose,
        json_log=json_log,
        trace_path=trace,
        console=None if json_log else console,
    )


def _handle_error(exc: Exception) -> None:
    if isinstance(exc, DumpKitError):
        console.print(f"[red]error:[/red] {exc}")
        for item in exc.advice:
            console.print(f"  - {item}")
        raise typer.Exit(1)
    raise exc


def _print_apps(apps: list) -> None:
    table = Table("PID", "Name", "Bundle ID", "Executable", "Version")
    for application in apps:
        table.add_row(
            str(application.pid) if application.pid else "-",
            application.name,
            application.identifier,
            application.executable or "-",
            application.version or "-",
        )
    console.print(table)


@app.command("list")
def list_apps(
    query: Annotated[
        str | None, typer.Option("--search", "-s", help="Filter by bundle id, name, or executable.")
    ] = None,
    usb: Annotated[
        bool, typer.Option("--usb/--no-usb", help="Use the first USB iOS device.")
    ] = True,
    host: Annotated[
        str | None, typer.Option("--host", help="TCP frida-server host, e.g. 192.168.0.71.")
    ] = None,
    device_id: Annotated[
        str | None, typer.Option("--device-id", help="Specific Frida device id.")
    ] = None,
    timeout: Annotated[
        float, typer.Option("--timeout", help="Connection timeout in seconds.")
    ] = 30.0,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
    json_log: Annotated[bool, typer.Option("--json-log", help="Emit logs as JSON lines.")] = False,
    trace: Annotated[
        Path | None, typer.Option("--trace", help="Write full debug trace JSONL to this file.")
    ] = None,
) -> None:
    """List installed apps visible to Frida."""

    _setup_logging(verbose, json_log, trace)
    try:
        client = FridaClient(_connection(usb, host, device_id, timeout))
        client.connect()
        apps = AppResolver(client.enumerate_apps()).list_apps(query)
        _print_apps(apps)
    except Exception as exc:
        _handle_error(exc)


@app.command()
def doctor(
    target: Annotated[
        str | None, typer.Argument(help="Optional bundle id or app name to validate.")
    ] = None,
    usb: Annotated[
        bool, typer.Option("--usb/--no-usb", help="Use the first USB iOS device.")
    ] = True,
    host: Annotated[str | None, typer.Option("--host", help="TCP frida-server host.")] = None,
    device_id: Annotated[
        str | None, typer.Option("--device-id", help="Specific Frida device id.")
    ] = None,
    ssh_host: Annotated[
        str | None, typer.Option("--ssh-host", help="SSH host for filesystem checks.")
    ] = None,
    ssh_port: Annotated[int, typer.Option("--ssh-port", help="SSH port.")] = 22,
    ssh_user: Annotated[str | None, typer.Option("--ssh-user", help="SSH username.")] = None,
    ssh_pass: Annotated[
        str | None, typer.Option("--ssh-pass", help="SSH password. Not logged.")
    ] = None,
    ssh_key: Annotated[Path | None, typer.Option("--ssh-key", help="SSH private key path.")] = None,
    output_dir: Annotated[
        Path, typer.Option("--output-dir", help="Directory writeability check.")
    ] = Path("dumps"),
    timeout: Annotated[
        float, typer.Option("--timeout", help="Connection timeout in seconds.")
    ] = 30.0,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
    json_log: Annotated[bool, typer.Option("--json-log", help="Emit logs as JSON lines.")] = False,
    trace: Annotated[
        Path | None, typer.Option("--trace", help="Write full debug trace JSONL to this file.")
    ] = None,
) -> None:
    """Run host, Frida, SSH, filesystem, and target diagnostics."""

    _setup_logging(verbose, json_log, trace)
    report = Doctor(
        _connection(usb, host, device_id, timeout),
        _ssh(ssh_host, ssh_port, ssh_user, ssh_pass, ssh_key, timeout),
    ).run(target=target, output_dir=output_dir)
    table = Table("Status", "Check", "Detail", "Advice")
    for check in report.checks:
        table.add_row(
            "[green]OK[/green]" if check.ok else "[red]FAIL[/red]",
            check.name,
            check.detail,
            check.advice or "",
        )
    console.print(table)
    if not report.ok:
        raise typer.Exit(1)


@app.command()
def dump(
    target: Annotated[str, typer.Argument(help="Bundle id, display name, or executable name.")],
    usb: Annotated[
        bool, typer.Option("--usb/--no-usb", help="Use the first USB iOS device.")
    ] = True,
    host: Annotated[str | None, typer.Option("--host", help="TCP frida-server host.")] = None,
    device_id: Annotated[
        str | None, typer.Option("--device-id", help="Specific Frida device id.")
    ] = None,
    ssh_host: Annotated[
        str | None, typer.Option("--ssh-host", help="SSH host for SFTP transfer.")
    ] = None,
    ssh_port: Annotated[int, typer.Option("--ssh-port", help="SSH port.")] = 22,
    ssh_user: Annotated[str | None, typer.Option("--ssh-user", help="SSH username.")] = None,
    ssh_pass: Annotated[
        str | None, typer.Option("--ssh-pass", help="SSH password. Not logged.")
    ] = None,
    ssh_key: Annotated[Path | None, typer.Option("--ssh-key", help="SSH private key path.")] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Exact output IPA path.")
    ] = None,
    output_dir: Annotated[Path, typer.Option("--output-dir", help="Output directory.")] = Path(
        "dumps"
    ),
    main_only: Annotated[
        bool, typer.Option("--main-only", help="Dump only the main app executable.")
    ] = False,
    include_extensions: Annotated[
        bool,
        typer.Option(
            "--include-extensions/--no-include-extensions", help="Include PlugIns and extensions."
        ),
    ] = True,
    include_frameworks: Annotated[
        bool,
        typer.Option(
            "--include-frameworks/--no-include-frameworks", help="Include nested frameworks."
        ),
    ] = True,
    include_app_groups: Annotated[
        bool, typer.Option("--include-app-groups", help="Copy app-group containers when exposed.")
    ] = False,
    analysis_artifacts: Annotated[
        bool,
        typer.Option(
            "--analysis-artifacts",
            help=(
                "Write readable analysis artifacts such as ObjC headers, strings, "
                "symbols, and Mach-O summaries."
            ),
        ),
    ] = False,
    metadata_only: Annotated[
        bool, typer.Option("--metadata-only", help="Extract metadata without packaging IPA.")
    ] = False,
    no_launch: Annotated[
        bool, typer.Option("--no-launch", help="Attach only; do not launch app.")
    ] = False,
    attach_pid: Annotated[
        int | None, typer.Option("--attach-pid", help="Attach to a specific PID.")
    ] = None,
    timeout: Annotated[
        float, typer.Option("--timeout", help="Per-stage timeout in seconds.")
    ] = 60.0,
    retry: Annotated[
        int, typer.Option("--retry", help="Retry count for Frida RPC and attach stages.")
    ] = 1,
    keep_temp: Annotated[
        bool, typer.Option("--keep-temp", help="Keep local and remote temp files.")
    ] = False,
    rootless: Annotated[
        bool,
        typer.Option(
            "--rootless",
            help=(
                "Stage the on-device dump inside the target app's sandbox container "
                "instead of the global temp root. Use on rootless jailbreaks where "
                "the injected agent cannot write to /tmp (dump fails with "
                "'Operation not permitted')."
            ),
        ),
    ] = False,
    rootless_temp: Annotated[
        str | None,
        typer.Option(
            "--rootless-temp",
            help=(
                "Explicit on-device staging root for --rootless, used when the app "
                "sandbox container cannot be resolved automatically. Point it at a "
                "path the target app can write, e.g. its Data container tmp dir."
            ),
        ),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
    json_log: Annotated[bool, typer.Option("--json-log", help="Emit logs as JSON lines.")] = False,
    trace: Annotated[
        Path | None, typer.Option("--trace", help="Write full debug trace JSONL to this file.")
    ] = None,
) -> None:
    """Dump a decrypted IPA from an authorised jailbroken test device."""

    _setup_logging(verbose, json_log, trace)
    options = DumpOptions(
        output=output,
        output_dir=output_dir,
        main_only=main_only,
        include_extensions=include_extensions,
        include_frameworks=include_frameworks,
        include_app_groups=include_app_groups,
        analysis_artifacts=analysis_artifacts,
        metadata_only=metadata_only,
        no_launch=no_launch,
        attach_pid=attach_pid,
        timeout=timeout,
        retry=retry,
        keep_temp=keep_temp,
        rootless=rootless,
        rootless_temp=rootless_temp,
    )
    try:
        with build_progress() as progress:
            summary = IOSDumper(
                _connection(usb, host, device_id, timeout),
                _ssh(ssh_host, ssh_port, ssh_user, ssh_pass, ssh_key, timeout),
                progress=progress,
            ).dump(target, options)
        console.print(f"[green]bundle:[/green] {summary.bundle.bundle_id}")
        console.print(f"[green]metadata:[/green] {summary.metadata_dir}")
        if summary.package:
            console.print(f"[green]ipa:[/green] {summary.package.path}")
            console.print(f"[green]sha256:[/green] {summary.package.sha256}")
        console.print(f"[green]decrypted modules:[/green] {len(summary.dumped_modules)}")
        if summary.work_dir:
            console.print(f"[yellow]temp kept:[/yellow] {summary.work_dir}")
    except Exception as exc:
        _handle_error(exc)


@app.command()
def metadata(
    target: Annotated[str, typer.Argument(help="Bundle id, display name, or executable name.")],
    usb: Annotated[
        bool, typer.Option("--usb/--no-usb", help="Use the first USB iOS device.")
    ] = True,
    host: Annotated[str | None, typer.Option("--host", help="TCP frida-server host.")] = None,
    device_id: Annotated[
        str | None, typer.Option("--device-id", help="Specific Frida device id.")
    ] = None,
    ssh_host: Annotated[
        str | None, typer.Option("--ssh-host", help="SSH host for SFTP transfer.")
    ] = None,
    ssh_port: Annotated[int, typer.Option("--ssh-port", help="SSH port.")] = 22,
    ssh_user: Annotated[str | None, typer.Option("--ssh-user", help="SSH username.")] = None,
    ssh_pass: Annotated[
        str | None, typer.Option("--ssh-pass", help="SSH password. Not logged.")
    ] = None,
    ssh_key: Annotated[Path | None, typer.Option("--ssh-key", help="SSH private key path.")] = None,
    output_dir: Annotated[Path, typer.Option("--output-dir", help="Output directory.")] = Path(
        "dumps"
    ),
    analysis_artifacts: Annotated[
        bool,
        typer.Option(
            "--analysis-artifacts",
            help=(
                "Write readable analysis artifacts such as ObjC headers, strings, "
                "symbols, and Mach-O summaries."
            ),
        ),
    ] = False,
    no_launch: Annotated[
        bool, typer.Option("--no-launch", help="Attach only; do not launch app.")
    ] = False,
    attach_pid: Annotated[
        int | None, typer.Option("--attach-pid", help="Attach to a specific PID.")
    ] = None,
    timeout: Annotated[
        float, typer.Option("--timeout", help="Per-stage timeout in seconds.")
    ] = 60.0,
    retry: Annotated[
        int, typer.Option("--retry", help="Retry count for Frida RPC and attach stages.")
    ] = 1,
    keep_temp: Annotated[bool, typer.Option("--keep-temp", help="Keep temp files.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
    json_log: Annotated[bool, typer.Option("--json-log", help="Emit logs as JSON lines.")] = False,
    trace: Annotated[
        Path | None, typer.Option("--trace", help="Write full debug trace JSONL to this file.")
    ] = None,
) -> None:
    """Extract metadata files without building an IPA."""

    _setup_logging(verbose, json_log, trace)
    options = DumpOptions(
        output_dir=output_dir,
        metadata_only=True,
        analysis_artifacts=analysis_artifacts,
        no_launch=no_launch,
        attach_pid=attach_pid,
        timeout=timeout,
        retry=retry,
        keep_temp=keep_temp,
    )
    try:
        with build_progress() as progress:
            summary = IOSDumper(
                _connection(usb, host, device_id, timeout),
                _ssh(ssh_host, ssh_port, ssh_user, ssh_pass, ssh_key, timeout),
                progress=progress,
            ).dump(target, options)
        console.print(f"[green]metadata:[/green] {summary.metadata_dir}")
    except Exception as exc:
        _handle_error(exc)


@app.command()
def verify(
    ipa: Annotated[Path, typer.Argument(help="IPA path to verify.")],
) -> None:
    """Verify IPA structure and Mach-O cryptid state."""

    result = verify_ipa(ipa)
    if result.valid:
        console.print(f"[green]valid:[/green] {ipa}")
    else:
        console.print(f"[red]invalid:[/red] {ipa}")
    if result.app_bundle:
        console.print(f"app bundle: {result.app_bundle}")
    for error in result.errors:
        console.print(f"[red]error:[/red] {error}")
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/yellow] {warning}")
    if result.encrypted_binaries:
        table = Table("Encrypted Mach-O")
        for name in result.encrypted_binaries:
            table.add_row(name)
        console.print(table)
    if not result.valid:
        raise typer.Exit(1)


@app.command()
def clean(
    ssh_host: Annotated[
        str | None, typer.Option("--ssh-host", help="SSH host for remote cleanup.")
    ] = None,
    ssh_port: Annotated[int, typer.Option("--ssh-port", help="SSH port.")] = 22,
    ssh_user: Annotated[str | None, typer.Option("--ssh-user", help="SSH username.")] = None,
    ssh_pass: Annotated[
        str | None, typer.Option("--ssh-pass", help="SSH password. Not logged.")
    ] = None,
    ssh_key: Annotated[Path | None, typer.Option("--ssh-key", help="SSH private key path.")] = None,
    remote_temp: Annotated[
        str, typer.Option("--remote-temp", help="Remote temp root to remove.")
    ] = DEFAULT_REMOTE_TEMP,
    timeout: Annotated[float, typer.Option("--timeout", help="SSH timeout in seconds.")] = 10.0,
) -> None:
    """Remove ios-dumpkit-ng remote temp files over SFTP."""

    ssh_config = _ssh(ssh_host, ssh_port, ssh_user, ssh_pass, ssh_key, timeout)
    if not ssh_config.enabled:
        console.print("[yellow]SSH config not supplied; nothing remote was removed.[/yellow]")
        raise typer.Exit(0)
    try:
        with SshClient(ssh_config) as ssh:
            ssh.remove_tree(remote_temp)
        console.print(f"[green]removed:[/green] {remote_temp}")
    except Exception as exc:
        _handle_error(exc)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
