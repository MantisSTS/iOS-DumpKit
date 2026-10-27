"""High-level dump orchestration."""

from __future__ import annotations

import posixpath
import shutil
import tempfile
import uuid
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TransferSpeedColumn

from .analysis import write_objc_runtime_artifacts, write_static_analysis_artifacts
from .app_resolver import AppResolver
from .config import ConnectionConfig, DumpOptions, SshConfig
from .device import AppInfo, BundleInfo, ModuleInfo, bundle_info_from_agent
from .errors import DEFAULT_RECOVERY_ADVICE, AppLifecycleError, DumpKitError, RpcCallError, SshError
from .frida_client import FridaClient, RpcInvoker
from .logging import get_logger, stage
from .macho import MachOError, patch_cryptid_file
from .metadata import AppMetadata, write_metadata
from .packager import PackageResult, build_ipa
from .ssh_client import SshClient
from .verifier import VerificationResult, verify_ipa

log = get_logger(__name__)

# Basename reused for the on-device staging directory, mirroring DEFAULT_REMOTE_TEMP.
ROOTLESS_STAGING_DIRNAME = "ios-dumpkit-ng"


def build_remote_job_dir(
    options: DumpOptions,
    identifier: str,
    data_container: str | None,
) -> str:
    """Build the on-device directory the agent writes decrypted modules into.

    On rootless jailbreaks the Frida agent runs inside the target app's sandbox
    and cannot write to a global temp root such as ``/tmp`` (the write fails with
    ``Operation not permitted``). When ``options.rootless`` is set, stage the dump
    inside a sandbox-writable location instead:

    * ``options.rootless_temp`` when given -- an explicit staging root the user
      knows the app can write (e.g. ``<data-container>/tmp``); or
    * the app's own Data container (``<container>/tmp``), resolved automatically
      from the agent's reported sandbox ``HOME``.

    Either way the SSH user can still read the result back for transfer.
    """

    job = uuid.uuid4().hex
    if options.rootless:
        if options.rootless_temp:
            return posixpath.join(options.rootless_temp, ROOTLESS_STAGING_DIRNAME, identifier, job)
        if not data_container:
            raise DumpKitError(
                "Rootless dump requested but the app sandbox container could not be "
                "resolved from the agent (its sandbox HOME was empty). Pass "
                "--rootless-temp with a path the target app can write, e.g. its "
                "Data container tmp dir "
                "(/var/mobile/Containers/Data/Application/<UUID>/tmp), then retry."
            )
        return posixpath.join(data_container, "tmp", ROOTLESS_STAGING_DIRNAME, identifier, job)
    return posixpath.join(options.remote_temp, identifier, job)


@dataclass(slots=True)
class DumpSummary:
    """Dump command result."""

    app: AppInfo
    bundle: BundleInfo
    package: PackageResult | None
    metadata: AppMetadata
    metadata_dir: Path
    verification: VerificationResult | None
    dumped_modules: list[ModuleInfo]
    work_dir: Path | None


class IOSDumper:
    """Coordinates Frida, transfer, Mach-O patching, metadata, and packaging."""

    def __init__(
        self,
        connection: ConnectionConfig,
        ssh_config: SshConfig | None = None,
        *,
        progress: Progress | None = None,
    ) -> None:
        self.connection = connection
        self.ssh_config = ssh_config or SshConfig()
        self.progress = progress
        self.frida_client = FridaClient(connection)

    def dump(self, target: str, options: DumpOptions) -> DumpSummary:
        with stage(log, "connecting Frida"):
            device = self.frida_client.connect()
            _ = device
        with stage(log, "resolving target"):
            apps = self.frida_client.enumerate_apps()
            resolved = AppResolver(apps).resolve(target)
            app = resolved.app
            log.info(
                "target resolved: %s (%s) via %s",
                app.identifier,
                app.name,
                resolved.matched_by,
            )

        ssh: SshClient | None = None
        if self.ssh_config.enabled:
            with stage(log, "checking SSH"):
                ssh = SshClient(self.ssh_config)
                ssh.connect()

        temp_root = Path(tempfile.mkdtemp(prefix="ios-dumpkit-"))
        remote_job_dir = posixpath.join(options.remote_temp, app.identifier, uuid.uuid4().hex)
        session = None
        try:
            with stage(log, "launching app" if not options.attach_pid else "attaching"):
                session = self.frida_client.attach_or_launch(
                    app.identifier,
                    current_pid=app.pid,
                    attach_pid=options.attach_pid,
                    no_launch=options.no_launch,
                    timeout=options.timeout,
                    retry=options.retry,
                )
                rpc = RpcInvoker(session.script)

            with stage(log, "enumerating modules"):
                bundle = bundle_info_from_agent(
                    dict(rpc.call("getbundleinfo", timeout=options.timeout, retry=options.retry))
                )
                raw_modules = rpc.call(
                    "enumeratemodules", timeout=options.timeout, retry=options.retry
                )
                modules = self.frida_client.modules_from_payload(raw_modules)
                selected = self._select_modules(modules, bundle, options)
                log.info("encrypted module candidates: %d", len(selected))

            remote_job_dir = build_remote_job_dir(options, app.identifier, bundle.data_container)
            if options.rootless:
                log.info("rootless mode: staging dump inside app container %s", remote_job_dir)

            local_bundle = temp_root / bundle.app_name
            if not local_bundle.name.endswith(".app"):
                local_bundle = temp_root / PurePosixPath(bundle.bundle_path).name

            with stage(log, "copying bundle"):
                if ssh is not None:
                    ssh.download_tree(bundle.bundle_path, local_bundle, self._progress)
                else:
                    self._download_tree_via_frida(rpc, bundle.bundle_path, local_bundle, options)

            dumped_modules: list[ModuleInfo] = []
            if not options.metadata_only:
                with stage(log, "dumping binary"):
                    if ssh is not None:
                        ssh.mkdir_p(remote_job_dir)
                    else:
                        rpc.call(
                            "ensuredir",
                            remote_job_dir,
                            timeout=options.timeout,
                            retry=options.retry,
                        )

                    for module in selected:
                        if session.detached.is_set():
                            raise AppLifecycleError(
                                f"App exited during dump: {module.path}",
                                advice=DEFAULT_RECOVERY_ADVICE,
                            )
                        remote_dump = posixpath.join(
                            remote_job_dir, f"{uuid.uuid4().hex}-{module.name}"
                        )
                        result = rpc.call(
                            "dumpmodule",
                            module.path,
                            remote_dump,
                            timeout=options.timeout,
                            retry=options.retry,
                        )
                        dumped_path = str(dict(result).get("outPath") or remote_dump)
                        local_dump = temp_root / "decrypted" / (module.relative_path or module.name)
                        if ssh is not None:
                            ssh.download_file(dumped_path, local_dump, self._progress)
                        else:
                            self._download_file_via_frida(rpc, dumped_path, local_dump, options)
                        self._replace_module(local_bundle, bundle, module, local_dump)
                        dumped_modules.append(module)

                with stage(log, "replacing binary"):
                    for module in dumped_modules:
                        target_path = local_bundle / (module.relative_path or module.name)
                        if target_path.exists():
                            try:
                                patch_cryptid_file(target_path)
                            except MachOError as exc:
                                log.warning(
                                    "Mach-O cryptid patch skipped for %s: %s", target_path, exc
                                )

            metadata_dir = options.output_dir / f"{app.identifier}-metadata"
            with stage(log, "extracting metadata"):
                metadata = write_metadata(local_bundle, metadata_dir)

            if options.analysis_artifacts:
                with stage(log, "writing analysis artifacts"):
                    analysis_dir = options.output_dir / f"{app.identifier}-analysis"
                    write_static_analysis_artifacts(local_bundle, analysis_dir)
                    module_names = sorted(
                        {module.name for module in modules if module.is_app_module and module.name}
                    )
                    objc_payload = dict(
                        rpc.call(
                            "enumerateobjcclasses",
                            module_names,
                            timeout=options.timeout,
                            retry=options.retry,
                        )
                    )
                    class_count = write_objc_runtime_artifacts(objc_payload, analysis_dir)
                    log.info("Objective-C runtime headers written: %d", class_count)

            if options.include_app_groups and metadata.app_groups:
                with stage(log, "copying app groups"):
                    group_paths = dict(
                        rpc.call(
                            "getgroupcontainers",
                            metadata.app_groups,
                            timeout=options.timeout,
                            retry=options.retry,
                        )
                    )
                    for group_id, group_path in group_paths.items():
                        if not group_path:
                            continue
                        safe_group = group_id.replace("/", "_").replace(":", "_")
                        destination = metadata_dir / "app_groups" / safe_group
                        if ssh is not None:
                            ssh.download_tree(str(group_path), destination, self._progress)
                        else:
                            self._download_tree_via_frida(
                                rpc, str(group_path), destination, options
                            )

            package: PackageResult | None = None
            verification: VerificationResult | None = None
            if not options.metadata_only:
                with stage(log, "packaging IPA"):
                    package = build_ipa(
                        local_bundle,
                        output=options.output,
                        output_dir=None if options.output else options.output_dir,
                    )
                with stage(log, "verifying output"):
                    verification = verify_ipa(package.path)
                    if not verification.valid:
                        raise DumpKitError(
                            "Final IPA verification failed.",
                            advice=tuple(verification.errors + verification.warnings),
                        )

            work_dir = temp_root if options.keep_temp else None
            return DumpSummary(
                app=app,
                bundle=bundle,
                package=package,
                metadata=metadata,
                metadata_dir=metadata_dir,
                verification=verification,
                dumped_modules=dumped_modules,
                work_dir=work_dir,
            )
        finally:
            if session is not None:
                with suppress(Exception):
                    session.script.unload()
                with suppress(Exception):
                    session.session.detach()
            if ssh is not None:
                if not options.keep_temp:
                    try:
                        ssh.remove_tree(remote_job_dir)
                    except SshError:
                        log.debug("Remote cleanup failed for %s", remote_job_dir)
                ssh.close()
            if not options.keep_temp:
                shutil.rmtree(temp_root, ignore_errors=True)

    def metadata(self, target: str, options: DumpOptions) -> DumpSummary:
        options.metadata_only = True
        return self.dump(target, options)

    def _select_modules(
        self,
        modules: list[ModuleInfo],
        bundle: BundleInfo,
        options: DumpOptions,
    ) -> list[ModuleInfo]:
        selected: list[ModuleInfo] = []
        for module in modules:
            if not module.is_app_module or not module.encrypted:
                continue
            if options.main_only and not module.is_main:
                continue
            if module.is_framework and not options.include_frameworks:
                continue
            if module.is_extension and not options.include_extensions:
                continue
            relative = module.relative_path or self._relative_to_bundle(bundle, module.path)
            selected.append(
                ModuleInfo(
                    name=module.name,
                    path=module.path,
                    base=module.base,
                    size=module.size,
                    is_app_module=module.is_app_module,
                    is_main=module.is_main,
                    is_framework=module.is_framework,
                    is_extension=module.is_extension,
                    encrypted=module.encrypted,
                    encryption=module.encryption,
                    macho_type=module.macho_type,
                    relative_path=relative,
                )
            )
        return selected

    @staticmethod
    def _relative_to_bundle(bundle: BundleInfo, path: str) -> str:
        bundle_path = bundle.bundle_path.rstrip("/")
        if path.startswith(bundle_path + "/"):
            return path[len(bundle_path) + 1 :]
        return PurePosixPath(path).name

    def _replace_module(
        self,
        local_bundle: Path,
        bundle: BundleInfo,
        module: ModuleInfo,
        local_dump: Path,
    ) -> None:
        relative = module.relative_path or self._relative_to_bundle(bundle, module.path)
        target = local_bundle / relative
        if not target.exists():
            raise RpcCallError(f"Cannot replace decrypted binary; local path missing: {target}")
        shutil.copy2(local_dump, target)
        target.chmod(target.stat().st_mode | 0o755)

    def _download_tree_via_frida(
        self,
        rpc: RpcInvoker,
        remote_path: str,
        local_path: Path,
        options: DumpOptions,
    ) -> None:
        listing = dict(
            rpc.call("listfiles", remote_path, timeout=options.timeout, retry=options.retry)
        )
        for directory in listing.get("dirs", []):
            (local_path / str(directory)).mkdir(parents=True, exist_ok=True)
        local_path.mkdir(parents=True, exist_ok=True)
        for rel in listing.get("files", []):
            self._download_file_via_frida(
                rpc,
                posixpath.join(remote_path, str(rel)),
                local_path / str(rel),
                options,
            )

    def _download_file_via_frida(
        self,
        rpc: RpcInvoker,
        remote_path: str,
        local_path: Path,
        options: DumpOptions,
    ) -> None:
        stat_payload = dict(
            rpc.call("statpath", remote_path, timeout=options.timeout, retry=options.retry)
        )
        if not stat_payload.get("exists"):
            raise RpcCallError(f"Remote path does not exist: {remote_path}")
        size = int(stat_payload.get("size") or 0)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        chunk_size = 1024 * 1024
        transferred = 0
        with local_path.open("wb") as handle:
            while transferred < size:
                read_size = min(chunk_size, size - transferred)
                chunk = rpc.call(
                    "readfile",
                    remote_path,
                    transferred,
                    read_size,
                    timeout=options.timeout,
                    retry=options.retry,
                )
                payload = bytes(chunk)
                if not payload:
                    raise RpcCallError(f"Short read while downloading {remote_path}")
                handle.write(payload)
                transferred += len(payload)
                self._progress(remote_path, size, transferred)

    def _progress(self, label: str, total: int, done: int) -> None:
        if self.progress is None:
            return
        task_id = self.progress.task_ids[0] if self.progress.task_ids else None
        if task_id is None:
            task_id = self.progress.add_task(label, total=max(total, 1))
        self.progress.update(
            task_id, description=Path(label).name, total=max(total, 1), completed=done
        )


def build_progress() -> Progress:
    return Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TransferSpeedColumn(),
    )
