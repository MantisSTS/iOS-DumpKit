# ios-dumpkit-ng

`ios-dumpkit-ng` is a modern Frida-based iOS app dump/decryption toolkit for authorised mobile application security testing.

It is designed as a cleaner, maintained replacement for older `frida-ios-dump` style tools, with better diagnostics, safer target resolution, modern Frida support, rootless jailbreak awareness, and more reliable IPA packaging.

> Authorised testing only. Use this tool only on devices and applications you own, operate, or have explicit written permission to assess. Do not use it for unauthorised app dumping, piracy, credential theft, stealth, persistence, or bypassing device ownership controls.

## Features

- Frida 17+ support with host and remote version checks
- USB Frida, TCP Frida, SSH/SFTP transfer, and iproxy-friendly workflows
- Safe app resolution by bundle id, display name, or executable name
- Ambiguous display-name detection with clear candidate output
- Handles app names with spaces, unicode, apostrophes, and shell-sensitive characters
- Rootful and rootless jailbreak path awareness
- App bundle path resolution through Frida/system APIs where possible
- Stage-level progress and structured diagnostics
- RPC timeouts and retries for long Frida operations
- App crash and process-detach detection
- Mach-O `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64` cryptid patching
- IPA creation with Python `zipfile`, not shell `zip`
- IPA verification for `Payload/*.app`, `Info.plist`, executable permissions, and remaining encrypted Mach-O files
- Metadata export including entitlements, URL schemes, ATS, associated domains, app groups, and dylib imports/exports
- Optional readable analysis artifacts: Objective-C runtime headers, strings, symbols, Mach-O summaries, and best-effort disassembly
- Trace logging with `--trace`

## Status

This project is intended for real-device authorised testing, but iOS jailbreak environments vary heavily. Treat the tool as security-testing infrastructure: run `doctor`, capture traces, and validate output IPAs before relying on results in a report.

## Requirements

Host:

- Python 3.11 or newer
- Frida Python package 17+
- `frida-tools`
- `typer`, `rich`, `paramiko`, `scp`, `packaging`

Device:

- Jailbroken 64-bit iOS test device
- Matching `frida-server` version
- Unlocked and trusted device
- Optional SSH/SFTP access for faster transfer

Supported connection patterns:

- Frida over USB
- Frida over TCP with `--host`
- Frida over USB plus SSH/SFTP over WiFi
- Frida over USB plus SSH/SFTP through iproxy
- TCP Frida plus SSH/SFTP when remote Frida is reachable

## Installation

Developer install:

```bash
python -m pip install -e ".[dev]"
```

Runtime install:

```bash
python -m pip install .
```

Confirm the CLI is available:

```bash
ios-dumpkit --help
```

## Quick Start

Use USB first. It is usually the most reliable path.

```bash
ios-dumpkit doctor --usb
ios-dumpkit list --usb
ios-dumpkit dump com.example.app --usb --output-dir ./dumps
```

Verify the resulting IPA:

```bash
ios-dumpkit verify ./dumps/Example.ipa
```

## Command Overview

```bash
ios-dumpkit doctor [target]
ios-dumpkit list [--search text]
ios-dumpkit dump <bundle-id-or-name>
ios-dumpkit metadata <bundle-id-or-name>
ios-dumpkit clean
ios-dumpkit verify <ipa>
```

## Target Resolution

Internally, `ios-dumpkit-ng` prefers bundle identifiers. You can still pass a display name or executable name:

```bash
ios-dumpkit dump com.example.app --usb
ios-dumpkit dump "Example App" --usb
ios-dumpkit dump ExampleExecutable --usb
```

If a display name matches multiple apps, the tool prints candidates and requires the exact bundle id.

Search installed apps:

```bash
ios-dumpkit list --usb --search example
```

## USB Workflow

```bash
ios-dumpkit doctor --usb
ios-dumpkit list --usb
ios-dumpkit dump com.example.app --usb --output-dir ./dumps
```

Add tracing for diagnostics:

```bash
ios-dumpkit dump com.example.app --usb --output-dir ./dumps --trace trace.jsonl --verbose
```

## USB Frida With SSH/SFTP Transfer

This is often the best real-device workflow: Frida stays on reliable USB, while bundle transfer uses SSH/SFTP.

```bash
ios-dumpkit doctor --usb --ssh-host 192.168.0.71 --ssh-user root --ssh-pass '<password>'
ios-dumpkit dump com.example.app \
  --usb \
  --ssh-host 192.168.0.71 \
  --ssh-user root \
  --ssh-pass '<password>' \
  --output-dir ./dumps
```

Key-based SSH:

```bash
ios-dumpkit dump com.example.app \
  --usb \
  --ssh-host 192.168.0.71 \
  --ssh-user root \
  --ssh-key ~/.ssh/ios-test-device \
  --output-dir ./dumps
```

Passwords are not logged.

## WiFi / TCP Frida Workflow

Only use `--host` after confirming TCP Frida works:

```bash
frida-ps -H 192.168.0.71 -ai
```

Then:

```bash
ios-dumpkit doctor --host 192.168.0.71
ios-dumpkit list --host 192.168.0.71
ios-dumpkit dump com.example.app --host 192.168.0.71 --output-dir ./dumps
```

With SSH/SFTP transfer:

```bash
ios-dumpkit dump com.example.app \
  --host 192.168.0.71 \
  --ssh-host 192.168.0.71 \
  --ssh-user root \
  --ssh-pass '<password>' \
  --output-dir ./dumps
```

If `frida-ps -Uai` works but `frida-ps -H <host> -ai` fails, use `--usb` for Frida and configure SSH separately.

## iproxy Workflow

Forward the device SSH port with your preferred iproxy command, then point SSH at localhost:

```bash
ios-dumpkit dump com.example.app \
  --usb \
  --ssh-host 127.0.0.1 \
  --ssh-port 2222 \
  --ssh-user root \
  --ssh-pass '<password>' \
  --output-dir ./dumps
```

If you also expose Frida over localhost, validate it first:

```bash
frida-ps -H 127.0.0.1 -ai
```

Then:

```bash
ios-dumpkit dump com.example.app \
  --host 127.0.0.1 \
  --ssh-host 127.0.0.1 \
  --ssh-port 2222 \
  --ssh-user root \
  --ssh-pass '<password>' \
  --output-dir ./dumps
```

## Dump Options

Common flags:

```bash
--main-only
--include-extensions / --no-include-extensions
--include-frameworks / --no-include-frameworks
--include-app-groups
--analysis-artifacts
--metadata-only
--no-launch
--attach-pid <pid>
--timeout <seconds>
--retry <count>
--keep-temp
--rootless
--rootless-temp <path>
--verbose
--json-log
--trace <path>
--output <file.ipa>
--output-dir <directory>
```

Examples:

```bash
ios-dumpkit dump com.example.app --usb --main-only
ios-dumpkit dump com.example.app --usb --analysis-artifacts --output-dir ./dumps
ios-dumpkit dump com.example.app --usb --metadata-only --output-dir ./metadata
ios-dumpkit dump com.example.app --usb --no-launch --attach-pid 1234
ios-dumpkit dump com.example.app --usb --timeout 120 --retry 2 --trace trace.jsonl
```

## Metadata Output

The `dump` and `metadata` commands create a metadata directory containing:

- `metadata.json`
- `Info.plist`
- `entitlements.plist` when entitlements are recoverable
- `embedded.mobileprovision` when present

`metadata.json` includes:

- Bundle id
- App version and build number
- Minimum iOS version
- Executable name
- URL schemes
- ATS settings
- Keychain access groups
- Associated domains
- App groups
- Imported and exported dylibs

## Analysis Artifacts

Use `--analysis-artifacts` to write readable reverse-engineering artifacts into the output directory:

```bash
ios-dumpkit dump com.example.app --usb --analysis-artifacts --output-dir ./dumps
```

The tool creates:

```text
dumps/
  com.example.app-analysis/
    analysis/
      manifest.json
      objc/
        objc_classes.json
        headers/
          ExampleClass.h
      macho/
        Example.macho.json
      strings/
        Example.strings.txt
      symbols/
        Example.symbols.txt
      disassembly/
        Example.disasm.txt
```

These are not original source files. Objective-C headers are reconstructed from runtime metadata. Swift and C/C++ code generally cannot be recovered as clean source; the tool exports available symbols, strings, Mach-O metadata, and optional disassembly when local tools such as `llvm-nm`, `llvm-objdump`, or `rabin2` are installed.

## IPA Output

The packager creates a standard IPA layout:

```text
Payload/
  Example.app/
    Info.plist
    Example
    Frameworks/
    PlugIns/
```

The final output prints:

- IPA path
- SHA256 hash
- Number of decrypted modules
- Metadata path

Verify output:

```bash
ios-dumpkit verify ./dumps/Example.ipa
```

## Doctor Checks

`doctor` validates:

- Frida host package
- `frida-tools`
- Remote frida-server reachability
- Frida version compatibility when the remote version is exposed
- SSH reachability when SSH mode is requested
- Device free disk space
- `/tmp` writeability
- App installation and launch/attach status when a target is supplied
- Python dependencies
- Local output directory writeability
- Common rootful/rootless jailbreak paths

Run:

```bash
ios-dumpkit doctor --usb
ios-dumpkit doctor com.example.app --usb --ssh-host 192.168.0.71 --ssh-user root
```

## Rootless Jailbreak Notes

The tool does not assume `/Applications`. It resolves the app bundle path from Frida and runtime bundle metadata where possible.

The doctor checks common jailbreak layout hints:

- `/var/jb`
- `/private/preboot`
- `/cores/binpack`
- classic rootful paths

This should work with many Dopamine, palera1n, and checkra1n-style layouts, but device-specific jailbreak changes can still require investigation with `--trace`.

### `--rootless` staging

On rootless jailbreaks the injected Frida agent runs inside the target app's sandbox and cannot write decrypted modules to the global temp root (`/tmp/ios-dumpkit-ng`). The dump then fails at the `dumping binary` stage with `Operation not permitted`, even though `copying bundle` succeeded (bundle copy is pulled over SFTP, not written from inside the sandbox).

Pass `--rootless` to stage the on-device dump inside the app's own Data container (`<container>/tmp/ios-dumpkit-ng/...`), which the sandboxed process can write and the SSH user can still read back:

```bash
ios-dumpkit dump com.example.app \
  --usb \
  --ssh-host 127.0.0.1 --ssh-port 2222 --ssh-user mobile --ssh-pass '<password>' \
  --rootless \
  --output-dir ./dumps
```

The container path is resolved automatically from the app's sandbox `HOME` (via a POSIX `getenv` call in the agent, so it works even when the Objective-C runtime is unavailable in-process); no manual UUID lookup is needed.

If auto-resolution still fails on an unusual setup, pass an explicit staging root the app can write:

```bash
ios-dumpkit dump com.example.app --usb \
  --ssh-host 127.0.0.1 --ssh-port 2222 --ssh-user mobile --ssh-pass '<password>' \
  --rootless \
  --rootless-temp /var/mobile/Containers/Data/Application/<UUID>/tmp
```

## Troubleshooting

### Stuck at 0.00B

Use USB, increase timeout, clear stale temp files, and capture a trace:

```bash
ios-dumpkit clean --ssh-host 127.0.0.1 --ssh-port 2222 --ssh-user root --ssh-pass '<password>'
ios-dumpkit dump com.example.app --usb --timeout 120 --retry 2 --trace trace.jsonl
```

### App Name With Spaces

Quote the name:

```bash
ios-dumpkit dump "Example App" --usb
```

If the name is ambiguous, use the bundle id from `ios-dumpkit list`.

### Frida Version Mismatch

Host `frida`, `frida-tools`, and device `frida-server` should match:

```bash
python -c "import frida; print(frida.__version__)"
```

Install matching packages and restart `frida-server`.

### TCP Frida Fails But USB Works

If this works:

```bash
frida-ps -Uai
```

but this fails:

```bash
frida-ps -H 192.168.0.71 -ai
```

then Frida is healthy over USB but not reachable over TCP. Use `--usb`, or restart `frida-server` with a reachable TCP listen configuration.

### SSH Authentication Failure

Provide `--ssh-pass` or `--ssh-key`, or omit SSH options to use Frida transfer:

```bash
ios-dumpkit dump com.example.app --usb --output-dir ./dumps
```

### App Crashes On Attach

Open the app manually, keep the device unlocked, then attach without launching:

```bash
ios-dumpkit dump com.example.app --usb --no-launch --timeout 120 --retry 2
```

### Final IPA Still Encrypted

Run:

```bash
ios-dumpkit verify ./dumps/Example.ipa
```

Then review `--trace` output for module dump failures, process exits, or missing encrypted modules.

## Project Layout

```text
ios_dumpkit/
  cli.py
  config.py
  logging.py
  frida_client.py
  ssh_client.py
  device.py
  app_resolver.py
  macho.py
  dumper.py
  packager.py
  metadata.py
  doctor.py
  verifier.py
  errors.py
  js/
    agent.js
  tests/
```

## Development

Install dev dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run checks:

```bash
python -m black --check .
python -m ruff check .
python -m pytest
```

Format:

```bash
python -m black .
```

## Security

See [SECURITY.md](SECURITY.md).

Do not include private app data, customer data, credentials, or proprietary binaries in public issues. Redact traces before sharing them.

## Legal

This project is for authorised security testing, research, and defensive assessment. You are responsible for complying with applicable laws, platform terms, and programme scope.

## License

MIT. See [LICENSE](LICENSE).
