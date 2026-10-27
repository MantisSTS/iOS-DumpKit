# Troubleshooting

## Stuck at 0.00B

This usually means the app exited, the transfer stalled, or the remote temp file was never produced. Run:

```bash
ios-dumpkit doctor --usb
ios-dumpkit clean --ssh-host 127.0.0.1 --ssh-port 2222 --ssh-user root
```

Then retry with `--timeout 120 --retry 2 --trace trace.jsonl`. Prefer USB over WiFi for large apps.

## App Name With Spaces

Quote the display name:

```bash
ios-dumpkit dump "Example App" --usb
```

If multiple apps share the same display name, use the exact bundle id from `ios-dumpkit list`.

## Frida Version Mismatch

Host `frida`, `frida-tools`, and device `frida-server` should match. The tool fails clearly when it can detect incompatible versions.

```bash
python -m pip install -U frida frida-tools
```

Replace and restart `frida-server` on the device with the same version.

## Remote frida-server Not Reachable

Check that the device is unlocked, trusted over USB, and that `frida-server` is running. For TCP mode, confirm the host and port are reachable and not blocked by WiFi isolation.

If this works:

```bash
frida-ps -Uai
```

but this fails:

```bash
frida-ps -H 192.168.0.71 -ai
```

then Frida itself is working over USB, but `frida-server` is not listening or reachable over WiFi/TCP. Run `ios-dumpkit` with `--usb` for Frida and use SSH/SFTP separately for file transfer:

```bash
ios-dumpkit dump com.example.app --usb --ssh-host 192.168.0.71 --ssh-user root
```

Only use `--host` after `frida-ps -H <host> -ai` succeeds. On some jailbreaks, `frida-server` binds only to the USB/usbmux path unless started with an explicit TCP listen address.

## SSH Authentication Failure

Verify `--ssh-user`, `--ssh-pass`, `--ssh-key`, `--ssh-host`, and `--ssh-port`. For iproxy:

```bash
ios-dumpkit doctor --host 127.0.0.1 --ssh-host 127.0.0.1 --ssh-port 2222 --ssh-user root
```

Passwords are never logged.

## App Crashes on Attach

Try opening the app manually first, unlock the device, then run:

```bash
ios-dumpkit dump com.example.app --no-launch --timeout 120 --retry 2
```

If the app uses fragile startup logic, attach by PID with `--attach-pid`.

## Final IPA Still Encrypted

Run:

```bash
ios-dumpkit verify dumps/com.example.app.ipa
```

If cryptid is still non-zero, inspect `--trace` output for module dump failures and ensure the app stayed alive while encrypted modules were loaded.

## Missing Payload Path

The IPA must contain `Payload/AppName.app`. Rebuild with `ios-dumpkit dump ... --output-dir ./dumps` and verify with `ios-dumpkit verify`.

## "Operation not permitted" During dumping binary

If `copying bundle` completes but `dumping binary` fails with `Operation not permitted` (raised from `copyFileSlice` in the agent), the injected agent cannot write the decrypted module to the global temp root. On rootless jailbreaks the agent runs inside the target app's sandbox, so writes to `/tmp` are denied. This is unrelated to the SSH user (`root` vs `mobile`): bundle copy is an SFTP pull, while the binary dump is the first write made from inside the sandbox.

Re-run with `--rootless`, which stages the dump inside the app's own Data container instead:

```bash
ios-dumpkit dump com.example.app --usb \
  --ssh-host 127.0.0.1 --ssh-port 2222 --ssh-user mobile --ssh-pass '<password>' \
  --rootless
```

## Rootless Filesystem Path Problems

Do not assume `/Applications`. Use `ios-dumpkit list` and `doctor`; the dumper resolves bundle paths through Frida and checks common rootless locations such as `/var/jb` and `/private/preboot`.

## WiFi Instability

Use USB or iproxy. WiFi drops can interrupt Frida RPC or SFTP transfers.
