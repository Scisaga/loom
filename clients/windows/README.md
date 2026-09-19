# Loom Windows client

`clients/windows` is the Windows HostAdapter for the v2 client contract. The
authoritative model is [Client runtime model](../../docs/rebuild/client-runtime-model.md);
enrollment and private transport are defined by
[Enrollment endpoint model](../../docs/rebuild/enrollment-endpoint-model.md).
This package does not define a second enrollment protocol, candidate store,
health authority, or selection state machine.

## Normal user flow

All three editions use the same native Misaka UI and the same private device
wire:

```text
Control creates Device and BootstrapInvite
  → Windows imports QR / .loom-invite / clipboard text
  → private tunnel claim or resume
  → DPAPI atomic profile commit
  → connect
  → HostAdapter starts the certified runtime
  → apply selector and read it back
  → real TCP/TLS and UDP/DNS observation
  → private signed report
  → Control and Windows UI readback
```

There is no Windows `enroll` command and no join secret on the command line.
The sidebar `+` action opens the import panel; **加入并保存** is the only normal
join action. A pending join can be resumed with the same capability, request ID,
and identity. A profile is added to the local index only after its protected
authority has committed. The index contains UI names, ordering, selection, and
the last connected profile only; it is never network authority.

Each profile owns exactly one `DeviceIdentity`, `CertifiedLKG`, and
`Preference`. Installed stores these under `%ProgramData%\Loom` with machine
DPAPI; Portable editions use `%LocalAppData%\LoomPortable` with user DPAPI. The
protected state contains the Ed25519 identity, stable claim request ID,
capability, rollback floor, irreversible v2 latch, complete certified LKG, and
preference. Plaintext private keys and partial LKGs are invalid. A new LKG is
replaced only after signature, identity, floor, canonical runtime, component,
and HostAdapter preflight checks succeed and the protected staging file reads
back exactly.

The UI displays only projections of this authority. `RouteCandidate` becomes a
`RuntimeCandidate` through `internal/clientmodel`; the mapping is pure and
stable. Applying a candidate is not success: `Selection` is the value returned
by the authenticated Windows selector after the write. `Observation` is created
only by real transport/business results—TCP with TLS where applicable and
UDP/DNS—not by ICMP, process existence, a listener, or a UI color. One failed
candidate may cause one same-exit fallback; it does not create a scheduler,
sample window, generation, or measurement authority.

The UI keeps the existing native Direct2D/DirectWrite Misaka layout, profile
interactions, favicon, tray behavior, DPI handling, and SCM broker. The EXE has
no WebView2, Electron, .NET, Qt, or bundled-font dependency.

## Editions

Installed, Portable TUN, and Portable Mixed differ only in delivery and
HostAdapter behavior. They do not duplicate enrollment, projection, selection,
fallback, observation, or reporting rules.

| Edition | HostAdapter and delivery |
|---|---|
| Installed | MSI, Windows Service broker, machine DPAPI, managed TUN plus mixed listener |
| Portable TUN | User ZIP, user DPAPI, elevated TUN lifetime owned by the process |
| Portable Mixed | User ZIP, user DPAPI, local HTTP/SOCKS listener without TUN or route changes |

Installed GUI requests are bounded local operations over the ACL-restricted
named pipe. The service verifies its SCM identity and accepts no caller-supplied
commands, paths, runtime configurations, or private keys. Uninstall removes the
program, service, active adapter/routes, listeners, and transient runtime files;
the protected machine profile is retained for a normal reinstall. A user must
delete a disconnected profile in the UI to delete its identity intentionally.

## Runtime and security boundaries

- `internal/clientjoin` strictly decodes bounded bootstrap QR images, files, or
  text and accepts only canonical `BootstrapInvite` values.
- `internal/deviceclient` owns the reusable private claim/resume/sync/report wire
  and the Windows DPAPI profile store. Windows does not copy Android/Linux
  protocol state machines.
- `internal/clientmodel` validates the complete runtime and projects certified
  routes into runtime candidates.
- `internal/clientcomponent` verifies the bundled component signature, hashes,
  PE architecture, sing-box identity, and Wintun Authenticode before use.
- `internal/clientruntime` performs edition-specific preflight and supervises
  the data plane in a kill-on-close Job Object.
- `internal/clientadapter` applies and reads the authenticated selector and
  records real TCP/TLS plus UDP/DNS results.

The client never uses the removed public `/loom-client/enroll`, public
report/config/pull routes, P-256 certificate identity, v1 fallback, Agent,
scheduler, probe budget, `min_samples`, generation/measurement authority, or a
second candidate store. If a pre-v2 Windows identity is ever found, migration is
an explicit one-way Rejoin/rekey that preserves stable Device meaning and the
rollback/latch boundary; it is not an automatic fallback.

## Build

Build all editions for amd64 and arm64 on the repository host:

```sh
bash ./scripts/build-windows-clients.sh
```

The build verifies the platform-signed component ZIPs before compiling and
publishes `out/windows-clients-SHA256SUMS` last. Each output ZIP contains the
edition-specific EXE, fixed-name `windows-dataplane.zip`, notices, and licenses.
Without the explicitly configured signing inputs these are unsigned preview
artifacts; the external Authenticode condition is tracked separately and does
not change source/runtime acceptance.

After the six ZIPs exist, build MSI databases on Windows with WiX 5:

```powershell
.\scripts\build-windows-installers.ps1 -Version 0.13.0 -Wix C:\tools\wix\wix.exe
```

The MSI builder verifies the ZIP manifest and publishes
`out/windows-installers-SHA256SUMS` last. Increase the three-part MSI version for
an upgrade. Do not treat an unpacked Installed EXE as an MSI installation.

`--build-info` reports edition, architecture, Go/VCS coordinate, and executable
hash. The source commit, verified input hashes, ZIP/MSI hashes, and each VM
stage/run/run-interactive/collect result must be kept as one audit chain.

## Verification boundary

Use the restricted same-host
[Windows 11 test VM](../../docs/windows-test-vm.md) only as a native executor.
All source, builds, component verification, artifact decisions, and retained
evidence stay on the repository host. Run `windows-test-vm.sh verify` before
acceptance. The VM can validate x64 GUI, DPAPI, SCM, MSI, TUN, route cleanup,
reboot, upgrade/rollback, and uninstall through normal entry points.

An amd64 VM or cross-build cannot validate ARM64 execution, physical
sleep/wake, a real network handoff, display hardware, multiple monitors/DPI, or
long-running desktop behavior. GitHub-hosted runners and a successful process
start are not completion evidence. Production evidence belongs only in ignored
`deploy/evidence/`; repository examples use `demo-*`, RFC 5737 addresses, and
`example` domains.

The executable, Explorer, title-bar, taskbar, installer, shortcut, and
notification-area base icon all use the approved violet-edged
`internal/control/static/favicon.svg`. `assets/loom-logo-v4.svg` is the larger
violet-gradient in-window brand tile; its generated ICO frames have a
one-eighth-width corner radius. Neither asset may be redrawn as an
edition-specific logo.
