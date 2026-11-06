# Loom Windows client

This document defines the target client behavior. Implemented behavior, business
acceptance, and release status are tracked in [implementation status](../../docs/progress.md).
Target prototypes follow explicit requirements and the current models; existing
code and native screenshots document implementation and its gaps, not limits on the design.

`clients/windows` is the Windows HostAdapter for the shared client contract. The
authoritative model is [Client runtime model](../../docs/clients/client-runtime-model.md);
enrollment and private transport are defined by
[Enrollment endpoint model](../../docs/core/enrollment-endpoint-model.md).
All editions use the same enrollment, candidate, observation, and selection
semantics.

The client selects one current Internet Policy per active profile. That Policy
uniquely determines its Service; the granted PolicyIDs are available choices,
including multiple policies under one Service, not simultaneous Internet rules.
The Service contains expected-service probe URLs and an optional restriction to
those targets. With the restriction off, the URLs do not form an Internet allowlist.
There is no separate Destinations editor, Probe object, or geographic classifier.
LAN authorization remains independent. See the [current business baseline](../../docs/core/control-model.md#服务与策略的当前业务基线).

The previous per-Service preference shape is an implementation and forward-migration
gap. Its presence in source, storage, screenshots, or tests does not constrain the
target. New field definitions and migration are not complete; preserve existing
identity, signed originals, high-water/floor, latch, and report sequence. Do not use
an old migration command as proof that this new selection model is implemented.

The existing `migrate-policy-selection` command converts an earlier global mode
to the old per-Service model. It is not the migration for the current target.
A new forward replacement must retain original protected bytes, verify an actual
fact-frontier advance, and preserve identity and anti-rollback progress. Ordinary
startup must not gain an old-format runtime fallback.

Invitation QR codes, links and files carry only a transaction credential and
minimal pinned TLS coordinates. They contain no policies, device names or member
proofs. The existing protected identity is saved with this reference before the
first connection. After key binding, the authenticated private response supplies
the original signed enrollment proof and this device's configuration. The same
identity then stores that proof and LKG; existing keys and rollback floors remain
unchanged. Interrupted enrollment reuses its key and request ID.

## Normal user flow

All three editions use the same native Misaka UI and the same private device
wire:

```text
Effective control signs an Invite for exact duties and grants
  → Windows imports QR / .loom-invite / clipboard text
  → local device key generation and issuer-only private claim or resume
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
join action. First use has an empty profile list and an **添加连接配置** action;
it does not create an empty profile automatically. The `join-empty` screenshot
is an exceptional existing-entry comparison, not the first-use screen or a step
after the import draft. Android can also retain an empty catalog, but creates an initial unjoined profile on first installation.
A pending join can be resumed with the same capability, request ID,
and identity. A profile is added to the local index only after its protected
authority has committed. The index contains UI names, ordering, selection, and
the last requested profile for reconnect only; it is never network authority or
proof that the profile connected successfully. QR Invite signing and claim
validation restrict duties to `access`; a request for `control` through another
medium waits for the old members' majority certificate.

Each profile owns exactly one `DeviceIdentity`, `CertifiedLKG`, and
`Preference`. Installed stores these under `%ProgramData%\Loom` with machine
DPAPI; Portable editions use `%LocalAppData%\LoomPortable` with user DPAPI. The
protected state contains the Ed25519 identity, stable claim request ID,
capability, continuous member proof, signer fact frontier, rollback floor,
irreversible anti-rollback latch, complete certified LKG, and preference.
Plaintext private keys and partial LKGs are invalid. A new LKG replaces the old
one after signature, identity, member proof, frontier, floor and canonical
runtime checks succeed and the protected atomic write reads back exactly.
Component verification and HostAdapter preflight belong to runtime application.
Their failure retains the newly accepted LKG and floor; an older execution may
continue only when every relevant input remains authorized by the new View.
Otherwise the affected business traffic stops while the authenticated repair
channel remains available. A runtime failure cannot restore revoked permissions.

The UI displays only projections of this authority. `RouteCandidate` becomes a
`RuntimeCandidate` through `internal/clientmodel`; the mapping is pure and
stable. Applying a candidate is not success: `Selection` is the value returned
by the authenticated Windows selector after the write. `Observation` is created
only by real transport/business results—TCP with TLS where applicable and
UDP/DNS—not by ICMP, process existence, a listener, or a UI color. Recovery stays within the current Policy and fixed-exit constraints;
continuous bounded measurements do not stop after finding one usable path. Business observations bind Service,
candidate, actual target and network generation; a result for one Service does
not establish another Service's health.

The current Policy determines the Service and optional target restriction.
Diagnostics retain the actual target, original execution context, result, time,
and expiry; historical results for inactive Policies are explicitly historical. Missing, expired, conflicting, or
incorrectly bound samples cannot establish current health. The selector readback
completion time is recorded separately in the disposable runtime status; refreshing
the UI or waiting for a report does not replace it with a business sample time.

Ordinary Direct has `final_exit=direct` and no managed hops. A device authorized
to execute as its own final egress keeps its NodeID in `final_exit` even though
its network hop list is empty. Local egress has no entry hop, so entry-node scopes
do not apply and it needs no self-dial or inbound resource.
Where the HostAdapter supports local egress, the selected Policy must explicitly
authorize it. Candidate choice stays inside that Policy, including its final-exit
restriction. The UI and profile reconstruction preserve the
logical exit instead of inferring Direct from an empty hop list.

The UI uses the native Direct2D/DirectWrite Misaka layout, profile
interactions, favicon, tray behavior, DPI handling, and SCM broker. The EXE has
no WebView2, Electron, .NET, Qt, or bundled-font dependency.

## Editions

Installed, Portable TUN, and Portable Mixed share enrollment, projection,
selection, fallback, observation, and reporting rules. Delivery and HostAdapter
behavior vary by edition.

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
  text and accepts only canonical `InvitationReference` values; the full signed
  `BootstrapInvite` is obtained through authenticated private enrollment.
- `internal/deviceclient` owns the shared private claim/resume/sync/report wire
  and the Windows DPAPI profile store.
- `internal/clientmodel` validates the complete runtime and projects certified
  routes into runtime candidates.
- `internal/clientcomponent` verifies the bundled component signature, hashes,
  PE architecture, sing-box identity, and Wintun Authenticode before use.
- `internal/clientruntime` performs edition-specific preflight and supervises
  the data plane in a kill-on-close Job Object.
- `internal/clientadapter` applies and reads the authenticated selector and
  records real TCP/TLS plus UDP/DNS results.

Component reports measure the running agent, supervised data-plane image and
actually loaded Wintun module independently of configured expectations. The
verified component files are held read-only for that runtime generation;
reported versions come from the manifest only after the measured file identity
and digest match. Portable Mixed does not report an unloaded Wintun DLL. Normal
stop releases these handles before upgrade or uninstall; no component-report
state is persisted separately.

The client accepts only private authenticated device data and a complete
certified `DeviceView`. Current runtime state comes from verified LKG and
HostAdapter readback.

## Build

Build all editions for amd64 and arm64 on the repository host:

```sh
bash ./scripts/build-windows-clients.sh
```

Build the reviewed Windows data plane on the same repository host with
`scripts/build-dataplane.sh windows/amd64 windows/arm64`. The script defaults to
Linux targets when none are specified. `build-windows-clients.sh` consumes
prebuilt, signed `loom-windows-dataplane-<version>-<arch>.zip` inputs from its
configured component directory. It derives the required version from the current
`clientcomponent.DataPlaneVersion` and authenticates both architectures before
building any edition. Renaming an older signed package does not make it current.

Use `loom client package-windows -arch <arch> -generation <generation>
-dataplane-dir <verified-windows-component-directory> -wintun-archive <pinned-archive>`
only with verified Windows inputs for that exact architecture.
Its schema 3 manifest binds the exact source build, patch, payloads and release
generation. The client rejects older generations, same-generation conflicting
content, and legacy component state. An explicit replacement must preserve old
component evidence and all device identity before installing the new package;
it does not reset a production release floor or activate a release catalog.

The build verifies the platform-signed component ZIPs before compiling and
publishes `out/windows-clients-SHA256SUMS` last. Each output ZIP contains the
edition-specific EXE, fixed-name `windows-dataplane.zip`, notices, and licenses.
Without the explicitly configured signing inputs these are unsigned preview
artifacts; the external Authenticode condition is tracked separately and does
not change source/runtime acceptance.

The existing `scripts/build-windows-installers.ps1` requires PowerShell and WiX 5.
This audit did not find a verified same-server execution path for those tools.
That is a build-chain gap: the restricted Windows VM remains a native test executor,
and must not become a second source/build environment. Verify the approved host
builder before generating a new MSI; do not treat the PowerShell script's presence
or a historical MSI as current build acceptance.

The MSI builder verifies the ZIP manifest and publishes
`out/windows-installers-SHA256SUMS` last. Increase the three-part MSI version for
an upgrade. Do not treat an unpacked Installed EXE as an MSI installation.

`--build-info` reports edition, architecture, Go/VCS coordinate, and executable
hash. The source commit, verified input hashes, ZIP/MSI hashes, and each VM
stage/run/run-interactive/collect result must be kept as one audit chain.

Publish the existing application artifacts through `loom release package-windows`
with `-artifact`, `-edition`, `-arch`, `-generation`, the deployment `.env`, an
independent `-pubkey`, and output `-o`. Installed also requires its original build
ZIP as `-bundle`. On the Linux publishing workstation, msitools and bubblewrap
inspect the MSI without executing installer actions and compare every extracted
file to that ZIP. The original MSI or portable ZIP plus detached manifest and
signature then enter the same `release stage` / `release publish` flow.

Releases exposes all three editions and both architectures, with the original
manifest and signature. Expected agent hashes identify the actual EXE, not the
download archive. Portable Mixed exposes no Wintun expectation. Platform release
signatures do not supply Windows Authenticode or change the preview designation.

## Verification boundary

Use the restricted same-host
[Windows 11 test VM](../../docs/operations/windows-test-vm.md) only as a native executor.
All source, builds, component verification, artifact decisions, and retained
evidence stay on the repository host. Run `windows-test-vm.sh verify` before
acceptance. The VM can validate x64 GUI, DPAPI, SCM, MSI, TUN, route cleanup,
reboot, upgrade/rollback, and uninstall through normal entry points.

For a `go test -c` native executable, inject the public release trust anchor at
`loom/clients/windows.buildPlatformPublicKey`; `main.buildPlatformPublicKey` is
the application build symbol. Confirm the linked test value before starting the
VM. A retry must keep the fixture's original control keys and protected device
profile. GUI acceptance waits for the displayed selection and its matching
resource observation, since runtime files can update before the visible row.

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

## Native visual review

The committed PNGs in `testdata/ui-golden` come from the production
`portableGUI`, Win32 controls, Direct2D/DirectWrite, and the existing
`WM_PRINT` memory capture. They are not a second renderer. Linux cross-compiles
the scenario test executable; the current fixed same-host Windows 11 VM baseline contains nine
synthetic `demo-*` scenes at 96 DPI and `876×614px`, without MSI installation or
real identity data.

The [target prototypes](../../docs/clients/prototype-review.md#windows原生场景与目标视觉设计)
can add or revise scenes according to requirements. They include a first-use
`profiles-empty` scene with an approved native baseline, distinguish import failure from
runtime failure, and separate business sample times from selector readback.
The complete Android and Windows gallery was approved together, recorded by the
native renderers, and strictly verified. Baselines do not freeze future requirements.

From the repository root run:

```bash
scripts/ui-review preview windows
scripts/ui-review verify windows
```

`preview` never changes the golden files. Review the generated gallery under
`out/ui-review`, then use `scripts/ui-review record all` only after both
platforms are approved. A Windows build, DPI, viewport, scene-set, or decoded
pixel mismatch is a hard failure; do not hide instability with tolerance.
