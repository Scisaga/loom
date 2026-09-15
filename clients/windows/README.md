# Loom Windows client

The Windows client accepts only v2 enrollment, certified configuration and private reports.
Its normal GUI, clipboard, Installed broker and reconnect paths share the same v2 host.
Legacy local identity files remain migration inputs; they never authorize the old
public enrollment, current-polling or report endpoints. Migration must preserve the
Device key and rollback state before removing those local inputs.

Protocol rules belong to [the control-plane specification](../../docs/protocols/control-plane/README.md).
[The implementation map](../../docs/development/implementation.md) distinguishes
source wiring from deployment and native acceptance.

In the v2 flow, an already-enrolled administrator reaches **Create Device**
only over the Loom overlay through the certified private `control_api` service,
verifies its internal certificate and overlay IP, and authenticates with admin
mTLS. An unjoined Windows client verifies the compact descriptor's catalog and
proof-bundle hashes and fetches both immutable objects without the token from one
of the QR's 2–3 static distribution mirrors. It measures only the outer
transport/SNI of the authorized Hysteria2 ingress (or the formal Trojan/TLS TCP
fallback when UDP is blocked), without presenting a bearer, and presents its
short-lived capability only to the selected ingress. After establishing the
route-limited tunnel, it verifies server-authenticated inner TLS, retrieves the
private exact Device intent and its hiding-commitment opening, and then sends the
token, stable claim core, CSR, and an identity-key detached PoP over the server
nonce. The wrapping key is separate and is never a PoP key. Public Nginx
serves only the fake website and immutable distribution; it never receives or
proxies a claim.

For v2, Raft durable commit alone is never an activation or authorization signal.
A `committed_not_certified` head cannot update mutable current, change grants,
select an endpoint, or trigger an external side effect; the client continues its
last-known-good profile. Before installation it verifies the bootstrap or recovery
lineage (including `recovery_policy_hash`), the ControlSet transition, the post-commit
replication QC, the Device inclusion proof, the public endpoint sets, and the
private service-directory commitment. It then
atomically advances all four durable floor groups:

```text
recovery_epoch + recovery_statement_hash + recovery_policy_hash
control_epoch + control_set_hash
control_revision + head_hash
device_generation + device_leaf_hash + device_view_hash
```

The first v2 install atomically persists those floors, the
`bootstrap_transition_hash`, and `protocol_latch=v2`. After that latch, no v1
current, invitation, view, or recovery statement can regain authority. Public
`DistributionEndpointSet`, `BootstrapIngressEndpointSet`, and
`DataIngressEndpointSet` are distinct and cannot authorize one another. Private
`control_api`, Enrollment, `device_config`, and `device_report` entries are typed
projections of `ControlServiceDirectoryV1`; they use overlay IP, internal
certificate profiles and purpose-specific mTLS rather than public DNS/WebPKI.
Public HTTPS/Hysteria2/Trojan endpoints use their exact signed server name,
transport identity and generation/overlap-bounded pin set.

`clients/windows` is the Windows-only client host. It does not compile the
control-plane publisher, SSH provisioning, systemd lifecycle, or other Linux
operations into the Windows executable.

## User flow

The control plane creates the Device first. The three embedded editions use
the same native Windows GUI and join flow. Installed uses an ordinary-user
window and an MSI-installed Service broker. The service owns machine credentials,
signed updates and the data-plane process:

```text
Control: Create Device → show one-time join QR
Windows: start client → import invitation → join and save → connect
```

The window uses a light Misaka appearance: saved connections in the sidebar,
the selected connection's status and route mode above, and actual Service paths
below. Windows system Direct2D and DirectWrite draw the frame, cards, text and
paths; native Win32 controls retain keyboard input, list selection, editing and
window behavior. There is no additional GUI runtime or bundled font dependency:
WebView2, Electron, .NET and Qt are not required. The Go runtime is included in
the executable; the signed data-plane sidecar remains a separate package.
The EXE embeds native-size variants generated directly from
`internal/webui/favicon.svg` for Explorer, the Windows taskbar, the window title
bar, and the notification-area icon.

Display scaling changes and moves between monitors update drawing coordinates,
text, input controls, icons and hit areas together through `WM_DPICHANGED`. The
window uses the position and size suggested by Windows. Native window tests
exercise scaling, keyboard input and rendering with synthetic profiles; they do
not change the machine's display settings or use a real joined identity.

<p align="center">
  <img src="../../assets/client/windows/loom-client-windows-current.png" width="900" alt="Loom Windows native interface with saved profiles, route modes and per-Service paths">
</p>

<p align="center"><sub>Portable TUN · Native window generated from repository source with synthetic profiles and measurements. Published previews may lag behind the source.</sub></p>

The screenshot is produced by `TestGUIProfilesSelectionAndActualServicePaths`
with `LOOM_PROFILE_GUI_CAPTURE` set to the output PNG path.

The [design reference](../../assets/client/windows/loom-client-home-misaka-v2.svg)
documents the layout; the [interaction reference](../../assets/client/windows/loom-client-interactions-misaka-v2.svg)
shows inline renaming and the invitation panel.

### Icon asset invariant

The executable/program icon, Explorer icon, taskbar icon, window title-bar icon,
and notification-area base icon **must use `internal/webui/favicon.svg`**. Do not
replace, redraw, recolor, invert, or substitute that mark with `loom-logo-v4.svg`
or a Windows-specific derivative. Rendering the same SVG into multiple native
ICO sizes is allowed; changing its geometry or colors is not. The window host
must load the current-DPI `SM_CXSMICON` and `SM_CXICON` sizes separately and set
both small and big window icons; it must not load an arbitrary intermediate
size and rely on Windows to rescale it. Transparent canvas margins may be
normalized without changing the favicon geometry, colors, or proportions. Connected state
may overlay the Windows-native green shield in the lower-right corner, but the
favicon beneath it remains unchanged. `assets/loom-logo-v4.svg` is reserved for
the larger in-window brand area beside the product name. That in-window tile is
cropped with a small one-eighth-width corner radius when its DPI-specific ICO
frames are generated; the source artwork and all application favicon frames
remain unchanged.

The left-hand list contains saved connection profiles. Single-clicking a row
changes only the details being viewed. Double-click its name, press **F2**, or
use the profile menu to rename it inline: **Enter** saves and **Esc** cancels.
Names must be unique locally and contain at most 64 characters. Renaming does
not restart a connection. **连接** or **切换连接** first stops and waits for the
active profile's workload, then starts the selected one; at most one profile can
be connecting or connected. The selected row and active-connection indicator
distinguish the viewed profile from the one carrying traffic.

The sidebar **+** opens **添加配置** in the right-hand pane. The list stays
visible and temporarily disabled; opening or canceling this panel creates no
empty saved profile. Enter a local name, import or paste a control-issued
invitation, then choose **加入并保存**. The new profile appears in the list only
after its joined identity and local index have been saved successfully. It stays
disconnected, and a connection already running under another profile continues.

Once joining starts, the client may already have generated or claimed an
identity. **稍后继续** cancels the current attempt and closes the panel while
retaining its protected identity and recovery data. Reopen the panel, including
after restarting Loom, and choose **继续加入** to resume that same transaction.
A recovery attempt cannot replace its invitation or identity; its local display
name can still be corrected. If the final profile-index write fails after the
identity is ready, retry saves that identity without claiming another Device.
A fresh state directory starts with an empty list. Only existing join identity,
pending/ready data or joined configuration creates the retained **Loom 网络**
entry on first initialization. Already saved indices are preserved, so an
existing unjoined entry can still use its original join action.

Each profile retains its own DPAPI-protected join identity, verified configuration,
route preference, Agent generations and measurements. Existing single-profile
state remains at its original protected location and appears in the list; it is
not copied into a new identity. Additional profiles use isolated subdirectories.
Local names and list selection do not change the control-plane Device or policy.
Deleting a disconnected profile removes only that profile's local identity and
configuration. MSI uninstall continues to preserve retained joined state,
profile metadata and pending recovery data. The profile index is strict and
written atomically; an invalid index blocks profile operations. A missing index
with existing additional-profile directories is also rejected.

The status label and corresponding list entry show an icon in every connection
state: progress while connecting or disconnecting, green when connected, gray
when disconnected, and red after failure. Connecting can be canceled. Progress
animation refreshes its own icon area, while unchanged status polls do not rewrite
controls or repaint the entire window.

The **直连 / 自动 / 固定出口** controls change the authorized route preference.
Auto retains per-Service routing. Fixed exit offers an authorized exit picker
and uses one shared path for managed internet traffic; the Agent still chooses
the intermediate servers leading to that exit. **当前选路** reads back the actual
server chain and shows the current entry, server-hop and target evidence
on its corresponding link. **详细信息** adds each measurement's source and time,
the decision reason and read time. Missing measurements stay unknown; segmented
estimates do not establish end-to-end P50/P95 or business-path health. The local
TUN capture address is not presented as an independently reachable Loom network IP.
Direct does not freeze a candidate snapshot or spend probe budget. On the first transition
into Auto or fixed-exit mode in each underlying-network generation, the client atomically
freezes the then-current candidate snapshot and probes each entry deduplicated by address
and source interface at most once and in parallel. Configuration refreshes, later mode or exit changes, and reconnects
within that generation reuse the result. Entries introduced later in the same generation
receive no active probe; only real dial/fallback attempts may produce passive evidence.
Entry probes never send business DNS/HTTPS requests and never gate data-plane startup.

The notification-area tooltip includes the embedded
edition and current state. Double-click restores the window; closing the window
hides it to the tray; the tray menu provides show, the current
import/connect/disconnect action, and an explicit exit.

Importing the QR never creates a second Device. In the Windows GUI, copy
the QR image from the control page and press `Ctrl+V` (or click the paste action),
select the downloaded QR PNG, or drag one local QR PNG, `.loom-invite`, or
`.loom-resume` file
onto the window. In the add-profile panel this reads the invitation; **加入并保存**
starts the join. Clipboard images are decoded in memory and are not written to
a temporary file. The executable does not accept join material as a command-line
argument, so its bearer token cannot enter process listings or shell history.

There is deliberately no Windows `enroll` command and no user-selected
`-component` argument. The data plane ships beside the executable as
`windows-dataplane.zip` and is selected automatically.

All three editions show the current join stage and elapsed time: local checks,
contacting the control, waiting for configuration publication after a `pending`
response, and verifying/saving the returned bootstrap. The clock keeps updating
during a slow request; Installed carries the same detail through its existing
broker status response. A pending response does not mark the client joined or
start the data plane. Retry and resume follow the certified transaction deadlines.
See the [enrollment diagnostics guide](../../docs/operations/enrollment-diagnostics.md).

Internally, the QR import performs an identity handshake: the client creates a
persistent, non-exportable P-256 identity in the Microsoft CNG software KSP,
creates a distinct wrapping key, binds the already-created Device, validates the
returned certificate and certified bootstrap, and protects the key descriptor,
wrapping material and durable state with purpose-bound DPAPI. This is an
implementation detail of **Join network**, not a
second Device-registration workflow. The private key and permanent credentials
are never placed in the QR code.

Reporting uses the identity created by this same join flow automatically. A
user never needs to locate or import a private key. An unjoined client starts
with a valid QR; restoring an old state directory is not a reporting-test
prerequisite. Live reporting acceptance follows the normal GUI join and connect
flow described in the [reporting contract](../../docs/clients/windows-reporting.md).

Deleting a local profile clears that profile's identity and configuration; it does not notify
the control plane. To join again, open the original Device in the control UI and
use **Rejoin Device**. For a joined access-only Device, this archives the old
identity and generates a new ID and QR with the same name and purpose. The old
access is revoked as servers apply the signed update. An unused QR can instead
be regenerated from the Device details while keeping its reserved ID.

## Editions

Portable is a delivery choice; TUN and mixed are traffic-capture choices.

| Edition | Traffic coverage | Elevation | Persistent installation |
|---|---|---|---|
| Portable Mixed | Applications explicitly using `127.0.0.1:1080` as HTTP/SOCKS proxy | None | None |
| Portable TUN | System TCP/UDP/DNS selected by the managed TUN rules | Requires an administrator relaunch before TUN activation | No MSI or Service; adapter/routes exist while connected |
| Installed | Managed TUN plus the same-rule mixed endpoint | MSI installation requires elevation; daily UI, join and connection do not | Windows Service and restricted machine-scope ProgramData state |

Portable editions can open and import a join QR without TUN privileges. Portable
TUN checks elevation only after the enrollment response has passed its applicable
v2 certified gate and the joined state is durably saved, immediately
before starting its data plane; its GUI offers a Windows UAC relaunch at that
boundary. Portable Mixed never
creates an adapter or changes the route table.

Portable state is stored under `%LocalAppData%\LoomPortable` using current-user
DPAPI. Installed state is stored under `%ProgramData%\Loom` using machine-scope
DPAPI. MSI creates a SYSTEM/Administrators-only state directory. Its local pipe
allows only the installing Windows user and administrators; the GUI verifies the
server PID against SCM before sending a QR credential. The service accepts only
status, profile selection/rename, opening or closing the add panel, joining or
resuming a v2 transaction, connect, disconnect, authorized
route preference and local deletion. Profile operations use bounded local
identifiers and names resolved by the service. Draft snapshots contain only
display state and progress. These actions use the existing local named pipe;
enrollment and reporting endpoints and signatures are unchanged.
It accepts no file paths, commands or configuration bodies from the GUI.

## Build and run

### GitHub Actions

Pushes to all branches (including `main`) and pull requests run CI checks. Windows builds and GitHub Releases are triggered manually.

To publish an unsigned preview to [GitHub Releases](https://github.com/Scisaga/loom/releases), open **Actions → Windows build → Run workflow** and select `main`. The workflow runs CI checks, builds the Windows packages, and publishes the release. Leave the version blank to increment automatically from the highest existing `windows-v<version>` tag or release draft, for example `0.1.6` → `0.1.7`, or supply a higher version. Manual builds of other branches produce artifacts only.

Each release contains all six edition/architecture ZIPs, both MSI installers, SHA-256 manifests, and `BUILD-INFO.txt` with the source commit and workflow run. SignPath signing is deferred in [issue #5](https://github.com/Scisaga/loom/issues/5).

Every Windows build also retains `loom-windows-<version>-preview` in **Artifacts** for 30 days. Release files are checked and uploaded to a draft before it becomes public. Existing version tags and releases are never overwritten. A failed upload leaves a draft; the next manually triggered build with the version left blank uses a higher version.

The workflow reuses the existing CI checks and packaging scripts on GitHub-hosted
Linux and Windows runners. Its repository setup is:

- Actions variable `LOOM_PLATFORM_PUBLIC_KEY`: the trusted platform Ed25519 public
  key in canonical base64, matching the existing local build's public key.
- Draft release `windows-components-1.11.4`: the two platform-signed component
  assets `loom-windows-dataplane-1.11.4-amd64.zip` and
  `loom-windows-dataplane-1.11.4-arm64.zip`. The workflow reads them using its
  built-in `GITHUB_TOKEN`, then verifies their signatures,
  architectures and pinned upstream contents before compiling.

GitHub requires `contents: write` to read draft releases and publish releases, so this permission is limited to the ZIP and release jobs. The test and MSI jobs use `contents: read`.

Keep the platform private key and device credentials on the operator's machine.
Updating components requires preparing new signed packages and updating the
reviewed version pins.

### Local build

Build all three editions for amd64 and arm64:

```sh
bash ./scripts/build-windows-clients.sh
```

The build requires the platform-signed component packages in
`deploy/staging/loom-windows-dataplane-1.11.4-{amd64,arm64}.zip` (or the directory
selected by `LOOM_WINDOWS_COMPONENT_DIR`). For each edition it produces a full
ZIP containing the edition-specific executable, the fixed-name
`windows-dataplane.zip` sidecar, `PREVIEW-NOTICE.txt`, Loom's Apache-2.0 `LICENSE`
and `NOTICE`, and the licenses/notices
for statically linked third-party modules. These are development-preview ZIPs,
not Authenticode-signed release artifacts unless signing is explicitly configured.
Portable Mixed has a native end-to-end test; TUN lifecycle acceptance is opt-in
because it changes the test machine's traffic capture.
`out/windows-clients-SHA256SUMS` is published last as the commit marker for the
complete six-ZIP build set. Build or verification failures before publication
leave the previous set in place; consumers must verify the manifest so an
interrupted partial publication is rejected.

MSI installers also install Loom's `LICENSE` and `NOTICE` alongside the executable.
Third-party components keep their own licenses. See the
[Code signing policy](../../docs/operations/code-signing.md) for the SignPath scope.

Release builds strip Go symbol and DWARF tables with `-s -w`. Package size is
still dominated by the signed data-plane sidecar: the amd64 sidecar is about
13.3 MB compressed and contains the 34 MB `sing-box.exe` plus Wintun. The outer
ZIP cannot materially recompress that already-compressed ZIP. The remaining
size is the statically linked Loom executable, including the Go runtime, QR
decoder, TLS, DPAPI, signature verification, update, and process supervision.

For example, extract:

```text
loom-client-windows-portable-mixed-amd64.zip
```

then start:

```powershell
.\loom-client-windows-portable-mixed-amd64.exe
```

This starts the GUI without a console window. On first launch, import the QR PNG
generated by **Devices → Create Device** on the control plane, complete joining,
then choose **连接**. Use the sidebar **+** to join additional profiles. Later
launches reuse the protected joined state and restore the last connected profile;
merely selecting a different row does not change that choice. An explicitly
disconnected client stays disconnected. `--build-info` reports the embedded edition,
architecture, Go/VCS coordinate, and executable hash.

## Security and runtime boundaries

- `internal/windowsv2` parses bounded compact QR, `.loom-invite` and `.loom-resume`
  inputs. Invalid carriers fail before any enrollment request. The broker rejects
  the removed v1 `invite` field, including when a valid v2 carrier is present.
- The embedded deployment public key verifies the bootstrap transition or existing
  control-log activation proof. It is a public trust anchor, not a Device credential.
  The descriptor's mirrors serve immutable catalog/proof objects without a token.
  A capability is presented only to the selected authenticated bootstrap ingress;
  the claim token is submitted only over verified inner Enrollment TLS.
- `internal/clientcomponent` verifies the fixed sidecar's signature, hashes, PE
  architecture, sing-box identity and Wintun Authenticode before installing an
  immutable slot. The GUI cannot select arbitrary executables or component paths.
- Newly enrolled Devices use a non-exportable CNG P-256 identity and separate
  wrapping key. Purpose-bound DPAPI protects the descriptor, wrapping material,
  exact pending transaction and installed state using the edition's scope.
- `state\client-v2.json.dpapi` atomically commits the certified Device view,
  ControlSet/QC context, all four rollback-floor groups, transition hash,
  irreversible v2 latch, certificate, secret references and runtime artifacts.
  A merely committed head without its QC cannot authorize activation.
- Pending retries keep the same identity, request and claim core. Invite and
  capability validity bound uncommitted retries; a committed transaction needs an
  administrator-issued exact-bound resume capability after expiration. The old
  one-hour automatic recovery path is removed. Successful installation is read
  back before deleting the token-bearing journal; restart completes that cleanup.
- The profile index commits only after the v2 state is installed. Canceling an
  unfinished draft preserves its identity and journal. Opening another profile
  does not switch the active data plane. Global UI/data-plane locks prevent
  concurrent hosts from racing the same state.
- `internal/clientruntime` retains Installed, Portable TUN and Portable Mixed
  capture modes and supervises sing-box in a kill-on-close Job Object. Only the
  validated v2 runtime artifact can supply configuration. Public transport DNS
  remains separate from business FakeIP; Direct resolves locally and proxied
  business names are carried to the selected egress.
- Configuration and health reports use only certified private `device_config`
  and `device_report` services with internal TLS and Device mTLS. No endpoint is
  derived from an enrollment or distribution URL. The durable report sequence
  retains an exact pending envelope until accepted. See the
  [report contract](../../docs/clients/windows-reporting.md).
- Existing `config\client.json`, legacy identities and verification floors are
  recognized as migration inputs and preserved. They cannot start an old host,
  send an old report or retry a consumed legacy invitation. The verified migration
  installer must complete before that profile can reconnect.

## 本地客户端选路目标契约

探测预算、网络代 registry、未知观测、分段估算和禁止行为统一由
[客户端消费边界](../../docs/clients/observations.md#客户端消费边界)定义。
Windows 宿主使用 `agent.RunClient`，以进程级 registry 跨 Agent/profile 生命周期保存结果；
接线见[代码映射](#agent-选路集成代码映射)。配置、偏好、重连与恢复通过同一激活事务交接 Agent。

选择状态保存于受 Windows DACL 保护的 `runtime/agent/generation-*`，不读取旧完整路径测量历史。
报告 GET 实际 selector，并用已签 plan 映射节点链；PUT 意图不表示已生效。原因继续进入 canonical
v5 reason，界面和 self-check 都不发业务探测。

修改选路时核对入口目标、次数、并发、启动等待、同代复用、授权、未知/过期证据和 selector 回读。
Windows 原生测试另覆盖单次 ICMP API；设置 `LOOM_SING_BOX_EXECUTABLE` 后，运行
`TestOfficialWindowsClientSelectsEntryWithoutBusinessProbes`，以官方数据面验证 selector 切换及
目标/代理接收器未收到业务探测。代码是否接通见[实现对照](../../docs/development/implementation.md)，
已执行的原生结果记录在[部署证据](../../docs/operations/local-deployment.md)。

## Acceptance contract

Acceptance is tracked per architecture and edition; one passing form does not
stand in for another:

- Portable Mixed covers bounded QR decoding, current-user DPAPI, Device binding,
  signed component/config installation, listener/report lifecycle, pending/ready
  recovery, multi-profile isolation, and shutdown without TUN or route changes.
- Installed covers ordinary-user GUI to ACL-restricted SCM broker, machine DPAPI,
  real TUN activation, route selection, disconnect/reconnect, signed reporting,
  upgrade/uninstall/reinstall with retained identity, and complete service/route
  cleanup.
- Portable TUN covers repeated connect/stop, adapter/route/listener/plaintext
  cleanup, process/host crash recovery, and fail-closed restoration.
- V2 coverage includes the certified-only gate, four durable floor groups with
  recovery policy hash, bootstrap transition/latch persistence, Device proof,
  split public EndpointSets/private service directory, SPKI pin overlap,
  restricted HY2/TCP bootstrap, and rejection of every v1
  authority after the latch.
- AMD64 and ARM64 require their own host evidence across supported network and
  display configurations. A database-valid MSI or cross-build is not host
  acceptance. Formal release additionally requires a trusted Authenticode
  certificate and timestamp.

Run the committed native evidence driver on each physical Windows architecture:

```powershell
.\scripts\test-windows-v2.ps1 `
  -OutputDirectory .\out `
  -PlatformPublicKey C:\path\to\platform-public-key `
  -EvidencePath .\out\evidence\amd64-packages.json `
  -RequirePackages -RequireMSI
```

Invite completion, committed `.loom-resume`, Installed lifecycle, Portable Mixed
lifecycle, elevated Portable TUN lifecycle, user-scope tombstone, machine-scope
tombstone, multi-profile UI, and underlay-generation-change evidence may require
separate clean-state runs. In particular, `-InstalledInviteCarrier` and
`-InstalledResumeCarrier` are intentionally mutually exclusive. Use the matching
switches (`-RunInstalledLifecycle`, `-RunPortableMixedLifecycle`,
`-RunPortableTUNLifecycle`, and `-TombstoneScope user|machine`) and bind the two
human-inspected artifacts with `-MultiProfileEvidencePath` and
`-UnderlayEvidencePath`. Evidence JSON contains only checks, source/build
coordinates, and hashes/sizes of those artifacts; it never embeds carriers,
identities, addresses, credentials, or runtime configuration.

After all runs from both native architectures refer to the same clean commit,
merge them into the release decision:

```powershell
.\scripts\confirm-windows-v2-gate-b.ps1 `
  -Evidence (Get-ChildItem .\out\evidence\*.json).FullName `
  -OutputPath .\out\windows-v2-gate-b.json
```

The merger fails closed unless every per-architecture native/lifecycle/UI/cleanup
check, all six exact ZIPs, both exact MSI databases, and signed sidecar verification
are present. Authenticode remains the separate, non-blocking Issue #5 gate and is
checked only when `-RequireAuthenticode` is requested.

Record each native result with its exact source/artifacts under ignored
`deploy/evidence/`, or reference its protected external receipt. Source integration
gaps remain in [the implementation map](../../docs/development/implementation.md).

## Installed package

After the six ZIPs are built, run on Windows with WiX 5 available:

```powershell
.\scripts\build-windows-installers.ps1 -Version 0.1.0 -Wix C:\tools\wix\wix.exe
```

This produces amd64/arm64 MSI files and `out/windows-installers-SHA256SUMS`.
Increase the three-part MSI version for each installed upgrade.
The script verifies the full ZIP input manifest, stages both installers, and
publishes their checksum manifest last. Install the matching MSI from the Windows
account that will operate Loom, then open **Loom** from the Start menu. An unpacked
Installed EXE expects this registered service and cannot substitute for MSI.

The service starts with Windows and restores an existing joined Device. Closing
the window hides it to the tray; explicit **Exit Loom** disconnects the workload.
If join is still pending, the service finishes saving the identity and stays
disconnected instead of starting traffic capture after the window exits.
Uninstall stops/removes the service and installed program, while preserving the
restricted machine identity and its authorized operator for reinstall. Use
the profile menu's **删除配置…** while that profile is disconnected to intentionally
remove its identity.
Portable state is separate and is never imported or deleted by MSI. Old preview
state with user-owned files is rejected by the service; it must not be silently
promoted to trusted machine state. Initialization errors are recorded in the
Windows Application event log.

For a signed release, set `LOOM_WINDOWS_SIGN_CERT` to a CurrentUser\My certificate
thumbprint and `LOOM_WINDOWS_TIMESTAMP_URL` to an HTTPS RFC3161 endpoint. The ZIP
build also accepts `LOOM_WINDOWS_SIGNTOOL` and `LOOM_WINDOWS_REQUIRE_SIGNED=1`.
The MSI build accepts `-SignTool` and `-RequireSigned`. Both sign the EXE before
packaging; MSI is then signed separately. Signing verifies the requested signer,
trusted Authenticode chain and timestamp before publishing the artifact manifest.

Opt-in native acceptance tests:

- `LOOM_ACCEPT_INSTALLED=1`: ordinary-user IPC/ACL checks; after join,
  `TestInstalledConnectStopLive` tests disconnect/reconnect and route cleanup.
- `LOOM_ACCEPT_INSTALLED_QR`: a fresh control-issued PNG for
  `TestInstalledGUIJoinLive`, executed as the ordinary installing user.
- `LOOM_ACCEPT_TUN_LIFECYCLE=1`: `TestWindowsTUNLifecycleLive`, executed elevated
  after normal Portable QR join and with other Loom workloads disconnected.

## Agent 选路集成代码映射

| 目录 | 运行代码 / 文档 | 测试 |
|---|---|---|
| `clients/windows` | `README.md`, `activation.go`, `agent_activation.go`, `main_windows.go`, ``route_control.go`, `route_windows.go`, `runtime_report.go`, `activation_log.go` | `activation_test.go`, `agent_activation_test.go`, `join_windows_test.go`, `lifecycle_windows_test.go`, `v2_runtime_windows_test.go` |
| `internal/clientruntime` | `agent.go`, `agent_paths_other.go`, `agent_paths_windows.go`, `candidate.go`, `selector.go` | `agent_paths_windows_test.go`, `agent_test.go`, `agent_windows_integration_test.go`, `candidate_test.go`, `selector_test.go` |
| `internal/clientstatus` | `agent.go` | 由宿主选路与 UI 测试验证 |
| `internal/agent` | `observed.go`, `observed_windows.go`, `run.go`, `state.go`, `store.go` | `observed_test.go`, `observed_windows_test.go`, `run_state_test.go`, `state_test.go` |
