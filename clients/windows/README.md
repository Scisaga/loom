# Loom Windows client

`clients/windows` is the Windows-only client host. It does not compile the
control-plane publisher, SSH provisioning, systemd lifecycle, or other Linux
operations into the Windows executable.

## User flow

The control plane creates the Device first. All three embedded editions now use
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

<p align="center"><sub>Portable TUN · Native window captured from the current source with synthetic profiles and measurements. Published previews may lag behind the source.</sub></p>

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
the larger in-window brand area beside the product name.

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
server chain and shows each available entry, server-hop and target measurement
on its corresponding link. **详细信息** adds each measurement's source and time,
the decision reason and read time. Missing measurements stay unknown; segmented
estimates do not establish end-to-end P50/P95 or business-path health. The local
TUN capture address is not presented as an independently reachable Loom network IP.

The notification-area tooltip includes the embedded
edition and current state. Double-click restores the window; closing the window
hides it to the tray; the tray menu provides show, the current
import/connect/disconnect action, and an explicit exit.

Importing the QR never creates a second Device. In the Windows GUI, copy
the QR image from the control page and press `Ctrl+V` (or click the paste action),
select the downloaded QR PNG, or drag one local QR PNG or `.loom-invite` file
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
start the data plane. The existing three-second retry interval and request/overall
timeouts are unchanged. These messages explain the wait; they do not shorten
the control's publication process. Server-side work belongs in the server development
environment; use the [enrollment latency prompt](../../docs/server-enrollment-latency-prompt.md).

Internally, the QR import performs an identity handshake: the
client generates its private key locally, binds the already-created Device,
validates the returned certificate and signed bootstrap, and protects local
secrets with DPAPI. This is an implementation detail of **Join network**, not a
second Device-registration workflow. The private key and permanent credentials
are never placed in the QR code.

Reporting uses the identity created by this same join flow automatically. A
user never needs to locate or import a private key. An unjoined client starts
with a valid QR; restoring an old state directory is not a reporting-test
prerequisite. Live reporting acceptance follows the normal GUI join and connect
flow described in the [reporting contract](../../docs/windows-client-reporting.md).

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
| Portable TUN | System TCP/UDP/DNS selected by the managed TUN rules | The current preview requires an administrator relaunch before TUN activation | No MSI or Service; adapter/routes exist while connected |
| Installed | Managed TUN plus the same-rule mixed endpoint | MSI installation requires elevation; daily UI, join and connection do not | Windows Service and restricted machine-scope ProgramData state |

Portable editions can open and import a join QR without TUN privileges. Portable
TUN checks elevation only after the join is safely committed and immediately
before starting its data plane; its GUI offers a Windows UAC relaunch at that
boundary. Portable Mixed never
creates an adapter or changes the route table.

Portable state is stored under `%LocalAppData%\LoomPortable` using current-user
DPAPI. Installed state is stored under `%ProgramData%\Loom` using machine-scope
DPAPI. MSI creates a SYSTEM/Administrators-only state directory. Its local pipe
allows only the installing Windows user and administrators; the GUI verifies the
server PID against SCM before sending a QR credential. The service accepts only
status, profile selection/rename, opening or closing the add panel, joining or
resuming its draft, the existing profile join, connect, disconnect, authorized
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
[Code signing policy](../../docs/code-signing-policy.md) for the SignPath scope.

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

New QR codes include the SHA-256 fingerprint of the deployment platform key.
The client compares it with its embedded key locally before sending the
one-time code, so joining does not depend on an extra public trust route. QR codes
without this fingerprint are rejected; already joined identities remain valid. See
[`docs/status/current.md`](../../docs/status/current.md) before testing.

## Security and runtime boundaries

- `internal/clientjoin` decodes only bounded QR images, join files, or Loom URIs.
- The deployment platform public key is embedded in each build as a small,
  non-secret verification key; it is not a Device credential, connection
  secret, or control address. A clean first launch does not parse it and simply
  waits for QR import. Import or recovery then loads this trust anchor. The fixed
  sidecar is read once and its signature and architecture are checked before a
  one-time join code is submitted. New invitations carry only the SHA-256
  fingerprint of that public key, allowing a local comparison before the claim
  POST without adding another network or reverse-proxy dependency.
- `internal/clientenroll` implements the private wire protocol used behind QR
  import; it binds an existing Device and is not a user registration command.
- `internal/clientsecret` protects the join identity, secret vault, and hydrated
  candidates with edition-appropriate DPAPI scope.
- `internal/clientupdate` verifies signed current state, generation floors,
  snapshot signatures, and the Device bundle before activation.
- `internal/clientcomponent` verifies the bundled component signature, hashes,
  PE architecture, sing-box identity, and Wintun Authenticode before installing
  an immutable runtime slot.
- `internal/clientruntime` derives the exact Installed, Portable TUN, or TUN-free
  Portable Mixed profile and supervises sing-box in a kill-on-close Job Object.
  TUN profiles enable default-interface binding for underlay sockets and prepend
  a TUN-only port-53 `hijack-dns` rule. This sends system DNS to the signed DNS
  resolvers and prevents outbound connections from looping back through TUN.
  These local capture settings leave the signed egress rules, selectors and
  outbounds intact; Portable Mixed receives neither setting. Native compatibility
  is checked with the bundled sing-box using `TestOfficialWindowsTUNCaptureCheck`
  (`LOOM_SING_BOX_EXECUTABLE` and `LOOM_TEST_CA_CERTIFICATE`).
- `internal/clientreport` sends the existing Observation, including actual Agent evidence, with a v5
  attestation and self-check v1, using the retained DPAPI identity. After
  activation it reports the active snapshot every 60 seconds to the same-origin
  report URL derived from the validated enrollment URL; redirects are refused
  and accepts verified server observations in a bounded HTTP 200 response, with
  compatibility for the old empty HTTP 204 response. Candidates do not advance
  `applied`, and stopping the workload stops reports. Self-check checks local
  runtime listeners and the managed TUN adapter; it sends no business requests.
  Business reachability remains unmeasured. Server observation errors are
  separate from local runtime health. See the
  [reporting contract](../../docs/windows-client-reporting.md).
- Each profile's `config\client.json` is written last in the join core and is its
  joined-state marker. A newly added profile becomes selectable only after a
  subsequent atomic profile-index commit. Failed imports cannot start a partial
  client, and a ready identity remains recoverable if that index commit fails.
- Until the join commits, the exact QR credential and generated identity are
  protected with the edition's DPAPI scope. The control permits only the same token, CSR,
  request ID, platform and Device facts during a one-hour recovery window. A
  validated ready response is journaled separately before local installation;
  the pending token is scrubbed after `config\client.json` commits. Existing
  registered profiles retain their startup recovery behavior. A new add-profile
  draft resumes when the user chooses **继续加入**, using its retained identity.
- `state\profile-draft.json` stores only a schema, random local profile ID and
  display name. The invitation and credentials stay in protected per-profile
  storage. Canceling a draft does not delete a pending or ready identity.
- A global UI lock prevents two Windows client windows from running at the same
  time, and the data-plane lock prevents two joined workloads; the latter remains held while
  an update swaps child data planes, and the final joined-state commit never
  replaces an existing file.

## 本地客户端选路（§5.6 / §7.3.3）

Windows 使用 `agent.RunClient`。从已验证配置与实际 detour 提取授权入口，每次激活
按地址去重、各发一次并行 ICMP；在 TUN 启动前捕获源网卡，探测不阻塞激活。
不调用服务器使用的完整路径 `agent.Run`，不扫描 Service × 候选路径，不等待样本。

后段复用原上报响应中的已验签服务器观测。服务器结果更新只重算，不触发客户端探测。
后段证据未到时沿用当前出口，只比较同出口候选的入口延迟；latency 使用入口 RTT、
实际承载的服务器邻接/公网 Hy2 RTT 和出口已覆盖目标的首字节时间估算，沿用切换阈值。
同一声明的候选使用相同目标子集，未覆盖目标明确标注未知，不阻断其他已有数据。
其他目标指标缺乏相应分段证据时明确说明，不能冒充已经优化。未覆盖目标保持未知。

Auto 保留授权的 Service 分流；FixedExit 从签名配置识别默认上网声明，保留到所选
末跳的全部授权前缀，让受管上网流量共用一条 Agent 择优路径。独立私网或私网/公网
混合规则无法安全合并时，拒绝固定出口并保留当前有效配置。Direct 停止选路 Agent。
配置、偏好、重连和恢复继续使用同一激活事务，等待旧 Agent 退出再启动新代次。
签名 bundle、DPAPI 身份、授权裁剪、回滚及服务器协议保持原契约。

选择状态保存于受 Windows DACL 保护的 `runtime/agent/generation-*`，不再写入或消费
完整路径 measurement 历史。报告每次 GET 实际 selector，并用签名 plan 映射节点链；
PUT 意图不能冒充已生效路径。原因用已有 canonical v5 reason 签名，不新增线格式。

界面显示入口单次延迟和服务器分段估算，业务健康标为未测。P50/P95 与完整路径样本
不再由客户端填充。每轮 self-check 只检查本机监听、托管网卡及当前运行态，缺少
业务目标不再被误报为设备断网。界面读取和健康上报均不触发业务探测。

测试覆盖入口去重与并行、启动不等待服务器观测、更新不重测、授权限制、未知与过期
证据、失败约束、实际 selector readback、固定末跳、代次取消及原签名绑定。
Windows 原生测试验证单次 ICMP API；设置 `LOOM_SING_BOX_EXECUTABLE` 可运行
`TestOfficialWindowsClientSelectsEntryWithoutBusinessProbes`，使用官方数据面验证
selector 已切换且目标及代理接收器始终没有收到业务探测请求。
当前实机及发布情况见 `docs/status/current.md`，历史端到端探测验收不代表新版本已部署。

## Current implementation boundary

Portable Mixed has a native Windows end-to-end test covering QR decoding,
current-user DPAPI, HTTPS Device binding, signed component installation, first
signed pull, listener startup, startup grace, two signed report attachments
after token cleanup, and clean shutdown without TUN or
route changes. All three editions provide the same first-launch and connection
GUI; file selection, window lifecycle, and console-free PE output have been
exercised on the Windows host. Native draft tests cover cancellation before
allocation, protected recovery after restart, a late ready response after cancel,
atomic profile-index failure, and joining without switching the active profile.
Misaka rendering tests use isolated native windows and synthetic profile/path
data. These checks do not replace live acceptance of multiple real identities.

Installed uses the same lifecycle implementation inside SCM and connects the
ordinary-user window through an ACL-restricted named pipe. Windows amd64 native
acceptance covers ordinary-user QR join, machine DPAPI, actual TUN activation,
route selection, disconnect/reconnect and signed reporting. MSI upgrade, uninstall
and reinstall were exercised with the same retained machine identity and no
second QR; uninstall removed the service, executable, TUN routes and listener. Portable TUN live
acceptance covers three connect/stop cycles, adapter and route removal, listener
and plaintext-config cleanup, and host crash followed by signed-state recovery.
The control UI has also been observed changing the stopped Device to stale.

ARM64 packages are built and their MSI databases validated, but ARM64 host and
multiple physical network/display configurations need their own acceptance.
Authenticode signing requires a real code-signing certificate and timestamp
service. These external requirements do not turn an unsigned build into a
formal signed release.

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

## 本次 Agent 接入修改文件

| 目录 | 运行代码 / 文档 | 测试 |
|---|---|---|
| `clients/windows` | `README.md`, `activation.go`, `agent_activation.go`, `main_windows.go`, `report_windows.go`, `route_control.go`, `route_windows.go`, `runtime_report.go`, `update_loop.go` | `activation_test.go`, `agent_activation_test.go`, `join_windows_test.go`, `lifecycle_windows_test.go`, `report_windows_test.go` |
| `internal/clientruntime` | `agent.go`, `agent_paths_other.go`, `agent_paths_windows.go`, `candidate.go`, `selector.go` | `agent_paths_windows_test.go`, `agent_test.go`, `agent_windows_integration_test.go`, `candidate_test.go`, `candidate_windows_test.go`, `selector_test.go` |
| `internal/clientreport` | `observation.go` | `observation_test.go` |
| `internal/agent` | `observed.go`, `observed_windows.go`, `run.go`, `state.go`, `store.go` | `observed_test.go`, `observed_windows_test.go`, `run_state_test.go`, `state_test.go` |
