# Loom Linux v2 客户端安装


**类型：操作手册。** 适用于 Linux v2 客户端 CLI；协议由[控制面规范](../protocols/control-plane/README.md)定义。
源码提供 Invite/Resume 验证、bootstrap、安装及私有配置/报告客户端；正式服务端的接线缺口见
[实现对照](../development/implementation.md)。只有部署具备相应私有服务且交付有效输入时，才可完成以下正常流程。
命令存在或开发检查通过不表示某环境已具备 v2 入网能力。

当前使用 v1 身份与 signed pull 的部署，维护步骤见[v1 安装手册](../operations/linux-v1-install.md)。
两代状态与输入不可混用；已加入身份不因文档变更重新生成。管理端职责及 SSH/本地执行的分工见
[本机部署说明](../operations/local-deployment.md)。

## 准备条件

- 目标机为 Linux amd64，有 root/sudo、`tar` 与 `sha256sum`；通用包提供 Loom 和固定版本 sing-box。
- 使用正常管理流程交付的有效 v2 Invite/Resume；管理员已入网并能访问私有 control API。
- 节点能访问 descriptor 的静态 distribution、bootstrap ingress，并经受限隧道到达私有 Enrollment。
  公网 Nginx 不代理 claim；不依赖管理 SSH 是否可达来判断 Enrollment 能否使用。
- Linux 原生主机验收要求 amd64；arm64 仍构建并做静态/交叉检查，不要求原生机器，也不以 Android ABI 代替。

## 存量设备保留原身份迁移

原设备不重新领取邀请。先在原节点导出原 P-256 身份签名的公共请求：

```bash
sudo loom client export-migration-request \
  -device demo-server \
  -floor /path/to/original/release-floor.json \
  -out /path/to/private-channel/device-migration-request.json
```

默认读取 `/etc/loom/tls/` 中的原证书、私钥、CA，以及 `/etc/loom/platform-signing.pub`；
实际路径不同时用命令对应参数指定。命令验证原证书与设备、私钥的绑定，只把原身份复制到
root-only v2 存储并生成独立 wrapping key；原文件和 floor 不变。重复导出复用同一对 key。
请求只含公钥、原 floor 与签名，交由管理员按原网络的认证迁移流程处理。

管理员交付 `control export-migration` 导出的对应设备迁移包后，在原节点执行：

```bash
sudo loom client import-migration \
  -device demo-server \
  -floor /path/to/original/release-floor.json \
  -file /path/to/private-channel/device-migration.json
```

导入先验证原平台签名、原身份、floor 与完整迁移证明，再从认证静态镜像下载精确运行制品，
解封给本机 wrapping key 的凭据。完整 runtime 语义预检通过后，一次保存独立 migration state，
随后执行正常 `accept-v2-runtime -apply` 事务。control 节点还须用
`-control-peer-directory` 交付 Head 认证的私有 peer directory。

`-dry-run` 只验证候选，不保存 migration state 或激活服务。若身份已保存而运行事务失败，错误
会明确指出这一状态；修复主机条件后运行 `client accept-v2-runtime -apply`，不删身份、不降低
floor、不重新入网。稳态配置与报告直接消费同一 v2 installation；迁移不会生成虚假的 Enrollment 记录。

## v2 加入过程

1. 紧凑 QR/URI 的 exact descriptor 携带 schema/cluster/invite/expiry、token/commitment、
   minimum recovery/trusted checkpoint、`bootstrap_catalog_hash`、`proof_bundle_hash`、2～3 个静态
   `DistributionMirrorRefV1`、有界 `PrivateEnrollmentServiceRefV1` 和短期
   `BootstrapTunnelCapabilityV1`。
2. Linux 只向这些 Nginx mirrors 发无 token GET，分别验 catalog/proof hash 与 QC 后取得
   `BootstrapIngressEndpointSetV1`。public proof 只含 `DeviceEnrollmentIntentCommitmentV1` 及认证路径，
   不含 exact intent/opening。Nginx 只有 fake website 和 immutable distribution，不见 token，不代理 Enrollment。
3. 客户端从当前 underlay 对实际 HY2 入口各测至多一次；首版以 HY2 完成闭环，
   正式版在 UDP 全阻断时尝试已签独立 Trojan/TLS TCP fallback。
4. 选中入口后才出示 capability，建立只可达 `PrivateEnrollmentServiceRefV1`
   `/32`/`/128` 和 TLS port 的短期隧道。验证内层 server-auth TLS 后，先用不含 token/CSR/key 的
   `EnrollmentIntentPreflightRequestV1`/`ResponseV1` 取得 `DeviceEnrollmentIntentOpeningV1`
   并重算 hiding commitment；不匹配时不发 token。
5. Linux 生成 root-only identity/CSR signing key 和独立 wrapping key；wrapping key 只用于
   凭据包装，Enrollment PoP 只由 identity key 签名。客户端构造稳定
   `EnrollmentClaimCoreV2`，取得 `EnrollmentPoPChallengeV1`，对含 server nonce 的
   `EnrollmentPoPBodyV2` 签名，再在 `EnrollmentClaimSubmissionV2` 中提交 token、core、
   challenge 与 detached PoP；当前 stable ControlSet 的 voters 先形成
   `StableEnrollmentAdmissionQCV1`，再以 Raft CAS 保证一次消费。
6. reserved/issued_provisional 响应必须携 canonical progress receipt；Linux 从 Invite 已验 Head
   重放 admission QC、reservation/issuance operation 与 Head lineage 后，将 exact
   claim-operation/admission-QC/transaction hashes 和 retry deadline 原子写入受保护 pending state，
   作为后续 resume descriptor 不可回退、不可分叉的本机校验下限。ready 必须同时返回 result artifact
   和 canonical completion receipt；Linux 从 Invite 已验 Head
   连续重放 reservation/issuance/completion Head、QC、operation/view inclusion，核对本机
   claim/core/key、CA profile、正式证书与 sealed recipient，按每个 exact immutable ref 取得 canonical
   envelope 并用独立 wrapping key 解封。证书、完整 DeviceView、durable floors、stable claim 摘要与
   credentials 必须写入同一个 root-only canonical installation state 后才算安装完成，不能用多个文件的
   依次 rename 冒充跨文件原子提交。随后才清除 pending、token、capability、临时 profile/隧道；清理失败
   保留 pending 供 exact replay，正式 identity key 永不进入清理集合。
   然后由同一 Linux 客户端宿主建立正式 WG control/L3 overlay；配置与报告继续访问
   `ControlServiceDirectoryV1` 中分用途的 `device_config`/`device_report` 私有服务。

这个流程不使用 WG 做首版 bootstrap，也不以 distribution HTTPS RTT 代替实际隧道测量。
自动重试只在 invite/capability 有效期内执行；重试保持 token 和字节完全相同的
`EnrollmentClaimCoreV2`，可对新 server nonce 重签 detached PoP，但不得改 core/hash。claim 已 commit
而 capability 过期时，管理员先经私有 `role=control_api` 服务线性化确认事务，
再生成不含 token、exact-bound 的 `EnrollmentResumeDescriptorV1`，以 QR 或 `.loom-resume`
带外交付；Linux 通过受保护文件或标准输入导入，并与 progress receipt 已固化的 pending
core/identity/admission/retry binding 逐字段核对。本机 transaction hash 是最后已验 floor，管理员签发的
descriptor 可绑定响应丢失后服务端已前进的 state；返回的 progress/completion receipt 必须证明单调前进，
同阶段分叉或回退仍失败关闭。恢复时发送无 token 的
`EnrollmentResumeSubmissionV1`，只用原 identity key 对 fresh server nonce 重签 detached PoP。
`.loom-resume` 必须是无未知字段、无尾随空白的 exact canonical 普通文件（也可从标准输入读取）；
客户端不得在 identity 缺失时生成替代 key。它从 descriptor 的 2–3 个镜像重新取得 exact
Invite proof/catalog，以本机 v1 platform key 与 migration anchor 重放 authority lineage，随后用
catalog parent Head 对应的 ControlSet 验 config QC；descriptor 自报 hash 不能充当 trust root。
该 descriptor 不经公网 mirror 动态发布，客户端不能自动刷新；ControlSet 只幂等
继续/取回既有结果，不延长旧 capability、不重消费 token。

### v2 Linux 命令

签名客户端包可直接安装并执行同一条 v2 路径：

```bash
sudo ./install.sh --invite-v2-file ../client.loom-invite
```

在 root 身份下从标准输入或普通 exact canonical `.loom-invite` 文件执行初次加入：

```bash
sudo loom client enroll-v2 \
  -invite-file /path/from/private-channel/device.loom-invite
```

也可使用 `-invite-uri 'loom://enroll/v2#d=…'`，但 URI 会进入 shell history，生产环境不推荐。
命令只访问 descriptor 中的 2～3 个认证 mirror；验证 proof 与 catalog 后，先尝试真实
HY2/QUIC tunnel，UDP 不可用才尝试 catalog 中独立的 Trojan/TLS generation。outer WebPKI、
SPKI pin、inner overlay IP SAN 和 private service SPKI 均会验证，任何一层都不能关闭校验。

若本轮只到 `reserved` 或 `issued_provisional`，命令以成功提交状态退出，并保留同一个
`/var/lib/loom/client-v2/pending.json`、identity、CSR 与 request ID。不要删除该目录或换 key。
管理员线性化确认后私下交付 `.loom-resume`，Linux 使用原 v1 migration trust root 恢复：

```bash
sudo loom client resume-v2 \
  -resume-file /path/from/private-channel/device.loom-resume \
  -v1-platform-pubkey /etc/loom/trust/platform.pub \
  -v1-platform-key-id '<certified-key-id>' \
  -v1-migration-anchor 'sha256:<digest>'
```

若完成态引用 sealed secret artifact，默认命令会在清理临时 capability/tunnel 之前，从同一个
private Enrollment 服务按 ciphertext SHA-256 自动取得 completion 已授权的 exact canonical
envelope；服务端同时核对 cluster、Invite、completed transaction 与 result ref，客户端再逐项
核对 digest、owner、recipient key 与 result refs。该读取不会经过公网 distribution，也不需要
额外 bearer。

受控离线恢复时，也可把 private artifact store 导出的 envelope 放入 root-only 目录；文件名为
ref 中 ciphertext SHA-256 的 64 位小写十六进制加 `.json`，命令按 result ref 取用，不扫描其他文件：

```bash
sudo loom client resume-v2 \
  -resume-file device.loom-resume \
  -v1-platform-pubkey /etc/loom/trust/platform.pub \
  -v1-platform-key-id '<certified-key-id>' \
  -v1-migration-anchor 'sha256:<digest>' \
  -secret-envelope-dir /run/loom-enrollment-artifacts
```

也可按 result ref 的规范顺序重复使用 `-secret-envelope <file>`；两种离线输入不能混用，提供任一
离线输入时不会同时联网拉取 artifact。

客户端会逐项核对 envelope digest、owner、recipient key 与 result refs，解封后把 certificate、
Device view 承诺的 Linux config 会同时从原 descriptor 钉住的 public mirrors 以无 token
content-addressed GET 取回，并与 floors、stable claim 摘要和 credentials 一次提交到
root-only `state.json`，成功后
才删除 pending。原始 Invite/Resume carrier 和 sealed envelope 由交付方负责在受控存储中销毁；
Loom 不会擅自删除调用者提供的文件。

## v2 稳态 private config 与 report

Enrollment completion 的 certified Device view 必须承诺并释放
`secret_id=device-private-control`、`purpose=device_credential` 的 sealed credential；其中把
`ControlServiceDirectoryV1`、exact ControlSet、directory hash 与 internal CA roots 绑定到
一个已认证且不高于 Device view durable floor 的 Head。首次交付通常绑定 Enrollment base
authority；后续目录/CA 或 ControlSet 轮换由新 Device-owned sealed credential 原子替换，旧
recovery/control epoch、未来 Head 与同坐标分叉均失败关闭。客户端解封后与正式 certificate/view/floors 一起写入 0600 state，
稳态命令只从该 durable credential 选 private overlay tuple，不接受公网 `latest` 作为替代。

```bash
sudo loom client sync-v2-view \
  -state-dir /var/lib/loom/client-v2
```

命令只拨号 directory 中的 exact overlay tuple，验证 TLS 1.3、internal CA、IP SAN、
SPKI pin 和 Device mTLS，并在 QC/Merkle/identity/floor 全部通过后才替换 LKG。
如 final Device view 的 config/secret refs 改变，同步会先从 durable mirror refs 取回全部
Linux config，再用本机 wrapping key 解封 delivery 中的 exact Device envelopes；任一制品失败
都不推进 floor，全部到齐后才与 final view/ControlSet 原子提交。
旧版 installation 尚未包含该 sealed credential 时，迁移期才允许同时传入
`-directory`、`-directory-hash`、`-control-set` 与 `-internal-ca` 四项；部分提供会失败关闭。
首次成功同步后 current/previous ControlSet 进入 durable state，后续动态 ControlSet 更新由
private delivery 的完整保留窗口验证，不再要求操作者逐次替换 ControlSet 文件。

上报 payload 必须是与服务端 reader contract 一致的 exact canonical JSON object：

```bash
sudo loom client report-v2 \
  -state-dir /var/lib/loom/client-v2 \
  -payload /run/loom/device-health.json \
  -kind health -payload-schema 1
```

reporter 在网络发送前先把已签 exact envelope 写入
`/var/lib/loom/client-v2/device-report-journal.json`。请求或进程中断后，下次运行先重放该
pending bytes；收到 `204` 前不会推进 sequence。

同步 Device view 后，默认使用与 view 原子保存的 `linux-link-intents` exact canonical
artifact 提交本机 runtime LKG。先验收 runtime LKG 并预览完整安装事务（不安装配置或改动服务）：

```bash
sudo loom client accept-v2-runtime \
  -state-dir /var/lib/loom/client-v2 \
  -dry-run
```

确认后执行同一条验证路径并安装：

```bash
sudo loom client accept-v2-runtime \
  -state-dir /var/lib/loom/client-v2 \
  -apply
```

仅旧 installation 迁移时需要显式给出
`-link-intents /etc/loom/client-v2/linux-link-intents.json` 与
`-runtime-artifact /etc/loom/client-v2/linux-runtime.json`。

命令重新打开 durable Device LKG，不接受命令行自报 Device 职责、grants 或 credential；只使用
与 view 原子保存的 current/previous ControlSet 及正式 enrollment installation 内已安装的
credential ID，并钉住 artifact 的 size、content hash、
render contract、Device generation、EndpointSet transport 及已见 listener generation floor。
`linux-link-intents` 不是客户端临时拼出的 JSON：服务端必须在生成下一张 Device view 前，按
`linux-link-intents-v1` 合约确定性生成并发布 exact canonical artifact。artifact 的
`authority_head_hash` 固定为待生成 Head 的 parent，随后返回的 typed content ref 才进入 Device
view；Linux reader 会同时核对该 parent binding，避免 artifact content hash 与引用它的 Head
形成循环，也拒绝把无关 Device 或 bootstrap edge 混入稳态运行面。
第二个 `linux-runtime-v1` artifact 只携不含秘密的 renderer output，并同时绑定上述 LinkIntent 的
exact content hash/generation、每条 action、每个 listener generation、固定 config path 与 runtime
tag。客户端只允许 LinkIntent 已授权的 credential placeholder，在节点上从原子安装的 sealed
credentials 注入；密钥不会进入命令行、公开 artifact 或输出。
包含 `control_overlay` 时还必须传入 `-control-peer-directory`；joint Head 必须同时传入
`-previous-control-set`。验证失败不会覆盖已有的
`/var/lib/loom/client-v2/link-runtime-state.json`。

`-apply` 使用同一个部署事务先在 staging 目录执行 `sing-box check`/`wg-quick strip`，再以
WG → sing-box → Agent 的顺序替换、启动并验证；任一步失败会恢复旧文件和旧 unit 状态。
installed inventory 以 CAS 保护，删除仅限该 inventory 中的固定 v2 路径。v2 使用
`/etc/loom/{sing-box,agent}/v2/`、`lmv2-*` WireGuard interface 及
`loom-client-v2-{sing-box,agent}.service`，不会覆盖或停用 v1 路径。若新旧监听资源冲突，
v2 启动验证失败并恢复旧状态。当前启动器尚不负责退役 v1；这是完整迁移的缺口，
新版接管须按[迁移验收](../protocols/control-plane/migration.md#从当前实现迁移)完成对应旧路径清理。

Device view 进入 certified `revoked` 或 `decommissioned` tombstone 后，同一命令不再读取已被
清除的 runtime/secret artifact。`-dry-run` 只展示受影响的旧 v2 inventory；`-apply` 在相同
CAS/回滚事务中先停服务，再删除该 inventory 内的固定 v2 文件和 inventory 自身。active Device
不能调用这条下线路径，terminal Device 也不能靠命令行重新注入 runtime 或 authority。

操作者卸载本机 v2 软件运行面时使用发行包中的固定入口：

```bash
sudo ./uninstall.sh
```

它调用 `loom client uninstall-v2-runtime -apply`，同样只按 root-owned installed inventory
先停用 unit/WireGuard interface，再以 CAS/回滚事务删除固定 v2 runtime 文件。这个本机动作不冒充
控制面撤权，也不删除 Device identity、正式 LKG、四组 floor 或报告 journal；重装后仍按 current
certified policy 恢复。当前 `/usr/local/bin/{loom,sing-box}` 和平台 trust 仍与 v1 兼容路径
共享，因此本机卸载脚本保留这些文件；存量迁移另须删除已替换的旧服务与调用路径。需要移出网络时，管理员仍必须先完成 certified
暂停/撤权/decommission，不能用本机卸载替代。

开发检查可按需要运行，结构化结果默认写入忽略的 `out/evidence/`，不包含域名、IP、
Device ID、证书或 secret：

```bash
scripts/test-linux-v2-development.sh
```

该入口要求固定的 sing-box 1.11.4、`unshare` 与 `ip`；它会在隔离的 user/network namespace
中实际启动 TUN 数据面，覆盖域名恢复、UDP DNS、HTTP/TLS 与进程停止，再执行双架构构建。

该结果只证明 Linux 双架构可构建及 wire/client/control 单元与集成套件通过，字段明确标记
`real_host_acceptance=false`、`gate_b=false`；它不能替代 #12 的干净主机、真实网络、职责流量、
故障注入或控制面迁移的正常流程验收。

### 原生验收资产复用与续跑

真实主机验收可能跨多次会话。开始下载镜像、拉取容器或新建 VM 前，必须先检查当前
验收宿主已有的受控资产，避免重复下载或把上一次留下的可写客机误当成干净系统：

```bash
docker image inspect loom/linux-acceptance-base:ubuntu-24.04-amd64 >/dev/null
docker image inspect ubuntu:24.04 >/dev/null
docker ps -a --filter 'name=^/loom-accept-' --format '{{.Names}} {{.Image}} {{.Status}}'
find /var/cache/loom/acceptance -maxdepth 2 -type f \
  \( -name '*.qcow2' -o -name '*cloudimg*.img' \) -print
```

这些命令只做本机资产发现；任何一项不存在都不能靠 `docker run` 的隐式 pull 或未校验 URL
自动补齐。确需下载时，先记录发行方、版本、架构和预期 SHA-256，再显式下载并验签/验摘要。
临时目录（包括 `/tmp`、`/var/tmp`）会被清理，不是可跨会话依赖的镜像缓存。

本机约定的 amd64 不可变基础镜像标签是
`loom/linux-acceptance-base:ubuntu-24.04-amd64`。它只含干净 Ubuntu 与验收工具；每个场景都从
该标签创建新的可写容器/VM，先证明 `/etc/loom`、`/var/lib/loom` 和 Loom unit 不存在。跑过
安装或 Enrollment 的实例只能用于同一场景续跑，不能重新标记为干净基础镜像。

每次续跑先在受控证据库记录并核对：Loom commit、制品 SHA-256、基础镜像 ID/digest、
`uname -m`、`/etc/os-release`、虚拟化类型、场景状态和可写实例是否已销毁。真实地址、域名、
Device ID、证书、token、密钥、原始抓包和 SSH inventory 仍只进入忽略目录或外部受控证据库；
仓库只提交脱敏摘要。amd64 原生结果与 arm64 构建/静态结果分别出具；当前范围不要求
arm64 原生运行结果，也不能用 Android ABI 冒充 Linux 主机证据。
