# Loom Linux 客户端安装

> **适用范围：v2 当前实现与 v1 兼容流程。** v2 已提供严格 Invite/Resume carrier、
> mirror/catalog/proof/QC verifier、HY2 主入口与 Trojan/TLS fallback、私有 Enrollment、
> pending 恢复和完成态原子安装命令。本文后半仍保留单 control、v1 invite、平台公钥、
> `public_endpoint + inbound_port` 和 signed pull 的兼容说明。v2 的紧凑 QR、
> 静态 distribution catalog、bootstrap tunnel、ControlSet/QC、托管域名、EndpointSet 和 listener generation 见
> [分布式控制平面设计](distributed-control-plane.md)；两代状态目录和输入不可混用。
> 目标 v2 的 Create Device 只由已入网管理端经 overlay 访问
> `ControlServiceDirectoryV1` 中 `role=control_api` 的私有服务并使用 admin cert 提交；
> Linux bootstrap claim 从已验公网 transport 建立限路由临时隧道，只访问 QR 中
> `PrivateEnrollmentServiceRefV1` 所指的私有 `role=enroll` 服务。下文的公网 v1 HTTPS claim 是历史兼容，
> 不是目标安全边界。

本文面向安装 `linux/amd64` Device 的管理员。具有 `use_loom` 职责的 Device 使用本地
`127.0.0.1:1080` mixed 入口，不接管宿主机路由表，也不会自动修改全局代理环境变量。
加入和安装共用 v1 SSOT、publisher 与 signed pull，不创建另一套网络或选路规则。
下文保留的 `Enrollment`、`loom://enroll`、`--no-enroll` 和 `loom client enroll` 都是
内部协议或 Linux CLI 的兼容拼写，不表示还要创建或注册另一个客户端记录；产品动作
始终是把客户端绑定到控制平面已创建的 Device 并加入网络。

当前项目的 Linux 原生主机验收范围是 amd64。arm64 制品仍须可重复构建并通过静态、交叉
编译和格式验证，但不要求提供 arm64 实机或原生主机，不能把手机的 `arm64-v8a` ABI 当作
Linux arm64 验收环境。

## 准备条件

- 目标机是 Linux amd64，能够通过 HTTPS 访问加入码中写明的 v1 control 加入端点，并能访问
  其下发的分发地址；
- 具有 root/sudo 权限；
- 在 Loom overlay 内打开 private control HTTPS；导入 `admin.p12` 后才能创建 Device、生成加入码和
  下载已验证的客户端包。没有管理员证书时 UI 仅提供只读信息，不存在 UI 密码登录；
- 目标机上有 `tar` 和 `sha256sum`。Loom 与 sing-box 已包含在分发包内。

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
v2 启动验证失败并恢复旧状态；Gate B 前不会自动退役 v1。

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
certified policy 恢复。Gate B 前 `/usr/local/bin/{loom,sing-box}` 和平台 trust 仍与 v1 兼容路径
共享，因此卸载脚本明确保留这些文件。需要移出网络时，管理员仍必须先完成 certified
暂停/撤权/decommission，不能用本机卸载替代。

开发门禁可一键运行，并把不含域名、IP、Device ID、证书或 secret 的结构化结果写到忽略目录：

```bash
scripts/test-linux-v2-development.sh
```

该入口要求固定的 sing-box 1.11.4、`unshare` 与 `ip`；它会在隔离的 user/network namespace
中实际启动 TUN 数据面，覆盖域名恢复、UDP DNS、HTTP/TLS 与进程停止，再执行双架构构建。

该结果只证明 Linux 双架构可构建及 wire/client/control 单元与集成套件通过，字段明确标记
`real_host_acceptance=false`、`gate_b=false`；它不能替代 #12 的干净主机、真实网络、职责流量、
故障注入或 #10 Gate B。

### #12 验收资产复用与续跑

#12 的真实主机验收可能跨多次会话。开始下载镜像、拉取容器或新建 VM 前，必须先检查当前
验收宿主已有的受控资产，避免重复下载或把上一次留下的可写客机误当成干净系统：

```bash
docker image inspect loom/linux-acceptance-base:ubuntu-24.04-amd64 >/dev/null
docker image inspect ubuntu:24.04 >/dev/null
docker ps -a --filter 'name=^/loom-accept-' --format '{{.Names}} {{.Image}} {{.Status}}'
find /var/cache/loom/acceptance -maxdepth 2 -type f \
  \( -name '*.qcow2' -o -name '*cloudimg*.img' \) -print 2>/dev/null
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

## 1. 创建 Device 和加入码

在中控打开 **Devices → Create Device**，选择 Linux 平台并直接勾选职责：
`use_loom`、`forward`、`internet_egress`。`internet_egress` 必须与 `forward`
同时选择；只有 `use_loom` 才选择允许访问的 Destination grants。不要填写出口节点或
路径，路由仍由 active signed 控制规则和 Agent 决定。本节是 v1 兼容流程：平台、职责、grants
和转发连接方向都固定在 v1 邀请中，客户端不能在 claim 时修改。目标 v2
不携 Device-wide direction，只在 Enrollment 后由 certified LinkIntent 按边固定 initiator。

创建成功页展示短时加入码。只含 `use_loom` 时可提供二维码和 `.loom-invite` 文件。
所有 Linux 组合都通过 shell bootstrap 消费页面显示的一次性 `loom://enroll#…` 输入：

- 在目标机本地执行页面给出的 shell bootstrap；
- 或由管理员先 SSH 到目标机，再执行完全相同的 bootstrap。

纯 `use_loom` Linux Device 也可单独点击 **Download join file** 下载
`client.loom-invite`，供 Linux CLI 使用。

SSH 不是另一种 Enrollment，也不由 Loom 中控保存主机地址、账号、私钥或口令。

### 安装页面的可达性分支

创建结果页必须在同一页面内联展示两个并列入口，不使用弹窗，也不让中控主动扫描 SSH：

```text
已有管理 SSH / ProxyJump 可达
  → 操作者自行打开 SSH 会话
  → 在目标机运行页面中的 shell bootstrap

SSH 未开放、不可达或节点位于 NAT 后
  → 使用云厂商控制台、串口/IPMI 或机器本地终端
  → 运行完全相同的 shell bootstrap
  → 节点主动访问 distribution、bootstrap ingress 和私有 Enrollment
```

页面不能从 `direction`、职责或 `nat_mapped` 推断 SSH 是否可达，也不提供要求上传 SSH
私钥/口令的表单。若节点出站访问 distribution 或已签 bootstrap ingress 失败，安装器应保留
可重试状态并明确显示失败阶段、目标角色和 transport；不得改用未签 URL、扫描其他端口，
也不得把它误报成 NAT 映射失败。应先完成包下载与校验，再通过标准输入消费一次性 URI，
避免在纯下载失败时浪费加入码。

这些方式共享同一个短 TTL、一次性 token。普通重启、断线重连和配置更新不会再次加入。
不要把加入 URI 放进 shell 参数、聊天记录或工单；它是有效期内的 bearer secret。

## 2. 下载并核对客户端包

目标 v2 同时发布 `loom-client-linux-amd64.tar.gz` 与 `loom-client-linux-arm64.tar.gz`；
二者由对应架构的 Loom/sing-box ELF 作为全部输入确定性生成。包内 manifest/checksums 必须覆盖
Loom `LICENSE`/`NOTICE`、sing-box license 与由实际 Go build version 生成的对应源码地址，缺少法律材料
时 builder 和 verifier 都失败关闭。

在 Devices 页下载与目标架构一致的归档。中控只在使用其独立的
`/etc/loom/trust/platform.pub` 验证 detached signature、archive 哈希和包内文件后
才提供下载；下载响应本身不把同目录公钥当成信任根。

把页面显示的 SHA-256 与本地文件核对：

```bash
printf '%s  %s\n' '<页面显示的 SHA-256>' \
  loom-client-linux-amd64.tar.gz | sha256sum -c -
```

不要只信随压缩包一起取得的公钥或校验值。如果需要在中控之外独立验签，应通过
另一个可信通道取得平台 Ed25519 公钥以及同一制品的 `.sha256`、`.sig`，再运行：

```bash
loom client verify \
  -archive loom-client-linux-amd64.tar.gz \
  -pubkey /path/from/trusted/channel/platform-signing.pub
```

中控发布人员从待发布的干净 commit 运行 `scripts/build-linux-client.sh`；脚本只构建
一次 Loom 二进制，用同一字节生成并验签客户端包，最后将 archive 作为提交标记原子
发布到 `/var/lib/loom/client-dist/`。脏工作树构建默认会被拒绝。

包内 `install.sh` 在修改本机前先核对全部 checksums，并分别执行候选 Loom selfcheck 与
sing-box version 检查。三个共享 package 文件在同一 `deploy.lock` 下替换；每次变更前把旧文件
和固定目标写入 root-only transaction manifest 并持久化。普通失败/信号立即恢复旧文件；若在
进程无法捕获的中断点退出，下一次安装会先恢复唯一未完成事务，再开始新安装。安装成功前不会
把 v1 state directory 当成 v2 副作用创建。

## 3. 转发职责先声明可达事实

只有所选 Responsibilities 包含 `forward` 时，才需要在消费加入码前创建严格的本地配置：

```yaml
# /etc/loom/device.yaml
server:
  public_endpoint: edge.example.net
  inbound_port: 61698
  # inbound_protocol: hysteria2 # 默认；也可显式选择 trojan
  direction: bidirectional
  # country: CN       # 可选
  # city: Beijing     # 可选
  # provider: example # 可选
```

`public_endpoint` 是不带 scheme/端口的 DNS 或 IP；`inbound_port` 使用的传输由
`inbound_protocol` 决定：默认 Hysteria2/UDP，显式 `trojan` 时为 TCP，不能一律当作 UDP。
`direction` 必须与中控邀请一致，只能是 `bidirectional`、`reverse_only` 或
`direct_only`。在本文 v1 兼容契约中，`reverse_only` 由该 Device 主动建立并维持反向 WireGuard 隧道；它表达
公网/NAT 可达性而不是地理位置。部署可以将境外服务器设为 `reverse_only`，但协议并不
禁止境外 Device 承担接入或其他已授权职责。

这两个静态字段只描述 v1 bootstrap 事实。目标 v2 中每个 `forward` server 均具有
稳定 FQDN、只服务 fake/immutable distribution 的 Nginx、DNS-01 证书管理、HY2 UDP 和不同
UDP tuple 上的 WG listener；正式版另有独立 Trojan/TLS TCP bootstrap fallback。直连服务器使用
443 或 EndpointSet 中的替代 HTTPS 端口，NAT server 另显式区分 public/local port 并预配 TCP/UDP 映射。
这些由 certified `PublicEndpointIntent`、`ManagedZone` / `DomainBinding`、按用途拆分的 EndpointSet 和
listener generation 表达，并通过新旧 listener overlap 轮换；
DNS 解析结果和本机探测只能帮助选 endpoint，不能自行授权未签地址或端口。

NAT 映射由操作者在 Loom 之外预先提供，Loom 不要求网关管理权限，也不通过 UPnP、
NAT-PMP 或供应商接口改动映射。安装完成后，本机 listener 自检和公网就绪是两个状态：
只有外部观察点对 signed public/local TCP/UDP tuple 逐项验证，并以真实跨节点流量确认
transport 一致后，`forward` public access 才能从 `preparing` 进入 active/advertised。
公网端口未开放或既有映射不匹配时，Device identity、软件和私有配置可以保留，但 UI 必须
逐 transport 显示失败并给出三种明确动作：检查主机防火墙、让操作者确认既有映射，或放弃
本次邀请并创建不含 `forward` 的 Device。不得自动改网关、扫描邻近端口或静默降级职责。

客户端在本机创建或复用 `/etc/wireguard/node.key`，只把公钥随加入请求发给中控。缺少
`/usr/bin/wg` 或 `/usr/bin/wg-quick` 时，会在消费加入码前通过受支持的 apt/dnf/yum/apk/
zypper 安装 `wireguard-tools` 并复检；失败不会建立 Device identity 或修改 SSOT。
v1 的主动公网 LinkMetric 目前只定义 Hysteria2；Trojan 入口不得伪造或借用该指标，只能显示
listener 自检与真实拨号证据，后续扩展须使用版本化观测 schema。不新增一套“再次拨入”循环。

## 4. 安装并加入

已经下载加入文件时：

```bash
tar -xzf loom-client-linux-amd64.tar.gz
cd loom-client-linux-amd64
sudo ./install.sh --invite-file ../client.loom-invite
```

只有复制的 URI 时，先安装二进制，再从标准输入粘贴一行 URI，最后按 `Ctrl-D`；这样
不会把 token 留在 shell history：

```bash
tar -xzf loom-client-linux-amd64.tar.gz
cd loom-client-linux-amd64
sudo ./install.sh --no-enroll
sudo /usr/local/bin/loom client enroll -stdin
```

客户端在本机生成 P-256 私钥和 PKCS#10 CSR，私钥不会发给中控。中控绑定身份后先
生成并预置秘密、原子提交 SSOT，再等待 v1 publisher 发布精确版本；这段时间状态是
`provisioning`，不是 online。ready bootstrap 完整返回后，客户端才落盘节点证书、
CA、平台公钥、release authority 和本机秘密，并执行首次 signed pull。任何一步失败
都不会用假配置启动服务。

加入或首次 pull 因网络中断时，保留 `/etc/loom/client`，并用同一份加入输入重跑安装
命令。相同 token、identity/CSR 与 request ID 的重试是幂等的；首次绑定仍受页面所示
TTL 限制，已经绑定的事务只在 v1 control 的有限恢复窗口内允许精确重放。删除该目录会丢失
设备私钥，不能作为普通重试手段。默认命令等待 provisioning 最长 5 分钟；恢复窗口
过期后必须由运维人员明确处理原 Device；v1 契约禁止用新码静默改绑身份。

## 5. 让应用使用 Loom

安装完成后，只让需要接入的应用显式使用回环代理。例如：

```bash
ALL_PROXY=socks5h://127.0.0.1:1080 your-command
```

使用 `socks5h` 把业务 FQDN 交给 Loom；Auto/指定出口配置必须让它穿过所选服务器链并由
最终出口的受管 resolver 解析，不能在本机或第一跳提前固化 A/AAAA。Direct 才在本机解析。
控制/配置/报告/数据入口自身的 hostname 使用独立 underlay resolver 和已签 endpoint identity，
不得借业务远端 DNS 建立隧道。不要把该变量无条件写入整机全局环境；这可能影响包管理、
控制通道和无关服务。

目标客户端的 Direct / Auto / 指定出口三个模式复用同一个 `1080` 入口。Auto 使用 active signed 控制平面
下发的 `Host → Service → Policy → Agent`；指定出口只固定最后一跳，前置中继继续自动
择优。v1 Linux 安装契约只要求加入、签名拉取和运行已下发配置；三态交互与独立 GUI
属于客户端迁移目标，也不能以在 Current Paths 页面手选路径替代。实际覆盖范围只见
[当前状态](status/current.md)。

## v1 运行手册边界

- 本手册的历史命令示例仍以 Linux amd64 为准；目标 v2 的同构可重现包覆盖 amd64/arm64。
  deb/rpm、Linux GUI 与通用卸载器不属于该 v1 契约；
- 加入码消费/身份绑定不等于在线，Devices 列表中的数据面健康必须来自后续可信报告；
- access-only 的安全回收必须同时完成 signed decommission、移除/吊销、秘密清理与 purge
  canary；服务器职责和其他平台同样必须同时撤销控制面与数据面授权，不能仅用删除列表
  记录冒充凭据已经失效；
- Windows 与 Android 客户端宿主不在这个分发包内。

架构与安全边界见[客户端接入设计](client-access.md)，生产是否已经运行本版本见
[当前状态](status/current.md)。
