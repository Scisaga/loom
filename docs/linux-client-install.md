# Loom Linux 客户端安装

> **适用范围：v1 安装流程契约。** 本文描述单 control、v1 invite、平台公钥、
> `public_endpoint + inbound_port` 和 signed pull 的兼容命令。目标 v2 的紧凑 QR、
> 静态 distribution catalog、bootstrap tunnel、ControlSet/QC、托管域名、EndpointSet 和 listener generation 见
> [分布式控制平面设计](distributed-control-plane.md)；迁移完成前不要混用两代字段。
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

## 准备条件

- 目标机是 Linux amd64，能够通过 HTTPS 访问加入码中写明的 v1 control 加入端点，并能访问
  其下发的分发地址；
- 具有 root/sudo 权限；
- 在 v1 指定 control 登录运维会话。v1 契约中只有该写入口能创建 Device、生成加入码和下载已验证的客户端包；
- 目标机上有 `tar` 和 `sha256sum`。Loom 与 sing-box 已包含在分发包内。

## v2 目标加入过程（不是下文 v1 命令）

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
6. ready 后原子安装正式 certificate/view/credentials，清除 token、capability、临时 profile/隧道，
   然后由同一 Linux 客户端宿主建立正式 WG control/L3 overlay；配置与报告继续访问
   `ControlServiceDirectoryV1` 中分用途的 `device_config`/`device_report` 私有服务。

这个流程不使用 WG 做首版 bootstrap，也不以 distribution HTTPS RTT 代替实际隧道测量。
自动重试只在 invite/capability 有效期内执行；重试保持 token 和字节完全相同的
`EnrollmentClaimCoreV2`，可对新 server nonce 重签 detached PoP，但不得改 core/hash。claim 已 commit
而 capability 过期时，管理员先经私有 `role=control_api` 服务线性化确认事务，
再生成不含 token、exact-bound 的 `EnrollmentResumeDescriptorV1`，以 QR 或 `.loom-resume`
带外交付；Linux 通过受保护文件或标准输入导入并与本机 pending core/identity 核对。
该 descriptor 不经公网 mirror 动态发布，客户端不能自动刷新；ControlSet 只幂等
继续/取回既有结果，不延长旧 capability、不重消费 token。

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

这些方式共享同一个短 TTL、一次性 token。普通重启、断线重连和配置更新不会再次加入。
不要把加入 URI 放进 shell 参数、聊天记录或工单；它是有效期内的 bearer secret。

## 2. 下载并核对客户端包

在 Devices 页下载 `loom-client-linux-amd64.tar.gz`。中控只在使用其独立的
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

- 本手册只定义 Linux amd64 `tar.gz`；deb/rpm、Linux GUI 与通用卸载器不属于该 v1 契约；
- 加入码消费/身份绑定不等于在线，Devices 列表中的数据面健康必须来自后续可信报告；
- access-only 的安全回收必须同时完成 signed decommission、移除/吊销、秘密清理与 purge
  canary；服务器职责和其他平台同样必须同时撤销控制面与数据面授权，不能仅用删除列表
  记录冒充凭据已经失效；
- Windows 与 Android 客户端宿主不在这个分发包内。

架构与安全边界见[客户端接入设计](client-access.md)，生产是否已经运行本版本见
[当前状态](status/current.md)。
