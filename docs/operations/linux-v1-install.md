# Linux v1 兼容安装与维护

**适用条件：** 仍使用 v1 Invite、平台签名和 signed pull 的部署；本手册不要求继续保留已被新版替换的入口。
v2 安装使用[Linux v2 手册](../linux-client-install.md)，源码范围见[实现对照](../implementation.md)。

v1 的 `use_loom` Device 使用回环 mixed 入口，不接管宿主路由表或修改全局代理。
加入共用 v1 SSOT/publisher/signed pull，只绑定控制面已创建的 Device，不再新建第二份身份记录。
目标机须能访问已验证的 v1 加入端点和分发地址，具有 root/sudo、`tar` 与 `sha256sum`。
管理员经私有 HTTPS 和有效管理员证书创建 Device；没有 UI 密码登录。

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
属于客户端迁移目标，也不能以在 Current Paths 页面手选路径替代。源码接线及缺口见
[实现对照](../implementation.md)。

## v1 运行手册边界

- 本手册的历史命令示例仍以 Linux amd64 为准；目标 v2 的同构可重现包覆盖 amd64/arm64。
  deb/rpm、Linux GUI 与通用卸载器不属于该 v1 契约；
- 加入码消费/身份绑定不等于在线，Devices 列表中的数据面健康必须来自后续可信报告；
- access-only 的安全回收必须同时完成 signed decommission、移除/吊销、秘密清理与 purge
  canary；服务器职责和其他平台同样必须同时撤销控制面与数据面授权，不能仅用删除列表
  记录冒充凭据已经失效；
- Windows 与 Android 客户端宿主不在这个分发包内。

架构与安全边界见[客户端接入规范](../client-access.md)；实际制品与运行结果按
[部署记录](local-deployment.md)核对。
