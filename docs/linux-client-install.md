# Loom Linux 客户端安装

本文面向安装 `linux/amd64` Device 的管理员。具有 `use_loom` 职责的 Device 使用本地
`127.0.0.1:1080` mixed 入口，不接管宿主机路由表，也不会自动修改全局代理环境变量。
加入和安装共用现有 SSOT、publisher 与 signed pull，不创建另一套网络或选路规则。
下文保留的 `Enrollment`、`loom://enroll`、`--no-enroll` 和 `loom client enroll` 都是
内部协议或 Linux CLI 的兼容拼写，不表示还要创建或注册另一个客户端记录；产品动作
始终是把客户端绑定到中控已创建的 Device 并加入网络。

## 准备条件

- 目标机是 Linux amd64，能够通过 HTTPS 访问加入码中写明的中控加入端点，并能访问
  中控下发的分发地址；
- 具有 root/sudo 权限；
- 在中控登录运维会话。只有中控能创建 Device、生成加入码和下载已验证的客户端包；
- 目标机上有 `tar` 和 `sha256sum`。Loom 与 sing-box 已包含在分发包内。

## 1. 创建 Device 和加入码

在中控打开 **Devices → Create Device**，选择 Linux 平台并直接勾选职责：
`use_loom`、`forward`、`internet_egress`。`internet_egress` 必须与 `forward`
同时选择；只有 `use_loom` 才选择允许访问的 Destination grants。不要填写出口节点或
路径，路由仍由中控规则和 Agent 决定。平台、职责、grants 和转发连接方向都固定在这次
邀请中，客户端不能在 claim 时修改。

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
  direction: bidirectional
  # country: CN       # 可选
  # city: Beijing     # 可选
  # provider: example # 可选
```

`public_endpoint` 是不带 scheme/端口的 DNS 或 IP；`inbound_port` 是部署使用的 UDP
端口；`direction` 必须与中控邀请一致，只能是 `bidirectional`、`reverse_only` 或
`direct_only`。`reverse_only` 由该 Device 主动建立并维持反向 WireGuard 隧道；它表达
公网/NAT 可达性而不是地理位置。当前部署可将境外服务器设为 `reverse_only`，但协议并不
禁止境外 Device 承担接入或其他已授权职责。

客户端在本机创建或复用 `/etc/wireguard/node.key`，只把公钥随加入请求发给中控。缺少
`/usr/bin/wg` 或 `/usr/bin/wg-quick` 时，会在消费加入码前通过受支持的 apt/dnf/yum/apk/
zypper 安装 `wireguard-tools` 并复检；失败不会建立 Device identity 或修改 SSOT。
公网可达性仍由配置应用后的现有签名 Hysteria2/拓扑观测验证，不新增一套“再次拨入”逻辑。

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
生成并预置秘密、原子提交 SSOT，再等待现有 publisher 发布精确版本；这段时间状态是
`provisioning`，不是 online。ready bootstrap 完整返回后，客户端才落盘节点证书、
CA、平台公钥、release authority 和本机秘密，并执行首次 signed pull。任何一步失败
都不会用假配置启动服务。

加入或首次 pull 因网络中断时，保留 `/etc/loom/client`，并用同一份加入输入重跑安装
命令。相同 token、identity/CSR 与 request ID 的重试是幂等的；首次绑定仍受页面所示
TTL 限制，已经绑定的事务只在中控的有限恢复窗口内允许精确重放。删除该目录会丢失
设备私钥，不能作为普通重试手段。默认命令等待 provisioning 最长 5 分钟；恢复窗口
过期后必须由运维人员明确处理原 Device，当前实现不能用新码静默改绑身份。

## 5. 让应用使用 Loom

安装完成后，只让需要接入的应用显式使用回环代理。例如：

```bash
ALL_PROXY=socks5h://127.0.0.1:1080 your-command
```

使用 `socks5h` 可让域名在代理侧解析，避免本地 DNS 与中控选路语义分叉。不要把该
变量无条件写入整机全局环境；这可能影响包管理、控制通道和无关服务。

目标客户端的 Direct / Auto / 指定出口三个模式复用同一个 `1080` 入口。Auto 使用中控
下发的 `Host → Service → Policy → Agent`；指定出口只固定最后一跳，前置中继继续自动
择优。当前 Linux 分发包完成加入、签名拉取和已下发配置的运行闭环，但尚未提供这组三态
交互或独立 GUI；也不要在 Current Paths 页面手选路径。

## 当前边界

- 当前只发布 Linux amd64 `tar.gz`，没有 deb/rpm、Linux GUI 或通用卸载器；
- 加入码消费/身份绑定不等于在线，Devices 列表中的数据面健康必须来自后续可信报告；
- Linux access-only 已完成 signed decommission、移除/吊销、秘密清理与 purge canary；
  服务器职责和其他平台的通用控制面/数据面双重吊销尚未完成，不能仅用删除列表记录
  冒充凭据已经失效；
- Windows 与 Android 客户端宿主不在这个分发包内。

架构与安全边界见[客户端接入设计](client-access.md)，生产是否已经运行本版本见
[当前状态](status/current.md)。
