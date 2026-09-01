# Loom Linux 客户端安装

本文面向安装 `linux/amd64` Device 的管理员。具有 `use_loom` 职责的 Device 使用本地
`127.0.0.1:1080` mixed 入口，不接管宿主机路由表，也不会自动修改全局代理环境变量。
注册和安装共用现有 SSOT、publisher 与 signed pull，不创建另一套网络或选路规则。

## 准备条件

- 目标机是 Linux amd64，能够通过 HTTPS 访问邀请中写明的中控注册端点，并能访问
  中控下发的分发地址；
- 具有 root/sudo 权限；
- 在中控登录运维会话。只有中控能创建邀请和下载已验证的客户端包；
- 目标机上有 `tar` 和 `sha256sum`。Loom 与 sing-box 已包含在分发包内。

## 1. 创建邀请

在中控打开 **Devices → Add Device**，填写便于识别的设备名称并选择不可变的 Device
purpose。不要填写平台、出口节点或路径：平台由客户端上报，路由仍由中控规则和 Agent
决定。默认 purpose 只在本机使用 Loom；服务器 purpose 展开为 `forward` 与
`internet_egress`，不是另一种 Enrollment 协议。

创建成功页只展示一次短时邀请，并提供三种等价载体：

- 扫描二维码；
- 点击二维码下载 `client.loom-invite`；
- 复制 `loom://enroll#…` URI，供无浏览器的 Linux 主机使用。

三者共享同一个短 TTL、一次性 token。普通重启、断线重连和配置更新不会重新注册。
不要把邀请 URI 放进 shell 参数、聊天记录或工单；它是有效期内的 bearer secret。

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

## 3. 服务器职责先声明可达事实

只有邀请的 Responsibilities 包含 `forward` 时，才需要在 claim 前创建严格的本地配置：

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

`public_endpoint` 是不带 scheme/端口的真实公网 DNS 或 IP；`inbound_port` 是部署实际开放的
UDP 端口；`direction` 只能是 `bidirectional`、`reverse_only` 或 `direct_only`。这些字段
声明服务器如何加入现有拓扑，不是让客户端手选路径或出口，也不会创建第二套选路逻辑。

客户端在本机创建或复用 `/etc/wireguard/node.key`，只把公钥随 claim 发给中控。缺少
`/usr/bin/wg` 或 `/usr/bin/wg-quick` 时，会在消费邀请前通过受支持的 apt/dnf/yum/apk/
zypper 安装 `wireguard-tools` 并复检；失败不会建立 Device identity 或修改 SSOT。
公网可达性仍由配置应用后的现有签名 Hysteria2/拓扑观测验证，不新增一套“再次拨入”逻辑。

## 4. 安装并注册

已经下载邀请文件时：

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

注册或首次 pull 因网络中断时，保留 `/etc/loom/client`；在页面所示邀请有效期内，
用同一份邀请重跑安装命令。相同 identity/request 的重试是幂等的；删除该目录会丢失
设备私钥，不能作为普通重试手段。默认命令等待 provisioning 最长 5 分钟；邀请过期后
需要由运维人员创建新邀请。

## 5. 让应用使用 Loom

安装完成后，只让需要接入的应用显式使用回环代理。例如：

```bash
ALL_PROXY=socks5h://127.0.0.1:1080 your-command
```

使用 `socks5h` 可让域名在代理侧解析，避免本地 DNS 与中控选路语义分叉。不要把该
变量无条件写入整机全局环境；这可能影响包管理、控制通道和无关服务。

Direct / Auto / 指定出口三个模式复用同一个 `1080` 入口。Auto 使用中控下发的
`Host → Service → Policy → Agent`；指定出口只固定最后一跳，前置中继继续自动择优。
当前 Linux 分发包完成注册、安装和运行闭环，但尚未提供独立 GUI；也不要在 Current
Paths 页面手选路径。

## 当前边界

- 当前只发布 Linux amd64 `tar.gz`，没有 deb/rpm、Linux GUI 或通用卸载器；
- 邀请消费/身份绑定不等于在线，Devices 列表中的数据面健康必须来自后续可信报告；
- 控制面与数据面双重吊销尚未完成；不要用删除列表记录冒充凭据已失效；
- Windows 与 Android 客户端宿主不在这个分发包内。

架构与安全边界见[客户端接入设计](client-access.md)，生产是否已经运行本版本见
[当前状态](status/current.md)。
