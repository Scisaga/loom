# Windows 11 原生测试虚拟机

[客户端接入设计](client-access.md#84-开发构建与验证环境) ·
[Windows 客户端](../clients/windows/README.md)

这台虚拟机只承担 Loom Windows 客户端的**原生执行与验收**。源码、Git 历史、平台
签名能力、服务端凭据和发布判断全部留在 Linux 工作树；虚拟机只接收本次测试所需的
已编译制品和脚本，并回传脱敏证据。它不是第二个开发环境、控制面节点、发布源或
Windows 状态权威。

## 固定边界

- Guest 是 Windows 11 Pro x64，使用 QEMU/KVM、Q35、OVMF Secure Boot、swtpm 2.0
  和 qcow2；默认 4 vCPU、4 GiB 来宾内存和 100 GiB 稀疏磁盘。systemd 对 QEMU、图形
  缓冲和设备模拟的总内存设 7 GiB 上限，避免安装高峰触顶，同时给宿主保留余量。
- QEMU 直接使用 user-mode NAT，不创建 libvirt bridge，不修改现有 Docker、WireGuard
  或 nftables 网络。管理网卡只承载宿主转发，数据网卡才允许 Loom 和故障注入使用。
- SSH、RDP 和 VNC 只监听宿主 `127.0.0.1`。跨机器查看桌面时由操作者建立 SSH
  转发，不把这些 listener 暴露到局域网或公网。
- 宿主 `loomvm` 是无登录 shell 的 system user，只能访问 KVM 和 VM 状态目录；QEMU
  的 systemd unit 没有宿主 root 权限，也不能读取工作树或 root home。
- Guest `loomtest` 是专用本地管理员。OpenSSH 只接受服务器上的专用 Ed25519 公钥，
  只监听管理网卡，禁用密码登录并钉住 guest host key。RDP 也只允许管理网卡入站；其
  密码只存在于宿主 root-only 私有文件。
- Guest 的 Loom Device 私钥仍由 Windows DPAPI 产生和保存，绝不复制回宿主。平台
  签名私钥也绝不进入 guest。

Windows 虚拟机能验收 Win32 GUI、DPAPI、CNG、SCM Service、MSI、Wintun/TUN、路由
清理、重启恢复和升级/卸载。它不能替代 ARM64 实机、真实 Wi-Fi/有线切换、睡眠唤醒、
多显示器/DPI 组合或长期桌面行为的最终验收。

## 介质与首次准备

只接受操作者提供的合法 Windows ISO，或从
[微软 Windows 11 正式下载页](https://www.microsoft.com/software-download/windows11)
取得的 x64 多版本 ISO。当前 provisioning 选择简体中文 `Windows 11 Pro` image；脚本
在创建磁盘前验证微软公布的 SHA-256，并用镜像内不随显示语言变化的
`EditionID=Professional` 找到唯一 image index，找不到或不唯一时失败，不能退回 Home
或猜 index。

provisioning 不保存或注入产品密钥；Windows 授权由操作者用其合法 Pro 许可独立完成，
激活状态既不是 Loom 配置，也不能作为客户端功能通过的证据。

宿主依赖是 QEMU/KVM、OVMF、swtpm、wimlib、dosfstools、mtools、socat、AppArmor tools
和 OpenSSH client；当前服务器已经安装。官方 ISO 固定放到 provisioning 报错所示的
`media/` 文件名后再运行 setup。setup 会幂等创建 `loomvm` system user、KVM 补充组、
宿主专用 Ed25519 密钥和随机 Guest 口令；不会复用仓库或操作者的日常 SSH 身份。它还
只允许 `swtpm` 访问该 VM 的 `tpm/` 和 `runtime/*.sock`，若本机已有不同的 site-local
AppArmor 规则则拒绝覆盖，要求操作者显式合并。

SSH 只是管理和测试传输通道，不是 Loom 产品依赖。setup 从微软维护的
[PowerShell/Win32-OpenSSH 发布页](https://github.com/PowerShell/Win32-OpenSSH/releases)
取得固定版本的 x64 MSI，宿主校验固定 SHA-256，Guest
再次校验 SHA-256 和 Authenticode 签名后只安装 Server feature。包通过一次性 seed 离线
进入 Guest，避免首次安装依赖 Windows Update/CDN 是否可达；升级版本必须同时显式更新
固定 URL 和摘要，不能静默跟随 latest。

setup 还会从宿主当前网络保存一个可达 IPv4 DNS 和可选 HTTP(S) 出站代理，专供 Guest
首次安装 Windows 可选组件。它们存放在 root-only `secrets/`，注入一次性 seed，并作为
Guest 的机器级网络设置；真实地址不进入 Git、命令输出或验收证据。若宿主网络变化，
可在首次安装前由 root 更新相应私有文件并重新运行 setup。带用户名或密码的代理 URI
会被拒绝，避免把可复用凭据写入 Guest。

宿主私有状态固定在 `/var/lib/loom/windows-test-vm/`，不进入 Git：

| 内容 | 位置 | 权限与生命周期 |
|---|---|---|
| Windows ISO、固定 OpenSSH MSI、一次性 USB/FAT seed | `media/` | QEMU 可读；安装成功后销毁含口令的 seed |
| 活动磁盘与 UEFI vars | `disk/` | 仅 `loomvm` 可读写 |
| TPM 状态 | `tpm/` | 与磁盘和 Device 身份共同保留 |
| SSH host-key pin、RDP 本地口令、出站 DNS/代理输入 | `secrets/` | 仅宿主 root 可读 |
| monitor socket、临时截图 | `runtime/` | VM 生命周期内可再生 |

初次准备由 root 执行：

```bash
sudo ./scripts/setup-windows-test-vm.sh
sudo ./scripts/windows-test-vm.sh start
sudo ./scripts/windows-test-vm.sh wait-ready
sudo ./scripts/windows-test-vm.sh finalize-install
sudo ./scripts/windows-test-vm.sh verify
```

`setup-windows-test-vm.sh` 是一次性 provisioning 入口；已经完成 `finalize-install` 后会拒绝
重新生成含口令的安装介质。重装意味着销毁现有 Windows/TPM 身份，必须作为单独的显式
操作处理，不能用重复运行 setup 暗中重置。

`finalize-install` 只有在 guest 回读为 Windows 11 Pro、bootstrap marker 正确、SSH 会话
拥有管理员能力、TPM 2.0 与 Secure Boot 可用、公钥 SSH/SFTP 使用限定的绝对路径、双网卡
和管理面防火墙符合约束且一次性 AutoLogon 口令已清除时才成功。随后它正常关闭 Windows，
销毁包含本地初始口令的 seed，
以无安装介质的模式重启并再次执行同一验证。systemd unit 默认不随宿主开机启动，
避免生产宿主无意长期占用内存；需要时显式 `start`。

## 日常使用

```bash
sudo ./scripts/windows-test-vm.sh status
sudo ./scripts/windows-test-vm.sh start
sudo ./scripts/windows-test-vm.sh verify
sudo ./scripts/windows-test-vm.sh ssh
sudo ./scripts/windows-test-vm.sh screenshot out/demo-windows-screen.ppm
sudo ./scripts/windows-test-vm.sh stop
```

`endpoints` 显示当前三个 loopback endpoint，供本机工具或经 SSH 转发的 RDP/VNC viewer
使用。不得把显示出的端口改绑到非 loopback 地址。

每次测试使用受限 run ID 和独立目录。Linux 先完成源码修改、交叉构建、签名/哈希验证，
再只传入本轮文件：

```bash
sudo ./scripts/windows-test-vm.sh stage demo-native-run \
  out/demo-client.exe out/demo-client.test.exe out/run.ps1
sudo ./scripts/windows-test-vm.sh run demo-native-run
sudo ./scripts/windows-test-vm.sh collect demo-native-run
```

需要真实桌面会话的 Win32 测试使用 `run-interactive`。它只触发预建的
`LoomInteractiveTest` 任务，从该 run 目录读取 `run.ps1`；账户未登录时失败，不会静默
改在 Session 0 执行。GUI、UAC 或路由测试结束后必须回读实际窗口/运行时状态，不能以
进程启动或测试脚本退出零代替产品结果。

run 脚本只把允许回传的日志、截图和结构化结果写入其 `evidence/` 子目录。`collect` 只
取回这个目录，保存到被 Git 忽略的 `deploy/evidence/windows-vm/`；Device 私钥、DPAPI
vault、二维码原文、节点证书和未脱敏配置不得进入 evidence。

数据网卡可由宿主独立断开和恢复：

```bash
sudo ./scripts/windows-test-vm.sh data-down
sudo ./scripts/windows-test-vm.sh data-up
```

这只形成虚拟以太网故障，不得描述成真实 Wi-Fi、蜂窝或公网质量证据。

## 身份、快照与恢复

干净基线只能建立在 Windows、SSH 和测试权限准备完成而**尚未 Enrollment**的状态。
Enrollment 后，磁盘、OVMF vars 和 TPM 状态构成同一个不可拆分的本机身份；不能只回滚
qcow2，也不能复制 VM 后让两个实例同时运行同一 Device。恢复干净基线后必须在控制面
创建新的测试 Device 或按正式 Rejoin 流程取得新二维码。

不要把生产身份或现网私有材料放入这台 VM。测试 TUN 前先保留管理通道并设置有界超时；
若 guest 无法正常关闭，`force-stop` 只停止 QEMU，不代表路由清理、stale 或恢复验收成功。
