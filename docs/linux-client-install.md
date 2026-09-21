# Loom Linux 客户端安装

本文面向 `linux/amd64` 的原生安装与 `linux/arm64` 的制品核验。Linux 与 Android 复用
[客户端运行时最小模型](rebuild/client-runtime-model.md)：Direct、Auto 和指定最终出口只是同一候选集合上的
`Preference`，实际路径必须来自 sing-box selector 回读，授权与可用性不得混为一谈。

## 下载与验证

控制面 Releases 页面只提供经过平台签名验证的通用公开制品。通过另一条可信通道取得平台 Ed25519 公钥，
再核验下载的 archive、checksum 和 detached signature：

```bash
loom client verify \
  -archive loom-client-linux-amd64.tar.gz \
  -pubkey /path/from/trusted/channel/platform-signing.pub \
  -arch amd64
```

发布者从干净提交运行 `scripts/build-linux-client.sh`。默认一次生成并签名 amd64、arm64 两份 archive；
amd64 必须完成原生 service 和业务验收，arm64 只做交叉构建、ELF/build-info 检查和签名往返，不把交叉结果
写成原生验收。

## 私有 Enrollment 与安装

管理员在私有控制面创建 Linux Enrollment。其 DeviceView 必须包含按稳定 ID 排序的授权候选和一份规范
`sing_box` RuntimeProfile；Invite 只用于受限 bootstrap tunnel，不进入 shell history、公开站点或日志。

```bash
tar -xzf loom-client-linux-amd64.tar.gz
cd loom-client-linux-amd64
sudo ./install.sh --invite-file ../client.loom-invite
```

installer 依次完成：

1. 核对 archive 内所有文件摘要，并把 Loom 与 sing-box 写入内容标识的 release 目录；
2. 通过 `loom client enroll` 在本机生成 Ed25519 身份，经私有 tunnel claim/resume，原子保存完整认证 LKG；
3. 用精确 release 中的 sing-box 对 LKG RuntimeProfile 做 preflight；
4. 切换 `/usr/local/lib/loom-client/current`，启动唯一正式 unit `loom-client.service`；
5. 等待 selector 实际回读。失败时恢复先前 current/unit，旧可运行 release 不被覆盖；
6. 成功后停用并移除旧 `loom-client-v2*` units，把旧身份/store 和配置移入 owner-only retired 目录，
   不作为 fallback 读取。

Enrollment 尚未批准时，installer 不启用 service。使用同一 Invite 重跑会 resume 同一事务，不生成第二身份。
`--no-enroll` 只安装已验证 release，不创建身份也不启动 service。已 Enrollment
的机器升级时使用 `sudo ./install.sh --upgrade`；它复用现有 owner-only 身份与完整
LKG，候选 preflight 或启动回读失败时原子恢复旧 `current` 与旧 unit。

既有 server/hybrid 首次接管前，先在旧数据面仍受保护时暂存一次受限迁移 overlay：

通过新 release 的 installer 在停止旧 unit 前执行提取：

```bash
sudo ./install.sh --upgrade \
  --server-migration-source /etc/loom/sing-box/v2/config.json
```

该命令只接受 owner-only 旧配置，只提取旧公网 listener 的用户、`auth_user` ACL 和 ACL 直接引用的
`direct` 出站；输出固定为 `/var/lib/loom-device/migration-overlay.json`（`0600`），并打印不含秘密的源摘要。
存在 overlay 时签名 runtime readback 必须为 `exact=false`。所有 access 已使用新凭据且真实业务、报告和重启
恢复均通过后，操作者用 stage 时的精确摘要删除它，再重启唯一 service：

```bash
sudo loom client finalize-server-migration -source-sha256 <stage 输出的摘要>
sudo systemctl restart loom-client.service
```

只有随后对纯认证 `ServerRuntime` 的 listener、WG、selector 和配置回读全部成功，报告才可变为
`exact=true`。这两条命令不读取旧 SSOT，不恢复旧 unit，也不会接受旧 telemetry 或任意公网中继出站。

## 正式运行与回读

`loom-client.service` 每次启动都从 `/var/lib/loom-device/state.json` 重新验证完整 LKG，将 RuntimeProfile
投影到 `/run/loom-client/config.json`，再启动同一 release 内的 sing-box。控制面暂时离线时继续使用 LKG；
不存在公开 config、旧 pull 或 v1 fallback。

偏好通过唯一 CLI 入口修改：

```bash
sudo loom client route direct
sudo loom client route auto
sudo loom client route exit demo-exit
```

命令只持久化 `Preference` 并重载同一 service。service 使用共享纯核心选择候选、应用 selector 并读回；
随后执行一次真实 TCP/TLS 与 UDP/DNS 业务检查。首次失败时只尝试一次同一偏好范围内的必要 fallback。

实际 Selection、当前网络代和有限 Observation 从正常入口回读：

```bash
sudo loom client status
sudo loom client inspect
```

`status` 来自 `/run`，service 未运行时不能用上次期望值冒充当前路径。签名报告经私有 device tunnel 提交，
控制 Web/API 的 Devices 与 Live paths 页面从同一观测投影回读结果。

## 撤权与恢复边界

设备撤权后，新的私有 device tunnel、配置读取和报告在服务端立即拒绝，Web 不再显示其授权路径。已经离线
保存的历史 LKG 不会被远程改写；客户端获知新认证状态前可能仍具有旧数据面能力，这一边界必须如实展示，
不能宣称服务端删除等于离线设备即时清除。新 LKG 一旦移除候选，该候选立即停止承接新连接。

service 重启会从同一身份、floor、v2 latch 和完整 LKG 恢复；底层网络代未变且 Observation 仍有效时不重复
采样。网络代变化使旧 Observation 回到 unknown，但不阻塞合法候选启动。
