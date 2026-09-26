# Loom Linux 客户端安装

本文面向 `linux/amd64` 的原生安装与 `linux/arm64` 的制品核验。Linux 与 Android 复用
[客户端运行时最小模型](../clients/client-runtime-model.md)：Direct、Auto 和指定最终出口只是同一候选集合上的
`Preference`，实际路径必须来自 sing-box selector 回读，授权与可用性不得混为一谈。

> **安全暂停：** 2026-09-21 的宿主网络接管事故证明，access TUN 不能运行在宿主初始 network namespace。
> 本分支后续构建的 access/hybrid preflight 会在该环境失败关闭，`loom-client.service` 必须保持 disabled；在专用
> namespace 生命周期完成前，只允许 `--no-enroll` 安装制品、仅承担 `forward`/`internet_egress` 的运行时或隔离环境中的开发验证。
> 不得删除门禁或手工添加宿主路由来强行完成安装。详见
> [事故记录](../incidents/2026-09-21-host-network-takeover.md)。
> 事故宿主还安装了 `00-host-network-quarantine.conf`；正式隔离闭环完成前不得删除或覆盖该 drop-in。

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

以下是隔离完成后的**目标流程**。当前 access/hybrid 安装在专用 namespace 生命周期及回读验收完成前
失败关闭；安全暂停期间不按这些步骤启用正式 service。实际进度见[实施状态](../progress.md)。

有效 control 在私有控制面签发 Linux Invite，签发即批准；设备在本机生成私钥，经签发者处理首次 claim。
其 `DeviceView` 必须包含成员表证明、事实前沿、按稳定 ID 排序的授权候选和一份规范
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
4. 对 access/hybrid 验证进程位于专用 network namespace；隔离缺失时在切换 `current` 或启用 unit 前失败；
5. 隔离成立后切换 `/usr/local/lib/loom-client/current`，启动唯一正式 unit `loom-client.service`；
6. 等待 selector 和宿主网络不变量实际回读。失败时只允许恢复已证明安全、同样隔离的先前 release/unit；
   若旧 release 会在初始 netns 启动 access TUN，保持 service disabled/failed，不得为了“回滚成功”重施危险状态；
7. 成功后停用并移除旧 `loom-client-v2*` units，把旧身份/store 和配置移入 owner-only retired 目录，
   不作为 fallback 读取。

claim 尚未由签发者接受时，installer 不启用 service。使用同一 Invite 重跑会 resume 同一事务，不生成第二身份。
`--no-enroll` 只安装已验证 release，不创建身份也不启动 service。已 Enrollment
的机器升级时使用 `sudo ./install.sh --upgrade`；它复用现有 owner-only 身份与完整
LKG，候选 preflight 或启动回读失败时按上述安全条件恢复；未证明旧 unit 安全时保留失活状态。

既有承担 `forward`/`internet_egress` 的节点首次接管前，先在旧数据面仍受保护时暂存一次受限迁移 overlay。
以下 `--server-migration-source` 是现有一次性命令参数名，不定义 `server` 职责：

通过新 release 的 installer 在停止旧 unit 前执行提取：

```bash
sudo ./install.sh --upgrade \
  --server-migration-source /etc/loom/sing-box/v2/config.json
```

该命令只接受 owner-only 旧配置，只提取旧公网 listener 的用户、属于该 listener 的 `auth_user` ACL、
ACL 直接引用的 `direct` 出站及映射到新运行时 fail-closed 出站的 `block` 规则；同进程中其他认证入口的
用户和规则不会迁入。输出固定为 `/var/lib/loom-device/migration-overlay.json`（`0600`），并打印不含秘密的源摘要。
存在 overlay 时签名 runtime readback 必须为 `exact=false`。所有 access 已使用新凭据且真实业务、报告和重启
恢复均通过后，操作者用 stage 时的精确摘要删除它，再重启唯一 service：

```bash
sudo loom client finalize-server-migration -source-sha256 <stage 输出的摘要>
sudo systemctl restart loom-client.service
```

只有随后对纯认证的转发/出网运行时 listener、WG、selector 和配置回读全部成功，报告才可变为
`exact=true`。这两条命令不读取旧 SSOT，不恢复旧 unit，也不会接受旧 telemetry 或任意公网中继出站。

## 正式运行与回读

以下描述正式架构的回读要求；当前 access/hybrid service 尚未恢复启用。

`loom-client.service` 每次启动都从 `/var/lib/loom-device/state.json` 重新验证成员证明、事实前沿与完整 LKG。仅承担转发/出网职责的运行时可在宿主
运行；access/hybrid 必须先确认自己不在 PID 1 的 network namespace，再将 RuntimeProfile 投影到
`/run/loom-client/config.json` 并启动同一 release 内的 sing-box。控制面暂时离线时继续使用 LKG；
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
