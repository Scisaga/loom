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

有效 control 在私有控制面按职责签发 Invite，签发即批准；平台由目标识别并在首次 claim 绑定，
不预先把邀请写成 Linux 专用。纯 access 使用二维码媒介，其同一邀请文件也可交给 CLI 导入；
组合职责使用 SSH 或 sh。设备在本机生成私钥，经签发者处理首次 claim。
其 `DeviceView` 必须包含成员表证明、事实前沿、按稳定 ID 排序的授权候选和一份规范
`sing_box` RuntimeProfile；Invite 只用于受限 bootstrap tunnel，不进入公开站点、进程参数、环境变量或日志。
以下文件导入方式不把 Invite 正文写入命令。Web 的一次粘贴脚本由节点管理员在目标机器的 root shell 中执行，按
[Enrollment 交付契约](../core/enrollment-endpoint-model.md)先核验安装器摘要，再经标准输入传入 Invite；
操作者已明确接受该完整命令可能被终端历史保存的风险，页面须在复制入口说明。

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
6. 等待 selector 和宿主网络不变量实际回读。失败时只允许恢复已证明安全、同样隔离，且能执行当前
   已接受授权的先前 release/unit；认证 LKG、floor 与撤权不能随运行失败回退。无法证明旧运行部分
   仍获授权时停流，只保留认证修复通道。旧 release 会在初始 netns 启动 access TUN 时保持
   service disabled/failed，不得为了“回滚成功”重施危险状态；
7. 经批准的前向切换及新路径回读通过后，在同一工作项停用并移除旧 `loom-client-v2*` units，
   将已替代且经所有权核对的旧配置/store 原始字节归档到 owner-only retired 目录。
   现行身份、私钥、floor 和 latch 不属于清理对象；唯一正式 service 不读取旧配置或迁移 overlay。

claim 尚未由签发者接受时，installer 不启用 service。使用同一 Invite 重跑会 resume 同一事务，不生成第二身份。
`--no-enroll` 只安装已验证 release，不创建身份也不启动 service。已 Enrollment
的机器升级时使用 `sudo ./install.sh --upgrade`；它复用现有 owner-only 身份与完整
LKG，候选 preflight 或启动回读失败时按上述安全条件恢复；未证明旧 unit 安全时保留失活状态。

## 旧迁移 overlay 与现行切换的边界

现有 `--server-migration-source`、`stage-server-migration` 和 `finalize-server-migration` 属于旧实现。
它们曾从旧公网 listener 提取用户、`auth_user` ACL 及相关出站，保存到
`/var/lib/loom-device/migration-overlay.json`，参与运行时合并并报告 `exact=false`。
这里仅记录待退出的路径，不把它作为 schema 3 的安装步骤或授权来源；`exact=false` 也不授权
继续把旧用户/ACL 加入现行运行投影。现有 finalize 只核对源摘要并删除 overlay，不完成身份、
授权、floor 的前向迁移，也不删除旧 unit 或源配置。

目标切换必须遵守[唯一现行契约](../core/current-contract.md#现网字节与生产切换)，按以下顺序收口：

1. 在受保护证据中核对旧身份、密钥引用、实际授权范围、原始材料、floor/latch 及部署坐标；
   由操作者批准并验证它们到当前认证对象的前向对应。无法证明权限及不可回退约束保全时停止切换。
2. 新运行时只消费通过当前契约验证的完整 DeviceView。检测到旧 overlay 或需要依赖旧 ACL 的
   切换计划时，在激活 schema 3 前拒绝；保留原文件及受保护的最后可验证运行状态，不自动删除、
   重签旧用户或把 overlay 改名成另一份 store。本规则不允许恢复被隔离的宿主 access runtime。
3. 前向切换获准后，沿正式入口完成安装、认证授权、listener/ACL/链路与真实业务回读，重启后仍只
   使用现行配置。确认不再依赖旧入口后，按批准清单及精确源路径/摘要将旧配置、overlay 和已替代
   store 原始字节归档；清理不移走仍被当前身份引用的密钥文件，也不重置 floor/latch。
4. 仅移除经所有权核实的旧 `loom-client-v2.service`、`loom-client-v2-agent.service`、
   `loom-client-v2-sing-box.service` 和 `loom-client-v2-report.service` unit 文件，刷新并回读
   systemd：四个旧 unit 不再运行、启用或可加载，旧源路径和 overlay 不再是正常入口。
   唯一正式 unit 不引用这些路径；再次重启并回读纯认证运行配置、真实业务和签名报告。

这是尚待实现并验收的目标顺序，不是批准生产切换的记录。归档失败、摘要不符、旧入口仍可加载
或新路径尚不能承担原业务时，保留证据并报告具体阻碍，不以 `exact=true` 单项结果宣称完成。
清理不 flush 共享 route/rule/firewall，不移除事故宿主的 `00-host-network-quarantine.conf`，
也不重新启用初始 namespace access TUN。

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

已认证的新 View 先按同一原子保存规则接受，再应用运行配置；应用失败不恢复旧授权。
旧运行部分必须能证明仍符合当前已接受的 View，否则停止相关流量并保留修复配置的认证入口。
