# Loom Linux 客户端安装

本文面向 `linux/amd64` 的原生安装与 `linux/arm64` 的制品核验。Linux 与 Android 复用
[客户端运行时最小模型](../clients/client-runtime-model.md)：Direct、Auto 和指定最终出口只是同一候选集合上的
`Preference`，实际路径必须来自 sing-box selector 回读，授权与可用性不得混为一谈。

> **安全暂停：** 2026-09-21 的宿主网络接管事故证明，access TUN 不能运行在宿主初始 network namespace。
> 本分支的 TUN preflight 在该环境继续失败关闭。默认 TUN installer 在专用 namespace 生命周期完成前
> 只能 `--no-enroll` 安装制品。2026-10-04 用户明确授权的正式替换使用显式 Mixed 与认证服务资源，
> 已完成宿主停止、SIGKILL、精确 WG 清理、重启和基础网络回读；这不开放初始 netns TUN。
> 不得删除 TUN 门禁或手工添加宿主逃生路由来完成安装。详见
> [事故记录](../incidents/2026-09-21-host-network-takeover.md)。
> 旧 TUN unit 与 quarantine 原件已随明确授权的替换保存在受保护证据；当前正式 unit 固定 `-capture mixed`，
> 使用 `Restart=no` 和 `ExecStopPost=loom client cleanup`。不得将其改回初始 netns TUN。

## 下载与验证

控制面 Releases 页面只提供经过平台签名验证的通用公开制品。通过另一条可信通道取得平台 Ed25519 公钥，
再核验下载的 archive、checksum 和 detached signature：

```bash
loom client verify \
  -archive loom-client-linux-amd64.tar.gz \
  -pubkey /path/from/trusted/channel/platform-signing.pub \
  -arch amd64
```

发布者先运行 `bash scripts/build-dataplane.sh`，再从干净提交运行 `scripts/build-linux-client.sh <generation>`。
generation 是显式选择的非零发布代，不从时钟推导。默认一次生成并签名 amd64、arm64 两份 archive；
amd64 必须完成原生 service 和业务验收，arm64 只做交叉构建、ELF/build-info 检查和签名往返，不把交叉结果
写成原生验收。

包内 manifest 使用[唯一 schema 3 字段](../core/current-contract.md#linux-客户端-manifest-的规范字段)，
逐项签名覆盖程序、源码证据、安装脚本和 unit；数据面必须匹配审核的源码修正版。下载附件 `.sig` 是与包内
manifest.sig 相同的原始 Ed25519 签名；旧 JSON 签名封装拒绝。构建入口只生成并验证制品，不再调用已删除的
旧 catalog 写入器；它不改变现有发布 floor、`current` 或运行服务。

## 私有 Enrollment 与安装

以下是默认 TUN 安装包在隔离完成后的**目标流程**。当前 access/hybrid 的 TUN 安装在专用 namespace
生命周期及回读验收完成前失败关闭。本轮经明确授权的 Mixed 服务直接替换另见
[实施状态](../progress.md#已授权的正式服务替换)，不能把该部署回读视为默认 installer 已验收。

有效 control 在私有控制面按职责签发 Invite，签发即批准；平台由目标识别并在首次 claim 绑定，
不预先把邀请写成 Linux 专用。纯 access 使用二维码媒介，其同一邀请文件也可交给 CLI 导入；
组合职责使用 SSH 或 sh。设备在本机生成私钥，经签发者处理首次 claim。
其 `DeviceView` 必须包含成员表证明、事实前沿及按稳定 ID 排序的授权候选；access 另有一份规范
`sing_box` RuntimeProfile，纯服务节点消费自身资源与入站授权。Invite 只用于受限 bootstrap tunnel，
不进入公开站点、进程参数、环境变量或日志。
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
6. 等待 selector 和宿主网络不变量实际回读。当前 installer 失败时仅恢复包文件并保持 service disabled，
   不自动启动先前 release/unit；认证 LKG、floor 与撤权不能随运行失败回退。初始 netns 中的
   access TUN 继续失败关闭，不得为了“回滚成功”重施危险状态；
7. 经批准的前向切换及新路径回读通过后，在同一工作项停用并移除旧 `loom-client-v2*` units，
   将已替代且经所有权核对的旧配置/store 原始字节归档到 owner-only retired 目录。
   现行身份、私钥、floor 和 latch 不属于清理对象；唯一正式 service 不读取旧配置或迁移 overlay。

claim 尚未由签发者接受时，installer 不启用 service。使用同一 Invite 重跑会 resume 同一事务，不生成第二身份。
`--no-enroll` 只安装已验证 release，不创建身份也不启动 service。已 Enrollment
的机器升级时使用 `sudo ./install.sh --upgrade`；它复用现有 owner-only 身份与完整
LKG，候选 preflight 或启动回读失败时按上述安全条件恢复包文件并保留失活状态。
installer 在激活前拒绝尚存的旧权威路径、迁移 overlay、旧 unit 和事故 quarantine drop-in；
这些材料与启动项只能由经批准的前向切换处理，不由安装器自动搬走。既有平台信任公钥不匹配时同样拒绝覆盖。

## 旧迁移 overlay 与现行切换的边界

旧 `--server-migration-source`、`stage-server-migration` 和 `finalize-server-migration` 已从当前命令和运行路径删除。
它们曾从旧公网 listener 提取用户、`auth_user` ACL 及相关出站，保存到
`/var/lib/loom-device/migration-overlay.json`，参与运行时合并并报告 `exact=false`。
这里仅记录须保全并在获准切换后归档的历史路径，不把它作为 schema 3 的安装步骤或授权来源；
`exact=false` 也不授权继续把旧用户/ACL 加入现行运行投影。删除命令源码不等于完成身份、授权、floor
的前向迁移，也不表示已部署的旧 unit、配置和原始字节已经移除。

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

上述默认 installer 的自动处理仍待验收；本轮人工指定精确制品的正式替换已完成对应归档、删旧及回读。
归档失败、摘要不符、旧入口仍可加载
或新路径尚不能承担原业务时，保留证据并报告具体阻碍，不以 `exact=true` 单项结果宣称完成。
清理不 flush 共享 route/rule/firewall，也不重新启用初始 namespace access TUN。
旧隔离 unit 的归档不改变当前源码的 TUN 拒绝门禁。

## 正式运行与回读

以下描述正式运行的回读要求。本轮已启用显式 Mixed/service 运行方式，精确制品及现场结果保存在受保护部署证据。

开发 CLI 默认 Mixed，也可显式选择 `loom client preflight -capture mixed` 和 `loom client run -capture mixed`。
有 access 职责时，该入口把唯一受管 TUN 输入派生为回环 HTTP/SOCKS listener，保留原输入
标签、路由匹配、selector 与候选身份。Mixed capture 本身不创建 TUN、路由或 DNS 接管；
节点另有认证 WG 中继资源时，由 HostAdapter 安装其精确接口、peer、地址与主机路由，并持久记录本 generation
的可删除所有权凭据。hybrid 可同时消费 Hy2 与 WG 资源，纯服务节点不启动这份 access listener。业务请求必须显式使用本机代理，普通宿主流量
不进入它；单 scope、单认证 HTTPS 目标及认证 DNS 已明确时，探测也必须经过同一 SOCKS 入口。
端口占用时不得停止其他进程来完成验证。该方式不抵扣隔离 TUN 或自动安装包验收；正式部署仍逐项验证宿主不变量。

承载一跳 Hy2 的节点额外传入 `-resource-inputs /path/to/demo-resource-inputs.json`，文件形状与
TLS 引用见[本机配置模型](configuration-model.md)。普通 `resource.put` 与 Service/Policy 事实经私有
配置通道投影出 listener 和入站用户；本机文件只能定位材料，不能增加资源、用户或目标权限。
`client status` 的 resources 以及私有签名报告回读实际 UDP 归属、TLS 身份、认证和当前 ACL 摘要。
删除最后一个自有资源后，纯服务节点保持配置/报告通道，数据面报告 stopped。配置收窄先关闭旧进程
与全部已认证会话；父进程异常退出也由内核终止其数据面子进程。失败保留新 LKG，不能复活旧 ACL。
当前资源拨号地址已验收 IP；资源主机名的认证 resolver 接线和业务 DNS 仍待完成，不使用主机 resolver
为该 underlay 拨号补值。server listener 与 access TUN 的组合在生命周期分离前明确拒绝。

包内默认 unit 与安装 preflight 使用 `-capture tun`，继续检查专用 network namespace。本次获准部署的 unit
明确使用 `-capture mixed`，两者不能混为同一验收结果；不得把已通过的 Mixed unit 改回初始 netns TUN。

WG 新接口先以不可碰撞的临时名称创建，取得 ifindex 并设置所有权 alias 后才改成资源规定的名称；
不假定创建命令会保留 alias。`config.json.wg-ownership` 只保存本 generation 的清理凭据，不是网络权威。
正常退出与 `client cleanup` 均按名称、ifindex、alias、peer 和精确路由 compare-and-delete；
缺少所有权、对象已被替换或清理失败时保持 failed/inactive，不重启反复施加。SIGKILL 后由 systemd
终止同 cgroup 的子进程，再执行相同清理；未知接口、共享 route/rule 和宿主 resolver 不在清理范围。

`loom-client.service` 每次启动都从 `/var/lib/loom-device/state.json` 重新验证成员证明、事实前沿与完整 LKG。
TUN 必须先确认自己不在 PID 1 的 network namespace，再将 RuntimeProfile 投影到
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

runtime 重启会从同一 schema 3 身份、逐键已见前沿、不可回退 latch 和完整 LKG 恢复；底层网络代未变且 Observation 仍有效时不重复
采样。可删除的 Observation 缓存还必须绑定相同认证 View 摘要；旧缓存缺少绑定或 View 改变时清空结果，
保留唯一 Preference。这个摘要只验证缓存适用范围，不构成第二份配置权威。网络代变化使旧 Observation
回到 unknown，但不阻塞合法候选启动。

已认证的新 View 先按同一原子保存规则接受，再应用运行配置；应用失败不恢复旧授权。
旧运行部分必须能证明仍符合当前已接受的 View，否则停止相关流量并保留修复配置的认证入口。
