# Loom Linux 客户端安装

本文面向 `linux/amd64` 的原生安装与 `linux/arm64` 的制品核验。Linux 与 Android 复用
[客户端运行时最小模型](../clients/client-runtime-model.md)：Direct、Auto 和指定最终出口只是同一候选集合上的
`Preference`，实际路径必须来自 sing-box selector 回读，授权与可用性不得混为一谈。

> **安全暂停：** 2026-09-21 的宿主网络接管事故证明，access TUN 不能运行在宿主初始 network namespace。
> 本分支的 TUN preflight 在该环境继续失败关闭。正式 installer 必须显式选择 `--capture mixed`；TUN 安装在专用 namespace 生命周期完成前拒绝。2026-10-04 用户明确授权的正式替换使用显式 Mixed 与认证服务资源，
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

已签包可经[本地 catalog 审查入口](configuration-model.md#本地签名交付审查与私有下载)接入私有 Releases
页面。页面下载同时固定 catalog 与 archive 摘要，附件保持原 manifest 签名字节；下载后的正式核验仍使用
上述独立公钥命令。目录更新不会绕过 installer 已接受的组件代，也不自动激活服务。

## 私有 Enrollment 与安装

### 正式安装入口

安装入口复用 CLI/runtime 的显式 Mixed、同事务加入和按 generation 清理，不新增安装状态机、receipt 或第二身份 store。
`install.sh` 保留为正常入口，由包内同一 Loom 程序完成严格验签、目录核验与安装，避免 shell 另写规范
manifest/floor 的解码。脚本入口和直接 CLI 使用同一流程。

激活必须显式选择 `--capture mixed`，邀请来源恰好为 `--invite-file` 或 `--invite-stdin`；升级使用 `--upgrade`，
只缓存已验证制品使用 `--no-enroll`。TUN 安装在完整 namespace 生命周期接通前明确拒绝，不因安装进程偶然
位于某个 namespace 就生成会在 PID 1 namespace 运行的 unit。stdin 不写 argv、环境或日志；原加入事务可
恢复，已有身份不重建。state 与可选 resource-inputs 的路径只用于生成同一 unit 的实际 argv 和受保护读写
范围，不改变认证授权。路径生成须正确处理 systemd 的引用、百分号和变量转义。

签名 manifest 的 generation 与内容 ID 是已有发布坐标，不增加权威实体。缓存 release 不推进接受代；唯一
`current` 指向已接受的规范 manifest 及原始签名，安装时以系统级排他文件锁串行核对。低代、同代异值和旧
格式拒绝；同代同值允许继续。现有签名、程序和 unit 先回读，新 View/floor 保留。停止旧 service 并确认本
generation 清理成功后，才安装新 unit 和原子推进 current；新服务启动失败保持 failed/inactive，保留已接受的
新包与设备认证状态，不把旧指针或旧授权恢复为运行路径。尚无现行包记录的旧部署须沿已批准的前向切换处理，
不能以“第一次安装”绕过旧发布 floor。首次信任公钥来自操作者的带外输入，既有信任不由包内公钥覆盖。

领域到实现的对应只有：已签 Manifest → 规范原始字节及签名 → 内容目录/current → 精确进程文件；
DeviceIdentity/LKG/Preference → 既有 deviceclient 文件 → 同一 runtime → CLI 与私有签名报告。
unit、status 和安装输出只是输入或回读投影。正常链为受保护管理入口交付邀请 → stdin/file 加入 → 原子持久
身份和 LKG → Mixed/service 应用 → CLI 与控制端报告回读 → 停止/异常退出/重启后的同身份恢复。
最小验证覆盖实际 systemd 安装与业务、同事务重试、升级代比较、损坏制品与失败后的身份/floor 保留，以及
未授权 TUN 拒绝；正式包生成、缓存安装或单次 status 成功均不抵扣这条链。

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
sudo ./install.sh --capture mixed --pubkey /path/from/trusted/channel/platform-signing.pub \
  --invite-file ../client.loom-invite
```

installer 依次完成：

1. 核对 archive 内所有文件摘要，并把 Loom 与 sing-box 写入内容标识的 release 目录；已有相同内容 ID 的
   目录须逐项核对程序与 manifest 的字节、所有者、权限及普通单链接文件属性。仅 manifest 相同不能证明
   已安装程序正确；损坏或链接替换拒绝，不覆盖现场内容，也不继续激活或改变设备身份；
2. 通过 `loom client enroll` 在本机生成 Ed25519 身份，经私有 tunnel claim/resume，原子保存完整认证 LKG；
3. 用精确 release 中的 sing-box 对 LKG RuntimeProfile 做 preflight；
4. 将显式 state 与可选 resource-inputs 投影到唯一正式 unit；包内 unit 是模板，不直接复制为运行配置；
5. 原子推进 `/usr/local/lib/loom-client/current`，启动 `loom-client.service`，确认精确程序与当前认证 View 的运行回读；
6. 接受新版本后的失败保留其 current、身份与认证 floor，停止并禁用 service，不恢复旧程序或旧授权；
7. 新运行时回读通过后，按旧签名清单和实际所有权核对，删除同平台较低代的 Loom 与 sing-box 可执行文件，保留旧签名与源码证据。
   接受后失败再重试仍使用这些已有清单识别退役程序，不增设旧指针或安装 receipt；未来代缓存不受影响。
   不自动清理未知目录、旧权威 store 或身份密钥。

claim 尚未由签发者接受时，installer 不启用 service。使用同一 Invite 重跑会 resume 同一事务，不生成第二身份。
`--no-enroll` 只安装已验证 release，不创建身份也不启动 service。已 Enrollment
的机器升级时使用 `sudo ./install.sh --capture mixed --upgrade`；它复用现有 owner-only 身份与完整
LKG，候选 preflight 失败不接受新发布代，已停止的服务保持禁用；接受后启动失败则保留新包和失活状态。
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

installer 不自动处理上述旧部署；本轮人工指定精确制品的正式替换已完成对应归档、删旧及回读。
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

包内模板、安装 preflight 和生成的正式 unit 使用显式 `-capture mixed`。这不抵扣隔离 TUN 验收，
不得把 Mixed unit 改回初始 netns TUN。

WG 新接口先以不可碰撞的临时名称创建，取得 ifindex 并设置所有权 alias 后才改成资源规定的名称；
不假定创建命令会保留 alias。`config.json.wg-ownership` 只保存本 generation 的清理凭据，不是网络权威。
正常退出与 `client cleanup` 均按名称、ifindex、alias、peer 和精确路由 compare-and-delete；
缺少所有权、对象已被替换或清理失败时保持 failed/inactive，不重启反复施加。SIGKILL 后由 systemd
终止同 cgroup 的子进程，再执行相同清理；未知接口、共享 route/rule 和宿主 resolver 不在清理范围。

`loom-client.service` 每次启动都从安装时指定的 state（默认 `/var/lib/loom-device/state.json`）重新验证成员证明、事实前沿与完整 LKG，
再将 RuntimeProfile 投影到
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
