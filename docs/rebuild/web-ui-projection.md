# 控制面 Web 投影

[重建入口](README.md) · [白名单](migration-whitelist.md)

控制面 Web 是必须保留的产品能力，但它不是第四套权威状态。页面只显示核心模型的认证状态、
当前运行事实和历史事件；任何表单都通过统一管理 operation 写回控制面。

## 输入与边界

```text
CertifiedHead + Projection ─┐
Device/Path Observation ────┼─► deterministic WebProjection ─► JSON/WebSocket ─► SPA
ReleaseStore + Events ──────┘

SPA write ─► {kind, payload, request_id, base_head} ─► private authenticated control API
```

浏览器入口只允许私有 overlay 或 `127.0.0.1` TLS listener。服务端使用浏览器兼容的 P-256
服务端 leaf，验证 TLS 1.3、管理员证书、exact listener、Origin 和 read/admin capability，再交给同一个
SPA。TLS `CertificateRequest` 的可接受签发者名称由当前 read/admin exact leaf 的 `RawIssuer` 单向派生；
它只帮助浏览器选择已经安装的客户端证书，不授予权限，也不替代 HTTP 层的 exact leaf 匹配。公网 Nginx
永远不能到达该页面或 API。
本机 CLI 可通过 root-only admin Unix socket 提交同一 operation envelope；socket 只改变传输认证，仍调用
同一个 handler、Raft 提交、reducer 和 QC 链，不能形成旁路写入。

## 最小重建恢复桥

完整控制写入重新启用之前，守护进程只拥有一个可删除重建的只读恢复投影。一次性 importer 同时验证旧
ControlSet、CertifiedHead、稳定 QC、浏览器 TLS 身份、管理员证书、release floor 与 v2 reader floor，
再把认证 LKG 投影成下表展示值。导入成功后运行时只读新状态文件，不再回退读取旧 operation、registry、
report 或 SSOT store；写能力明确为 false。

```text
verified recovery inputs -> CertifiedHead + recovery evidence + WebProjection cache
state.json               -> private TLS runtime -> snapshot/release readback -> SPA
```

该状态文件的 domain、wire 和 persistent 表达是一一对应的严格 JSON；保存后重新加载必须得到相同值。
`WebProjection` 仍只是由认证 LKG 得到的单向缓存，不得倒写或被当成新的 authority。恢复证据保存输入摘要、
anti-rollback floor 与 v2 latch，删除任何一项都会使重启后无法证明没有降级或重新 bootstrap。quorum
写入激活时，一次性 importer 将恢复投影写成 genesis Material，随后删除 `state.json`；运行 daemon
只读三份核心逻辑存储，恢复桥不再作为 fallback 或第二套提交状态机。

## 展示值

| 概念 | 来源 | 用途 |
|---|---|---|
| `UIState` | CertifiedHead、ControlConfig、当前副本追赶状态 | head/revision、可写性、警告和观察时间 |
| `Device` | DeviceView + presence/runtime observation | 身份、职责、授权、在线与实际运行状态 |
| `Link` | Projection 中的授权边 + Observation | 声明链路、实际状态与未知原因 |
| `Path` | RouteCandidate + Selection + Observation | 最终出口、有序链、当前选择与动态可用性 |
| `Service` | Projection | 名称、matcher/address 与 policy |
| `Release` | 已验证 release catalog | 平台、架构、版本、源提交、签名和下载 |
| `Deployment` | 平台密钥签名 PublisherObservation + 设备签名 DeviceReport | generation、目标/实际快照及精确一致性 |
| `Event` | 已提交认证变化，或保留 30 天的内容寻址签名报告 | 从原始事实重建的状态变化及当前未解决状态 |

Invite、traffic bucket、authority coordinate 和各种 `*View` 只是上述概念的值或 DTO，
不获得独立持久生命周期。

## 同构与投影关系

| 层 | 表达 | 是否权威 | 约束 |
|---|---|---:|---|
| domain | 核心模型实体 | 是 | 由各模型文档定义 |
| wire | 一个版本化 Web snapshot/event envelope | 否 | 只携当前投影，不引入新状态 |
| persistent | 无专用 UI authority | 否 | 可选缓存删除后能从输入重建 |
| runtime | `WebProjection = f(Projection, Observation, Release, Event)` | 否 | 同一输入逐字节稳定 |
| UI | 上述展示值 | 否 | 不能通过展示字段反向修改 authority |

Web snapshot 的 encode/decode 只保证展示语义往返：

```text
decode_ui(encode_ui(WebProjection)) = WebProjection
rebuild_ui(core_inputs)             = WebProjection
```

它不满足 `core_state = inverse(WebProjection)`，因此服务端禁止把浏览器提交的完整 View 当作新 SSOT。
写请求只携操作种类、最小 payload、稳定 request ID 和 base head。

## 页面行为

- Overview、Devices、Device detail、Topology、Live paths、Services、Releases/Deployments、Events 和 SSOT 页面保留；
- Device 只出现一次，不再并存 Client/Node 两份身份事实；
- 已完成后被撤权的 Enrollment 保留在不可变控制历史中，但不再作为当前 Device/Topology 投影；尚未完成的 Enrollment 仍显示其真实状态；
  投影只为当前 Authorization 选择一笔已完成事务，或展示尚未完成的当前事务，绝不遍历全部历史事务重新制造设备；
- Enrollment 的 `completed` 只表示授权 Material 已认证，不表示 Ready。邀请与节点投影依次显示
  `awaiting_claim / awaiting_approval / awaiting_deployment / ready`；只有新设备本身及其所有派生 route chain
  中的服务器都提交三分钟内、schema-2、running、exact 且匹配当前 DeviceView digest 的签名报告，才显示 Ready；
- 浏览器凭据和集群写能力分开显示。管理员证书仍标识为 admin；quorum 当前不可写时 snapshot 不下发任何
  mutating operation，因此页面不会展示注定失败的写按钮；
- topology 从当前 Projection 生成，当前 Path 仅作颜色叠加，不参与排序；
- 授权与观测分开显示，缺失或过期观测保持 unknown；
- schema-2 access 的业务状态只由当前所选候选的真实观测形成；候选包含 server 时，还必须看到路径上每台
  server 对其最新 DeviceView digest 的新鲜 running 回读。presence、组件匹配、链路计数或授权本身不能补绿；
- 同一控制集的成员通过私有认证通道合并每台设备最新的有效观测；成员短暂失联时允许暂时 unknown，恢复后收敛，不能把本地缺失补成 available；
- 只读状态不使用 Apply/切换等写动作措辞；
- release 下载只返回 catalog 精确引用且摘要/签名验证通过的 bytes；
- deployment 只在 publisher heartbeat 新鲜、分发检查成功，且设备回报的 generation、pointer payload 摘要、
  selected/applied snapshot 和 rollout verified 全部匹配时显示 current；任一缺失必须显示 waiting/unknown/mismatch；
- Events 不另建 event store：控制成员先按报告当时的认证 DeviceView digest 与设备公钥验证保留的原始报告，
  再按时间顺序重建 runtime、selection、path、component、link 和 deployment 的值变化；重复心跳不产生事件；
- snapshot 只返回经过裁剪的 WebProjection，不把原始 DeviceReport、RuntimeKey 或设备本机诊断文本暴露给浏览器；
- WebSocket 首帧是当前 snapshot，后续只因输入事实变化发送，不触发额外网络测量。

## 正常写入

1. SPA 从 `UIState` 取得 `base_head` 和可写能力；
2. 用户动作生成一个统一 operation envelope；
3. private API 验管理员权限与 expected head；
4. 控制模型完成 commit、reduce 和 QC；
5. WebProjection 从新 Projection 重算；
6. JSON 回读和 WebSocket 使用同一结果。

陈旧 head 返回 conflict；未认证或跨源请求拒绝；pending 材料可以显示诊断状态，但不能提前改变页面中的
effective 配置。

## 最小测试

1. 私有/回环 TLS 使用 P-256 服务端 leaf；模拟 Chrome 按 `CertificateRequest` 签发者选择客户端证书后，
   read/admin capability 到达同一 SPA，无证书握手失败且公网入口不可达；
2. 一个 Device intent 加一组观测在 Devices、Topology、Path 中只产生同一身份，unknown 不被补绿；
3. 一个代表性管理员操作从表单提交到 certified 回读，stale head 与无权限分别拒绝；
4. WebSocket 先发一次当前 snapshot，一次输入变化只发一次新 snapshot；
5. 一份有效 release 可列出并下载 exact bytes，篡改制品拒绝。

不为页面、按钮、平台和状态组合建立笛卡尔测试矩阵。

浏览器视觉审查使用生产 `Server.AdminHandler`、生产静态资源和本机真实 Chrome，在固定
`1586×992`、device scale factor 1 的环境渲染 Overview、Nodes、Device detail、Topology、Live paths、
Services、Deployments、Events、SSOT，以及 Linux/Android/Windows Releases 和 Add Device。固定输入只
是认证 Projection/观测的测试值，不是第二套页面或浏览器拼接层。运行：

```bash
LOOM_WEB_VISUAL_TEST=1 go test ./internal/control -run TestWebVisualScenariosChrome -count=1 -v
```

截图只写入被忽略的 `out/ui-review/web/current/`，须与 `assets/loom-control-center-*-misaka-v1.svg`
人工并排审查；普通 `go test` 跳过浏览器渲染但仍验证 fixture 覆盖所有产品数据面。最终生产验收仍须
使用真实 TLS 1.3、reader/admin 客户端证书和正式 endpoint，HTTP 视觉 fixture 不能替代认证握手测试。

真实 Chrome mTLS 验收另走生产 `Server.Handler`、TLS 1.3 socket、Chrome NSS 客户端证书库和
`AutoSelectCertificateForUrls` 管理策略。测试使用临时 CA、reader/admin leaf 和浏览器 profile；唯一写入的
系统策略文件不含证书、密钥或地址，并在测试返回前删除。该测试需要 Chrome、`libnss3-tools`、OpenSSL
以及写入 Chrome managed-policy 目录的权限：

```bash
LOOM_WEB_TLS_CHROME_TEST=1 go test ./internal/control \
  -run TestWebTLSClientCertificatesChrome -count=1 -v
```

它必须证明无证书连接在 HTTP 前失败、admin Chrome 得到管理员 capability、reader Chrome 只得到只读
capability；同一开关还运行真实 SPA 交互验收：管理员打开 Service 草稿后由另一个正常 operation 推进
certified head，WebSocket keyed update 必须保留原输入节点、焦点和值，随后浏览器用表单冻结的旧
`base_head` 提交必须得到 409 且草稿仍在。这仍不替代隔离 N=3 集群上的完整 Add Device 和业务流量验收。

## 禁止恢复

- v1 SSOT 文件写回、旧 registry 生命周期或 report daemon 拼接结果作为 UI authority；
- Client/Device、Node/Device、Clients/Devices 等同义双模型；
- 每个按钮独立的 manager/store/receipt；
- 独立 SSR 页面和与 SPA 重复的 operation-progress HTML；
- `/act/`、不可达下载别名或只有测试提供者的 action registry；
- 为保留页面而保留后端重复状态机。
