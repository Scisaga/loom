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

浏览器入口只允许私有 overlay 或 `127.0.0.1` TLS listener。服务端验证 TLS 1.3、管理员证书、
exact listener、Origin 和 read/admin capability，再交给同一个 SPA。公网 Nginx 永远不能到达该页面或 API。

## 最小重建恢复桥

完整控制写入重新启用之前，守护进程只拥有一个可删除重建的只读恢复投影。一次性 importer 同时验证旧
ControlSet、CertifiedHead、稳定 QC、浏览器 TLS 身份、管理员证书、release floor 与 v2 reader floor，
再把认证 LKG 投影成下表七个概念。导入成功后运行时只读新状态文件，不再回退读取旧 operation、registry、
report 或 SSOT store；写能力明确为 false。

```text
verified recovery inputs -> CertifiedHead + recovery evidence + WebProjection cache
state.json               -> private TLS runtime -> snapshot/release readback -> SPA
```

该状态文件的 domain、wire 和 persistent 表达是一一对应的严格 JSON；保存后重新加载必须得到相同值。
`WebProjection` 仍只是由认证 LKG 得到的单向缓存，不得倒写或被当成新的 authority。恢复证据保存输入摘要、
anti-rollback floor 与 v2 latch，删除任何一项都会使重启后无法证明没有降级或重新 bootstrap。后续 quorum
写入必须直接接管核心控制模型，不能扩展这条恢复桥成为第二套提交状态机。

## 七个展示概念

| 概念 | 来源 | 用途 |
|---|---|---|
| `UIState` | CertifiedHead、ControlConfig、当前副本追赶状态 | head/revision、可写性、警告和观察时间 |
| `Device` | DeviceView + presence/runtime observation | 身份、职责、授权、在线与实际运行状态 |
| `Link` | Projection 中的授权边 + Observation | 声明链路、实际状态与未知原因 |
| `Path` | RouteCandidate + Selection + Observation | 最终出口、有序链、当前选择与动态可用性 |
| `Service` | Projection | 名称、matcher/address 与 policy |
| `Release` | 已验证 release catalog | 平台、架构、版本、源提交、签名和下载 |
| `Event` | 认证变化或观测变化 | 已发生变化及未解决状态的展示记录 |

Invite、traffic bucket、rollout、authority coordinate 和各种 `*View` 只是上述概念的值或 DTO，
不获得独立持久生命周期。

## 同构与投影关系

| 层 | 表达 | 是否权威 | 约束 |
|---|---|---:|---|
| domain | 核心模型实体 | 是 | 由各模型文档定义 |
| wire | 一个版本化 Web snapshot/event envelope | 否 | 只携当前投影，不引入新状态 |
| persistent | 无专用 UI authority | 否 | 可选缓存删除后能从输入重建 |
| runtime | `WebProjection = f(Projection, Observation, Release, Event)` | 否 | 同一输入逐字节稳定 |
| UI | 七个展示概念 | 否 | 不能通过展示字段反向修改 authority |

Web snapshot 的 encode/decode 只保证展示语义往返：

```text
decode_ui(encode_ui(WebProjection)) = WebProjection
rebuild_ui(core_inputs)             = WebProjection
```

它不满足 `core_state = inverse(WebProjection)`，因此服务端禁止把浏览器提交的完整 View 当作新 SSOT。
写请求只携操作种类、最小 payload、稳定 request ID 和 base head。

## 页面行为

- Overview、Devices、Topology、Live paths、Services、Releases、Events 和 SSOT 页面保留；
- Device 只出现一次，不再并存 Client/Node 两份身份事实；
- topology 从当前 Projection 生成，当前 Path 仅作颜色叠加，不参与排序；
- 授权与观测分开显示，缺失或过期观测保持 unknown；
- 只读状态不使用 Apply/切换等写动作措辞；
- release 下载只返回 catalog 精确引用且摘要/签名验证通过的 bytes；
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

1. 私有/回环 TLS 经 read/admin capability 到达同一 SPA，公网入口不可达；
2. 一个 Device intent 加一组观测在 Devices、Topology、Path 中只产生同一身份，unknown 不被补绿；
3. 一个代表性管理员操作从表单提交到 certified 回读，stale head 与无权限分别拒绝；
4. WebSocket 先发一次当前 snapshot，一次输入变化只发一次新 snapshot；
5. 一份有效 release 可列出并下载 exact bytes，篡改制品拒绝。

不为页面、按钮、平台和状态组合建立笛卡尔测试矩阵。

## 禁止恢复

- v1 SSOT 文件写回、旧 registry 生命周期或 report daemon 拼接结果作为 UI authority；
- Client/Device、Node/Device、Clients/Devices 等同义双模型；
- 每个按钮独立的 manager/store/receipt；
- 独立 SSR 页面和与 SPA 重复的 operation-progress HTML；
- `/act/`、不可达下载别名或只有测试提供者的 action registry；
- 为保留页面而保留后端重复状态机。
