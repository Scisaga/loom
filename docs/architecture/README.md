# 架构总览

[文档入口](../README.md) · [实现对照](../development/implementation.md) · [实现依赖](../development/dependencies.md)

Loom 管理加密隧道与服务调度。代理上网由请求给出目标地址，只选择服务器链；
服务调度还可以在访问契约允许互换的地址之间选择。路径的排序与观测单位是
`RouteCandidate = (服务器链, 目标地址)`，不能把两个轴各自的排名直接相加。

## 七条不变量

1. **目标地址不是节点。** 只有接入节点 `access` 和服务器节点 `server` 受管；网站、API、
   内网服务只是地址，不参与节点身份、配置渲染或拓扑排序。
2. **出口是位置。** 路径上最后一台服务器就是此次出口，没有“出口节点”类型；直连是零跳候选。
3. **职责和链路分别授权。** 数据面能力按职责块推导；v2 每条 LinkIntent 显式认证发起方、
   transport、可达性与 purpose，节点级 v1 `direction` 只用于迁移输入。
4. **策略先约束，度量再选优。** 不用低延迟覆盖授权或合规边界；缺失、过期、无效观测保持未知。
5. **数据面只做 L4 选路。** 不改写 Host、凭据或协议；访问契约不同构时，换地址需要独立 L7 承载。
6. **应用层指标需要 L7 观测点。** L4 首字节时间不能代表 TTFT、tokens/s 或响应结构。
7. **控制面停机，数据面继续运行。** 配置来自 certified effective SSOT 的纯函数渲染；
   v2 只有 Raft durable commit、apply/recompute 与提交后 replication QC 才能改变生效状态，
   不可达或无有效新状态时继续使用 last-known-good。

## 按主题阅读

| 主题 | 规则正文 |
|---|---|
| 节点、地址、路径与访问契约 | [模型](model.md)、[凭据与数据模型](credentials-model.md) |
| 候选过滤、目标函数与服务器调度 | [调度](scheduling.md)、[Agent 执行](agent-runtime.md) |
| 数据链路、转发与指纹参数 | [隧道](transports.md)、[服务器](servers.md)、[指纹](fingerprints.md) |
| 控制权威、渲染与秘密分离 | [控制边界与纯函数](control-rendering.md)、[身份与密钥](identity.md) |
| Device 产品动作与节点退役 | [Device 生命周期](device-lifecycle.md)、[节点生命周期](lifecycle.md) |
| 分发、激活与回滚 | [配置分发](distribution.md)、[部署契约](deployment.md)、[公网入口](public-endpoints.md) |
| 观测、事件与状态展示 | [采集上报](reporting.md)、[观测点与预算](measurement.md)、[事件与拓扑](events-topology.md) |
| 控制界面和管理员权限 | [控制 UI](control-ui.md) |
| 架构边界、选型和部署输入 | [边界与选择理由](boundaries.md) |

v2 认证对象、共识及状态机由[控制面规范](../protocols/control-plane/README.md)定义。
客户端宿主、交互和交付见[客户端入口](../clients/README.md)；网络代测量预算只由
[观测消费规范](../clients/observations.md)定义，不能套用服务器候选轮询。
未采用的扩展见[Local Network](../proposals/local-network.md)与[密钥保护强化](../proposals/key-protection.md)。
