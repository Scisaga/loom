# 设计边界与技术选择

[文档地图](../README.md) · [架构入口](README.md) · [控制面规范](../protocols/control-plane/README.md) · [实现对照](../development/implementation.md) · [本机部署信息](../operations/local-deployment.md)

**规范范围：架构与数据平面。** 本文定义对应主题的规则；标明 v1 的契约仅用于该版本，标明目标态的机制不表示已实现。

---

## 明确不做的事

| 不做 | 理由 |
|---|---|
| 控制平面参与数据转发 | 违反 [铁律:控制平面与数据平面分离](control-rendering.md#铁律控制平面与数据平面分离),且成为瓶颈与单点 |
| 让 CRDT 原始合并结果直接授权安全关键状态 | [逻辑 SSOT 与纯函数渲染](control-rendering.md#逻辑-ssot-与纯函数渲染)；邀请、撤权、成员和 current 必须完成 Raft commit、apply/recompute 与提交后 QC |
| 根据在线节点自动缩小 quorum | [`control` 是动态节点能力，不是固定三台机器](control-rendering.md#control-是动态节点能力不是固定三台机器)；分区两侧会分别自封多数 |
| 用 DNS/公开 TLS 证书证明 control membership | [密钥与信任](identity.md#密钥与信任)、[托管域名与证书](public-endpoints.md#托管域名与证书)；它们只负责发现和传输身份 |
| 端口轮换时直接关闭旧 listener | [公网 listener 与端口无中断轮换](public-endpoints.md#公网-listener-与端口无中断轮换)；必须 prepare/advertise/prefer/drain/retire |
| fork 修改密码学协议 | [不自己改协议](fingerprints.md#不自己改协议),风险不可控 |
| 纯度量驱动、无策略约束的调度 | [策略裁剪候选集,度量在候选集内选优](scheduling.md#策略裁剪候选集度量在候选集内选优),策略必须在度量之前生效 |
| 仅凭标签判定端点可互换 | [等价类:标签不足以保证可替代性](model.md#等价类标签不足以保证可替代性),必须有可验证的等价类契约 |
| 连接建立后的路径迁移 | TCP 语义不允许;切换只影响新建连接 |
| 对外暴露加权求和式目标函数 | [目标函数:约束式优于加权求和](scheduling.md#目标函数约束式优于加权求和),客户给不出权重 |
| 把主干网拓扑先验写进评分函数 | [策略裁剪候选集,度量在候选集内选优](scheduling.md#策略裁剪候选集度量在候选集内选优),先验只能进过滤层与排障标注,实测优先 |
| **在数据平面改写请求内容**(Host、鉴权、协议转换) | [访问契约:换地址能不能只靠 L4 完成](model.md#访问契约换地址能不能只靠-l4-完成),那是 L7 网关的职责;数据平面只做 L4 选路 |
| **默认几个地址可被 L4 直接互换** | [访问契约:换地址能不能只靠 L4 完成](model.md#访问契约换地址能不能只靠-l4-完成)、[由此产生的三个后果](servers.md#由此产生的三个后果),访问契约通常不同构 |
| **把目标地址建模成节点** | [两类节点,加一类不是节点的东西](model.md#两类节点加一类不是节点的东西)、[目标地址](servers.md#目标地址),它不进拓扑、不参与渲染 |
| **把尚未部署的 mesh 当成当前控制通道** | [只渲染被显式授权的 LinkIntent](transports.md#只渲染被显式授权的-linkintent)、[permanent overlay 与数据链路分开](servers.md#permanent-overlay-与数据链路分开)；目标设计不能冒充现状 |
| **用 L4 观测推断 `tokens/s` 或响应结构** | [被动观测优先,但被动能看到什么由观测点决定](measurement.md#被动观测优先但被动能看到什么由观测点决定),加密隧道里没有请求边界 |
| **地址与服务器链分开排序后相加** | [决策位置由信息可得性决定](scheduling.md#决策位置由信息可得性决定),质量取决于 `(服务器链, 地址)` 组合 |
| **候选集为空时自动绕过合规约束回退** | [数据不足与候选集为空](scheduling.md#数据不足与候选集为空),空候选集需要人介入,不需要兜底 |
| **只用控制通道回连作为部署确认条件** | [自动回滚（仅 Linux/server 发布 canary 的跨节点目标态）](deployment.md#自动回滚仅-linuxserver-发布-canary-的跨节点目标态),该通道不依赖数据平面健康 |
| 把节点私钥纳入 SSOT 以求"纯渲染" | [纯函数的三个产物](control-rendering.md#纯函数的三个产物)、[私钥不集中生成](identity.md#私钥不集中生成),秘密层与渲染层分离 |

## 技术选型建议(非强制)

| 组件 | 建议 | 理由 |
|---|---|---|
| 逻辑 SSOT | 内容寻址 operation DAG + Raft commit ledger + post-commit attestation QC；YAML/Git 作导入导出、评审和归档 | 多副本下仍只有一个 certified head；保留 diff/blame/回滚与纯函数渲染 |
| 控制复制 | Go 共识状态机 + Merkle/CRDT anti-entropy | 共识决定生效，CRDT 复制事实/草稿/不可变对象，边界不能混 |
| **控制平面** | **Go** | 与 Agent 同语言,**渲染器与校验器共用同一份实现** —— 跨语言实现同一套规则是长期漂移来源,会产生"两侧对同一份配置的合法性判断不一致" |
| **Agent** | **Go**,单个静态二进制 | 交叉编译、零运行时依赖、单文件分发、A/B 双槽自更新简单([制品与版本管理](deployment.md#制品与版本管理)) |
| 渲染 | 任意模板引擎,但**必须纯函数** | 可测试、可 dry-run |
| Agent ↔ control plane | 当前 v1 HTTPS + 单签名；目标为 permanent overlay 上的 private service directory + mTLS + ControlSet QC | 公网 EndpointSet 只用于 distribution/bootstrap/data；传输认证、配置授权与防回退不能互相替代 |
| DNS/ACME | provider-neutral adapter + DNS-01；DNS token 仅在 executor 秘密层 | Gandi/Dynadot 只是 adapter，DNS 不是 control authority |
| 度量存储 | 轻量时序;价格与配额用关系表 | **声明值与度量值分开**([评分输入分两类](scheduling.md#评分输入分两类)) |
| 数据平面 | sing-box/libbox（HY2 主入口、Trojan/TLS TCP fallback）+ WireGuard（permanent L3/control overlay 与逐边数据 link） | 按 purpose 分离且覆盖移动弱网、UDP 阻断与稳定私网 |
| **L7 网关**(若需要,[访问契约:换地址能不能只靠 L4 完成](model.md#访问契约换地址能不能只靠-l4-完成)) | 现成反代 + 少量鉴权/改写逻辑 | **不要自己写 L7 代理。** 它同时承担 [被动观测优先,但被动能看到什么由观测点决定](measurement.md#被动观测优先但被动能看到什么由观测点决定) 的应用层埋点,埋点比转发更值得投入 |
| UI | 服务端渲染 | 内部工具,不需要复杂前端 |

> **求解器([当前用启发式,后续引入求解器](scheduling.md#当前用启发式后续引入求解器))作为独立服务经 API 接入,其语言选择与控制平面无关** —— 因此"与求解器同栈"不构成控制平面的选型理由。

**命名约定**:项目名为 Loom,但**不向下渗透**。内部一律用通用词:`node` / `path` / `declaration` / `snapshot` / `agent` / `tunnel` / `credential` / `render` / `apply` / `rollback`。
