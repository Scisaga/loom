# 设计边界、选型与规划输入

[文档地图](../../README.md) · [架构入口](../../design.md) · [控制面规范](../../distributed-control-plane.md) · [实现对照](../../implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范范围：架构与数据平面。** 本文定义对应主题的规则；标明 v1 的契约仅用于该版本，标明目标态的机制不表示已实现。

---

## A · 明确不做的事

| 不做 | 理由 |
|---|---|
| 控制平面参与数据转发 | 违反 [§11](control-rendering.md#11-铁律控制平面与数据平面分离),且成为瓶颈与单点 |
| 让 CRDT 原始合并结果直接授权安全关键状态 | [§12](control-rendering.md#12-逻辑-ssot-与纯函数渲染)；邀请、撤权、成员和 current 必须完成 Raft commit、apply/recompute 与提交后 QC |
| 根据在线节点自动缩小 quorum | [§11.1](control-rendering.md#111-control-是动态节点能力不是固定三台机器)；分区两侧会分别自封多数 |
| 用 DNS/公开 TLS 证书证明 control membership | [§13](identity.md#13-密钥与信任)、[§14.3.1](public-endpoints.md#1431-托管域名与证书)；它们只负责发现和传输身份 |
| 端口轮换时直接关闭旧 listener | [§14.3.2](public-endpoints.md#1432-公网-listener-与端口无中断轮换)；必须 prepare/advertise/prefer/drain/retire |
| fork 修改密码学协议 | [§17.1](fingerprints.md#171-不自己改协议),风险不可控 |
| 纯度量驱动、无策略约束的调度 | [§5.1](scheduling.md#51-策略裁剪候选集度量在候选集内选优),策略必须在度量之前生效 |
| 仅凭标签判定端点可互换 | [§4.3](model.md#43-等价类标签不足以保证可替代性),必须有可验证的等价类契约 |
| 连接建立后的路径迁移 | TCP 语义不允许;切换只影响新建连接 |
| 对外暴露加权求和式目标函数 | [§5.3](scheduling.md#53-目标函数约束式优于加权求和),客户给不出权重 |
| 把主干网拓扑先验写进评分函数 | [§5.1](scheduling.md#51-策略裁剪候选集度量在候选集内选优),先验只能进过滤层与排障标注,实测优先 |
| **在数据平面改写请求内容**(Host、鉴权、协议转换) | [§4.4](model.md#44-访问契约换地址能不能只靠-l4-完成),那是 L7 网关的职责;数据平面只做 L4 选路 |
| **默认几个地址可被 L4 直接互换** | [§4.4](model.md#44-访问契约换地址能不能只靠-l4-完成)、[§9.2](servers.md#92-由此产生的三个后果),访问契约通常不同构 |
| **把目标地址建模成节点** | [§1](model.md#1-两类节点加一类不是节点的东西)、[§9](servers.md#9-目标地址),它不进拓扑、不参与渲染 |
| **把尚未部署的 mesh 当成当前控制通道** | [§6.3](transports.md#63-只渲染被显式授权的-linkintent)、[§8.3](servers.md#83-permanent-overlay-与数据链路分开)；目标设计不能冒充现状 |
| **用 L4 观测推断 `tokens/s` 或响应结构** | [§16.2](measurement.md#162-被动观测优先但被动能看到什么由观测点决定),加密隧道里没有请求边界 |
| **地址与服务器链分开排序后相加** | [§5.6](scheduling.md#56-决策位置由信息可得性决定),质量取决于 `(服务器链, 地址)` 组合 |
| **候选集为空时自动绕过合规约束回退** | [§5.8](scheduling.md#58-数据不足与候选集为空),空候选集需要人介入,不需要兜底 |
| **只用控制通道回连作为部署确认条件** | [§15.2](deployment.md#152-自动回滚仅-linuxserver-发布-canary-的跨节点目标态),该通道不依赖数据平面健康 |
| 把节点私钥纳入 SSOT 以求"纯渲染" | [§12.1](control-rendering.md#121-纯函数的三个产物)、[§13.1](identity.md#131-私钥不集中生成),秘密层与渲染层分离 |

## B · 技术选型建议(非强制)

| 组件 | 建议 | 理由 |
|---|---|---|
| 逻辑 SSOT | 内容寻址 operation DAG + Raft commit ledger + post-commit attestation QC；YAML/Git 作导入导出、评审和归档 | 多副本下仍只有一个 certified head；保留 diff/blame/回滚与纯函数渲染 |
| 控制复制 | Go 共识状态机 + Merkle/CRDT anti-entropy | 共识决定生效，CRDT 复制事实/草稿/不可变对象，边界不能混 |
| **控制平面** | **Go** | 与 Agent 同语言,**渲染器与校验器共用同一份实现** —— 跨语言实现同一套规则是长期漂移来源,会产生"两侧对同一份配置的合法性判断不一致" |
| **Agent** | **Go**,单个静态二进制 | 交叉编译、零运行时依赖、单文件分发、A/B 双槽自更新简单([§15.4](deployment.md#154-制品与版本管理)) |
| 渲染 | 任意模板引擎,但**必须纯函数** | 可测试、可 dry-run |
| Agent ↔ control plane | 当前 v1 HTTPS + 单签名；目标为 permanent overlay 上的 private service directory + mTLS + ControlSet QC | 公网 EndpointSet 只用于 distribution/bootstrap/data；传输认证、配置授权与防回退不能互相替代 |
| DNS/ACME | provider-neutral adapter + DNS-01；DNS token 仅在 executor 秘密层 | Gandi/Dynadot 只是 adapter，DNS 不是 control authority |
| 度量存储 | 轻量时序;价格与配额用关系表 | **声明值与度量值分开**([§5.2](scheduling.md#52-评分输入分两类)) |
| 数据平面 | sing-box/libbox（HY2 主入口、Trojan/TLS TCP fallback）+ WireGuard（permanent L3/control overlay 与逐边数据 link） | 按 purpose 分离且覆盖移动弱网、UDP 阻断与稳定私网 |
| **L7 网关**(若需要,[§4.4](model.md#44-访问契约换地址能不能只靠-l4-完成)) | 现成反代 + 少量鉴权/改写逻辑 | **不要自己写 L7 代理。** 它同时承担 [§16.2](measurement.md#162-被动观测优先但被动能看到什么由观测点决定) 的应用层埋点,埋点比转发更值得投入 |
| UI | 服务端渲染 | 内部工具,不需要复杂前端 |

> **求解器([§5.4](scheduling.md#54-当前用启发式后续引入求解器))作为独立服务经 API 接入,其语言选择与控制平面无关** —— 因此"与求解器同栈"不构成控制平面的选型理由。

**命名约定**:项目名为 Loom,但**不向下渗透**。内部一律用通用词:`node` / `path` / `declaration` / `snapshot` / `agent` / `tunnel` / `credential` / `render` / `apply` / `rollback`。

## C · 开工前需要确定的问题

> 加粗的两条是**阻塞项** —— 它们决定 L2 能采什么、L3 能优化什么,必须在 L2 之前有答案([§20.5](../../design.md#205-两条容易搞反的依赖))。其余可以边做边定。

**模型侧**

1. **节点清单**:各 Device 位置、Responsibilities、PublicAccessProfile、每条 LinkIntent 的可达性和是否 managed
2. **服务标签体系**:初期定义哪些等价类,粒度如何划分
3. **⚠️ 访问契约与承载方式([§4.4](model.md#44-访问契约换地址能不能只靠-l4-完成))** —— 每个等价类的成员地址是否共用域名、证书、凭据与接口?`carrier` 取 `l4_direct` / `l7_gateway` / `sdk` 中的哪个?**这条不定,服务调度无法落地**
4. **第三方端点**:哪些不可部署的端点需纳入候选;它们的契约是否同构,不同构时是否值得为它引入网关
5. **访问声明**:初期定义哪几个,各自模式、objective、约束、`fallback`
6. **最大跳数**:2 是否够用
7. **双模测量**:哪些 LinkIntent 允许对未启用方向/transport 做低频风险探测

**调度侧**

8. **⚠️ 观测点([§16.2](measurement.md#162-被动观测优先但被动能看到什么由观测点决定))** —— `ttft` / `tokens/s` 从哪来:自有端点埋点、L7 网关、调用方 SDK,还是只能主动契约请求?**没有答案就不要选这两个目标函数**
9. **两级周期**:`ranking_period` 与 `tuning_period` 分别设多少
10. **度量窗口**:`window` / `min_samples` / `stale_after` 取值([§5.8](scheduling.md#58-数据不足与候选集为空))
11. **等价类校验**:多久校验一次、失败后自动移出还是仅告警
12. **探测预算**:主动探测的频率上限与成本上限
13. **价格数据来源**:人工录入、合同导入,还是供应商 API

**平台侧**

14. **控制平面拓扑（已定）** —— `control` 是正交 Device 能力，`ControlSet` 为 1～全部
    合格节点，CFT quorum 动态推导；具体首批选 1/3/5 个稳定 Linux voter 属部署决定
15. **信任与恢复材料** —— Device/control/admin/public TLS 分域；离线 recovery root 的
    保管人数、介质和恢复演练仍需按部署确定
16. **秘密层怎么放** —— 私钥文件路径约定、generation 记法、轮换流程([§12.1](control-rendering.md#121-纯函数的三个产物))
17. **Android 客户端边界（已定）** —— 必须内嵌 [§7.5](agent-runtime.md#75-android-的调度承载) 的最小 signed pull、验签、防回退和窄调度；
    不接受退化为静态选路。仍需部署决定的是升级渠道、签名密钥托管与真机验收矩阵
18. **是否面向多租户** —— 决定 [§5.7](scheduling.md#57-跨客户聚合是网络效应) 跨客户聚合的脱敏设计是否现在就要做
19. **是否启用指纹参数化** —— 触发自建客户端的重决策([§17.5](fingerprints.md#175-性能代价与客户端耦合))
20. **托管 DNS provider 与 zone 委派** —— 选择 Gandi、Dynadot 或其他 adapter，以及
    Loom 独占子区、最小权限 token、DNSSEC/CAA 和传播验收策略
21. **公网入口兼容窗口** —— 双端口 overlap、最大离线兼容期、旧会话 quiet period 与
    emergency retire 的审批门槛
