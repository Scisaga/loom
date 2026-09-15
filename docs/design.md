# Loom · 架构与设计入口

[文档地图](README.md) · [实现对照](implementation.md) · [本机部署信息](operations/local-deployment.md)

**职责：全系统术语、不变量与依赖拓扑。** 按下表进入本任务的主题，不必通读所有专题。
`§` 编号沿用原设计，代码注释和旧链接继续可定位；D 编号只用于解释历史理由。

**规范归属：** 数据平面、纯函数渲染与模型见下列设计专题；v2 控制协议的对象、认证、
状态机和完成标准见[控制面规范](distributed-control-plane.md)。客户端测量预算的完整定义见
[客户端观测复用](client-observation-reuse.md)，平台手册引用它。相关专题应同步修正冲突，
不得靠“最新决策优先”让实现者现场裁决。目标设计与源码、生产状态分别记录。

**公开仓库边界：** 示例使用合成身份、RFC 5737 地址与 example 域名；部署参数和凭据按
[本机部署信息](operations/local-deployment.md)管理，不写入规范、测试或原型。

Loom 是一个基于加密隧道的链路与服务调度基础设施。它只在授权预算内采集可归因的观测；
没有覆盖的候选保持 unknown，不以全路径扫描填补空白。

## 摘要

**问题:** 从任意接入设备到达任意目标地址,存在多条可能路径(直连、单跳、多跳)。这些路径的质量随时间变化;当同一个服务有多个可互换的地址时,还要在它们之间做选择 —— 而"最优"取决于服务性质:交互式推理看首字延迟,批量传输看吞吐,长连接看稳定性,采购决策还要看价格。

**两类应用场景:**

| 场景 | 最终地址从哪来 | 选什么 |
|---|---|---|
| **代理上网** | 由客户端的请求决定(你打开的那个网页) | 只选服务器链 |
| **服务调度** | 从一组可互换的地址里选(如各地机房的推理服务) | 选地址 **+** 选服务器链 |

两者共用同一套机制 —— 第一类只是第二类"地址退化为常量"的情形。第二类的价值更大:当同一服务在多个数据中心部署、且**价格、容量、网络质量都在变动**时,为客户持续选择成本与性能最优的接入路径。

```
        ┌──────────────┐
        │  接入节点     │  PC / Linux / Android
        │  access      │  你的设备,流量从这里进来
        └──────┬───────┘
               │
        ┌──────▼───────┐
        │  服务器节点   │  国内云机 / 境外 VPS —— 同一类东西
        │  server      │  区别只有:在哪、怎么接入
        └──────┬───────┘
               │   ← 链上最后一台服务器就是这次的「出口」
               ▼
          目标地址        网站 / API / 内网服务
                         ★ 不是节点,Loom 不管它,只是一个地址

        路径 = 接入节点 → [0..n 台服务器] → 目标地址
        零跳(直连)是一条合法候选路径,与多跳路径同台竞争
```

**核心模型:**

| 概念 | 定义 | 章节 |
|---|---|---|
| **两类节点** | 接入节点 / 服务器节点,一台机器可兼任。目标地址不是节点 | [§1](specs/design/model.md#1-两类节点加一类不是节点的东西) |
| **出口是位置** | 链上最后一台服务器就是出口 —— 不是一种节点类型 | [§1.1](specs/design/model.md#11-出口不是一种节点是路径上的一个位置) |
| **链路契约** | 发起方、可达性、transport 与 purpose 按边固化；节点级 direction 仅作 v1 迁移输入 | [§2](specs/design/model.md#2-发起方向可达性与-transport-是每条边的契约) |
| **路径** | 从接入到目标地址的一条具体走法,零跳到多跳 | [§3](specs/design/model.md#3-路径) |
| **两个选择轴** | 地址轴 / 服务器轴 —— **决定度量作用在哪儿** | [§4](specs/design/model.md#4-两个选择轴) |
| **等价类** | 只有真正可互换的地址才能进同一候选集 | [§4.3](specs/design/model.md#43-等价类标签不足以保证可替代性) |
| **访问契约** | 输出等价还不够,请求还得能原样送过去 —— **决定换地址能否只靠 L4** | [§4.4](specs/design/model.md#44-访问契约换地址能不能只靠-l4-完成) |
| **路径候选** | `RouteCandidate = (服务器链, 目标地址)` —— 排序与归因的唯一单位 | [§5.6](specs/design/scheduling.md#56-决策位置由信息可得性决定) |
| **调度** | 策略裁剪候选集,度量在候选集内按周期选优 | [§5](specs/design/scheduling.md#5-调度) |
| **控制集合** | `control` 是正交 Device 能力；生效成员为动态 `ControlSet(epoch)`，数量 1～全部合格节点 | [§11](specs/design/control-rendering.md#11-铁律控制平面与数据平面分离) |

**七条不变量:**

| # | 不变量 | 出处 |
|---|---|---|
| 1 | **目标不是节点。** 自建的和买来的一视同仁,都只是地址 | [§1](specs/design/model.md#1-两类节点加一类不是节点的东西), [§9](specs/design/servers.md#9-目标地址) |
| 2 | **出口是路径上的位置,不是节点类型。** 最后一跳就是出口 | [§1.1](specs/design/model.md#11-出口不是一种节点是路径上的一个位置) |
| 3 | 角色字段分块、能力由职责推导；链路发起/transport/purpose 必须逐边 certified | [§1.3](specs/design/model.md#13-数据平面职责分块control-是正交只读投影), [§2](specs/design/model.md#2-发起方向可达性与-transport-是每条边的契约) |
| 4 | **策略约束候选集,度量在候选集内选优** —— 两者不得互相污染 | [§5.1](specs/design/scheduling.md#51-策略裁剪候选集度量在候选集内选优) |
| 5 | **数据平面只做 L4 选路,不改写连接内容** —— 换地址只在访问契约同构时成立 | [§4.4](specs/design/model.md#44-访问契约换地址能不能只靠-l4-完成) |
| 6 | **应用层指标需要 L7 观测点** —— L4 隧道拿不到 `tokens/s` 与响应结构 | [§16.2](specs/design/measurement.md#162-被动观测优先但被动能看到什么由观测点决定) |
| 7 | **控制平面停机,数据平面必须继续运行**；`control` 数量不固定，只有完成 Raft durable commit、状态机 apply/recompute 并取得提交后 replication QC 的 `certified` head 才能改变 effective SSOT，配置仍是其纯函数渲染 | [§11](specs/design/control-rendering.md#11-铁律控制平面与数据平面分离), [§12](specs/design/control-rendering.md#12-逻辑-ssot-与纯函数渲染) |

---

<a id="loom--设计文档"></a>
<a id="第一部分--模型"></a>

## 按主题阅读

| 范围 | 正文与职责 |
|---|---|
| §1, §2, §3, §4 | [节点、地址、路径与服务](specs/design/model.md) |
| §5 | [候选、调度与缺失数据](specs/design/scheduling.md) |
| §6 | [数据隧道与 transport](specs/design/transports.md) |
| §7 | [接入方式与客户端平台](specs/design/client-platforms.md) |
| §7.3 | [日常入口、三模式与 DNS](specs/design/client-routing.md) |
| §7.3.3 | [Agent 执行与客户端宿主](specs/design/agent-runtime.md) |
| §8, §9 | [服务器转发与目标访问](specs/design/servers.md) |
| §10, §11, §12 | [控制边界与纯函数渲染](specs/design/control-rendering.md) |
| §13 | [身份、秘密与加入网络](specs/design/identity.md) |
| §14 | [配置分发、apply 与发布](specs/design/distribution.md) |
| §14.3 | [域名、公开证书与入口轮换](specs/design/public-endpoints.md) |
| §14.4 | [节点生命周期](specs/design/lifecycle.md) |
| §15 | [部署、回滚与组件制品](specs/design/deployment.md) |
| §16 | [采集、上报与分段观测](specs/design/reporting.md) |
| §16.1.3 | [控制界面与管理身份](specs/design/control-ui.md) |
| §16.2 | [观测点、吞吐与服务器探测预算](specs/design/measurement.md) |
| §16.3 | [事件、拓扑与回放](specs/design/events-topology.md) |
| §17 | [指纹参数与轮换](specs/design/fingerprints.md) |
| §18, §19 | [凭据与概念数据模型](specs/design/credentials-model.md) |
| §A, §B, §C | [设计边界、选型与规划输入](specs/design/appendices.md) |
| 客户端交付 | [客户端接入](client-access.md) · [Device 生命周期](device-lifecycle-and-delivery.md) |
| 可选后续设计 | [Local Network](local-network.md) |

## 20. 依赖驱动的构建顺序

**不是时间表,是依赖拓扑。** 每一层只依赖它下面的层。

```
L0  模型与渲染
    ↓
L1  数据平面连通
    ↓
L2  度量采集
    ↓
L3  调度引擎
    ↓
L4  部署自动化
    ↓
L5  运维界面      L6  凭据分发

控制平面与 Enrollment 迁移支线（依赖现有 L0/L4，不能跳步）：
C0  canonical object/QC/transition + issuer/policy/admission proof + public/private split 黄金向量
    ↓
C1  单成员 ControlSet + WG private overlay + overlay-only control service directory
    ↓
C2  forward PublicAccessProfile、静态 Nginx distribution、catalog/public proof 与全平台 v2 reader
    ↓
C3  HY2 BootstrapIngress + exact-bound capability/ACL + private Enrollment TLS/token/server-nonce PoP/resume
    ↓
C4  learner + Joint/Final consensus + 分布式 Enrollment/事件/publisher
    ↓
C5  permanent Device connectivity、private config/report、全平台切换与恢复
    ↓
C6  Trojan/TLS TCP fallback + DNS/ACME + per-generation overlap/frozen refs + 独立端口池/NAT 映射轮换
    ↓
C7  全平台验收、故障演练，并退役 v1 public claim/单中控 authority
```

控制平面支线的完整迁移与验收见
[分布式控制平面 §19～§20](specs/control-plane/migration.md#19-从当前实现迁移)。域名、证书和
端口轮换不能先于 v2 reader：旧严格 schema 客户端看不懂多 endpoint，提前关闭旧端口必然
造成离线 Device 失联。

**独立可选项**(不在主线上,任何时候可插入):

- **替换 WG peer 协调实现**（如 Headscale）—— 只能替换 peer 分发/NAT 协调，不改变
  permanent overlay、ControlSet 或 private service authority；
- **L7 API 网关**([§4.4](specs/design/model.md#44-访问契约换地址能不能只靠-l4-完成))—— **只有需要把访问契约不同构的地址纳入同一等价类时才需要**。它同时是 [§16.2](specs/design/measurement.md#162-被动观测优先但被动能看到什么由观测点决定) 应用层指标的观测点,因此若目标函数含 `ttft` / `tokens/s` 而地址侧没有埋点,它就从"可选"变成"必需";
- **指纹参数化**(AmneziaWG)—— 依赖 L4 的自动回滚,且触发客户端自建的重决策;
- **回放/回测**([§16.5](specs/design/events-topology.md#165-回放与回测))—— 依赖 L2 的度量留存,**在 L3 期间就应具备**,否则阻尼参数只能拍脑袋;
- **求解器**—— 依赖 L2 与 L3,**由 [§5.4](specs/design/scheduling.md#54-当前用启发式后续引入求解器) 的耦合条件触发,不按时间排期**。

### 20.1 L0 · 模型与渲染

**做什么:** 把"网络长什么样、有哪些服务、什么策略"写成结构化数据,再写一个把它变成配置文件的函数。**这一层不含任何自动部署** —— 生成完文件,人工 scp 过去。

**为什么它必须最先做 —— 一个具体例子。** SSOT 里写入一条 certified link intent：

```yaml
link: { from: demo-a, to: demo-b, purpose: data_forward, transport: wireguard, initiator: demo-b }
```

渲染器要输出**两个必须严格对应的文件**:

| `demo-a` 接受侧 | `demo-b` 发起侧 |
|---|---|
| demo-b 的公钥 | demo-a 的公钥 |
| 绑定 intent 指定的 listener | `Endpoint = <intent 中的已验证 public tuple>` |
| 接受方 overlay `/32` | `PersistentKeepalive` 与发起方 overlay `/32` |
| data-forward ACL | 同一 purpose/route scope |

密钥要配对、IP 不能撞、端口与 mapping 必须一致，发起方向和允许 transport 必须来自同一
LinkIntent。v1 迁移器可以从两端 `direction` 推导一次，目标 reader 不再重复猜。

每条双端 link 都至少产生两份必须吻合的配置。手工写错一个字符的后果可能是隧道
静默不通，也可能是 route scope 意外扩大；两者都必须由渲染和校验消除。

> **只渲染被 certified RouteCandidate 或 control overlay 引用的 LinkIntent。** 不生成所有
> forward Device 的笛卡尔积，也不因某个节点有公网 FQDN 就自动授权一条边。

L0 就是消灭这件事。它排在最前,是因为 L1 要建的隧道矩阵、L3 要用的候选集,全都是这份数据的渲染产物。

**产出:** 一套可校验、可 diff、可重放的配置生成能力。

### 20.2 L1 · 数据平面连通

LinkIntent、接入节点接管、服务器转发、末跳出公网，以及每台 forward Device 的
FQDN/Nginx/HY2/WG/PublicAccessProfile。**此时路径是静态指定的** —— 还没有选优，只是能通。

**产出:** 每条候选路径都真实可用。没有连通的路径,无从测量。

### 20.3 L2 · 度量采集

被动观测、主动探测、网络层与应用层指标采集与上报、探测预算控制。

> **开工前必须先定观测点([§16.2](specs/design/measurement.md#162-被动观测优先但被动能看到什么由观测点决定))。** L4 隧道只能产出连接级指标;`ttft` / `tokens/s` / 响应结构需要自有端点埋点、L7 网关或调用方 SDK。**观测点没定,这一层就只能做出网络层的一半。**

**产出:** 每条质量数据都标明观测点、覆盖范围和实测/估算属性；未被证据覆盖的
RouteCandidate 或指标保持 unknown，而不是强制全候选探测或补造数值。

### 20.4 L3 · 调度引擎

策略过滤、等价类校验(输出等价 + 契约同构)、目标函数打分、两级周期与切换阈值、RouteCandidate 排序下发、两个轴的决策分工([§5.6](specs/design/scheduling.md#56-决策位置由信息可得性决定))、冷启动与空候选集处理([§5.8](specs/design/scheduling.md#58-数据不足与候选集为空))。

**产出:** Loom 的核心能力成立。

### 20.5 两条容易搞反的依赖

**L0 必须早于 L1。** 隧道矩阵是全系统最易出错的手工工作。先手工建矩阵再补渲染,等于先制造错误再补工具。

**L2 必须早于 L3。** 没有真实质量数据就写调度引擎,权重只能靠猜,而且**无法验证阻尼参数是否合适** —— 振荡是否发生,只有靠数据才看得出来。

**访问契约与观测点必须早于 L2。** 这两个决定([§4.4](specs/design/model.md#44-访问契约换地址能不能只靠-l4-完成)、[§16.2](specs/design/measurement.md#162-被动观测优先但被动能看到什么由观测点决定))看起来像实现细节,实际决定了 L2 能采到什么、L3 能优化什么。**先建观测再定观测点,等于先采一堆用不上的数据。** 具体地:目标函数选了 `ttft`,却发现所有候选都只有 L4 观测点 —— 那 L3 从第一天起就在拿首字节时间冒充 TTFT,而且没人会发现。

---

<a id="附录"></a>

<details>
<summary>旧章节链接（按需展开；仅跳转，不含第二份规范）</summary>

<a id="1-两类节点加一类不是节点的东西"></a>[1. 两类节点,加一类不是节点的东西](specs/design/model.md#1-两类节点加一类不是节点的东西)
<a id="11-出口不是一种节点是路径上的一个位置"></a>[1.1 出口不是一种节点,是路径上的一个位置](specs/design/model.md#11-出口不是一种节点是路径上的一个位置)
<a id="12-服务器之间只有职责和可达性差异"></a>[1.2 服务器之间只有职责和可达性差异](specs/design/model.md#12-服务器之间只有职责和可达性差异)
<a id="13-数据平面职责分块control-是正交只读投影"></a>[1.3 数据平面职责分块；`control` 是正交只读投影](specs/design/model.md#13-数据平面职责分块control-是正交只读投影)
<a id="14-目标地址带服务类型标签"></a>[1.4 目标地址带服务类型标签](specs/design/model.md#14-目标地址带服务类型标签)
<a id="2-发起方向可达性与-transport-是每条边的契约"></a>[2. 发起方向、可达性与 transport 是每条边的契约](specs/design/model.md#2-发起方向可达性与-transport-是每条边的契约)
<a id="21-目标态的-linkintent"></a>[2.1 目标态的 LinkIntent](specs/design/model.md#21-目标态的-linkintent)
<a id="22-v1-direction-只是迁移输入"></a>[2.2 v1 `direction` 只是迁移输入](specs/design/model.md#22-v1-direction-只是迁移输入)
<a id="23-反连只是某条链路的实现"></a>[2.3 反连只是某条链路的实现](specs/design/model.md#23-反连只是某条链路的实现)
<a id="对端走-ddns-时必须重解析"></a>[对端走 DDNS 时必须重解析](specs/design/model.md#对端走-ddns-时必须重解析)
<a id="24-双模测量"></a>[2.4 双模测量](specs/design/model.md#24-双模测量)
<a id="3-路径"></a>[3. 路径](specs/design/model.md#3-路径)
<a id="31-直连是一等公民"></a>[3.1 直连是一等公民](specs/design/model.md#31-直连是一等公民)
<a id="32-组合爆炸必须裁剪"></a>[3.2 组合爆炸必须裁剪](specs/design/model.md#32-组合爆炸必须裁剪)
<a id="4-两个选择轴"></a>[4. 两个选择轴](specs/design/model.md#4-两个选择轴)
<a id="41-为什么要钉死出口"></a>[4.1 为什么要钉死出口](specs/design/model.md#41-为什么要钉死出口)
<a id="42-为什么要在多个地址间选"></a>[4.2 为什么要在多个地址间选](specs/design/model.md#42-为什么要在多个地址间选)
<a id="43-等价类标签不足以保证可替代性"></a>[4.3 等价类:标签不足以保证可替代性](specs/design/model.md#43-等价类标签不足以保证可替代性)
<a id="44-访问契约换地址能不能只靠-l4-完成"></a>[4.4 访问契约:换地址能不能只靠 L4 完成](specs/design/model.md#44-访问契约换地址能不能只靠-l4-完成)
<a id="45-服务中控分流与度量的单位"></a>[4.5 服务:中控分流与度量的单位](specs/design/model.md#45-服务中控分流与度量的单位)
<a id="应用照常请求-urlloom-ui-不重复选择每个请求的目标"></a>[应用照常请求 URL，Loom UI 不重复选择每个请求的目标](specs/design/model.md#应用照常请求-urlloom-ui-不重复选择每个请求的目标)
<a id="每个请求不需要额外携带选择"></a>[每个请求不需要额外携带选择](specs/design/model.md#每个请求不需要额外携带选择)
<a id="两种地址集合别混"></a>[两种地址集合,别混](specs/design/model.md#两种地址集合别混)
<a id="服务清单会不全而这是可观测的"></a>[服务清单会不全,而这是可观测的](specs/design/model.md#服务清单会不全而这是可观测的)
<a id="任意-url-默认放行也必须显式声明"></a>[任意 URL 默认放行也必须显式声明](specs/design/model.md#任意-url-默认放行也必须显式声明)
<a id="5-调度"></a>[5. 调度](specs/design/scheduling.md#5-调度)
<a id="51-策略裁剪候选集度量在候选集内选优"></a>[5.1 策略裁剪候选集,度量在候选集内选优](specs/design/scheduling.md#51-策略裁剪候选集度量在候选集内选优)
<a id="52-评分输入分两类"></a>[5.2 评分输入分两类](specs/design/scheduling.md#52-评分输入分两类)
<a id="53-目标函数约束式优于加权求和"></a>[5.3 目标函数:约束式优于加权求和](specs/design/scheduling.md#53-目标函数约束式优于加权求和)
<a id="54-当前用启发式后续引入求解器"></a>[5.4 当前用启发式,后续引入求解器](specs/design/scheduling.md#54-当前用启发式后续引入求解器)
<a id="55-调整周期与阻尼"></a>[5.5 调整周期与阻尼](specs/design/scheduling.md#55-调整周期与阻尼)
<a id="56-决策位置由信息可得性决定"></a>[5.6 决策位置由信息可得性决定](specs/design/scheduling.md#56-决策位置由信息可得性决定)
<a id="57-跨客户聚合是网络效应"></a>[5.7 跨客户聚合是网络效应](specs/design/scheduling.md#57-跨客户聚合是网络效应)
<a id="58-数据不足与候选集为空"></a>[5.8 数据不足与候选集为空](specs/design/scheduling.md#58-数据不足与候选集为空)
<a id="第二部分--数据平面"></a>[第二部分 · 数据平面](specs/design/scheduling.md#第二部分--数据平面)
<a id="6-隧道与协议"></a>[6. 隧道与协议](specs/design/transports.md#6-隧道与协议)
<a id="61-跨受限链路"></a>[6.1 跨受限链路](specs/design/transports.md#61-跨受限链路)
<a id="62-无约束链路"></a>[6.2 无约束链路](specs/design/transports.md#62-无约束链路)
<a id="621-接入侧协议可按节点配置"></a>[6.2.1 接入侧协议可按节点配置](specs/design/transports.md#621-接入侧协议可按节点配置)
<a id="怎么判断-udp-到底通不通"></a>[怎么判断 UDP 到底通不通](specs/design/transports.md#怎么判断-udp-到底通不通)
<a id="63-只渲染被显式授权的-linkintent"></a>[6.3 只渲染被显式授权的 LinkIntent](specs/design/transports.md#63-只渲染被显式授权的-linkintent)
<a id="7-接入节点"></a>[7. 接入节点](specs/design/client-platforms.md#7-接入节点)
<a id="71-两种接管方式"></a>[7.1 两种接管方式](specs/design/client-platforms.md#71-两种接管方式)
<a id="72-平台差异"></a>[7.2 平台差异](specs/design/client-platforms.md#72-平台差异)
<a id="721-windows-的-portable-与安装版"></a>[7.2.1 Windows 的 Portable 与安装版](specs/design/client-platforms.md#721-windows-的-portable-与安装版)
<a id="73-v1-只有一个逻辑日常入口"></a>[7.3 v1 只有一个逻辑日常入口](specs/design/client-routing.md#73-v1-只有一个逻辑日常入口)
<a id="linux-兼容与高级覆盖"></a>[Linux 兼容与高级覆盖](specs/design/client-routing.md#linux-兼容与高级覆盖)
<a id="731-selector-需要一个能切它的端点"></a>[7.3.1 selector 需要一个能切它的端点](specs/design/client-routing.md#731-selector-需要一个能切它的端点)
<a id="732-dns-必须显式配而且要给它留一条出路"></a>[7.3.2 DNS 必须显式配,而且要给它留一条出路](specs/design/client-routing.md#732-dns-必须显式配而且要给它留一条出路)
<a id="733-agent调参回路的唯一执行者"></a>[7.3.3 Agent：调参回路的唯一执行者](specs/design/agent-runtime.md#733-agent调参回路的唯一执行者)
<a id="排序失败率优先相同失败率再比目标指标"></a>[排序:失败率优先,相同失败率再比目标指标](specs/design/agent-runtime.md#排序失败率优先相同失败率再比目标指标)
<a id="三条切换规则优先级从高到低"></a>[三条切换规则,优先级从高到低](specs/design/agent-runtime.md#三条切换规则优先级从高到低)
<a id="windows--android-客户端减少无收益中继"></a>[Windows / Android 客户端：减少无收益中继](specs/design/agent-runtime.md#windows--android-客户端减少无收益中继)
<a id="窗口必须装得下-min_samples"></a>[窗口必须装得下 min_samples](specs/design/agent-runtime.md#窗口必须装得下-min_samples)
<a id="不能执行的-objective-必须显式拒绝"></a>[不能执行的 objective 必须显式拒绝](specs/design/agent-runtime.md#不能执行的-objective-必须显式拒绝)
<a id="734-探测入口一个端口用户名区分候选"></a>[7.3.4 探测入口：一个端口，用户名区分候选](specs/design/agent-runtime.md#734-探测入口一个端口用户名区分候选)
<a id="735-可选扩展按服务热更新-rule_set"></a>[7.3.5 可选扩展：按服务热更新 `rule_set`](specs/design/agent-runtime.md#735-可选扩展按服务热更新-rule_set)
<a id="74-环境变量代理的已知坑"></a>[7.4 环境变量代理的已知坑](specs/design/agent-runtime.md#74-环境变量代理的已知坑)
<a id="75-android-的调度承载"></a>[7.5 Android 的调度承载](specs/design/agent-runtime.md#75-android-的调度承载)
<a id="8-服务器节点"></a>[8. 服务器节点](specs/design/servers.md#8-服务器节点)
<a id="81-职责"></a>[8.1 职责](specs/design/servers.md#81-职责)
<a id="82-凭据即访问声明"></a>[8.2 凭据即访问声明](specs/design/servers.md#82-凭据即访问声明)
<a id="83-permanent-overlay-与数据链路分开"></a>[8.3 permanent overlay 与数据链路分开](specs/design/servers.md#83-permanent-overlay-与数据链路分开)
<a id="9-目标地址"></a>[9. 目标地址](specs/design/servers.md#9-目标地址)
<a id="91-一个目标地址声明什么"></a>[9.1 一个目标地址声明什么](specs/design/servers.md#91-一个目标地址声明什么)
<a id="92-由此产生的三个后果"></a>[9.2 由此产生的三个后果](specs/design/servers.md#92-由此产生的三个后果)
<a id="93-出口鉴权凭据"></a>[9.3 出口鉴权凭据](specs/design/servers.md#93-出口鉴权凭据)
<a id="第三部分--控制平面"></a>[第三部分 · 控制平面](specs/design/servers.md#第三部分--控制平面)
<a id="10-职责"></a>[10. 职责](specs/design/control-rendering.md#10-职责)
<a id="11-铁律控制平面与数据平面分离"></a>[11. 铁律:控制平面与数据平面分离](specs/design/control-rendering.md#11-铁律控制平面与数据平面分离)
<a id="111-control-是动态节点能力不是固定三台机器"></a>[11.1 `control` 是动态节点能力，不是固定三台机器](specs/design/control-rendering.md#111-control-是动态节点能力不是固定三台机器)
<a id="12-逻辑-ssot-与纯函数渲染"></a>[12. 逻辑 SSOT 与纯函数渲染](specs/design/control-rendering.md#12-逻辑-ssot-与纯函数渲染)
<a id="121-纯函数的三个产物"></a>[12.1 纯函数的三个产物](specs/design/control-rendering.md#121-纯函数的三个产物)
<a id="13-密钥与信任"></a>[13. 密钥与信任](specs/design/identity.md#13-密钥与信任)
<a id="131-私钥不集中生成"></a>[13.1 私钥不集中生成](specs/design/identity.md#131-私钥不集中生成)
<a id="132-ssh-证书-ca-替代-authorized_keys"></a>[13.2 SSH 证书 CA 替代 authorized_keys](specs/design/identity.md#132-ssh-证书-ca-替代-authorized_keys)
<a id="133-ca-与恢复私钥是最高价值目标"></a>[13.3 CA 与恢复私钥是最高价值目标](specs/design/identity.md#133-ca-与恢复私钥是最高价值目标)
<a id="134-凭据轮换必须分两步"></a>[13.4 凭据轮换:必须分两步](specs/design/identity.md#134-凭据轮换必须分两步)
<a id="为什么不能一步切"></a>[为什么不能一步切](specs/design/identity.md#为什么不能一步切)
<a id="命名第一代不带后缀"></a>[命名:第一代不带后缀](specs/design/identity.md#命名第一代不带后缀)
<a id="路由规则要匹配两个名字"></a>[路由规则要匹配两个名字](specs/design/identity.md#路由规则要匹配两个名字)
<a id="顺序不能反而且工具会挡"></a>[顺序不能反,而且工具会挡](specs/design/identity.md#顺序不能反而且工具会挡)
<a id="忘了第二步是这套流程最可能出的错"></a>[忘了第二步,是这套流程最可能出的错](specs/design/identity.md#忘了第二步是这套流程最可能出的错)
<a id="135-客户端加入网络复用-certified-ssot-与发布链"></a>[13.5 客户端加入网络复用 certified SSOT 与发布链](specs/design/identity.md#135-客户端加入网络复用-certified-ssot-与发布链)
<a id="14-控制通道"></a>[14. 控制通道](specs/design/distribution.md#14-控制通道)
<a id="141-可达性是图不是成员资格"></a>[14.1 可达性是图，不是成员资格](specs/design/distribution.md#141-可达性是图不是成员资格)
<a id="142-signed-pull-与管理面快速发布并存"></a>[14.2 signed pull 与管理面快速发布并存](specs/design/distribution.md#142-signed-pull-与管理面快速发布并存)
<a id="1421-apply五步顺序不能换"></a>[14.2.1 apply:五步,顺序不能换](specs/design/distribution.md#1421-apply五步顺序不能换)
<a id="wg-quick-不能用-systemctl-restart"></a>[wg-quick 不能用 systemctl restart](specs/design/distribution.md#wg-quick-不能用-systemctl-restart)
<a id="一次-ssh-传完"></a>[一次 ssh 传完](specs/design/distribution.md#一次-ssh-传完)
<a id="1422-分发面公开证明与私有-device-view-分离"></a>[14.2.2 分发面：公开证明与私有 Device view 分离](specs/design/distribution.md#1422-分发面公开证明与私有-device-view-分离)
<a id="状态一致比版本号一致重要"></a>[状态一致比"版本号一致"重要](specs/design/distribution.md#状态一致比版本号一致重要)
<a id="三类自己套自己的坑"></a>[三类"自己套自己"的坑](specs/design/distribution.md#三类自己套自己的坑)
<a id="v1-二进制与配置的安全契约"></a>[v1 二进制与配置的安全契约](specs/design/distribution.md#v1-二进制与配置的安全契约)
<a id="1423-publisherreconciler提交与外部副作用分开"></a>[14.2.3 Publisher/reconciler：提交与外部副作用分开](specs/design/distribution.md#1423-publisherreconciler提交与外部副作用分开)
<a id="143-拉取通道的保护"></a>[14.3 拉取通道的保护](specs/design/public-endpoints.md#143-拉取通道的保护)
<a id="1431-托管域名与证书"></a>[14.3.1 托管域名与证书](specs/design/public-endpoints.md#1431-托管域名与证书)
<a id="1432-公网-listener-与端口无中断轮换"></a>[14.3.2 公网 listener 与端口无中断轮换](specs/design/public-endpoints.md#1432-公网-listener-与端口无中断轮换)
<a id="144-节点生命周期四个状态加和删要对称"></a>[14.4 节点生命周期:四个状态,加和删要对称](specs/design/lifecycle.md#144-节点生命周期四个状态加和删要对称)
<a id="暂停纯接入设备的转发访问"></a>[暂停纯接入设备的转发访问](specs/design/lifecycle.md#暂停纯接入设备的转发访问)
<a id="排空让流量走开但别瞎"></a>[排空:让流量走开,但别瞎](specs/design/lifecycle.md#排空让流量走开但别瞎)
<a id="下线一条经过认证的停机指令"></a>[下线:一条经过认证的停机指令](specs/design/lifecycle.md#下线一条经过认证的停机指令)
<a id="移除两件机器管不了的事"></a>[移除:两件机器管不了的事](specs/design/lifecycle.md#移除两件机器管不了的事)
<a id="处在过渡态是看不出来的"></a>[处在过渡态,是看不出来的](specs/design/lifecycle.md#处在过渡态是看不出来的)
<a id="control-capability-必须先退出-finalcontrolset"></a>[control capability 必须先退出 FinalControlSet](specs/design/lifecycle.md#control-capability-必须先退出-finalcontrolset)
<a id="15-部署与回滚"></a>[15. 部署与回滚](specs/design/deployment.md#15-部署与回滚)
<a id="151-流程"></a>[15.1 流程](specs/design/deployment.md#151-流程)
<a id="152-自动回滚仅-linuxserver-发布-canary-的跨节点目标态"></a>[15.2 自动回滚（仅 Linux/server 发布 canary 的跨节点目标态）](specs/design/deployment.md#152-自动回滚仅-linuxserver-发布-canary-的跨节点目标态)
<a id="153-幂等收敛"></a>[15.3 幂等收敛](specs/design/deployment.md#153-幂等收敛)
<a id="154-制品与版本管理"></a>[15.4 制品与版本管理](specs/design/deployment.md#154-制品与版本管理)
<a id="16-度量与可观测"></a>[16. 度量与可观测](specs/design/reporting.md#16-度量与可观测)
<a id="agent-自身的分发契约"></a>[Agent 自身的分发契约](specs/design/reporting.md#agent-自身的分发契约)
<a id="顺序先二进制后配置"></a>[顺序:先二进制,后配置](specs/design/reporting.md#顺序先二进制后配置)
<a id="跑不起来的二进制装上去这台机器就再也拉不到修复了"></a>[跑不起来的二进制装上去,这台机器就再也拉不到修复了](specs/design/reporting.md#跑不起来的二进制装上去这台机器就再也拉不到修复了)
<a id="两个容易忘的实现细节"></a>[两个容易忘的实现细节](specs/design/reporting.md#两个容易忘的实现细节)
<a id="161-采集什么"></a>[16.1 采集什么](specs/design/reporting.md#161-采集什么)
<a id="1611-两个角色决策者与上报者"></a>[16.1.1 两个角色:决策者与上报者](specs/design/reporting.md#1611-两个角色决策者与上报者)
<a id="不是所有变化都是问题"></a>[不是所有变化都是问题](specs/design/reporting.md#不是所有变化都是问题)
<a id="没有后续不等于还在持续"></a>["没有后续"不等于"还在持续"](specs/design/reporting.md#没有后续不等于还在持续)
<a id="没有问题也要说出来"></a>["没有问题"也要说出来](specs/design/reporting.md#没有问题也要说出来)
<a id="三个容易做错的地方"></a>[三个容易做错的地方](specs/design/reporting.md#三个容易做错的地方)
<a id="覆盖面由拓扑决定且必须说出来"></a>[覆盖面由拓扑决定,且必须说出来](specs/design/reporting.md#覆盖面由拓扑决定且必须说出来)
<a id="1612-按段量不按整条路线量"></a>[16.1.2 按段量,不按整条路线量](specs/design/reporting.md#1612-按段量不按整条路线量)
<a id="每台机器量两样"></a>[每台机器量两样](specs/design/reporting.md#每台机器量两样)
<a id="转述没有隧道也能听到"></a>[转述:没有隧道也能听到](specs/design/reporting.md#转述没有隧道也能听到)
<a id="用法一剪枝"></a>[用法一:剪枝](specs/design/reporting.md#用法一剪枝)
<a id="用法二分段合成估计"></a>[用法二：分段合成估计](specs/design/reporting.md#用法二分段合成估计)
<a id="1613-界面运行态可分布读取管理写经私有-control_api-由任一-control-device-接收"></a>[16.1.3 界面：运行态可分布读取，管理写经私有 control_api 由任一 control Device 接收](specs/design/control-ui.md#1613-界面运行态可分布读取管理写经私有-control_api-由任一-control-device-接收)
<a id="界面是运行模型的投影不是另一套产品模型"></a>[界面是运行模型的投影,不是另一套产品模型](specs/design/control-ui.md#界面是运行模型的投影不是另一套产品模型)
<a id="进入路径与认证"></a>[进入路径与认证](specs/design/control-ui.md#进入路径与认证)
<a id="权限按身份和用途分"></a>[权限按身份和用途分](specs/design/control-ui.md#权限按身份和用途分)
<a id="写入口只提交-ssot-operation"></a>[写入口只提交 SSOT operation](specs/design/control-ui.md#写入口只提交-ssot-operation)
<a id="control-本机-bootstrap-与-certified-membership-分开"></a>[control 本机 bootstrap 与 certified membership 分开](specs/design/control-ui.md#control-本机-bootstrap-与-certified-membership-分开)
<a id="页面里不能有任何外部资源"></a>[页面里不能有任何外部资源](specs/design/control-ui.md#页面里不能有任何外部资源)
<a id="162-被动观测优先但被动能看到什么由观测点决定"></a>[16.2 被动观测优先,但被动能看到什么由观测点决定](specs/design/measurement.md#162-被动观测优先但被动能看到什么由观测点决定)
<a id="1621-首字节不是全部每多一跳吞吐掉到四分之一"></a>[16.2.1 首字节时间与吞吐是不同指标](specs/design/measurement.md#1621-首字节不是全部每多一跳吞吐掉到四分之一)
<a id="后果按首字节排会挑出连得快传得慢的路"></a>[后果:按首字节排会挑出连得快、传得慢的路](specs/design/measurement.md#后果按首字节排会挑出连得快传得慢的路)
<a id="3-说了跳数上限没说第二跳的代价"></a>[§3 说了跳数上限,没说第二跳的代价](specs/design/measurement.md#3-说了跳数上限没说第二跳的代价)
<a id="测不出吞吐时必须说出来不能并列最差"></a>[测不出吞吐时必须说出来,不能并列最差](specs/design/measurement.md#测不出吞吐时必须说出来不能并列最差)
<a id="1622-探测预算有界而不是全探"></a>[16.2.2 探测预算:有界,而不是全探](specs/design/measurement.md#1622-探测预算有界而不是全探)
<a id="预算引入了一条新的算术约束"></a>[预算引入了一条新的算术约束](specs/design/measurement.md#预算引入了一条新的算术约束)
<a id="163-告警"></a>[16.3 告警](specs/design/events-topology.md#163-告警)
<a id="1631-事件只记变化不记状态"></a>[16.3.1 事件:只记变化,不记状态](specs/design/events-topology.md#1631-事件只记变化不记状态)
<a id="判据两次观测不同才产生一条记录"></a>[判据:两次观测不同,才产生一条记录](specs/design/events-topology.md#判据两次观测不同才产生一条记录)
<a id="内容寻址事件在-control-副本间收敛"></a>[内容寻址事件在 control 副本间收敛](specs/design/events-topology.md#内容寻址事件在-control-副本间收敛)
<a id="这不是告警而且不能当告警用"></a>[这不是告警,而且不能当告警用](specs/design/events-topology.md#这不是告警而且不能当告警用)
<a id="164-可视化"></a>[16.4 可视化](specs/design/events-topology.md#164-可视化)
<a id="165-回放与回测"></a>[16.5 回放与回测](specs/design/events-topology.md#165-回放与回测)
<a id="17-指纹重建"></a>[17. 指纹重建](specs/design/fingerprints.md#17-指纹重建)
<a id="171-不自己改协议"></a>[17.1 不自己改协议](specs/design/fingerprints.md#171-不自己改协议)
<a id="172-amneziawg-参数化"></a>[17.2 AmneziaWG 参数化](specs/design/fingerprints.md#172-amneziawg-参数化)
<a id="173-参数必须每次部署重新生成"></a>[17.3 参数必须每次部署重新生成](specs/design/fingerprints.md#173-参数必须每次部署重新生成)
<a id="174-轮换是高危操作"></a>[17.4 轮换是高危操作](specs/design/fingerprints.md#174-轮换是高危操作)
<a id="175-性能代价与客户端耦合"></a>[17.5 性能代价与客户端耦合](specs/design/fingerprints.md#175-性能代价与客户端耦合)
<a id="18-凭据与分发"></a>[18. 凭据与分发](specs/design/credentials-model.md#18-凭据与分发)
<a id="19-数据模型"></a>[19. 数据模型](specs/design/credentials-model.md#19-数据模型)
<a id="第四部分--构建顺序"></a>[第四部分 · 构建顺序](specs/design/credentials-model.md#第四部分--构建顺序)
<a id="a--明确不做的事"></a>[A · 明确不做的事](specs/design/appendices.md#a--明确不做的事)
<a id="b--技术选型建议非强制"></a>[B · 技术选型建议(非强制)](specs/design/appendices.md#b--技术选型建议非强制)
<a id="c--开工前需要确定的问题"></a>[C · 开工前需要确定的问题](specs/design/appendices.md#c--开工前需要确定的问题)

</details>
