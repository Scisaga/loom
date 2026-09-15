# 服务器转发与目标访问

[文档地图](../../README.md) · [架构入口](../../design.md) · [控制面规范](../../distributed-control-plane.md) · [实现对照](../../implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范范围：架构与数据平面。** 本文定义对应主题的规则；标明 v1 的契约仅用于该版本，标明目标态的机制不表示已实现。

---

## 8. 服务器节点

目标态以 `forward` Responsibility 正向识别服务器。国内/境外、直连公网/NAT、是否同时
`use_loom` 或 `control` 都不产生新的节点类型；差异由 public access profile、LinkIntent 和它在
某条路径上的位置表达。

### 8.1 职责

每台 `forward` 服务器至少收敛四类受控服务/资源：

1. **Nginx HTTPS**：只提供 fake website 与无 token、content-addressed、客户端自行验签的
   immutable `distribution`；不接收或反代 Enrollment/control API；
2. **证书管理**：节点本地持有 TLS key，经最小权限 DNS-01 adapter 签发/续签；
3. **Hysteria2 UDP**：承载正式 data ingress，并可承载短期受限 bootstrap tunnel；
4. **WireGuard UDP**：承载已授权的数据 link 和首版 permanent control L3 overlay。

正式交付还部署独立 Trojan/TLS TCP bootstrap/data fallback，以覆盖 UDP 全阻断网络；它可以与
Nginx 共用一个 L4 SNI dispatcher，但不能由 Nginx 终止或转发 Enrollment。HY2 与 WG 都是 UDP，
不得占用相同 `<address, port, protocol>`；Nginx TCP 443 与 HY2 UDP 443 则不存在传输层冲突。

数据面继续承担：验证连接凭据与访问声明、转发到 LinkIntent 指定的下一跳、在链上最后一跳
从自己的受管 resolver 解析 FQDN 并直连目标，以及上报可归因的分段观测。每台 forward
服务器都具备成为最后一跳的实现能力，是否获得 `internet_egress` 授权由 certified SSOT 决定。

每台 forward 服务器必须有稳定 FQDN，指向其公网地址或 NAT 前端，并有
`ServerPublicAccessProfile`：

| 部署形态 | 公开 HTTPS | UDP listener |
|---|---|---|
| 直连公网且 443 可用 | FQDN:443 → 本机 Nginx | HY2 与 WG 使用各自端口 |
| 443 因部署/合规条件不可用 | FQDN:签名替代 TCP 端口 → Nginx | UDP 端口仍分别声明 |
| NAT/光猫后 | FQDN → NAT 公网地址；外部 TCP 端口映射到本地 Nginx | 外部 UDP 端口/范围映射到不同本地 HY2/WG listener |

DNS 记录本身没有端口；客户端实际拨号 tuple 只从 signed EndpointSet 读取。直连公网部署没有
“映射”可配置；NAT 部署必须把 public/local address、port 与 transport 分开建模并逐项验证。
映射由操作者在 Loom 之外预先提供；Loom 不要求网关管理权限，不通过 UPnP、NAT-PMP 或供应商
NAT API 创建、修改、删除映射，只管理对既有 tuple 的 reservation 与外部验证证据。
替代端口是网络部署能力，不是绕过备案或供应商政策的法律方案。

> 同一物理 Device 若兼任 `control`，public listeners 与 overlay-only control listeners 必须绑定
> 不同地址/防火墙域和用途证书；公网 Nginx 不能成为控制服务反向代理。

### 8.2 凭据即访问声明

服务器上的规则是 `凭据 → 访问声明 → **允许的下一跳集合**`。接入节点通过**使用哪张凭据**表达它要什么,通过**建连时指明的下一跳**表达它选中了哪条 RouteCandidate。

**服务器做准入校验,不做选路**([§5.6](scheduling.md#56-决策位置由信息可得性决定)):校验请求的下一跳是否在该凭据允许的集合内,是则转发,否则拒绝并计入异常。下一跳可能是另一台服务器,也可能是目标地址。

| 接入节点 | 持有凭据 | 效果 |
|---|---|---|
| Windows / Android / Linux 日常入口 | 一把或多把，仅限本设备获授权的声明 | Direct 本地直连；Auto 使用 certified 控制规则；指定出口固定最后一跳，前置路径仍由 Agent 选择 |
| Linux 兼容/高级覆盖 | 多把 | 端口或临时 CLI 只可强制使用已经授权的声明，不得扩权 |

**服务器侧零改动,差别只在发几把钥匙。**

> **凭据同时是授权边界。** 允许的下一跳集合是访问声明的渲染产物([§19](credentials-model.md#19-数据模型))—— **拿到一张凭据不等于能经这台服务器访问任意地方。**

### 8.3 permanent overlay 与数据链路分开

首版以 Loom 自己的 certified LinkIntent 渲染 WG peer，建立 Device/control 所需的 permanent
L3 overlay；Raft、Enrollment、`control_api`、`device_config` 和 `device_report` 只监听该 overlay
的私有 IP。是否以后用 Headscale 等协调器分发 WG peer 是可替换实现，不得改变 ControlSet、
EndpointSet、证书和 ACL authority。

数据链路可以逐边选择 WG 或 HY2，不要求都进入 permanent overlay。Android 只有一个
`VpnService`，因此由同一 libbox/TUN 宿主承载用户流量与必要的 Loom 私网路由，不额外运行
第二个 VPN 应用。未获 ACL 的 Device 即使建立了数据 transport，也不能访问 control subnet。

---

## 9. 目标地址

> ### 不变量
> **目标不是节点。** 它不进拓扑、不参与配置渲染、没有 Agent、不上报状态。Loom 对它做的唯一事情是:**从某台服务器连过去,并测量这次连接的质量。**

自建的推理服务和买来的第三方 API,在这里**完全同等对待**。你可能在自建服务的机器上有 root,但那与 Loom 无关 —— Loom 不管它的网络配置,只把它当成一个要访问的地址。

### 9.1 一个目标地址声明什么

```
- address: https://llm-b.internal/v1
  service: llm:qwen3-32b-int8@openai-v1     # 服务类型标签(§1.4)
  access_contract: {...}                    # 换地址的前提(§4.4)
  credential_ref: vault:llm/hz              # 若需鉴权
```

没有 `server` 块、没有 `direction`、没有隧道 —— 那些都是节点才有的东西。

### 9.2 由此产生的三个后果

- **它不参与配置渲染**,只作为候选集中的一个条目存在;
- 质量数据只能来自外部观测,且受 [§16.2](measurement.md#162-被动观测优先但被动能看到什么由观测点决定) 的观测点可得性限制 —— 没有 L7 观测点时,拿不到 `tokens/s` 与响应结构;
- **不同来源的地址通常不满足 [§4.4](model.md#44-访问契约换地址能不能只靠-l4-完成) 的访问契约同构**:不同域名、不同凭据、不同接口细节。

> ⚠️ **因此不能默认几个地址可以被 L4 直接互换。** 前提是二者之一:它们共用访问契约,或由 L7 网关承载改写。**把这一点当成默认可行,是服务调度最容易犯的设计错误。**

### 9.3 出口鉴权凭据

若目标地址需要鉴权(API Key 等),**出口服务器需要持有它**。这与 [§8.2](#82-凭据即访问声明) 的接入凭据是**两类不同的东西**:

| 凭据类型 | 谁持有 | 用途 |
|---|---|---|
| **接入凭据** | 接入节点 | 向服务器证明"我是谁、我要哪条访问声明" |
| **出口凭据** | 出口服务器 | 向目标地址证明身份 |

两者都由控制平面签发下发,但**作用域完全不同,不可混用**。出口凭据同样只以引用形式进渲染层([§12.1](control-rendering.md#121-纯函数的三个产物))。

---

<a id="第三部分--控制平面"></a>

---
