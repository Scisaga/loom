# 数据隧道与 transport

[文档地图](../README.md) · [架构入口](README.md) · [控制面规范](../protocols/control-plane/README.md) · [实现对照](../development/implementation.md) · [本机部署信息](../operations/local-deployment.md)

**规范范围：架构与数据平面。** 本文定义对应主题的规则；标明 v1 的契约仅用于该版本，标明目标态的机制不表示已实现。

---

## 隧道与协议

**协议按边和 purpose 选择，不做全局统一。** 同一种协议也不能跨 purpose 复用凭据或
listener：control overlay、正式数据转发和首次 bootstrap 是三份独立契约。

### 跨受限链路

服务器间需要稳定 L3 或主动反连的边默认 WireGuard。`PersistentKeepalive` 适合由指定一侧
维持、建立后双向可达的长期 overlay；首版 Raft/control overlay 因此固定使用 WG。

Hysteria2 的拥塞控制可能在高丢包数据链路收益更大。只要 LinkIntent 明确发起端和 listener，
它可以承载某条代理/数据转发边，不需要保留“境内/境外固定协议”的分类；收益必须实测。

> **WG 是首版 control L3 的默认，不是所有数据边的默认。** HY2 代理转发不等价于任意
> 双向 L3；未实现 L3-over-HY2 时不得用它承载 Raft/control overlay，也不默认 WG-over-HY2。

### 无约束链路

公网数据入口默认 Hysteria2。首次 Enrollment 的临时 bootstrap tunnel 首版也只实现 HY2，
避免在 Device 身份尚未签发时先向所有入口分发 WG peer。正式交付增加独立 Trojan/TLS TCP
fallback 以覆盖 UDP 完全阻断网络；该 TCP listener 不是 Nginx Enrollment 反代。

### 接入侧协议可按节点配置

前两节讲的是"哪个更好"。接入这一跳还有一个更硬的前置问题:**上游的网络让
什么出去。**

有的网络会整体封禁 UDP(封 QUIC,把流量逼回可审计的 TCP 代理)。那种链路上:

| | 能用吗 |
|---|---|
| Hysteria2(QUIC/UDP) | ❌ |
| **WireGuard(UDP)** | ❌ **它也是 UDP** |
| Trojan / VLESS(TCP + TLS) | ✅ |

> ⚠️ [跨受限链路](#跨受限链路) 说跨受限链路默认 WireGuard,那是针对服务器之间。**接入节点所在的
> 网络你往往控制不了**,而 UDP 被整体封禁时,WireGuard 和 Hysteria2 会一起
> 失效 —— 这时唯一的出路是 TCP。

目标态在 `BootstrapIngressEndpointSet` / `DataIngressEndpointSet` 中并列授权实际可用的
transport；v1 才继续由 `inbound_protocol` 单值兼容。客户端先测 HY2，确认 UDP 不可达后才
使用已签名的 Trojan/TLS TCP fallback。两者都必须执行各自的认证和 ACL。

**默认仍是 Hysteria2。** 只在确认 UDP 不通之后才改 —— 见下面的排查方法,
以及那个很容易掉进去的坑。

#### 怎么判断 UDP 到底通不通

| 现象 | 含义 | 修法 |
|---|---|---|
| `connection refused` | 包到了,没人监听 | 起服务 |
| `i/o timeout` | 包被丢 | 防火墙 —— 但**先确认是哪一侧** |

判断被谁丢掉,要在服务器上抓包:

```bash
tcpdump -nn -i any "udp and host <客户端出口IP>"
```

> ⚠️ **这里有个坑,我们真掉进去过。**
>
> 抓包过滤器里的"客户端出口 IP"必须是**该客户端直连时的出口**。如果那台机器
> 同时配了 HTTP 代理,`curl https://api.ipify.org` 报出的是**代理的**出口 IP,
> 不是它自己的。拿那个 IP 去做过滤器,抓不到任何包 —— 而"抓不到包"看起来和
> "UDP 被封"一模一样。
>
> **正确做法:先不加 host 过滤器抓一次**,直接看源 IP 是什么。多花十秒,
> 省掉一次完全错误的归因。
>
> 同理,测试端口必须落在防火墙实际放行的范围内。拿范围外的端口去测,
> 测到的是防火墙规则,不是网络能力。

### 只渲染被显式授权的 LinkIntent

目标态不再从 `reverse_only` 或全连接 mesh 自动生成隧道矩阵。渲染器只处理 certified
SSOT 中确有业务候选或 control overlay 需要的 `LinkIntent`，并逐边验证 purpose、发起端、
transport、地址、listener、凭据和路由。v1 可以用 [v1 `direction` 只是迁移输入](model.md#v1-direction-只是迁移输入) 真值表把既有 `direction + Tunnel`
确定性迁移成这些对象；迁移后不再读取节点级方向做新决策。

需要到达同一末跳的多个前置服务器通常仍各自直连，避免人为制造汇聚单点：

```
接入(北京) ──选中──→ 北京云机 ──[反连隧道]──→ 境外 VPS
接入(贵州) ──选中──→ 广州云机 ──[反连隧道]──→ 境外 VPS
                            ↑ 每台各自直连,无单点汇聚
```

强制汇聚会产生无收益绕行。具体扇出集合由已授权 RouteCandidate 反推，不是所有
`forward` Device 的笛卡尔积；没有候选引用的 link 不应只为“矩阵完整”而创建。

**一条隧道一个网卡,不是一个网卡挂多个 peer。**

这不是风格选择。**多台境外 VPS 都要承载 `AllowedIPs = 0.0.0.0/0`**(出口流量的目的地是任意公网地址),而 WireGuard 按目的地址匹配 peer —— 同一个网卡上不能有两个 peer 都吃下全部地址空间。**必须分网卡。**

> ⚠️ **每条双端配置仍必须由渲染器生成。** 两端密钥、AllowedIPs、端口、transport 与
> 发起方向必须逐字段对应；一端无法表达时整条 link 失败关闭，不能降级到另一协议。

---
