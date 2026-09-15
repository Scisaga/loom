# Device 控制能力、quorum 与故障模型

[文档地图](../../README.md) · [架构入口](../../architecture/README.md) · [控制面规范](README.md) · [实现对照](../../development/implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## Device 能力与控制角色

control 候选必须先按 [Enrollment、邀请与报告](enrollment-invite.md#enrollment邀请与报告) 完成 Enrollment、持有有效 Device identity，并已能通过永久 Loom
overlay 到达现有 ControlSet；不能在公网 bootstrap 阶段直接成为 voter。目标 SSOT 对
`access/server` 仍使用“角色块存在即拥有能力”；`control` 块只展示
`FinalControlSet` 已授予的 capability projection，不是管理员可直接生效的普通字段：

```yaml
nodes:
  - id: demo-a
    server: { ... }
    control:
      member_id: 00000000000000000000000001
      signing_public_keys:
        config: ed25519:...
        membership: ed25519:...
        enrollment: ed25519:...
```

不存在另一个可写的 `capabilities: [control]`。不过 `control` 不能像普通字段那样先改 SSOT
再自我授权：规范内部成员事实是 Raft 配置日志中的 committed `FinalControlSet`/transition
ledger；reducer 只有在 Final 取得 joint QC、并取得 matching private directory 后，才把它投影为
授权 operator 可见的 private materialized `control` 块。`committed_not_certified` Final 已约束
Raft 自身，却不能更新客户端 authority；public projection 永远只有 opaque set/key 与 directory hash。
用户仍只维护一套逻辑模型，但任何
增删/换 key 都必须走 [ControlSet 成员变化](membership-transition.md#controlset-成员变化) 的 joint state machine，不能用普通 operation、CRDT 合并或手填第二
成员表绕过。

需要区分以下状态：

| 状态 | 含义 | 能否投票 |
|---|---|---:|
| candidate | 管理员已提出加入，但尚未同步 | ❌ |
| learner | 已建立 control mTLS 并复制完整 checkpoint/log | ❌ |
| joint member | 正处于旧、新集合联合提交阶段 | 只按 joint 规则 |
| voter | 当前 `ControlSet(epoch)` 的正式成员 | ✅ |
| retiring | 已从新集合移除，仍完成 joint handoff | 只按 joint 规则 |
| removed | 不再是 control；普通 Device 生命周期另行处理 | ❌ |

candidate/learner/retiring 是控制协议运行态，不作为可与 `control` 块矛盾的长期 SSOT
布尔字段。一次迁移完成后，内部稳定成员状态只由 committed `FinalControlSet` ledger 推导；
private operator view 的 `control` 块只在 certified 结果与 matching directory 上联合投影，不能反向
自我授权，也不得进入 public distribution/per-Device view。

control Device 至少必须具备：耐久磁盘、受保护的独立密钥、受监测的可信时间源、可与其他成员建立
mTLS、支持当前控制 schema/协议，并能保存完整 checkpoint。协议不按 Android、Windows 或
Linux 平台禁止 voter；任何 Device 只有通过相同 eligibility 才可入组。当前部署究竟哪些平台
已有合格实现只见 [实现对照](../../development/implementation.md)，不得写死在目标协议。

静态镜像、DNS/ACME executor 和 control voter 是三种不同职责。镜像不投票；executor
只能应用 certified 期望；voter 不因持有普通 Device 证书或能访问管理 API而自动获得 admin 权限。

---

## ControlSet、quorum 与故障模型

在 crash-fault tolerant（CFT）配置下：

```text
N = |ControlSet(epoch)|
q(N) = floor(N / 2) + 1
可容忍离线数 = N - q(N)
```

| N | q | 可容忍离线 | 说明 |
|---:|---:|---:|---|
| 1 | 1 | 0 | 最小可运行；无控制面 HA |
| 2 | 2 | 0 | 任一成员离线即停写 |
| 3 | 2 | 1 | 最小推荐 HA 部署 |
| 4 | 3 | 1 | 比 3 多一成员但不多容忍一次故障 |
| 5 | 3 | 2 | 更高可用性，提交路径也更长 |

quorum 永远按 committed 成员数 `N` 计算。健康检查、DNS 记录、当前可达成员或操作者
选择都不能改变它，否则一次分区可能让两侧分别按较小的在线集合提交。

架构允许所有合格 Device 都拥有 `control`，但不要求这样部署。跨地域 voter 越多，
控制写入需要跨越的故障域和尾延迟通常越大；常见部署可选择 3 或 5 个稳定 voter，其他
Device 仍可作为镜像、观测副本或 learner。这个建议不进入协议校验。

首版 CFT 假设控制进程可能宕机、丢包或分区，且正确 voter 遵守 Raft 持久化、选举和日志
匹配规则；它不容忍任意作恶或密钥失陷。每个 voter 的独立签名提供来源和审计，不能把 CFT
自动宣传成 Byzantine 容错。若以后需要容忍 `f`
个恶意 voter，必须切换到经过审计的 BFT profile，至少满足 `N >= 3f + 1`、提交证明
至少 `2f + 1`，并实现锁定、轮次和 view-change；仅把签名门槛改大不够。

---
