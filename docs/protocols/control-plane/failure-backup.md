# 故障、备份与垃圾回收

[文档地图](../../README.md) · [架构入口](../../architecture/README.md) · [控制面规范](README.md) · [实现对照](../../development/implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## 故障语义

| 故障 | 必须行为 |
|---|---|
| 所有 distribution mirror 不可达 | 若有已验证离线包则继续，否则在发送任何秘密前失败；不从 DNS 猜新镜像 |
| mirror 返回错误 hash/签名 | 丢弃并标记 mirror 不可信；不尝试解析其 endpoint |
| HY2 全失败但 UDP 未确定阻断 | 有界重试其他已签 HY2；不扫描端口 |
| UDP 完全阻断 | 正式版转 Trojan/TLS TCP fallback；未部署 fallback 时明确报告不支持 |
| capability 过期/超限，claim 未 commit | 入口拒绝并要求新 Invite；客户端不能自动刷新或拿 token 直接拨号 |
| capability/Invite 已过期，reservation 已 certified | `retry_not_after` 前管理员可按 exact transaction binding 重签短期 resume capability；不复活 Invite、不重置事务、不重消费 token |
| bootstrap ingress 被攻陷 | 外层只能转发精确 Enrollment tuple；内层 TLS 阻止其读取/篡改 claim |
| private Enrollment 无 quorum | 不消费 token；返回可重试状态，已 reserve 由 Raft 状态决定 |
| claim 响应丢失 | 保持 exact claim core/key，对新 server challenge 重签 detached PoP；在期限内返回同一 artifact |
| 同 token 不同 key/request | CAS 拒绝并产生安全事件 |
| control_api 公网可达 | 严重配置错误；防火墙/reconciler fail closed |
| Nginx 出现动态 claim/control route | 严重配置错误；不激活该 generation |
| DNS 正确但端口不可达 | endpoint 保持 preparing，不 advertise |
| NAT UDP 映射丢失 | 保留其他 generation；不把 TCP 健康视为 UDP 健康 |
| cert 续签完成但 pin 未提交 | 新 listener 不 advertise，旧 listener继续服务 |
| control quorum 丢失 | 停止新写和外部 destructive reconcile；数据面使用 LKG |
| Device config/report 不可达 | 已安装 tunnel 不停止；缓存报告并按有界策略重试 |
| 同 epoch/revision 出现冲突 QC | 全部 reader/publisher fail closed并报警 |

所有错误必须指明是 distribution、bootstrap transport、inner TLS、claim transaction、control quorum
还是 steady-state API；禁止统一显示“网络错误”导致操作者把 Nginx、HY2 和 Enrollment 混为一谈。

---

## 备份、恢复与垃圾回收

备份必须覆盖：

- Raft log/snapshot、certified heads、QC 和 ControlSet transition；
- CRDT immutable objects 与 content-addressed distribution inventory；
- private ControlServiceDirectory、Invite record/lifecycle 和 enrollment transaction；
- encrypted secret artifacts、issuer authorization、recovery policy；
- DNS/cert/listener/mapping desired generation 与外部 observation；
- 每个 Device 的 view root/result artifact，但不包含 Device private key；
- retention tombstone 和已消费 token commitment。

不备份节点本地 private TLS/WG/Device key；恢复后由原节点证明持钥或走显式 replacement。公开
distribution mirror 可由 signed immutable inventory 重建，不是 authority。

垃圾回收只能追随 certified reachability graph。Invite token plaintext、descriptor 和 capability
应在 consumed/revoked/expired 后尽快擦除；commitment/tombstone 保留到审计期限。旧 endpoint、
证书和 mapping 只有在 reader floor、drain、离线宽限和 backup retention 全部满足后才删除。
Emergency recovery 必须产生新 recovery epoch，不得通过恢复旧数据库回退 floor。

---
