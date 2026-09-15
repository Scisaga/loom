# v2 验收矩阵

[文档地图](../../README.md) · [架构入口](../../architecture/README.md) · [控制面规范](README.md) · [实现对照](../../development/implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## 验收矩阵

### 共识与成员

1. N=1、3、5 的 quorum 计算正确，不按在线成员缩小；
2. candidate 必须已有 Device identity 和 overlay reachability；
3. learner 未 catch-up 不投票；
4. joint old/new 双多数与 Final QC 正确；
5. leader 在 commit 后、QC 前崩溃可恢复相同 certified result；
6. minority partition 不能创建 Invite、消费 token、改 ACL 或轮换 listener；
7. control peer cert 不能调用 admin API，admin cert 不能参与 Raft；
8. public FQDN/Nginx compromise 不能到达 control socket。

### CRDT、SSOT 与 secret

1. operation/object 顺序不同收敛到相同 root；
2. 相同 key 的竞争写确定性处理；
3. CRDT 草稿和 committed_not_certified 不驱动外部副作用；
4. secret artifact 只有目标 Device 能解封；
5. bootstrap issuer 不能签正式 Device cert/config head；
6. backup restore 不回退 recovery/config/listener floor；
7. renderer 输出确定性，无时钟、随机、网络查询。
8. 新 Invite/Device view 出现节点级 direction 字段必须按 unknown field 拒绝；链路只读 certified LinkIntent。

### QR、distribution 与 catalog

1. QR 只含 2–3 mirror refs、hash、token/capability 和有界 private service ref；
2. QR 大小上限、未知字段、重复 mirror、单故障域镜像按 policy 拒绝；
3. .loom-invite 与 QR descriptor canonical hash 相同；
4. Nginx 只接受 GET/HEAD fake/static hash path；
5. POST claim、动态 token URL、cookie 和任何 redirect 全部拒绝；
6. mirror 返回错误 digest/QC/floor/expired catalog 时客户端不发送 capability；
7. mirror hints 只影响下载顺序，不决定真实 tunnel；
8. 无 mirror 但有完整合法 offline package 可以继续；
9. 静态 catalog 不含 token、capability、private ControlServiceDirectory 或 per-Device view；
10. public proof 只能披露 hiding commitment，不含 Device intent/opening；客户端只在已验证 inner TLS
    的 private preflight 取得 opening，commitment/opening/intent 任一不匹配即不发送 token。

### Bootstrap transport 与 capability

1. HY2 是首选；首版 reader 对 WG bootstrap 明确报不支持；
2. 客户端对当前网络代的每个授权 ingress 最多一次有界主动 probe；
3. UDP 全阻断后选择独立 Trojan/TLS fallback；
4. HTTP 200 或 Nginx RTT 不能标记 HY2/Trojan 可用；
5. capability 必须引用 committed Invite，并 exact 绑定 policy、service ref、issuer authorization、
   当前 registry root/audit path；capability ID 必须仅由 body 重算且无自引用；
6. issuer authorization 的 previous/status/revocation 链异常，或 ingress/service 不在其 scope，均拒绝；
7. 过期、未来签发、超 initial/resume TTL/流量/session/次数、错误 ingress set 全拒绝；
8. tunnel 只能访问一个 Enrollment /32或/128 + TCP port；
9. control_api、Raft、SSH、DNS、ICMP、UDP 和 Internet egress 均不可达；
10. ingress 无法读取内层 opening/token/CSR/Device identity；
11. 同 capability 并发 session 和异常重放受限，但不代替全局 token CAS；
12. 网络切换后在有效期限/次数内可跨 ingress 重试；
13. initial capability 不晚于 Invite 过期，客户端不能自动刷新过期 capability；
14. committed claim 可由管理员签发 exact-bound `EnrollmentResumeDescriptorV1`；completed 返回原
    result，reserved/issued_provisional 继续原事务，且 token consumption 计数不增加；
15. resume 中 request/CSR/identity/wrapping/transaction 任一 hash 改变都拒绝；descriptor 只能经
    private admin-authenticated control_api 一次性交付，v2 拒绝旧 1 小时窗口。

### Enrollment transaction

1. internal TLS 验 CA、IP SAN/SPKI；错误 cert fail closed；
2. token 只在内层 TLS 发送，日志/URL/telemetry 无 token；
3. CSR key、声明 key 与 Keystore PoP key 完全一致；
4. stable claim core 绑定 invite、request、record、intent opening、CSR 和 keys；每次 detached PoP
   另绑定 fresh server nonce/challenge 与 token commitment；
5. 同 claim core 可对新 server nonce 重签且仍返回相同 certificate/view artifact；
6. 同 token 不同 request/key/body 只有一个 CAS 成功；
7. 少数签名不能形成 admission QC；claim operation 的 `retry_not_after` 不等于 certified
   policy/Invite/admission 推导值时 reducer 拒绝；
8. leader 在 reservation、provisional issuance、approval、completion 各点崩溃均可恢复且不提前释放；
9. Invite expiry 后的新 admission/reservation 被拒绝；expiry 前已 certified reservation 可在
   `retry_not_after` 前用 exact resume 继续，但原 token 不能创建新 core；
10. capability 过期不能调用稳态 API；
11. Android private key 不可导出，卸载/清除数据后的身份恢复符合 policy；
12. Enrollment 成功后临时 tunnel、token/capability 被擦除。

### DNS、证书与公开 profile

1. 每个 active forward server 都有 FQDN；纯 control/use_loom Device 不被错误要求公网域名；
2. direct_standard 解析/443 正常；
3. direct_alternate 的明确 public HTTPS port 正常，客户端不默认 443；
4. nat_mapped 的 TCP/UDP public-local tuple 和 transport 正确；
5. DNS-01 不依赖 80；
6. provider credential 不能修改 zone 外记录或域名注册；
7. private key 节点本地生成，不进入 snapshot/distribution；
8. cert 续签先 old/new pin overlap；
9. DNS 正确但实际端口不可达时不 advertise；
10. Nginx 和 Trojan TCP tuple 冲突必须由独立端口或 L4 SNI 解决；
11. HY2/WG UDP tuple 冲突被 validator 拒绝；
12. direct server 不伪造 NAT mapping，NAT server 缺 mapping 不发布；
13. 三类 public Endpoint listener 只接受已认证的 `dial_target_fqdn`，IP literal 失败关闭。

### 轮换

1. prepare 未通过 local/external verify 不 advertise；
2. advertise 阶段新旧 generation 同时可拨；
3. prefer 后新连接使用新 listener，旧会话保持；
4. 新 view 不再选择 draining 代，但旧 view 的有界回退与既有会话可持续到 guard deadline；
5. deadline 后 retire，客户端不扫描邻近端口；
6. executor 重启/接管保持相同 operation/port；
7. NAT 在操作者预先提供的映射范围内轮换 Loom reservation，不修改网关；
8. 已提供映射的正常路径做真实外部验证；池耗尽、映射消失、range offset 错误用合成故障明确失败；
9. 紧急 revoke 明确中断而非伪称无中断；
10. WG 未实现双 interface/peer 前不能通过“无中断”验收；
11. 同 endpoint ID 的 old/new listener generation 可同时发布，但每代 state 唯一且可拨 endpoint 恰有一个
    preferred，retired/revoked/abandoned 只能以 tombstone 出现；
12. frozen dependency 任一 hash 在 rotation 中途改变都需 abandon/restart；retire 前仍有效的 catalog、
    Invite、capability、resume、Device view/LKG 引用，或 reader/drain/offline/backup guard 未满足均拒绝。

### 客户端与移动可靠性

1. Android、Windows、Linux 验同一 descriptor/catalog/QC vectors；
2. Android VPN permission、前台服务、protect、防回环和 Keystore 正常；
3. Wi-Fi 默认 Network/AP 变化创建新 network generation，旧代观测不污染新代；蜂窝与
   Wi-Fi 切换在独立 GitHub Issue #16 的具备 telephony 真机上验收，不阻塞 Wi-Fi 主矩阵；
4. Direct 不主动探测；Auto/指定出口复用同代 registry；
5. 锁屏、省电、进程回收、重启后恢复正式 LKG，不恢复 bootstrap token；
6. 固定出口只更换入口/listener generation，不偷偷更换最终出口；
7. DNS 在最终出口解析的既有数据面要求继续验收；
8. UDP 丢包、MTU、QUIC、TCP fallback 分别有真实流量验收；
9. 撤权后拒绝新 view/报告并按 policy 停止数据通道；
10. 覆盖升级保持 Device key、anti-rollback floor 和签名连续性。

### 运维、UI 与负面暴露

1. UI 分开显示 mirror、bootstrap ingress、private Enrollment/control 和 data endpoint；
2. read-only observation 不使用 Apply/切换文案；
3. public scan 只能发现 fake/static distribution 与已发布 data/bootstrap transport；
4. public HTTP path fuzz 无 claim/control/config/report handler；
5. private API 要求正确 admin/Device/control cert profile；
6. 日志和诊断包无 token、capability body、private key、真实拓扑；
7. 无 quorum 时 UI 明确只读/LKG，reconciler 不删旧资源；
8. safety checker 拒绝真实地址、域名、主机名、端口、指纹和指标进入仓库；
9. 历史文档不用于推断当前部署，目标设计不被声称已实现；
10. server 与当前 deployment inventory 中实际启用的平台 issue 都引用同一 milestone 与验收编号；
    未部署平台不构成虚假的关闭门禁。

---
