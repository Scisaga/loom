# 外部副作用、租约与 UI/API

[文档地图](../../README.md) · [架构入口](../../architecture/README.md) · [控制面规范](README.md) · [实现对照](../../development/implementation.md) · [本机部署信息](../../operations/local-deployment.md)

**规范状态：已批准的 v2 目标协议。** 实现、接通、部署、验收须分别核对；本文不证明当前源码或生产已经具备所列能力。

---

## 外部副作用与租约

DNS、ACME、listener、防火墙和 publisher 都是 certified desired state 的幂等 reconciler，不是
authority。NAT mapping 是操作者提供的外部事实，Loom 的 reconciler 只对其 private intent、
reservation 与外部 readback/evidence 收敛，不调用网关/provider 写接口。每类受管资源按
resource_id + generation 获取短租约；租约绑定 Raft term/index、certified head 和有界 deadline。

执行规则：

1. 只有持当前租约且已验证 head/QC 的 executor 能创建/修改外部资源；
2. provider 支持 CAS 时必须使用；不支持时用 deterministic ownership tag 和 generation fencing；
3. 超过时钟安全截止立即停止发新请求；
4. 接管者先 read-after-write 观察，再继续未完成步骤；
5. 外部失败写 observation/status，不反向生成另一份 SSOT；
6. 删除动作必须晚于 reader propagation floor、drain deadline 和 backup retention；
7. public Nginx 配置检查必须证明不存在动态 Enrollment/control/config/report route。

执行顺序必须尊重依赖：

~~~text
DNS 写入 / 操作者提供的 mapping intent 与外部 readback 就绪
  → 证书签发
  → local listener install
  → firewall least privilege
  → external verify
  → EndpointSet advertise
  → client floor
  → prefer/drain/retire
  → 回收旧证书、listener 与 Loom mapping reservation（不改网关）
~~~

ControlSet 失去 quorum 时，不创建新端点、不轮换证书、不删除旧 listener；已有数据面和未过期
LKG 继续运行。证书临近到期但无 quorum 是显式告警，不能让单 executor 绕过 QC 续写 authority。

---

## UI 与 API

UI 是模型的投影，必须把以下状态分开：

- **ControlSet**：成员数、quorum、leader、certified head、replication freshness；只显示 private
  overlay 服务，不出现“公网中控地址”；
- **Server public access**：FQDN、direct/alternate/NAT、DNS/cert 状态、Nginx distribution、
  HY2/WG/Trojan listener 与 mapping generation；
- **Distribution**：镜像可达性、artifact hash、复制进度；不得显示 claim 请求或 token；
- **Enrollment**：Invite committed/QC、capability 期限、bootstrap ingress、private service、
  reserve/consumed 状态；不把 Nginx mirror 标为 Enrollment server；
- **Device**：正式身份、配置 view、报告新鲜度和 LKG；
- **Rotation**：prepare/verified/advertised/preferred/draining/retired 的每代证据。

管理 API 仅在 private control_api 上接受 admin mTLS。浏览器 UI 也只由该 private HTTPS tuple 提供：
未提交客户端证书时只能读取脱敏状态，只有当前 certified Admin ACL 精确授权且仍有效的 leaf 才能
进入配置处理器；不得以 UI 密码、Cookie 或调用方可伪造的 HTTP header 提权。用于验证服务端的
internal CA 公共证书与包含 admin leaf/private key 的 PKCS#12 客户端身份必须分开，任何 Root CA
私钥都不得导入浏览器。写操作必须携 expected head 与 request ID，成功响应只返回已取得 QC 的结果。
公开 Nginx 没有管理 API。UI 中“测试 mirror”只测试静态下载；
“测试 bootstrap”必须测试真实 HY2/Trojan transport；“测试 Enrollment”在不发送 token 的前提下
完成外层 tunnel 和内层 server TLS，不能用普通 HTTPS GET 冒充。

管理端创建预览可从 private intent 显示 expiry、目标 Device intent、mirror 数与 transport 支持；
未入网客户端在 inner-TLS preflight 前只能显示 expiry、mirror/transport 和 opaque commitment，
验过 opening 后才显示 exact intent 并要求确认。不得把 bearer token、capability 原文写进日志、
DOM telemetry、截图诊断或分析事件。诊断导出默认脱敏 public host、
端口、capability ID 和 Device identity。

---
