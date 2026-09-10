# 服务端开发环境：优化 Windows 加入等待

> **状态：v1 专项提示词。** 它优化单 registry、单 publisher 和严格 v1 Enrollment 的等待，
> 不定义目标 v2 的多 seed、quorum token CAS 或分布式 executor。v2 迁移必须另按
> [分布式控制平面设计](distributed-control-plane.md)实施，不能把本文的本地唤醒机制提升为
> 集群共识或长期 SSOT 权威。

将以下提示词交给**服务端开发环境**执行。Windows 环境只实现真实阶段与等待时长的
界面反馈；本提示词不表示服务端优化已实现或已部署。

---

请在 Loom 服务端开发环境优化 Windows Device 正常二维码加入的实际耗时。
先检查工作区和当前主分支，阅读 `CLAUDE.md`、`docs/design.md`、
`docs/windows-client-reporting.md` 以及当前加入、provision、publisher 实现。
只修改实现该优化所需的服务端代码、测试和文档，不修改 Windows 客户端或加入协议，
不手工修改 SSOT、registry、设备绑定或部署配置；完成后提交，不部署。

目标是去除加入关键路径上的空等和无效工作。不能通过提前返回 ready、减少验签、
放宽分发证据或把“已登记”显示成“已连接”来制造瞬间完成。

## 先核对现有瓶颈

以下是 v1 回归基线；开始修改前须先按 `docs/status/current.md` 与当前代码复核，不能把它当成完成状态：

1. `internal/report/clients.go` 的 claim 先绑定现有 Device，再同步调用 provision。
   `internal/report/client_provision.go` 的 `provision` 在保存 SSOT 前调用
   `installExistingNodeSecrets`，等待已有 Linux 节点的秘密安装完成。
   安装已并行，但未对所有 Linux 节点跳过内容不变的秘密层；网络操作位于配置锁内。
2. `internal/publish/run.go` 的常驻循环在一轮工作结束后再等待 `Options.Interval`，
   默认 30 秒。加入提交 SSOT 后可能等待轮询，也可能排在已有发布之后。
   不要把这种串行排队误称为“一次加入必然发布两次”。
3. `publishOnce` 对配置中的 VerifyURLs 顺序执行 `VerifyServed`，每个有独立超时；
   本轮 evidence 在后续 health 保存后才对加入路径可见。
4. `readyBootstrap` 要求 `verifiedEnrollmentDistributionURLs` 有与本次 SSOT 精确
   匹配的公开分发证据，并检查 release authority 的 snapshot，才签发证书并返回 ready。
   URL 选择器已经允许工作正常的分发备选，不能误改成“必须所有镜像都健康”。
   publisher 整体健康与单个加入可用的可信分发证据是两个现有判据。

先记录脱敏的分阶段耗时：claim、锁等待、秘密准备与安装、SSOT 提交、等待 publisher、
渲染/签名、制品推送、分发验证、ready 返回。现有日志不足以精确归因的阶段明确写
“未测得”；不得输出 token、CSR、证书、私钥或秘密正文。不要假定每轮都重传大二进制，
先核对现有内容寻址和缓存命中逻辑。

## 按最小改动优化

- 为 SSOT 成功提交后的 publisher 提供轻量本地唤醒，保留原有周期作为兜底。
  先确认 report 与 publisher 是否在不同进程，选能跨越实际进程边界的现有机制；
  不为此新增公开 HTTP 接口、消息队列或数据库。
  多次唤醒应合并；发布进行中有新提交时，结束后立即重读最新输入，不丢失通知。
  保留发布锁、锁后输入复核和 generation 单调约束，不在 claim 里再同步跑一遍完整发布。
- 对比当前与候选的每节点秘密内容，跳过不受影响的节点安装；只同步实际需要改变的节点。
  保留“必要秘密安装成功后才提交 SSOT”的边界。验证部分失败后的重试、原有非 Linux
  秘密更新限制及不同加入并发时的幂等性，不能只靠未验证的缓存断言远端已经就绪。
- 若实测确认镜像验证影响明显，将独立验证做有界并行，稳定收集结果，并保持失败镜像
  的诊断。若需要更早保存已验证备选的 evidence，必须证明 SSOT、snapshot、authority
  和发布事务一致，防止旧轮次或不同发布的证据混用；没有这一证明就保留现有保存边界。
- 只在上述耗时证据支持时进一步缩短锁内网络工作；不要直接把网络操作移出锁后裸写
  旧 SSOT。维持并发提交复核、失败可重入和现有权限边界。

复用 `202 pending` / `200 ready` 与既有相同身份重试。二维码仍为现有一次性凭据，
固定 `windows-desktop + use_loom`，不新增 enrollment schema、轮询端点或生命周期枚举。
本任务不修改上报：仍是原始 Observation、canonical v5 attest + self-check v1 两签；请求
`observations=1` 时成功响应可以是带有界原始 Observation 数组的 `200`，旧服务兼容空正文
`204`。空 `204` 只表示上报成功，不能冒充已经取得可复用观测。Windows 的 applied 仍只在
实际激活成功后推进。

## 验收与交付

- 用可控时钟/阻塞点测试唤醒：空闲即时响应、忙时合并且不丢最新提交、进程退出与
  周期兜底；避免以真实睡眠构造易抖动的时间断言。
- 测试无变化节点不安装、变化节点必须成功安装、失败不提交 SSOT、重试不重复创建设备
  或身份；覆盖两次加入并发及与普通 SSOT 编辑交错。
- 测试慢/坏镜像不串行拖累独立验证，同时拒绝错误 SSOT、旧 snapshot、不同 authority
  和未验证 URL。ready 必须仍来自完整可信 bootstrap。
- 运行相关测试、race、全仓 test/build/vet、修改文件 gofmt 和仓库安全扫描。
- 在获准的测试环境从正常有效二维码做加入对比，给出优化前后各阶段耗时及 ready、
  客户端激活、实际成功的 `200`（含可验证观测）或兼容 `204` 证据。不要求用户提供私钥、
  恢复旧身份目录或手工签报告。
  已正常加入的生产设备保持原身份；新加入实测使用测试环境正常流程提供的二维码。
- 报告提交号、修改文件、实测数据、未确认事项。未做生产端到端测试就明确标注；
  未获得部署授权时只交付代码。真实地址、设备 ID 与运行记录只放忽略的 `docs/status/`。
