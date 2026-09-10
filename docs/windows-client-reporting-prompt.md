# Windows 客户端上报实测提示词

> **用途：仅验收 v1 compatibility profile。** 本提示词固定了单 enrollment endpoint、同源 report URL、
> 平台公钥和既有两签 Observation，不可作为 v2 ControlSet/EndpointSet 的实现规范。
> 开始分布式迁移时应按独立 v2 issue 和
> [分布式控制平面设计](distributed-control-plane.md)执行；不得在此任务中顺手改变 wire schema。

请继续 Loom Windows 客户端的正常二维码加入与最小 NAT Device 状态上报验收。
先检查工作区状态，完整阅读 `docs/windows-client-reporting.md` 和
`clients/windows/README.md`，并遵守 `CLAUDE.md` 的执行边界。旧实现不覆盖用户新要求。

## 当前任务的硬约束

- 每个底层网络代维护跨 Agent/profile 重启的 probe registry；Direct 不探测，首次进入 Auto/指定
  出口时冻结当时的授权入口快照，按地址与源接口去重后各并行探测至多一次；同代切换/重连不重测，后段
  复用现有已验证服务器观测。
- 不做客户端整条业务路径探测、Service × 路径扫描、样本预热、挑战者比较或等待观测。
  不以后台健康验证、异步补样、兜底、旧 `min_samples` 或测试要求重新引入。
- 观测缺失保持未知，入口可达不能宣称业务全部可达；不要为健康绿灯生成额外探测。
  是否已完成替换只按 `docs/status/current.md` 核对；已替换时不得恢复旧完整路径 Agent。
- 验证目标、次数、并发与启动等待是否符合要求；完成独立修改后及时本地提交。

## 验收基线

代码、部署和实机证据只从 `docs/status/current.md` 读取，不在提示词复制完成状态。若当前
状态已有合法加入身份，应继续使用，不要求重新扫码、找私钥或恢复旧目录；若没有，才走
正常二维码流程。无论历史版本做过什么，本任务都不得恢复每轮业务目标或完整路径探测；
单个目标结果也不能概括所有网站和出口。

## 工作步骤

1. 先检查当前客户端是否已正常加入：已有成功提交的加入状态时，继续使用该客户端
   保存的 DPAPI 身份，不要求重新扫码。尚未加入时才使用当前状态所声明的 v1 compatibility control 正常流程提供的有效
   二维码导入；二维码失效按中控既有流程处理。私钥生成、证书验证和 DPAPI 保存
   全部由客户端自动完成；不要求用户找私钥、恢复旧目录或沿用历史绑定。
2. 启动真实客户端数据面，由现有 activation/recovery 成功路径提供 active snapshot。
   下载、验签、hydrate、preflight 和 candidate 都不能提前推进 `applied`。
3. 上报实机验收检查读取观测时的 `200` 或旧契约的空正文 `204`，从中控核对当前
   Device、`ts`、last-seen 和 `applied`。按本次改动选择相关验收，不为重复历史验收
   添加业务探测、重新加入或等待五分钟 stale；未取得实机证据就如实标注未验证。
4. 发现问题时沿该流程定位，只修改 Windows 客户端及必要的跨平台客户端包。
   不修改服务端源码、部署配置，也不手工修补 SSOT、registry、证书或设备绑定。
5. 若修改代码，运行相关测试、vet 和 Windows amd64/arm64 交叉编译，再提交。
   报告提交号、修改文件、实际测试证据与未确认事项；不部署服务端。

## 实现边界

- 排查“正在加入”耗时，按客户端显示的本地检查、联系中控、等待配置发布、验证并保存
  阶段区分原因。计时只用于反馈；`pending` 不能提前成为已加入、已连接或健康。
  服务端发布耗时的优化交给服务端开发环境，使用
  [加入耗时优化提示词](server-enrollment-latency-prompt.md)，不在 Windows 环境修改服务端。
- Windows 邀请只允许 `windows-desktop + use_loom`，由中控固定职责。客户端只声明
  Windows 平台，不提交 server 或职责字段，不迁移未消费的旧加入码。已加入身份继续
  使用；新二维码必须包含与发行包匹配的指纹和精确的 HTTPS `/loom-client/enroll` 入口。
- 复用最小 Observation：外层只有 `node`、`ts`、`applied`、`attest`、`self_check`。
- 只有 `attest.Claim` canonical v5 与 self-check v1 两份签名，使用客户端本次正常加入
  保存的同一身份；不生成 legacy Claim、`attest_extended` 或 self-check v2。
- 从已验证并保存的 enrollment URL 同源推导 report URL；HTTPS、精确路径、拒绝重定向。
  不使用 `POST /status`。摘要、共同时间戳与 HTTP 结果规则以接入说明为准。
- reporter 串行运行，UTC RFC3339Nano 时间严格递增。停止或无法恢复的退出后停止上报，
  由已有报告老化；不新增生命周期协议、睡眠或网络 watcher、复杂重试状态机。
- 健康结论只说明已有证据覆盖的范围，未知不能伪装成成功或失败。
  上报任务不授权新增业务探测，不新增未签名探测端点来制造绿灯。
- 排查 TUN 联网时，确认派生配置已绑定默认网卡，并将 TUN 的 DNS 请求交给签名
  DNS 模块；分别验证系统流量、TUN DNS 与本地代理。窗口显示已连接或进程存活
  不能替代实际连通性结果，手工访问成功也不应直接变成自动上报的健康证据。
- Windows 生产代码不依赖 `internal/report`。公网拒绝测试和手工报文不能替代正常
  客户端验收；网络诊断使用客户端实际传输方式与配置的 DNS。

真实端点、设备 ID 和实测记录只写入忽略的 `docs/status/`，不进入仓库示例。
