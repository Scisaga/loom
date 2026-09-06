# Windows 客户端上报实测提示词

请继续 Loom Windows 客户端的正常二维码加入与最小 NAT Device 状态上报验收。
先检查工作区状态，完整阅读 `docs/windows-client-reporting.md` 和
`clients/windows/README.md`，按当前仓库实现工作。

## 当前基线

- 服务端上报适配器已实现并上线，客户端最小两签 producer 已提交。
- 本地 Windows 原生测试已覆盖二维码加入、DPAPI、真实 Portable Mixed 进程激活、
  两签报告及空正文 `204`；单元测试、race、build、vet 和双架构交叉编译已有结果。
- 已正常扫码加入的 Windows amd64 客户端已完成真实 TUN 探测，自动报告得到 `204`，
  中控收到递增的两签健康与配置证据。停止后五分钟 stale 已由真实停止与中控页面验收。
  继续使用当前已加入客户端，不要求重新扫码、找私钥或恢复旧身份目录。
- Windows 已接入与 active 绑定的每轮代表性探测。Mixed 经过 1080；TUN/Installed
  检查接管与实际 IPv4 DNS/HTTPS。只有当轮成功才报告 healthy=true；缺目标和探测
  失败均明确报告 false。此结论不覆盖所有网站和出口。

## 工作步骤

1. 先检查当前客户端是否已正常加入：已有成功提交的加入状态时，继续使用该客户端
   保存的 DPAPI 身份，不要求重新扫码。尚未加入时才使用中控正常流程提供的有效
   二维码导入；二维码失效按中控既有流程处理。私钥生成、证书验证和 DPAPI 保存
   全部由客户端自动完成；不要求用户找私钥、恢复旧目录或沿用历史绑定。
2. 启动真实客户端数据面，由现有 activation/recovery 成功路径提供 active snapshot。
   下载、验签、hydrate、preflight 和 candidate 都不能提前推进 `applied`。
3. 验证客户端自动上报空正文 `204`，并从中控核对本次加入的 Device、`ts`、last-seen
   和 `applied`。检查 60 秒周期更新和健康→失败→恢复；再停止客户端并验证停止更新及五分钟 stale。
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
- 健康结论必须有真实数据面及代表性端到端证据；不新增未签名探测端点来制造绿灯。
- 排查 TUN 联网时，确认派生配置已绑定默认网卡，并将 TUN 的 DNS 请求交给签名
  DNS 模块；分别验证系统流量、TUN DNS 与本地代理。窗口显示已连接或进程存活
  不能替代实际连通性结果，手工访问成功也不应直接变成自动上报的健康证据。
- Windows 生产代码不依赖 `internal/report`。公网拒绝测试和手工报文不能替代正常
  客户端验收；网络诊断使用客户端实际传输方式与配置的 DNS。

真实端点、设备 ID 和实测记录只写入忽略的 `docs/status/`，不进入仓库示例。
