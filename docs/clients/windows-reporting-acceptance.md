# Windows v2 上报验收规程

用于本次明确涉及的 Windows 加入、配置同步或报告改动。先读[报告契约](windows-reporting.md)、
[构建入口](../../clients/windows/README.md)与[实现对照](../development/implementation.md)。
本规程不自行扩大部署范围；当前对话已有的迁移、发布授权继续有效。

## 准备

- 核对原生 Windows 主机、实际 exe/sidecar 与源码提交。跨平台编译不是 Windows 实测。
- 复用已有 Device 身份；存量升级经认证迁移，新设备才从正常 v2 二维码加入。
  不要求用户提供私钥，不清数据，不手工改 registry、Head、ACL 或设备绑定使验收通过。
- 私有配置来自 `.env` 及部署证据；真实设备、端点、证书和制品坐标只存忽略的
  `deploy/evidence/`。日志不得包含 bearer、完整证书、私钥或配置正文。
- 本次不增加业务路径探测；按[消费边界](observations.md#客户端消费边界)验证入口预算与同代复用。

## 正常流程

1. 从实际 GUI 导入中控生成的 v2 邀请；Installed 通过现有受限 broker。确认 capability 只到
   选定的 bootstrap ingress，claim 只在内层私有 TLS 提交，public Nginx 不收到动态 claim。
2. 确认同一 Device 的认证配置、证书、四组 floors 和 latch 已保存；仅 reservation/pending
   不算加入。需续传时使用管理员为原事务签发的 exact-bound resume，不能使用旧一小时恢复。
3. 连接并核对实际运行版本。配置候选先校验，再由正常激活流程生效；更新失败保留原可用版本。
4. 取得实际客户端自动生成的有效签名报告 **204**，再从控制面读取同一 Device 的持久序号、
   接收时间和当前健康正文。端口可达、无签名 403 和模拟 HTTP 请求均不算报告实测。
5. 按改动检查报告重试/重启、配置切换或撤权，确认不存在旧公开地址、旧序号覆盖和协议回退。
   缺失观测保持未知，不为让界面变绿追加网络测量。
6. 执行相关 Go 测试、vet 和 amd64/arm64 交叉编译；原生 CNG、DPAPI、TUN 与 UI 结果按实际
   测试平台记录。用 [原生驱动](../../scripts/test-windows-v2.ps1)记录与本次改动相关的检查。

## 交付判定

分别说明实现、接通、构建、发布与原生验收。可运行的 v2 reader、组件测试和新的 ZIP 不能
证明实际 Device 已使用 v2。未迁移的身份必须保留并明确记录缺口，不能回退到旧协议继续运行。

窗口显示连接或进程存活不证明业务流量成功；健康检查也不等同于端到端测量。
真实回执关联准确源码与制品；公开文档只保存契约、操作与源码入口。
