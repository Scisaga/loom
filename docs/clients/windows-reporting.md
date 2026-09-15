# Windows v2 状态上报

Windows 正常加入、配置同步和报告均使用 v2。旧公开报告端点、从 Enrollment URL 推导报告地址、
Observation 发送、独立 v1 presence 发送及旧协议回退已从 Windows 宿主删除。
[实现对照](../development/implementation.md)列出源码与存量迁移缺口；
[验收规程](windows-reporting-acceptance.md)区分组件检查和原生实测。

## 正常入口与身份

```text
中控创建 Device → Windows 导入 v2 二维码 → 私有 Enrollment → 保存认证配置 → 连接 → 私有配置同步与报告
```

GUI、剪贴板、文件拖放和 Installed broker 使用同一个 carrier 解析与加入事务。Windows 邀请绑定
`windows-desktop + use_loom`；客户端不能自行更改职责、授权或创建另一个 Device。
首次加入生成非导出的 CNG P-256 身份与独立 wrapping key，DPAPI 保存密钥描述符和事务。
已有身份通过认证迁移保留，不能清空目录或重新生成身份绕过迁移。

报告只能读取已经验证的 Device view 中的 `ControlServiceDirectoryV1`，按 `device_report` role
选择精确 overlay IP、端口、证书 profile 与 pin。传输校验 internal service TLS 和 Device mTLS；
公网 distribution、bootstrap 和 Enrollment 地址不授权报告服务。Portable Mixed 经本地代理访问
overlay；TUN/Installed 使用已激活数据面。失败不触发旧公开 URL 回退。

## 运行、持久序号与响应

宿主的[控制循环](../../clients/windows/v2_runtime_windows.go)在配置成功激活后运行：

1. 先重放尚未得到成功响应的原报告；不能先推进配置 floors 使原 envelope 永久失效。
2. 从私有 `device_config` 获取并验证更新；验证候选数据面后原子保存，成功激活才采用新状态。
3. 检查当前实际数据面，构造 `health` schema 1 正文：`healthy` 与已激活的版本标识 `version`。
4. [durable reporter](../../internal/windowsv2/report_journal.go)先保存签名 envelope，再通过私有
   `device_report` 发送。当前成功契约为 **空正文 204**；重试使用同一个序号、正文与签名。

Envelope 绑定 Device、证书、当前认证状态和序号；服务端验证签名、证书授权、状态坐标及
序号持久化。相同序号只能重放原正文，不得覆盖成另一份报告。收到成功响应后才清理 pending。
实现与 wire 规则见[私有 Device 服务](../protocols/control-plane/device-services.md)。

报告生命周期属于活动宿主。退出/撤权后停止报告并按认证终态清理运行凭据；下载成功、
候选配置或本地进程存活不能冒充已经激活或健康。当前健康正文不包含 v1 Observation、
独立 presence、业务吞吐或 WireGuard 观测，不能把 204 解释为这些数据已采集。

## 健康和选路边界

健康检查只查看本机监听、托管 TUN 和实际 selector 等运行状态，不发送业务探测。
未知或过期服务器观测保持未知，不能变成健康成功，也不能直接判为本机故障。

选路始终遵守[客户端消费边界](observations.md#客户端消费边界)：同一底层网络代复用 registry，
Direct 不花预算，首次代理模式冻结入口并去重、并行、各至多一次。配置更新、报告或 profile
切换不授权重复探测、整路径扫描和启动等待。

## 修改时验证

- 普通二维码/文件/剪贴板/Installed broker 拒绝旧 v1 输入；损坏 v2 不回退。
- 私有目录 role、IP、pin、证书和 Device mTLS 不匹配时失败；禁止从公开 URL 推导端点。
- 签名报告的真实 204、持久序号与重启后 exact 重放；相同序号篡改正文失败。
- 更新/激活失败保留已验证配置；健康来自实际运行版本，撤权终态停止运行与上报。
- 未签名请求 403、端口连通和交叉编译不能替代正常报告与控制面回读。
