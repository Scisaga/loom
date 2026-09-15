# Windows v1 状态上报契约

**适用范围：** 尚在使用 v1 compatibility 身份的 Windows 客户端。本文保留仍有实现的协议契约，
不要求继续运行旧服务端。v2 使用 certified private `device_report`、Device mTLS 与 ControlSet/QC，
见[从当前实现迁移](../protocols/control-plane/migration.md#从当前实现迁移)，不能把 v2 字段加进严格 v1 JSON。
源码入口和接线缺口见[实现对照](../development/implementation.md)；实机流程见[验收规程](windows-reporting-acceptance.md)。

## 身份与正常入口

```text
有效 v1 二维码 → Windows 导入 → 客户端生成密钥并加入 → 验证并激活配置 → 自动上报
```

已有加入身份直接复用；仅未加入时从粘贴、文件选择或拖放二维码开始。客户端自动生成设备私钥、
验证节点证书，并用 DPAPI 保存，不要求用户提供私钥或恢复旧目录。过期或已消费的二维码通过
中控正常流程重新取得；不手工修改 registry、证书或设备绑定。

Windows 邀请固定为 `windows-desktop + use_loom`，职责由中控确定。客户端只声明平台，不发送
`server`、职责或旧 profile 字段。未消费的旧加入码不迁移；中控拒绝后结束本次加入，不重试旧协议。
已有身份不因邀请模型更新而被清除。

发送一次性凭据前校验精确 HTTPS `/loom-client/enroll` 和必需的 `platform_key_sha256`；无指纹
旧码失败关闭。二维码格式正确不表示邀请仍有效。加入过程的 `pending` 不表示已加入、连接或健康。

## 两类独立请求

[Windows reporter](../../clients/windows/report_windows.go) 与[presence worker](../../clients/windows/presence_windows.go)
使用同一 DPAPI P-256 身份，但生命周期、签名和结果互不替代。

| 项目 | 完整 Observation | 进程 presence |
|---|---|---|
| 触发条件 | 已加入且配置成功激活；随 active workload 停止 | 已注册的 Windows Loom 进程启动/停止；与连接和流量无关 |
| 周期 | 串行一分钟；activation/recovery 成功可触发一次串行报告 | 立即首包，随后五秒 |
| 查询 | helper 追加精确 `observations=1` | helper 追加精确 `presence=1` |
| 正文 | 最小 `node/ts/applied/attest/self_check` | 严格 `node/ts/signature` 三字段 |
| 成功响应 | 有界 `200 application/json` 原始 Observation 数组，兼容旧服空正文 `204` | 只接受空正文 `204` |
| 状态作用 | 完整观测与已激活配置证据 | 服务端接收时间起十五秒在线 lease |

端点来自已验证的 `clientenroll.PreparedIdentity.Endpoint`：必须为 HTTPS，无 userinfo/query/fragment，
path 精确为 `/loom-client/enroll`；仅将 path 同源替换成 `/loom-client/report`，不猜其他地址。
这是 v1 特有规则；v2 只能读取 certified service directory，不能从 enroll URL 推导 report。

HTTP 客户端拒绝重定向。Observation 不使用 Bearer token 或 mTLS，认证来自两份签名附件、
节点证书和 registry 当前 `ready` 身份的精确 SPKI；presence 根据 `node` 查同一身份，不重传证书。
日志不记录私钥、完整证书、正文或加入 token。

- 活动宿主调用 `clientreport.SendWithObservations`，由 helper 处理查询与响应边界。旧 `Send`
  helper 只接受无查询地址与空正文 `204`，不能只改 URL 就声称已读取观测。
- 200 正文损坏、超限或来源验签失败单独记录，不改写已经上报的本机健康。服务器观测的验证和
  Agent 消费只由[观测复用规范](observations.md)定义。
- 每类 worker 每 tick 只尝试一次；网络错误或失败状态等下个周期。Observation 尊重 `Retry-After`，
  不假定反代限流一定是 `429`。presence 不使用 Observation 的响应或重试兼容分支。
- 不记录第四个心跳字段，不把心跳装进 Observation，也不因心跳失败触发完整上报。

## 签名与状态坐标

完整报告串行构造严格递增的 UTC RFC3339Nano 时间。外层、canonical v5 Claim 和 self-check v1
使用相同 `node/ts`，外层和 v5 Claim 的 `applied` 相同；两签使用同一 P-256 key 和同一节点证书。
签名实现见[attest](../../internal/attest)，服务端入口见[client_report.go](../../internal/report/client_report.go)。

`applied` 只取最后成功激活的 snapshot：下载、验签、hydrate、preflight 或 candidate 不推进；
`activationManager.Replace`/recovery 成功后读 active spec，失败恢复 standby 后报告原 snapshot。
主动停止不发送空 `applied` 的报告，由既有完整报告老化；检查期间激活代次改变则取消旧结果。

完整 Observation 只有两份签名：

1. `attest.Claim{CanonicalVersion: 5, Node, TS, Applied, MeasurementsSHA256}` → `attest.Sign`。
2. `attest.SelfCheckClaim{Version: 1, Node, TS, Healthy, Problems}` → `attest.SignSelfCheck`。

最小报告省略 `attest_extended/version/components/rollout/agent/edges/targets/traffic/link_metrics`，
不生成 legacy Claim 或 self-check v2。`healthy == (len(problems) == 0)`；问题列表排序、去重，
满足既有长度与控制字符约束。增加附件时须按对应现行签名规范处理，不能扩写这个最小契约。

没有 WireGuard 测量时，省略 `edges/targets`，实际计算 `{"edges":null,"targets":null}` 的 SHA-256：

```text
474446bd582f00c7791db95c26a5327054c8925e5d0ca1fdee71eb05bbc337e4
```

它是 v5 Claim 的 `measurements_sha256`，不是第三份签名，也不能在生产构造器硬编码测试常量。

presence 用 `loom-presence-v1` 域和长度前缀后的 `node/ts` 生成 ASN.1 DER ECDSA 签名，
以无填充 base64 放入 `signature`。其时间戳单独串行递增；过期、旧或相同时间戳的包不能刷新
接收时间、完整 Observation 或列表。服务端验证边界见[presence.go](../../internal/report/presence.go)。

## 健康与选路边界

self-check 只描述已激活的本机配置、生命周期、实际 selector、本地代理监听和托管 TUN 网卡。
缺少配置、监听或网卡时报告具体问题；这些检查不请求业务目标。路径健康保持 unknown，入口单次
延迟和服务器分段估算不得包装成端到端实测。观测缺失、ICMP 无响应或服务器响应验签失败不能
直接变成设备整体故障。

客户端探测预算、网络代 registry 和观测消费统一遵守
[客户端消费边界](observations.md#客户端消费边界)。不再保留旧 Service 健康 URL、
整路径 DNS/TLS/HTTP 验证或为健康绿灯补样的条目。

## 修改时的必要验证

按本次变更选用对应检查，不为文档变更重跑实机流程：

- 最小两签报告进入 gossip table；缺 digest/self-check、混用身份、时间异常及篡改坐标被拒绝。
- Endpoint 精确校验、同源推导、重定向拒绝；DPAPI 身份在 token 清理后仍可上报。
- 空测量摘要向量、两签验签、严格递增时间与 activation/recovery 的 `applied` 绑定。
- `200` 观测读取/验签和旧 `204` 兼容，错误分层、限界读取及失败后不紧密重试。
- 本机正常、监听缺失及恢复的报告；确认采集不发送业务请求。
- 选路修改核对实际入口目标、次数、并发和启动等待，不能恢复已排除行为来满足旧测试。
- 已注册但未连接的进程仍立即并按周期发严格三字段心跳；篡改、夹带字段、撤销、重放和混合查询
  被拒绝；心跳与完整 Observation 不互相刷新或触发。
- Device inventory 在有效心跳到达及 lease 到期时更新；线上状态须同时满足当前平台的心跳与
  完整观测判定，不用进程心跳替代配置或健康证据。

真实验收必须取得客户端有效报告的 `200` 或旧契约 `204`，以及对应中控回读。
未签名请求的 `403` 只证明拒绝路径；细节按[验收规程](windows-reporting-acceptance.md)记录。
