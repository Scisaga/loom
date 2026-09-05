# Windows NAT Device 状态上报接入说明

> **状态：** 服务端传输适配器已上线，Windows producer 待接入
> **边界：** 复用现有 `report.Observation`、`loom-attest-v5` 和
> `loom-selfcheck-v1`；不新增状态协议、envelope、心跳格式或 self-check v2。

## 1. 最小目标

Windows 客户端在加入完成、首轮 signed pull 验证且数据面成功激活后，每 60 秒向
当前生产 enrollment URL 的同源 report 路径提交自身 Observation。服务端验签后写入
既有 gossip table，中控继续复用原有健康与配置版本判定。

首版只提交：

- 外层 `node`、`ts`、`applied`；
- 主签名 `attest`，直接使用 canonical v5；
- 独立的 `self_check` v1。

`measurements_sha256` 是 v5 Claim 内的摘要字段，不是第三份签名。首版省略
`attest_extended`、`version`、`components`、`rollout`、`agent`、`edges`、`targets`、
`traffic` 和 `link_metrics`。

## 2. 端点与 HTTP

端点来自 DPAPI 保护的 `clientenroll.PreparedIdentity.Endpoint`。本次生产部署的已验证
约定是：只接受 `https`、无 userinfo/query/fragment 且 path 为
`/loom-client/enroll`，保持 scheme、host、port 不变，将 path 替换为
`/loom-client/report`。这是当前生产部署约定，不是任意 Loom enrollment URL 都天然
具备的通用推导规则；不匹配时 fail closed，不猜测其他地址。

```text
POST https://<current-production-host>/loom-client/report
Content-Type: application/json

<raw Observation JSON>
```

不使用 Bearer token 或 mTLS。认证来自两份签名附件中的节点证书和签名，以及服务端
registry 中 `ready` enrollment 身份的精确 SPKI 绑定。HTTP 客户端拒绝重定向，不记录
私钥、完整证书、正文或加入 token。

只有空正文的 `204` 表示成功。首版每个 60 秒 tick 只尝试一次；网络错误、`429`、
`5xx` 或其他非 `204` 响应只做脱敏日志并等待后续 tick。若响应携带 `Retry-After`，不得
在其到期前重试。当前反代限流默认可能返回 `503`，不能假设一定是 `429`。

## 3. 报文与签名

每轮生成一份 UTC、严格晚于上一份成功构造报告的 RFC3339Nano 时间。外层 Observation、
v5 Claim 和 self-check 必须使用完全相同的 `node` 与 `ts`；外层和 v5 Claim 的
`applied` 也必须完全相同。报告构造与发送必须串行，避免同一时间戳的第二份状态被既有
gossip 排序规则忽略。

`applied` 表示最后一次成功激活的配置 snapshot：

- candidate 仅完成下载、验签、hydrate 或 preflight 时不得推进；
- `activationManager.Replace` 或恢复成功后，取实际 active spec 的 snapshot；
- 更新失败并恢复 standby 后，使用恢复后的旧 snapshot；
- 不发送“主动停止后 applied 为空”的报告。首版 reporter 随已激活 workload 停止，
  随后由既有报告老化为 stale。

没有 WireGuard 测量时，省略 `edges` 和 `targets`。它们反序列化为 `nil`，v5 Claim 的
`measurements_sha256` 必须实际计算以下 JSON 的 SHA-256，而不是硬编码测试常量：

```json
{"edges":null,"targets":null}
```

测试向量：

```text
474446bd582f00c7791db95c26a5327054c8925e5d0ca1fdee71eb05bbc337e4
```

签名步骤只有两步：

1. 构造 `attest.Claim{CanonicalVersion: 5, Node, TS, Applied,
   MeasurementsSHA256}`，调用 `attest.Sign`，结果写入外层 `attest`；
2. 构造 `attest.SelfCheckClaim{Version: 1, Node, TS, Healthy, Problems}`，调用
   `attest.SignSelfCheck`，结果写入外层 `self_check`。

两份附件必须使用 DPAPI 身份中的同一 P-256 私钥和加入后保存的同一节点证书。不得生成
legacy Claim，不得携带 `attest_extended`。`healthy` 必须等于
`len(problems) == 0`；问题列表继续遵守既有排序、去重、长度和控制字符约束。

脱敏的最小结构如下；占位签名不可发送：

```json
{
  "node": "demo-windows",
  "ts": "2026-09-05T12:34:56.1234567Z",
  "applied": "<successfully-activated-snapshot>",
  "attest": {
    "canonical_version": 5,
    "node": "demo-windows",
    "ts": "2026-09-05T12:34:56.1234567Z",
    "applied": "<successfully-activated-snapshot>",
    "measurements_sha256": "474446bd582f00c7791db95c26a5327054c8925e5d0ca1fdee71eb05bbc337e4",
    "cert": "<node-certificate-pem>",
    "sig": "<base64-ecdsa-asn1-signature>"
  },
  "self_check": {
    "version": 1,
    "node": "demo-windows",
    "ts": "2026-09-05T12:34:56.1234567Z",
    "healthy": true,
    "cert": "<same-node-certificate-pem>",
    "sig": "<base64-ecdsa-asn1-signature>"
  }
}
```

## 4. 健康与生命周期边界

服务端验证 self-check 的身份、签名、时间和 `healthy/problems` 内部一致性，但不会替
客户端证明数据平面确实健康。客户端只能从真实运行态生成 verdict；进程存在、bundle
验签成功、candidate 已提交或启动宽限期通过，任何一个都不能单独证明端到端健康。

现有协议没有 Starting、Stopped 或 Exited 枚举。首版不新增枚举，也不实现睡眠/网络
Win32 watcher：

- 成功激活并通过既有健康判定后周期报告；
- activation/recovery 成功可以额外触发一次串行报告；
- replacement 进行中继续保留上一份成功报告，不抢先推进 `applied`；
- 主动停止、无法恢复的异常退出或整个宿主退出后不再产生报告，由旧 Observation 在
  5 分钟后显示 stale；
- 如果客户端尚不能获得上位设计要求的代表性端到端健康证据，就不得报告
  `healthy=true`，也不得为达成绿灯发明未签名探测端点。

## 5. 最小验收

服务端契约测试至少覆盖：

- `attest=canonical v5`、无 `attest_extended`、带 self-check 的最小报告返回 `204`
  并进入 gossip table；
- 缺 measurement digest、缺 self-check、混用身份、过期/未来时间和篡改
  node/ts/applied 均被拒绝。

Windows 侧至少覆盖：

- 从当前生产 enrollment URL 得到同源 report URL，并拒绝重定向；
- DPAPI 身份在 invite token 清理后仍可取得 Endpoint、私钥和节点证书；
- 空 measurement digest 测试向量；
- 两签验签以及 node/ts/applied 篡改失败；
- 串行、严格递增时间戳；candidate 未激活不推进 applied，成功恢复报告旧 snapshot；
- `204` 成功，其他结果不紧密重试且日志脱敏。

生产验收只使用已有 Windows Device：成功报告后一个刷新周期内 last-seen 更新；真实健康
时显示 Online；非空 `applied` 补齐配置版本证据，并且只有与当前生产 snapshot 相同才
表示配置已收敛。不创建测试设备，不修改 SSOT 或 registry。
