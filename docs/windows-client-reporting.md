# Windows NAT Device 状态上报接入说明

> **状态：** 服务端传输适配器已实现，Windows producer 待接入  
> **上位约束：** [设计文档](design.md)、[客户端接入设计](client-access.md)与
> [D98](decisions.md#d98--nat-device-只新增-observation-传输适配器不新增状态协议)

本文是 Windows 客户端的实现交接，不定义新状态协议。客户端继续生成既有
`report.Observation`、`loom-attest-v5` 与 `loom-selfcheck-v1`，只增加适合 NAT Device
的 HTTPS 出站传输。服务端入口见
[`internal/report/client_report.go`](../internal/report/client_report.go)，既有签名绑定见
[`internal/report/attestation.go`](../internal/report/attestation.go)。

## 1. 交付目标与边界

Windows 客户端在加入完成并验证首轮 signed pull 后，周期生成自身状态，向加入入口
的同源 report 路径提交。服务端验签后把 Observation 写入既有 gossip table，后续
`/status` 转述、中控健康与配置版本证据不建立第二套逻辑。

客户端不得：

- 上传完整 `Status` 或 `learned`；
- 把 `POST /status` 当成上传协议；
- 新增 envelope、心跳格式、生命周期枚举或 self-check v2；
- 在没有 WireGuard 测量时伪造邻居、流量或链路状态；
- 修改 SSOT、设备 registry 或加入协议。

## 2. 端点与 HTTP 约定

从 DPAPI 解密后的 `clientenroll.PreparedIdentity.Endpoint` 取得已验证的 enrollment URL。
只接受 `https`、无 userinfo/query/fragment 且 path 精确为 `/loom-client/enroll` 的 URL，
然后保持 scheme、host 和 port 不变，将 path 精确替换为 `/loom-client/report`。例如：

```text
https://control.example/loom-client/enroll
→ https://control.example/loom-client/report
```

不得从 HTTP Host、未签名配置或内部节点地址猜测入口；HTTP 客户端应拒绝重定向。
加入 token 清理后仍须保留 DPAPI 保护的 `PreparedIdentity`，不能要求重新扫码。

请求约定：

```text
POST /loom-client/report
Content-Type: application/json

<raw Observation JSON>
```

正文上限为 1 MiB。认证不使用 Bearer token 或 mTLS，而由正文签名携带的节点证书、
签名以及服务端 registry 中当前 ready enrollment SPKI 共同完成。只有空正文的 `204`
算成功。`400/403/405/413/415` 表示构造、身份或协议错误，不应紧密重试；`429` 尊重
`Retry-After`；网络错误和 `5xx` 使用带 jitter 的有上限指数退避，并重新采集和签名，
不得持久化旧报告反复重放。日志不得输出私钥、完整证书、正文或加入 token。

## 3. Windows 代码边界与状态来源

Windows 生产代码不要 import `internal/report`：该包的传递依赖包含 Linux syscall。
应新增平台无关的客户端 wire/builder 包（例如 `internal/clientreport`），复用跨平台的
`internal/attest` 签名实现，并定义与 `report.Observation` JSON 兼容的最小结构。

每轮只生成一个 UTC RFC3339 秒级时间；外层 Observation、两份 Claim 和 self-check
必须使用完全相同的 `node` 与 `ts`。

状态必须来自真实运行态：

- `node` 来自已加入配置的 NodeID；
- `applied` 来自当前真正运行成功的
  `activationManager.active.spec.Version.Snapshot`，且只能在现有启动宽限期通过后报告；
- 新 candidate 只完成拉取或预检时，不能提前成为 `applied`；
- 回滚/恢复 standby 后，报告实际恢复的旧 snapshot；
- `version` 使用 Windows Loom host 的实际 `version.Self()`；
- `components` 至少报告 `sing-box`：`expected` 来自签名 candidate，`actual` 来自
  active slot 的真实运行制品；失败时保留脱敏 `error` 并判为不健康。

不要无锁读取 `manager.active`。由串行 update loop、只读快照方法或状态事件回调提供
一致视图，并让报告 worker 独立于 sing-box 子进程存活。

当前没有 WireGuard 邻居测量时，省略 `edges`、`targets`、`traffic`、`link_metrics` 和
`agent`。零长度 edges/targets 在摘要计算时必须归一为 `nil`，对固定 JSON
`{"edges":null,"targets":null}` 做 SHA-256 并输出小写 hex；预期测试向量为：

```text
474446bd582f00c7791db95c26a5327054c8925e5d0ca1fdee71eb05bbc337e4
```

实现必须实际计算摘要，不能只返回测试常量。

## 4. v5、兼容签名与 self-check

构造 current `attest.Claim`：

- `CanonicalVersion=5`；
- `Node`、`TS`、`Applied` 与外层完全相同；
- 将外层 `version` 展开为 Claim 的版本坐标；
- `Components` 与外层完全相同；
- `MeasurementsSHA256` 绑定外层 edges/targets。

再从 current 构造 legacy Claim：`CanonicalVersion=0`、`Components=nil`，其余绑定字段和
measurement digest 保留。若以后加入 Agent，legacy 投影还必须删除
`Agent.ComponentVersion` 和每个 selection 的 `Health`。

使用 DPAPI 保护的同一设备私钥与加入后的节点证书：

1. `attest.Sign(legacy, keyPEM, certPEM)` 写入 `attest`；
2. `attest.Sign(current, keyPEM, certPEM)` 写入 `attest_extended`；
3. `attest.SignSelfCheck(...)` 写入 `self_check`。

不能把 v5 主签名写入 `attest` 后再附加 `attest_extended`。所有签名附件必须使用同一个
ECDSA P-256 身份。self-check 固定 `version=1`，其 `node/ts` 与 Observation 相同，且
`healthy == (len(problems) == 0)`。`problems` 必须排序、去重、无控制字符；最多 64 条，
单条最多 512 bytes，总计最多 16 KiB。

脱敏结构示例（不是可发送的有效签名）：

```json
{
  "node": "demo-windows",
  "ts": "2026-01-01T00:00:00Z",
  "applied": "<active-snapshot>",
  "version": {
    "commit": "<commit>",
    "binary": "<binary-sha256>",
    "go": "go1.x",
    "platform": "windows/amd64"
  },
  "components": [
    {"name": "sing-box", "expected": "<expected>", "actual": "<actual>"}
  ],
  "self_check": {
    "version": 1,
    "node": "demo-windows",
    "ts": "2026-01-01T00:00:00Z",
    "healthy": true,
    "cert": "<same-node-certificate-pem>",
    "sig": "<base64-ecdsa-asn1-signature>"
  },
  "attest": {
    "node": "demo-windows",
    "ts": "2026-01-01T00:00:00Z",
    "applied": "<active-snapshot>",
    "measurements_sha256": "474446bd582f00c7791db95c26a5327054c8925e5d0ca1fdee71eb05bbc337e4",
    "cert": "<same-node-certificate-pem>",
    "sig": "<base64-ecdsa-asn1-signature>"
  },
  "attest_extended": {
    "canonical_version": 5,
    "node": "demo-windows",
    "ts": "2026-01-01T00:00:00Z",
    "applied": "<active-snapshot>",
    "components": [
      {"name": "sing-box", "expected": "<expected>", "actual": "<actual>"}
    ],
    "measurements_sha256": "474446bd582f00c7791db95c26a5327054c8925e5d0ca1fdee71eb05bbc337e4",
    "cert": "<same-node-certificate-pem>",
    "sig": "<base64-ecdsa-asn1-signature>"
  }
}
```

实际实现中，如果外层携带 `version`，两份 Claim 也必须携带完全一致的展开版本坐标；
示例为突出结构而省略了这部分重复字段。

## 5. 生命周期映射

现有协议没有独立的 Starting/Stopped/Exited 枚举：

| 本地状态 | 既有协议表达 |
|---|---|
| 整个客户端未运行 | 无法上报；旧 Observation 自然过期 |
| 数据面启动中 | `healthy=false`，problem 为“Windows 数据面启动中”；没有 active 时 `applied` 为空 |
| 正常运行 | 启动宽限期通过、active snapshot 和组件核验均成功后才可 `healthy=true` |
| 用户主动停止数据面 | reporter 存活时 `healthy=false`，problem 为“Windows 数据面已由用户停止” |
| sing-box 异常退出 | supervisor 存活时立即报告脱敏问题；整个宿主退出则由旧报告过期表达 |
| 回滚成功 | 报告恢复后的实际 snapshot、组件版本和健康状态 |

不能用 rollout 冒充进程生命周期。组件预期/实际不一致或探测失败时，保留 component
证据并让 self-check 不健康。

## 6. 调度与验收

加入完成、ready bootstrap 与首轮 signed pull 通过后启动 reporter。正常周期为 60 秒；
activation 成功、回滚/恢复、sing-box 启停或异常退出、用户停止/恢复、系统睡眠恢复和
网络恢复时立即触发一次。每次都重新取得一致状态、生成时间和签名。

至少覆盖以下自动测试：

- enrollment URL 的同源精确替换，以及 HTTP、错误 path、userinfo、query、fragment、
  redirect 的拒绝；
- DPAPI 身份在 invite token 清理后仍能提供 Endpoint；
- 空 measurement digest 的确定性；
- v5、legacy 与 self-check v1 验签；篡改 node/ts/applied/components/measurements 后失败；
- 缺 self-check、混用证书、陈述过期或超过两分钟未来偏差时失败；
- 初次启动、运行、更新、回滚、主动停止和子进程异常退出均不会虚报健康或 snapshot；
- HTTP `204`、重定向、`400/403/413/415/429/5xx` 分类及退避；
- 相关 package 的 race test、vet，以及全部 Windows edition 的 amd64/arm64 交叉编译。

如需用服务端 verifier 做契约测试，只能放在 `//go:build !windows` 的外部测试包；Windows
生产依赖图仍不得引入 `internal/report`。

使用现有已加入 Device 做生产验收：客户端只记录脱敏的 `204` 结果；一个状态刷新周期内
中控应出现新 last-seen。真实运行且 self-check 健康时显示正常；`applied` 非空会补齐配置
版本证据，只有它与当前生产 snapshot 一致时才表示收敛。停止数据面应显示问题，退出宿主
或断网后应随旧报告老化为离线。
