# Windows NAT Device 状态上报接入说明

> **协议代次：v1 compatibility。** 本文的同源 `/loom-client/enroll` → `/loom-client/report`、单
> enrollment endpoint、平台公钥和 `200/204` 契约描述现行兼容路径，不是分布式目标协议。
> v2 使用 certified private `ControlServiceDirectoryV1` 中 overlay-only `device_report` 服务、
> Device mTLS、ControlSet checkpoint/QC 和独立 versioned resource；不得把 v2 字段加入本文严格的 v1 JSON。迁移见
> [分布式控制平面设计 §19](distributed-control-plane.md#19-从当前实现迁移)。

> **需求优先级：** 本文保留既有协议与历史验收说明。当前客户端选路遵守
> [执行边界](../CLAUDE.md#执行边界与客户端选路约束)：入口单次并行探测，后段复用
> 服务器观测。下文旧端到端健康采集与验收条目，不授权保留或新增客户端整路径探测。

> **稳定契约：** Windows 保留两签 producer；本机检查不请求业务目标，选路使用
> 入口单次并行 ping 与服务器观测复用。最新测试和部署情况见忽略目录的当前状态。
> **边界：** 复用现有 `report.Observation`、`loom-attest-v5` 和
> `loom-selfcheck-v1`；不新增状态协议、envelope、心跳格式或 self-check v2。
>
> **读取契约：** 活动宿主在同一报告周期使用 `SendWithObservations` 请求
> `observations=1`，成功接受 `200` 的有界原始 Observation 数组，也兼容旧服务器的空正文
> `204`。来源与测量独立验签后进入 Agent 的剪枝缓存；规则见
> [观测复用说明](client-observation-reuse.md)。

## 给 Windows 客户端仓库的简短提示词

```text
遵守 CLAUDE.md 的执行边界：客户端只补入口单次并行探测，后段复用服务器观测；
不要因健康上报、旧测试或 min_samples 重新加入整条业务路径探测。
只修改 Loom Windows 客户端：在已加入且成功激活配置后，从 DPAPI 身份的已验证
PreparedIdentity.Endpoint 精确要求 /loom-client/enroll，并同源替换为 /loom-client/report；
每 60 秒 POST 现有 report.Observation 原始 JSON，并以 observations=1 请求服务器观测。
成功接受200原始Observation数组或旧服空正文204；观测响应错误与设备健康分开。
复用现有 canonical v5 attest 和 self-check v1：
两份附件使用同一 P-256 设备私钥/节点证书，node/ts 必须一致，applied 绑定最后成功激活
的 snapshot；无 WG 测量时省略 edges/targets，并按 {"edges":null,"targets":null} 计算
measurements_sha256。串行生成严格递增 UTC 时间，拒绝重定向，失败等待下一周期且日志脱敏。
不要新增 envelope、第三份签名、心跳协议、self-check v2 或服务端改动。Windows 邀请固定为
windows-desktop + use_loom；已加入身份继续使用，仅未消费的旧加入码失效并需由中控重新创建。
按本文“最小验收”补测试。
```

## 1. 最小目标

Windows 客户端在加入完成、首轮 signed pull 验证且数据面成功激活后，每 60 秒向
v1 enrollment URL 的同源 report 路径提交自身 Observation。服务端验签后写入
既有 gossip table，中控继续复用原有健康与配置版本判定。

用户操作流程始终是：

```text
v1 compatibility control 提供有效加入二维码 → Windows 导入二维码 → 加入网络 → 启动数据面 → 自动上报
```

二维码是一次性加入凭据。客户端在加入过程中自动生成设备私钥、验证 v1 compatibility control 返回的节点
证书，并用 DPAPI 保存身份；此后上报直接复用这份身份。用户不需要准备、查找、导入或
备份私钥，也不需要手工构造签名报告。未加入的客户端从二维码开始，不把恢复旧目录或
沿用旧设备身份作为测试前提。二维码过期或已使用时，按中控现有的重新生成或重新加入
流程取得有效二维码；客户端仍走同一个加入入口。

Windows 邀请固定为 `windows-desktop + use_loom`，职责由中控创建邀请时确定；客户端
只声明 `windows-desktop`，不提交 `server`、职责或旧的 profile 字段。未消费的旧加入码
由 v1 compatibility control 作废，客户端收到拒绝后直接结束本次加入，不变更平台或尝试旧协议。已加入的
DPAPI 身份继续使用，不因邀请模型更新而清除或要求重新加入。

导入新二维码时，Windows 在发送一次性凭据前校验精确的 HTTPS `/loom-client/enroll`
入口及必需的 `platform_key_sha256`；缺失指纹的旧码不再走兼容分支。中控对加入码是否
仍有效保有最终判断权，不能仅凭二维码格式或指纹认定旧码有效。

首版只提交：

- 外层 `node`、`ts`、`applied`；
- 主签名 `attest`，直接使用 canonical v5；
- 独立的 `self_check` v1。

`measurements_sha256` 是 v5 Claim 内的摘要字段，不是第三份签名。首版省略
`attest_extended`、`version`、`components`、`rollout`、`agent`、`edges`、`targets`、
`traffic` 和 `link_metrics`。

## 2. 端点与 HTTP

端点来自 DPAPI 保护的 `clientenroll.PreparedIdentity.Endpoint`。v1 部署契约是：只接受
`https`、无 userinfo/query/fragment 且 path 为
`/loom-client/enroll`，保持 scheme、host、port 不变，将 path 替换为
`/loom-client/report`。这是 v1 兼容约定，不是任意 Loom enrollment URL 都天然
具备的通用推导规则；不匹配时 fail closed，不猜测其他地址。

目标 v2 明确禁止继续从 enroll URL 猜 report URL：客户端只使用 certified private
`ControlServiceDirectoryV1` 中的 `device_report` 条目，核对 overlay IP、internal CA/EKU 和
Device mTLS policy；在同 role 私有服务间故障切换，不依赖公网 DNS/WebPKI，也不把 HTTP
重定向当作新 authority。

```text
POST https://report.demo-node.example/loom-client/report?observations=1
Content-Type: application/json

<raw Observation JSON>
```

不使用 Bearer token 或 mTLS。认证来自两份签名附件中的节点证书和签名，以及服务端
registry 中 `ready` enrollment 身份的精确 SPKI 绑定。HTTP 客户端拒绝重定向，不记录
私钥、完整证书、正文或加入 token。

读取模式接受 `200 application/json` 的完整数组，旧服务器的空正文 `204` 也表示
上报成功。200 观测正文损坏、过大或验签失败会单独记录，不改变已上报的设备健康。
每个 60 秒 tick 只尝试一次；网络错误、`429`、`5xx` 或其他状态只做脱敏日志并等待后续 tick。
若响应携带 `Retry-After`，不得
在其到期前重试。当前反代限流默认可能返回 `503`，不能假设一定是 `429`。

`clientreport.Send` 是保留给不读取观测的 legacy producer helper：它拒绝带查询的地址且只
接受空正文 `204`。需要观测的活动宿主必须调用 `SendWithObservations`，由 helper 自己追加
精确 `observations=1` 并处理有界 `200`/兼容 `204`；调用方不能给配置 URL 手工追加 query，
也不能只改 URL 就声称已经验证并复用了服务端观测。接口见
[客户端观测复用说明](client-observation-reuse.md)。

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
    "healthy": false,
    "problems": ["本地代理监听未就绪"],
    "cert": "<same-node-certificate-pem>",
    "sig": "<base64-ecdsa-asn1-signature>"
  }
}
```

## 4. 健康与生命周期边界

服务端验证原 self-check 身份、签名、时间及 `healthy/problems` 一致性。
Windows 当前 self-check 只说明已激活的本机运行面：配置、生命周期、实际 selector、
本地代理监听及托管 TUN 网卡。通过这些检查不代表所有网站或整条业务路径可达。
Agent 路径健康保持 unknown，入口单次延迟与服务器分段估算写入已有签名 reason。

- 成功激活后按原周期上报；缺少本机运行配置、监听或托管网卡时报告具体问题。
- 不再从 Service 生成健康探测 URL，也不发送 DNS、TLS、HTTP 业务验证请求。
  服务目标缺测和 ICMP 无响应不等于设备整体故障。
- 服务器观测从同一次签名上报的响应读取；读取或验签失败独立记录，不改变本机健康。
- activation/recovery 成功可触发一次串行报告；candidate 不提前推进 `applied`。
- 检查或发送期间激活代次变化会取消并丢弃旧结果；主动停止和无法恢复的退出后不再
  上报，继续使用原 stale 规则。没有新增网络 watcher、等待样本或重试调度器。

## 5. 最小验收

服务端契约测试至少覆盖：

- `attest=canonical v5`、无 `attest_extended`、带 self-check 的最小报告返回 `204`
  并进入 gossip table；
- 缺 measurement digest、缺 self-check、混用身份、过期/未来时间和篡改
  node/ts/applied 均被拒绝。

Windows 侧至少覆盖：

- 从 v1 enrollment URL 得到同源 report URL，并拒绝重定向；
- DPAPI 身份在 invite token 清理后仍可取得 Endpoint、私钥和节点证书；
- 空 measurement digest 测试向量；
- 两签验签以及 node/ts/applied 篡改失败；
- 串行、严格递增时间戳；candidate 未激活不推进 applied，成功恢复报告旧 snapshot；
- `200` 读取观测与旧 `204` 兼容，其他结果不紧密重试且日志脱敏。
- 本机运行正常、监听缺失及恢复时的两签上报；检查不发送任何业务请求。
- 多 Service 共享入口只发一次 ping；服务器结果更新不重新探测；切换/停止隔离旧代次。
- 新二维码入口、指纹在请求前验证；Windows 请求不附加 server/职责字段；中控对旧码
  或错误平台的拒绝不会触发重试或协议降级，已加入身份不受影响。

生产验收使用用户指定的 Windows Device，按正常用户流程执行：

1. 在中控取得有效加入二维码，用 Windows 客户端的粘贴、文件选择或拖放入口导入。
2. 由客户端完成加入、证书和 signed pull 验证，并实际启动数据面。
3. 检查客户端自动生成的两签报告得到 `200` 观测数组（或旧服空正文 `204`）；
   读取扩展另核对真实来源观测已验签并进入当前 Agent，不能用空数组冒充复用成功。
4. 从中控核对该次加入产生的 Device ID、递增的 `ts`、last-seen 和实际 active snapshot。
   在 v1 验收中，只有 `applied` 与控制平面的 active signed snapshot 相同才表示配置已收敛；健康状态按真实证据验收。
5. 确认后续 60 秒周期仍有更新；停止客户端后确认不再更新，并在五分钟后观察 stale。

本环境只改客户端及必要的跨平台客户端包，不修改服务端源码或部署配置，不手工修改
SSOT、registry、证书或设备绑定来使验收通过。加入和重新加入由中控与客户端现有流程
维护身份。配置回滚恢复属于数据面激活事务，与恢复旧加入身份是两件事。

无签名请求返回 `403` 只证明拒绝路径，不能算上报成功。排查网络时复用客户端的
`netx.Client` 和已配置 DNS；通用工具的请求结果不能替代实际客户端验收。

继续工作的提示词见 [Windows 上报实测提示词](windows-client-reporting-prompt.md)。
