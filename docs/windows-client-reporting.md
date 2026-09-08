# Windows NAT Device 状态上报接入说明

> **状态：** Windows 最小两签 producer 和每轮健康采集已实现。原生测试覆盖加入、
> 健康/故障/恢复、配置切换及两签上报；Windows amd64 实机已确认 TUN 探测成功、
> 自动上报 `204` 和中控接收 healthy=true。停止后五分钟 stale 已在中控验收。
> **边界：** 复用现有 `report.Observation`、`loom-attest-v5` 和
> `loom-selfcheck-v1`；不新增状态协议、envelope、心跳格式或 self-check v2。

## 给 Windows 客户端仓库的简短提示词

```text
只修改 Loom Windows 客户端：在已加入且成功激活配置后，从 DPAPI 身份的已验证
PreparedIdentity.Endpoint 精确要求 /loom-client/enroll，并同源替换为 /loom-client/report；
每 60 秒 POST 现有 report.Observation 原始 JSON，成功只认空正文 204。复用现有 canonical v5 attest 和 self-check v1：
两份附件使用同一 P-256 设备私钥/节点证书，node/ts 必须一致，applied 绑定最后成功激活
的 snapshot；无 WG 测量时省略 edges/targets，并按 {"edges":null,"targets":null} 计算
measurements_sha256。串行生成严格递增 UTC 时间，拒绝重定向，失败等待下一周期且日志脱敏。
不要新增 envelope、第三份签名、心跳协议、self-check v2 或服务端改动。Windows 邀请固定为
windows-desktop + use_loom；已加入身份继续使用，仅未消费的旧加入码失效并需由中控重新创建。
按本文“最小验收”补测试。
```

## 1. 最小目标

Windows 客户端在加入完成、首轮 signed pull 验证且数据面成功激活后，每 60 秒向
当前生产 enrollment URL 的同源 report 路径提交自身 Observation。服务端验签后写入
既有 gossip table，中控继续复用原有健康与配置版本判定。

用户操作流程始终是：

```text
中控提供有效加入二维码 → Windows 导入二维码 → 加入网络 → 启动数据面 → 自动上报
```

二维码是一次性加入凭据。客户端在加入过程中自动生成设备私钥、验证中控返回的节点
证书，并用 DPAPI 保存身份；此后上报直接复用这份身份。用户不需要准备、查找、导入或
备份私钥，也不需要手工构造签名报告。未加入的客户端从二维码开始，不把恢复旧目录或
沿用旧设备身份作为测试前提。二维码过期或已使用时，按中控现有的重新生成或重新加入
流程取得有效二维码；客户端仍走同一个加入入口。

Windows 邀请固定为 `windows-desktop + use_loom`，职责由中控创建邀请时确定；客户端
只声明 `windows-desktop`，不提交 `server`、职责或旧的 profile 字段。未消费的旧加入码
由中控作废，客户端收到拒绝后直接结束本次加入，不变更平台或尝试旧协议。已加入的
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

上述是现有 producer 的默认契约。服务端另支持显式 `?observations=1` 返回已有
签名 Observation 数组，接口见[客户端观测复用说明](client-observation-reuse.md)。
当前 `clientreport.Send` 会拒绝带查询的地址，且只接受空正文 204；读取模式仍需
客户端接入，不能仅给现有配置追加参数就声称已复用服务端观测。

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
    "problems": ["端到端探测超时"],
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

- 成功激活后周期报告实际健康判定；缺少可信健康证据时报告 `healthy=false`；
- activation/recovery 成功可以额外触发一次串行报告；
- replacement 进行中继续保留上一份成功报告，不抢先推进 `applied`；
- 主动停止、无法恢复的异常退出或整个宿主退出后不再产生报告，由旧 Observation 在
  5 分钟后显示 stale；
- 如果客户端尚不能获得上位设计要求的代表性端到端健康证据，就不得报告
  `healthy=true`，也不得为达成绿灯发明未签名探测端点。

Windows 每轮在现有 reporter 内执行一次有界健康探测，随后上传当轮结果：

- 从成功激活时保存的探测计划取目标，不读 candidate 指针。目标来自签名配置中匹配
  当前用户入口的 Service 具体域名，按现有 Agent 规则组成 `https://地址/`；排序后取
  一个代表性地址。后缀及由后缀扩展的根域名、候选专用探测规则不提供目标。
- Portable Mixed 显式经过本地 `1080` 代理；TUN/Installed 查验托管网卡和 DNS/目标
  的路由，绑定 TUN 源地址并通过 TUN 网关解析 A 记录，再发送 IPv4 HTTPS。
  不读取环境代理，不允许物理网卡或 IPv6 旁路冒充 TUN 成功。
- 校验目标 TLS 证书，不跟随重定向。沿用 Agent 的可达性判据：目标非 5xx 响应；
  另排除代理鉴权失败。它证明代表性通路可达，不证明所有业务授权、网站或出口健康。
- 成功时 `problems=[]`、`healthy=true`；缺目标、接管无效、DNS/TLS/连接失败或超时
  时报告具体的脱敏问题。每轮重新采集，不缓存成功值。
- 探测期间激活实例、snapshot、运行状态或出口偏好变化时丢弃结果；配置切换可取消
  在途探测和发送。主动停止仍不再上报，继续使用既有 stale 规则。
- 探测预算 8 秒、上传预算 5 秒，相互独立。探测超时仍上传 `healthy=false`，
  不因复用已到期的 context 丢掉故障报告。周期仍为 60 秒，没有额外重试循环。

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
- 健康、失败、恢复的当轮采集和两签上报；探测超时后仍有独立的发送预算。
- 缺少具体目标、TLS 错误、错误路由与重定向；切换/停止/退出不沿用旧探测结果。
- 新二维码入口、指纹在请求前验证；Windows 请求不附加 server/职责字段；中控对旧码
  或错误平台的拒绝不会触发重试或协议降级，已加入身份不受影响。

生产验收使用用户指定的 Windows Device，按正常用户流程执行：

1. 在中控取得有效加入二维码，用 Windows 客户端的粘贴、文件选择或拖放入口导入。
2. 由客户端完成加入、证书和 signed pull 验证，并实际启动数据面。
3. 检查客户端自动生成并发送的两签报告得到空正文 `204`。
4. 从中控核对该次加入产生的 Device ID、递增的 `ts`、last-seen 和实际 active snapshot。
   只有 `applied` 与当前生产 snapshot 相同才表示配置已收敛；健康状态按真实证据验收。
5. 确认后续 60 秒周期仍有更新；停止客户端后确认不再更新，并在五分钟后观察 stale。

本环境只改客户端及必要的跨平台客户端包，不修改服务端源码或部署配置，不手工修改
SSOT、registry、证书或设备绑定来使验收通过。加入和重新加入由中控与客户端现有流程
维护身份。配置回滚恢复属于数据面激活事务，与恢复旧加入身份是两件事。

无签名请求返回 `403` 只证明拒绝路径，不能算上报成功。排查网络时复用客户端的
`netx.Client` 和已配置 DNS；通用工具的请求结果不能替代实际客户端验收。

继续工作的提示词见 [Windows 上报实测提示词](windows-client-reporting-prompt.md)。
