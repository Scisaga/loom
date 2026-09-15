# Windows v1 上报验收规程

**适用条件：** 当前任务明确涉及尚在使用 v1 身份的 Windows 加入、完整上报或进程心跳时使用。
本文不自行启动验收，不延长 v1 服务端生命周期，也不限制其他任务已经获得的部署授权。
v2 迁移使用[控制面实施规程](control-plane-implementation-prompt.md)，不向 v1 schema 填入新版字段。

## 开始前

- 阅读[协议契约](windows-client-reporting.md)、[Windows 构建入口](../clients/windows/README.md)
  与[源码能力对照](implementation.md)。实际部署及已有验收从 `.env` 指向的配置和
  `deploy/evidence/` 对应记录核对，不从静态规范推断。
- Windows 专项默认限于 Windows 客户端、必要的共享客户端包及当前明确要求的服务端验签/
  在线投影；不顺手修改 Android/Linux producer 或部署配置。不手工修补 SSOT、registry、证书
  或绑定使验收通过。更大的迁移/上线任务按当前对话范围执行。
- 复用客户端已经保存的合法 DPAPI 身份；没有加入身份时才走二维码流程。私钥由客户端产生，
  不要求用户查找私钥、恢复旧目录或清除已加入状态。
- 客户端选路只按[消费边界](client-observation-reuse.md#客户端消费边界)验证。
  不新增业务目标、整路径扫描、重复样本或启动等待。

## 正常流程与证据

1. 未加入时，从当前中控正常生成有效 Windows 邀请，通过客户端二维码入口加入；已有身份则
   直接使用。新码校验入口与指纹，服务端拒绝旧码不触发降级。观察本地检查、联系中控、等待配置、
   验证保存各阶段；`pending` 不算已完成。服务端延迟按[分段排查](server-enrollment-latency-prompt.md)处理。
2. 启动实际客户端。上报相关改动需确认真实 active snapshot，由 activation/recovery 成功提供；
   下载成功或 candidate 不足以推进 `applied`。
3. 心跳相关改动核对进程首包、五秒节拍、断开数据面仍发包，以及停止进程后十五秒 lease 到期时
   已打开列表变为 `Stale`。该流程不触发完整 Observation，不新增网络故障注入。
4. 完整上报相关改动取得客户端自动生成的两签报告 `200` 观测数组或旧服空正文 `204`，并从中控
   核对同一身份、递增时间、last-seen 与实际 active snapshot。`applied` 与 active signed snapshot
   一致才说明 v1 配置收敛；健康按实际证据范围判定。
5. 观测复用相关改动核对真实来源观测已验签并进入当前 Agent；空数组或只改 report URL 不算复用。
   检查后续原周期更新及两类状态隔离，按改动选择必要检查，不重复无关历史矩阵。
6. 如修改代码，运行相关测试、vet 与 Windows amd64/arm64 交叉编译，提交相关实现；生产发布
   仅在当前任务授权范围内执行。实机未验证就明确记录，不以 HTTP `403` 或手工报文代替。

## 排障与交接

TUN 连通问题分别核对默认网卡绑定、签名 DNS 配置、系统流量、TUN DNS 与本地代理。
窗口显示连接或进程存活不代表流量成功；手工访问结果也不能直接成为自动健康证据。
网络诊断复用客户端传输与配置 DNS；Windows 生产代码不依赖 `internal/report`。

交接给出源码修改、已执行测试、实际客户端报告结果和仍未验证项。真实设备、端点、提交制品坐标
与日志进入忽略的 `deploy/evidence/`；公开[实现对照](implementation.md)只更新源码和接线缺口。
