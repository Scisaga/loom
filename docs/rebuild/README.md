# v2 最小重建

本目录是 `rebuild/v2-minimal` 的设计入口。重建源码以提交 `6be9e4c9` 为基线；旧实现封存在
`archive/v2-overgrown-20260917`。这个选择只决定从哪份源码重新开发，**不表示生产回退到 v1**，
也不授权清空现网身份、密钥、数据、floor 或 v2 latch。

## 重建目标

重建只追求四个结果：

1. 用最少领域概念同时完成 N>1 治理与增量 CRDT 数据同步；
2. 通过受限 Bootstrap 完成私有 Enrollment、私有配置和私有报告；
3. Linux 与 Android 从同一候选模型选择直连或中继，并以真实运行结果更新可用性；
4. 完整保留控制面 Web 产品，改由新的认证状态和观测投影供数。

旧代码、旧 issue、测试数量和 wire 类型数量都不是需求来源。默认不移植旧实现；只有
[白名单](migration-whitelist.md)中的能力可以进入重建分支，而且仍须符合对应核心模型。

## 同构说明是实现前置条件

每个核心模型必须在文档中完整定义，不能让读者通过追踪构造器、store 或测试反推语义：

- [控制权威模型](control-model.md)
- [Enrollment 与 Endpoint 模型](enrollment-endpoint-model.md)
- [客户端运行与选路模型](client-runtime-model.md)
- [本机节点与部署配置模型](configuration-model.md)
- [控制面 Web 投影](web-ui-projection.md)

对任一权威模型，设领域状态为 `D`、规范 wire 为 `W`、耐久状态为 `P`：

```text
decode(encode(D)) = D
load(save(D))      = D
decode(W)          = error，若 W 含未知、歧义或不可规范化内容
```

`encode/decode` 与 `save/load` 必须保存同一语义，不得在 wire 或磁盘层偷偷增加另一份状态机。
运行时 `R = run(D, local_input)` 与界面 `U = project(D, Observation, R)` 是单向投影，不要求能反推
`D`，也不得倒写权威事实。缓存和索引必须可删除重建。

每份模型文档都必须给出：

- 有限的领域实体及删除它会破坏的需求；
- 关系、状态转换、不变量与失败语义；
- domain、wire、persistent、runtime、UI 的逐项映射；
- 哪些映射可逆，哪些只是投影；
- 一条正常业务链和最小必要测试集；
- 明确不允许重新引入的实体和兼容路径。

实现若需要文档中不存在的新权威实体，先回到模型证明其必要性。helper、DTO 或 adapter 可以存在，
但不能拥有未在模型中定义的事实、生命周期或完成判定。

## 串行实施顺序

### 1. 安全重建基线与 Web 保全

- 导入现有认证状态所需的最小只读材料，保持身份、数据、floor 和 v2 latch；
- 保留浏览器 UI、TLS/管理员权限边界、Releases、Devices、Topology、Services 与 Events；
- 建立窄的 Web 投影接口，不保留旧 SSOT/registry 作为第二权威；
- 禁止新增 per-device 配置进入公网镜像；私有交付未接通前相应写操作失败关闭。

### 2. N>1 治理与增量 CRDT

- 任一健康 control 可受理管理操作；
- CRDT 只增量同步不可变材料，Raft 只排序材料引用与成员变化；
- reducer 产生唯一 Projection，Head + QC 是唯一对外生效证明；
- 少数派拒绝扩权但继续提供旧 certified LKG；分区恢复只传缺失材料。

### 3. 私有 Enrollment 与 EndpointGeneration

- 完成公开 catalog → capability tunnel → private Enrollment → private config → signed report；
- resume 是同一 EnrollmentTransaction 的幂等取回；
- listener 轮换只是 EndpointGeneration 的 overlap/prefer/drain/retire 转换；
- 公网 Nginx 只承载 fake website 和通用 immutable artifact。

### 4. Android 运行闭环

- 同一最终出口的一跳直达与境内入口经 WG 中继同时作为候选；
- 实际 transport/业务结果决定 `available / unavailable / unknown`；
- 完成签名 Release 的一条直连和一条同出口 fallback 真机业务。

### 5. Linux 运行闭环

- Direct、Auto、FixedExit 使用同一客户端模型；
- 正式 service 启动实际 runtime，不再用旧扫描式 Agent 代替客户端模式；
- amd64 完成代表性正常、fallback、重启 LKG 和撤权；arm64 只构建与交叉检查。

每一阶段必须在同一项工作中完成实现、正式入口、持久结果、运行时消费、结果回读、必要部署和
旧路径删除。不得把“开发”和“验收”再次拆成彼此可以独立关闭的任务。

## 明确排除

- Windows 原生实现与验收在另一台机器进行；本分支不以交叉编译抵扣，也不修改其工作；
- DNS provider、DNS-01、ACME 自动签发和续期不属于核心重建；首轮只消费现有有效证书；
- 不登录或修改 NAT/路由器，不自动分配操作者没有提供的公网映射；
- 不恢复公开 claim/config/report、v1 fallback、全路径扫描、启动等待、样本填充或平台矩阵；
- 不重新生成已经存在且可验证的 bootstrap、身份或迁移材料。
- 不删除 `.env` 这一私有本机配置入口；按[配置模型](configuration-model.md)瘦身并严格解析，运行状态和历史证据不得塞回其中。

## 完成判定

代码量、测试量、schema 数量和组件存在都不是进度。只有一条正常业务请求经过正式入口、认证、
权威状态变化、持久化、运行时消费和用户可见回读，并且被替代旧路径消失，才算对应结果完成。
扩展测试只能在这个最小闭环之后进行。

分支、issue 与发布等远端结果还必须满足
[外部操作预检与完成证据](../../AGENTS.md#外部操作预检与完成证据)。
