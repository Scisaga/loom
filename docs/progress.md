# 实施状态

本文是按各节证据日期和源码坐标保留的实施历史，不是当前远端状态、后续任务授权或目标设计的来源。
早期记录中的“本轮”“当前”“已完成”只指该节当时范围；其旧模型、字段和获批操作不能覆盖用户
后续纠正。当前目标见[设计入口](README.md)与[业务基线](core/control-model.md#服务与策略的当前业务基线)，
尚未闭合的实现见[交付对账](delivery-audit.md#当前目标与尚未闭合的实现)。

文档审计阶段仅修订文档，没有修改生产授权或执行部署，也没有重新执行全部历史验收。
用户随后已要求继续当前计划，恢复范围及实际结果见下一节。历史原始证据保持原义；实体终验和
正式入口回读仍按各任务实际范围判定。

## 最终收敛：部分确认签报与正式诊断消费

2026-11-07，本轮开始时工作区干净，本地 HEAD 和远端 main 均为
`6207c8db426bd1bc74d53d120e5800edbc7644d2`。本节更新当前交付边界，下方各历史窗口的
“本轮”仍指各自源码、制品及 RUN，不追溯改写。没有执行生产迁移或正式发布。

### 手机部分确认的反例、修复和同 RUN 原件

先核对原冻结 `.28` 安装摘要、原身份与认证进度、六节点只读连接和前次资源清理。复用原独立
测试 authority／Gateway，在新的 user／net／mount namespace 内通过正式 CLI 建立临时 LAN
授权，手机正常“检查更新”、选择 Policy 和连接；普通应用 UID 的 HTTPS 与 LAN TCP 原流保持。
只修改本次自有 LAN Service 的名称，以新认证 View 的正常保留运行入口触发两个 Scope 重新确认。
JDI 仅在 selector 初始 GET 之前的调用边界暂停单个事件线程，未改字段、局部值、产品期限或时钟；
两个 Scope 同时具有待应用及 CAS 要求，先释放 Internet 完整 GET／准备／CAS／回读，再保持 LAN。
报告只调用正常 `reportRuntimeOutcome`，不传入 selections、applied 或 Observation。

原 APK 在这一真实部分确认状态仍输出双意图、空 selections 的 unknown 签报，反例成立。
缺陷在 Kotlin 报告投影和 mobile 签名桥，不在 Scope 应用、native CAS 或 control 验签端。
最小修复逐 Scope 验证当前偏好、完整 candidate／targets／Policy／choices／revision 回读及
该 Scope 在途状态；只上传已确认子集。mobile 桥允许 unknown／空 applied／当前权限证明下的
这份子集，仍拒绝 stopped、error、缺权限、错误 View 及越权候选，业务样本继续要求完整 running。
另由正式 retained-runtime 调用顺序确认，服务层已切新 View、RouteManager 尚持旧回读的短窗
不得产生整实例 applied；完整报告增加当前 runningProfile View 绑定。没有新增协议字段、状态、
持久权威或跨 Scope 事务；相关模型同步修订同一 schema 3。

官方入口重建双 ABI AAR；最后仅 Kotlin 的绑定修正复用该冻结 AAR，生成独立最终 Debug APK，
原件和中间未安装 APK 均保留。最终 APK 同签名覆盖安装，受保护身份、密钥、latch、high-water
及报告序列保持。93 项 JVM 无失败／跳过，lint、Debug 与 instrumentation APK 构建通过；实际
AAR／APK 两 ABI 库逐字一致，手机运行报告的 APK 和 ARM64 库 components 匹配精确制品。

最终手机同一 APK、同一 worker RUN 的结果分别为：

| 时刻 | 真实状态与交付原件 |
|---|---|
| 同时待应用 | 两 Scope 的在途和 CAS 要求均成立；双意图、无已确认选择，unknown／空 applied |
| 部分确认 | Internet 真实新 revision 和完整回读成立，LAN 仍未确认；签报仅一项 Internet selection，双意图、unknown／空 applied 和当前权限证明 |
| 全确认 | 同一 worker 尚运行时的独立签名原件为双 Scope running，applied 匹配 View；逐候选、Policy、targets 与真实 native 回读一致 |
| 正常停止 | 原双流无失败、正常关闭并 cleanup；手机正常 UI 断开，收到空选择的 stopped 原件 |

全确认采集中的普通快照当时仍指向较早的部分 unknown 报告，保持原值；随后交付的 running
原件以严格报告序列、同手机 worker 时钟区间、精确组件及实际 selector 关联取证。worker 结束后
另有 running 原件，明确排除，不拼进在途区间。新 APK 的首个 JDI 尝试在绑定前误拒旧取消事件，
按夹具缺陷保留后修正；绑定后的 owner 替换仍严格拒绝。首次 setup 的旧 request ID 冲突、UI
辅助器入口错误、JDI 退出后空行清理错误与正常停止后的 API 关闭分别留证，不改记产品故障。

全部 producer 正常退出后，离线审计覆盖原报告数据库、历史身份键、规范签名、数据库键／序列、
保存快照的每个报告和测量引用；部分、最终 running、stopped 原件及引用样本均保全，数据库
字节／文件身份／时间和 authority 原件／目录集合保持。临时授权经正常新事实撤回，手机正常
接受、原偏好恢复，独立加密持久双读等于当前缓存且认证进度／报告序列不降。自有 runtime、
namespace、监听、ADB 映射、凭据和逐 RUN 命令／状态文件精确清理；未建立引入归属的共享 jar
与通用 UI dump 保留为非运行文件。宿主结构只比较保存的较晚基线至最终，不补造初始防火墙基线。
精确来源、命令、失败和原件在 `deploy/evidence/2026-11-07-convergence-scope/`，其中
`audit-extra/summary.json`、`audit-extra/bindings.json` 和 `cleanup-result.json` 分别给出最终证明。

### 正式 daemon 的诊断失败消费

新增显式 opt-in 的 `TestOfficialLinuxNativeDiagnosticFailureConsumedByDaemon`，复用原 `.28`
WG native、正式 control CLI 加入、签名 LKG 和默认 Run 测量调度。独立 user／net／mount namespace
先证明仅 loopback、无外部路由，再使用既有允许的合成普通互联网目标算法；不连接公网，不写
Observation、不修改测量缓存、不复制额外 sampler 的结果、不改变产品预算或观测有效期。

本次只丢弃自有 WG UDP 报文，默认诊断等待到期后，真实 unavailable 样本进入正式 Status、
持久缓存、选择和签名报告。唯一合法固定出口候选仍保留，真实 selector 的 Policy／最终出口
不变。两个明确业务窗口依次取证：故障存在时普通 TCP 实际失败，并保留本机内部建连 deadline
的真实 unknown 反馈；精确解除丢弃后，在同一失败样本原有效期内完成正常 TLS 验链／名称验证
和完整正文，反馈 available，旧连接 UUID／链保持，随后默认调度产生新鲜 available 恢复样本。
没有合法备选时不制造 Direct 或越过固定出口；不将本机等待错误写成远端明确不可用。

首轮集成因测试误筛 unavailable 而拒绝已有的 unknown TCP 反馈，原 RUN 和失败保留；修正只
涉及测试断言及完整回读取证，未改产品、期限、AAR 或 native。修正后的普通及 race 集成均无
跳过通过，无 race 报告；
停止 Run／control 后，精确失败样本的签名原件、数据库键和序列通过，数据库字节保持；测试
namespace 的自有进程全部退出，宿主结构前后相同。此项只补两类正式消费窗口，不把此前额外
sampler 的其他配对改记为 daemon 已消费；真实业务 deadline、诊断 timeout 和反馈 unknown
分别记录，内部 TCP 尚未完成时不得称 Echo 执行帧超时。每个通过 RUN 已收的签名原件包含
真实失败样本；恢复仅由正式 Status／selector 及新鲜样本证明，未等待恢复／停止新报告 ACK，
不宣称另有这两类签名原件或额外完成恢复缓存持久回读。命令、最终源码及二进制摘要、首轮
失败、修正续验和清理在 `deploy/evidence/2026-11-07-convergence-diagnostic/`。

本轮实际检查命令和结果分别保全：

- 官方 `bash scripts/build-mobile-aar.sh`，以及最终复用 AAR 后的
  `bash gradlew --no-daemon --max-workers=4 :app:testDebugUnitTest :app:lintDebug :app:assembleDebug :app:assembleDebugAndroidTest` 均通过；另有 Scope／接管定向 JVM 与诊断日志定向 JVM 通过。
- `mobile/loomcore` 内 `go test ./...`、部分确认定向普通／race 和 `go vet ./...` 通过；旧桥的两项部分确认红测试失败原件保留。一次从根目录调用嵌套模块的入口错误不计产品失败。
- `internal/clientadapter` 普通及诊断关联／cause／复用定向 race 通过；新诊断消费普通／race 由私有 namespace 执行器显式 opt-in 执行，均无跳过。
- 最终 `go build ./...`、`go test -json ./...`、`go vet ./...`、全部 tracked／untracked Go 的 `gofmt -l`、`python3 scripts/check_repository_safety.py`、`git diff --check` 均通过，格式与 diff 无输出。默认测试的跳过逐项保留，不能抵扣显式业务测试；最终重查使用了 Go 测试缓存，来源摘要前后相同。

命令数组、真实退出值、耗时、源码／制品摘要、默认跳过和缓存范围在上述各私有证据根及
`deploy/evidence/2026-11-07-convergence-checks-final-001/`；此前检查日志保留，不冒充最终源码。

### 历史异常与阶段 3 的终审边界

历史手机 Admission Echo 超时原窗仍未定位。保存的规格与网络代不能补出同请求 Echo／native
ID、Operation／Policy 或发送／接收端／underlay 证据；原窗相近的内部 TCP deadline，以及后来
独立 Linux `.28` 已关联的内部 TCP 到期事件，均不能与它合并归因。新增安全 Debug 把真实 flight
的 Echo ID 与资源／规格／Operation／网络代／Policy 绑定，root、mobile 和既有 native ID 可关联；
不记录 nonce、秘密、原始帧或业务正文，日志失败不改变结果。最终 APK 的正常日志已实际产生
这些绑定，不等于复现或解释历史超时。专项原件在
`deploy/evidence/2026-11-07-convergence-wg-history/`。

阶段 3 只审计既有异网 F1／F2／E 的实际业务、故障、恢复、撤权与清理，不重跑矩阵。
前一恢复窗口的 TTL／EOF／failed／cleanup 保留，后续独立 epoch 自身证明恢复；浏览器依赖
成功仍未观察新 HTTP 连接，不单独证明 Forward 路径。六节点只读回查、Nginx 历史 stop/start、
持续真实 ACL 增删与 SSH relay reset 的证据和来源未知边界见下文
[最终保全](#阶段-3精确撤权与最终保全)，本轮未修生产或宿主网络。

阶段 1 的真机部分确认和阶段 2 的上述 Linux 正式消费分别成立，阶段 3 的既有真机业务经审计
保持；新提交托管 CI、阶段 4–8、正式签名发布与生产激活仍未执行。下一唯一业务入口是阶段 4
的正式 Policy 操作及合法旧流保持，不提前展开缺少蜂窝／Windows 实体条件或生产授权的阶段。

## Internet 与 LAN 的组合 Scope 续验

2026-11-07，从干净的 `c5fb6b103689761781ec0ba59811e762e2ca1345` 开始；本地与远端
`main` 相同，该提交主 CI 四个 Job 已正常读回成功。以下新增测试的本地结果不冒称已经有
新的托管 CI。Scope 独立应用已有实现，本次未重写 RouteManager、资源池、授权或 schema 3。

Android JVM 补齐两个 Scope 的真实回环 HTTP 接管交错：旧 PUT 完整到达、客户端取消、新的
同值完整 CAS 与回读完成后再释放旧 PUT，测试接收器返回冲突；另核对各自 revision 独立推进。
资源准备失败的原回调用例扩为 Internet／LAN 对称覆盖。完整 JVM 为 21 组、90 项，全部通过，
无跳过；日志及 XML 在 `out/scope-jvm-followup-results/`。报告原表补齐双意图但只有 Internet
确认，以及部分执行保留意图、权限证明而不伪造整实例成功；定向普通／race 均通过。

新增显式 opt-in 的 `TestOfficialLinuxNativeInternetAndLANScopesKeepConcurrentConnections`，
正式 Linux Run 消费签名 LKG 和持久 Preference。独立 user／net／mount namespace 在生成
合成公网地址前核对只有 loopback、没有外部路由；HTTPS 使用测试信任根与名称校验取得完整
正文，LAN TCP 按签名映射到真实接收 socket。两个接收应用互等请求到达后才响应，证明同时
在途。两 Scope 分别换选择及一起待应用时，各自完整 CAS／revision 回读成立；原两条连接的
UUID、资源链和持续双向业务保持，新连接仅以本轮新增 UUID 核对实际选择。

测试调用的局部回环 gate 仅注入本机 API 边界：两个 Scope 各一次资源 GET 失败；LAN 准备
请求挂起及真实取消；完整旧 PUT 被接收、调用方取消、新 CAS 完成后才向真实 native handler
转发。冲突由真实 handler 返回，gate 不制造冲突。失败和取消期间两条旧流继续收发，完整
选择快照保持。它不代表真实 sender factory 构造失败，也不代表 Android RouteManager 已在
手机上执行相同故障。最终普通／race 均实际通过、无跳过或 race 诊断，宿主结构回读保持。

夹具首次一次写两项偏好、误用删去 lazy sender 的启动配置、以及缺少完整新 UUID 排除的
取证缺项均保留原记录。扩展中一次 race 发现选择快照变化，原轮未保存前后快照，原因仍未
定位；不将其写成已证实的选路或产品缺陷。最终夹具明确每条 Policy 只有一个合法首跳资源，
保持相同最终出口，并保存各故障窗口前后的完整快照；未放宽断言、延长期限或改变生产选择。
完整命令、精确二进制及原件在 `deploy/evidence/2026-11-07-multiscope-native/`。

当时固定的 `.27` 原生库对应 Android ARM64 Debug APK 随后完成正常组合业务：独立测试
control 先取得 Gateway
的真实签名 LAN 报告，再经正常分配预览、Service／Policy 写入及设备授权交付。手机沿正常
配置更新、LAN 策略选择和连接界面接受、持久保存并启用两 Scope；原互联网 Policy 保持。
普通 UID socket 同时持续取得非探测网站的完整 HTTPS 正文及 LAN TCP／HTTP 响应；另以同一
应用 UID 的 DatagramSocket 完成真实 LAN UDP 回包。原生 tracker、Service、确认 Policy、
两 Scope revision 与接收端分别核对，两条原 UUID／资源链及 native Box 保持。

| 实际手机报告状态 | 已确认选择 | 整实例证明 |
|---|---|---|
| 启动／部分执行的 `unknown` | 不伪造未齐选择 | applied 留空，独立权限证明保留 |
| 两 Scope 确认后的 `running` | Internet 与 LAN 各一条 | applied 与本次认证 View 相同 |
| 正常断开后的 `stopped` | 无当前运行选择 | 不复用上次成功证明 |

安装 APK 与实际 ARM64 库摘要匹配正常签名报告。control owner 退出后以只读方式逐件核验
全部本轮手机和 Gateway 报告的规范字节、签名、数据库键及序列，正常 snapshot 精确引用
匹配，数据库前后字节、文件身份与时间不变。临时授权以新事实撤回，手机正常更新接受，
原偏好恢复；两次独立加密存储读取等于缓存，完整规范身份、密钥、latch、high-water 和报告
进度核验通过，无明文身份落盘。辅助对象、映射和隔离实例精确清理，宿主结构保持。
证据及 Scope 矩阵在 `deploy/evidence/2026-11-07-multiscope/review-summary.json`。

后续精确 `.28` Debug APK 沿正式 UI 再次启用两 Scope，真实普通 HTTPS 与映射 LAN TCP
同时持续收发。第一轮取得 LAN GET 在一次性本机 API gate 挂起、正常 UI 后继操作取消的
独立证据；旧 peer EOF、新调用对象及前驱 cancelled 相互对应。该轮临远端 TTL 的后续 worker
终态 `failed` 单列为 confounded，不用于产品失败判定，也不与下一 RUN 拼接连续性。

新 epoch 使用同一 `.28` APK、原身份和偏好，另建普通业务 RUN／tracker。LAN、Internet
各一次准备故障仅改变本次 native prepare/auth 请求配置副本中的本机 API secret，保留
原 body、配置和权限。两次都在真实返回点读到 `supported=true`、`permission_current=false`、
`resources_ready=false`，随后正常 UI 恢复并读回新 revision。这是一次本机准备／认证调用
失败，不是 sender factory 构造坏，也未直接取证原始 HTTP 401；布尔值不改写授权事实。
LAN 的完整非 reject PUT 则在客户端取消后保留原 body，由正常 UI 同 Scope 的新完整同值
reject CAS、新选择与完整 GET 接管后，才原样转发至原 native handler，实际返回 409。
gate 不合成冲突。原产品的三秒 socket 和八秒准备期限均未改变。

以下对应本轮 A–F 风险，覆盖层次分别判定。JVM 的真实 HTTP 使用契约 receiver，不能称为
真实 native；函数见 [ScopeApplicationTest](../clients/android/app/src/test/java/io/github/scisaga/loom/route/ScopeApplicationTest.kt)
与 [SelectorTakeoverTest](../clients/android/app/src/test/java/io/github/scisaga/loom/route/SelectorTakeoverTest.kt)。
Linux 项统一由上述正式 Run 测试覆盖，故障只在本机 API 边界注入。

| 风险 | Android JVM／HTTP 契约 | 真实 Linux Run／native API | 当前 `.28` 手机 |
|---|---|---|---|
| A：LAN 准备失败，Internet 保持 | `ScopeApplicationTest.partialIoFailureDoesNotDiscardSuccessfulScopeOrSkipLaterScope` 通过 | LAN 准备资源 GET 失败、原业务及确认保持通过 | 本次 native prepare/auth 返回三布尔失败；旧 Internet 连接、revision 与确认决策保持，通过 |
| B：Internet 准备失败，LAN 保持 | 同一对称用例通过 | Internet 准备资源 GET 失败、原业务及确认保持通过 | 对称真实返回失败；旧 LAN 连接、revision 与确认决策保持，通过 |
| C：LAN 在途不阻挡 Internet | `accessReadPrepareCasAndReadbackFinishBeforeLanInitialGetReturns` 通过 | LAN 准备资源 GET 挂起时两条旧流持续，通过 | 本机 Scope GET 准备边界实际挂起，原 HTTPS／LAN TCP 保持，通过 |
| D：取消及确认记忆隔离 | `cancellationInvalidatesOnlyUnconfirmedWritesAndDoesNotBecomeNetworkFailure` 通过 | 真实取消、socket 退出及完整确认保持通过 | 正常 UI 取消旧调用，EOF／前驱取消对应；Internet 确认决策、样本和版本保持，通过 |
| E：旧完整 PUT 迟到 | `SelectorTakeoverTest.successorCasRejectsCancelledLatePutForInternetAndLan` 通过 | 新完整 CAS 后真实 handler 拒绝迟到写入，通过 | LAN 新完整 CAS／GET 后旧原请求实际 native 409，通过 |
| F：各自 revision／CAS | `internetAndLanCasAdvanceOnlyTheirOwnRevision` 通过 | 两项偏好一起待应用后，各自 CAS／revision 通过 | 正常 UI 独立变化及另一 Scope revision 保持通过；未另做两项同时待应用的手机交错 |

新 epoch 三个故障前后及整个本 RUN 的两条原 worker 连接、本机端口、native UUID 和资源链
相同，完整 2xx 正文持续增加。每次另一 Scope 的确认决策、样本、版本、Policy、网络代与
native binding 保持；仅本机决策时钟／健康期限自然推进，不称整份 memory 字节相同。
Box、app 与原映射保持，临时 JDI／gate 正常退出并精确清理。交接给阶段 3 的 fresh worker
只承接自己的 RUN；手机首跳不证明远端 F1 的实际后续路径。当前精确 `.28` 另沿普通应用
UID 完成正常 LAN UDP：消费本窗口的 Scope 参数，三次 datagram 均为 exact reply，socket
正常关闭。工作负载 jar 字节虽复用，业务已在本 APK 重新执行；这不计作故障期间 UDP。

手机、三个远端节点、Gateway 及 control 的本轮 producer 正常退出后，离线只读审计已通过。
五个报告源的规范字节、签名、数据库键、序列及历史签名身份逐件核对，故障过程与最终正常
snapshot 的报告和样本引用均匹配原件；数据库摘要、文件身份、长度、时间及权威原件不变。
两次 prepare 真实返回后取得的正常报告，均有双意图但为保守 `unknown`，applied 与 selections
为空；恢复后的原件存在两 Scope 全确认、applied 匹配 View 的 `running`。本轮没有部分 Scope
确认的签名报告，不由单测或本机确认记忆补造该历史。正常断开后的本机报告序列继续前进，
已停 control 未收到的后续序列不冒称已经入库。

按用户要求，本节结项信息保留七项，源码、本地、隔离、设备与发布范围不合并：

| 报告字段 | 当前记录 |
|---|---|
| 1. 提交 SHA | 当前 HEAD 为 `c5fb6b103689761781ec0ba59811e762e2ca1345`，新增工作区输入及各精确制品按摘要分别保全；新增结果未冒称新提交托管 CI |
| 2. 修改文件与理由 | 上述 `ScopeApplicationTest.kt`、`SelectorTakeoverTest.kt`、`native_scopes_network_linux_test.go` 和 `report_preference_test.go` 补验收；真机一次性夹具仅在忽略目录，不重写 Scope／资源池或增加产品 test hook |
| 3. 已修复缺陷 | 本轮未据夹具失败宣称新 Scope 产品缺陷；已修正夹具断点、恢复配对及等待／回读门禁，旧失败原件保留 |
| 4. 命令与结果 | `:app:testDebugUnitTest` 当轮 90 项通过；独立 namespace 执行器内 `scopes-normal.test`／`scopes-race.test` 的本测试 `-test.count=1 -test.timeout=90s` 均无跳过通过；`go test ./internal/control -run TestCurrentReportSignsIndependentLANSelections -count=1` 及对应 `-race` 定向签名往返通过；真机沿正常 UI、私有 `phone_window.py` 与 `udp_current.py` 执行；停 producer 后显式包含 Gateway 与 joint Scope 的原件审计通过，私有审计器格式反例及普通／race 检查通过，命令及摘要见原件 |
| 5. 真实业务证据 | `.27` 正常组合保持原制品范围；本轮 `.28` 为普通 HTTPS／LAN TCP、两向准备失败、挂起／取消、完整迟到 CAS 与两条原连接保持，另有本 APK 正常 LAN UDP 重验；逐 RUN 保存 Scope／receiver／tracker／正文及恢复证据 |
| 6. 具体缺口 | 本轮原始签名与正常投影已完成离线核对；最终身份双读、偏好恢复已由下述最终窗口的正常入口完成，精确清理另留记录；正常 UDP 不写成故障期间 UDP，通过范围不外推实体 LAN 拓扑、正式制品或生产激活 |
| 7. 下一入口 | 阶段 3 的实际业务与远端链单独取证；后续有界 epoch 保留原身份与认证进度，正常回读和清理不以原件验签代替 |

已签名的部分报告规范往返仍由 `TestCurrentReportSignsIndependentLANSelections` 覆盖：
Internet 已确认而 LAN 未齐、LAN 已确认而 Internet 待选、双意图部分执行的保守 `unknown`
均保持规范签名；Android 未齐时不伪造整实例 applied 或 selections。此前正常组合窗口的签名
原件与本轮 `.28` 故障原件均已各自离线核验；部分确认的规范测试不充当本轮手机实际报告。
本轮两 epoch 的 `closure-audit-reviewed.json`／`closure-reviewed.json`、精确源码／制品摘要、
失败和清理原件仅在 `deploy/evidence/2026-11-07-multiforward-linktrace/phone/` 的各自窗口内。
原件审计结果、输入摘要、停 producer 凭证及只读矩阵保存在同一证据根的
`signed-report-audit-*.json` 与 `scope-raw-audit-*/`，实际序列和指标只进入私有证据。
独立 Gateway 使用隔离测试 LAN，不外推外部实体局域网拓扑。当前核心工作项保持 open，
未执行正式发布或生产激活。

### 现有六节点的只读测试准备

操作者明确测试隔离针对实例和影响范围，不要求新增物理机器。六节点经既有严格部署加载器
与 SSH 执行器有界并行只读核对，正式身份、职责、安装与运行字节、资源及已有映射均有回读。
生产程序来源仍为 `fd274e04`、数据面仍为 `.15`，未替换它们；认证公共资源与实际运行回读
分别保存，不由声明数推导物理 peer 或会话数。

实际 F1、F2 和境外 E 已从不同既有主机选定，备用出口亦已登记；位置依据是认证部署标签及
既有操作史，本轮未重新做物理地理定位。一个原候选只有生产已占用入口，已改选有操作者提供
空闲映射的出口，不占生产端口。管理坐标与 SSH 实际地址的一项历史差异保留为事实，未编造
隧道原因或修改配置。真实分工、坐标、来源和差异仅在
`deploy/evidence/2026-11-07-six-node-readonly/final-redacted-summary.json`。

后续复用既有远端隔离工具：每台主机独立测试目录、身份、材料及 user／net／mount namespace，
以 slirp 消费原映射。测试入口必须取得真实认证传输及回包证据；空闲监听不证明 NAT 可达。
故障只作用于测试 namespace 的精确测试链路，不停止或替换生产实例、不修改生产授权／密钥、
宿主默认路由／DNS／防火墙或路由器映射。本节尚未创建远端测试实例或验证新测试端口。

## 阶段 2：诊断错误链与 Echo 关联续验

2026-11-07，本节继续使用 `c5fb6b10` 加本轮工作区源码快照；构建前后逐文件来源一致，
不把基线提交号当成包含所有修改的干净提交。Transport Echo、指定 Policy 的 Admission Echo
与普通 TCP／UDP 业务保持三个独立结果；观测失败不能撤回授权，真实认证拒绝和撤权仍须拒绝。
未改变候选模型、稳定选择、固定最终出口、逐跳认证或 schema 3，也未增加重试掩盖故障。

代码反例确认 Hy2 首跳循环曾丢弃解析、拨号及认证的原始 cause，最后只返回通用认证失败。
修复保留各次错误与阶段、耗时，通过错误链保全取消／超时的 `errors.Is`／`errors.As` 语义。
WG 本机连接失败同样保留阶段与 cause。两传输共用的 Echo 往返明确区分 preface 写入、
请求写入、响应读取和响应校验；远端明确拒绝为 `ErrEchoDenied`，明确不可用为
`ErrEchoUnavailable`，畸形响应或 nonce 不符独立报错。合法响应的接收端处理时间不能比较时，
保留接受结果但不制造 RTT。原生 HTTP 502 仍不传出内部原始 dial cause，须配合同次 native
诊断证据；不能称所有跨层错误正文都已透传。

本轮用现有 Echo nonce 的 SHA-256 派生关联 ID，不新增 wire 字段或授权身份。root、mobile
与两传输 native 的 Debug 记录覆盖请求开始、peer 准备、内部连接、请求发送、接收请求、
认证身份、Receiver Echo／Admit、响应返回及最终超时／取消这些事件位置。安全解析只接受
固定格式的 ID、阶段、耗时、结果与错误类型，不记录原始 nonce、帧、密钥、凭据或业务目标，
不增加正常业务高频 Info。日志失败与 observer panic 不改变既定结果；Linux 仅显式
`client run -trace-probes` 开启，默认关闭。启动与热更新共用同一 Debug 配置投影，已用
先失败后通过的 reload 回归阻止仅因日志级别不一致而误替换运行实例。

测量完成时刻、有效期与各阶段耗时先固定，再交付诊断日志；完成标记只记一次，测量预算等
实际 flight 完成才释放，复用中的调用不能借另一请求的时间戳。root／mobile 的反例和普通／
race 回归均通过。同步日志消费者仍可能延迟调用返回，不将此表述为日志完全不影响等待时间；
本轮没有增加独立日志队列或后台状态机。

native 定向 race 实际发现既有 `pause.WaitActive` 无锁读取 channel、与暂停状态更新并发的
数据竞争。独立纯内存反例在原源码报告 race；修复仅在锁内取得 channel 快照，等待仍在锁外。
修复后反例及相关包普通／race 通过。旧 `.27` 的原精确 transport 关闭单项本轮未复现该 race；
不能把新反例或锁修复当成原手机超时的根因。

| 实际检查 | 本轮结果与边界 |
|---|---|
| 错误链反例与回归 | 原反例失败保留；clientadapter 定向普通／race 各 36 个通过事件、无跳过 |
| 完成计时与隔离 | root 定向普通／race 各 46 个通过事件，mobile 各 9 个；反例及最终来源快照保留 |
| native 诊断与暂停修复 | 六相关包普通／race 各 170 个通过事件；纯内存 race 红绿记录独立保留 |
| 官方原生入口 | `python3 scripts/test-native-dataplane.py` 的来源、正反补丁、协议副本、关键集普通／race 各 244 个通过事件，无失败／跳过；正式 Linux amd64 构建与来源读回通过 |
| 根模块完整检查 | 最终 `go build ./...`、`go test ./...`、`go vet ./...`、仓库安全与 diff 检查均退出 0，全部 tracked／untracked Go 格式检查无输出，源码输入前后相同；本阶段未重复根全库 race，不借历史结果冒称本轮全库 race |
| Android 官方构建 | 双 ABI AAR、91 项 JVM、lint、Debug APK 与 instrumentation APK 均通过；AAR／APK 两 ABI 库逐字一致，与 Linux 来源记录相同，Debug 签名核对通过 |

Android 沿 `clients/android/scripts/build-mobile-aar.sh` 和 Gradle 的
`testDebugUnitTest`、`lintDebug`、`assembleDebug`、`assembleDebugAndroidTest` 正式入口构建，
并发有界。新增 native 修改登记为制品 `1.11.4-loom.28`，不是协议升级；`.27` 的历史来源、
摘要与原件字面冻结。Windows 继续引用 `.27`，本轮 Linux amd64 与 Android 双 ABI 独立固定
`.28` 来源；未构建的平台没有填入假摘要。源码、CLI、AAR、APK、库及签名的精确坐标只在
`out/diagnostic28/` 和受保护证据中。本节只确认构建及本地范围，不抵扣新 APK 的真机业务、
真实多级 Forward 或正式发布签名。

后续对既有远端 `.28` 原件的只读审计已定位一项实际 WG 失败：同一 flight 的 peer 准备成功，
随后内部 TCP 建连到期，本机 CONNECT 未建立，尚未发送 Echo 执行帧。安全 Echo ID 与 native
日志 ID 唯一对应，但未取得该 flight 的 Resource／Spec／Operation 映射，不能命名为某个出口
WG 或 Admission Echo。未匹配到接收端事件的结论仅覆盖已保存的三端日志窗口，不证明窗口外
没有接收；也不将 HTTP 层的最终超时分类说成内部原始 cause 已跨层透传。本项不是诊断与
普通业务的配对通过，原手机 WG Admission Echo 超时仍未定位。原件在
`deploy/evidence/2026-11-07-multiforward-linktrace/continuation-0002/`。

原手机 WG Admission Echo 超时仍未定位。新增九类事件接线及本地回归使下一次真实复现可
按同一 ID 追查，不能补写过去缺失的接收端证据。六行须逐行绑定实际精确制品、候选或路径、
Policy、证据来源与故障窗口；源码、隔离原生与手机证据分别判定，不要求共用一个全局环境、
Policy 或出口，也不要求全部在手机执行。

本轮新增 `TestOfficialLinuxNativeDiagnosticBusinessMatrix`，复用正式 `Run`、签名 LKG、
持久偏好及既有 `.28` native，在独立 user／net／mount namespace 内取得下列真实配对。
每行绑定实际候选、Policy、规格及窗口，有测量的行另核真实样本有效期；成功业务均完成
SOCKS5、证书／名称校验的
TLS 及完整正文，失败业务为真实关闭目标的 native TCP 连接失败，并读回对应 TCP 观测。
原 TLS tracker／UUID／资源链持续保持；测试未手写 selector、伪造 Observation 或修改权威。

| 诊断结果 | 真实业务结果 | 本轮隔离原生实际证据 |
|---|---|---|
| 成功 | 成功 | 真实 Receiver 接受响应交付，完整 TLS 正文成功 |
| 超时 | 成功 | 仅暂扣本次诊断真实响应至调用到期，合法候选上的完整 TLS 业务继续 |
| 失败 | 失败 | 本次诊断响应交付真实 EOF；另一个关闭目标的实际业务连接失败 |
| 成功 | 失败 | 真实 Echo 接受，关闭目标的实际业务连接失败，不制造业务成功 |
| 未知 | 成功 | 正式 Run 首次合法选择且尚无真实诊断观测时，完整 TLS 正文成功 |
| 未知 | 失败 | 同一正式 Run 未测窗口，关闭目标的实际业务失败及反馈读回 |

未知两行使用正式 Run 的首次 running／合法 selector、`ResourceObservations` 为空的真实
窗口；仅在现有测量回调前等待，最终返回真实当前时间，不伪造时钟。释放后取得正式采样
恢复的真实观测。其余四行复用额外一次真实 sampler flight，保留响应状态、原 Observation
及阶段绑定；未将它们注入正式 Run 缓存或权威，不能称 daemon 已消费这些额外失败样本。
其中诊断超时／失败只控制该诊断响应交付，不冒称 underlay 故障；失败／失败一行也不冒称
诊断交付 EOF 与业务目标拒绝来自同一个远端故障。以上六行完成隔离原生配对，不能抵扣
手机普通 UID 业务或正式 Run 消费额外失败诊断样本的集成结论。

另有两类真实网络 deadline 续验。精确测试 UDP 代理丢弃实际加密 WG 报文后，关联日志为
peer 准备成功、内部 TCP 到期、本机 CONNECT 未建立且未发送 Echo 执行帧，真实新业务亦
失败；解除该丢弃后同候选／Policy 的完整 TLS 恢复。执行确认窗口只在测试 namespace 对
一个合成目标的 TCP SYN 精确丢包，实际读到 SYN_SENT；同一 native ID 的 peer 准备及
内部 TCP 成功，随后原有执行确认期限实际到期，调用方期限尚未到期。接收端仅该测试配置
的目标拨号等待长于原生确认期限，未改产品期限；否则原先较短的接收端拒绝不能充作确认
超时，首次失败原件已保留。旁路原 TLS 持续成功，删除经回读核对的自有 filter／qdisc 后，
同目标完整 TLS 恢复。安全日志 reader 最小补收既有 `execution-confirm` 阶段，原 native、
远端 CLI、AAR／APK 字节未因此重建或替换，不能把后续 reader 来源写入历史制品来源。

上述定向普通／race 均无跳过通过；先确认只有 loopback 且无外部路由，才生成并仅在测试
namespace 绑定合成地址。宿主 namespace、IPv4／IPv6 路由／规则／链路／地址及解析器摘要
前后结构一致，仅排除自然到期字段并保留原差异；未采集防火墙前基线，不宣称防火墙前后
一致。最终全库普通检查在独立 net／mount 与私有临时目录执行，保留原用户映射供真实非
root 权限测试使用；首轮仅 root 映射导致的两项权限夹具失败保全，未改源码或测试绕过。
peer、认证拒绝、撤权、用户取消及远端明确拒绝的既有证据仍按各自来源判定，不统称一个
unavailable，也不以本轮两项 deadline 外推全部错误类型已完成普通业务配对。固定出口约束
保持，禁止 Direct fallback。
原始红绿日志及来源摘要位于 `out/phase2-diagnostic-*`、`out/phase2-echo-*`、
`out/echo-diagnostic-native/`、`out/diagnostic28/root-checks/`、
`out/native-dataplane-tests/run-r9v86y9o/` 与
`deploy/evidence/2026-11-07-native28-preparation/`；CLI 来源另在
`deploy/evidence/2026-11-07-diagnostic28/`。本轮六行、两项 deadline、失败原件、最终源码与
全库检查在 `deploy/evidence/2026-11-07-multiforward-linktrace/phase2-paired-isolated/`，安全
日志 reader 的红绿与独立 CLI 来源在 `deploy/evidence/2026-11-07-diagnostic28-confirmtrace/`。
真实多 Forward 由后续独立记录，不继承本节隔离原生或阶段 1 旧 APK 的结论。

| 报告字段 | 阶段 2 当前记录 |
|---|---|
| 1. 提交 SHA | `c5fb6b103689761781ec0ba59811e762e2ca1345` 加本轮未提交工作区；每次构建和验证的真实来源另以摘要冻结 |
| 2. 修改文件与理由 | `protocol/diagnostic.go`、`internal/clientadapter/*probe*.go`、`measurement_budget.go`、`mobile/loomcore/resource_probe.go` 及 Android 完成日志保留原错误与真实完成时刻；Linux `probe_debug.go`、启动／热更新接线与 `forward.go` 增加显式安全诊断；native 补丁修正等待竞争，制品来源登记同步更新；对应测试和官方构建脚本保留反例 |
| 3. 已修复缺陷 | Hy2 原始 cause 丢失、日志交付前未固定真实测量完成时刻、`pause.WaitActive` channel 读取竞争；未将夹具失败或本轮内部 TCP 到期称为历史手机超时根因 |
| 4. 命令与结果 | 官方 native 脚本普通／race、Android AAR／JVM／lint／APK 及根 build／test／vet 通过；`TestOfficialLinuxNativeDiagnosticBusinessMatrix` 的独立 namespace 普通／race 无跳过通过；上述两类真实 deadline、日志 reader 反例及对应回归通过，精确参数和产物摘要见私有记录 |
| 5. 真实业务证据 | 正式 Run 六行真实诊断／TLS 配对，目标失败和 TCP 反馈、旁路原 TLS 保持、解除精确丢包后同目标完整 TLS 恢复；这是隔离原生业务，未声称全部发生在手机 |
| 6. 具体缺口 | 原手机 WG Admission Echo 超时仍未定位；部分配对是独立真实 sampler flight，未声称 daemon 消费了额外失败样本；跨 HTTP 的内部原始 dial cause 仍需同次 native 关联 |
| 7. 下一入口 | 阶段 3 用精确 APK、真实异网节点、正常共享测量、实际 CAS、新旧连接及固定出口证据分别判定；下一次 WG 实际复现沿现有安全 ID 追查 |


## 阶段 3：既有异网节点与当前 Android 制品的首轮窗口

2026-11-07，复用前述六节点只读核对中选定的三台不同主机，分别执行 F1、F2 与境外 E。
每台具有独立测试身份、目录、监听及 user／net／mount namespace；只消费操作者原有且实际
空闲的 UDP 映射。生产实例、身份、密钥、授权与安装路径没有被测试实例接管。正常 Link
回显及跨节点响应已证明本轮使用的部分真实传输入口可达，不能再把整体缺口笼统归为 NAT。

本轮正常 Invite／加入、沿用原互联网 Service 及新 Policy／设备授权写入限定手机经 F1 接入、
可经 F2 中继且只允许同一
最终 E；不授权 Direct 或本机出口。新 `.28` APK 经同签名覆盖安装，安装后实际字节等于
冻结 APK，原身份、密钥、认证进度、报告序列与 latch 保留。手机通过正常配置更新、Policy
选择和连接入口运行；Linux 三端均消费正常认证配置并产生真实签名报告。

精确 APK 在此窗口取得普通境外 HTTPS 完整正文；另两条普通 UID TLS 连接持续取得完整
响应，原 UUID、tracker、资源链及 native Box 有读回。出口 IP 的地址族与摘要和同一 E
namespace 的独立读回匹配。普通浏览器也显示了目标页面，但 UI 文字不证明其全部网络依赖。
这只抵扣本轮制品的已取证业务，不能当作自动中继或完整应用依赖验收。

故障工具只在测试 namespace 的精确链路设置报文时延：先保持直达 E 的基线，再只降低
F2→E 时延。正常签名共享样本覆盖三段，来源、完整规格与当前 F1 视图匹配；跨节点同一
Echo ID 能关联发送完成与接收认证／Admit／响应写入。纯函数对实际输入回放可得经 F2 的
合法优选，但在本轮有界观察内没有取到 F1 自动反转的必要证据。未手动 PUT selector、
伪造 Observation、修改 Policy 或以重新授权推动切换。

Forward 的当前顺序须读 `exit_choices[final_exit]` 及 CAS revision；通用 `now=reject` 与空
`targets` 是其正常投影，不能误判为尚未应用。本轮 F2 的真实顺序更新不能替代 F1 所需
反转。两条旧 TLS 在质量变化期间保持业务，也不能写成“已跨成功自动换路保持”。尚无
换路后新连接经过 F2、换路前后同一出口 IP，以及五项失效／恢复／撤权的完整矩阵。

本轮 F1 的只读 nil-base 共享样本领取成功，不能证明原 daemon 的历史 cursor／delta
领取与运行内存。为下一窗口增加显式 `-trace-probes` 下的安全摘要：批量领取／实际消费
的集合摘要、校验结果，及选择排序、pending、确认次数、原采样版本和 CAS／确认结果。
标识只输出摘要，错误只输出有限类型；已合并缓存不能反推服务端 reset／delta，故该字段
明确为 unknown。日志在原计算和发布边界之后交付，不能改变选路规则、缓存失败语义或
原时间；同步 sink 仍可能延迟返回。新增 CLI 独立冻结，不把原 AAR／APK 称为来自后续
修改的源码树，也不重建或替换本轮已取证的 Android 字节。

首轮封存原件的后续时间审计表明，支持反转的第二份远端新样本靠近观察末端才进入签名
报告；未证明 daemon 在窗口内还有再次领取、消费与确认的机会。旧源时钟偏差亦缺少界限，
不能由条件同钟统计推断缓存或算法缺陷，也不能因此将未观察到的自动反转改记为通过。
后续使用真实消费／确认记录判定，保持原性能条件及原采样有效期。

隔离入口准备的失败原件均保留：证书用途、规范输入末尾字节、私有 `/run` 导致解析器
符号链接目标缺失，以及父执行器曾未传播子进程失败。修正仅作用于测试工具、测试证书或
私有 namespace，保留原 CA、身份与认证进度；不能把这些夹具问题当作生产缺陷或历史 WG
超时根因。原手机 WG Admission Echo 超时和本轮 F1 未反转原因仍未定位。

窗口结束后手机正常断开并恢复原偏好，正常更新接受测试授权撤回；独立加密存储重复读取
与缓存一致。三端先正常退出，再归档全部测试身份和状态，最后按精确所有权删除测试目录；
本机辅助映射与凭据精确清理。六节点重新建立管理连接，生产字节、长期进程和原生产监听
保持；DNS／防火墙前后比较只覆盖实际保存了基线的节点和窗口，不补造全六节点相等。
全部生产者和本地 control owner 退出后，严格离线审计通过本轮规范报告、签名、来源键、
序列、分叉、共享测量原件与页面引用；手机确有固定 Policy、已确认选择且 applied 等于
认证 View 的 running 原件，数据库前后字节、inode、大小与时间保持。页面快照取到的
unknown／stopped 不能反推出整个窗口没有 running；报告真实性也不抵扣自动中继。
完整普通业务、失败窗口、来源、清理和回读位于
`deploy/evidence/2026-11-07-multiforward-physical/`、
`deploy/evidence/2026-11-07-multiforward-executor28/` 与
`deploy/evidence/2026-11-07-six-node-postcheck-3383468160880184/`。

阶段 3 保持未闭合；下一窗口复用同一执行工具和既有三台主机，以新 CLI 的实际消费证据
定位缺口。已删除测试设备的墓碑不能复活，下一轮按正式加入建立新的测试设备；旧原件和
身份历史保全，手机原身份不变。阶段 1 的手机局部故障和阶段 2 的真实配对矩阵仍单独保留，
不因本节正常境外业务成功而判定通过。正式发布、生产激活均未执行。

## 阶段 3：同身份续窗的真实自动反转

续窗复用既有三个异网主机、同一独立测试 authority 和原工具。新测试身份正常加入后，同根
执行 epoch 之间只轮换已停止的执行元数据，保留身份、密钥、认证进度和报告序列；首轮已
删除设备的墓碑不复活。手机仍为相同 `.28` APK，Linux 测试实例独立冻结 CLI 摘要以
`0bfe4fcf` 开头；native／AAR／APK 不重建，生产实例不替换。源码 HEAD 仍 `c5fb6b10`
加未提交工作区，后续 Linux 日志白名单修正产生的独立 `073838d7` CLI 尚未在该窗口运行。

在真实普通 HTTPS 与 LAN TCP 原连接持续运行时，仅降低 F2→E 的测试链路时延。F1 的
真实共享测量领取、消费、pending 与原样本版本确认已保存，实际 Forward CAS 从直达 E
改为经 F2；Policy、最终 E、授权和手机首跳不变。只读领取与消费的整集合摘要不能逐条证明
某个 UI 样本进入缓存，已合并读取亦不能反推 wire reset／delta。自动反转本身由实际 CAS
及正常 GET 证明，不用纯算法回放、F2 的选择或手机首跳代替。

旧两条业务的手机 UUID／资源链、本机端口、Box、各自 Policy／revision 保持，完整响应
继续增加；旧 HTTPS 在 F1 的原 tracker 仍直达 E 且双向字节增加。随后另建普通应用 HTTPS
连接并取得完整正文，三端实际连接分别显示 F1→F2、F2→E、Egress，第二次回读同一 tracker
的双向字节继续增加。F1 新 tracker 不在换路前完整旧集合中；F2／E 未保存新流前的完整
集合，仅据独立 UUID、唯一普通目标上下文、实际资源链与连续字节增长关联，不制造跨节点
全局 UUID 或要求不同层字节相等。手机换路前后出口 IP 的地址族与摘要相同，且匹配同 E
namespace 的独立读回。原 Scope worker 此后正常停止，其保持证明不外推后续刻意丢包。

接着仅对 F2→E 的测试链路注入丢包。首个普通 HTTPS 实际连接超时，VPN 仍已连接，原件
保留；真实失败样本经正常报告传播后，F1 自然回到直达同 E，后续新普通请求取得完整正文。
两次请求和传播观察分别记录，不以后一成功覆盖首败，不宣称即时或零中断恢复。未修改
Policy／最终出口、伪造 Observation、手工写 selector 或增加重试。该链路已恢复健康；
持续运行内的新鲜恢复样本／再选 F2 与精确撤权另行取证。

本窗口手机、Gateway、三端 client／native、relay、bridge 及本地 control 已正常退出，
实际 foreground join 与 owner 读回保留。辅助 UI 脚本曾未找到滚动区外的断开按钮，失败
原件单列；最终通过产品 UI 正常断开，未 force-stop。手机断开晚于 control 停止，不声称
手机最终 stopped 报告在此之前送达。原手机身份与密钥、latch 保持，正常验证器确认认证及
报告进度前向；最终持久双读、全链路签名原件审计与精确清理仍须分别完成。

实际 CAS、旧流、新流、出口与故障首败／恢复原件位于
`deploy/evidence/2026-11-07-multiforward-linktrace/continuation-0002/` 与同窗口 `phone/`。
下一同身份 epoch 已分别验证两条链路失效。F1 原首选为直达 E 时，只对 F1→F2 的两传输
丢包；正常报告出现两项新的 unavailable，实际首选保持 E，普通 HTTPS 完整成功且出口
IP 摘要相同。该项不称自动首选切换。恢复后正常报告取得 F1→F2 的新鲜 available，并
确认 F2→E 可用、各自当前网络代及未过期，才开始下一项故障。

随后仅对 F1 直达 E 的两传输丢包。首个普通 TCP 请求超时并单列保留，F1 后续实际 CAS
从 E 改为 F2。该节点为 forward-only，冻结源码的选择入口不接收 native TCP 反馈；这次
CAS 来自正常 Link／共享测量链，未证明究竟哪次本机回调先触发。故障切换没有两组性能
确认，不能套用先前质量优化的确认解释。换路后两条普通 TLS 均持续取得完整正文，三端
完整新流前 UUID 集合排除旧流，两次回读的新 UUID／链保持且双向字节增长，明确经过
F1→F2→同 E。出口 IP 摘要仍相同，工作负载随后正常停止，持续失败为零。原件在当前
窗口 `continuation-0003/`；它补齐此案例三端的新流前集合，不补造前一案例缺失的集合。

本 epoch 解除 F2→E 故障后，正常报告回读取得合法备选的 available 样本；未要求实际首选
立即反转。恢复前已有的普通 HTTPS／LAN TCP 与恢复后新建的双 TLS 分属两个独立 RUN，
均实际取得完整 2xx 正文。相同 app 的单调时钟证明：新 RUN 达到真实 baseline 后，旧 RUN
的两个原 socket 仍继续响应，connection ID／端口保持；不跨 RUN 拼接连续性。前置只读
capture 已把旧两流绑定到各自手机 native tracker，F1 的唯一普通目标上下文实际使用 E
传输；新 RUN 缺少对应三端 tracker，不把其正文成功写成新流已经实证经过 F1→F2→E。

窗口末三个 TLS 约同刻 EOF，两个 worker 随后均为 `failed` 且 cleanup 已确认，原件完整保留。
远端一小时 TTL 已结束，实际 namespace／client／恢复后 relay 均退出，Root 后续 stop 操作
发生在这些 owner 已死之后；原 relay 外层失败也另存。该末段受 TTL 停机干扰，不能算撤权、
产品故障或无故障持续运行通过。没有本窗跨机时钟偏差区间，不由各源墙钟推断精确 TTL／EOF
先后；恢复后已取得的正文与旧 socket 保持区间按手机单调时钟单独成立。

既有默认浏览器已在本次独占创建的普通测试 tab 完成 document、CSS、三个 JS 和 image。
六项均按本次 loader／request ID 逐一核对 request、response、loadingFinished 的实际事件序，
取得 200、有效 TLS、非缓存／service worker 的完整传输，并核对必要 DOM、样式、脚本和图片
结果。私有 helper `30308e6b` 实际退出 0 并 join，仅关闭本次 tab、精确移除本次 forward，
app／浏览器 owner 与原映射保持。旧 helper 对 response／finish 时间戳的额外排序假设误拒，
以及正常前台前 metadata 请求超时，均保留原件；未据此定位浏览器冻结原因。此轮没有观测到
新建 HTTP 连接，CDP 成功不单独证明下游 native 路径或出口，也不外推其他页面／应用。

限定恢复与浏览器证据分别在同窗口 `continuation-0003/recovery-existing-evidence-audit-*.json`
及 `phone/browser-final-summary-*.json`，实际时长、序列、UUID 与坐标只进私有证据。
至该 epoch 结束时，精确撤权、最终原件审计、持久回读及清理尚未完成；后续实际结果见下节，
不追溯改写本 epoch 的失败或缺失证据。正式签名制品与生产激活未执行。

## 阶段 3：精确撤权与最终保全

最后一个有界 epoch 仍在相同三台异网主机、同一组测试身份和原 `.28` APK 上执行。Linux
原测试 CLI／native 不变，仅外层既有 SSH 执行器显式复用已有保活参数；未修改 sshd、NAT，
未重启 namespace／client／native 或生产实例。上一 epoch 私有 control relay 的外层 SSH 曾复位，而 namespace、
client、native 与其他 relay 仍活；只恢复精确 relay 后正常配置领取／消费／报告恢复。原复位
原因未知，不把当时 control 不可用的业务失败当作选路算法缺陷。

先取得正常 F1→E 首选及三段当前规格、网络代、未过期 Link 样本，只降低测试 F2→E 的实际
报文时延。F1 由正常共享测量和稳定确认完成 E-Hy2→F2-WG 的实际 CAS；pending 变化及
新采样进度均在原日志读回，没有手工 selector 或重新授权。旧 HTTPS／LAN 的手机连接、
UUID、资源链与 Box 保持，完整响应继续；F1 旧 HTTPS tracker 仍直达原 E 且双向字节增长。
新建双 TLS 后，三端完整旧 UUID 集合均排除这些新流，两个时点的真实资源链与增长分别
证明 F1→F2-WG→E-Hy2→互联网。这里不制造跨节点统一 UUID，也不要求层间字节相等。

随后只沿正常 `policy.put` 从该测试 Policy 的 RelayScope 移除 F2，其他字段和无关对象的
认证 head 保持。三端均接受新 View／权限证明并应用；F2 的相关转发消失，原其他 Policy
保持，F1 仍有直达同 E 的合法资源。两个新 F2 TLS 实际 EOF，worker 为 `failed` 且注册
socket 均清理，三端对应 tracker 消失；手机原直达 E HTTPS、LAN 的 UUID／链与 Box 保持，
同一旧流完整正文和双向字节继续增加。撤权后的新普通 HTTPS 完整成功，出口 IP 的地址族
和摘要仍匹配此前同 E 的独立读回；N4 没有另做一次 E 端独立 IP 读取。授权变化会正常提高
确认 revision，不能要求整份内存
字节不变。额外一次超过计划观察上限的回读另标，不伪称都在该限内；未取得的拒绝日志
字段不补造。旧 worker 后续自然到达自身有界寿命，不将其末段称为撤权关闭。

故障与恢复矩阵按各自独立窗口判定，不能把不连续 RUN 拼接为一个长连接：

| 场景 | 正常测量／实际选择与业务结果 | 范围限制 |
|---|---|---|
| F2→E 失效 | 正常失败样本传播，F1 回到同 E 的直达首选，后续普通正文成功 | 首请求实际超时保留，不承诺零中断 |
| F1→F2 失效 | 非首选链路两传输新 unavailable，原 E 首选、普通正文及同出口保持 | 不称首选切换 |
| 直达 E 失效 | 首请求失败后正常 Link／共享测量驱动 F1 CAS 至 F2；新双 TLS 三端 tracker／资源链、正文及同出口通过 | forward-only 入口未消费 native TCP 反馈，不套用性能优化确认次数 |
| F2 恢复 | 解除精确故障后取得当前规格／网络代的新鲜 available；新普通业务成功，原两 Scope socket 在独立同钟区间继续收发；最后 epoch 再由新样本实际选 F2 并完成三端新流取证 | 恢复 RUN 缺三端 tracker，末段 TTL 停机不计持续业务或产品失败；不强加恢复后立即首选反转 |
| 精确撤销 F2 | 正常新权限三端应用；仅新 F2 流关闭，旧直达 E／LAN 保持，后续新正文及同出口通过 | 不外推未测试 Policy 或所有传输组合 |

测试后先正常恢复该 Policy 的 F2 范围并回读，再由手机正常 UI 断开、恢复原 Internet 偏好及
空 LAN 偏好。Gateway／远端 client、native、relay、bridge 和 namespace 的真实 foreground
均退出；最后 accepted running 报告不倒写为 stopped 已送达。先归档三端身份、状态及签名
历史，再对全部指定测试根整树比较，全体通过后并行精确删除；本机归档和 authority 原件保留。
LAN Service／Policy、Gateway 临时角色、手机测试授权和多 Forward 测试材料均通过正常
新事实撤回。一次正常 snapshot 读取失败的原始原因未保留，后续同入口读取成功并按原
请求继续，不臆测认证或产品故障，也不改写历史 head。

全部授权清理之后，手机再次通过正常“检查更新”接受最终认证前沿，保持原偏好及断开状态。
正常 CLI `export-device-view` 的规范字节与手机 LKG 一致；完整身份验证器及两次独立加密
存储读取等于缓存，原身份、密钥、claim、invite、latch 保持，high-water／认证拒退边界和
报告序列均前向。原身份只在专用消费者内读取，不保存明文副本。此前清理回执明确标记
尚未验证最终手机接受；其 false 原样保留，以独立 POST 证明补齐，不回写旧回执。

本地 control 随后正常停止，原 foreground 实际退出 0，namespace／slirp 均退出。手机动态
RUN 的自有 nonce 文件、API 凭据和精确映射已清理，forward／reverse 恢复原基线；无引入
归属证明的共享 jar／UI dump 保留为非运行文件。全部生产者与 control 停止后，冻结审计器
实际退出 0：五源完整报告的规范字节、签名、数据库键、序列／分叉／因果、签名历史身份及
全部输入正常 snapshot 的报告／测量引用通过。共同 running 原件存在；手机末份原件为
stopped，其他源的最后已收签报仍为 running，其停止由独立 owner／join 证明，不补造报告。
数据库摘要、inode、大小、mtime 和 authority 原件均不变。

旧 snapshot 仅按原 SHA 定位已迁移的原件；新增嵌套 capture 格式只按唯一 JSON key 的原
字节偏移提取正常对象，绑定来源、偏移、长度与摘要，不重编码或改动签名 RAW。该输入
取证不声称片段就是原 API wire，也不将报告真实性当作业务成功。最终原件与命令在同根
`final-signed-raw-audit-*/`、`signed-report-audit-*.json`，六节点新连接回查另记。

最终复用既有执行器并行取得六节点新 SSH 只读回读。Loom 身份、程序／清单字节、长期
进程的 PID／启动时间／namespace、已有服务字段及 IPv4 route／rule 均与最初材料相同。
完整 TCP／UDP／Loom Unix 监听按端点核对；本机手机辅助 API 移除后补读，没有新增端点，
消失的旧测试监听逐项绑定同一 slirp owner 与停止证明。bridge 的精确 gc_timer 字段及
地址自然寿命变化单列；一项相同 UDP 端点／owner PID 的 fd 编号变化不伪称新端口。

回查仍有两个具体未解释变化：一台主机相同 Nginx 监听的 worker PID 集合更替，以及一个
未参与转发测试的备用节点输入防火墙 ACL 实际增删。后者不只是计数器；初始六节点没有
防火墙基线，现有证据只证明前次回查到本次的差异，不能确定写入者或归因本任务。原严格
比较的 false 保留，稳定字段通过和这些未知分别记录，不宣称全六节点防火墙或全部进程
从未变化，也不为清零差异修改生产。实际三台转发测试主机的防火墙与已保存的早期 preflight
相同，DNS 只按实际较晚基线判定；未新增全六节点
IPv6、WireGuard 握手、宿主代理或公网主动业务验收。宿主本机另有完整 IPv4／IPv6 路由、
规则、接口、地址、namespace 与 resolver 对照通过。六节点原件及严格差异在
`deploy/evidence/2026-11-07-final-six-node-postcheck-*/`，不会用后采材料冒充初始基线。
本节实际 CAS、新旧流、精确撤权、正常最终接受和三端归档／删除原件在
`deploy/evidence/2026-11-07-multiforward-linktrace/continuation-0004/`、同根 `phone/`、
`authority/` 与 `lan-attach/`。真实坐标、指标和签名原文仅保留于私有证据。

2026-11-07 最终收敛只读补审继续使用以上原件，未重跑故障矩阵。既有摘要／引用、实际
CAS 日志及完整 tracker 原件核对通过；后续 epoch 三端各两条新 TLS 均排除完整旧 UUID
集合，两次双向字节增长且撤权后消失，原直达 E 增长及手机局部关闭／旧 Scope 保持一致。
前一恢复窗口的两个独立 RUN 及各自 EOF、failed、cleanup、TTL 边界不改记通过；后续
epoch 有独立 namespace owner 身份及自己的实际选 F2／三端新流证据，未拼接旧 RUN。
各源时钟偏差仍未知，不补造 TTL 与 EOF 的精确顺序。浏览器六项依赖及正常清理通过，
未观察新 HTTP 连接的限制保持；现有原生 HTTPS 证据足以保留已验业务，不再展开浏览器矩阵。

本轮六节点新 SSH 只读回读均完成，与前次最终材料比较的身份、程序／清单、IPv4 main
路由及规则保持；未发现原多 Forward 测试根或其 Loom／native 进程。环境溯源扩大了历史 journal
覆盖，新增证实原异常主机发生过 Nginx 服务 stop/start，触发者仍未知；不将这一后得证据
写成前次窄窗口已知。备用节点 ACL 继续真实增删，现装厂商脚本可见相同链名，但没有
能对应历史写入的 audit／操作记录，写入者及原因保留未知，不能按自然计数过滤。
测试执行器没有该备用节点的对应拥有操作记录，这也不证明某个外部写入者。SSH relay
原客户端 reset／broken-pipe 及 wrapper 非零退出，与 relay 自身正常退出分别成立；
服务端窄窗口关闭类日志缺少同请求身份，不能以邻近事件归因，也不与 Forward 故障混写。
没有补造六节点初始防火墙基线或主动 IPv6／WG／代理／公网业务证明，未改生产服务、ACL
或宿主网络。只读采集器均真实退出并 join；首轮 service 列表状态符解析和 SSH 过宽计数
窗口只影响取证，已保留原输出并以修正后的窄窗口续查，未改变产品结果。
补审原件、精确命令及来源在 `deploy/evidence/2026-11-07-convergence-audit/` 的
`forward-final-audit-expanded.json`、`environment-final-review.json` 和
`six-current-baseline-summary.json`。原报告离线审计结果仅重核文件引用与摘要，未另开活库，
也未把本次只读审查说成重新执行全量验签或业务。

| 报告字段 | 阶段 3 当前记录 |
|---|---|
| 1. 提交 SHA | `c5fb6b103689761781ec0ba59811e762e2ca1345` 加未提交工作区；实际远端 CLI `0bfe4fcf`、native 与已安装 APK 分别固定来源；后续 `073838d7` 日志 reader CLI 未部署 |
| 2. 修改文件与理由 | `internal/clientadapter/forward.go`、Linux `private_io.go`／`probe_debug.go` 及相关测试补显式领取／消费与稳定选择证据；不改选路算法。其余拓扑、故障、浏览器与清理工具仅在忽略目录复用既有入口，未另建部署平台 |
| 3. 已修复缺陷 | 本阶段未证实新的多 Forward 产品算法缺陷；修正一次性工具的证据门禁、浏览器事件序假设、规范删除请求与本次已接受事实的清理输入，原失败保留 |
| 4. 命令与结果 | 正常 CLI 加入／配置／运行／`policy.put`／撤回／导出，手机正常 UI 与既有 UID worker、三端只读 tracker、精确 namespace 链路工具、owned browser helper 均实际执行；最后三端 check 全通过再并行 delete，真实退出 0；根完整检查见阶段 2 |
| 5. 真实业务证据 | 精确 `.28` 手机、异网 F1／F2／境外 E，正常测量驱动实际 CAS、新流经 F2、旧直达流保持、同出口、五项故障恢复矩阵及一个普通浏览器页面的六项实际依赖；原失败与各 RUN 边界分别保全 |
| 6. 具体缺口 | 浏览器未观察新 HTTP 连接，不独立抵扣 native 路径；恢复末段受 TTL 干扰，已验区间与缺失 tracker 单列；六节点 Nginx worker／备用节点 ACL 的观测变化未归因，不宣称全项不变；历史手机 WG 超时、正式签名制品及生产激活仍未闭合，核心工作项 open |
| 7. 下一入口 | 按下节阶段 4 的正式 Policy 操作／精确 Service 重建／既定模拟图像扫码入口继续；阶段 5–8 保留各自设备、连续窗口和生产授权门禁 |


## 阶段 4–8 的后续执行入口

以下是前三阶段之后的执行计划，不代表已执行，也不新增权威状态、Policy 语义或资源池。
各项先核当前精确制品与既有实现，再补缺失的最小实测；真实手机期间不得并行干扰 ADB、VPN
或网络。真实坐标、逐字签名原件、失败日志与观测窗口仅进入忽略的私有证据。

### 阶段 4：Policy、连接与加入交互

复用 Android `ScopeApplicationTest`、`SelectorTakeoverTest`、
`SelectorOperationInstrumentedTest` 与正式 UI：启动旧请求挂起时手动选择另一 Policy，
新 revision 完整确认后释放旧请求，核对锁外 I/O、取消及真实 selector CAS 回读。随后执行
允许范围内的 A→B：旧合法 A 连接 UUID、资源租用与收发保持，新连接使用 B；再以正常授权
入口撤销 A，只关闭失权连接，B 保持。沿现有产品 Service 重建入口核对 Kotlin、JNI 与
native receiver，确认仅目标 Service 的连接重建，其他 Scope／Service 的连接、统计与
资源继续工作；不以重启整个 Box 代替精确操作。

加入复用 `InviteScannerInstrumentedTest` 的既有图像输入方法：ADB 模拟二维码图像，经过
真实 CameraX Analyzer、ZXing 与产品回调，不新增光学摄像头前置条件。用同一单调时钟记录
图像提交、解码、扫码回调、bootstrap、身份绑定、加密持久化、连接和首个普通业务完整响应；
重复连续试验并分别输出分段分布，不把不连续窗口相加。每轮检查正常界面回读及身份进度，
不为提速跳过正常加入或持久化。

### 阶段 5：跨物理网络恢复

沿现有 `NetworkProbe`、`UnderlyingNetworkSelection` 与 `LoomVpnService`，记录 Android
Network ID／网络代、实际接口、WG／Hy2 underlay socket 绑定、选择 revision、新旧样本及
新业务。分别执行 Wi-Fi→蜂窝、蜂窝→Wi-Fi，必要时不同 Wi-Fi 之间切换；旧代测量必须失效，
新代正常产生测量并恢复新连接。旧 TCP 不要求存活，但失效须如实报告；不重新加入或重置
身份、密钥、floor、high-water、latch 与报告序列，不修改宿主网络制造条件。

当前设备 SIM 非 ready，尚缺可用蜂窝数据条件；同一 Wi-Fi 断开恢复不能抵扣本项。可先复核
现有采集入口与身份只读基线，待蜂窝或相应物理网络可用后执行对应方向，不要求新增 Linux
测试机器，也不把不同 Wi-Fi 的结果替代蜂窝方向。

### 阶段 6：闲置、冷建与长期成本

复用现有 Lease、CAS、Receiver Fence 与纯发送资源池，结合当前隔离 Gateway 和真实手机
普通工作负载：两种传输可用时保留被选路径及旧连接，另一条无实际需求后，核对真实 WG peer
删除和 Hy2 会话回收；接收／管理基础保留。重新产生需求后核对冷建、新业务和迟到 Release
不能删除新 generation。使用现有 `/loom/resources`、`/loom/wireguard-counters`、
`/connections/`、正式运行回读及签名报告，不由描述对象数推导实际 peer 数。

按候选节点、Forward Link、测量目标逐档增加，先声明工作负载与连续观测窗口，再记录发送／
接收／管理 peer、实际 Hy2 会话、各节点／Link／目标请求量、签名原件及差量字节、CPU、
RSS／PSS、Loom 进程或 UID 的 RX／TX、Android 实际耗电与需求到可用的冷建耗时。保留采集
前后基线和原始样本；接口总流量不充当 Loom 独占流量，短时 RSS 不推导内存上界，短窗口不
宣称续航或长期成本已经验收。

### 阶段 7：Windows 实体终验

按 [Windows 测试环境](operations/windows-test-vm.md) 保留当前服务器开发与 VM 证据，
不重复已经通过的软件构建、安装或 VM 检查来抵扣实体缺口。复用
`scripts/windows-test-vm.sh`、`scripts/windows-full-tests.ps1`、
`scripts/verify-windows-installer.ps1` 与 `scripts/ui-review-windows.ps1` 的既有执行／
采集入口，先固定精确制品、日志路径与恢复步骤；VM 日常维护由代理负责。

Windows ARM64 实际运行、真实网卡切换、睡眠／唤醒、TUN 恢复、显示器／DPI 变化及原生 GUI
长期运行仍须对应实体设备。目前缺少该实体条件，保持待验；取得设备后逐项记录正常入口、
网络及管理安全、恢复后的新业务、身份进度与界面结果，不把 VM 判为物理通过。

### 阶段 8：正式制品与生产前向迁移准备

本轮不激活生产。先沿严格配置加载器、正常 inspect／签名 View 及服务回读，整理生产程序和
数据面版本、实际入口、节点身份、固定 WG key／Hy2 认证材料的受保护引用、签名 Material
原件、认证前沿、high-water、floor、latch 与报告序列；密钥正文不进入文档、参数或日志。
沿现有构建／打包／签名清单入口制定各目标的真实来源及签名计划，独立保留 `.27` 与本轮
Linux／Android `.28` 坐标，不伪造未构建平台摘要，也不将 Debug 签名当正式发行。

先准备停止精确数据 owner 后的逐字原件备份与验签、可验证的前向步骤、分批激活及重启恢复
回读、安全停止和不可回退约束。真正生产激活须在其他阶段完成并取得单独明确授权后执行；
届时各独立节点有界并行，先全体验身份、再分发实际所需制品，全部制品及规定 HTTPS 验证
通过才推进发布指针，始终保留管理入口。异常只停止或 compare-and-delete 本次确实拥有的
对象，不改生产授权／Policy／密钥，不删签名原件，不降低认证进度，也不恢复旧协议 fallback。

## 当前版本定向审查与修复

2026-11-06，起始工作区干净，分支 `main`、本地 `origin/main` 与 HEAD 均为
`1c387417fd916530395d532a77accc7bc28bb096`。本轮只做用户指定的定向审查、局部修复和本地验证；
未远端重新核验部署状态，历史操作与验收仍按原记录保留。本节记录提交前的本地验证；操作者
随后明确要求提交推送，修复坐标以 Git 历史及远端回读为准。未使用发布私钥，未执行发布、
部署、生产迁移或宿主网络配置变更。

Forward 的基线缺陷已经代码读回确认：候选标签本来绑定实际 TransportResource，派生 LinkID
也按网络／来源／接收资源／用途唯一，但 ForwardRoutePaths 仅按下一跳节点索引首段引用，
同节点 WG／Hy2 因而覆盖彼此。当前只保留现有 FirstResourceID 到 LinkSampleRef 的对应，
并核对来源、接收者及样本来源；suffix 继续按实际 LinkID 和完整规格定位。无签名字节、schema、
Policy／Service 关系或新权威状态变化，最终出口和稳定选择／CAS／确认流程保持。

原实现通过 Go overlay 运行新增回归时，直达／中继及 RTT 两种方向四组均按预期失败，日志在
`out/current-review-baseline/regression-before-fix.log`；修复后 clientmodel／clientadapter 普通
及 race 检查通过。覆盖同下一跳的 WG／Hy2、100/25 与 20/120 毫秒反转、图遍历顺序、不同
SpecDigest／资源／Link、unavailable 与过期隔离、并行 suffix、当前拓扑／跳数收缩和资源撤销。
适配器测试经过完整 GET／CAS／回读／确认；重复旧样本不增加性能确认，旧记忆不能复活撤下资源。

逐跳审查覆盖用户指定的十类攻击场景。未发现正常 PrepareContext、WG／Hy2 接收与恢复流程
需要修改的生产逻辑缺陷；补充协议负面测试、连接历史副本隔离和原生上下文／当前撤权恢复测试。
可信 forward 必须保全原连接绑定，接收端独立复验当前授权；这不是 Byzantine 防御，合法形状的
伪历史与仍获授权的旧上下文复用不具备端到端真实性／一次性保证。完整边界已写入
[安全契约](core/current-contract.md#逐跳上下文的信任边界)。protocol 普通／race、原生 WG／Hy2
真实回环加密 TCP／UDP、四类 dialer 上下文及撤权定向 race 通过，日志保留在
`out/hop-security-native/security-tests.log`。

原生自动化新增独立 CI Job；本地实际执行 `python3 scripts/test-native-dataplane.py` 通过。
五份上游 commit／module sum、补丁正向应用／反向检查及全部 protocol 文件逐字节一致均通过；
各嵌套模块使用明确工作目录及同一固定依赖图。关键集普通与 race 每轮各 229 个测试／子测试
事件，无失败或跳过，Linux amd64 正式 tags 构建及来源读回通过。逐项日志、摘要和来源位于
`out/native-dataplane-tests/run-z1ylmcng/`。它不覆盖所有上游包、宿主 TUN／路由或生产业务；
本地通过不表示 GitHub 托管 Job 已执行。

Android 的七项 Scope 要求已有实现，不重复改写 RouteManager。当前源双 ABI AAR 重建通过；
首次 JVM 回归暴露四项 SelectorTakeover 测试固定回环端口与宿主既有监听冲突，原日志／XML
保存在 `out/android-review-initial-failure/`。局部注入同一真实 HTTP transport，仅让测试服务
使用自有动态回环端口；正式固定端点校验保持，并新增拒绝其他端点的回归。重跑 21 组共 88 项
JVM 测试全部通过，无跳过，指定 Scope 回归及接管测试全部通过；Debug APK 构建成功。AAR／APK
两种 ABI 原生库逐字一致，来源记录匹配当前补丁和源码。执行命令（工作目录 `clients/android`）：

```bash
ANDROID_HOME=/opt/android-sdk JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 bash scripts/build-mobile-aar.sh
ANDROID_HOME=/opt/android-sdk JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 bash gradlew --no-daemon --max-workers=4 :app:testDebugUnitTest :app:assembleDebug
```

日志在 `out/android-review-aar.log`、`out/android-review-gradle.log` 及
`out/android-review-final/`。本轮未安装、运行真机或做 release 签名，构建与 JVM 回归不抵扣
互联网／LAN 组合真机、真实多中继稳定优选、闲置冷建及生产前向迁移验收。

交付对账已纠正 Scope 独立应用与纯发送资源回收的过时缺项，保留原失败版本及实际验收边界。
首次全库验证的命令、退出码和分步日志位于 `out/current-review-validation/`；后续修复结果见
[全量验证续作](#全量验证续作测试成本与来源坐标)：

| 命令 | 实际结果 |
|---|---|
| `go build ./...`、`go test ./...`、`go vet ./...` | 均退出 0 |
| `go test -race ./...` | 退出 1；clientdist 与 control 均触发默认整包 10 分钟超时，不能称全量通过 |
| `go -C mobile/loomcore test ./...`、`go -C mobile/loomcore test -race ./...`、`go -C mobile/loomcore vet ./...` | 均退出 0 |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | 18 项通过 |
| `python3 scripts/check_repository_safety.py` | 通过 |
| 仓库 Go 文件 `gofmt -l`、`git diff --check` | 无输出 |

全量 race 原失败保存在 `out/current-review-validation/03.log`，没有 race 报告，但这不等于未完成
的包已通过。clientdist 当时运行 `TestLinuxManifestRejectsAmbiguousAndLegacyBytes`，其某个清单
负例在既有 BestCompression 打包路径压缩完整临时 CLI；测试没有读取本轮原生制品，相关实现
和测试未改。control 当时运行 `TestReportMemberDeltaFillsOldHolesAndForksThroughPrivateTLS`，
该项已运行 2 分 32 秒，堆栈在 Snapshot 的 JSON 深拷贝；它耗尽的是整包累计预算，不能据此认定
该测试自身超时或死锁。control 的测试生产依赖不包含本次修改的 clientmodel／clientadapter，
protocol 仅测试文件变化。上述事实尚不构成同环境基线全量 race 已复现的证明。首次审查阶段
将这两项全量验证失败保持为未解决，没有提高超时、跳过失败或扩展到打包／报告同步重构；
后续修复与验证见下节，原失败结果不改写。

补充诊断曾执行以下单项 race；按停止追加诊断的指令在 86.078 秒主动终止测试子进程，
退出 1、日志为 `signal: terminated`，不计为通过或单项超时证据，原日志／profile 保留在 `out/`：

```bash
GOTOOLCHAIN=go1.27.0 go test -race ./internal/control -run '^TestReportMemberDeltaFillsOldHolesAndForksThroughPrivateTLS$' -count=1 -timeout=90s -cpuprofile out/control-race-diagnosis.cpu > out/control-race-diagnosis.log 2>&1
```

### 全量验证续作：测试成本与来源坐标

操作者随后要求继续推进，范围仍为本地审查、修复和验证，不含生产签名、发布、部署或迁移。
保留首次全量 race、被终止诊断及以下所有失败原日志，不以调整限额或跳过用例消除失败。

clientdist 的四项元数据测试不执行包内 CLI；此前却反复构建完整 CLI 并对每个清单负例重新
压缩。现在只将这些夹具改为具有相同入口和 ELF/buildinfo 身份的小型临时程序，保留完整
签名、摘要、规范编码、篡改断言和正式压缩逻辑。真实 CLI 与双架构数据面的正式包测试保持。

control 的单项 race 在下调为 3 分钟的诊断限额内超时，完整日志及 CPU profile 保留为
`out/current-review-followup/control-before.*`。采样中 Snapshot／深拷贝约占 5.7%，没有足够
收益依据去修改生产权限查询或拷贝边界；更明显的成本在测试辅助的重复编码、解码和构树。
修复仅位于两个测试文件：一次查询复用 codec，仍逐件严格解码；排序复用已验证且复制拥有的
规范原字节；进度循环只读取真实原件条目数。最终两端仍完整校验原件 key／内容 ID／引用集合、
数量和规范字节。1200 份报告、61 个稀疏点、故障、重试及限额均保留，生产 Snapshot、权限与
协议代码未改。相关四用例普通及 race 通过，之后以默认限额验证整包。

真实包测试还正确拒绝本轮新来源沿用 `.26` 登记：安全测试补丁及准备脚本已改变，即使当时
数据面二进制仍相同，也不能静默改写已登记的来源。现按实际四架构构建字节新增 `.27` 独立
制品坐标和来源摘要；`.26` 及更早登记完整保留，并增加历史冻结及逐文件篡改拒绝回归。
这是本地构建坐标，不是协议版本，schema 3、签名原件、发布 generation／catalog 与已安装
指针不变。来源／历史隔离、四架构构建及真实 Linux 双架构包链已经实际通过，未做 Windows
原生执行。默认 `/tmp` 祖先不符合包捕获安全边界的拒绝也保留；正式包复验使用受保护磁盘
TMPDIR，未放宽门禁或改用 fallback。

准确命令 `go test -race ./internal/clientcomponent ./internal/clientdist` 已在默认限额内通过；
显式 `TestReviewedLinuxPackages` 对当前 CLI 和 `.27` 数据面逐架构完成 Build、Verify、
VerifyPackage、VerifyFiles、VerifyDirectory 与篡改拒绝，未跳过。来源登记与原件保全证据、
真实包命令及逐步结果均位于 `out/current-review-followup/`。

Android 当前源 `.27` 双 ABI AAR 重建、强制重跑的 88 项 JVM 测试及 Debug APK 构建通过；
两种 ABI 原生库与来源逐字一致，补丁及协议副本匹配当前源码。日志和完整命令见同目录的
`android-summary.json`。这不抵扣真机或生产验收。

最终 control 整包使用 `GOTOOLCHAIN=go1.27.0 go test -race ./internal/control`，默认限额内
退出 0，耗时 567.862 秒。源码保持后，根 `go test -race ./...` 也退出 0，75.042 秒；Go 复用
了同源同参数的整包通过结果，日志明确显示 control 为 cached，没有跳过或替换测试入口。
因此首次两项整包超时已通过局部测试成本修复闭合，不能把旧超时改写成当时已经通过。

| 最终命令 | 实际结果与证据 |
|---|---|
| `go build ./...`、`go test ./...`、`go test -race ./...`、`go vet ./...` | 全部退出 0；`root-summary.json` 与对应日志 |
| `go -C mobile/loomcore test ./...`、`go -C mobile/loomcore test -race ./...`、`go -C mobile/loomcore vet ./...` | 全部退出 0；同一 root 摘要 |
| `python3 scripts/test-native-dataplane.py` | 当前 `.27` 来源、补丁正反与协议副本检查、逐模块关键集／race 每轮各 229 个通过事件、Linux amd64 构建通过；无失败或跳过 |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | 18 项通过 |
| `python3 scripts/check_repository_safety.py` | 通过 |
| 全部 Git 可见 Go 文件 `gofmt -l`、`git diff --check` | 无输出 |

当前原生验证摘要位于 `out/native-dataplane-tests/run-ynra3h0h/`，入口退出码及日志在
`out/current-review-followup/native-final.*`；首次原生结果保持原坐标。托管 CI、所有上游包、
宿主 TUN、实体机与生产多中继验收仍不由本地检查抵扣。本节验证阶段尚未提交；后续提交推送
按操作者新指令处理，未执行 release 签名、发布、部署、生产迁移或宿主网络配置变更。

### 提交后的平台与隔离业务续验

操作者要求提交推送全部代码后继续推进。提交 `c52fe299e30b5cb8da30c19663d9b1f990c13363`
已推送至 `origin/main`，远端 ref 与本地提交逐字回读一致。该提交的
[首次托管 CI](https://github.com/Scisaga/loom/actions/runs/42197289815) 中，新增原生 Job 实际通过；
根普通／race 与 Windows Job 失败，不能把此前 Linux 本地检查称为已覆盖全部平台。Android
独立工作流也在 SDK 初始化失败。原日志保留在 `out/current-review-postpush/`。

Android 初始化显式仅请求仍受支持的 platform-tools，API／build-tools／NDK 固定输入保持；
许可证继续由原 setup action 处理，去掉重复的手工管道。相同 SDK 包集合本地实测通过。
Linux 临时托管 runner 的根普通／race 改以 root 身份和受保护磁盘 TMPDIR 执行原完整套件，
保持生产密钥的 root-owned 保护；非托管 runner 或显式原生业务 opt-in 输入提前拒绝，默认
TUN 测试仍自行隔离。vet／build 使用同一缓存身份，不全盘改缓存 owner。deployhost 模拟目标
补齐父目录 owner 的映射，仅测试夹具变化。

传输目录测试在不受保护的祖先下，实际在创建 capture 前被拒绝，替换回调未执行；这不是删除
替换目录的生产缺陷。受保护磁盘下原清理逻辑正确保留 canary。测试现明确断言已到达替换点，
并覆盖不受保护祖先在读取输入前拒绝；生产清理未改，两种前提的原复现日志均保留。

Windows 测试从当前 View／Preference 派生候选，不恢复 View.Routes 或按 Service 同时选择。
当前平台的加入 fixture 与正式入口一致；Linux 下载用例按其唯一正式入口和
[私有签名包交付契约](core/current-contract.md#私有设备的精确签名包交付)完整移到 Linux 测试文件，
通用 I/O 期限用例仍跨平台，原样本／断言未减少。Linux 明文证据的 POSIX 权限断言不冒充
Windows ACL／DPAPI；Windows 真实保护由原生 DPAPI 用例验证。

同机 Windows VM 的七个 CI 包均原生退出 0，共 577 个 PASS 事件，无失败；12 个既有显式
opt-in 用例未执行，不能抵扣真实加入、数据面／TUN、跨账号或视觉终验。七包 ARM64 编译及
Windows cross-vet 通过，不冒称 ARM64 原生执行。完整结果和 skip 名称在
`out/current-review-postpush/windows/native-summary.json`；原件在
`deploy/evidence/windows-vm/demo-postpush-policy-final-20261106/`。VM 正常关闭至 inactive，
原 SID 保持、测试进程及本轮 RDP／Xvfb 清理完成，未放宽认证或改密码／网络。

显式两跳原生用例最初在 CAS 成功后仍报 sender preparation pending；实际资源池为空。
该旧夹具绕过了当前正式准备链，现仅将其 API owner 接入
`writeNativeResourceConfig → ApplyRuntimePermissions → ReconcileRuntimeResources → 原完整 CAS`。
无 overlay 的当前源码已通过首跳 WG／Hy2 与后段 WG／Hy2 四组合，以及三个正式 Run 的
故障切换、WG／Hy2 后台恢复与旧 TCP 保持。每个顶层用例使用独立 user／net／mount namespace，
只有 loopback 且无外部路由；实际对象与说明摘要匹配，进程正常退出无残留，宿主对象排除自然
expires 倒计时后保持。全部失败、诊断与最终证据保存在
`deploy/evidence/2026-11-06-native-business-c52fe299/run-w6nkgz3x/`。

本批修正的根 build／test／race／vet、18 项脚本测试及仓库安全检查已通过，日志及命令在
`out/current-review-postpush/root-check-summary.json`。托管工作流结论须按修正提交的实际
run 回读，不由这些本地结果推定。四种两跳组合不等于真实 RTT 驱动的同下一跳 Forward
资源优选，也不覆盖多 forward 节点链、物理 Android／ARM64 或生产迁移。未做生产签名、
发布、部署、路由器或宿主网络配置变更。

修正提交 `859dc0b0cafb3b9eb5bdeb0d94375c44f23e525f` 已推送。该提交的
[Android 工作流](https://github.com/Scisaga/loom/actions/runs/42202133120)全部成功，
[主 CI](https://github.com/Scisaga/loom/actions/runs/42202133959)的 Windows 与原生 Job 成功。
Linux 托管续验又发现 checkout 下的 scratch 前缀过长使 Unix socket 入口超限，且新 user
namespace 的 root 无法穿过 runner 私有 home 祖先执行测试程序。现在改用临时托管 VM 上的
短路径 `/ci`：原子创建，已存在即拒绝，并核对 root:root 0700。没有截短业务 socket、放宽
目录权限或跳过隔离测试。私有 mount namespace 的失败等价类普通／race 均通过，宿主 mount
与 namespace 保持，证据为 `out/current-review-postpush/short-scratch/summary.json`。
执行器修正提交 `5083595f916f133eba951e47840dbae9c4c0803c` 已推送；其
[托管 CI](https://github.com/Scisaga/loom/actions/runs/42204054178)的 Windows 与原生 Job 成功，
Linux 普通／race 的 socket 长度和程序执行问题消失，均只剩原生激活夹具读取 PID 1 namespace
的权限失败。新 user namespace 不能重开 `/proc/1/ns/net`；测试现由父进程预先打开该精确
初始 namespace，以唯一继承句柄 FD3 交给子进程。原隔离比较与 fresh loopback 检查保持，
未增加权限、修改内核设置或放宽 skip。原四个真实激活子例和三个 namespace 边界测试普通／race
均通过，无跳过，证据为 `out/current-review-postpush/final-ci-namespace-fd-summary.json`。
托管失败原日志继续保留；该夹具修正的托管结论以实际提交对应工作流为准。

本地提交前复核也曾误用过长 TMPDIR，再现相同两项 socket 失败；原日志保存在
`out/current-review-postpush/namespace-fd-root-checks/`。随后在独立 mount namespace 中使用
短的受保护目录，根 `go test ./...` 与 `go vet ./...` 均退出 0，宿主挂载及 namespace 不变；
根 build 已通过。新修改的定向 race 已通过，本次不重复本地全库 race，继续由新提交的托管
完整 race 验证，详见该目录 `short/summary.json`。

夹具修正提交 `f687ffea14065f6ba714b073ffffbc076ab8f4af` 已推送，其
[主 CI](https://github.com/Scisaga/loom/actions/runs/42206384032)四个 Job 全部成功：根普通／
race、Windows 原生检查、固定来源的原生数据面检查均通过。普通／race 的 linuxclient 包
分别实际执行 7.112／63.021 秒，日志不是 cached；非 verbose 输出不提供逐用例 PASS／SKIP
明细，不据此声称每个 opt-in 用例均执行。完整日志与状态保存在
`out/current-review-postpush/ci-f687-final-status.json` 及同目录对应日志。

### 同下一跳 Forward 的真实测量反转续验

新增显式 opt-in 的
`TestOfficialLinuxNativeForwardMeasuredRTTReversalKeepsExistingTCP`。正式 Linux Run 使用
持久签名 LKG 和唯一不变的本地 access 候选；forward 在同一 Policy、最终出口和下一跳的
WG／Hy2 两个实际资源之间选路。测试只改变隔离 namespace 中 UDP 代理的真实报文延迟，
不写入观测或 selector；默认测量节奏、两次新样本确认和最小切换间隔保持。

最终源码普通与 race 二进制分别在 fresh user／network／mount namespace 实跑，均通过，
无跳过或 race 诊断。地址生成前核对隔离、仅 loopback 和无外部路由；两条 Link 的资源、
规格、action、target 和网络代独立核对。每个资源均保留两次反转后的实际样本；签名报告由
测试接收端完成 TLS／设备 challenge 认证、验签并保存原件。forward 的出口 choices 首选
从 Hy2 变为 WG，revision 同时改变；access 的唯一候选／Policy／targets 与签名 View 摘要不变。
连接回读同时保留原 Hy2 tracker 和新 WG tracker 的排他实际链，旧 TCP 持续返回应用数据。

首次编译的局部遮蔽错误、首轮测试接收端使用 `any` 导致规范编码拒绝的自然超时失败，及
中间轮终态文件被 TempDir 清理抢先删除的取证缺口全部保留。修正仅在新增测试夹具：使用
精确结构类型、完整保留所有接收端口直至代理端口分配结束、同步发布不可变 LKG，并通过
标准 `-test.outputdir` 直接保存终态原件。最终源码重新编译后普通／race 各完整重跑，
没有提高预算、改生产权限或添加 fallback。

执行入口为 `go test -c` 与 `go test -race -c` 构建 linuxclient 测试二进制，再经
`unshare --user --map-root-user --net --mount --propagation private --fork` 执行该精确用例；
`LOOM_LINUX_MIXED_EXECUTABLE` 指向已审阅 `.27` 数据面，标准 outputdir 指向 owner-only
私有证据目录。实际完整命令及逐轮结果位于
`deploy/evidence/2026-11-06-native-forward-f687ffea/commands.txt` 与 `review-summary.json`；
最终两轮为 `run-80on1m7g`／`run-phzasfbr`，源文件摘要
`9210260cc255d1b4c17f85e316f3750559516a5d428a28cbfa4aeba216322bc2`。
各轮原生进程均退出、无残留，规则及宿主结构排除 IPv6 expires 自然倒计时后保持。

本次闭合的是本机隔离的实际传输、测量、Forward CAS 和新旧业务流；测试报告接收端不抵扣
真实 control authority 的报告接收持久化／重启，也不覆盖独立 access 经多个 forward 的链、
实际异网位置、Android／ARM64 实体机或生产迁移。新测试默认无显式输入时保持 opt-in 跳过，
上述通过结论来自两次显式原生执行，不由默认根测试推定。

### 真实控制面报告续验与独立 LAN 签发

操作者继续推进后，以 `3e77bfdb` 的干净工作区开始本轮报告闭环续验；范围仍为源码、本机
隔离运行和构建，不含生产签名、发布、部署或配置迁移。原始日志及报告原件仍只保存在
被忽略的 `out/`／`deploy/evidence/`，仓库只记录实现、回归源码和结果摘要。

实际发现并修复共享签名器的 LAN-only 缺陷：互联网待选、独立 LAN 已确认时，正常调用方会
生成非空 LAN selections，但原 SignDeviceReport 因缺少互联网 PolicyID 一律拒绝，报告尚未
发出。control 新回归及 Android 正常报告桥均在修复前实际失败。现在逐条要求 selection 的
PolicyID 非空且匹配当前互联网或该 LAN 意图；无关 LAN map 不能掩护未绑定选择，历史
policy_choices／preference 仍不能新签发。unsigned 编码、签名算法、schema 3、历史解码和
原件验签均未改，现行契约中过时的“新字段未完成”文字已清理。

control 签名及现有调用方普通／race 回归、共享移动核心全库 test／race／vet 均通过，
修复前后证据在 `out/current-review-postpush/lan-report-signing-summary.json`、
`out/continuation-control-forward/android-lan-first.log` 与 `lan-mobile-core-checks/`。
最终共享源码的双 ABI AAR 重建成功；88 项 JVM 测试实际重跑，无失败／跳过，Debug APK
构建通过，AAR／APK 原生库及来源逐成员一致。后续 control HTTP 修正后的 AAR 再次重建，
完整 AAR 及全部成员字节不变，复用同一 JVM／APK 结果；证据在
`out/current-review-postpush/lan-android-checks/` 与 `lan-android-final-source/`。
未安装到 Android 设备或执行 release 签名。

另以真实管理 WebSocket 复现了控制服务生命周期缺口：收到首个正常 snapshot 后取消 Serve，
原实现的请求上下文没有随服务结束，连接仍未关闭。现仅派生并绑定本实例请求上下文，退出时
先取消请求，再执行原有 HTTP shutdown；ConnContext 身份、关闭上限和错误上抛保持。
该唯一反例已红转绿，连同既有 Serve、TLS 身份／撤权和配置长轮询测试普通／race 通过，
证据为 `out/current-review-postpush/control-stop-context/verification.json`。
此前一次原生 race 运行在最终停止等待上限被终止，未取得进程堆栈；其具体原因仍未知，
不能因独立 WebSocket 缺陷已修而倒写旧失败定因，原失败与已通过阶段均保留。

现有 Forward 定向原生用例已接入真实临时 control：正式 CLI 完成 init、Endpoint 本机输入、
serve、普通事实写入、邀请加入、WG 公钥登记、资源配置、同步和 source client run。Source
使用真实 authority 签发并持久保存的同轮 LKG，保留 CLI 默认十五秒刷新；出口仍复用已验的
原生接收适配器，只消费该实际 authority 的投影。本轮删除原手工 TLS／ACK 报告接收器，
报告由真实私有认证入口进入唯一 observations.db，在线读取走正常 Unix 管理 snapshot／
Link history；仅在 daemon 正常退出后只读核验数据库，不打开第二个在线 owner。

最终冻结源码普通／race 各在 fresh user／network／mount namespace 完整实跑通过，0 跳过，
无 race 诊断。每个资源至少两次不同观测时间的反转后真实样本均在已签原件中保留；当前
snapshot 与 Link history 的精确方向、资源、规格及原 Observation 相等。forward 的真实
CAS／新 WG 流和原 Hy2 tracker 保持，access 唯一候选不变。control 正常停止、离线逐件核
规范字节／签名／原件键与最高序列后，同目录重启恢复相同样本，后续实际报告序列继续前进；
公开身份、完整 LKG（含签名、证明与事实前沿）及偏好不变。第二次停服后再次逐字核对全部
原件保全，原生及 CLI 子进程均退出，无残留。未修改 GORACE、关闭上限、测量节奏或稳定门槛。

首轮夹具缺少 device.put 必需的 Service 直接因果依赖、当前 UI freshness 字面值写错、
UI 投影误用权威 canonical writer，以及把可选 RoundTrips 统计当原件计数的反例均保留。
最高报告可只携带其中一条变化 Link，另一已 ACK 样本正常省略；页面当前样本和原件仍在，
不能从统计缺席推断数据丢失。最终凭据改为完整历史原样本与已签原件，未改生产统计算法，
本轮也不宣称波动统计验收通过。

完整命令、每轮固定 CLI／数据面摘要、原始失败与最终原件位于
`deploy/evidence/2026-11-06-control-forward-3e77bfdb/`。最终两轮为 `run-9m1167i9`／
`run-1b2i_9yq`，main 测试源码摘要
`9f7246dfc7b2c69fde865030db7f8729094a0d85aeafe7eeb1c6696b74722041`。
根 build／全库 test／vet、最终 test-only 来源的 linuxclient／vet 补查均通过，覆盖关系见
`out/current-review-postpush/real-control-root-checks/final-http-context/latest-source-coverage.json`；
完整托管 race 仍按新提交对应工作流实际回读。隔离执行未修改宿主网络或挂载；短路径 scratch
创建／清理造成的宿主目录 mtime 变化保留原值，不冒称所有文件元数据完全不变。

本次补齐本机真实 control 报告持久化、当前回读及重启恢复；仍不抵扣独立 access 经多个
forward 的实网链、波动统计、Android／ARM64 实体机和生产迁移验收。

该轮提交 `b92406cfd13268082d1d4ad383e6e839d1226107` 已推送；精确 head 的
[主 CI](https://github.com/Scisaga/loom/actions/runs/42217933025) 四个 Job 全部成功，包括
全库普通／race、Windows 原生及固定来源数据面检查。
[Android CI](https://github.com/Scisaga/loom/actions/runs/42217933044) 同一 head 也成功，覆盖
共享核心、AAR、lint、JVM 与 APK 构建；没有执行设备 instrumentation。上述托管结论已再次
读取 run、jobs 和日志中的 checkout SHA，不从按包汇总输出推定 opt-in 业务用例已执行。

### 独立 Access 与两个 Forward 的共享测量续验

操作者继续推进后，以 `b92406cf` 开始本机隔离四节点验收；本轮修改仅为测试辅助、原生用例
和脱敏记录。新增 `TestOfficialLinuxNativeMultiForwardSharedSuffixKeepsExistingTCP`：四台独立
正式 CLI runtime 分别承担 access、forward、forward、internet_egress，实际执行
`A → F1 → F2 → E` 的 WG／Hy2／WG 独立传输段。唯一互联网 Policy、最终出口和 access 的唯一
候选固定；两个纯 forward 的 access PolicyIDs 为空。自动派生的四条有向边全部保留，包括
F1 直达 E 和 F2 返回 F1；跳数上限与范围没有被用来强制经过 F2。

实验只降低 F2→E 桥接中的真实 UDP 报文延迟，F1 两条本地边与反向边的实验输入不变。
F2 的真实已签高／低延迟 Link 样本经过正式报告入口持久化，并由 F1 的正常
`/device/link-observations` 接口取得。F1 实际 Run 的 forward revision／首选从 E 改为 F2，
F2 首选仍为 E；新连接在两个 forward 的实际 tracker 分别使用 F2、E 资源并返回应用字节，
原直达连接的 UUID、资源链和应用收发保持。辅助 Fetch 本身不被当作 Run 消费的证明，结论
同时依赖上述远端唯一实验变量、实际 CAS、连接链和回包。

四个真实 runtime 均有 current 报告。停服后只读逐件核验数据库的规范原字节、签名和键，
两个交付引用的 DeviceID、sequence、digest 与完整 Observation 均匹配原件；F1 没有把远端
样本重新报告为自己采集。完整签名 LKG、偏好、网络代和 access 候选保持。新四节点用例没有
重复 control 重启场景；本轮同时用同一冻结普通测试二进制完整复验原两节点入口，0 skip。
旧用例的两个资源各有至少两次反转后样本，CAS、新旧连接、真实报告持久化、同目录重启恢复、
后续序列前进及旧签名字节保全均通过，验证参数化控制面辅助没有改变原行为；本项未重复 race。

每台 runtime 使用独立 network namespace，固定 namespace FD 启动整个正式 CLI；有限的
socket worker 在所属 namespace 创建 socket，经 SCM_RIGHTS 交付并逐件核对 SO_NETNS_COOKIE。
桥接只转发原始 TCP／UDP 字节，保留 TCP 半关闭及 UDP 来源映射，不解析权限或选择路径。
任何网络命令前先排除初始 user／net／mount namespace，并核对只有 loopback、无外部路由；
合成公网业务地址仅绑定出口 namespace 的 loopback。未使用 veth、宿主 TUN 或宿主路由变更。
独立 socket proof 普通／race 与初始 namespace 拒绝检查均通过；失败路径的 runtime 停止顺序
和出口 accepted socket 的 FD 所有权也已审查修正。

最终冻结源码的普通／race 两版分别在 fresh user／net／mount namespace 完整通过，均为
0 skip、无 race 诊断；不是默认 opt-in 跳过结果。两版精确测试源一致，使用普通／race 正式
CLI 和原 `.27` 数据面，全部 runtime／worker 正常退出，socket／namespace FD 已关闭，
无所属进程残留。规则与宿主结构排除 IPv6 expires 自然倒计时后相同。首轮误把 access Policy
选择传给纯 forward 的夹具失败原件保留；隔离检查前移与清理顺序的审查修正也有记录，没有
更改生产授权、测量节奏、稳定门槛、关闭上限或 schema 3。

完整命令、固定二进制与源码摘要、边界快照、已签原件和逐轮结果只存于被忽略的
`deploy/evidence/2026-11-06-multiforward-b92406cf-final/`；最终两轮为 `run-lsye5n4r`／
`run-xeo95gor`，汇总为 `review-summary.json`。首轮失败和中间成功轮保留在同级不带 `-final`
的目录。旧两节点回归位于 `deploy/evidence/2026-11-06-multiforward-old-two-node-regression/`，
汇总为 `review-summary.json`。main 测试源摘要为
`758f532725fc87afed2cf03cce4523cdabff1f112c905609e7ad588aa6a48d98`。
根 build／全库 test／vet、格式、仓库安全及 diff 检查通过，短受保护 TMPDIR 仅在私有 mount
namespace 使用，证据在 `out/continuation-multiforward/root-checks/`。本轮完整 race 的托管结论
仍按新提交的实际工作流读回，不用本地定向结果抵扣。

本次补齐的是独立 access 经两个 forward、固定出口的本机隔离共享测量与新旧业务流。
反向边可达性、所有拓扑／出口组合、真实异网质量、实体机、波动统计和生产迁移仍未验收；
本轮没有签名发布或部署，也没有把该场景记作完整多中继自动选路交付完成。

### Android ARM64 当前制品真机续验

操作者随后明确要求进行真机测试。本次基于 `9e681d34` 的干净源码，在既有 ARM64 实体设备
执行当前 Debug APK；设备由 USB 管理，明确核对不是模拟器。当前 CLI／AAR／APK 构建通过，
安装前验证同一应用签名，正常覆盖安装后全部受保护存储槽逐字节相同，没有卸载、重建身份或
使用生产发布签名。本机独立 control／接收端使用当前 CLI 和 `.27` 数据面，生产节点没有更新。

真机沿正常连接界面启动，普通 UID socket 完成探测列表之外的 HTTPS、正常证书校验和完整正文。
私有工作负载只发送真实业务；其加载调试器在请求前退出，不写 selector、观测或产品身份。
实际 access 选择、原生连接链与接收端原生日志核对相同传输；签名报告测得的 APK 与实际 ARM64
原生库摘要均等于本次安装字节。两个原 TLS／TCP 持续返回响应，UUID、端口、传输链与 native
Box 保持。仅增加少量延迟的第一轮没有形成真实 RTT 反转，未发生换路，原断言失败保留，
没有把它重记为性能切换通过。

随后用同一已安装 APK 开启独立的有界校准窗口，先取得两种资源各自的新鲜成功样本，再仅对
测试 namespace 内接收端 tap0 的相应 UDP 返回报文施加延迟。真实包计数确认生效，没有改宿主
路由／规则／DNS／防火墙，也没有写入 selector 或健康样本。两资源均有至少两次不同原时间的
反转后已签样本；真实 RTT 优劣反转后，应用在相同 Policy、相同最终出口内自动从 Hy2 切至 WG。
原两条 Hy2 连接的 UUID、链与连续响应保持，新两条 WG 连接完成 TLS 与业务响应；native Box
没有替换。测试结束正常断开，全部自有辅助线程、映射、凭据文件、接收实例与 namespace 已清理。
两轮原始失败、实际命令、源码及二进制摘要和回读分别保留，不拼接成一个没有失败的运行。

实际 Wi-Fi 失去／恢复后，来源网络代改变，新的 HTTPS 请求完整成功；这只证明同一 Wi-Fi 的
失去／恢复，不是 Wi-Fi／蜂窝或不同网络间切换。正常断开后冷重启应用，同一配置再次沿正常
界面连接并完成新业务。原身份、密钥、绑定、偏好、latch 及单调认证／报告进度保持；最终受保护
身份两次独立读取等于缓存，并由当前规范 codec 验证完整往返、密钥及签名，没有保存明文身份。

早期报告的 `unknown / runtime_apply_pending` 原件保留。完整确认后的实际 `running` 报告具有
与认证 View 相同的 applied 摘要；额外的静止窗口读取通过应用既有报告回调触发，没有提供
替代状态或观测。两轮最后均有正常 `stopped` 报告。control owner 退出后，只读核验本次新增
报告的规范原字节、签名及网络／设备／序列／摘要键；第一轮的 running 引用、校准轮的 stopped
引用分别与正常 UI snapshot 精确对应。全部原始授权与本机执行输入字节保持，没有签发策略或
资源变化。工具空行解析、并发变化时拒绝缓存快照及未收到 UI 事件的调试请求均保留为工具结果，
不据此判断产品网络失败。宿主结构回读仅排除自然递减的 IPv6／地址有效期字段。

原始报告、APK 备份、日志、UI 回读及汇总只进入被忽略的
`deploy/evidence/2026-11-06-physical-current/` 和
`deploy/evidence/2026-11-06-physical-current-rtt/`，两目录的 `review-summary.json` 给出范围；
没有提交真实设备、地址、端口、凭据、签名原件或运行指标。仓库只记录本节脱敏结论。

本次补齐当前 Android ARM64 制品的普通业务、两种独立传输、实测自动优选、既有连接保持、
正常停止、同身份冷重启及同一 Wi-Fi 恢复。互联网与 LAN 组合 Scope、手机经多个 forward 的
实际异网链、真实境外出口、蜂窝切换、Windows ARM64 实体机、长期规模／耗电及生产发布迁移
仍未验收，不能称全部客户端或完整多中继交付完成。

## 操作者指定的端口占用与可用范围修正

2026-11-04，操作者确认一台节点的指定端口已由其他程序使用，并重申原先提供的完整可用范围。
此前配置只登记一个监听端口，遗漏其余可用区间；先前以“未包含占用端口”认定无需修改配置
的结论错误，现已纠正。当前唯一部署 YAML 按操作者确认的原范围修复，仅扣除供其他程序使用
的末端端口；公网与本机端口保持原对应，其他节点配置不变。

已通过同一严格 loader 的正式入口重新加载，并逐个核对可用范围内的映射及范围外、占用端口
的拒绝。前一次 SSH 只读回读已确认目标端口存在双栈 UDP 监听，Loom 使用其他监听端口；
这不能替代完整可用范围的配置。[配置模型](operations/configuration-model.md#yaml-字段与基础设施映射)
已明确二者区别。真实坐标、原配置、修正值及验证保存在
`deploy/evidence/2026-11-04-external-port-reservation/range-correction/`；前次原始证据保留。
本次只修订本机部署输入，未执行服务切换或端口迁移。

## Android 加入与持续选路改造：实施中

本工作项继续源码与本地验证，整体保持未完成；生产授权、生产配置迁移及正式发布／安装未执行，
本地真机安装按下文实际范围记录。
当前约束与逐项缺口统一见[交付对账](delivery-audit.md#当前目标与尚未闭合的实现)，历史证据
不作为新模型或当前设备状态的证明。

2026-11-05，经用户明确授权开始真实境外出口的临时隔离验收，仅使用独立测试网络，不切换
生产授权或服务。Linux 正式启动发现两项此前 IPv4 场景未覆盖的问题：新建 WG 管理接口经
down／重命名／up 后丢失 IPv6 地址；原生库关闭自动路由时仍为 IPv6 生成额外默认路由及
策略规则。地址恢复仅补原授权地址；Linux 原生无自动路由时不再安装或删除隐式路由、规则。
真实 NativeTun 的混合地址族启动、重命名、关闭及正式投影的普通业务先红后绿，严格校验
保留。Linux `.18` 两架构来源与实际制品已登记，`.17` 原来源、Android 和 Windows 制品原义保留。

真机已分别经境外直达及既有 forward 到同一固定出口取得非探测网站完整正文，出口 IP 摘要
与境外节点独立参考请求一致。中继执行使用临时首跳约束，已前向恢复；自然测量窗口未满足
性能改善条件，不记为自动性能换路通过。恢复入口时暴露了连接连续性缺陷：forward 的本地
遍历投影把首跳范围当作设施变化，造成实例重建。对应字段及设施资格投影已修，完整接收
权限保持，正式 Run 和多出口反例已回归；中间修复制品的真机转发端实例已保持。

同次复验的手机来源端仍重建了自身数据面并中断长连接。入口扩展不仅增加候选，还增添签名
View 的传输认证材料、WG 内部地址与目标恢复路由、诊断用户和出站设施，超出当前权限差量
能力；不能忽略差异或恢复旧权限绕过。用户已选择按需增量资源池：保持现有认证材料交付边界，
稳定内部来源与诊断分派，常驻内核按需增加、撤下设施并保留合法旧连接。相关契约和实现继续
推进，不以全量发放材料或重签同前沿 View 替代。临时境外实例已精确停止，原始失败、签名材料
及身份密钥已耐久保全；实际连续性、最终制品真机闭环及整体工作项均未完成，生产未迁移。

按需实现已在独立原生测试中覆盖准备失败／取消、发布比较、合法旧流租用、首次 WG 资源及
精确绑定回收；实际 manager、内存连接与 source／receiver 权限 API 的集成检查验证了仅拨号
坐标变化保连接、认证身份变化和资源撤销只影响对应旧流。另一个先红后绿的反例补齐了 Policy
收窄后的校验：按每条连接已固定的下一节点重查中继、边及出口约束，不读取新的优选来替代。
三端接线、正式原生补丁与精确制品尚未完成最终冻结；这些检查不抵扣新 APK 的真机验收。

原生补丁随后已冻结到 `.19` 来源，四个 Linux／Windows 架构按正式参数构建并登记，正式重建
源码与已测试暂存源码逐文件一致；旧 `.17`、`.18` 来源和制品摘要保留。报告还拆出可选的完整
权限应用确认，使资源部分未齐时仍可共享独立有效的分段／出口样本，完整应用和业务证明不
因此放宽。旧报告缺席字段的规范字节、验签缓存、部分状态下样本的原期限及停止／切网拒绝已
回归；AAR／APK、实际安装和新制品真机连续性仍待完成，生产未切换。

随后 `.20` 把 forward 遍历图与动态容器接入同一增量池：遍历描述、优选顺序一次读取，
更新保留最新仍合法的排序并拒绝旧修订。失败入口不阻塞其他显式探索，合法旧流继续租用原对象。
四架构原生制品、真实 Android AAR 与 APK 已按冻结输入构建；Android 五项构建检查和 JVM
测试通过，两种 ABI 的 APK 库与 AAR 相符。真机已保留原加密配置覆盖安装，不卸载或重建身份。
本地与境外隔离环境已沿用原测试身份启动该制品；实际连接连续性复验进行中，尚无最终结论。

该 `.20` APK 的正式连接随后在原生配置检查阶段崩溃，尚未启动 VPN，不能计入联网耗时
或业务通过。两次实际栈均定位到新关闭代码的空错误回调；同一正式 `libbox.CheckConfig`
已在旧代码复现，修正后的 `.21` 同时保留未启动关闭与真实启动失败的原错误。原制品、
崩溃现场及失败日志已保全，`.21` 四架构原生制品已构建，Android 精确制品与真机复验继续。

`.21` 随后完成精确 Android AAR／APK 构建与原身份覆盖安装，全部输入前后摘要一致。
正式配置检查关闭异常修复后，真机经 forward 及直接接入同一境外最终节点，均取得未列入
探测的普通网站完整 HTTPS 正文，出口地址摘要与该节点独立参考一致。两种第一跳传输分别
建立的原 TLS 连接，在入口扩展后保持应用连接和 source／出口 tracker，继续双向收发；
新 HTTPS 同时成功。实际持有的 VPN service／native Box 对象保持，资源工作集已增量增加。

同一已认证 View 下还观测到同入口内 WG→Hy2 的自动候选变化；没有注入样本或手工修改
selector。相邻快照不足以唯一还原切换瞬间的触发分支，不记为自动改用另一入口通过。
该自然窗口的分段估计仍以当前入口更优，不能用单次 HTTPS 总耗时替代 RTT 相加。

新增 access 经正式 CLI 完成受限引导、绑定及耐久认证；独立 user／network／mount namespace
中的当前 CLI 和数据面使用 LKG、显式 Mixed 取得普通 HTTPS 完整响应，暂不可达的 control
未阻止业务。加入完成后的因果标记之后，手机两条原 TLS 均继续响应，新请求也成功，手机
内核及境外进程身份未变。它不抵扣当前 APK 的加入交互计时、物理切网、长期规模或耗电终验；扫码输入按用户要求使用 ADB 模拟。

当前制品的阻塞 selector 真机回归、根 Go 构建／测试／vet、移动模块 race／vet、Android
构建／单元测试／lint、格式和仓库安全检查均通过。另移除了远端资源地址对本机 underlay
接口观测的错误过滤，保留真实 VPN／LAN 冲突证据；内部无效资源参数随调用一并删除。
身份、原始签名和认证进度继续保全，临时加入身份及测试授权已前向撤下；手机恢复原选择
并正常停止，冷启动回读和隔离实例的最终清理结果保存在受保护证据。生产未迁移或发布，
整体工作项保持未完成。证据在 `deploy/evidence/2026-11-05-ber01-isolated-trial/source-pool/`。

当前 `.21` APK 后续另以全新临时 access 身份完成 ADB 模拟图像扫码：真实 CameraX
analyzer、解码器和产品回调完成加入，完整 state 经当前解码／校验／规范编码往返，并从
实际加密磁盘读回一致。正常 UI 连接后取得非探测网站的完整 HTTPS 正文；二维码生成、
持久 Ready、UI 连接上界与业务请求分别计时。Ready 后插入原件保护及测试器编排，故不能
把各段相加称为即时扫码到上网的总耗时，也未单独隔离接收准入传播耗时。

最终原始密钥、签名、认证前沿和报告序列连同临时密文/index 已受保护保全，再沿正常入口
撤销临时授权、删除临时配置；原配置和系统连接意图恢复，未修改旧 Keystore。其余原始
密文与身份/偏好/前沿分别回读，辅助文件、ADB 映射及本地隔离实例已精确清理。证据在
`deploy/evidence/2026-11-05-ber01-isolated-trial/source-pool/qr21-20261105T014928Z/`；
本轮输入方式遵循用户的 ADB 模拟要求。

随后以同一冻结 APK 和另一全新身份补了一次连续即时链：业务观察器先准备并退出 JDI，
真实图像提交、加入、持久 Ready、正常 UI 连接和非探测 HTTPS 完整正文使用设备同一单调
时钟连续记录；Ready 后不插原件校验。正常导航、两次焦点核验和观察开销都计入总耗时，
未延长业务观察器截止或重发应用请求。它只证明本地固定出口的一次已安装 APK 结果，不
代表冷启动、真实境外出口的扫码总耗时或重复统计。首业务后再校验保全、正式撤权并正常
删除临时配置，恢复原选择及 VPN 停止意图；原始非 index 密文及生命周期引用保持，全部
辅助对象和隔离实例已精确清理。证据在同一私有根的
`source-pool/qr21-immediate-20261105T022545Z/`。

Windows 正式打包脚本的旧坐标已改为读取现行组件常量，在任何客户端构建之前验完两架构
当前签包。旧包改名和架构错配仍拒绝，旧输出原件保全；以独立测试发行公钥生成的六形态
ZIP 已沿正式入口构建并验字节。它们是未作平台代码签名的 preview，不是 MSI 或生产发布，
ARM64 只有构建证据；当前 Windows 原生验证仍须按同机 VM 实际结果单独判定。

该 `.21` 制品随后在代理维护的同机 Windows VM，经原账号的正常交互执行器完成限定原生
回归，配置检查、临时 DPAPI 撤权与恢复、取消和部分权限报告均通过。首跑旧测试夹具误建
已退出模型的独立探测池，尚未执行对应报告断言；只删旧夹具重建后，同组回归全过，断言
保持，首红保全，未重编未变的生产包。原 SID、DPAPI 材料、原有文件与组件 floor 经摘要
对照保全，临时任务／桌面和测试输入精确清理，VM 正常关机。此结果不抵扣 GUI 加入、
普通业务、TUN、MSI、ARM64 或全部资源池生命周期。

后续独立审查补出了 `.21` 未覆盖的 WG 反例：同公钥只改拨号坐标，已有旧流租用会把创建时
peer 规格重新并入，与当前坐标冲突；无旧流先改址、随后出现租用时也可能使同值重试失败。
现有 Hy2 坐标更新检查和直接调用 WG endpoint 的测试不能抵扣真实资源池的这个分支。
原 `.21` 与失败反例保全，修正限定为旧流保留绑定、当前原生快照保留拨号规格，并沿同一
快照 CAS 发布；不改签名 wire、认证材料范围或业务权限。该修正及精确制品复验仍在推进。

该修正随后在独立 `.22` 来源完成：旧流只保留同一实际快照仍承认的精确来源／peer 绑定，
当前请求拨号规格优先；退出工作集但仍有旧流时取最新已应用坐标，旧准备不能回写历史值。
丢失来源路由、prefix 归属变化、认证变化及重叠继续拒绝。真实用户态 WG 的 TCP／UDP 在
接收端换端口后保持，改址后重试及工作集退出也通过。另修正域名或端口已变却复用旧解析
endpoint 的分支：新目的地解析失败正常返回，同目的地刷新和协议学习地址保持原义。
相关包 race 与正式配置检查通过，原失败、阶段库存及 `.21` 原件保留；正式补丁重建源码与
已测试 Go／module 文件一致，四架构制品登记完成，schema、权限和持久格式未变化。

新的根 Go 构建／测试／vet、移动模块 race／vet、格式和仓库安全检查通过，源码输入摘要
前后一致；Android AAR、两 ABI 和正式 APK 构建／单元／lint 也通过。Windows 六形态 preview
沿正式打包入口，以本轮原独立测试发行键的下一代组件构建，并在同机 VM 完成同组限定原生
回归；不借用生产签名或改原组件 floor。Android 最终字节与真实改址连续性回读继续按下文
独立证据判定，不把上述构建、race 或 Windows 配置检查扩大为真机业务完成。

`.22` 真机 WG-only 续验随后未通过。先查明测试器把两个外部 UDP 入口转到同一内部监听，
返回包误用新增口；精确撤下本次新增转发后，原 WG 握手／数据计数恢复，未改产品、DNS、
超时或 WG 拨号坐标。但普通 HTTPS 仍出现来源端拒绝／确认失败，不能归因网站或视为业务
通过。随后实际进程发生 Go 空指针崩溃；当前 APK、实际内存映射、原日志和 tombstone 均保全。

精确符号化和正式 Endpoint 反例确认，WG 确认失败时的具体空指针被转换为非空 `net.Conn`
接口，上层错误清理调用自动生成的 `Close` 而崩溃。`.23` 仅在转换接口前先返回字面空连接和
原错误，并在真实原生拒绝及目标拒绝路径检查空接口；不改 `Close`、权限、确认期限或协议。
原反例由红转绿，相关包 race 通过；`.22` 原件和登记保持，正式 `.23` 四架构来源与制品
核对完成，根与移动模块检查通过，Android 精确制品和实际失败入口复验继续。
该修复不自动解释前置的普通业务失败，后续仍须分别核实来源选择、当前权限和真实下游结果。

`.23` 随后完成精确 AAR／APK 构建、原身份覆盖安装及真机续验，限定窗口未再出现上述空指针。
两个普通网站经系统 TLS 和主机名校验取得完整正文，但首次请求仍有失败，不能标为普通上网
闭环。同期回读确认，UI 已宣布连接时 selector 仍为拒绝；稍后才取得有效 WG 默认选择。
启动就绪接线现按当前 Policy 的完整实际选择收口，仍须以新的精确 APK 沿首次请求复验。

另一次普通域名请求经实际 TUN 的合成地址恢复为原域名，进入资源池 WG sender 后超时，
接收端相邻窗口没有对应执行记录。同期 literal 请求成功不足以证明差异一定来自目标类型：
两次之间的资源解析缓存和时序也有变化。定位继续区分 peer 准备、内部 TCP 建连与执行确认，
不据总截止直接归因 DNS、出口或网站；真实 WG 改址连续性验收暂停，未改变拨号坐标。
本次临时资源授权已沿正式入口前向恢复并由手机耐久接受，身份及认证进度保全；正常停止、
辅助对象和本地隔离实例清理完成。精确记录在同一私有根的
`source-pool/android23-final-20261105T040106Z/`；生产未迁移或发布。

首条选择的 Kotlin 接线随后通过独立审查及相关 JVM 回归：网络回调统一重查首选，selector
在途不能复用旧缓存，新配置绑定改变只使本机回读失效，不关闭合法旧流；选路成功也不再
代替完整资源确认。最终源码与测试快照一致，新 APK 的首个普通请求仍待真机复验。
另以冻结 `.23` 的正式权限、资源池、用户态 WG 和 gVisor TUN 做同批对照，literal、域名及
合成 IPv6 恢复域名均收到完整回包，未复现手机超时。测试器自身的初始化和重复 tag 错误
另存原始记录，不算产品失败。下一 `.24` 只补上述三段的错误诊断，原因链、期限及权限
不变；独立审查及相关 race 通过，四架构正式来源与已测文件相符。诊断制品不算业务修复，
继续沿精确 APK 的真实失败入口验收。

同次审查发现独立 LAN 准备会连带清除已确认互联网的整批完成缺口。Android 后续修复已按
scope 接线：access 先确认，局部未确认写入只使自身回读失效，memory 分项确认，完整报告
保守降级；用户操作沿取消接管，安全停止仍核精确旧调用和 VPN 会话。独立审查、全部 JVM、
正式 APK 五项构建及两 ABI 校验通过，输入库存前后一致；沿用同一 `.24` AAR／原生库，
没有为 Kotlin 改动重建其他平台。该后续 APK 尚未安装，不冒称当前真机已经消费此修复。

该 scope APK 随后已保全原配置覆盖安装，原报告／停止回归通过。VPN 关闭时先准备普通
InetSocketAddress 请求，调试器退出后再正常 UI 连接，首次普通网站取得完整正文；没有
修改 DNS、身份、缓存或原请求截止。准备两条长 TLS 时，首条另在本机 access 选择阶段
立即拒绝，未进入 WG；fake 地址恢复、当前权限和实际资源摘要均已核对，较晚的有效默认
无法证明拒绝瞬间。未执行改址，临时授权前向恢复并由手机耐久接受，全部测试对象已清理。
下一 `.25` 只增加首次拒绝分支及被 pin 的选择哈希诊断，不改权限、选路或超时。

另行提出的采样唤醒／串行让出草稿已完整保护并精确移出构建输入，工作树恢复到上述已验
scope APK 对应源码。手动换 Policy 是否关闭仍获授权旧流正在向用户确认，旧文档不能追认
该行为已获同意。独立审查亦确认未知／过期首跳没有被核心算法作为放行门禁，不能据假想
门禁继续扩展抢占或关闭状态；真实拒绝原因仍待同一请求的分支证据。

`.25` 随后按上述诊断边界冻结：首次拒绝原因和原选择哈希沿同一连接保持，后续 pin 检查
不能用新快照覆盖首因；字段不进入 wire 或持久值，正常成功不增加警告。独立审查、相关
原生测试及 race、正式四架构制品、AAR 两 ABI、Android 五项检查与全部 JVM 回归通过；
正式重建源码和已测来源相符，根与移动模块规定检查的输入前后保持。Windows 应用包与
同机限定原生回归仍按 `.23` 记录，不把新数据面构建等同于新的 Windows 业务验收。

真机已保全原身份和加密配置覆盖安装该 `.25` APK，实际原生映射及报告／停止回归通过。
正常 UI 连接后的首个普通网站完整正文成功；其后屏障启动的两条 TLS 在原有界窗口内持续
响应，尚未复现瞬时拒绝。窗口剩余时间不足以安全完成改口及验证，故单独封存为改口未执行，
不延长原 worker 或追记成功。随后独立窗口完成正式仅公开端口变更及单活映射切换；两个原
TLS 在两端均保持真实 tracker 并继续收发，两条新 TLS 的完整正文成功，两端 WG 实例代和
应用进程保持。业务窗口未取 Java Box 对象身份，不增加该项声称。原口、Hy2、Service 及
Policy 已沿新签名事实恢复，手机耐久回读与原身份、进度、配置保全通过；正常停止及所有
测试对象清理完成，宿主网络结构保持。未复现拒绝不等于根因修复。证据在同一私有根的
`source-pool/android25-reason-20261105T070907Z/`；生产授权及部署未改变。

独立审查又以正式原生 HTTP handler 和完整选择 CAS 证明迟到写入反例：客户端取消旧 PUT
后，新调用只 GET 确认相同选择，旧请求仍可晚提交拒绝，权限和实际资源摘要不变。仅加
handler 取消检查仍有检查后提交的竞态；新调用沿原接口同值 CAS 推进修订后，旧请求被
拒绝且当前选择保持。反例及对照原件保存在同一私有根的 `source-pool/late-selector25-review/`，
冻结 `.25` 来源未改。Android 接管未确认写入的修复继续实施，不把确定性代码反例冒称为
前次真机拒绝的唯一原因，也不为此增加执行协议或持久状态。

用户同时确认闲置传输按需回收，仅保当前路径、合法旧连接和在途任务所需对象，接受闲置
备选再用时的建连成本。工作集累积和部分静态保活仍是待改实现，当前增量创建及端口变更
验收不抵扣回收、规模或流量／耗电结果。目标已同步到现行契约，不增加保温模式或管理页。

随后用户明确手动 Policy 切换的旧流语义：新连接立即采用新选择，仍获授权的旧连接保持，
主动“重建该服务连接”才关闭该服务存量连接。已替换现行契约中的待定文字，三端普通切换
及失败收口的自动关闭正按该目标核对；真实撤权继续由完整当前权限逐流执行。先前自行写入的
“必关旧连接”不作为迁移约束，也不回放依赖它的额外关闭状态草稿。

接管修复随后冻结到新的 Kotlin-only APK，继续复用 `.25` AAR／原生库；必需 CAS 的范围在
首次 GET 前捕获，准备未齐、409、取消和局部失败不丢失该义务，完整确认后才清除。正常已
确认同值检查继续只读。独立审查、相关真实回环 HTTP 测试、正式五项构建、全部 JVM、双 ABI
和输入库存一致性通过；固定测试 API 端口由独立仅回环 namespace 隔离，不接管宿主监听。
测试依赖仅补固定版本的 JVM JSON 实现；原端口冲突、JSON stub 和测试签名错误均保留原件，
不冒充产品故障或隐去首红。构建 namespace 已释放，宿主规范回读保持；新 APK 的物理复验继续。

Android 同批删除手动切换时的自动服务关闭，保留显式重建入口。共享 Go 另删除普通拒绝及
选择应用中的两处自动关闭，Windows／Linux 的现调用链因此只阻止新连接；真实撤权继续由
原生当前权限执行。旧实现的三个关闭反例保红，新共享包及 Linux race 回归、冻结原生私有
overlay 的同 Service 跨 Policy 真实 TCP 与选择性撤权均通过。未修改冻结原生或重建其他
平台制品，不把源码、overlay 或旧 Windows 包称为新物理验收。证据分别在同一私有根的
`source-pool/selector-takeover25-fix/`、`source-pool/android25-cas-policy-build-20261105T075245Z-ea1321/`
和 `source-pool/manual-policy-go-continuity-20261105T075244Z/`。

新 APK 其后实际安装、原配置保全及基础回归通过；在同 Service 的两条策略都已获授、仍选择
原策略的真机窗口中，UI 连接完成后默认 selector 持续为 reject，已有两条 TLS 仍收发正常。
尚未点选另一策略或执行撤权，不能把旧流保持当成手动切换验收。私有观察器、原日志、签名
报告库及当前缓存均已保全；历史失败样本未找回，当前成功缓存不能倒填该窗口的原因。
测试授权、资源及原选择已正式前向恢复，临时策略删除，耐久回读、原配置及身份进度保全、
停止与完整清理通过。证据在同一私有根的 `source-pool/android25-manual-20261105T080116Z/`。

独立代码反例确认两项时序缺口：Android 测量循环沿报告周期等待，失败样本到期后未必触发
重算；reject 的空 Policy 又使原本机结果检查提前返回。短寿命失败还可能在周期报告前过期，
没有进入任何签名报告。另明确的本机 CONNECT 未就绪／过期被 HTTPS 封装丢失 Deferred，
会伪装为测量失败。这些是已证实代码缺口，尚不等于已还原上述物理窗口的唯一触发原因。

后续 P0 修复复用现有运行检查重算当前获授的 blocked scope，不续期样本；测量检查间隔由同一
Go timing 派生，与报告分开。新采样通过当前所有权校验合并后，即通知原单报告 worker；
它按同一 timing 限制最短发送间隔并合并通知，保留原周期保底，不等待 selector I/O、不为每条
网址创建报告任务。诊断只记录已采用样本的散列、结果及原始时间期限，坏诊断不影响业务。
本机明确未就绪／过期及取消保持 Deferred，真实传输失败仍按原分类。

相关真实 HTTP 反例、报告短样本窗口、运行检查、合并通知及取消测试和独立审查通过；新的
`.25` AAR、正式五项 Android 构建、全部 JVM、双 ABI、Go 全库及移动 race 检查通过，实际
输入前后一致。新制品保留前次 CAS 接管及手动切换旧流修复；物理复验已启动，未作生产切换。
证据在 `source-pool/p0-expiry-sampler-report31ae-20261105T084307Z-bb865c/`、
`source-pool/aar-20261105T090228Z/` 与 `source-pool/android25-p0-build-20261105T091025Z-4164ac/`。

按需回收的私有原生暂存已验证描述安装、原子选择引用交接、旧流保持及冷 forward／probe
入口；正式来源与制品尚未切换。底层 WG 配置有同步发送、join 及部分提交边界，相关回收
取舍已向用户说明，依赖修改暂停；已通过的局部 race 不作为可发布或成本已达标的证明。

最新 `.25` P0 制品随后保全原身份覆盖安装、实际原生库及基础回归通过。正常 UI 连接后，
普通 IANA 全文、旧 TLS 与新 HTTPS 均成功；跨多次检查及真实测量机会未见连接后的默认
reject。本轮自然样本均成功，未自然触发前次失败／过期分支，因此不能把一次稳定窗口认作
已解释并消除前次现场根因；相关拒绝、原件缺项及确定性反例继续保留。

另一个明确窗口已沿正常 UI 在同 Service 的两条已授 Policy 间切换：原 A 的两条 TLS 在两端
保持真实连接标识并继续收发，B 新连接的原生 TCP 结果绑定 B；同一应用实例、WG 实例及
资源摘要保持。只撤该手机的 A 授权后，A 两旧流选择性关闭，B 两旧流继续响应，B 新 HTTPS
完整正文成功。未重建身份、注入观测或延长工作线程截止。

原授权及资源已用新事实恢复，临时策略删除；原 A Preference、签名配置、身份和不可回退
进度正常回读保全，VPN 已停止。原配置槽位保全，仅当前配置状态与测量缓存按预期前进；
自有辅助文件、线程、映射、进程及 namespace 已精确清理，宿主结构回读保持。报告库只在
control 正常退出后离线保全并逐条验签；采样到签名报告的实际时效另按原时间核对。
本地证据在同一私有根的 `source-pool/android25-p0-20261105T092018Z/`；此结果不抵扣物理
切网、闲置回收、规模／耗电、新版境外出口或生产迁移，整体工作项仍开放。

显式“重建该服务连接”的独立暂存已补齐精确归属：本机连接通过正式选路与权限检查后，从
Policy 固定派生 ServiceID，TCP／UDP tracker 按值保存；后续选择不能倒写旧流。共享筛选及
移动纯桥以该 ID 与实际 source scope 取出原 UUID，再复用逐连接关闭入口；不再按共享 access
链关闭其他 Service。真实 Pin→权限检查→tracker、旧流保持、缺失归属拒绝及 HTTP 方法的
无网络调用检查均通过 race，移除实际派生赋值的反例按预期失败。正式源码、已验制品和认证
状态未因此变更；新增 JNI 的完整 Kotlin 编译、实际原生 HTTP 关闭和真机验收仍待可用的
资源池制品，不以这些局部测试抵扣交付。证据在同根 `source-pool/service-scope26/` 与
`source-pool/idle-resource26/service-metadata-source/`。

私有 Go 资源池接线另已完成独立审查：构造描述与实际对象分开，保留全部仍获授 Policy 的
合法材料；冷探测和校准不逐次请求全目录。恢复测量频率已改由测量周期派生，与样本有效期
解耦。此暂存尚未合入或打包；默认参数下已验制品的时间相同，不代表任意参数的解耦已经
进入该制品。

用户随后选定完整回收闲置纯发送 WG peer。当前引用、合法旧流、在途任务及真实接收／管理
用途继续保留对象；最后需求退出后删除实际协议对象，再用时冷建，不增加闲置时钟。正式
Go／Kotlin 已合入完整描述、原生按需入口、独立测量周期及按 Service 精确重建接线；新增
JNI 尚待新 AAR 完整编译。接收 base 不再继承发送保活，实际 outgoing 说明统一使用原保活
规格，由原生有效引用决定是否启用；旧“有接收资源才为在用发送保活”的条件属于迁移差距。
另已核实普通资源的接口地址被旧投影误留为接收 base，会阻止纯发送 peer 回收；正式收发
只消费执行目标、目标池及已授权的接收 principal，相关多余 host ACL 正在最小清除，显式
System／HostSources 和签名资源原件保留。原生修订正在补齐锁外准备／回收、并发重用和完整
实例停止顺序；当前仍不可发布，不以较早局部 race 或旧制品证明方案二已实际交付。

随后独立原生验证已覆盖实际 peer 的删除／同设备冷建、同公钥迟到清理、部分 IPC 失败后的
最新输入收敛、忙锁返回及整实例先中断自有 I/O 再等待退出。零本机发送引用的接收节点，经
纯权限接受新增来源及完整描述后，新来源首次实际握手和 TCP 成功，旧来源连接保持。原生
七个相关包完整 race 与独立审查已通过；完整 peers／listener 设施 RPC 的深层物理 I/O 仍有
自身等待边界，不能将日常权限／描述／冷借用结果扩大为所有设施 RPC 全程可取消或无损换监听。
报告／日常回读不等待这些物理锁，整实例停止可先解除自有 I/O；该额外设施边界继续单列待验。

用户确认在本运行实例内保留少量累计字节，并要求重新审视设计。统计现收敛为 Device 内
同公钥共享两项原子数；原计数写点各加一次，新旧协议对象及迟到握手任务共享它，不做删除
结算或 offset 账本。协议 peer 与队列正常回收，统计不持有其对象或密钥，独立实际 peer 计数
用于回收证明。旧采样的“必须等于全部授权 peer”假设同步替换为当前授权内的真实已观测
子集，未观测项不补零；相邻报告按共同 peer 计算，缺项不抹其他可比项，Link 最新缺项时
当前速率未知。原全量报告规范字节和签名保持，报告字段及 schema 不变，页面明确已观测 WG
部分。相关必要 race 已通过；新精确 CLI、AAR／APK、实际入口与真机验收尚须最终冻结后执行。

随后正式 Go 全库规定检查及实际浏览器的 WG 子集、缺项与非 WG 展示验证通过，精确 CLI 已
重建。首批原生／AAR 与部分 APK 构建后，隔离的正式选路→真实传输验收发现首条 TCP 被
本机拒绝：来源选择填入逐连接执行上下文后，冷资源租用仍保存填入前的 context。四类真实
拨号／监听入口的最小反例已复现，并以选择后、租用前重新绑定同一已固定上下文修正，原
校验保持。独立审查及相关 race 通过，修正来源已可重现，新四架构制品及 AAR／APK 已重建。
真实 Hy2 的三流验收随后证明按 Service 关闭只影响对应旧流，另一 Service 原流继续收发，
新连接采用当前 Policy；Android、WG 业务和回收验收继续独立推进。首批失败制品及未安装
APK 原件保留，不用构建或本地 Hy2 的结果抵扣真机及 WG 结果。证据在
`deploy/evidence/2026-11-06-wg-idle-reclaim/`，生产授权与部署未变。

独立 WG 的正式 Run 随后正确拒绝未登记的新制品。已补齐同一制品坐标的精确来源及四架构
摘要，旧登记内容原样保留；这只改变本地构建目标，不推进发布指针。正式 Go 检查与新 CLI
重建通过，无私有登记 overlay 的 WG 故障／后台恢复验收也已通过，旧连接持续收发。新增
登记文件不在 Android 两 ABI 的实际构建闭包中，逐项依赖、AAR、APK 与 provenance 均未变，
因此复用已经验过的精确 Android 字节，避免重复构建；手机业务及回收验证继续独立进行。

该 Android 主包随后同签覆盖安装，身份和全部加密配置保全。真机操作回归的旧模拟资源
回读缺少描述字段，已仅修测试设施、重建 test APK，三个原操作回归通过；产品未恢复预建
全部发送对象的旧假设。普通互联网完整响应也已取得。然而后续限定取证捕获了连续 reject
窗口：WG 准入回显发生真实拨号超时，fresh 失败样本被当前选路过滤成零候选，生成阻断；
后一次回显成功才恢复。窗口内资源及权限回读均保持原值，不是网址探测或样本自然过期。
底层回显为何超时尚未证实，也未在 reject 窗内发业务请求，不能宣称全网失效或业务成功。

用户选择的限定取证已结束；原授权、配置及偏好已沿正式前向事实恢复，认证进度单调，VPN
关闭，所有自有辅助对象、进程、映射和隔离环境清理及宿主回读通过。原失败和完整窗口原件
均保留在 `deploy/evidence/2026-11-06-wg-idle-reclaim/phone26-qa-20261105T190057Z/`。
闲置／冷建及跨 Service 精确重建的真机阶段按用户选择暂缓，不能标记完成。当前优先在离线
修正诊断证据与合法执行资格混用的推断。该修正现已独立审查并正式合入：诊断失败保作排序
负面，合法当前路径及冷启动候选仍可尝试，真正失格和无合法拓扑保持拒绝；可靠的新 TCP
开始时刻仅反证本机首跳。既有首次可用发现记忆跨故障切换保留，恢复不能绕过性能间隔。
模型及实际桥接、全库规定检查、新代码下独立 WG／Hy2 的正式后台恢复与旧 TCP 保持回归
通过；新 AAR／APK 构建及 Android 检查也通过。两个仍要求诊断失败阻断唯一候选的旧移动
测试已按新目标修正，真实保护失败、原采样时间、TTL、重测和撤权断言保留。新 Android
修复字节尚未真机验收，底层回显超时仍未定因；不能据此标记整个工作项完成或已发布。

用户另行批准的限时复验已完成安装、身份保全和真实的阻塞回读／报告／停止检查，但没有
执行普通请求：私有自动化根据旧页面一次计算多次 TAB，页面节点变化后焦点未到目标，
安全断言没有发出连接动作。此结果不是产品联网失败，也不是新版业务验收通过；不能借用
上一制品的普通响应填补。原策略、资源、认证进度及配置已前向恢复，设备与隔离环境在总
时限内清理。完整原件在 `deploy/evidence/2026-11-06-wg-idle-reclaim/phone26-fallback-short-20261105T203619Z/`。
当前仅离线修正动态焦点读取及依赖命令失败后仍继续执行的验证工具，未开始新的设备窗口。

2026-11-04 的后续独立真机续作修正了权限收窄触发整实例替换及出口测量 I/O 提前释放预算的
问题，四架构数据面、Android AAR／APK 与对应回归完成。权限收窄／前向恢复的真实连接选择性
关闭在当时中间制品成立；最终制品另验正常浏览器的非探测网站、已完成资源及渲染，不能将
前一制品的结果冒称已在最终字节重复。出口成功样本已由签名报告、control 缓存与正式批量
接口进入 access，Android 实际运行内存已读回，原样本有效期未被续写。

按用户本轮决定，以 ADB 图像交给真实扫码解码器及产品回调，不等待移动手机。最终制品的新
身份完成正式加入、加密保存、正常连接及首个非探测目标完整正文；各段计时分别记录，测试器
编排和调试观察开销保留。加入期间原运行配置的两条业务连接保持原 tracker 且继续收包。
最后正常断开并恢复原配置，冷重启后密钥、加入绑定、latch 和偏好保持，认证及报告进度单调。
本轮另只读核对了全部生产节点与普通 access 的实际候选；生产仍运行旧制品及旧模型，未迁移
或发布。独立出口在本机隔离运行，不能抵扣实际境外出口、异网切换、完整规模与耗电终验。
证据在 `deploy/evidence/2026-11-04-android-restriction-review/`，完整边界见
[本轮独立验收](delivery-audit.md#权限收窄共享出口测量与模拟图像加入)。

最近一次续作已接通普通 TCP 原生结果、本机有界 RAM 消费及诊断显示，并将 Policy 可见性接入
既有批量样本与列表通道。隔离正式 Run 在管理请求挂起时仍为失败目标更新新连接选择，旧 TCP
保持；独立 WG／Hy2 的四种两跳组合取得实际原生结果。精确 AAR／APK 在原真机身份覆盖安装，
探测列表外 HTTPS、运行内存消费、接收节点连接及持续 TLS/TCP 分别读回。后续仅补诊断文字，
沿相同 AAR 再验普通请求与实际 UI；页底说明的滚动回读仍未完成。首次触摸自动化未触发启动，
键盘聚焦按钮完成正常连接，不把这段等待当作网络延迟证据。

非固定出口的恢复方式已经用户确认：先后台试连，再让新连接换路，已有连接保持。相关算法、
原生认证入口与三端预算接线已实现；正式隔离 Run 的独立 WG、Hy2 均以真实试连恢复目标新连接，
保留该目标的原连接及无关长连接。精确 Android 新制品在原身份覆盖安装，固定出口下普通 HTTPS、
连续 TCP、原生消费与诊断回读通过；不把它冒称非固定出口的真机恢复。原件、身份进度、报告和
宿主网络已复核，测试实例已清理。证据在 `deploy/evidence/2026-11-04-background-tcp-calibration/`。
差量累计超限与 cursor 淘汰的循环已通过有界查询、跨页工作集及精确提交修正；Go 全库与精确
Android 构建通过，真机已消费当前 cursor 与原样本截止。旧 Web 报告年龄不再剪裁选路样本，
同目标换规格会清除旧槽。新制品真机首进程发现 system IPv4 TCP 监听缺失；重连后强制 IPv4
恢复，受限 FD 跟踪未复现关闭，不能当作已经修复。随后已完成同身份、Policy、出口与捕获
配置的冻结制品对照，并为共用 UDP 域名适配及 gVisor 分配修复另构建、真机回归。
用户已明确确认 Android 默认采用 gVisor，并保留这两项 UDP 修复；源码投影与已验制品相符，
无需为确认决定重复构建或安装。原 system 制品和失败现场继续作为历史证据保留。
测试资源和宿主回读已完成，采用依据、未解决项及验收边界见
[Android 接入栈对照](delivery-audit.md#android-接入栈对照与-udp-目标修复)。本步不代表整体交付或生产切换完成。
独立测试环境的另一 access 正式加入与接收准入差量已执行，手机既有连接保持；仍非摄像头
扫码或新设备首业务验收。整体、完整 QR／物理交互及规模成本未闭环，生产未迁移或发布。
精确范围见[普通 TCP 与列表投影](delivery-audit.md#普通-tcp-本机反馈与策略列表投影)，证据在
`deploy/evidence/2026-11-03-native-business-feedback/`，平台接线证据另在
`deploy/evidence/2026-11-03-native-tcp-local-feedback/`。

前一次续作已完成 WG 公网拨号与本机监听端口解耦、失败后明确端口重试，以及本机 access
撤权与同节点 forward 职责分离；未新增 wire 字段、管理对象或协议版本。正式隔离 Run／Store
验证保连接和恢复后，当前工作区的精确 APK 已在既有 Android 身份上覆盖安装并实际访问普通
HTTPS：不同公网／本机端口的 WG 持续连接保持，新连接可使用更新后的 Hy2 优选。
身份、认证进度、原件及宿主网络分别回读，测试资源已清理；完整范围、监测修正及待完成项见
[WG 本机端口与职责独立的运行更新](delivery-audit.md#wg-本机端口与职责独立的运行更新)。
生产未迁移或部署，多 WG 接收资源未启用，完整 QR 耗时、普通业务反馈和规模成本仍未闭环。

此前的逐跳确认续作仅修正真实业务反馈的前置结果：原生 WG／Hy2 TCP 在写完请求后便返回，forward 因而
可能尚未完成下游建连就向上游 Accepted。现在沿已有响应头逐跳等待，固定最终出口后再实际
连接目标；不等待应用首包。明确拒绝、路径不可用、未知、取消及正常 EOF 分开，Hy2 通用消息
不被重解释为原生失败。共享会话的创建等待可取消，关闭与发布共用短锁，取消后迟到创建不能
复活；没有新的授权、签名对象、持久状态或协议版本。

原生真实 socket、竞态及旧 TCP 跨另一连接取消检查通过。正式渲染及完整选择 CAS 的隔离测试
覆盖两种首跳和两种后段的四种两跳组合：无探测网址，普通示例域名由认证配置解析，关闭的目标
端口被拒绝，完全静默的应用仍可完成 TCP 建连，首字节保持；新拨号失败不关闭旧连接或共享传输。
保留旧精确制品和原来源登记后，同一具名测试在旧程序复现提前确认、新程序通过。

初次测试错误地把 HTTP CONNECT 的 200 当成下游建连；改用裸 IP SOCKS 后，入口名称嗅探的
预读仍会提前确认。这两组结果不能证明原生因果，原日志及修正说明保留。最终测试使用明确的
普通示例域名，避免入口预读；尝试普通互联网访问 `.loom` 被权限正确拒绝，未为测试放宽权限。
这进一步确认后续被动反馈应采集实际原生拨号结果，不能读代理握手颜色或状态。

四平台数据面和 Android AAR／APK 已重新构建并核对来源及库字节，Go 与 Android 本地检查通过；
该次未安装手机或生产制品。当次 ADB 已重新读回在线设备，不把上轮真机结果当作该次新制品
已验收。发送端取消尚不能使远端 forward 的在途 Dial 立即退出，仍受各跳期限约束；不能把
双向连接的半关闭当成取消。当时被动反馈与可见性尚未接通，后续结果以上述新续作为准；
完整交互与规模成本仍待完成。
证据在 `deploy/evidence/2026-11-02-native-tcp-confirmation/`，宿主网络与受保护原件另行回读。

已按用户确认把 View 收敛为稳定授权、资源及必要身份材料，删除签名候选、完整运行 JSON 和
逐路径凭据／ACL／peer 表。设备从唯一 LKG 和 Preference 派生当前互联网 Policy 及独立 LAN 选择；
原生 selector 的完整 CAS 快照包含 Policy 与入口／资源／出口，资源 transport 跨 Policy 复用。
WG 与 Hy2 独立认证实际发送节点，请求显式携带 Policy、原始来源、最终出口及已走节点。
历史扩展 View 仅由显式前向替换验证，身份、原件、密钥、认证进度、latch 与报告序列保持。

来源权限与接收端差量接口已接源码；原生权限更新保留仍获授权的连接，撤权与新流登记共用
校验边界。Linux 已验证局部接线；Android／Windows 的新增接线与精确制品仍在验证。
源配置只用于证明静态设施未变，运行时已解析的地址与捕获边界保持；局部应用失败不恢复旧权限。

共享测量沿既有签名报告和 observations.db 的可重建原件索引及差量同步。出口独立检测网址，
相同执行规格跨 Service／Policy／设备复用；access 不再逐完整路径重复扫描。当前有向规格由
认证事实一次计算，报告校验不再逐项生成私有 View。Hy2 有向测量的 RTT、实际 UDP 计数和域名
坐标已修正接收校验，仍须核对其正式上报及消费。WG 身份已按用户确认登记在节点授权中，
不再由监听是否存在隐式切换；身份保全不代替连接连续性。Hy2 的测量依赖仍须独立核对。

已通过当前渲染到原生配置的消费检查及来源权限差量的回环 API 调用；真实 TCP 验证当前来源
selector 的性能更新保留旧流并改变新流，不再用多个互联网 Service 同时生效的旧场景冒充业务入口。
原生配置解析会丢弃空权限表的缺口已修正，缺失／null／未知字段仍拒绝。

按[常驻数据面与增量应用](clients/client-runtime-model.md#常驻数据面与增量应用)，本次把 WG
peer 更新扩展到实际出站坐标、keepalive、AllowedIPs 和局部增删；纯发送 endpoint 不再要求
伪造接收权限。未变化 endpoint 不下发，域名工作按受影响 peer 取消，迟到及 A→B→A 结果不能
复活旧坐标。用户态 WG 的持续 TCP 在无关 peer 增删及同一对端改址后继续收发，实例 epoch 保持；
真实渲染配置也已沿本机 API 提交和完整回读。相关原生包的 race 检查通过。
Linux 将 peer 坐标与宿主接口／管理返回路由所有权分别比较，配置更新和周期 DNS 改址消费
同一原生 peer 差量，不再仅因这类改址返回整代替换。宿主对象不因此获得修改授权。
正式后台配置领取原来在接受变化后先取消整代，已改为通知应用主循环并中断当前测量工作；
持久化失败仍停止，首轮通知竞态在开始工作前复核 LKG，应用错误不被测量取消掩盖。相关
取消、持久化保全与 race 检查通过。普通互联网正向验收最初因使用文档地址而被正确拒绝，
该失败保留。用户随后明确允许在验证隔离且只有 loopback、没有外部路由的 namespace 内
临时生成公网范围合成地址，源码不保存实际值，不连接公网或放宽权限。
Linux 正常 supervisor 已在此边界消费签名配置及唯一 Policy：无探测网址时，字面 IP、网站
和应用依赖域名均通过显式 Mixed 访问，域名使用认证配置的 DNS；改名及仍允许原业务的权限
修订后，已有 TCP 和新请求保持正常，停止回读及原身份恢复成立。正式运行链 race 检查通过。
宿主快照首次原始摘要因 IPv6 路由过期倒计时不同而不相等；原记录保留，后续逐字段对照保留
行顺序，仅排除该倒计时，宿主 namespace、接口、路由及规则配置保持。此隔离合成结果不证明
真实公网质量、Android 加入耗时、完整多节点路径或实体切网已经验收。
这仍未覆盖新传输设施、栈地址、监听或捕获的全部局部变更，不能称所有 View 变化都已无中断应用。

根模块测试、build/vet、共享客户端检查、移动 Go 模块和 Windows 交叉编译分别按当次输入验证；
后续改动须重跑相应检查。Android 单元、lint 和 Debug 构建已通过，新增原生修正后的精确 AAR／APK
已核对两份原生库与来源记录一致，未安装或发布。规模数据仅为本机合成场景；当前 ADB 无已连接设备。

扩大原生消费检查时，Windows 当前来源配置曾被旧校验器以 unknown field access 拒绝；旧 WG
源地址测试也缺少当前执行地址绑定，失败证据保留。随后删除 Windows 重复业务 DTO、权限／
传输校验器及任意业务 JSON 构造入口：当前构造直接消费认证 View，由共享渲染器生成业务配置，
只添加平台捕获、认证 DNS 及本机边界。监督器消费同一临时投影，修改配置副本不能改变它；
未选择 Policy 仍拒绝业务，不把普通互联网放进 route.final。
三种交付形态的当前 WG／Hy2 投影最初只通过开发程序的原生语法检查；完整预检正确拒绝其
未登记摘要与构建参数，失败保留。随后按正式参数重建四架构制品，复现相同字节，再将同一
`.16` 来源及字节登记为源码构建目标，保留历史登记原值。Linux 来源检查、Windows 组件的
确定性打包与验签、历史来源拒绝混用，以及三种捕获配置的完整预检均通过；不再绕过来源检查。
这些预检不启动 TUN，也不推进生产发布。随后同机 Windows VM 实际执行三种捕获配置的完整
预检、非法权限及未知字段拒绝，全部通过。客户端撤权恢复复验在 SSH 会话调用 DPAPI 时
被拒绝访问；用户已明确选择用既有交互执行器复验，不降低保护或改密钥。代理最初误把测试
VM 登录交给用户，该操作前提已撤销，并写入工作指引避免重复。随后由代理处理原测试账号
密码到期，通过验证旧密码的正常续期保留原 SID，不使用管理员强制重置、不改变到期策略或
DPAPI 范围；正常控制台登录后，沿既有交互任务运行原摘要制品。
三项当前捕获／权限检查及八项客户端检查全部通过，包含用户与机器 DPAPI 的撤权、职责撤回、
应用失败后的持久恢复，以及无关认证进度不重启运行。子进程返回码、任务完成标记、交互会话
和实际日志均回读通过；来源与制品保持原摘要。证据在 `2026-10-31-windows-interactive-recheck/`。
原 SSH 失败及执行器普通 stderr 中断、子进程返回码空缺的失败原件分别保留，执行器已修正。
这些结果不包含普通客户端的完整网站业务、报告及故障恢复验收，不能报已可发布。仅验证 DNS／捕获机制的隔离夹具
与当前认证 View 的测试分开，其旧目标匹配不成为现行 Service 模型。

WG 最小字段已接普通加入、`device.put`、历史原件验证、View、原生投影和节点身份回读。
省略字段的普通编辑、同请求重试、撤权后重新授权及重启均保留登记值；接收资源公钥必须与
owner 一致。固定私钥继续读取原文件，删除接收资源不隐式改用派生键；共享实例 tag 稳定。
隔离验证在没有 Hy2、来源没有接收资源的情况下，经正常来源预检和 selector 执行独立 WG
普通业务，错误本机私钥拒绝，宿主网络配置前后相同。Mixed 校验也已能沿认证 selector 成员
识别组合 access／forward 节点。证据在 `2026-10-31-wg-registered-identity/`。
该验证不证明存量 TCP 可以跨监听删除无损继续，也不抵扣正式 QR、配置传播和生产前向登记。

共享调度器现已按完成任务串行交付增量，不等整轮结束；缓冲受并发数约束，取消或消费失败后
等待实际工作退出。仍有消费者时保留共享请求，最后一个消费者取消才终止并等待真实清理。
Linux 在当前身份、授权、偏好及网络代复核后即时重选，复用已构建的图；Android 首跳与私有
共享观测领取分别使用既有可取消调用，两个循环独立推进，完成回调属于原 VPN 协程，提交前
复核运行、配置、偏好和网络代。Android 选路桥改用整数毫秒时间，修正同秒新样本被整秒当前
时间排除的问题。Windows 接入相同增量，用户改变选择后停止旧测量并重读本机意图；其进程锁
是单实例所有权，未误删为 UI 操作锁。
增量合并覆盖重复缓存引用及切网；Linux 缓存、状态回读按完整资源测量规格去重，保留同一
资源在互联网和独立 LAN Policy 下的不同准入原件，不因资源 ID 相同拒绝合法样本。
Android 切网及用户选择 Policy 后立即重新探索，不等周期唤醒。继续核对还发现 WG 在途复用
遗漏 Policy 和完整规格，现已与观测身份一致；真实原生帧交换覆盖同资源不同规格独立执行，
以及一个 Policy 成功、另一个被接收端拒绝时不能串用准入结果。

隔离正式运行验收暴露 WG 准入被错误送入业务上下文出站，失败原件保留；已改用同一来源的
原生诊断通道，保持精确执行地址、端口、诊断用户与接收端 Policy 校验。正常 supervisor 消费
签名 LKG、当前 Policy 和固定 WG 身份后，实际准入原样本立即进入运行回读；另一入口静默且
探测仍未截止时，普通互联网业务已成功。无网址的域名及应用依赖、配置更新前后的持续 TCP、
停止恢复与独立固定键 WG 的隔离回归通过。无宿主网络变更，未由此推断真实公网或真机质量。
移动 Go 的真实受保护 Hy2 交换也已覆盖快速完成与另一路静默、回调拒绝及取消；并发检查修正
了测试用 socket 计数器本身的竞争，没有串行化真实测量。证据在 `2026-10-31-progressive-measurements/`。
根模块 build/test/vet、共享与隔离运行 race、移动模块 race/vet 均通过；Android 单元、lint、Debug
构建及 AAR/APK 两份原生库和来源记录核对通过，未安装或发布。Windows 本次新增接线完成
两架构交叉编译，未将此前 VM 的旧摘要结果当作本次接线已原生验收。再次 ADB 读回无在线设备。
宿主接口、路由、规则和解析器文件摘要前后保持，仅对比时排除 IPv6 路由的过期倒计时；原始
快照保留。现存 Go 文件的格式检查无输出；原指令仍因索引中的既有删除文件报错，未为此恢复
源码或修改暂存区。最初的时间精度、WG 准入及构建／测试夹具失败记录分别保留。

2026-11-01 继续核对配置传播：签发成员原同步只有拉取，不能只凭本机 wake 推断其他成员立即
取得新设备准入。现以原认证输入修订通知本机，在既有成员前沿请求中附带一次可丢弃提示；
接收成员仍按原 CRDT 取缺、验签和持久保存。真实双 control 私有 TLS 在没有周期 tick 时取得
新加入事实，空闲后没有结束即重试的忙循环。Linux/Android 以同一配置摘要有界跟随变化，
返回前重新检查身份、当前输入和发布引用；同 View 前沿也保存并回读。没有新授权或持久游标。
Android 后台配置不再脱离 VPN 调用启动协程；配置与报告均使用现有可取消请求，网络等待
不占共享操作锁，取消实际 I/O 后不退回已占报告序列。Windows 端尚未接入该跟随，原生复验不能抵扣。

正式 CLI 在专用 user/net namespace 内沿邀请、bootstrap、身份绑定和耐久 LKG 启动真实 Mixed
数据面，并访问没有列入探测网址的合成公网目标；另一 access 加入和原设备重命名后，原 TCP
连接及新请求保持。场景为 Direct，不称为共享 WG/Hy2 接收节点的正式加入验收。受保护证据
`2026-11-01-configuration-follow/` 保留分段实测，不能换算 Android 扫码或公网耗时。修复旧的
慢私有请求测试夹具，使它使用当前普通互联网而非历史 Service 白名单；真实 HTTPS、慢管理
请求、独立首跳增量、域名/应用依赖、持续 TCP、撤权及停止回归通过。生产授权和制品未激活。

仍须完成真机渐进首跳与取消、真实业务反馈、完整流量及耗电核算、接收节点准入传播、正式 QR 到
首个普通业务的分段计时、固定出口选路、长连接、加入不干扰其他设备、故障及重启恢复。
这些缺口与前向迁移、精确制品验收及旧路径删除共同构成一个工作项，局部通过不单独报完成。

## 统一加密解析与 Android 配置恢复

按[解析器契约](core/current-contract.md#servicepolicy-与设备授权)，同一 schema 3 `dns_servers`
扩展为原规范 IP 或字面 IP HTTPS 解析端点的同传输集合；原 IP、缺席字段、历史签名与原运行渲染保持。
新邀请草稿预填加密配置，签发前检查具名入口的执行需要；既有邀请只读、设备修改继续使用普通
`device.put`，不引入网络级 DNS 权威、版本、配置键或长期 fallback。首次短引用仅解析其唯一
bootstrap Host，之后只使用认证 View，TLS 名称与全部钉住的身份保持。

共享 Go 连接、WG 地址和原首跳检查使用同一 DoH POST 核心，校验 TLS IP 身份与完整 DNS 响应，
取消后关闭并等待本次查询的全部连接；数据面复用原支持 DoH 的制品。业务探测保留域名沿获授权
候选执行，最终出口解析，Direct 本机解析；不声称未经单独测量的 UDP/DNS 成功。Android 保留
socket protect，已接受的认证配置先持久保存，执行失败显示已加入及运行未就绪，重试不重新加入。

隔离网络内的 Android 原生开发入口已验证正常加入、空解析配置接受后执行失败、普通同步修复、
DoH 启动失败后的普通重试、真实 WG/HTTPS、签名运行与停止报告；同一 profile、公钥、high_water、latch 和报告序列连续。
客户端与出口故意返回不同业务地址，实际请求仍使用出口答案。Linux 回环 Mixed 验证加密备用端点
及解析基础设施不扩宽 Service 权限；Windows 同机 VM 验证共享解析 TLS、响应、取消和三种既定
交付形态的配置派生。模拟器、回环进程及 VM 不抵扣实体终验或生产实际路径回读。

生产配置与发布指针尚未修改，须按[发布顺序](operations/configuration-model.md#加密解析配置的发布顺序)
先升级读取者，再沿普通设备授权前向修改解析器。只读候选检查有五个现网节点通过，另一节点的
管理通道返回不可达，不能为其激活配置。原出错 Android 实体设备的升级、重试与重启回读仍待执行。
本轮受保护证据仅位于 `deploy/evidence/2026-10-28-android-enrollment-dns/`；此处不标为生产完成。

## Hy2 首跳认证的真实传输输入

按[实际传输速率](clients/client-runtime-model.md#hy2-首跳认证的实际传输速率)，复用原保护 UDP socket
的认证动作计数 TX/RX，并记录单调时钟纳秒时长；原 schema 3 Observation 增加可省略的闭合测量值。
旧报告缺席时逐字往返，失败/取消不产生吞吐，原资源/凭据/网络代/时效验证保持。该值是小量
QUIC/TLS 认证探测速率，含协议开销与重传，不是饱和容量、应用用量或新的选路输入。

正式 Topology 的公开首跳观测与设备 Measurements 已接入同一签名原值，TX/RX 方向、字节、时长、
范围与时间分别回读；不创造 Hy2 Link，不借 WG 计数。原报告签名/严格拒绝/重启、真实 QUIC
认证及失败、缓存复用、Chrome 当前/过期/旧缺字段与相关竞态通过；仓库规定检查通过。
三端实际采集已验收：Linux 隔离真实认证、HTTPS 与原报告验签；Android 当前正式 APK 的正常加入、
VPN HTTPS、同身份重启、正常断开及原签名报告；Windows 同机 VM 的生产 GUI/HostAdapter、独立
Hy2 HTTPS、DPAPI 重启、路由保持及原报告验签。重启复用仍有效的同范围原样本；样本过期或网络代
变化时验证新的实际采样，不以无条件原值相等代替恢复。Android 系统 UI 无响应、一次重启业务超时、
验收脚本的过期样本误判及 Windows 测试工具公钥链接错误均保留原失败记录；修正只涉及测试执行，
没有重建未改的数据面或把失败记录算作通过。

源码 `964d7758` 的第 104 代正式目录已完成全部目标及规定 HTTPS 校验。第一次分发有一个目标的
传输未确认，未推进指针；后经已有管理节点的独立 SSH 通道恢复同次精确目录，按摘要复用已完成文件。
工作站的临时 SSH 连接设置已恢复原字节与权限，并重新验证管理连接。三 control 分组切换，六 Linux
客户端并行应用精确程序，原数据面复用；现网身份、密钥、原认证字节、floor、高水位和 latch 保持。
每节点仍为一个共享 WG，Linux 保持 Mixed。国内与国际 Service 的各自 HTTPS 均通过。

两个 control 的正常管理员浏览器从真实签名报告回读 Hy2 原字节和时长，Topology 与设备详情一致；
另一个 control 在该窗口没有当前样本，保留 unknown，不声称全部成员当前。新样本在生产 control
重启后保全；基础网络、新建 SSH 及原 underlay 回读通过。删除九个被替代程序目录和本次传输/单元
备份临时文件。Android 与六款 Windows 应用制品已正式发布；模拟器、同机 VM 和临时宿主权限
已清理，实体安装与终验仍由用户负责。受保护证据为 `deploy/evidence/2026-10-12-hy2-throughput/result.json`。
本项小量认证探测速率交付闭环，不抵扣应用吞吐或线路容量。下一核心软件项为签名目录自动消费与旧
发布 floor 的前向关系；网站签回、生产 LAN 参数、扩展排序取舍和实体终验仍分别保留。

## 普通对象显式冲突解决

本工作项接续 Events，补齐既定 schema 3 `conflict.resolve`；规范原已定义操作，原先缺的是实现与正式页面。
领域/签名 wire/持久/运行/UI 映射见[普通对象的显式冲突解决](core/control-model.md#普通对象的显式冲突解决)。
目标限于正常可编辑对象的同目标并发最终值或原删除语义，不通过选择来源改换设备身份、取消成员门禁
或改写 Invite/Endpoint 的发行者生命周期。原签名字节、现网身份及不可回退进度保持。

正式 Configuration state 已接入公开原件审阅、实际字段差异、全部当前来源、Policy/设备/仍有效邀请影响、
最终值编辑和删除。设备只提交公开字段，daemon 组合受保护前值。逐项引用及写锁内的当前冲突检查
拒绝漏引用和新并发；相同请求重试返回原事实，重启从原件恢复，DeviceView 沿原消费者读取。
字段编码、顺序无关、并发晚到、设备秘密、删除墓碑、已暂停引用与原生浏览器通过。
浏览器发现刷新来源时旧表单同时冻结旧引用，已修正为保留草稿、更新来源并重新确认；另外消除了
新增处理器对无关点击的异步延后，既有 Events 导出和设备撤权表单的回归验证通过。
仓库规定检查及相关竞态通过。源码 `af7545d3` 已推送，正式第 103 代目录完成全部目标的必要分发
与 HTTPS 校验；只构建 control 所需程序，其余平台、客户端和数据面原件复用。两远端 control 并行
恢复后再切换管理成员，三台均激活精确程序；六 Linux 客户端仍运行第 100 代 `b2849a6a`。

真实管理员浏览器在两个成员的正常 Services 表单以同一前值并发修改现有国内 Service 的名称，
Configuration state 审阅全部来源后签发解决事实，恢复该 Service 的完整原值。原件回读确认两个
冲突来源均被明确引用，修改范围仅为名称；Linux 实际运行的认证前沿已消费该事实。两个成员的正常
页面及 Events 回读新结果，另一成员在观察期限内未收到；分组重启后三个各自的本地结果保持，
不把迟到副本等同客户端失败，也不宣称全部成员同步。

首轮浏览器过早回查跨副本传播，普通恢复表单遇到晚到的新并发而被拒绝；最终清理使用正式显式
解决入口恢复原值，失败与实际恢复原件分别保留。独立国内与国际 Service 的实际 HTTPS 最终通过，
国际请求曾失败，随后在相同目标及原偏好下恢复；具体外部丢包原因未被证明。身份、密钥、全部旧
认证原件、高水位/floor/latch、原客户端与数据面、每节点单一共享 WG 和宿主基础网络均回读保持。
验收辅助器曾误用保留的旧客户端程序查询新 control 原件，已改为查询实际激活组件；外部动态安全链
变化经精确差异审阅，没有改写共享防火墙。旧 control 程序经进程、unit、指针核对后删除，原不可变
公开目录保留；临时凭据、传输文件与 unit 备份回收清理。完整证据位于
`deploy/evidence/2026-10-12-conflicts/result.json`。本项交付完成，后续 Hy2 认证探测速率交付见上节；签名目录自动消费仍缺，
网站材料、生产 LAN 参数、扩展排序目标和实体终验仍分别保留边界。

用户已明确将实体机测试留给自己；其余现行模型内的实现、同机虚拟机/模拟器验证、正式部署、业务回读
和旧路径清理由本轮执行持续完成。实体机未验不阻止推进其他工作，也不冒充实体机通过。
阶段性检查或进度汇报不构成停工点；只在具体外部条件或不可变现网材料冲突确实阻塞时说明缺项。

### 功能对账与 Events 完整窗口

本次已按设计入口的使用场景完成有结束条件的[交付对账](delivery-audit.md)，替换累计的旧 open 表。
六节点并行只读回查确认交接精确客户端及原数据面仍在运行，管理返回路径不走被替换 WG。
网站页面和三端 LAN 软件的较新结果不再列为未实现；陈旧 control 副本与暂时底层链路问题
分别记录，不能用“全部变绿”制造新的软件门禁。只读证据存于
`deploy/evidence/2026-10-12-delivery-audit/`。生产根/原 CSR 签回叶、真实 LAN 参数、未定多指标
排序和实体终验各自独立；当时确认的 Configuration state 软件缺项已由本页较新闭环记录完成。

Events 已从最高报告快照筛选替换为原件查询：固定窗口和结果摘要、完整类型分桶、连续加载、
同过滤全量 CSV；重复投递和不变运行值不生成新事件。首次接收附注与原签名字节分开，旧原件
缺时间的区间标为未覆盖，不从采样时间或文件 mtime 补造。普通事实、成员证书、冲突与运行变化
均只输出公开引用；历史不倒写当前事实。原快照报告事件、未筛选浏览器 CSV 和虚构保留期已删除。

真实 Chrome 已验证滚动追加、失败重试、详情及未提交草稿保留、筛选重置和全过滤导出。
Go 验证覆盖完整总数/分页/分桶/CSV 一致、窗口边界、新报告不漂移、结果变化明确刷新、
原件重复/缺口/分叉/损坏、成员多数证书、冲突历史、索引删除重建和重启原字节保全；竞态通过。
首轮全仓检查发现启动接收附注的空事务会改变报告库物理字节，已修复为只读确认，只有缺附注
或索引时才前向创建；失败原件及最终检查保留。第 101 代目录先完成全目标正式分发，未用于生产 control 激活。发布前复核用原源码证明
截止点后收到的签名分叉会改变旧窗口说明；已修正为验证同一截止点之前的原件集合，
修正源码 `4a780ece` 已推送，正式第 102 代完成全部 YAML 目标、变化公开包正文、未变包路径/长度
及最终原件回读；第 101 代已推进目录保留，没有回退。只构建本次 control 所需 Linux amd64
程序，其余平台与数据面原件复用。目录代与客户端实际程序代不混同。

两远端 control 并行恢复后再切换管理成员；三台都激活精确程序。停服后保全原报告库，
初始化前后按全部原件键与字节逐项摘要核对完全相同；原事实、身份及既有认证进度保留。
首次执行器的换行转义错误在脚本解析时失败，无节点变更；增加整段发送前编译后继续同一部署，
失败原件保留。没有重建网站根、CSR、客户端身份或 WG；六客户端仍运行交接第 100 代程序。

实际管理员证书 Chrome 在各 control 的原私有调试入口完成正常 Service 创建、Events 查询、
完整分桶/总数、同过滤 CSV 及正式删除；三台按同样依赖分组重启后，固定查询结果完全一致。
最初要求验证对象传播到另一成员时三分钟内未见该事实，此迟到原件保留；随后分别验收各成员
的本地正式写入及历史，不将迟到副本当客户端失败，也不声称全网即时同步。旧接收时间未知的
区间保持未覆盖，窗口总量只包含已知本地接收历史，不能宣称具备过去完整覆盖。

六节点身份、原认证字节、高水位/floor/latch、客户端与数据面、单一共享 WG、非 Loom 路由/规则、
解析及防火墙语义均回读保持；新建 SSH、LAN/系统 DNS、原 WG HTTP proxy 和默认公网通过。
国内、国际两个独立 Service 的实际 HTTPS 在切换期间及最后回读成功，原偏好保持。旧 control
程序经进程、unit 和指针核对清除；全部原报告备份已回收到受保护目录并验全量原件摘要一致，
临时凭据和传输文件已清理。最初未压缩备份传输触及本次等待期限，按实际部分文件压缩续传完成，
未重复清理已删除程序，也没有重启已验服务；失败和各目标实际耗时保留。

软件检查、竞态、真实浏览器、正式发布、停服原件保全、分组重启、业务与基础网络原件位于
`deploy/evidence/2026-10-12-events/`。网页网站信任切换、生产 LAN、多指标排序与实体机终验仍按
交付对账的独立边界；后续 Configuration state 的显式冲突解决已完成，见本页较新记录。

### 本地执行不再等待慢私有请求

操作者已明确底层链路暂时不通、丢包和控制副本暂时落后是必须容忍的运行条件。验收目标是
获准业务在有可用替代路径时继续进展，失败只影响实际范围；不要求全部物理链路或页面始终正常。
报告传递和成员复制是异步信息交付，不是客户端选择的前置门禁，陈旧页面不能制造客户端故障。

已按[本地执行与私有管理请求](clients/client-runtime-model.md#本地执行与私有管理请求)拆开 Linux
刷新中的阻塞：配置刷新和报告上传各有一个后台在途请求，本地选择和输入不等待网络；待发报告
只保留最新原始快照。原采样和生成时间不续期，旧快照确认不能覆盖新选择。新授权完整认证、
持久接受后取消并停止旧 generation；持久错误仍失败关闭，普通网络失败保留已接受配置。
身份、floor、报告序列、latch、schema 与授权来源保持，没有队列文件、新管理实体或操作输入。

原源码在真实不回应的私有 TLS 连接下复现启动阻塞；新源码通过正式 supervisor、实际数据面
和真实 HTTPS 完成本地输入、撤权拒绝、取消退出及同身份恢复。原 Mixed 业务与接受 View 转换
也在隔离 namespace 中完成竞态验收。全仓构建、测试、静态、格式、安全及差异检查通过。

发布器按[公开制品检查范围](operations/configuration-model.md#全目标签名分发的正式执行入口)
只完整下载变化项，全部目标旧认证目录中相同的包检查路径和长度；source、目标实际字节及
消费者下载校验保持。CLI 区分正文和元数据，不声称未变包本次被完整下载。另复用同次已验证
源 Store 的解析结果，避免各目标重新解包；传输前仍核对全部源字节，验证锁不占用网络发送。
真实签名目录完成条件发布、部分失败重试、并发传输、缓存删除重建、损坏拒绝及原件保全。
跨文件系统的测试目录错误已修正，初始失败与带竞态插桩的大包检查成本保留，不隐藏其耗时。

精确 Linux 制品由正式 CLI 发布到全部 YAML 目标，其他平台和数据面复用原件；只补缺失程序，
独立目标和节点并行。正常认证页面提交全部客户端对应期望，全部正式客户端和配套服务已激活；
control 与数据面程序保持。精确进程、每节点单一共享 WG、正常停止、旧所有权清理、原身份与
不可回退状态均回读，新增管理会话及宿主 LAN、DNS、旧 WG 代理、默认公网和非 Loom 网络保持。
既有云安全链的外部拒绝项变化经精确差异审阅；没有改写共享防火墙，写入者未被认定为已证明。

可达成员的正常认证浏览器读到全部新签名组件报告。两个独立业务服务实际完成 HTTPS，当前
程序另经正式 service 正常停止、同身份重启和基础网络回读。重启后首轮未测路径请求失败，
随后 Auto 自行选择另一获准路径并恢复实际业务，没有清空观测或改变偏好；首轮失败保留。
被替代客户端程序经进程、服务与指针引用核对删除，仍被事实引用的签名公开目录保留。

本节修复的慢管理请求阻塞和重复发布验证已经部署验收。正常页面仍观测到远端报告传播滞后，
一个成员副本仍陈旧；这些现状分别记录，不冒充已恢复，也不作为要求全部链路稳定的软件欠账。
这不宣称全部观测、真实业务反馈或所有平台工作已经完成。软件缺项应由可复现的行为及业务目标
确定，不由页面正常比例决定。正式结果、发布计时、前后实际业务、失败恢复、正常页面及原件
位于受保护 `deploy/evidence/2026-10-11-private-io/`，索引为 `result.json`。

### 临时链路失败下的选路与观测

操作者已确认跨地区底层链路可能暂时封禁或随机丢包；全部链路稳定不能成为业务可用或发布
验收的隐含前提。现场对照已见部分 UDP 流可往返、另一源端口的返回未到达，但尚不能认定
具体外部丢包位置，也不能把换端口描述为永久修复。现行可达性、认证和持久身份仍是不同事实。

复现到共享执行器在本轮两条候选失败后直接拒绝整个服务，即使仍有获准且未测的候选。已按
[多服务独立执行](clients/client-runtime-model.md#多-service-配置与唯一当前互联网-policy)修正：保持有界采样，失败后
应用并回读剩余合格候选，未测路径保持 unknown，下一轮继续；只有没有合格候选才拒绝。
暂时失败到期后仍可恢复参与，不扫描全部路径，也不补造成功。Linux 的独立链路检查改为
有限并发，结果寿命从完成时起算；取消等待检查退出，不补成网络失败。

身份 getter 现在只复制私有已认证领域值，读取实际保护文件时仅复用完整字节摘要相同的
已认证值；新字节、独立句柄的变化、重启和摘要缺失仍完整认证。摘要只在内存派生，不写入
身份，删除即可重建；原规范字节、floor、序列、latch、认证边界与前向规则保持。
最小检查覆盖副本隔离、实际字节损坏拒绝、摘要删除恢复、独立 writer、两次失败后的剩余
选择及到期恢复、独立链路的并发上限、取消清理和完成时间。全仓检查与相关竞态通过。

隔离的真实 Mixed 执行完成正式运行入口、授权 HTTPS、未授权目标拒绝、实际 selector 失败拒绝、
样本到期后未知选择恢复业务、偏好回读、停止和路由保持。旧验收将没有认证探测目标的通用
诊断样本当作服务健康；新旧源码均复现该测试偏差后，已按现行目标范围修正测试，未恢复旧语义。
该隔离结果不抵扣生产报告、全部平台或所有路径的端到端验收。

真实数据面的隔离故障验证还完成两条上游连接被拒绝后的第三条未知路径：实际 selector 保留它，
HTTPS 成功先于下一轮健康确认，指定最终出口保持。现场相同失败结果的串行与并发对照证明
检查等待不再逐条叠加；另一节点两轮实际结果不同，不能将不同网络结果当作纯性能改善。
读取正在运行的身份时，重复复制与同字节 Reload 的实测成本下降；不同字节仍完整认证。

精确 Linux 制品经正式 CLI 签名发布到全部 YAML 目标，其他平台与数据面复用原制品。全部获准
客户端只补缺失 agent，由正式页面提交对应期望后并行切换；control 程序保持。正常停止的
所有权清理、精确进程、同身份恢复与每节点单一共享 WG 已回读。所有远端另建未复用的 SSH
会话核对返回路径，宿主 LAN、系统 DNS、原 WG HTTP proxy、默认公网和非 Loom 路由、规则、
解析及服务定义保持。既有云安全链的外部拒绝项仅按精确差异审阅，没有改写共享防火墙。

可达 control 的正常认证页面读到全部客户端的精确签名组件报告；另一 control 仍显示陈旧事实。
切换后首轮国际业务走未测路径而失败，随后 Auto 不清空观测、不改偏好，实际选择另一获准路径，
国内与国际两个独立服务均完成 HTTPS。正常页面的新报告、RTT 与波动已记录；可达成员仍有
报告迟到及间歇到期，不能用 getter 成本下降宣称全部传输和当前观测问题已解决。被替代程序经
进程、服务与指针引用检查清除，仍被原事实引用的签名目录保留，临时远端诊断程序已删除。

发布虽只传缺失文件，仍重复读取全部公开制品正文；该开销未被本轮修正删除。当前观测工作项
保持 open。正式结果索引为受保护目录中的 `program-and-observation-result.json`；现场诊断、
实际发送与公开读取量、阶段耗时、正常页面及每次失败原件保存在
`deploy/evidence/2026-10-11-gz-hz-investigation/`，不把瞬时网络现象写入模型或作为稳定前提。

### 报告预留：删除同一次写入的重复认证

继续分段定位到客户端预留报告序列的持久写入。旧实现为同一份已接受配置反复解码、投影与验签，
包括已验证字节写后读回的再次认证。现按[身份持久边界](clients/client-runtime-model.md#持久与派生边界)
在锁内完整验证实际当前状态、仅递增序列，编码时验证新规范值；两次写后读回改为与已验证字节
逐字比较。独立句柄、重启、新配置与损坏输入仍完整认证；原子替换、文件及目录同步、失败锁定、
身份、floor 和偏好保留，不增加缓存或第二状态文件。

受保护现场身份的临时隔离副本对照验证同一真实配置证明的预留成本，副本只用于持久化试验，
不连接生产、不预留生产序列，结束后删除。相关持久、并发旧句柄接受新配置、损坏拒绝及保护
适配器检查，以及全仓 build/test/vet、格式、安全、diff 和客户端竞态通过。Windows 持久模块已
交叉编译检查，本次没有据此宣称新的 Windows 原生验收或 Android 发布。

精确 Linux 制品已签名并由正式 CLI 发布到全部 YAML 目标；未变化的其他平台制品复用。
全部获准 Linux 客户端只补缺失 agent，在正常页面提交对应期望后并行切换；原数据面、身份、
认证进度、配置、缓存和宿主基础网络保持。正常停止的所有权清理、精确程序与同身份启动回读通过，
control 保持此前已激活的优化程序。既有云安全链新增的外部来源拒绝项经精确差异复核记录，
其余有序防火墙语义一致；没有修改共享防火墙，也没有据在场进程推断规则写入者已经得到证明。

两台可达 control 的正常认证浏览器均读到全部客户端的新签名组件报告；原偏好下，国内与国际
两个独立授权服务的真实 HTTPS 通过。启动初期国际路径曾未可用，恢复后的成功不抵扣该失败记录。
正常页面继续收到新报告，现场观察中的报告迟到有所下降，但当前 RTT 仍有间歇到期，原不可达
control 的成员回程问题也未恢复，整个当前观测问题保持 open。没有延长有效期或改变健康判定。
旧客户端程序经进程、服务和当前指针引用检查后清除，仍被组件引用的公开签名目录保留。

发布工具虽只上传缺失文件，仍从每个公开入口完整读取目录内全部制品；这项重复发布验证开销
未由本次报告优化消除，不能将“未重复上传”表述成“没有重复传输”。真实发送量、公开回读量、
阶段耗时、首次业务失败与恢复、组件及页面记录位于
`deploy/evidence/2026-10-11-report-reservation/`，写入对照保存于本轮报告交付证据目录。

### 报告交付：未变事实解码与成员连接复用

继续沿真实报告入口分段测量，确认未变普通事实仍反复规范解码，成员同步也在每轮重新支付证明
与普通请求的建连成本。现按[控制原件复用](core/control-model.md)及
[成员同步](core/control-model.md#4-普通写入与大规模增量同步)修订：读回实际原件摘要后复用
相同内容的解码结果，连续尝试分别复用普通连接与受限证明连接。成员身份变化、撤权、证书有效期、
新原件规范检查及完整投影失败语义保持；原权威、报告、采样频率、有效期和页面交互不变。

同一现场普通事实与真实私有连接的只读对照中，重复解码分配和耗时、后续成员请求链耗时均下降；
冷启动与首次连接仍需完整建立。损坏、未知非规范原件、缓存删除恢复、跨轮复用、证明通道隔离、
连接关闭、在途撤权及取消已覆盖。原多进程控制事实测试改为只打开 Authority，
不再让多个完整 runtime 争用已规定由单 daemon 独占的报告库。异常退出恢复检查还发现原打开超时实际不执行锁重试，已补有界等待，持续持锁仍拒绝。
本次不修改报告库格式，不复制或迁移历史，不调整客户端网络。
全仓检查与相关竞态通过，已并行分发缺少的单一程序并在全部 control 激活；原身份、floor、
控制原件、客户端及宿主网络回读保持，旧 control 程序按精确引用检查删除。正常认证浏览器的
新报告和历史已回读；当前观测仍间歇到期，不可达成员的握手响应在两宿主间未送达，保持 open。
现场证据位于 `deploy/evidence/2026-10-11-report-delivery/`。

### 报告存取：取消日常全库复核

按[报告原件事务模型](core/current-contract.md#报告原件的事务持久化)，daemon 现在独占一个数据库
句柄，日常读写使用短事务。可删除重建的定位索引与原件同事务追加；目录只读范围摘要，历史按
时间及精确链路规范定位，最高位置和全部分叉仍从原件核对。规范检查与验签只缓存不可变结果，
不缓存完整报告、当前授权或健康结论。原件、schema、签名、认证进度、历史保留及页面交互不变。
首次构建索引先排序定位项再事务写入，避免无序插入搬移；已有索引的重启不再遍历历史。
原逐次打开数据库、全量内存目录、追加后的目录重建及为其增加的读写排队层已删除。

同一份受保护现场历史副本的对照覆盖真实签名原件追加、目录、当前读取、历史查询、并发提交及
重启，逐字节集合与页面投影相同。首次建索引有一次性成本，重复查询与重启的分配和耗时下降；
不把累计分配量当作常驻内存。事务失败、取消、分叉、时钟回调、索引删除重建、实际原件损坏、
缓存验证键隔离、并发与正常浏览器回归已纳入本次最小检查。
全仓 build/test/vet、格式、安全与 diff 检查，以及相关竞态和实际 Chrome 回归通过。精确 control
制品已签名验证，仅并行传送缺少的程序与原件校验工具；独立远端并行切换后，再切换保留的管理
成员。每台在第一次启动前记录全部原件键与正文摘要，启动后停止校验全部原件保全，再同身份重启；
新程序、认证原件、floor、客户端制品、既有网络对象及基础连接均已回读。被替代 control 程序与
临时校验工具已按精确摘要和引用检查清理，客户端和数据面没有重启或重发。

所有 control 的正常认证浏览器可读取原页面及历史；可达成员持续读到新报告。运行后的匿名内存
采样下降，RSS 中新增的数据库映射文件页单独记录，不把匿名内存变化冒充总内存变化。当前 RTT
仍间歇到期，已有成员同步异常仍未恢复；正式页面观测到的报告迟到没有因存储开销下降而消失，
因此整个当前观测问题保持 open。此次没有延长观测寿命、增加报告频率或改变健康判定来隐藏延迟。
证据、相同副本性能对照、必要发送量、逐原件保全和正常页面时间记录保存在
`deploy/evidence/2026-10-11-report-store-incremental/`。

### 成员同步调度：已激活，生产当前观测仍迟到

上一轮实际浏览器发现可达成员的报告持续迟到，当前 RTT 因原有效期结束而为未知。已将串行成员
轮询改为[独立成员尝试](core/control-model.md#4-普通写入与大规模增量同步)：每成员只有一个在途
请求链，等待中的成员不阻止其他成员的后续调度，成员撤销或换钥取消旧尝试，关闭服务取消并等待
全部退出。原请求预算、schema 3、验签、授权、持久原件和观测寿命保持，没有新同步权威或操作输入。

真实成员 TLS 测试中，一个成员仍阻塞时，另一成员的连续新报告分别持久接收，重新打开后原字节
一致；同成员无重叠、撤销、换钥与关闭取消及竞态检查通过。换钥夹具曾缺少原所有者发起及封存证明，
正确被拒绝；补齐真实成员证明后保持既有仅取证明恢复通道，不将其误判成普通成员授权。
全仓 build/test/vet 已通过；安全检查发现旧测试的固定地址不符合示例规范，改为从演示资源派生
合法执行地址，相关测试和安全检查通过。原失败记录保留。

隔离 namespace 的正式 CLI 加入、真实 WG HTTPS、签名报告及两个 control 的正常 mTLS 浏览器
已通过。一个成员持续不回应时，可达成员仍连续收到新报告与当前 RTT/波动；两台 control 与客户端
同身份重启后继续成立，原报告字节保全、精确清理与宿主隔离通过。截图发现六节点布局的底部标签
与所选链路度量重叠，现仅按节点标签下缘留出度量位置，保持拓扑关系和页面交互。
精确发行已重复完成上述隔离验收，并通过全部发布目标读回；各节点只补缺失程序，数据面复用
已验证原件，独立目标并行分发。全部正式 Linux 程序已激活，组件期望由正常页面提交；正常停止、
精确网络对象清理、身份、原签名材料及基础网络回读通过，control 逐台重启。

生产 Auto 的实际 HTTPS 通过，本机 control 的正常页面读到当前 RTT、波动、计数及全部组件；
另一可达 control 的组件和业务路径已更新，但当前 RTT 仍因报告迟到而未知，最初还出现启动期
快照暂不可读。已有回程丢失的 control 仍未收敛。因此生产验收失败，被替代程序尚未删除，整项
保持未完成。云侧既有管理防火墙链出现外部来源拒绝项变化，已单独保留失败及精确差异复核；
未修改共享防火墙，也不把尚未核实的规则写入者称为已确认。

真实保留报告库的受保护副本验证表明，首次历史验签远慢于缓存就绪后的合并；远端诊断在历史
验签阶段达到总时限。原件没有被诊断写入。后续正常浏览器确认缓存就绪后仍持续迟到；实现还会
沿同一报告目录补多批旧历史直到轮次结束，新到最高范围须等下一次取目录。当前修订为每次
只提交一个有界批次，再由下一次尝试重新优先比较最新范围；历史验签逐条响应取消，不扩大
TTL、请求时限或协议号。真实 TLS 积压回归已先复现旧行为失败，修订后的完整回归、精确发行与
隔离原生验收通过；精确制品已发布并切换全部获准 Linux 服务，三台 control 同身份重启回读通过。
生产 Auto HTTPS、两台可达 control 的组件与路径通过，但另一可达 control 的当前 RTT 仍未通过，
原回程异常成员也未恢复；被替代程序继续保留，不称验收完成。

后续只读诊断已分别确认单条和完整实际批量可沿正式成员认证接口取回，原件解码、验签通过。
两次目录求差没有旧范围积压，目标原件集合仍在增长；因此不能把当前全部延迟归因于历史补传。
首次严格读取真实历史仍慢，另有每请求重建 TLS 的重复成本。相同接口的只读连接复用对照已有
改善，已按[同次成员请求复用](core/control-model.md#4-普通写入与大规模增量同步)修正：普通请求
仅在同一次尝试中复用连接，证明恢复仍使用独立受限连接；复用时继续核对当前成员、验证键和
证书有效期，结束即关闭空闲连接。真实 TLS、撤销及换钥取消、证书到期、竞态及全仓检查通过。
精确 Linux 发行在隔离环境完成加入、实际 WG HTTPS、原签名报告、正常浏览器及同身份重启验收。
全部发布目标和公开正文已验证，各节点精确服务已切换，原事实、身份、认证进度与基础网络保全；
组件期望经正式页面提交。后续恢复验收已将独立远端 control 并行重启，前组回读成功后再重启
保留的管理成员，调度要求同时写入工作指引和配置模型。

生产 Auto HTTPS、两台可达 control 的路径与全部组件匹配通过；本机页面的当前 RTT、波动和
双端历史通过，另一可达 control 的当前 RTT 再次超时，已有回程异常成员也未恢复。因此本轮
生产验收仍失败，被替代程序没有删除。随后本机管理接口的只读取样确认报告迟到和远端页面
数据读取耗时同时存在；分段读取确认生产连接实际复用，不能把这项改善称为问题已解决。
继续测量原签名报告在两端首次可读的时间，不增加权威状态或放宽样本有效期。前轮诊断保存在
`deploy/evidence/2026-10-10-report-batch-yield/`，本轮发布、失败与诊断保存在
`deploy/evidence/2026-10-10-member-connection-reuse/`。

正常拓扑页直接选择获授权链路后仍无法稳定取得当前 RTT，已排除“必须先拿到新鲜全量快照才能
打开详情”的验收前提。实际页面的历史请求和源码核对进一步发现：流量聚合在数据库读句柄内
解码、验签和计算，会阻止新报告取得写锁。并发回归先复现写入超时，现按
[历史读取边界](clients/web-ui-projection.md#页面和状态)固定本次原件键后分批复制，在锁外统计。
并发新报告与补历史、固定查询输入、原字节保全、损坏及取消拒绝的回归、竞态和全仓检查通过；
精确发行的隔离原生加入、实际 WG HTTPS、报告、正常浏览器及同身份重启与精确清理通过。
全部公开发布目标、正文和指针读回通过，必要文件并行分发，三台 control 与全部 Linux 服务已切换；
组件期望经正常页面提交，远端 control 并行重启后再重启管理成员。身份、原字节、认证进度及基础
网络回读通过；既有防护链的外部来源拒绝项变化另存精确差异，未改动共享防火墙。

生产 Auto HTTPS、两台可达 control 的组件、路径和流量历史通过，本机当前 RTT 与波动通过；
另一可达 control 的当前 RTT 再次超时，已有回程异常成员仍失败，被替代程序未删除。页面实际收到
的报告已超过链路观测有效期，读锁修复没有解决全部延迟，不能据局部改善关闭此项。
重启后首轮页面快照较慢，发布中的一次提前浏览器读回也超时；原失败、正常入口结果和只读时间
记录分别保留。继续对照原签名报告在两端落盘与正常页面收到它的时间，定位剩余延迟。
本次证据保存在 `deploy/evidence/2026-10-10-history-read-contention/`。

后续现场文件锁采样确认：报告写入等待时，后到的页面读取仍持续取得共享锁，使写入饥饿。
按[报告事务读写顺序](core/current-contract.md#报告原件的事务持久化)为同一 store 的数据库操作
接入可取消的公平读写许可，排队与文件锁共用原取得锁期限，既有读取并行完成，锁外统计不占许可。
正常报告提交与后续快照、取消与失败后的继续写入、原件重启保全的回归与竞态通过。生产报告库的
受保护副本在并发历史查询期间成功提交后到的真实签名报告，原字节一致，原库未改动且副本已清理。
精确发行的隔离原生加入、实际 WG 业务、签名报告、正常浏览器及同身份重启已通过。
全部目标并行发布并激活，正式页面写入组件期望、分组 control 重启和原件回读通过；随后生产
Auto HTTPS 成功，但新签名偏好的页面回读失败。只读认证请求确认设备使用的私有入口连接被重置，
承载入口的节点在配置应用时因 WG 对端域名重复解析失败而退出数据面。一次显式重新加载后该节点
恢复，正常认证配置读取及全节点身份、floor、网络与新建管理连接回读通过；原失败保留，页面复验
已确认本机 control 的当前 RTT、波动、组件和业务路径通过；另一可达 control 的新 Auto 报告、
组件和流量历史通过，但当前 RTT 仍超时。已有回程异常成员也未恢复，被替代程序尚未删除，
当前 RTT 缺口保持未完成。
同时核对发现，Linux adapter 已解析的管理 peer 地址未进入原生执行配置。正按
[认证解析与运行消费](clients/client-runtime-model.md)接回既有地址，不改认证域名、公钥、权限或启动期限；
原生反例已先在旧代码复现，IPv4/IPv6 地址消费与拒绝回归、竞态通过；隔离网络中已通过
数据面无法自行解析原域名时的实际 WG/Hy2 业务、管理返回路径、停止及原缓存恢复。独立内核
对端夹具起初仍使用域名，修正为同一测试解析结果后通过，原失败保留；该修正现已随下述发行部署。
本轮证据保存在 `deploy/evidence/2026-10-10-report-writer-admission/`。

后续生产 CPU 采样与真实历史副本对照确认了两项重复成本：未变化的报告索引仍先分配完整 map，
同一次页面快照又为路径和报告分别生成相同设备执行投影。现按
[原件索引检查](core/current-contract.md)与[同请求投影复用](clients/web-ui-projection.md#页面和状态)
修正；逐条原件摘要、规范键、报告签名及当前授权验证保持。正常管理快照入口使用相同原报告副本、
真实授权与已验签发布集合，对照输出逐字节一致，分配和处理耗时下降；生产原件未写入，副本已精确清理。
撤权后的下一次请求排除旧报告，匹配新 View 的报告可再次显示，篡改签名拒绝；索引同数量替换、
删除、损坏、取消及竞态检查通过。含大容量签名夹具的竞态执行与相关边界竞态执行均已通过；
全仓 build/test/vet、格式、安全与 diff 检查通过。
精确发行已完成隔离原生加入、真实 WG HTTPS、签名计数与 RTT、正常浏览器、失联成员不阻断
其他成员进展、同身份重启和精确清理验收。全部公开分发目标已完成正式发布与实际 HTTPS 正文核验；
只补传缺失文件，独立目标和节点并行。生产客户端、三台 control 和配套服务已切换，运行配置中的
主动 WG peer 确认使用已解析 IP，每节点仍只有一个共享接口。身份、原事实、认证进度、非 Loom
网络对象和新建基础连接回读通过；组件期望由正式页面提交，分组 control 重启后原件继续可接受。

发布中途的正常页面提前检查失败：当时客户端仍运行旧程序，报告上传显示失败，正式认证配置请求
却能取得相同 View；不能将其归为此前的数据面退出故障，也不能把这次检查抵扣最终验收。全部切换后
Auto 真实 HTTPS、报告上传及本机 control 的当前 RTT 和波动通过；另一可达 control 的全部组件、
业务路径和双端流量历史通过，但当前 RTT 仍超时，既有回程异常成员也未通过偏好回读。两端原签名
报告的只读取样已确认，目标端取得新原件时相应 Link 样本仍会过期，故局部性能改善没有闭合生产
时效缺口；被替代程序尚未删除，整项继续 open。公开核验仍下载目录引用的完整制品正文，不能将
校验量称为新增上传量。成功、失败、原件到达时间和精确发行证据保存在
`deploy/evidence/2026-10-10-report-index-reuse/`。

后续分段测量确认，写入已取得公平许可后，原件全库扫描仍可能耗尽提交期限。当前源码将一次
提交的历史检查限定到输入设备的完整原件范围，并将链路、运行和流量历史的原件摘要检查移到
有界复制后的锁外；相关范围仍逐条核对，不以缓存高水位或文件属性替代原件。跨进程提交、
同序列分叉、跨复制批次分叉、相关原件损坏、取消及原字节保全回归和全仓检查通过。生产副本中，
并发历史查询下的单设备原件提交通过；该验证没有覆盖实际成员同步中多设备一起提交的批次，
不能据此推断完整同步链已满足当前观测时效。副本在原节点本地生成，未跨节点传输数据库，
诊断结束后按精确所有权清理，生产原件没有被诊断改写。

精确发行的隔离原生业务、报告、正常浏览器、当前 RTT 与同身份重启通过；全部发布目标读回，
必要程序并行分发，正式 Linux 服务与三台 control 已激活，组件期望经正常页面提交。
独立远端 control 并行重启后再重启管理成员，身份、原事实、认证进度和基础网络回读通过。
生产 Auto HTTPS、本机 control 的当前 RTT 与波动通过；另一可达 control 的组件、业务与流量
通过，但当前 RTT 再次超时，既有回程异常成员仍未恢复。被替代程序尚未删除，整项仍未完成。

重启后的原签名报告只读取样继续确认目标 control 首次取得原件时，观测已超过原有效期；
成员认证、目录、ID 和原件的只读请求链也存在明显延迟。该诊断不包含目标端的实际批量提交，
不能把总延迟都归给某一个接口或网络 RTT。当前写入仍扫描输入设备的完整历史，最新报告读取和
成员交换的多条路径仍扫描全库；多设备提交可能再次覆盖大部分历史。下一步性能验证必须包含
实际成员批次和正常页面并发负载，不能用单设备写入改善或隔离小数据集通过替代生产验收。
针对时钟偏差的现场复核已并行读取全部部署节点的 UTC、NTP 同步状态与 chrony 偏差估计；
本次样本全部显示同步，偏差估计远小于已测得的报告迟到时间。该结果只证明当前采样，
不能推断从未发生过时钟跳变；现有证据不支持将本轮持续迟到归因为服务器未校时。

另一项现场读回确认，源 control 的服务内存限额持续触发回收。按
[本机服务限额](operations/configuration-model.md#私有入口的节点执行输入)核对宿主余量、原服务与
独立管理连接后，已仅调整该 control 的持久内存上限，调整当时原进程及网络对象保持。后续原客户端报告
及该 control 正常浏览器的当前 RTT 恢复，另一可达 control 的当前 RTT 仍超时；增加限额没有
关闭整体缺口。原报告随周期持续追加和成员同步，当前没有自动历史过期清理；页面样本时效
不是持久保留期限。报告保留边界及随历史增长的处理成本仍是未解决的容量问题，不能将增加
内存或数据页容器变更称为其完成，也不能据此直接删除现有原件、高水位或分叉证据。
本次正式服务重启后的内存读回已分别记录匿名内存、文件缓存、服务上限及限额事件；
当前占用与配置上限不是同一个数，文件缓存也不能全部解释为 Go 堆或业务数据。
限额变更、失败与成功回读、诊断副本及实际传输范围均保存于
`deploy/evidence/2026-10-10-history-hash-unlock/`。

本轮进一步核对确认数据库已有按网络、设备、序列和摘要排序的 B+ 树，缺口是当前调用没有
利用位置查找，而非遗漏一条 SQL 索引。按[报告原件事务](core/current-contract.md#报告原件的事务持久化)
修订：提交只验证本批所有者的实际最高位置及输入位置，当前状态只取实际最高位置及全部分叉；
目录检查实际键集合，取件仍核对原正文、规范键和值并在消费处验签。删除随历史增长的 writer
验签记忆和每次写入复制完整索引。历史查询按同一内容 ID 的不可变元数据排除窗口外正文，最高
位置始终核对；未知元数据读取原件，完整键集合保留分叉，跳过位置仍切断计数相邻关系。
服务路径历史也改为有界复制、锁外计算，不再占用整个统计期间的数据库读句柄。

必要位置损坏、跨进程高水位、直接重放、旧位置分叉、跨设备原子批次、取消、索引丢弃与原件
重启保全回归及竞态已通过，全仓 build/test/vet、格式、安全与 diff 检查通过。同一生产副本
分别运行旧实现与本次实现，覆盖实际多设备批次、并发 Link/流量历史、目录、最新状态及取件；
两组均完成全部原件逐项核对和重启前后最新报告逐字节一致，新实现减少了处理耗时与分配。
首次实验将参与批次设备数量误作全库所有者数量，导致两组相同断言失败；已改为完整原字节
比较，保留失败原件。对照期间宿主还有其他工作负载，耗时只说明本次实验，不当作固定性能保证。
生产库没有被实验写入，本机副本已清理；冷启动全库解码、目录遍历和历史保留容量仍有成本。
远端生产副本也完成多设备批量提交、全部原件核对及重启最新报告逐字节保全；临时副本和诊断
程序已精确删除，数据库没有跨节点传输。精确 Linux 发行在隔离 namespace 完成正式 CLI 加入、
实际 WG HTTPS、签名报告、正常 mTLS 浏览器的当前 RTT/波动、失联成员不阻断其他成员及同身份
重启恢复；全部 owned 对象正常清理。必要程序并行分发，全部正式 Linux 服务和 control 已激活，
发布目标、组件期望、原身份、认证进度和基础网络回读通过。生产 Auto HTTPS 及本机 control 的
当前 RTT/波动通过；另一可达 control 的当前 RTT 再次超时，原件到达改善没有关闭页面时效缺口。
正常浏览器追踪显示链路历史可以返回有效观测，但全量状态快照持续超时，实时帧更新也落后。
代码确认快照和设备期望每次都在同一发布库锁内哈希全部安装包。按
[签名发布对应](core/current-contract.md#签名-catalog-与安装包运行文件的对应)分开无状态的原签名
元数据投影与实际包消费校验；不增加权威值，不放宽原件、下载或安装验证。源码修正已接正式
control 入口，必要单测、竞态及全仓检查通过。精确发行完成隔离业务与原件恢复，并行发布及全部
Linux 服务激活；三台 control 重启后原事实继续可读。正常页面的两台可达 control 完成业务路径、
组件、流量及一次当前 RTT/波动回读，已有回程异常成员仍失败。正式私有浏览器下载实际 Linux 包，
长度及摘要与签名目录一致。经精确摘要、进程及 unit 引用核对，被替代且无引用的旧程序已删除，
基础网络与身份回读通过；原签名材料与历史没有删除。
随后持续正常页面观察仍发现所选链路的波动长期未知；一次回读通过不能抵扣连续显示缺口。
当前 RTT 不称完成。实验、检查和发布证据保存在 `deploy/evidence/2026-10-10-report-query-scope/`
及 `deploy/evidence/2026-10-10-release-metadata-projection/`。

上述分配实验统计的是处理期间累计申请的字节，不是常驻堆、峰值内存或需要保留的历史体积。
首次写入原实现遍历历史并建立验签记忆，现已删除这项重复工作；持久原件的保留边界仍单独待解决。
现场 control 资源取样没有 CPU 配额或节流，也未触发内存上限或 OOM，不能据此将剩余页面问题归为
资源限额。该结果只覆盖本次取样；匿名内存、文件缓存、宿主负载与压力分别留证。

正常拓扑页的被动观察进一步确认：所选 Link 的 RTT 请求仍与全表轮转，持续刷新未得到优先。
按[页面历史调度](clients/web-ui-projection.md#页面和状态)修正所选 RTT 与流量的优先顺序，并让
波动按响应实际绑定的报告判断，不由请求开始时的旧刷新标记否决。并发仍有界，后台链路继续轮转，
原授权、最新报告序列、原有效期与撤权拒绝保持。实际浏览器交错回归及全仓检查通过；精确程序包
已签名并独立验签，仅三台 control 完成部署。远端同时分发必要程序、并行切换并回读，再切换管理
成员；client 指针、实际进程、数据面、公开目录和组件期望保持。各 control 的真实进程摘要、原始
签名事实、成员、身份、认证进度、WG 所有权、路由、规则、防火墙、解析及基础新连接回读通过。
切换后的真实 Auto HTTPS 通过，三台正常认证页面加载精确源码；两台可达 control 持续观察均多次
取得所选链路 RTT/波动。远端随后另一轮被动观察再次显示有效结果，未增加人工 API 轮询；临时
浏览器凭据已删除。验收脚本曾将 daemon-reload 清空的 ExecStart 执行记录误作进程改变，已按实际
MainPID、程序摘要、命令及 unit 分别复核；保留失败证据，未重复重启已成功的远端服务。

这项页面修正没有解决全部报告时效：远端仍有较长未知时段，实际收到观测时原有效期已经所剩无几，
当前报告的历史响应有时不再包含有效 RTT 统计。只读成员请求复测继续显示多步认证与取件累计耗时，
其中包括网络与远端处理等待，不能全部归为接收节点 CPU。已有回程异常成员仍无最新业务报告；
整体同步时效和历史容量问题继续 open。实际修正、持续观察、资源及只读分段证据保存在
`deploy/evidence/2026-10-10-selected-link-history/`，没有延长观测寿命、调整资源限额或删除历史原件。

隔离启动的首轮参数使进程观察到同一 PID namespace 的初始网络，安全门禁在创建网络对象前拒绝；
修正启动方式后继续，门禁没有放宽。另一次验证错误地把正常报告周期计入同步超时，现先确认新原件
在源端落盘，再计时回读目标；原生产频率与有效期不变。失败记录与原件对照均保留在
`deploy/evidence/2026-10-10-member-sync-scheduling/`。

### 共享 WG 流量：已激活，生产验收仍未通过

已核对用户态 WG 的真实计数来源，并按[报告计数模型](core/current-contract.md#共享-wg-的原始计数与流量派生)
接入原签名报告、三端采样入口、小时增量、有效覆盖速率与页面。网络汇总按发送端计一次，正反 Link
明确共享同一 peer；设备分列 RX/TX，所选 Link 显示双端同尺度 TX，Live paths 引用同一共享范围。
没有样本与实测零值分开，重置、时钟矛盾、规范变化及序列分叉不会补造流量或当前速率。

隔离数据面的双 peer TCP/UDP、计数分离、认证拒绝与实例重启通过，四个平台的精确数据面已构建。
正式 CLI 加入的多个 Linux 执行实例经共享 WG 完成真实 HTTPS，计数随原报告从私有入口持久化，
正常 mTLS 浏览器读取双端历史和速率；控制重启保留原字节，客户端重启换 epoch 并恢复业务，正常停止
精确清理通过。原报告字节兼容、整数精度、授权范围、拒绝、撤权与真实浏览器选择/刷新/未知显示通过。
精确 Linux 签名包及数据面重复完成上述正式业务链。Windows VM 的普通界面加入、独立 WG HTTPS、
撤权、原 DPAPI 身份重启、重新授权和计数 epoch 更新通过；测试使用同源码 UI 程序及精确签名数据面，
不把它称为全部发行包的实体机验收。Android 正式 APK 的普通界面加入、独立 WG VPN HTTPS、撤权、
同身份进程重启、重新授权、新 epoch 和 control 重启保留原报告通过。三端均检查了原私有报告签名。
Android 首轮被模拟器启动时的 System UI 超时弹窗阻断，处理弹窗后业务链通过；失败证据保留，未重建身份。
Windows VM 和 Android 模拟器均已正常关闭，临时 Windows 测试输入权限已恢复；原身份和测试失败证据保留。
真实 Linux 浏览器回读另发现混合节点在路径图重复显示为一跳；修正仅收敛显示及对应 Link 边，
保留实际候选、选择及授权。低于显示精度的正流量单独标记，不再显示成实测零值；浏览器回归通过。
精确三端制品已沿正式 CLI 发布到全部 YAML 目标，全部公开 HTTPS 正文和目录指针读回通过。
独立节点并行，只传缺少的必要文件；一个节点的首轮传输超时后按原部分文件续传，未重发全部内容。
旧发布校验器不能接受新增的已审阅数据面，首次调用失败且未推进目录指针。保留失败后，先更新
目标校验程序和全部 control 消费者，再启动新增计数报告的生产者；同目录重试复用已核验文件。
六节点已激活精确新程序和同一数据面，每节点仍只有一个共享 WG，身份、认证原字节、floor/latch、
原路由、策略规则、解析配置、服务定义及管理和基础连接已回读。组件期望经正常页面提交，
两台 control 已读到全部节点匹配的实际签名组件报告；另一台仍因下节记录的私有回程问题停在旧报告。

Direct 的境内 HTTPS、指定既定境外出口的国际 HTTPS 和 Auto 实际请求均通过。首次 Auto 浏览器
验收时另一台 control 未在限定时间内显示新报告；之后已读到新鲜 Auto，不能将该独立超时归因为
已知回程故障，首次失败保留。正常停止、SIGKILL、精确清理与恢复、控制服务逐台重启及最终
身份和宿主网络读回已经通过。
其中两台 control 已读到所选 Link 的双端历史与速率；首轮一台图表加载超时的失败仍保留，
重启后只读请求记录和实际截图已回读正常，Auto 真实业务及这两台 control 的路径页面也通过。
两轮被替代程序经精确摘要、进程和 unit 引用核对后删除，删除后的全部节点与宿主基础连接回读通过。
原身份、签名材料及受保护证据保留；程序激活及这些局部结果不抵扣全控制面同步验收。

对连续新报告与慢查询的实际 Chrome 复现还确认：旧页面会反复取消同范围历史读取，后续流量图
得不到执行。修正把授权范围与刷新依据分开，所选 Link 优先首次读取，缓存范围轮转刷新；新报告
不取消同一授权的在途读取，旧历史保留原截止时间，当前速率须等待对应刷新完成。撤权、规范变化、
未知值、精确零值和迟到响应拒绝已有浏览器验证。修正已随精确 Linux 制品发布到全部 YAML 目标，
六节点和全部 control 已激活；两台 control 的正式浏览器读到新页面、全部精确组件、路径与双端图，
Auto 实际 HTTPS 通过。另一台仍为已知私有回程阻断，不能据局部结果关闭整项。旧程序经精确引用
核对后删除，删除后的身份与全部基础连接回读通过。原生加入、共享 WG 业务、原报告及同身份
重启恢复均使用同一发行程序验证；新增部署结果在 `deploy/evidence/2026-10-10-history-scheduling/`。
测试在整点跨小时误设有效增量的
首轮失败已保留，修正夹具后通过，没有放宽跨小时不插值的领域规则。
RTT 与波动的后续实现见下节。原始结果位于 `deploy/evidence/2026-10-10-wg-counters/`，本项保持 open。

### WG DNS RTT 与波动：已激活，生产验收未通过

既有 DNS 探测现在分别报告完整耗时和连接建立后的请求往返；后者明确显示为 WG DNS RTT，
包含端点处理，不冒充 WG 握手或纯线路时延。没有新增连接、探测频率、业务权限或选路权重。
新增可选原值沿同一 schema 3 签名报告保存，旧字段缺席的规范字节保持；失败不产生 RTT。
拓扑连线、表格、所选 Link 及实际路径消费同一方向原值；原报告详情纠正了把 WG DNS 完整耗时
标成 HTTPS 的错误。十五分钟 P50/P95 与差值直接取原报告，重复、冲突、分叉、旧规范、旧网络代、
未来及失败样本不补数。少于两个独立样本为未知，有效零值保留。报告序列进入只读投影与刷新依据，
避免设备时间相同的新报告继续使用旧分位数或当前速率。

全仓 build/test/vet、格式、安全及 diff 检查通过；真实 Chrome 验证零值、缺失后恢复、相同报告时间
的新序列、连续刷新和已有历史导航。正式 CLI 在独立 network/mount namespace 完成多个节点加入、
共享 WG 的实际 HTTPS、真实 DNS RTT、私有签名报告、正常 mTLS 浏览器及分位数回读；control 重启
保留原报告，客户端同身份重启后继续真实采样与业务，正常停止精确清理。截图已审阅。
精确签名发行程序已重复完成相同隔离业务链及重启验证，截图已审阅；全部 YAML 发布目标和公开
HTTPS 正文回读通过，六节点及三个 control 已激活，组件期望已通过正常页面提交。正常停止、
精确清理、基础网络及控制逐台重启回读通过，原身份、签名字节和不可回退状态保持。

生产 Auto 的国际 HTTPS 通过；本机 control 的当前 RTT、多样本分位数与波动页面通过。另一台
control 的首轮页面曾返回 503，随后恢复并读到全部节点新鲜组件；但报告仍延迟，当前 RTT 样本
在它读到前已过期，正式浏览器因此超时。该内部缺口与另一台 control 的已知外部回程问题分开保留。
源码核对确认成员反熵串行等待会让失联成员拖住可达成员的后续报告；正在按原模型修正独立调度，
不延长样本寿命、不改变选路。被替代程序暂未删除，不能将本轮激活或局部通过写成整体完成。
证据位于 `deploy/evidence/2026-10-10-link-round-trip/`。首次计时夹具缺少合法资源认证字段而被拒绝，
补全演示资源后通过，未放宽执行入口或字段校验。Hy2 独立探测吞吐和事件完整窗口仍有缺口。

### 管理快照的发布目录重复读取：已激活，生产验收未通过

沿正式快照路由复现了组件期望与当前下载使用同一目录时的重复整包验证。修正仅在一次请求
内复用已经验证的相同 `ReleaseSet`；其他保留目录仍独立验证，下一次请求仍重读原字节。
正常入口、当前指针变化、缺失目录、失败部分值拒绝及恢复检查通过；真实签名目录与生产权威的
只读对照返回完全相同的快照字节，减少重复包读取。对照未接入设备报告，不能宣称全部页面或发布
耗时按相同比例减少。完整构建、测试、vet、格式、安全检查及真实 Chrome 回归通过。
精确 Linux 程序在隔离环境完成正式加入、Mixed HTTPS、原签名报告与重启恢复。

独立分发目标并行补齐缺失文件，全部公开正文及条件指针回读通过；六节点程序已经激活，
组件期望从正常页面提交，正常停止的精确清理、身份和基础网络已回读。生产 Auto 的实际请求通过，
但其中一台 control 的报告停留在切换前，其他两台页面有新鲜回读；当次整项生产验收失败。
后续控制重启验收和被替代程序删除已随上述共享 WG 计数与历史查询修正完成，私有同步缺口仍在，
程序运行与组件存在不能抵扣该缺口。

只读核对确认，受影响 control 的两个私有目标均经现有、由 Loom 管理的共享 WG，新的 TCP 连接
超时。双端抓包显示接收节点收到境外 WG 握手并发出响应，境外两端没有收到回包；另一个已配置
UDP 映射上的普通短报文也有相同回程丢失。操作者此前确认云端没有出站 UDP 限制，该操作史保持；
当前丢失位置与原因待外部回程证据核对，不能改称已证明的云策略故障。未改路由器、NAT、共享
防火墙或身份，没有放宽授权，也未把其他节点的成功当作全网通过。其他不依赖此回程的实现继续。

首轮失败与回程证据在 `deploy/evidence/2026-10-10-web-snapshot-release-reuse/`，恢复后须重做失败的
正式浏览器范围和全控制面业务回读；后续已完成的重启和精确清理不改写首轮失败，尚无全网完成回执。
RTT、流量、波动、事件完整窗口及其余既定缺口仍在推进，整个核心工作项不关闭。

### 链路小时历史与发布导入复用：已部署并回读

Topology 已按[链路小时历史](clients/web-ui-projection.md#页面和状态)接入固定小时槽，
从发送端原签名报告读取精确 LinkID、方向、资源与当前规范范围内的 WG 观测；每小时取最后样本，
不代表连续可达率。没有新增探测、Hy2 Link、流量事实或历史权威，同时间冲突、同序列异文、
错误签名及范围变化不能填图。当前状态继续独立判断时效；其他 Service 或组件期望变化不抹去
仍匹配的链路样本。查询复用可丢弃的原报告位置索引，入选原件重新验签，索引重建与重启结果一致。

拓扑行保留当前观测、方向、小时状态与传输历史的位置；读取失败可重试，页面刷新保留拓扑选择，
离开范围取消查询。设备详情的长版本号按栏换行。发布前复核还修正了原拓扑把接收端限为 forward
的错误：原生 WG 接收端仅承担 internet_egress 也可保留合法链路；控制授权和传输执行未改变。
接口与真实 Chrome 覆盖这一资格、原件范围、重试、撤权、导航和长版本布局。完整源码检查通过；
测试的错误目标改为从演示资源派生，保留 IPv6 私有执行地址的既有拒绝边界，初次失败记录保留。

首轮已切换的程序在真实拓扑页返回 503：历史查询错误地依赖完整设备配置生成，而现场组件期望
需要的发布材料没有传入。开发夹具缺少该条件，未提前暴露问题；当次运行历史、Auto 业务和组件
通过不能抵扣链路历史失败。修正后，查询直接消费已授权 Link、两端资源的规范摘要和原签名报告，
不受无关组件期望影响，设备执行配置的完整验证仍保持。带组件期望的接口与真实浏览器回归通过，
并在现网真实签名权威和原报告库上只读运行正式查询路由，全部当前 Link 都返回原始小时样本。
失败记录保留在 `deploy/evidence/2026-10-10-web-link-history/`；修正版重新完成以下正式发布与回读。

精确发行程序在独立网络空间完成正式 CLI 加入、Mixed HTTPS、原签名报告、正常 mTLS 浏览器、
control 重启及同身份客户端恢复。原报告与历史保留，重启不续期。本次隔离 Direct 夹具没有
正向 Link 传输；Link 的真实样本由现网原报告只读查询及以下生产页面验收覆盖，不拿缺失查询的
拒绝结果冒充链路业务。原三分钟自然到期规则沿用上一项已验结果，未因本项改动重复等待。

仅重建 Linux 包，原 Windows、Android 和数据面制品继续复用。独立节点与发布根并行，目标只接收
新增不可变文件；全部公开 HTTPS 正文与条件指针回读通过。六节点正式程序已切换，组件期望通过
正常管理页面提交。三台 control 的真实浏览器均读到全部显式 WG Link 的小时历史、全部节点运行
历史和精确组件；列表与详情截图已审阅。生产 Auto 的国际业务通过，control 逐台重启后再次核对
业务、历史和组件。选路与传输执行未改，不把本项当作其余模式或实体机的重新验收。

停止时精确清理、一个共享 WG、独立 Hy2、原身份、密钥、签名字节、floor/latch、管理与基础网络
均已回读。早先未激活候选和被替代程序经摘要、进程与 unit 引用核对后删除；保护证据保留。
没有改写共享防火墙或宿主网络服务，已存在的云安全链变化只按精确规则与新连接回读处理。

发布导入在一次调用内复用已按同一独立公钥验证的包解析结果，仍逐件重读完整正文并核对长度、
摘要、manifest、签名、锁内指针与目标原件。真实签名包的篡改、prepare 不切指针、重开、并发
旧计划和禁止回退检查通过；只读对照证实每包重复深度解析减少。新版工具激活后，各正式目标经
原 CLI 对当前目录再次 prepare-only，全目录、原指针与 floor 保持；不把本机解析提速写成整次
公开 HTTPS 发布耗时减半。

完整结果为 `deploy/evidence/2026-10-10-web-link-history-scope/web-link-history-scope-production-closure.json`。
RTT、流量和波动的实际输入与投影、事件完整窗口仍有缺口；生产网站签回、指定 LAN 和旧发布 floor
前向消费分别保持未完成，实体机终验由用户完成，整个核心工作项不关闭。

### 设备运行历史与浏览器时钟恢复：已部署并回读

Devices 列表与设备详情已接入[运行状态小时采样](clients/web-ui-projection.md#页面和状态)，
从原签名报告读取固定 24 个小时槽，区分运行、明确错误、停止、显式未知与没有样本；不将其画成
连续在线率，不从流量或业务结果补造状态。原报告摘要、序列、采样时间与 View 保留在历史回读中；
同序列异文、错身份、未来和窗口外样本均不入图。浏览器只请求当前页面所需设备，最多同时两项，
撤权与离开页面后移除相应缓存和请求；读取失败可重试，当前状态继续独立按时效判断。
读取复用原正文摘要索引中的原时间，保留全设备范围检查和入选原件验签。现网报告库的只读对照已
确认索引就绪后的查询消除了重复全量解码；首次索引重建单独计时，冷热缓存结果与重启结果一致。

真实 Chrome 复现并修正浏览器时间跳到未来后校正，后续有效投影仍受旧时间基准排除的问题。
仅新服务端投影重建本地时间基准，旧样本不会因本地回拨恢复。必要报告边界、原字节重启和浏览器
状态条、草稿、详情链接及撤权回读已通过；一次夹具把样本放到注入时间之后，历史正确排除该样本，
修正夹具时间后通过。完整源码检查发现下载取消测试的空响应完成竞争，夹具现保持未完成响应直到
取消回读结束，保留其原取消断言。

精确 Linux 发行程序在独立网络空间完成正式 CLI 加入、真实 Mixed HTTPS、原签名报告及正常
mTLS 浏览器回读；历史字段与原报告一致。客户端异常退出后等待原三分钟自然到期，当前状态变为
未知而历史保留；control 重启及同身份客户端恢复后再次核对。仅重建改动的 Linux 包，复用原
Windows、Android 与数据面；发布目标并行增量准备，公开 HTTPS 全部正文及条件指针回读通过。

六节点正式程序已切换，组件期望由正常管理页面提交；三台 control 的正常浏览器均读到全部节点
的当前状态、固定小时槽、原始历史和精确组件坐标，列表与详情已查看实际截图。生产 Auto 的国际
业务通过，控制服务逐台重启后再次核对业务、历史与组件；本项不改选路执行器，未重复上一轮已经
完成的其他模式及未改动的平台安装。停止时精确清理、一个共享 WG、独立 Hy2、原身份、密钥、
认证字节、floor/latch 及管理与基础网络保持。既有云安全链的外部来源 SSH 拒绝规则变化已逐项
核对，具体写入进程未证明；未改写该链。旧程序经进程与 unit 引用核对后删除。

完整结果为 `deploy/evidence/2026-10-10-web-observation-history/web-observation-history-production-closure.json`。
当时截图发现详情长版本号挤占相邻栏，修正与 LinkID 状态条验收见上一节。流量范围与扩展度量仍有缺口；生产网站签回、指定 LAN 和旧发布 floor 前向消费
继续分别保持未完成，实体机终验由用户完成，整个核心工作项不关闭。

上一轮同一公开入口的顺序/两路小流量读取对照没有证实明显提速，未增加无收益的并发；独立发布根
和节点继续并行，完整正文验证保留。读回成本与本轮证据记录于
`deploy/evidence/2026-10-10-web-observation-history/`。

### 管理页面的观测时效：已部署并回读

按[接收端限时投影](core/current-contract.md#接收端的限时观测投影)补齐运行报告、实际选择、
组件回读及逐条样本的时效。运行报告采用已说明的三分钟工作假设，样本另受原始有效期和层级
上限约束；当前与历史分别显示，不延长原样本、不修改签名 wire、客户端选路、探测频率或宿主时钟。
未来或过长时间、最新报告失效、网络/规范不匹配、多目标混合和空集合均不制造可用结论。
运行与目标结果不能变成整机在线或健康；原始签名、原时间、偏好与历史选择保留。

必要源码检查和真实 Chrome 回归通过；页面在到期时保留编辑文字、焦点和选区，慢请求完成也
不会把操作者拉回已经离开的页面。正式 Linux 包内的同一程序在独立网络空间完成 CLI 加入、
真实 Mixed HTTPS、签名报告与 mTLS 浏览器回读；终止客户端进程后等待原三分钟自然到期，当前
显示未知，原成功样本保留历史。control 重启不续期，同身份客户端恢复后，真实业务和当前回读
恢复，原样本截止仍保持。首次旧验收脚本的浏览器名称不匹配记录保留，修正脚本后分别完成开发
程序与精确发行程序验收；没有放宽产品 TLS。

仅重建改动的 Linux 包，复用原 Windows、Android 与数据面制品；全部发布目标并行增量准备，
公开 HTTPS 完整正文核验和条件指针回读通过。六节点仅预置必要的新 agent，原数据面本地复用。
生产正式服务已激活，组件期望通过正常页面提交；Direct 对应国内业务，指定境外出口与 Auto
对应国际业务，三模式在全部 control 的正常浏览器回读通过；control 重启后复验 Auto 真实业务、
原签名报告和全部组件回读，原 Auto 已恢复。停止时精确
清理、恢复后一个共享 WG、独立 Hy2、显式 Mixed、原身份/密钥/认证字节/floor/latch、管理与
基础网络均已回读；对应旧程序核对引用后删除。此次产品只改变控制面投影和页面，未重复安装
未改动的 Windows/Android 制品，不将原生虚拟环境视为实体终验。

完整结果为 `deploy/evidence/2026-10-10-observation-freshness/observation-freshness-production-closure.json`。
本轮已记录各阶段时间及实际上传/公开下载量；同一公开入口内逐文件串行校验的成本另行核对，
不能为了速度省去原正文摘要验证。扩展指标排序、生产网站签回、指定 LAN 和旧发布 floor 前向
消费仍分别保持缺项，整个核心工作项不因此关闭。

### 首跳样本参与选路：已部署并回读

已核对三端真实入口及现网已部署源码：资源样本已采集、保存并报告，但未传入纯选择函数。
按[精确首跳对应](clients/client-runtime-model.md#首跳样本参与必要尝试)修订同一模型，保留
原采样范围和签名字节，仅接入匹配实际凭据、资源及网络代的原样本；不把入口认证当作服务健康，
不新增探测或授权。共享模型、执行器、移动桥接和必需源码检查通过。Linux 正式 CLI 在专用
namespace 内、Android 正式 APK 经独立 Hy2 VPN、Windows 当前源码经 Portable Mixed 正常界面，
分别完成真实首跳失败、无主动业务探测时自动换路、替代路径 HTTPS、原签名回读、同身份缓存
恢复及 control 重启；服务健康保持未知，没有制造业务样本。Linux 实测程序、Android APK 与
原生库均和发布包原始字节相符；双架构 MSI 核对包内字节，不把该检查写成全部新 MSI 原生安装
或 ARM64 执行。Windows 等待实际显示的路径及对应资源结果，避免把界面刷新延迟误判为切换失败。
测试夹具与模拟器系统界面造成的失败原件保留，最终通过证据不替换失败记录。

精确制品向全部发布根并行增量发布并完成公开 HTTPS 正文验证；各节点只预置必要新 agent，
未改的数据面本地复用。六节点正式服务已切换，组件期望经正常管理页面提交。Direct 对应国内
业务，指定境外出口与 Auto 对应国际业务；全部 control 的实际路径、模式及组件页面在切换后
和重启后分别回读，原 Auto 已恢复，生产服务与探测目标保持。
正常停止、异常退出后的精确清理、同身份恢复、管理与基础网络均通过；原身份、密钥、认证
字节、floor、latch、一个共享 WG、独立 Hy2 和显式 Mixed 保持。原云安全链的外部来源 SSH
拒绝规则变化逐次核对，管理及节点地址不在其中，其他有序规则语义保持；具体写入进程未证明。
被替代的精确程序核对后删除，VM、模拟器和临时浏览器已退出，宿主临时权限已恢复。

完整证据索引为
`deploy/evidence/2026-10-10-first-hop-selection/first-hop-selection-production-closure.json`。
后续观测时效见上节；扩展指标排序、生产网站签回、指定 LAN 和旧发布 floor 前向消费仍分别保持
缺项；实体机终验由用户完成，整个核心工作项不因此关闭。

### 缺失指标时的确定性选路：已部署并回读

相同单目标观测集合在候选排列变化时选出不同路径，已在共享纯模型复现。原比较器混用耗时、
当前选择和 ID，缺指标时形成比较环。按[稳定基准与可比较证据](clients/client-runtime-model.md#preference-与-selection)
先确定基准，再只接受严格更好的同目标有效耗时；不引入多目标性能排名、额外探测或新偏好。
领域、签名 wire、持久字段及现网认证字节不变。全部排列、缺项、平局、过期、换网和多目标边界
回归通过，Windows 原生执行同一回归；三端持续使用同一纯选择核心。

Linux 正式 CLI 在独立 namespace 完成真实 Mixed 业务、原签名报告、到期恢复及同身份重启。
正式 Android APK 经独立 WG VPN、Windows 当前源码经 Portable Mixed 界面完成真实业务、
多服务隔离、撤权、同身份重启、再授权和控制面回读。Android 首轮被模拟器的系统界面无响应
弹窗挡住文件选择器；现场窗口证据及失败原件保留，释放已完成的 Windows 测试资源后，重跑
正常入口通过。实际 Android APK 与原生库均和发布包摘要一致。双架构 MSI 验证包内原始字节，
不把该核对当作全部新 MSI 的安装验收；VM/模拟器不代替实体机。

精确制品沿正式入口向所有发布根并行增量发布，并通过全部公开 HTTPS 正文校验。六节点仅预置
必要新 agent，未改数据面本地复用；服务切换后经正式管理页面写入并回读组件期望及签名实际坐标。
Direct 对应国内业务，指定境外出口与 Auto 对应国际业务，全部 control 页面和重启后回读通过，
原 Auto 已恢复。正常停止及异常退出后的精确清理、同身份恢复、管理与基础网络均通过；认证
原件、floor、latch、一个共享 WG、独立 Hy2 和显式 Mixed 保持。原云安全链新增外部来源的
SSH 拒绝规则已逐项审查，管理及节点地址不在其中，其他规则保持；具体写入进程未证明。
被替代旧程序核对后删除，VM、模拟器及本轮临时桌面已退出，宿主临时权限恢复。

完整证据索引为 `deploy/evidence/2026-10-10-selection-order/selection-order-production-closure.json`。
本项只修复已证实的确定性错误；后续首跳样本参与选路的结果见上节。扩展指标排序、全局新鲜性、
生产网站签回、指定 LAN 和旧发布 floor 前向消费仍分别保持缺项，整个核心工作项不因此关闭。

### 同一服务多个目标的观测与选择：已部署并回读

按[同一服务的多个测试目标](clients/client-runtime-model.md#同一服务的多个测试目标)修正客户端
按候选覆盖目标样本的问题。国内与国际访问继续使用各自服务；同一服务保留一条路径，不增加
地域混合服务、旁路探测或监听端口。全部目标成功、全部失败及混合/缺失结果分别形成该测试集合的
available、unavailable、unknown；部分失败保留当前路径，全部有效失败才触发本服务一次必要回退。
Linux 与 Windows 复用同一执行器，Android 复用同一纯选择规则；报告直接保留实际 target，旧无目标
缓存不能反推目标。Windows 与 Android 沿原页面显示各目标结果及原观测时间。

共享模型、执行器、Linux 缓存恢复、Android 单元与 lint、Windows 原生执行均通过。Linux 正式
CLI 在独立 namespace 内验证了同一服务部分目标失败仍保留路径、全部失败只拒绝该服务、自然
到期恢复、同身份重启及控制面重启后的原签名报告。正式 Android APK 经真实 VPN 和 Windows
当前源码经 Portable Mixed 正常界面分别验证同一服务多个 HTTPS 目标、另一服务失败与恢复、
撤权、同身份重启、再授权及原始签名报告。Windows 验收补齐了等待实际显示内容的条件；原仅等
运行文件的截图可能落后于界面刷新，失败和修正后的证据分别保留。新双架构 MSI 完成包内字节核对，
不把该检查写成全部新安装包的原生安装验收，也不把同机虚拟环境当作实体机。

精确制品已向全部发布目录并行增量发布、通过公开 HTTPS 正文回读；各运行节点只接收必要的新
程序，未改的数据面在本地复用。公开 APK 的一次正文校验失败记录保留；发布工具随后修正固定
总下载期限，按持续读取与停滞判断等待，并输出逐件进度。只重建工作站发布工具，原客户端制品
保持；重试复用了已验签文件，仍重新核对各入口的完整正文和原签名。

正式服务切换后，各 control 的正常管理页面已回读精确组件期望与签名运行组件，重启后再次通过。
正式客户端的 Direct 只验证国内业务，指定境外出口与 Auto 验证对应国际业务，全部 control 读回
实际偏好和路径，原 Auto 设置已恢复。生产既有服务与目标未改写；多目标失败组合在前述受控真实
业务环境验收，不把生产单目标回读当作多目标覆盖。正常停止与异常退出、精确清理、同身份恢复、
新建管理连接及宿主基础网络均已回读；保持一个共享 WG、独立 Hy2 和显式 Mixed。
既有云安全链的外部来源拒绝规则变化另存差异审查，其余防火墙语义保持；未确认规则的具体写入进程。

被替代的精确程序经摘要、进程和 unit 引用核对后删除；原身份、密钥、认证字节、floor 和 latch
保全。VM 与模拟器已停止，原磁盘与设备身份保留，宿主临时权限恢复。完整证据索引为
`deploy/evidence/2026-10-10-multi-target/multi-target-production-closure.json`。
本项未激活网站证书、未经指定的生产 LAN 或旧发布 floor 的自动前向消费；性能指标排序也未
借多目标修正改变。整个服务授权工作项继续保持 open，实体机终验由用户完成。

### 多服务隔离与共享 WG 批次修正：已部署并回读

按[多服务的独立执行](clients/client-runtime-model.md#多-service-配置与唯一当前互联网-policy)补齐 Windows/Android 的
逐服务探测、失败拒绝与到期恢复；三端切换 selector 时仅关闭属于该服务的实际连接，移除全局连接重置。
Linux 与 Windows 原生数据面已验证切换另一服务时既有连接继续收发。Windows 当前源码的三种
交付形态经正常 GUI 验证不同服务结果、自动恢复、撤权、同身份重启、再授权及原始签名报告；
本轮双架构 MSI 另核对了包内字节与构建产物，不把该检查写成全部新 MSI 的原生安装运行。
Android 正式签名 APK 已从正常加入及 VPN 入口完成独立 WG HTTPS、不同服务的失败与恢复、
撤权、Keystore 同身份重启、再授权及私有签名报告，control 重启后保留原报告。
原报告循环先于异步业务探测结束的问题已修正；原生回读确认失败目标持续期间能收到该服务失败、
另一服务成功的原始签名报告。

部署前回读另发现既有共享 WG 数据面发生宿主批次合并越界，失败服务已通过原停止/启动入口恢复。
旧实现的多 peer 临时切片覆盖已由并发对照重现；调用内批次修正通过 race、真实多出口与管理 peer
验证，制品修订为 `1.11.4-loom.10`，schema 仍为 3。精确制品已向全部 YAML 发布目标并行增量
发布并完成 HTTPS 字节校验，各部署节点也已并行切换，仅发送缺少的程序。节点组件期望经正式
管理页面与 CLI 提交，全部 control 重启后均从实际管理浏览器读到期望值与签名运行组件相符。
原页面写入等待失败的记录保留，剩余提交沿正式 CLI 完成，不将它描述为全部页面写入通过。

正式客户端 CLI 的 Direct、指定境外出口与 Auto 分别完成匹配出口的真实 HTTPS，control 重启后
再次完成三种业务、签名报告及全部管理页面回读，原 Auto 偏好已恢复。国内直出只验证国内目标，
境外业务验证实际境外出口；国内接入后的境外中继路径不会被当作国内直出。各节点正常停止与
异常退出后的精确清理、同身份恢复、新建管理连接及宿主基础网络均已回读；保持一个共享 WG、
独立 Hy2 和显式 Mixed。云代理原有防火墙链的外部变化另存差异审查，不声称防火墙逐字节未变。
旧程序经摘要、进程及 unit 引用核对后删除；身份、原认证字节、密钥、floor 和 latch 保全。

本项部署与业务结果索引为
`deploy/evidence/2026-10-09-service-probes/service-probes-production-closure.json`。
此项没有实现同一 Service 的多目标归约、性能指标排序或旧运行发布 floor 的前向消费；
也不激活生产网站或未经指定的 LAN 共享，整个服务授权工作项继续保持 open。

### Android 报告等待与正常断开

另发现报告网络请求持有 VPN 启停锁。现在只在锁内读取实际运行输入及耐久预留报告序列，
释放运行锁后发送固定报告；profile 操作仍按原规则串行，没有新增队列、持久状态或协议。
当前正式签名 APK 已验证：真实报告请求等待时，正常断开完成，网络等待仍在继续；恢复 control
后可读到序列更高的签名停止报告。服务失败与恢复、撤权、同身份重启和再授权同时通过。
原测试夹具的 TLS 初始化、debug/release 方法名和文件选择问题分别保留失败证据；最终验证不冒充
旧 APK 的原生对照重现，也不声称另一个未复验的 profile 切换延迟已修复。

本修复只更新 Android 应用，Linux/Windows 已验精确字节继续复用。正式发布向全部 YAML 目标
并行分发缺少的不可变文件，真实 HTTPS 校验和全部 control 私有下载页面的来源、摘要回读均通过；
原节点组件期望引用保留。发布后的汇总脚本最初少算了随发布代变化的 bootstrap 清单及签名，
其计数断言失败记录保留；独立文件集合差异核对已确认正式发布成功，没有重复上传。
原生及发布证据位于 `deploy/evidence/2026-10-09-android-report-lock/`，结果索引为
`android-report-release-closure.json`。
Windows VM 与 Android 模拟器已停止，保留原磁盘和设备身份，宿主临时权限恢复；实体机终验由用户完成。

### 旧发布 floor：当前只读核对结果

各节点原 floor 的完整字节摘要与本轮生产读回相同，发布验签公钥延续；当前签名 catalog、包内程序、
真实运行摘要与正式组件期望也已建立精确对应。较早核对记录中名为 `verified_matches` 的候选实际
标记为 generation、载荷及快照均不匹配，不能按字段名当作已找到原件；其中一个可变路径后来还已
切换到新版目录。本轮重新验证保留的旧签名指针，仍未取得与原 floor 完全对应的 signed-current 原件。

只读对应记录位于 `deploy/evidence/2026-10-09-floor-forward-proof/node-coordinate-map.json`。
它不是迁移授权，也未证明单调接受与崩溃恢复顺序。生产文件没有改写，旧 floor 没有重置；
已授权的精确程序切换不因此变成旧发布 floor 的前向消费，安装器自动接管继续保持未完成。

## 传输实现纠偏

用户明确禁止把 Hy2 套进 WG，也禁止为了复用权限执行让 WG 依赖 Hy2。先前允许依赖
同节点 Hy2 的答复不再作为依据。以下较早的阶段记录只说明当时执行过什么；涉及嵌套传输
或内核 WG 安装器的结果不能证明当前方案正确，当前状态以本节为准。

### 当前模型与源码

普通客户端可独立使用 Hy2 或 WG 首跳；Hy2 在入口终止，后续显式 Link 逐段使用原生 WG
传输业务。接收端依据同一 Service/Policy、完整候选、实际发送节点和精确来源执行授权，
保留目标名称与指定出口，不靠客户端自报、TLS SNI 或放宽 ACL 获得权限。

当前写入、DeviceView 与运行投影只有这一套语义。旧嵌套渲染、Hy2 Link 探测、
AccessHY2ResourceID 执行耦合及内核 WG 安装器已删除。已签历史材料仅在用户确认的
[限定历史验证](core/current-contract.md#前向替换的认证材料冲突)内保留原义；普通启动、
配置同步不调用旧 LKG reader，也没有旧运行 fallback。schema 仍为 3。

共享实例替换使用的固定数据面 `1.11.4-loom.8` 包含原生 WG 共享收发、目标与来源映射，以及
实际发现的 EOF、写半关闭和代理响应关闭修正。Linux/Windows 的 AMD64、ARM64 与 Android
制品均由固定来源构建和验签；交叉构建不抵扣实体架构执行。

### 共享 WG 收发修正：正式部署与业务回读

现场原有每节点三个 Loom 管理接口，接收实例之外还存在独立发送实例。当前已按
[共享收发模型](core/current-contract.md#分段传输的替代执行模型)完成源码和生产前向替换：
每节点一个固定键、UDP 监听和 peer 集合；通过各接收资源唯一目标池表达同一目标的多个
下一跳，不给不同 peer 重复默认网段。WG 和 Hy2 独立；UI 的服务、候选与出口含义不变。

正式控制入口已提交资源和 Link 整合事实，节点显式接受新签名 View。原身份、固定节点键、
RuntimeKey、报告序列、latch、high_water 和原签名材料保留；旧接收名称缓存停用后保存
精确原件，新执行只消费当前资源地址池。当前各部署节点回读只有一个 WG endpoint 和一个
精确管理接口，旧 generation 的多个接口已由正式停止入口清理。部署按节点并行，仅传送
缺少的精确程序及必要私有输入，没有分发源码或整个工作区。

正式发布 catalog、Linux 包、Windows 三种交付形态与安装包、Android APK 已完成签名验证，
配置中的全部发布目标已通过 HTTPS 原件回读。节点组件期望值已由正式管理页面提交；全部
control 的实际部署页面已回读到期望组件与签名运行报告一致，控制服务重启后再次通过。

新版的已验范围如下：

- Linux 正式投影与 adapter 在隔离 network/mount namespace 中完成两客户端、同入口、
  同域名及两族 IP、同时选择两个出口的 TCP/UDP；覆盖全部进程重启、接收端单独重启、
  撤权及另一客户端恢复新连接。接收端重启需要重新握手和业务重试，不承诺无中断。
- 标准内核 WG peer 可访问获准执行 DNS，冒用另一客户端来源的 TCP/UDP 被拒绝。
  精确管理地址通过独立 namespace 验证真实返回；多个管理 peer 共用一个接口，业务地址
  不进入宿主，正常停止清理成立。只有 loopback 的测试环境会暂停 WG 网络定时器，修正
  隔离 underlay 后重新完成验证；失败记录保留，不以重试覆盖。
- 当前 Android 签名 APK 经正常加入及 VPN 入口完成独立 WG HTTPS、撤权、Keystore
  同身份进程重启、再授权与私有签名报告；control 重启后可回读原报告。
- 当前 Windows Installed 安装包、Portable TUN 和 Portable Mixed 分别经正常 GUI 完成独立 WG HTTPS、
  撤权、同身份重启后保持拒绝、再授权、DPAPI 保全、签名报告与停止后的路由恢复。
  安装形态另回读 SCM 实际运行组件。上述同机验证不抵扣用户负责的实体机终验。

生产运行回读已确认原身份与精确程序、规则、非 Loom 路由、解析设置和基础连接；一个节点
原有云安全防火墙链发生动态变化，该差异单独保留，不写成整个防火墙逐字节不变。
切换初期部分跨节点 WG 握手失败，原抓包显示接收端发出响应而发送端未收到，事实与报告
同步因此受阻。单端更换端口及另一组双端试验仍有失败；随后在操作者既有可用入口范围内，
使用同一新监听端口完成全部有向 Link 的多轮真实 WG 认证 DNS，再经正式 `resource.put`
仅调整资源端口。原资源身份、固定密钥、地址和 Link 保持，未改 NAT、云网络或防火墙。
旧端口丢包的具体上游原因仍未证实，不以普通 UDP 通包或后续成功反推原因。

私有路径中断期间，control 导出的当前签名 View 通过既有 SSH 管理通道交付，设备使用
[显式正常同步入口](clients/client-runtime-model.md#私有通道中断时的显式配置交付)接受；
它仍验证当前规范、设备绑定和认证前沿，不调用历史 reader。恢复后全部 control 的资源、
Link 与原签名事实一致，设备恢复正常私有同步与签名报告，无待补依赖或无效事实。

正式客户端 CLI 保存 Direct、指定境外出口与 Auto 后，显式 Mixed 分别完成境内目标、
匹配境外出口的国际目标及自动选择的真实 HTTPS；全部 control 的正常认证浏览器读到相同
偏好与实际路径。节点正常停止和主进程强制退出均完成精确接口、路由及子进程清理；异常
退出保持 failed/inactive，不自动反复启动。停止期间及同身份恢复后，新建 SSH、系统 DNS、
默认公网，以及开发宿主 LAN 和原有 WG HTTP proxy 均通过。恢复继续使用唯一共享实例、
新持久端口与原缓存。各 control 逐个重启后，重复三种业务、事实与组件报告及页面回读均通过。

本节的共享实例替换已完成软件与获准部署验收；被替代的精确程序目录经摘要、进程和 unit
引用核对后删除，原身份、认证材料、floor 与受保护切换证据保留。Windows VM 与 Android
模拟器已停止并保留原磁盘和设备身份，宿主临时权限恢复。完整服务授权工作项仍因后文独立
缺项保持 open；实体机终验由用户完成。最新结果索引为
`deploy/evidence/2026-10-09-shared-wg/shared-wg-production-closure.json`；真实坐标和原件不进入本文。

### 共享局域网：当前开发与隔离验收

当前源码在同一 schema 3 的 Service 内表达固定网关、原始 IPv4 网段和等长虚拟前缀，
Policy 与设备选择继续提供授权。分配预览不保存独立状态；正式提交重新核对签名网段报告、
依赖与占用，过时预览拒绝。物理直连 LAN 与只用于冲突检测的其他隧道前缀分别报告，
后者不能直接成为可共享网段。冲突重分配有界，耗尽后持久禁用，只能由管理员显式恢复。

网关数据面通过受授权 direct dialer 保留主机位转换目标地址，使用网关自身连接取得返回流量；
不要求 LAN 目标添加 overlay 回程路由，也不向宿主或路由器写入 DNAT/SNAT。新数据面制品
坐标为 `1.11.4-loom.9`，不重写已发布 `.8` 的来源或摘要，不改变协议编号。

已完成真实 Chrome 的 LAN 创建、确认提交、策略、重启回读与禁用；正式 CLI 的独立
network/mount namespace 验证了实际网段报告、映射和授权写入、两个客户端经独立 WG
访问另一 namespace 中的 HTTPS LAN 主机、签名报告、控制面及客户端重启、单客户端撤权、
同身份再授权和服务删除。目标只有原 LAN 路由，实际来源为网关 LAN 地址。
原生分段测试另覆盖 WG/Hy2 独立首跳、WG 中继、虚拟 IP 与精确名称、冲突时拒绝及解除后的
正常选路恢复。恢复测试曾漏选路而停留默认拒绝，现按真实客户端流程执行；失败证据保留。

正式隔离 CLI 还完成了真实 UDP 的虚拟 IP 与名称访问、源地址及回复目标核对，覆盖控制面与
客户端重启、单客户端撤权、同身份恢复、再授权及删除后的路由、DNS 和 ACL 清理。

Windows 的本轮签名 Portable TUN 从正常 GUI 加入，实际访问只有本地返回路由的 LAN 目标；
网关源地址、签名报告、撤权、DPAPI 同身份进程重启、再授权及正常停止后的路由恢复均通过。
三种形态与双架构制品已构建并签署发布记录；本轮 LAN 原生范围不扩大为所有形态均已实测。
同机 VM 已正常关闭，原磁盘、身份及宿主目录权限保留。

Android 正式签名 APK 在同机隔离模拟器从正常导入、加入和 VPN 入口完成独立 WG LAN HTTPS、
撤权、Keystore 同身份进程重启后保持拒绝、再授权、原始签名报告及 control 重启回读。
现场发现 Android 的 Go 接口枚举不能提供所需网段，因此由 Java 平台只读枚举作为显式输入；
未知仍停止该 LAN 的捕获。网段值与其他报告字段在同一次签名前组装，修改网段会使验签失败。
原接口读回失败、签后追加字段被拒收及最终通过的证据分别保留。模拟器已正常退出并保留设备身份。

新版程序已在各部署节点并行切换，维持一个共享 WG 实例、原身份、固定密钥、缓存和认证高水位。
正常停止、强制退出后的精确清理、同身份恢复及宿主基础连接均已回读；保持显式 Mixed，不新增
宿主 NAT、默认路由或防火墙。原云安全链的精确来源拒绝规则发生变化；新增拒绝来源与该代理的封禁日志对应，其他
有序规则语义保持；没有完整内核写入者审计，不称整个防火墙原样未变。
正式目录已向全部 YAML 目标并行发布，实际公开下载字节验证通过。三种互联网偏好的真实业务与
全部 control 页面已通过；其中一次远端 Auto 报告传播明显延迟，原测量保留，不描述为及时稳定。
组件期望已通过正式页面提交；全部 control 重启后，三种业务、原事实、实际组件匹配和 LAN
表单中的签名物理网段均再次回读通过。该轮传播仍有等待，不承诺全网即时更新。被替代的精确
程序目录经摘要、进程及 unit 引用核对后删除，身份与认证证据保留。

这些结果不代表生产 LAN 已开通。生产首次共享仍缺操作者指定的网关、真实 LAN 网段及业务目标，
不会从接口报告自行授予共享权限。实体机终验由用户完成。受保护证据位于
`deploy/evidence/2026-10-09-local-network/`，结果索引为 `lan-capability-production-closure.json`。
生产指定 LAN 业务与完整服务授权工作项保持 open。

### 已验证的正式入口与隔离运行

- Linux 正式控制投影、adapter 与数据面在独立 network/mount namespace 中完成两种首跳、
  原生 WG 中继、域名及两族 IP 的 TCP/UDP、不同候选、交叉授权拒绝、来源冒用拒绝、撤权
  与恢复；原管理公钥和精确地址的返回路径成立。业务 peer 不能进入宿主管理端口。
- 同机 Windows GUI 的 Portable Mixed、Portable TUN 完成独立 WG HTTPS、撤权、同身份
  重启后保持拒绝、再授权、私有签名报告及清理。用户和机器 DPAPI 的显式前向迁移逐字节
  保全原密文。当前 Installed 签名包另完成正式加入、SCM 运行、独立 WG 业务与同身份恢复。
- 当前 Android 签名 APK 从正常文件导入、加入及系统 VPN 同意入口完成独立 WG HTTPS、
  撤权、Keystore 同身份重启、再授权和私有签名原报告；control 重启保留原报告。
- 接收器单独重启后，发送器保持原进程，原持久名称缓存及撤权边界恢复；业务在 WG 会话
  重建后恢复，存在重建等待，不能描述为无中断。初次短窗口失败与最终恢复证据均保留。

Windows VM 使用同一来宾状态，验证后已停止并恢复宿主原目录权限；Android 模拟器已退出。
这些结果不抵扣 ARM64 实机、真实睡眠、物理切网、显示硬件及其他由用户负责的实体终验。

### 生产前向替换与当前限制

六个节点已通过显式一次性迁移接受新 LKG，原身份、密钥、latch、报告序列和认证高水位
保留，原 LKG 字节进入受保护证据。正式控制入口提交了普通 WG 接入资源与原生 Link 的
前向事实；没有登录路由器、改写 NAT、换钥或降低 floor。

服务已切换为原生接收器与用户态业务会话。宿主只保留已认证管理 Link 对应的精确接口和
返回路由，没有 auto_route、默认路由、策略 rule 或新防火墙授权。Linux 使用显式 Mixed。
部署按节点并行，只发送该节点缺少的精确程序和必要材料；未分发源码或整个工作区。
公开签名发布同样并行，只传缺少的不可变文件，并从真实下载入口校验文件字节。

操作者开放一处公网入口的 UDP 入站后，其他节点发往其全部现用 WG、Hy2 监听的带标记
测试包均已收到。随后从正式 CLI 完成 Direct、指定该境外出口和 Auto 的真实 HTTPS：
Direct 仅访问适合本地访问的授权目标；指定出口与 Auto 实际使用独立 WG 首跳和原生 WG
中继访问国际目标，私有管理浏览器读到相同偏好与选择。此前独立 Hy2 首跳的成功证据仍保留。
这些结果只证明实际执行的候选，不替其他入口、出口或控制同步补绿。

现场验证还发现并修正：旧内核拒绝在线改名、接口初始化与改名竞态、正常取消与接口回读
竞态、重复 X25519 数学验证占用报告时间，以及 Auto 反复选择刚过期失败候选造成的饥饿。
修正复用既有状态、监听回读和排序规则；公钥计算缓存不能绕过签名、权限、规范值或 floor。
原生传输源码相关及全量检查通过。已部署的 Linux 修正版已在全部节点完成正常停止、强制退出、精确
所有权清理与同身份恢复；强制退出后保持 failed/inactive，没有自动重施。停止期间及恢复后
的新建 SSH、DNS、默认公网，以及开发宿主 LAN、既有 WG 代理均已回读。身份、原签名字节、
认证高水位、既有路由和解析配置保留；各节点恢复后均取得多轮不同序列的签名报告确认。
首次报告复验失败的原始记录保留，后续通过窗口不覆盖它。

另一处固定管理 WG 链路曾重复出现接收端发出响应、对端未收到的情况。核对原密钥、peer、
地址绑定和既有映射后，先用带标记的独立 UDP 验证映射内空闲端口，再通过正式 resource.put
只调整该资源端口。正常配置刷新恢复管理连接，全部 control 的事实前沿、目标投影和组件
期望相同，待补依赖及无效事实为空。相关客户端和 control 已重启并恢复同一身份、新端口和
原事实；全部节点的宿主网络回读通过。原签名材料与失败抓包继续保留，不以修改 NAT 解决。

最新签名目录已向所有 YAML 发布目标并行发布并逐文件验证；各 control 的真实 mTLS
浏览器均读到同一目录及原 manifest 引用。正式页面提交全部节点的 agent 与数据面期望引用，
全部 control 的实际部署页面均显示全部节点的期望组件与签名运行报告一致。接收新期望事实后，
另一次 control 重启恢复原事实和持久服务参数，浏览器与 Auto 的真实业务再次通过。
两轮已替代的程序发布目录按精确清单删除，未删除身份、事实、认证 floor 或受保护证据。

报告传播与页面读取的后续修正已正式发布并完成上述业务回读。此前成员交换的大量历史排队，
已按[报告差量](core/current-contract.md#control-成员之间的报告差量)改为最新原件优先、范围间交替取数和较小批次；
真实成员 TLS 的中断、重启补齐及原件保全回归通过。现场还通过请求耗时、函数采样和 cgroup
核对，修正未变原件的重复投影、数据库锁竞争的无等待循环，并按宿主余量调整服务自身内存限额。
原件校验及超时边界保持。最后一轮 Direct、指定境外出口和 Auto 的真实 HTTPS、三台 control
的实际路由页面均通过；六节点在控制重启后继续取得多轮不同序列的报告确认，客户端进程未变化。
原页面不可用、传播超时及调整前后的测量均保留，不能用最终通过覆盖失败过程。

当前限制及独立缺项继续保留，完整服务授权工作项保持 open：

- control 冷启动后的历史原件读取与重建仍有明显等待；稳定运行后的页面回读不能抵扣冷启动延迟，
  当前有限验证也不能证明任意历史规模下的性能。
- 一处宿主的防火墙与较早基线不完全相同，差异位于原有云代理管理的规则链。最新部署窗口中，
  新增的精确来源封禁规则已与云代理日志对应，其余有序规则语义及 Loom 路由、规则和解析配置保持。
  未修改共享防火墙；最新窗口的归因不能补齐更早的日志空缺，不能声称所有历史外部变化均已归因。
- 生产 `control.loom` 的离线网站证书输入与激活、共享局域网、多目标观测算法及旧运行发布 floor
  的前向消费仍为独立未完成结果，见[当前交付对账](delivery-audit.md)。实体机终验由用户完成。

原始失败、抓包摘要、身份与网络快照、签名制品、实际进程及浏览器证据统一保存在被忽略的
`deploy/evidence/2026-10-08-transport-correction/`。受保护目录中的逐项结果决定是否通过，
文档不保存真实节点、坐标、密钥、指纹或运行指标。本轮传输替换汇总为该目录下的
`native-production69-closure.json`；它只汇总其明确列出的业务范围，不关闭整个服务授权工作项。

## 当前工作项：普通设备服务授权与撤权

状态：进行中，未通过完整业务验收，不能关闭。用户已授权按同一业务闭环连续推进实现。

- 必须结果：正式管理入口创建 Service 与固定所属 Policy，设备选择 Policy 并完成私有加入；认证 View
  原子持久化后由客户端及服务节点实际消费，运行、业务和管理页面分别回读；修改、deny、策略替换与撤权
  在应用失败和重启后均不恢复旧权限。
- 保留边界：现网身份、密钥、认证原始字节、floor、latch、既有管理员访问，以及三端有效交互和视觉资产。
  本项不新增协议号、第二权威、长期兼容路径、DNS provider 或 ACME。用户已于 2026-10-04 授权逐节点部署、
  检查运行、修复缺口并再次部署验证；现网保全、宿主网络与生产前向切换的门禁继续适用。
- 当前结果：同一 schema 3 的普通事实、唯一 Authority、正式 CLI/daemon 和 Web 授权入口已替换旧链；
  Service → Policy → 设备 PolicyIDs → 私有加入 → 认证 View/LKG → Linux 实际 Direct、本机出口及一跳 Hy2/Mixed 业务 →
  撤权后的拒绝配置 → 重启/执行失败 → 签名报告和管理 API 回读已在临时隔离环境实证。
  Android API 35 x86_64 临时模拟器也已从正常文件导入和系统 VPN 同意入口，完成 Hy2 HTTPS、撤权热替换、
  Keystore 重启恢复、重新授权及界面/私有签名报告回读。
  前述临时环境结果之外，现已完成生产 Web 的策略移除/恢复、普通设备撤权/同身份重新授予、
  服务端原凭据拒绝、三 control 重启及真实业务恢复；范围见[设备恢复验收](#普通设备撤权后的重新授权)。
  Linux 显式应用的隔离 TUN 已完成正式 CLI、签名包及同机来宾生命周期验收，见下文。
  这些结果不抵扣其余传输、动态成员或全部平台终验。
- 仍须连续推进：生产 `control.loom` 的离线签回与激活、多目标归并与选路缺口、
  LAN 及旧发布 floor 的前向消费。`.loom` DNS 和客户端网站接线、Linux WG 中继、
  精确制品激活和旧运行入口退出已分别验证，见下文。
  动态成员多数链、原始证据持久化、三端证明消费和获准部署已完成软件验收，见下文；
  Hy2、LAN、发布和全部平台能力不是简单 Direct 链的共同前置。
- 生产状态：获准的 Linux client、control、私有 relay 和透明 endpoint edge 已使用本轮同一精确制品。
  本机 access 使用显式 Mixed；初始 netns TUN 拒绝门禁保留。历史只读检查不是当前部署状态，
  切换、端口修复、恢复和删旧证据保存在被忽略的 `deploy/evidence/2026-10-04-service-switch/`。

完成时仍须逐项给出正式入口、认证处理、持久/重启、实际消费、用户回读、获准部署和删旧证据；
缺一项即保留本工作项未完成，不把内部检查点拆成可分别关闭的工作项。

### 已授权的正式服务替换

前期只读检查与候选自检保存在 `deploy/evidence/2026-10-04-node-rollout/`；用户随后明确要求解决客户端、
正式切换、真实业务验证，并确认 `.env` 指向 YAML。此次执行及原始回读均在受保护的
`deploy/evidence/2026-10-04-service-switch/`，节点别名、映射、摘要、原始材料和运行指标不进入本文。

- 正式 `loom config check -env .env` 已严格读取既存 YAML，原输入保持；六键 reader 和相应迁移入口删除。
  `.env` 只保留文件定位和可选 provider secret，不能改写控制权威。
- 旧设备签名密钥、control 签名密钥、管理员证书、数据面证书与 WG 密钥逐项核对保留；旧认证原字节、
  floor 和 latch 保全。经本次明确替换授权建立现行信任材料，沿正式 Invite/claim 完成原设备身份绑定及
  Service/Policy/资源/Link 映射。新旧签名域与序列不以数字相等替代证明，旧发布 floor 原文件摘要保持。
- 同一精确制品已接管正式 client、control、relay 和 endpoint edge。所有获准节点经正式公网设备认证
  入口取得 View，运行时实际消费并提交签名报告；临时加入入口经 draining/retired 退出，临时 SSH 通道移除。
  原管理员证书通过 mTLS 正式 CLI 写入、成员同步、重启持久回读和原值恢复；真实 Chrome 已打开回环管理页。
- 客户端 WG 所有权和异常清理已修复；真实隔离环境完成 WG TCP/UDP 与 Hy2→WG→Hy2→HTTPS。
  生产端口问题通过同轮双端抓包及普通 UDP 对照定位：旧端口回复缺失，操作者确认云端无出站 UDP 限制；
  从既有 YAML 映射区间选取经对端验证的空闲端口，通过管理员 `resource.put` 修正后恢复握手和私有传输。
  未登录或修改云网络、NAT、路由器或防火墙，也未把推测写成丢包原因。
- 生产 Mixed 已实际访问授权 HTTPS，固定出口与 Auto 分别回读。一个首跳失败后，同出口中继被自动选择，
  后续业务成功；经修复节点的中继业务也成功。历史脚本还执行了未经业务需求确定的出口/目标组合；
  这些失败保留为可达性诊断，不能列为功能缺口或上线阻碍。允许选择某出口不表示要求该出口访问所有目标成功。
- 故障节点及开发宿主完成正常停止、SIGKILL、精确 WG/子进程清理和重新启动。本机每阶段新建 SSH、
  LAN DNS、默认公网 HTTPS、经既有 WireGuard 的 HTTP proxy 均通过；非本 generation 的 route/rule、
  resolver、密钥和发布 floor 不变。当前 unit 使用 `Restart=no`，不以反复重启掩盖清理失败。
- 已替代的 helper、候选及旧 control/WG timer 启动项从 systemd 退出；旧安装目录中的可执行文件删除，
  正常 `loom` 命令指向当前制品。旧 authority、report 输入和必要签名原件移到受保护证据，不能再作运行输入。
  旧公网制品 handler 和静态分发树已退出实际入口；Nginx 配置检查、reload 与读回通过，既有网站/TLS 保留。

本轮未完成 `control.loom`：现有网站叶证书缺该 DNS SAN，认证 DNS overlay 也尚未接线。
回环浏览器成功不能抵扣它，也不改写用户已确认的笔记本访问历史。旧 HTTP 分发 URL 未伪装成 HTTPS；
原值留证据，新发布 catalog/floor 消费仍未实现。本次直接激活不声称该发布链或 Android/Windows 实体机完成。

### 认证解析器与具名客户端入口

本次补齐设备解析器配置、Linux 私有域名入口及 Android 具名 Endpoint/Hy2 的实际消费；
证据位于受保护的 `deploy/evidence/2026-10-04-client-dns/`，不改变上述完整工作项的未完成判定。

- 解析器复用 Invite 和设备授权中的可选 `dns_servers`，沿正式邀请/设备管理表单或 `loom control write`
  写入同一普通事实，投影到既有 `DeviceView.dns_servers`。首次加入直接取得配置；改名和改权保留未编辑的值。
  未配置的已签发字段继续省略，原始字节不变，没有新协议号、全局默认 store 或系统 resolver 运行回退。
- 私有设备连接只向认证的字面解析器查询；域名答案只作临时拨号地址，原 TLS 名称、SPKI 和证书身份保持。
  Linux 与 Android 的 Hy2 运行投影接入同一 DNS 配置；Android 的 Go 私有连接及 DNS socket 也在 VPN capture
  前调用平台 protect，关闭后撤销回调。纯渲染没有网络查询，未配置解析器的具名入口明确失败。
- 所有获准 Linux 节点先经原管理员 mTLS 配置各自原有解析器，再确认旧客户端已保存签名 View，随后切换
  client、control、relay 和 edge 的同一精确制品。新客户端经具名入口完成正式 sync 和签名报告；
  控制节点同步一致，普通 DNS 事实经 control 重启后回读，正式 Chrome 也回读设备表单中的同一值。
- 固定出口及 Auto 使用真实 HTTPS 验证。单个出口首次失败的原始记录保留，单独复测经同出口中继成功；
  此前将境内最终出口访问国际目标的失败列为未完成项，缺少业务需求依据，该判定撤回。
  正向验收先确定 Service、预期最终出口及业务链；境内节点作为入口/中继时，检查它到所选境外出口的转发。
  不可达请求只有在明确验证失败识别、报告或选路时才属于反例验收，不能要求把不适用的链路测到成功。
  客户端正常停止、owned WG 清理和重启后 Auto 业务通过；
  各阶段新建 SSH、LAN DNS、系统 DNS、默认公网及既有代理正常，路由/规则的配置值保持。
  RA 路由租约的自然倒计时单独剔除后比较，原始快照保留。设备身份、RuntimeKey、旧 floor、证书/密钥及
  已有 Material 原字节逐项核对保持，运行制品与最终源码的重建摘要一致。
- 独立 user/network/mount namespace 中的 Android API 35 x86_64 原生验证使用具名私有入口和具名 Hy2
  资源，完成正常文件导入、VPN 同意、真实业务、撤权拒绝、Keystore 重启恢复、重新授权、签名报告与界面回读。
  DNS 查询与接收端记录、截图、精确 APK 摘要保留；临时模拟器及 fixture 已退出，宿主未安装 DNS/路由规则。
- Go 全仓 build/test/vet、mobile test/vet、真实 Chrome 邀请与改权、双 ABI Android AAR、JVM/lint/APK 检查通过。
  Windows amd64/arm64 源码编译通过，未用它抵扣新版原生执行、交互桌面或实体机验收。

`.loom` 权威记录与 `control.loom` 网站证书/浏览器入口、Windows 新制品原生验证、
实体机及正式签名交付仍未完成；本段的认证解析器结果不替代这些能力。

### 内核 WireGuard 具名资源

沿现有资源与设备配置入口补齐认证解析器到内核端点的执行映射，证据保存在受保护的
`deploy/evidence/2026-10-04-wg-dns/`。本节只证明该项能力，不改变完整工作项的未完成判定。

- 具名 WG 发起端只使用当前 View 的认证解析器，内核收到精确 IP:port；回读严格核对该地址、端口和
  认证 peer key。删除原先“域名可以匹配任意 IP”的回读逻辑；纯投影、签名资源与持久 LKG 不保存 DNS 答案。
- 同次解析复用相同名称，保留仍有效的本代地址；刷新确需换地址时精确清理并重建，相关旧业务观测失效。
  临时解析失败不制造健康结果，也不借宿主 resolver；首次执行缺少认证解析器明确失败。
- 独立网络与挂载 namespace 内实际完成具名 Hy2→WG→Hy2→HTTPS，DNS 答案变更后读回新内核端点并恢复
  HTTPS。初始握手及连接恢复的失败尝试保留；接口启动和单独握手均未算作业务通过。
- 全部获准 Linux 节点激活同一制品；既有具名 WG 资源被实际消费，所有发起端的内核地址逐项与所有权记录
  相等。切换先由旧进程清理自身 generation，再启动新制品；已替代程序退出并删除。
- 明确选定境外最终出口访问对应国际 Service，以及 Auto 的真实 HTTPS 均通过，原 Auto 偏好恢复。
  本机正常停止、精确 WG 清理、同制品重启和认证报告通过；停止与恢复期间新建 SSH、LAN DNS、系统 DNS、
  默认公网和既有 WG 代理均通过。现网身份、RuntimeKey、密钥/证书、旧 floor 和认证原字节保持，宿主
  route/rule 配置值与基线一致。

### Windows 认证 DNS、Hy2 与撤权恢复

首次 bootstrap 原先验证 Invite 后仍调用系统 DNS，Windows 实际导入具名入口时失败；现已先验证 Invite，
再经其中签名的解析器拨号。未配置解析器及篡改 DNS 拒绝，失败和继续加入保留同一身份与 request ID。
加入后的私有通道使用当前 View 的 DNS，两条路径共用平台 underlay dialer；没有新增 wire 字段或重写认证材料。

原生运行还揭示 Windows 的旧 Direct 校验器不能消费 Hy2，且 DNS 已被共用适配器提前添加，重复进入 capture
派生。现在共用源只添加本机 API，Windows 按三种既定形态添加一次 DNS/capture，保留完整 Hy2 CA、名称、
凭据和 detour；不安全 TLS、未知字段、循环 detour 及扩宽 capture 仍拒绝。

同机 Windows 11 x64 的真实交互桌面已完成文件导入、同事务继续加入、CurrentUser DPAPI、具名 Hy2 HTTPS、
撤权应用、正常断开、进程重启后仍拒绝、同身份重新授权后业务恢复、正常停止；各阶段私有签名报告、GUI
及运行时回读相符，Mixed 前后路由不变。未配置业务探测池时 UI 保持 unknown；实际 HTTPS 由独立业务请求验证。
证据在 `deploy/evidence/2026-10-04-windows-current/hy2-summary.json` 与 `hy2-initial/`、`hy2-final/`。
原桌面 DPAPI 与 GUI 定向回归也已通过；固定出口文字的检查修正为识别现有绿色字形，没有修改产品样式或视觉基准。

共用 Go 定向 race 及全仓 build/test/vet、安全和格式检查通过；Android 双 ABI 核心、JVM、lint 与调试制品
构建通过。Windows 三形态 TUN/升级卸载仍须继续；不能把此处 Portable Mixed 的开发业务链当作三形态交付或
实体机终验。Android release 输入检查已覆盖共享 Go 与 staged 修改，
防止制品标注 HEAD 却包含未提交的共用修复。

源码 `58305b2b` 已提交推送，并按既有明确授权在全部部署节点激活同一精确制品。原身份、认证材料、
floor 与 latch 保留，宿主 route/rule 不变；新建 SSH、LAN DNS、系统 DNS、默认公网及原 WG HTTP proxy 回读通过，
指定既定境外出口和 Auto 的国际 HTTPS 业务通过。逐节点旧程序和临时上传已删除，受保护证据位于
`deploy/evidence/2026-10-04-bootstrap-windows/deployment-summary.json`；不是新的签名 catalog 激活。

同一提交的 Android 正式 APK 已使用既有发布签名生成并验签，两个 ABI 的 native library 与 AAR 逐字节一致。
API 35 x86_64 干净模拟器实际安装正式 APK，从 DocumentsUI 导入、私有加入和系统 VPN 同意入口完成具名 Hy2
HTTPS、撤权、Keystore 进程重启恢复、再授权、界面/私有报告回读及正常断开。制品、首次安装和保留身份重试的
独立记录分别位于上述证据目录的 `android-release-artifact.json`、`android-release-clean-install/` 与
`android-release-native/`。首次尝试的首个业务请求失败，没有充分诊断确定原因；原身份重试与独立干净安装均通过。
验收测试保留每次失败原因，并在限定时间内独立等待真实业务结果，不把 runtime ready 当作业务已成功。
ARM64、物理切网、睡眠及其他实体机终验仍由用户执行。

更新后的 Windows 六份 ZIP 与双架构 MSI 已生成；x64 MSI 经正常安装后 SCM 以 LocalSystem 运行，安装的程序
回读提交与摘要相符，VM 原有六份 DPAPI 文件逐字节保留。当前桌面回归中 deviceclient 14 项、client/broker 14 项、
DPAPI 3 项和 GUI 54 项通过。安装本身不抵扣实际 TUN、重启/升级/卸载业务验收；这些验证继续进行。

### TUN 域名传递与缓存恢复

实际 Installed MSI 已经通过正常加入、Machine DPAPI、TUN 启动和签名运行报告；随后 HTTPS 暴露域名
Service 被发送为 Hy2 IP 目标的问题。接收端按原 ACL 正确拒绝，没有放宽接收端、替换服务目标或改动宿主网络。
当次失败后 service 已停止且 TUN 清理，原身份保留用于修正后的重试；下述正式制品重新验证已通过。

共用 capture 现按 Service 域名 matcher 派生仅适用于 TUN A/AAAA 查询的地址映射，保持签名 View 和原 ACL；
原始 IP 不因 SNI 变成域名。独立 user/network namespace 中，真实 TUN DNS、IPv4/IPv6 域名还原、Hy2 TLS、
HTTPS、无 SNI 连接、字面 IP 和伪造 SNI 拒绝均通过；同名 underlay 查询仍到真实解析器，正常重启保留映射。
实测原数据面在立即强制退出后重用了旧地址，新增窄源码补丁已通过三次异常恢复及损坏缓存拒绝测试。
源码准备固定上游 module 校验和、commit 与补丁摘要；数据面制品修订不改变 schema 3。

记录位于 `deploy/evidence/2026-10-04-tun-domain/`。修正版 Linux/Windows 双架构数据面和 Android 双 ABI AAR
已构建。Android 正式签名 APK 已在干净 API 35 模拟器经正常文件导入和 VPN 同意完成仅域名 Service 的
Hy2 HTTPS、撤权拒绝、Keystore 进程重启恢复、再授权、私有签名报告及界面回读；接收端确认收到域名目标。
该包源码为 `a1392929`，双 ABI 库与审核的 AAR 逐项一致，实体机仍由用户验收。

Windows 原版组件 writer 已替换为[规范 schema 3 manifest](core/current-contract.md#windows-数据面-manifest-的规范字段)：
固定源码、补丁和精确双架构制品，附许可证与可独立复现的构建方法；发布代同值重试、同代异值和倒退拒绝。
旧 schema 1 解码与 previous 运行回退删除，现有旧指针和签名包必须显式保全后替换，不自动重解释。
独立空目录重建的四份数据面与审核摘要一致；同机 Windows 原生签名包安装、Wintun Authenticode、逐文件
回读及数据面预检通过。原生正式交付结果见下一节；尚未替换现网数据面或启用生产 catalog。

### Windows 三种正式制品的原生业务与恢复

源码 `9274181a` 的六份 ZIP 与双架构 MSI 已构建，保存在 `dist/windows-9274181a/`；下面的实际执行
均限于同机 Windows 11 x64 VM。数据面使用经 Ed25519 验签的源码修正版，Wintun 的 Authenticode 验证通过；
应用 EXE/MSI 仍遵循既有未签名预览策略，不冒充已取得外部代码签名。

- Installed：正常 MSI 升级保留七份 Machine DPAPI、profile catalog 和现行组件代指针；原身份实际完成
  域名 TUN → Hy2 → HTTPS。关闭 GUI 后服务仍承载业务；TUN 运行中正常卸载清理程序、SCM、虚拟网卡和路由，
  保留配置身份与恢复意图，重新安装后无需新邀请即可恢复业务，并从私有控制入口读回新的签名报告。
- Portable TUN：正式 ZIP 经正常 GUI 加入，保存操作者输入的配置名及 CurrentUser DPAPI，实际完成域名
  HTTPS。强制退出后 Job/TUN 清理，再次运行同一制品恢复原身份、连接意图和名称映射；撤权后拒绝业务，
  再次异常重启仍拒绝，再授权后业务恢复。各步均回读真实 UI 与新的私有签名报告。
- Portable Mixed：正式 ZIP 复用同一用户的既有配置，从显式回环代理完成域名 Hy2 HTTPS；撤权、进程异常
  重启及再授权均通过，未创建 TUN，正常断开后路由与基线一致。

Portable TUN 的正常断开及两次强制退出后，系统 DNS 已实际返回真实地址，新的默认 HTTPS 连接成功，
没有用额外清 DNS 或路由补丁完成恢复。Installed 的整机重启已在登录桌面前自动恢复原身份、TUN、
真实 HTTPS 与新的私有签名报告；随后桌面回读、正常断开和默认 HTTPS 也通过。重启使 Windows 网卡索引
重新编号，原始路由逐字节比较因此失败；按唯一且未变的直连子网核对一一对应后，全部路由、下一跳及
metric 相同。原始差异、对应关系和实际读回分别保存，没有更改来宾路由来取得通过结果。

旧 schema 1 组件指针和原签名包已先逐字节保全、验证，再按精确所有权替换；该处理没有改变身份、认证
floor 或 latch，也没有新增旧格式运行解码。现行组件指针保留此前已接受的制品版本坐标，使后续前向升级
能继续比较原发布代；不能用当前编译版本覆盖或抹掉该 floor。

受保护证据位于 `deploy/evidence/2026-10-04-tun-domain/` 的 `final-upgrade/`、`installed-lifecycle/`、
`installed-msi-lifecycle/`、`portable-tun/`、`portable-mixed/`、`portable-dns-recovery/` 和 `installed-reboot/`，
包括正常入口、精确制品、运行回读与清理结果。
较早的脚本失败单独保留，不计为通过。此处不抵扣 ARM64、物理切网、睡眠或显示硬件终验，也不表示生产
签名 catalog 已实现。

### Linux 正式安装、失败升级与整机恢复

正式 `install.sh` 现在交给同一 Loom CLI 验签和安装，不再保留另一份 shell manifest/floor decoder。
激活显式要求 Mixed，stdin 邀请、自定义 state、可选资源输入和当前 runtime 使用同一组本机路径。
签名包中的 systemd 模板只作投影输入；安装时核对实际 FragmentPath、drop-in、程序字节、所有者和文件类型。
旧部署及其发布 floor 仍须经前向切换，不作为空安装重建信任。

同机 Linux amd64 VM 从正常入口完成以下实际验证，证据在
`deploy/evidence/2026-10-04-linux-package/native-install/`；来宾有独立管理网卡与数据网卡，使用 QEMU
用户网络，没有向开发宿主添加 TUN、路由或防火墙规则：

- 带外公钥验证的包从 stdin 加入；正式 systemd 消费同一身份/LKG，实际域名 Mixed → Hy2 → HTTPS 成功，
  私有控制入口收到新签名报告。相同邀请重跑复用原 Device；带空格、百分号和美元符号的 state 路径从真实进程 argv 回读一致。
- SIGKILL 后 service 停止，手动重启恢复业务；撤权后业务拒绝，异常重启仍拒绝，再授权后恢复，逐阶段回读签名报告。
- 合法签名新包在代理端口被测试进程占用时通过 preflight、接受发布代，但实际运行失败；service 保持 disabled/inactive，
  接受的 current、设备公钥、加入 request ID、认证 floor 与 latch 保持。旧签名包降级拒绝，释放端口后同包重试恢复业务。
- 首次升级故障测试发现重试成功后遗留旧程序，原失败证据保留；修正版从已有签名清单识别同平台较低代，
  精确删除旧 Loom/sing-box，保留 manifest、签名及源码证据，没有增加 receipt 或第二发布 store。
- 未知 systemd drop-in 使安装拒绝，原 current、PID 和实际业务保持。单独隔离缓存测试证明 `--no-enroll`
  不改变已有 current/身份，也不启动 service；缓存程序篡改后拒绝复用。
- 最终制品整机重启后 systemd 自动恢复同一身份和接受代，新的私有报告与实际 HTTPS 成功；正常停止后代理释放。
  各阶段新建 SSH、系统 DNS 和默认 HTTPS 成功，路由/规则只剔除 RA 租约自然倒计时后相同，原始快照保留。

最终双架构签名包由干净提交 `576977b6` 生成，发布代为 5，位于 `dist/linux-576977b6/`；前序代及失败尝试
单独留证，未用更新后的结果覆盖原失败。arm64 完成真实 ELF/源码坐标与签名包验证，原生实体机由用户测试。
全仓 build/test/vet、格式、安全检查通过。VM 与临时接收端已正常停止，磁盘、身份及接受记录保留。
Web 发起的 SSH/sh 自动下载交付、隔离 TUN 生命周期和生产 signed-current 前向消费仍须继续。

### 签名目录与私有 Web 精确下载

本地 `loom release stage` 已从唯一部署 YAML 读取发布签发能力，验证 Linux 双架构 archive 和 Windows
双架构数据面 ZIP 的原规范包，再签署 schema 3 catalog。原 manifest、签名及包字节保持，整包摘要与包内
程序摘要分开；Windows 数据面没有冒充完整客户端。旧 schema 1 catalog reader 和未接入正式 CLI 的
publisher observation 拼接层删除，未恢复旧发布或安装 fallback。

本地审查目录实际完成独立进程回读、同值重试、比较旧指针后前进、并发锁、陈旧计划、降代、同代异值、
文件损坏及历史指针丢失拒绝。拒绝后原 current 保持；已缓存解析仍重新核验真实字节，删除缓存可重建同一结果。
私有测试 control 经正式 init/serve 读取该目录，真实 Chrome 使用管理员 mTLS 打开 Linux/Windows 两页，
实际点击下载的文件与目录摘要相符；下载后 Linux/Windows 正式 CLI 验签通过。无管理员证书请求被拒绝，
新 current 不改变旧页面绑定的精确下载，损坏 catalog 撤下卡片并拒绝下载，恢复原字节后才恢复。
daemon 重启后同一管理员与下载目录回读一致，权威原字节保持；全仓 build/test/vet、格式、安全检查及
真实双架构 Linux 包的独立签名元数据核验通过。

证据保存在 `deploy/evidence/2026-10-05-release-catalog/`。测试只绑定回环私有监听，浏览器信任和策略位于
独立挂载 namespace；没有改变宿主信任、DNS 或路由。较早测试辅助程序等待页面过早、CLI 参数错误和测试
成员证书名不符的失败分别留证，未作为通过结果。原生产服务、发布 floor、身份及公钥保持。

该结果接通本地签名目录和私有下载，不表示公网分发、YAML 全目标发布、节点期望组件、生产 catalog/floor
消费或 Web SSH/sh 安装已完成；后续通用 bootstrap 结果见下一节，Android APK 与 Windows 应用签名交付仍须继续。

### Web 一次粘贴脚本与 Linux 实际安装

通用公开脚本现在是同一 catalog 中的 Artifact，独立签名 manifest 引用原 Linux 包；它只识别架构、下载
并核对 archive，再调用既有唯一 installer。私有 sh 邀请页先验签并从认证 distribution_urls 实际读回脚本，
再显示完整命令和终端历史提示。复制不重签，Invite 只经 quoted heredoc/stdin 交给安装器，不进入公开脚本、
URL、argv 或环境；已完成事务不再返回命令。脚本和不同代 manifest 的缓存分别按两个摘要定位，避免相同
脚本内容导致不同签名代被混淆。

独立 Linux 来宾经控制台核对 SSH 主机密钥；浏览器使用真实管理员 mTLS 打开邀请页，点击 Copy command
取得与页面逐字相同的完整块。真实 HTTPS 返回错误字节时，该块拒绝执行，未创建身份或 unit；恢复原字节后
同一块完成正式签名安装、systemd Mixed、具名 Hy2 HTTPS 和私有签名报告。相同命令重试保留私钥、公钥和
原邀请；整机重启后自动恢复同一身份、服务、真实业务和新签名报告，正常停止释放代理。
安装和重启后的 route/rule 与来宾基线一致，仅剔除 RA 租约的自然倒计时。实际常驻 control 的已热缓存也已
验证同脚本字节、不同签名代的独立回读；全仓 build/test/vet、格式和安全检查通过。

证据在 `deploy/evidence/2026-10-05-release-catalog/shell/`，截图中的邀请内容模糊处理，原命令只留受保护文件。
公开测试服务器仅提供签名白名单制品，管理员/设备请求仍走原私有服务。来宾只安装独立测试分发 CA；宿主
hosts 与浏览器信任改动均限于独立挂载 namespace，没有修改宿主 DNS、route/rule、防火墙或真实服务。
测试辅助程序早期 SSH banner 解析和资源输入多余字段的失败留证，修正后才计入结果。

该独立环境的 sh 安装不抵扣生产交付；后续生产静态 HTTPS 分发与实际来宾验证见下一节。
YAML 全目标 executor、SSH 前置识别/执行与现网发布 floor 的前向消费仍未完成。

### 正式签名分发与生产邀请交付

本轮已沿严格 YAML 的全部发布目标分发 schema 3 目录。新 `release import` 只接受显式 catalog 摘要，
重新验证原包、manifest、签名和逐文件内容；目标 current 在排他锁内比较旧值后推进，重试不能降代或覆盖异值。
发布私钥始终留在工作站，独立公钥经已有管理通道固定；不可变文件实际写入后，公开 HTTPS 回读与私有下载
分别核验。此处 current 只选择下载目录，原运行发布 floor 保持原字节，不授权自动应用。

- 获准分发目标已接受同一新目录。公网 Nginx 只开放签名公开制品的精确内容地址，既有网站和 TLS 保留；
  私有控制面使用配置的目录与独立公钥，真实管理员浏览器下载 Linux 包和 Windows 数据面 ZIP 后逐字节相符。
  Windows 数据面包仍不是完整 Windows 应用，页面不把它显示成应用安装器。
- 新 Linux 制品包含审核后的数据面及完整复现材料；全部获准节点已先激活源码 `d047bb4b` 的程序与数据面，
  control 随后使用 `3c129381` 修复真实邀请签发的入口预检超时。同一 TLS 协议不再重复握手，独立 Web 协议
  仍单独验证；没有放宽证书、名称、SPKI 或业务认证。
- 真实生产浏览器已从 Add Device 提交 sh 邀请并复制完整安装块。首次来宾执行在下载时发生连接重置，
  尚未创建身份或安装程序；另一处已认证分发地址能正常返回同一脚本。源码 `ae991e61` 因此使脚本与 archive
  分别尝试当前已验证地址，逐次检查同一固定摘要，仍只调用一次原 installer。新脚本已先于控制面升级分发。
  原失败记录保留，已过期的原邀请通过正式操作取消，未删除签名事实或重置客户端身份。
- 控制节点已运行 `ae991e61`，签名报告、原身份/认证字节/旧 floor、宿主路由规则、固定境外出口和 Auto
  的真实 HTTPS 均已回读，旧程序删除。生产来宾经新命令完成安装和私有加入；首次选用的策略只允许中继入口，
  对普通新客户端没有候选，这是验收准备漏查入口条件，不能靠放宽原策略解决。正式设备页面已改为现有的
  指定境外出口/国际 Service 策略，原身份与 Invite 保留；后续普通境内首跳修正见下文。
- 后续现场暴露 Linux 将单项业务不可用误作整个运行配置失败的问题。修正只增加本机 selector 的拒绝位置，
  保持认证字节和候选不变；真实隔离 sing-box 已验证失败时拒绝、进程保持、观测过期后 HTTPS 恢复与正常清理。
  源码 `e5b0f576` 已推送，生产来宾经正式签名 installer 升级并保留原身份与接受代，旧程序由 installer 删除。
  当次 control 与部分服务节点激活后，其余切换因报告确认等待超时未继续；未回退现有程序或认证状态。
  下载目录已前向推进，新公开制品在全部分发目标验签并完成实际 HTTPS 字节回读，运行发布 floor 未改写。
- 来宾的单跳境外业务仍失败：限定抓包证明请求从客户端物理接口发出，但所选境外 listener 没收到匹配请求。
  服务端其他回环/WG 流量不能充作返回证据。进一步核对发现，两处境内入口已有操作者提供的 UDP 映射与
  正在运行的 listener，宿主和原来宾都能核验其 QUIC/TLS 身份，但资源的 `link_only` 阻止普通客户端选用。
  已沿正式 `resource.put` 纠正这两个标记；原设备 Policy 本来允许这些入口到同一固定境外出口，
  不改变原身份、Policy、Service 目标、出口、端口、证书或宿主网络配置。普通客户端的真实中继业务已回读。
- 报告确认超时另有已测量的实现开销：现网持续持久接收报告，配置认证通道可达，但每次写入重复解码和重排
  全部历史。受保护副本验证可通过精确字节核对的内存解码缓存与规范位置插入减少开销，回写仍与原历史逐字节
  一致。跨 writer 的序列高水位、两种分叉到达顺序、文件变更/缺失拒绝与重启回读有定向测试。
- 源码 `b518d682` 已提交推送并激活至全部获准节点的 client、control、relay 和 edge；确认超时节点已恢复成功
  报告，原签名历史全部保留。原身份、RuntimeKey、密钥/证书、认证材料、旧运行 floor 及宿主 route/rule
  回读相符，新建 SSH、LAN、DNS、默认 HTTPS 与原 WireGuard 代理正常；两轮被替代的旧程序均按精确摘要删除。
- 生产来宾继续通过正式签名 installer 前向升级，实际程序与包内签名坐标一致。原设备已使用境内公网 Hy2 首跳、
  既有 WG 中继及原境外最终出口完成国际 HTTPS，真实选择与私有签名报告一致；固定出口与 Auto 的宿主业务也通过。
  来宾整机重启后同身份、同制品、业务与新报告恢复，认证前沿不回退，来宾路由规则和基础联网保持。
  原 Invite 保持 completed，管理页不再提供已消费的邀请或命令。
- 正式撤权后，测试设备的配置通道和新业务请求被拒绝，其他合法设备的同一业务保持。辅助脚本最初误把客户端
  进程立即退出当作撤权必需条件，该失败与修正均留证；现行模型允许保留未收到新认证状态的离线 LKG，
  不把本机进程存续解释为仍获服务端授权。正式删除测试设备后已停止来宾，身份原件保留。


- 后续多 control 回读发现一个节点停在旧事实前沿。原材料逐字节属于其他节点的完整前缀，没有分叉；
  只读认证探测确认首个中继超时、后一个中继可达，而顺序拨号使整轮请求先耗尽预算。现已改为在同一取消/
  超时内并行尝试本机已配置路径，逐条验证目标成员并关闭未选中连接。真实 TLS 差量、卡住的中继、
  取消清理和错误目标拒绝有定向回归，原实现可复现测试失败。`da0ba2fe` 已推送并在全部获准节点激活，
  落后节点通过正常差量同步补齐；各 control 再次重启后的事实前沿、设备授权与资源逐项相同，没有手工复制
  事实或重置认证状态。原身份、字节、floor 与宿主网络保持，固定境外出口和 Auto 的真实业务通过，旧程序已删除。
- Web 邀请在服务端接受、浏览器未收到响应时，旧表单重算到期时间，导致同 request ID 携带不同内容而无法重试。
  现已在可丢弃的表单草稿内固定完整规范请求；未改草稿重试保持原字节，编辑后的新请求保留对象与已审阅依赖。
  真实 Chrome 已复现旧失败并通过重试、唯一事实、私有加入、报告与重启回读；陈旧草稿及编辑后请求 ID 有回归。
  `9a3ef854` 已提交推送并激活；生产浏览器在丢失已接受响应后成功进入同一邀请，但二维码容量检查暴露了下一项缺口，
  因而该次浏览器综合验收保留失败，不用导航成功抵扣交付可用。
- 生产邀请的完整成员证明超过中等纠错容量，旧二维码入口返回错误而页面没有解释。现改为中等纠错优先、
  必要时使用标准低纠错；两者都不删减原邀请字节。所有单码等级都不足时明确显示原因并保留复制与文件下载。
  图片按实际尺寸显示并提供原尺寸入口。正常/低纠错/超容量的正式 API 与 Chrome 回归通过，Android 同款
  ZXing 解码器已从修复后的真实生产二维码原图恢复完全相同的交付字节。`0e1fbc51` 已在全部获准节点激活，
  生产管理员浏览器的原请求重试、同一签名事实、邀请回读与正式取消均通过，原图实际下载后独立解码通过。
  但截取页面显示图后解码失败：双栏卡片将完整码缩成非整数像素模块。因此该显示验收仍保留失败，未以原图
  成功抵扣。当前继续修正整行布局与整数模块缩放，窄屏给出原尺寸、复制和文件入口；浏览器截图独立解码加入回归。
  各 control 的事实前沿、设备授权与资源已一致；精确制品、原身份/字节/floor、宿主网络和固定境外出口/Auto
  业务回读通过，被替代旧程序已删除。布局修正 `d06184ab` 也已推送并激活至全部获准节点，浏览器请求重试及
  正式取消通过；新样本原始 PNG 暴露了独立于缩放的定位器问题。保留原文换到稍大的 QR 标准尺寸后，Go 与
  Android 解码器均恢复原始邀请；现把确定性的候选图像独立解码校验加入生成路径，并用合成反例与实际失败
  样本回归。修正 `440f6419` 已提交推送并激活至全部获准节点；真实生产管理员浏览器完成原请求重试，
  原始 PNG 和页面实际显示截图均由 Android 同款解码器恢复完整、逐字节相同的邀请，随后正式取消测试邀请。
  各 control 的事实一致，精确运行程序、原身份/认证字节/floor、宿主网络、固定境外出口及 Auto 业务均已回读，
  被替代程序删除。全部分发目标已接受同一前进目录，公开 HTTPS 精确字节与真实浏览器的 Linux/Windows
  下载分别回读，下载后的独立正式 CLI 验签通过。中间候选没有成为运行或下载选择，失败样本及签名原件保留。
  这些检查证明软件生成与实际浏览器显示的可解码性，不抵扣操作者的实体摄像头扫码终验。

逐节点切换、制品、公网/私有回读与失败原件在受保护的
`deploy/evidence/2026-10-05-release-distribution/`。下载目录发布与制品替换没有修改宿主 DNS、默认 route/rule
或 firewall；既有 WG 资源只沿本 generation 的精确所有权停止与恢复。目标 SSH 坐标与 YAML 有一处差异，
实际仍按 `.ssh_config` 连接，并与当前认证节点身份核对；原差异保存在受保护证据，没有倒写配置。

YAML 全目标正式 executor、期望组件事实与实际报告比较、现网发布 floor 的前向消费
仍未完成，不能以这次受保护执行和单目标 import 关闭完整工作项。后续 SSH 闭环见下一节。生产 sh 安装、同身份升级、业务、重启、
撤权与测试清理已完成上述范围的回读；对应精确结果在 `report-performance/` 子目录，原失败证据保留。

### SSH 目标检查与原事务执行

正式入口已接上 SSH 目标选择、签发前只读检查、原邀请的后台执行及结果回读。目标只来自显式选择的
`.env` → YAML → SSHConfig；新的可选 `ssh_target` 只属于原 Invite，历史缺席字段的签名字节保持。
未知平台、未验证安装、其他身份及已绑定身份丢失均拒绝安装；临时验签程序可读取尚无正式 CLI 的部分
安装身份。网页关闭不取消 daemon 执行；daemon 重启或连接中断后的结果为 unknown，继续时再次核对原
网络、Invite、request ID、公钥、平台与有效授权。不另建安装状态库，执行成功不代替加入和业务结果。

规范签名往返、原请求重试不重签、绑定/撤权拒绝、SSH 参数与秘密隔离有定向回归；真实 Chrome 验证
目标/职责改变使检查失效，已有身份回到原设备管理。独立 Linux 来宾用临时测试签名包执行正式 `install
-inspect`，身份、信任、服务、锁文件和 route/rule 配置均未改写；仅排除实际 RA 租约倒计时后比较，
原始失败与回读保留。全仓 build/test/vet、真实 Chrome、格式及仓库安全检查通过。

`83129c84` 已提交推送并激活，真实管理员浏览器签发原邀请；独立来宾在已有持久身份、尚无正式 CLI
与 current 的部分安装状态下，继续同一邀请完成安装。关闭浏览器没有取消后台执行，原加入变为 completed。
首次业务验证发现失败观测仍有效时持续拒绝该 Service，而同一授权境外路径的新 HTTPS 请求已成功；
原失败保留。`ca9f4f20` 将 Linux 新失败观测缩短为模型规定的 30 秒，成功观测及已保存的原截止时间不变；
隔离实际 selector 的拒绝与到期后 HTTPS 恢复通过。同时修正安装器成功、最终回读失败时应显示 unknown，
并保留最后一次成功检查，而不是改报安装失败或抹掉身份回读。

上述修正已再次提交推送并激活至全部获准节点，原身份、密钥、认证材料、floor/latch 与宿主路由/规则保全；
固定境外出口和 Auto 的真实 HTTPS、新建管理连接、LAN/DNS、默认公网及既有代理通过，原 Auto 偏好恢复。
各 control 的事实前沿、设备与资源一致，被替代可执行程序按精确摘要删除。全部 YAML 分发目标接受同一
前进 catalog，公网整包与签名逐项回读；实际浏览器下载 Linux 包和 Windows 数据面包后，独立正式 CLI 验签通过。

控制 daemon 重启后，原加入仍 completed，临时执行结果回到 unknown。浏览器继续原邀请，沿正式签名
安装入口升级来宾；原密钥、Invite、claim request ID 和身份保持，新精确进程、业务、签名报告与页面结果
分别回读。来宾整机重启后自动启动同一制品，认证高水位不退，业务和新报告恢复，管理/DNS/默认公网及
route/rule 配置保持。较低代可执行程序已移除；真实浏览器再次检查已有身份时拒绝重复添加，并返回原设备管理。

最后沿正式 CLI 撤权并删除测试设备。首次撤权业务检查仍成功，失败原件保留；随后逐个
入口与境外出口回读已认证前沿、凭据移除和实际运行 View，再确认新 HTTPS 与私有配置/报告通道拒绝。
其他授权设备业务正常，来宾持久身份未删，测试 VM 已停止。正式 control 已回到仓库 `.env` 所指的原 YAML，
目标集合与原配置相同；既有目标的真实 SSH 身份检查通过，未验证旧安装保持拒绝覆盖。service 只读挂载
确需的原 SSH 文件，其他 home 内容仍隐藏，私钥不进入浏览器，没有倒写 `.env` 或 YAML。

此节完成 Linux SSH 交付、原事务恢复、同身份升级及上述生产业务链；不抵扣隔离 TUN、生产发布 floor 的
自动消费或实体机终验。证据位于受保护的 `deploy/evidence/2026-10-05-release-distribution/ssh/` 和
`deploy/evidence/2026-10-05-release-distribution/ssh-recovery/`。

### 未绑定邀请自动终结与历史页面

原控制服务只按截止时间拒绝连接，未生成终结事实，因此未绑定的过期邀请仍占用设备 ID。
现在签发 control 在启动及运行期间沿同一 Authority writer lock 重新检查原事务，签发既有
`invite.expire` 普通事实；与首次 claim 串行，已绑定、已完成、冲突或其他签发者的事务不被自动改写。
签发失败保留原状态并重试，页面读取不制造终结事实，也没有新增过期 store 或协议版本。

生产正式 CLI 签发的未绑定邀请已实际到期，旧程序仍显示 open 的回读保留；更新后原签发 control
自动终结，同一未绑定设备 ID 成功用于新邀请，新邀请也由运行中的服务自动终结。两次原始邀请不变，
原终结签名字节经全部 control 同步和再次重启后保持一致，没有重复生成事实。该测试没有生成设备身份。

实际浏览器随后发现：设备 ID 被复用后，旧邀请页面只按当前设备投影查找，导致历史事务显示不存在。
现已按原 transaction 从认证 API 回读，沿既有可删除缓存显示终结状态；不交付旧邀请，也不误跳新事务。
真实 Chrome 开发回归及生产 mTLS 页面回读均通过。失败页面和未选中候选的证据保留，没有把失败候选
推进为生产下载 current。

最终修正的精确制品已激活全部获准节点；身份、RuntimeKey、密钥/证书、旧 floor、认证原件和宿主
route/rule 保持。固定境外出口与 Auto 的实际 HTTPS、新建 SSH、LAN DNS、系统 DNS、默认公网及既有
WG 代理均通过，控制前沿及节点投影一致，已替代和中间候选可执行文件逐节点删除。全部 YAML 分发目标
条件推进同一签名 catalog，公开 HTTPS 正文字节与私有真实浏览器 Linux/Windows 下载独立验签通过。
证据位于 `deploy/evidence/2026-10-05-release-distribution/invite-expiry/` 与 `invite-expiry-final/`。
绑定后的新增 control 仍依赖未实现的多数成员链；此次自动终结不释放已绑定身份，也不抵扣该结果。

### 全部 YAML 目标的正式签名分发

此前跨目标上传、公开回读及指针推进依赖受保护临时脚本。现已接入正式 `loom release publish`：
严格读取原 `.env` 与 YAML，经私有管理员入口核对当前节点授权，逐节点回读真实身份；所有目标原指针
检查完成后才上传原始签名包，全部不可变文件及公开 HTTPS 正文字节验证通过后才条件推进 current。
目标端保留独立验签与原指针比较，最终再次回读全部目标；没有新增常驻发布器、任务 store 或自动安装。

真实签名制品测试覆盖身份不符不上传、公开字节失败不推进、并发旧值拒绝、部分推进后同目录重试、
授权中途变化停止、降代拒绝及传输原字节保全。生产命令已实际完成全部 YAML 目标，真实 mTLS Chrome
下载 Linux 和 Windows 包后独立验签通过。公网仅以内容摘要映射已经核验为公开的不可变文件；原网站、
TLS 与私有路径边界实际回读保持，旧 SSOT 发布写入器及其重复目标、历史和指针写入路径已删除。
受保护旧签名字节仍可离线取证，不恢复为新发布或安装的运行权威。

同一精确程序已激活全部获准节点，身份、RuntimeKey、认证原件、证书、旧 floor 和宿主 route/rule 保持；
固定境外出口、Auto、新建管理连接、DNS 与既有 WG 代理通过，全部 control 前沿和授权一致。
已替代版本及未启用中间候选的可执行程序逐节点删除。证据位于
`deploy/evidence/2026-10-05-release-distribution/formal-publish/` 与 `formal-publish-final/`。
下载目录的推进仍不等于期望组件事实、旧运行 floor 的前向消费或应用制品的自动安装。

### 签名分发只传缺失文件

原正式发布器每次发送完整签名目录，未改动的平台制品也被重复上传。修正沿原管理通道核对目标实际
文件类型、路径、长度和摘要，只传本次目录中缺失的文件；已有异值拒绝，复用集合不持久化。目标临时
组合原文件与收到的缺项，仍经原完整接收器、包验签及条件指针比较，不增加接收协议或第二份发布权威。
CLI 明确回读发送和复用的数量，开始操作不再输出容易误读为失败的 verified=false。

真实签名目录与实际 shell/tar 验证覆盖空目标、部分补传、全复用、复用期间内容变化、异常路径及
额外尾随字节；原身份、HTTPS、条件推进、部分成功后重试和中途授权变化门禁保留。整包规范校验集成
曾触发默认时限，原失败日志保留；在足够的显式测试时限内完整通过，没有减少验签步骤。
源码修正 `82f7a78a` 已推送；精确工作站 CLI 对同一现网目录完成全部 YAML 目标的正式发布回读，所有
目标均复用原文件且未发送制品正文，公开 HTTPS 完整字节和最终目录验证通过。原配置和目录保持，
既有业务服务的精确程序继续运行，本项没有重建或切换不受影响的客户端。受保护证据位于
`deploy/evidence/2026-10-05-incremental-release/`。该结果减少上传，不省略公开下载验证，也不消费旧运行 floor。

### Linux 实际运行组件与版本页面

旧 Linux 报告只遍历期望列表，未设置期望时连已经运行的程序也不回读，页面还使用旧组件字段。
现已从当前 agent 和数据面子进程的实际镜像测量版本、平台及摘要；磁盘文件替换不改变旧进程报告，
测量缺项不抹去其他组件。数据面退出后的错误报告只保留实际 agent，没有新增组件状态 store。
节点详情和 Device versions 使用现行签名报告展示完整坐标及时间，无期望时明确显示未设置，
不从下载 current 推断已应用；该页面的旧 publisher 总进度和快照对照已删除。

最小回归覆盖真实进程文件替换、无期望回读、缺项、异平台比较，以及浏览器中的签名报告持久化与页面。
生产全部节点的运行镜像与当前 View 签名报告逐项匹配，真实 mTLS Chrome 已回读版本和摘要。
同制品业务、身份、密钥、认证原件、旧 floor、控制同步和宿主网络回读通过；正式 publish 分发、浏览器
精确下载及独立验签通过，已替代可执行程序删除。证据位于
`deploy/evidence/2026-10-05-release-distribution/component-readback/`。
本段只确认实际运行坐标；期望普通事实的生产消费与其他平台组件回读仍须分别验收。

### 期望组件事实与实际运行对照

节点详情的正式表单已写入期望组件普通事实，引用当前已验签 catalog 与 manifest 的精确坐标。
六个节点的 agent、sing-box 分别从认证 View 消费期望；实际进程测量保持独立，由签名报告给出比较结果。
真实 mTLS 浏览器已逐项回读。所有控制成员持久化同一批原始事实，控制与运行服务重启后再次回读一致。

本轮精确制品经正式全目标 publish 分发，私有浏览器下载与独立验签通过；重启后的指定境外出口和 Auto
HTTPS 业务通过。身份、密钥、旧 floor、已有认证原件及宿主 route/rule 保持，被替代的旧可执行程序已删除。
证据位于 `deploy/evidence/2026-10-05-release-distribution/expected-components-final/`。
该结果覆盖 Linux 的期望与实际比较；Windows 的 DLL 实际加载与组件回读仍在修复和原生验证中，
Android 组件回读、应用制品 manifest 和旧运行发布 floor 的前向消费仍未完成。

### Windows 实际加载组件与数据面修订

Windows 组件报告已从实际进程镜像和加载模块取得坐标，不按期望列表筛选。原数据面实际使用内嵌
Wintun，独立 DLL 虽在包中却没有加载；现已改为只加载同目录已验签、由运行代只读句柄固定的 DLL。
缺失或错误文件不能回到内嵌副本。启动前的 TUN 检查与当前审核制品使用同一坐标，删除旧制品号的重复定义。

源码输入和四种架构数据面已在独立目录逐字节复现。原已签 schema 3 包及 catalog 仍按其精确原件验证，
不同修订的程序和源码不能拼接，新 writer 只写当前审核制品；没有新增协议或运行 fallback。
同机 Windows VM 的 Installed、Portable TUN、Portable Mixed 均完成真实 HTTPS、实际程序/模块摘要、
签名报告、无期望回读、普通期望事实消费及重启。Mixed 未加载 Wintun 时不报告它；Installed 另完成
运行中卸载、组件句柄释放、原 DPAPI/profile 身份保留、重装后的业务与签名回读。三种形态停止后路由保持，
原生 DNS 和默认公网 HTTPS 恢复，VM 正常 inactive，宿主临时目录访问权限精确恢复。

全部获准 Linux 服务使用同一精确制品；正式全目标 publish、全部公开内容、mTLS 浏览器下载及独立验签通过。
节点详情表单提交期望，全部控制成员原始事实一致，重启后的实际进程、签名报告、指定境外出口与 Auto
业务再次通过。身份、密钥、认证原件及旧运行 floor 保留；本机异常退出的精确清理、停止期间基础连接、
同身份恢复均读回，被替代和未激活的中间程序删除。证据分别在
`deploy/evidence/2026-10-05-windows-components/external-wintun/` 与
`deploy/evidence/2026-10-05-windows-components/runtime-coordinate/`；失败的启动检查和验收脚本记录保留，
不充作通过证据。Android 组件回读、应用制品 manifest 与旧运行发布 floor 的前向消费继续推进，实体终验由用户完成。

### Android 实际加载组件与停止报告

Android 正式报告已删除固定空 components：当前应用主 APK 对应 agent，当前 ABI 实际执行的
libbox.so 对应 sing-box。共享核心用正在执行的代码地址核对 APK inode、映射偏移与 ELF 执行段，
从同一打开文件计算两个摘要，并在测量前后核对文件及映射；不读取期望组件，不把其他路径或 ABI 当实际运行。
版本分别来自应用编入的源码提交和实际 Libbox.version。错误只遗漏无法测量的项目，原 schema 3 签名报告不变。

实际停止验收另外发现正常断开取消周期任务后没有补发报告。现由已有应用作用域在资源清理后重新读取
真实 stopped/error，避免随 VPN service 一起取消；不等待网络成功才允许断开，不制造新的报告 store 或重试状态机。
当前模块仍已加载时继续回读其实际坐标，runtime.state 单独表示 VPN 已停止。

源码 `2bc02ab0` 的正式签名 APK 0.5.2 / versionCode 9 已构建，两个 ABI 的原生库均与 AAR 一致。
API 35 x86_64 隔离模拟器先以旧正式包正常导入、私有加入、真实 Hy2 HTTPS 和撤权，再原地升级；
同一 Keystore 身份及撤权 LKG 恢复，再授权后的 HTTPS 与签名报告通过。停止报告修正沿同一设备和控制数据继续
升级复验，连接、再次撤权、两次正常停止、进程重启、再授权及实际业务均通过；未清空身份或重新加入。
安装后独立拉取的 APK 与交付文件相同，报告中的 APK/当前 ABI 原生库摘要与独立提取结果逐项相同，
没有设置期望组件。控制 daemon 重启后从原始签名材料和报告字节恢复相同 UI 投影，停止报告及组件坐标保持一致。

根模块与 mobile 的构建/测试/vet、格式和仓库安全检查通过；Android JVM、lint、正式 APK 签名与发布原生测试通过。
证据位于 `deploy/evidence/2026-10-05-android-components/`，包括首次停止报告缺口的原始记录。
测试模拟器已正常退出，宿主 route/rule/link 回读未改变配置；路由到期计时单独排除比较。
实体 ARM64、真实设备 Keystore、切网等由用户终验；这组证据不单独证明应用发布，发布链见下一节。

### Android 应用发布与期望组件

[Android 应用 manifest](core/current-contract.md#android-应用-manifest-的规范字段) 已接入原 schema 3
catalog、严格 `.env` → YAML 签发入口、共享读取器、期望组件事实及 Releases 页面。
正式签名 APK 旁保存原 manifest 和 Ed25519 签名；APK、编入的源码/AAR 坐标、原始受审核来源记录与两种
ABI 的实际 ELF 逐项绑定。工作站使用固定 SDK 检查 APK 签名和包身份，节点读取器独立验签与核对原包。
期望仍引用 catalog/manifest；实际报告独立测量已执行的 APK 和原生库，不从期望复制摘要。

源码 `ed69c949` 的 APK 0.5.3 / versionCode 10 已通过正式构建、SDK 验签、原始 AAR/原生库核对及
规范清单集成验证。应用清单第 1 代已随 catalog 第 31 代通过正式 publish 分发至全部 YAML 目标；
各目标原身份、原目录比较、全部公开 HTTPS 正文、条件推进和最终目录均已读回，部署输入未改写。
三台 control 分别重新验证并投影 Android 清单。私有 mTLS Chrome 页面已实际下载 APK、原 manifest 和签名，
共享读取器使用独立公钥再次验签，下载字节与原生安装文件完全相同。

同一个隔离 API 35 x86_64 模拟器保留原 AVD、Keystore 和加入身份，正常原地升级后完成真实 Hy2 HTTPS、
正式 CLI 期望写入、撤权、两次停止报告、进程重启及再授权。实际 APK/原生库摘要与清单期望逐项一致，
控制 daemon 重启后从原始事实和观察恢复相同结果。验收等待实际授权路径消失/恢复，不能把同时发生的
期望更新或其他摘要变化当作撤权完成。原失败记录与成功复验分别保留，未清空设备或控制身份。
模拟器正常退出后宿主 route/rule/link 不变，新 SSH、LAN DNS、系统 DNS、默认公网和现有代理通道通过。

同批生产服务已切换到源码 `1da6dc2f` 的精确程序，Linux 签名包为第 29 代，数据面仍为原审核修订。
六个节点的实际进程摘要与私有签名报告一致；正式 Web 写入的期望组件在三台 control 上保留相同原始签名字节，
各服务重启后恢复相同期望和实际结果。指定境外出口及 Auto 的真实 HTTPS 均通过。
本机客户端受控异常退出后完成本 generation 清理并保持停止；停止期间和恢复后的管理与基础网络均通过，
原身份、密钥、认证材料及既有 floor/latch 保全，宿主 route/rule 不变。已替换程序及精确暂存文件从各节点删除，
原不可变发布证据继续保留，不作为运行 fallback。

证据位于 `deploy/evidence/2026-10-05-android-release/`。此结果不包含实体 ARM64、物理切网或真实设备
Keystore 终验；Windows 应用发布的后续结果见下一节，旧运行发布 floor 的前向消费仍是独立缺口。

### Windows 应用发布与三种形态的期望组件

[Windows 应用 manifest](core/current-contract.md#windows-应用-manifest-的规范字段) 已接入同一 schema 3
catalog、严格 YAML 发布入口、私有下载和期望组件事实。Installed、Portable TUN、Portable Mixed 各自
绑定实际架构、源码和文件；Installed 还绑定真实 MSI 版本。签发前只读审查 MSI，并在无网络的临时文件系统
提取后与原构建 ZIP 逐文件比较。节点独立核对平台签名和整包字节，ZIP 再核对实际内容；不存在第二套发布状态。

六份应用交付物沿用原源码 `99ddca5e`、MSI 0.13.36 的精确字节，没有为添加 manifest 重建或改签应用。
应用清单第 1 代已随 catalog 第 33 代通过正式 publish 分发到全部 YAML 目标；原目录比较、公开 HTTPS
完整正文、目标条件推进及最终目录均通过。生产私有 mTLS Chrome 实际下载六份应用及各自原 manifest/签名，
独立公钥再次验签后与原交付物逐字节相同。页面分别显示三种形态、架构及预览属性；平台发布签名不冒充 Authenticode。

同机 Windows 11 x64 保留原 VM、TPM、DPAPI 和加入身份，三种原制品分别实际完成 agent/数据面期望写入、
真实 Hy2 HTTPS、运行摘要与私有签名报告比较、停止及进程重启恢复；控制 daemon 重启后原事实与报告字节保持。
Mixed 的测试首次把“没有 TUN”误作旧进程已退出，导致新窗口等待失败；现按实际旧 agent 与数据面 PID
等待退出后再启动，同一未改动制品通过。失败记录单独保留，不以旧状态文件或 runtime running 代替新进程业务。
VM 正常停止后原宿主目录权限恢复，初始 netns 的 route/rule/link 配置未变。

同批公共程序源码 `c6a3f897` 已推送并激活六个正式节点，Linux 签名包为第 30 代，数据面保持原审核修订。
十二项期望由真实 Web 表单提交，六节点实际进程摘要与签名报告一致；三个 control 同步并重启后仍保留相同
原始期望事实。全部服务重启后的组件回读、指定境外出口与 Auto 的真实 HTTPS 均通过，两种偏好都读回同一
预期境外最终出口。原 Auto 偏好恢复，新建 SSH、LAN DNS、系统 DNS、默认公网与既有 WG 代理正常。
原身份、密钥、RuntimeKey、认证材料及既有 floor/latch 保全，宿主 route/rule 配置保持；被替代程序与精确上传暂存已删除。

受保护证据位于 `deploy/evidence/2026-10-05-windows-release/`。全仓与 mobile 检查、双架构原交付物验证、
完整目录导入/传输和浏览器回读通过。ARM64、真实睡眠、物理切网及显示硬件仍由用户终验；外部应用代码签名未启用。
下载目录推进不消费旧运行发布 floor，这项前向安装缺口继续保留。

### 管理员证书签发、普通授权与撤销

管理员交付已接入 `control admin issue`：显式读取既有签发证书和本机私钥引用，生成 P12、独立密码及
公开 `admin.json`；同目录重试核验并保留原交付字节。Settings 使用公开文件提交普通授权事实，并以同一
事实模型撤销精确证书。原 genesis、管理员身份与签名材料保留，不新增管理员 store 或共享签发密钥库。

独立双 control 的真实 daemon 已通过同机 Windows 原生 Edge 验证：P12 导入、原生选证、未授权拒绝、
浏览器授权、另一成员上的 Service 写入与同步、HTTP 和已连接 WebSocket 撤权，以及两个 daemon 重启后的
持续拒绝均成立。明确引用撤权事实重新授予后恢复登录，再次撤销并重启仍拒绝；测试 Service、证书和临时
浏览器策略已清理。过期会话、并发撤权优先、稳定 ID 拒绝重绑定、损坏交付拒绝覆盖也已通过最小测试。

`5169bc8c` 已提交推送并激活到六个获准 Linux 节点；Linux 签名包为第 31 代，下载 catalog 为第 34 代。
正式 publish 消费原 `.env` 与 YAML，三个分发目标完成不可变制品准备、全部公开 HTTPS 正文字节核验、
条件推进和最终验签回读。Android 与 Windows 原已签制品继续保留，运行发布 floor 未被消费或重置。

生产 control 沿正式本机 CLI 从经公开键核验的原签发能力生成测试 P12，同目录重试保留全部交付字节。
原管理员经 Settings 授予新叶，新管理员在三个 control 登录，并通过正常页面创建、回读和删除测试 Service；
另一 control 撤销该叶后，各成员的新 HTTP 请求和既有 WebSocket 均拒绝。三个 control 重启后仍拒绝新叶，
原管理员继续可用。新增授权与撤销的原始签名事实在三成员一致，临时交付包已按精确文件清单清理；
原管理员、原根与私钥、genesis 和既有签名材料保留，没有轮换信任根。

正式浏览器已更新六节点的 12 项组件期望；三个 control 持久保存并回读同一原始签名事实。
六节点正式服务再次重启后，实际 agent/数据面进程摘要、签名报告与期望一致，指定境外出口及 Auto 的
真实 HTTPS 业务通过并恢复原 Auto 偏好。原身份、密钥、配置、floor/latch 与原有材料字节保全，宿主
route/rule 未变；新 SSH、LAN/网关 DNS、系统 DNS、既有 WG 上的 HTTP proxy 和默认公网连接通过。
被替代程序与本轮临时上传文件已核对摘要和所有权后删除。全仓 build/test/vet、mobile 检查、格式、安全及
diff 检查通过。受保护证据位于 `deploy/evidence/2026-10-05-admin-access/`。

本项已完成管理员补发、普通授权与撤销的原生及生产业务链；`control.loom`、网站信任切换和用户笔记本
本轮终验仍未完成，不由上述结果抵扣。

### 普通设备撤权后的重新授权

现有后台允许同身份显式重新授权，但 Web 撤权后隐藏整个授权表单，缺少正式恢复入口。设备详情现在
从签名撤权的因果历史投影最后唯一的公开配置，明确显示撤权状态，由管理员审阅后提交原 `device.put`。
公开审阅值不参与运行授权，不保存另一份设备状态；永久删除、目标冲突或歧义历史不能生成恢复入口。
真实 Chrome 已验证加入后的改名/DNS 配置保留、撤权、重启后仍拒绝、同身份重新授权和永久删除拒绝；
签名事实测试覆盖并发未知授权不替换默认审阅值、歧义历史不择胜及到达顺序无关。
`81f674e3` 已提交推送并激活六个正式节点；Linux 签名包为第 32 代，下载 catalog 为第 35 代。
正式 Web 邀请与 CLI 加入建立独立 Linux 测试设备，原虚拟机身份另行保留。三个 control 页面回读一致；
设备详情移除策略后，客户端接受拒绝配置，实际接收节点移除凭据，正常客户端和保留原凭据的对照进程均被拒绝。
另一 control 恢复策略后，同身份真实 HTTPS 恢复，控制面和接收运行时都消费了对应变更。

普通设备撤权后，三个 control 重启仍保留撤权及公开审阅配置，旧报告不再用于当前状态，原凭据业务仍拒绝。
经另一 control 的恢复表单重新授予后，客户端接受新事实并恢复真实 HTTPS；原私钥、公钥、RuntimeKey、
事务及加入绑定保持，不重新扫码或加入。恢复期间曾出现传输超时，持续使用新连接验证，实际成功后才记为通过；
随后客户端重启恢复与真实 HTTPS 再次通过，不以 runtime running 或先前可用观测抵扣当时失败。
测试设备最终经正式 CLI 永久删除，三个页面不再提供恢复入口，接收节点再次拒绝原凭据；原始签名事实
在三个成员一致且重启保留。测试进程和精确执行暂存已删除，新测试身份原件保留，原虚拟机身份字节、
路由、规则及 DNS 不变，新建管理/DNS/公网连接通过后虚拟机正常关闭。

正式 publish 消费原 `.env` 与 YAML，三个分发目标完成制品准备、条件推进与最终验签，所有已认证分发 URL 的全制品 HTTPS 正文核验通过。
六节点 12 项期望由正式 Web 提交，各 control 保存相同签名事实；六节点正式服务再次重启后，真实
agent/数据面进程、签名报告和期望一致。指定境外出口及 Auto 的真实 HTTPS 通过并恢复原 Auto 偏好。
原身份、密钥、floor/latch、旧签名字节及宿主 route/rule 保全，新 SSH、LAN/网关 DNS、系统 DNS、
默认公网和既有 WG 上的 HTTP proxy 回读通过。被替代程序和精确上传暂存已删除。
全仓及 mobile 检查通过，受保护证据位于 `deploy/evidence/2026-10-06-device-policy/`。
本项完成普通设备撤权和同身份显式恢复；其余传输、隔离 TUN、DNS/LAN、动态成员及实体平台终验仍分别保留缺项。

### 策略复制与设备草稿返回

正式私有 Web 已读回：策略页缺少复制及引用范围提示，节点表单缺少进入同一策略编辑器后返回分配的入口。
本项沿用 `policy.put` 与 `device.put` / `invite.issue`，新策略先保存，设备或邀请仍须单独提交。
新增引用列表从当前有效设备及未终结邀请派生，不增加授权 store；绑定事务在签名期限后仍允许原身份续办。
浏览器已验证复制不改源策略、已有 ID 拒绝、取消保留草稿、保存返回后只替换同服务选择、响应丢失后原请求
重试，以及设备并发修改使第二步陈旧拒绝；新策略保留，重新审阅后仅改单设备，另一设备继续消费原策略。
添加设备的新策略也返回原邀请事务及 DNS/名称草稿，正式签发后引用可回读。设备在复制期间被永久删除时，
返回只保留不可执行的公开草稿，不恢复授权入口。

`c9f0d76a` 已提交推送并激活六个正式节点，Linux 签名包为第 34 代，下载 catalog 为第 36 代。
正式 Web 与 CLI 建立独立 Linux 测试设备，保留原虚拟机身份。首次加入曾遇认证 DNS 解析失败；解析器
返回有效地址后复用原已保存身份及请求完成加入，不重建密钥；首次失败原因未确证，原记录保留。
设备详情经同一 Policies 表单复制共享策略，取消后原草稿仍在；新 deny 策略保存后设备仍沿原策略成功访问，证明保存不自动分配。单独提交设备分配后，
运行时消费新 Policy，实际接收节点移除旧授权，正常客户端及保留原凭据的对照进程均被拒绝。
原共享策略和其他设备授权保持；其间原客户端一次 HTTPS 被拒绝，未改策略即恢复，而测试设备仍被拒绝。
该中断作为运行视图重建相关的待定位缺口保留，不能声称其他设备业务全程未受影响，也不能用后来的成功抹去失败。

另一 control 将该独立策略改为 allow 后，同一设备身份及 RuntimeKey 恢复真实 HTTPS；旧策略凭据继续
被接收端拒绝，不能跨 Policy 借权。三个 control 与测试客户端重启后，策略、分配和真实业务仍可回读。
添加设备表单中新建另一策略后返回原邀请事务及 DNS/名称草稿；所选 control 没有 serving bootstrap
入口时未提交邀请，新策略仍保留。随后在已有入口的 control 沿同一未签发事务选择该策略完成签发，
三个 control 均显示准确的待加入引用；该邀请未被标成已授权设备。测试设备最终永久删除，未加入邀请经原签发 control 正式取消，
两个测试策略经 Web 删除；原始签名事实三成员一致且重启保留。测试执行与凭据暂存删除、身份原件保留，
虚拟机原身份、既有路由、规则、DNS 保全；启动后另出现两条由原 RA 前缀与虚拟网卡 EUI-64 生成的
内核本地 IPv6 路由，已逐项核对，未将它们冒充字节完全不变。停止后新 SSH/DNS/公网连接通过，虚拟机正常关闭。

正式 publish 消费原 `.env` 与 YAML，三个分发目标准备、条件推进和最终验签通过，所有已认证分发 URL
的全制品 HTTPS 正文核验通过。六节点 12 项组件期望由正式 Web 提交；六节点正式服务重启后的实际
程序、签名报告与期望一致，指定境外出口与 Auto 的真实 HTTPS 均通过并恢复原 Auto。原身份、密钥、
认证 floor/latch 与旧签名字节保全，宿主网络和新连接回读通过，被替代程序与精确上传暂存已删除。
全仓、mobile 和实际 Chrome 检查通过，受保护证据位于 `deploy/evidence/2026-10-05-policy-assignment/`。
本项完成策略复制及独立分配流程，不抵扣隔离 TUN、其余传输、DNS/LAN、动态成员或实体平台终验。

### Linux 视图更新后的路径保留

策略独立分配验收中，原设备授权保持，但一次业务请求在运行视图重建后被拒绝，随后沿另一候选恢复。
日志确认重启及候选失败的次序，尚不能将全部失败归因于单一因素。源码已确认整个 View 摘要变化会
清空全部观测，并清理重建未变化的 WG 接口；被动采样没有复现路由计数导致的网络代变化，不据此修改
网络代算法。原始失败与分析保存在同次受保护验收证据中。

[客户端模型](clients/client-runtime-model.md#linux-更新时保留未变的执行输入)对应的实现已接入 Linux 运行
循环：在原缓存锁内逐条比较认证输入并保全原时间、失败结果与同期 Preference；WG 仅复用本进程的
精确创建句柄，并回读内核执行值。旧缓存整体清空和每次 View 变化无条件删除 WG 的路径已替换。
输入变化、撤权、重启缺少旧输入、被替换接口和清理失败的必要测试通过；隔离网络命名空间中的真实
WG TCP/UDP、复用、停止重建及记录清理通过；完整 Mixed 监督器实际接收新签名 View，保留真实 HTTPS
失败的原样本并在撤权后删除观测，正常停止释放 listener。精确制品已在全部获准 Linux 节点激活，
生产正式浏览器的策略撤回/恢复、原凭据拒绝、同身份真实 HTTPS、未变样本与 WG 创建句柄保留、
异常退出清理及显式恢复已回读。全部 YAML 目标的正式签名分发、完整 HTTPS 字节、条件推进及最终验签通过；
正式浏览器写入期望组件后，全部 control 原事实一致，所有 Linux 节点再次重启、实际进程摘要与新签名报告
相符，指定既定境外出口和 Auto 的真实 HTTPS 均通过。原身份、密钥、认证原件、floor/latch 与宿主网络
保留，新建基础连接通过；旧版及中间版程序、精确上传暂存已删除。受保护证据位于
`deploy/evidence/2026-10-05-runtime-view-continuity/`，最终运行源码为 `f6b2434e`。本项不增加版本、权威 store、选路偏好或新鲜性阈值，也不保留已撤销的 Hy2 会话。

部署重启暴露出另一个实际阻碍：某 control 的已接受报告历史仍在原文件容量内，却超过聚合 JSON
条目预算，导致重启严格解码失败。其原始历史已保护保全；[报告持久边界](core/current-contract.md#report-与逐条观测)
修正保持原规范集合和全部签名字节，统一写入与读取容量并在持久替换前拒绝越界。回归测试及现场原始
历史副本的严格读回已通过。原生产 control 已用精确修正版恢复，实际私有管理 API、原始签名报告保全
及设备新报告均已回读；第一次分发因控制入口不可读而终止，未推进目标指针，失败原件保留。
重试的正式发布及控制重启、报告回读均已通过。验收使用真实私有管理 API 就绪，不把程序进程启动
等同于 control 服务就绪。本修正保留既有文件容量，未增加自动历史清理；越界写入在持久替换前明确拒绝。

### 实时路径的服务关联与原始观测回读

正式认证浏览器已读回当前 `/routing` 页面、实际管理快照及与部署源码一致的脚本，记录在
`deploy/evidence/2026-10-05-runtime-view-continuity/routing-audit/`。后端路径使用现行 `service:` scope，
Service 也没有旧 `policy` 字段；审查时页面仍按 `policy:` 与 `Service.policy` 关联，并平铺设备与范围，
当时尚未实现[实时路径](clients/web-ui-projection.md#实时路径)要求的服务列表、设备列表与详情两层入口。
原页面只因存在选中报告就标为 Fresh，没有相应新鲜性依据。这些已确认的实现偏差不能用原型完成掩盖；
本项修正保留原视觉与导航语义，不增加选路开关、健康阈值或业务权威。

修正已按现行 PolicyIDs → Policy.ServiceID 实现服务导航、设备清单、只读详情、搜索/分页与返回上下文，
补齐原 Path 的首跳资源/传输、有序 LinkID 和规范摘要。历史只从现有签名报告读取，按当前授权、候选规范
和具体目标过滤，重复样本不增加观测，分叉/错签名/旧规范不进入有效历史，同时间矛盾值保持未知。
接收端时效契约未定时，选择、runtime 与目标结果只按原时间标为 reported；不以任意未来 valid_until
产生当前健康，也不从所选候选猜测偏好模式。未分配、deny、等待新 View 及缺失报告分别回读。
真实 Chrome 已沿普通邀请、私有 claim、签名报告和持久重开完成两层导航、历史查询、范围拒绝及
新 View 等待回读；图形与布局已按实际浏览器检查。设备时钟回拨时，合法观测时间可能晚于报告时间；
实现不再以契约未规定的两者顺序过滤原样本，签名回归用例已覆盖该反例。

完整构建、测试、静态检查和正式全目标签名分发通过，精确源码 `9c277a8c` 已在全部获准 Linux 节点
激活。全部 control 的真实 mTLS 浏览器在重启前后核对了实际脚本、Service/Policy/设备关联、只读详情、
原始签名样本对应的历史及越权范围拒绝；查询未改变权威事实。没有历史样本的 control 明确显示未知，
本项不把另一个 control 的样本视为已同步，也不声称当前新鲜性算法已经定义。
正式浏览器写入的期望组件在全部 control 保持一致并经重启恢复，全部节点实际进程摘要与新签名报告相符；
指定既定境外最终出口和 Auto 的实际 HTTPS 均通过，原偏好已恢复。原身份、密钥、认证原件和 floor/latch
保全，宿主网络与新建基础连接回读通过；被替代的旧程序及精确上传暂存已删除。生产证据位于
`deploy/evidence/2026-10-05-live-paths/`。当前新鲜性、未上报的偏好模式及逐 Link 观测仍保持缺项可见。

### control 成员之间的报告差量

设备报告此前只在接收 control 保存，成员通道只同步控制事实，导致不同 control 的历史不同。首轮实现
已完成正式增量分发和受影响 control 的程序切换，原身份、认证原件、floor/latch、宿主路由规则和新连接
回读保留；未受影响客户端的程序和进程未变。但现场大历史的报告索引请求超过成员时间预算，只有较小
历史互相补齐，不能以服务已切换或小规模 TLS 测试通过关闭本项。

修正继续使用[成员报告差量](core/current-contract.md#control-成员之间的报告差量)、同一 schema 3
签名报告与持久集合：纯索引计算移出文件锁，内存索引可删除重建并随原件提交更新；多个设备的缺失原件
进入同一有界批次，最高范围先于旧历史。没有新配置、持久索引、任务库、报告格式或长期旧协议 fallback。

真实 TLS 测试已覆盖跨设备批次、等高缺口、中断重启不重传、旧序号及最高序号分叉、错误签名/网络/范围
拒绝，以及另一成员原页面的历史回读。缓存还覆盖外部 writer、不可变旧快照、删除重建和缓存后非法文件
拒绝；现场原历史副本已用于相同既有内存限制下的只读索引与隔离写入测量。全部真实资料只进入被忽略的
`deploy/evidence/2026-10-06-report-sync/`，没有改写生产原报告做测试。

修正版的 build/test/vet、格式、安全及 diff 检查和成员同步并发检查已通过。Chrome 回归暴露了测试在刷新
真正开始前误认旧文档的等待问题；改为等待新文档并原子读取邀请值后复验通过，产品页面未改。源码
`269fd1d4` 已完成增量签名分发、全部公开 HTTPS 内容回读、最终指针验签与受影响服务切换；其他节点的
程序和正式 unit 进程未更新。原身份、认证材料、floor/latch、宿主路由规则和新建基础连接保留。

现场随后确认私有中继的 WG 返回路径异常：两端配置一致，接收端发出握手响应，发起端未收到。沿严格
部署配置已有的映射范围进行双向 UDP 对照，关闭临时监听后，经正式 `resource.put` 逐条修正实测可达的
端口；没有修改 NAT、路由器或宿主防火墙。私有 TLS 请求恢复，指定既定境外出口和 Auto 的实际 HTTPS
均通过，原 Auto 偏好已恢复；大历史索引仍超过成员请求预算。
一次探测选端口未排除已经授权但尚未绑定的同机资源，产生重复端口并使客户端失败关闭；这是部署执行错误。
保留失败记录后，改为排除全部认证监听坐标，再经正式写入前向修正。客户端自动恢复，并重新验证全部
相关握手、私有新连接和业务；未删除旧事实或改写原始证据。
浏览器已提交精确期望组件并在接收 control 读到对应签名报告，其他成员的报告回读尚未通过，相关等待
已结束并清理临时浏览器凭据；原失败证据保留，不以服务切换或局部回读关闭本项。

进一步修正消除索引读取对报告写锁的等待：按[成员报告差量](core/current-contract.md#control-成员之间的报告差量)
读取原子提交的完整文件快照，以同一原字节核对可删除的不可变索引；原写入锁、规范集合、签名与容量边界
保留。回归先在旧实现复现写锁争用失败，再验证有缓存和无缓存时均可读取已提交原件；外部 writer、非法
文件与旧快照不可变性仍覆盖。现场历史副本在既有内存限制下的持锁读取、完整构建检查及并发检查已通过。
读取修正 `aecd0979` 已完成增量分发、公开 HTTPS 回读、受影响服务切换与精确进程核对。身份、原件、
floor/latch、宿主网络和未受影响节点均保留；指定既定境外出口及 Auto 的业务再次通过。但完整请求链
仍被原成员轮次的总期限取消，其他成员的历史没有补齐，不能关闭本项。

逐请求诊断已确认前沿和索引成功，取原件时因共用期限耗尽而取消；同一现场历史副本在较长且仍有限的
预算内能提交多批，原生产文件未用于诊断写入。修正只调整 daemon 的有限轮次预算，单次请求上限不变，
取消及已提交前缀保留语义见[成员报告差量](core/current-contract.md#control-成员之间的报告差量)。现有 TLS
回归改为通过真实 daemon 轮次执行慢请求，旧实现已复现首批未落盘，修正后通过。预算修正的完整
build/test/vet、格式、安全和 diff 检查已通过。预算修正 `b86d5b99` 已完成正式增量分发、全部公开制品
回读及受影响服务切换；主 control 与一个远端通过原始历史逐份核对，全部 control 的正式浏览器已读到
新程序与期望组件匹配的签名报告。指定既定境外出口及 Auto 业务通过，其他节点程序和服务进程未变。

另一个远端在补历史期间被其现有服务内存上限终止，保持 failed，没有自动重启；原报告文件保留。该节点
后续浏览器静态资源请求失败，页面及重启验收不能称通过。隔离的原历史副本已复现：报告写入与并发索引
读取的临时缓冲、重复解码叠加触发同一内存限制。
继续按[成员报告差量](core/current-contract.md#control-成员之间的报告差量)修正：索引读取与冷重建限制并发，
保持独立于写锁及可取消等待；完整逐字节核对后复用不可变原件，变化才分配有界缓冲；增量索引在提交前
预计算，提交后立即发布，读取后重新检查最新缓存。没有提高内存上限、删除历史或改变报告字节及权威。
同一复现用例及更大的当前历史副本、正式批次上限和并发读取已在原服务内存限制下通过，相关回归通过。
内存修正的完整 build/test/vet、格式、安全和 diff 检查，以及成员报告并发检查已通过。`57b62c49` 已完成
正式增量分发、全部公开制品回读、受影响服务切换和精确运行程序核对；安装复用已验签落盘的包，没有再次
上传程序。原身份、认证原件、floor/latch、宿主路由规则及新建基础连接保留，未受影响节点的程序和进程
未变。指定既定境外出口及 Auto 的真实 HTTPS 已通过，测试后恢复原 Auto 偏好。

随后经一个 control 的正式 Chrome 管理页面写入期望组件，并在全部 control 页面读回：只更新受影响节点
的 agent，其他期望引用保留；实际签名报告中的程序摘要、源码版本与期望逐项一致。按报告内容摘要核对本轮之前保留的
全部已授权原始历史、各节点自己的全部原件及新程序报告，全部成员均包含应有原件。正式路径页面的
Service、Policy、设备关系、两层导航及按候选和目标限定的历史均回读通过，显示样本与本机原件一致；
重复参数和未授权目标拒绝，浏览过程没有改变控制事实。

逐节点重启同一精确程序后，再次完成签名组件报告、全部原始历史、正式页面及上述真实业务回读。原身份、
认证材料、floor/latch、宿主路由规则及基础新连接保留；未受影响节点的程序和进程未变。验收期间报告继续
写入，既有服务内存限制下未再发生内存终止。确认无活动进程引用后，已删除受影响节点被本轮替代的旧程序
目录；仍由其他节点引用的公开不可变制品和受保护证据保留。报告差量的本次生产业务链已完成，证据位于
`deploy/evidence/2026-10-06-report-sync/memory/`；这不代表动态成员、多目标算法或其他未实现功能完成。

故障节点首次恢复还暴露了另一项实际缺口：异常退出遗留管理员 Unix socket，正式服务启动因地址占用而
退出，并非再次发生内存终止。现场核对原身份、精确 service 均停止、受保护 socket 的类型与归属、无内核
监听及连接被拒绝，再比较文件身份，仅删除这一失效入口，随后同一精确程序启动并成功报告。此操作未修改
报告、密钥或网络配置；当时产品启动入口尚未实现该异常遗留的自动恢复，不能用这次人工清理抵扣崩溃恢复能力。

### Linux control 本机管理入口恢复

后续修正只接入[本机管理入口的异常退出恢复](operations/configuration-model.md#linux-本机管理入口的异常退出恢复)，
不新增权威对象或配置。正式 `Server.Serve` 在启动后台执行器前取得该入口的互斥和监听；锁由内核持有，
没有完成状态。只有受保护、归属匹配且明确无人监听的同一 socket 才可移除，关闭时也只清理自己创建的对象。
同一个真实服务进程回归已在旧启动逻辑复现强制退出后无法重启；修正后原持久字节保留，原管理入口恢复并
完成普通事实写入与读回，正常停止移除自身 socket。最小回归另覆盖活跃旧监听者、并发恢复、普通文件、
链接、权限/归属错误和关闭时替代物保全；自定义 socket 路径不能占用权威写锁。完整 build/test/vet、
格式、安全及 diff 检查、相关 race、Linux ARM64 及 Windows 源码编译已通过；编译不抵扣实体机验收。

`1daf905f` 已完成正式增量分发、全部公开 HTTPS 回读、受影响 control 的精确制品激活及正常业务验证。
安装直接复用目标已验签的包；其他平台制品、部署输入、未受影响节点的程序和进程保留。经正式 Chrome
表单更新受影响节点的 agent 期望组件后，全部 control 页面均读到与期望一致的实际签名报告；其他期望
引用保持不变，全部应有原始历史也已核对。

原故障节点随后执行了真实控制服务主进程强制终止：service 保持 failed，原 socket 遗留且内核锁释放。
沿原 `systemctl start` 入口即可恢复管理服务，没有人工删除 socket；再正常停止时自身 socket 消失，
锁释放，再次启动恢复正式入口。故障前全部报告原件、身份与既有签名材料保留；同节点客户端进程未中断，
内存限制及 `Restart=no` 未改。恢复后全部 control 的正式浏览器、实际签名组件报告与原始历史再次通过，
指定既定境外出口及 Auto 的真实 HTTPS 也通过，原 Auto 偏好恢复。宿主基础新连接、原路由规则及其他
节点进程保持；被替代程序目录已按精确摘要和无活动引用检查删除。本项显式重启恢复的生产业务链已完成，
证据位于 `deploy/evidence/2026-10-06-admin-socket/`。

执行过程的两项脚本问题也已保留记录：部署曾等待随刷新变化的 `reported` 瞬时标志，实际控制端已经保存
对应签名报告；现已移除这项冗余等待，持久报告与正式浏览器验收仍必需。第一次故障验收在启动瞬间过早
检查程序摘要而退出，服务随后读回为正确制品且正式接口正常；原失败记录保存后，改为有界等待实际程序
加载，再从原故障前基线继续完成停止、重启及原件保全验证。没有为让检查通过而改写业务状态或删除原证据。

### 本轮实现与实际验证

Linux 客户端制品已改用[规范 schema 3 manifest](core/current-contract.md#linux-客户端-manifest-的规范字段)，
显式发布代、带外公钥、逐文件摘要和规范 tar/gzip 均参与验证；源码修正版数据面、许可证与独立复现材料
随包交付。旧 schema 2 签名封装与旧 Linux catalog 写入器删除。amd64/arm64 的真实程序打包、验签、
规范往返和篡改拒绝已通过，记录在 `deploy/evidence/2026-10-04-linux-package/`。这只证明交付格式，
原生 Mixed 与 Web SSH 安装、恢复见上文；隔离 TUN 及生产发布 floor 的前向消费仍待完成。

- [规范编码](../internal/control/contract_encoding.go)、[规范值](../internal/control/contract_values.go)和
  [Material](../internal/control/model.go)使用唯一 schema 3、严格规范 JSON、逐事实签名及领域分隔符；
  未知/重复字段、非规范整数/转义、缺字段、null、非法集合顺序和旧格式均拒绝，不自动修复或重解释旧字节。
  Policy 固定 ServiceID，设备只选 PolicyIDs；同服务重复策略、无效引用和未经依赖证明的修改拒绝。
- [Authority](../internal/control/store.go)以系统排他锁保护签发序列及请求幂等，持久保存同一原始签名事实，
  文件和目录耐久提交后才回复；重启从完整事实重建唯一 Projection。初始化只接受显式新空目录和完整
  genesis，缺失/损坏或旧权威材料不自动初始化。初始任意成员数共用同一验证，第二个有效成员已实际签发普通事实。
- [同步与提交](../internal/control/cluster.go)已删除普通写入的 Raft/QC、全量 ID 轮询和旧 State 重放依赖，
  使用按签发键前沿的完整事实差量及精确依赖补取。真实双成员私有 TLS 同步通过；传输 CA 本身不授予成员资格。
  已认证缺依赖事实和同键分叉证据保留，受影响授权失败关闭，不选一个分叉赢家或复活祖先权限。
  新二进制已移除旧 SSOT 渲染、写入、发布激活、安装及回滚命令分派；离线验签/旧 current 取证和受保护
  备份恢复工具仍保留原字节，不授予新 Authority 重放资格；旧 client publish-linux catalog writer 也已从新 CLI
  删除。签名目录、私有下载及 YAML 全目标正式 publish 已实际验收；现网运行制品按本次明确替换授权激活，
  旧运行发布 floor 的可验证前向映射及自动消费仍缺失，不以目录分发或直接替换冒充该结果。
- [正式设备链](../internal/control/device_http.go)接通 invite.issue、私有 claim/resume、绑定和 device.join；
  RuntimeKey 只在首次加入生成并随原事实持久化，同事务重试/重启复用原身份。device.put 只接公开字段，
  保留已验证的私钥关联和 RuntimeKey；内部 bind/join/expire 不能由通用管理请求伪造。
  初始 control 的同 NodeID 首次普通职责绑定已验证，设备签名键不得复用 control 键；distribution_urls 归设备授权。
- Invite 携带完整 genesis/成员证明和签名 Material，唯一交付编码为完整规范值经固定 zlib 压缩后 base64url，
  不裁剪证明、不接受旧未压缩 fallback。真实双成员及管理员叶证书的 URI、文件、二维码和剪贴板回读通过；
  QR 以整数像素模块生成，超过媒介容量明确拒绝。SSH/sh 已沿同一邀请接通 Linux 自动安装与原身份恢复，实际范围见上文。
- [设备 View 与运行投影](../internal/control/runtime_projection.go)按 Service/Policy 生成 Direct、本机出口、一跳 Hy2 和显式 WG 中继候选，
  默认拒绝业务；最后一项授权移除、deny 或无分配产生合法拒绝配置。设备验证完整证明、签名、View 摘要和逐键前沿，
  同前沿不同 View 拒绝；唯一 LKG、高水位、latch、Preference 先耐久保存再执行，新配置执行失败不恢复旧权限。
  Linux、Windows 与 mobile 已改为消费同一 schema 3，旧 Head/runtime_contract/capability 运行分支不再作为 fallback。
  本机出口即使节点链为空，也保留本节点 FinalExit；只有 Direct 许可才满足 Direct 偏好，入口范围不伪限制本机出口。
  Android、Windows、Linux 与 Web 保留候选和选中结果的真实出口身份，未配置业务探测时路径仍为 unknown。
  客户端配置验证复用控制契约的唯一规范编码，证书 PEM 的换行不再被普通 JSON 的另一种转义形式误拒绝。
- [报告](../internal/control/observations.go)保存设备签名原值与单调序列；同序列不同内容保全为分叉，不能覆盖，
  索引可重建。当前报告必须与有效设备、认证 View 和精确观测范围一致才能进入当前 Web 投影；旧报告只作诊断。
  schema 3 区分认证 View 与实际 applied View，可真实表达运行错误，不伪造新配置 running 或已应用摘要。
- Web 保留样式、keyed DOM、草稿焦点及有效交互，Service、Policy、设备公开职责/PolicyIDs/distribution_urls、
  Invite 和报告已从唯一 Projection 接线；去掉旧 Head/State/SSOT/approve/base_head/quorum 投影。
  Chrome 正式 UI → AdminHandler → Authority 的测试已验证 Service/Policy 创建、草稿不被实时刷新覆盖、
  陈旧依赖拒绝及重新打开；邀请选项先于管理快照到达的反例也已验证，表单不会保留缺策略的初始草稿。
  真实 claim 后清空设备 PolicyIDs 会生成拒绝 View且不改变设备秘密，completed 邀请
  不再回吐可复用交付物。首次签发按模型进入邀请交付视图，再从明确链接进入同一 DeviceID 详情；两处复用
  同一个可丢弃交付/状态组件，没有独立进度或加入成功页。Chrome 验证首次交付→设备详情继续同一事务，
  二维码、下载、刷新/重开保持一致，实际私有加入后两处均移除交付并指向设备详情。事务刷新保留设备改权草稿，
  迟到 HTTP 快照不覆盖期间已接受的实时完成状态；这些交错已由真实 handler/Chrome 验证。设备详情只消费 schema 3 runtime
  的 state/applied_view_digest/error_code；签名 running/error、目标 URL、零/缺失 duration_ms 和四职责过滤
  均已浏览器回读，不再显示旧 overlay/exact/started 字段。部署 applied 无证据保持 unknown，业务观测不作全局健康归约。
- [Endpoint](../internal/control/endpoint_runtime.go)通过真实 advertised TLS 预检才允许 serving；
  prepared 新证书不挤掉有效旧 serving，draining 拒新连接并在明确期限关闭旧会话，retired 要求实际 Active 为零。
  取消、open 到期、设备撤权与证书到期会关闭既有连接；challenge 期间撤权也不能完成旧授权认证。
  completed 同绑定在 Invite 期限后仍可恢复，真实终结后拒绝。退出关闭未完成握手和本进程持有的连接；
  [TCP edge](../internal/control/endpoint_edge.go)也取消拨号并等待转发退出，清理错误传回调用方。
- 当时的旧凭据派生实现（原文件已删除）的固定 HKDF-SHA256、规范输入与独立 HMAC 向量已验证，
  历史上按网络、设备、Service、Policy、资源和接收节点隔离；现行规范见
  [资源与用途隔离凭据](core/current-contract.md#资源与用途隔离凭据)，不能由此恢复旧绑定。
  当时的[一跳投影](../internal/control/runtime_resources.go)把同一
  派生凭据交给 access outbound 和资源接收端，接收端不获得来源设备 RuntimeKey 或自身 access 分配。
  [Linux 服务端](../internal/linuxclient/resources.go)使用签名 CA/校验名与显式受保护本机证书引用；入站用户先排除
  其他已选 Service 的重叠目标，再执行允许范围，默认拒绝，不能以 SNI 扩大 IP 目标权限。
  接受新 View 后关闭旧进程及已认证 QUIC 会话；真实 owned UDP、TLS/认证和当前 ACL 摘要进入私有签名报告。
  父进程异常退出也终止子进程。删除资源停止数据面，空入站权限拒绝旧口令；运行失败与重启保留新 LKG。
  未新增授权 store、并行 writer 或版本，纯 server 不启动 access capture，server 与 access TUN 组合仍拒绝。

### 本轮检查及平台边界

- 正式 CLI 用真实随机测试密钥、双成员完整 genesis 和本地受保护输入执行 control init/serve/write/inspect、
  endpoint prepared→serving、client enroll/sync/inspect，验证请求幂等、daemon 重启、撤权与显式重新授权。
  证据：`deploy/evidence/demo-control-cli-20261003T191000Z.json`。测试 daemon 已按精确 PID 和程序路径核验后正常停止。
- Linux 在专用 user/network namespace 中，用同一正式 CLI、私有设备通道和真实 sing-box Mixed 执行授权业务、
  无关事实提高前沿且 sing-box 进程不重启、撤权拒绝、重启保留撤权、执行故障保留新 LKG、签名 runtime/error
  报告和 admin API 回读；停止后端口释放，
  隔离区路由不变，无配置业务目标仍为 unknown。证据：
  `deploy/evidence/demo-linux-formal-runtime-20261003T212743Z.json`；此前本轮记录保留其较早范围。没有在宿主初始 netns 启动 access TUN；
  此证据不抵扣 TUN、WireGuard 崩溃恢复、宿主安全或生产激活。
- 本机出口的正式隔离链还验证：Direct 偏好无法借空节点链使用本机出口，重启保持拒绝；指定本机出口通过显式
  reload 从同一 View 恢复，Auto 正常消费，撤销出网职责收口候选。偏好由正式 CLI 保存，reload 通知使用只指向
  该测试 PID 的临时适配器，没有调用宿主 systemd。证据：`deploy/evidence/demo-linux-local-egress-20261003T212737Z.json`。
- Hy2 的正式隔离链覆盖两节点私有加入、resource/Service/Policy 写入、一跳 HTTPS、selector/CLI/admin API 回读、
  错误 TLS 名/口令、越权 IP、借用合法 SNI 的 IP 请求，以及后来 Service 重叠时仍有效的旧凭据被接收端拒绝。
  旧 QUIC 会话及已打开流随 ACL 替换关闭；父进程 SIGKILL 后子进程退出，重启恢复当前 ACL；撤权和故障均不复权。
  资源删除后报告 stopped，监听释放，隔离路由不变。证据：`deploy/evidence/demo-linux-hy2-20261003T212729Z.json`。
  当前实测为 IP 资源拨号和 IP 业务，域名资源解析、跨实体网络、Android/Windows 原生 Hy2、安装与生产均未由此证明。
- control、deviceclient、clientjoin、mobile 和共享 clientruntime 的相关测试/race 检查已通过；mobile test/vet 通过。
  本轮 Go 全仓 build/test/vet 的检查记录在 `deploy/evidence/demo-schema3-go-final.json`；control、Linux、
  clientadapter、clientmodel、deviceclient 的 race 全部通过，其中 control 启用真实 Chrome 的正式 UI 入口。
  记录在 `deploy/evidence/demo-schema3-hy2-race.json`，不借此前检查点的旧通过记录抵扣。
  控制端连接级测试还覆盖成员身份验证、端点轮换/排空/撤销、认证中撤权、退出清理和失败关闭。
- Android 双 ABI AAR 与当前 Kotlin 的 34 项 JVM、lint、debug APK 构建通过；lint 为 11 warning、1 info、
  无 error，AAR/APK 内两 ABI libbox 的摘要逐项一致。证据：
  `deploy/evidence/2026-10-03-schema3-android/gradle-native.json`。
  原生测试发现并修复 Hy2 的 UDP underlay 重新进入 VPN：本机投影启用 libbox 平台接口控制，实际调用
  `VpnService.protect`；认证私有 Endpoint IP 精确排除，撤权后的更新和报告仍能通过同一私有通道。
  未接认证解析的 Endpoint 主机名明确拒绝，不借系统 resolver 绕过；此修复不放宽 Linux 初始 netns 门禁。
- Android 在专用 user/network namespace 中启动全新临时 API 35 x86_64 模拟器，保留已有 AVD；正常
  DocumentsUI 导入、私有加入、系统 VPN 同意、真实 Hy2 HTTPS 与接收端业务记录均通过。撤权后 VPN 自动
  应用拒绝 View、业务失败、选择清空；强制退出应用再启动恢复同一撤权 LKG，重新授权后同一身份恢复真实业务。
  各阶段都有私有签名报告和可见 UI 回读，最后正常断开；隔离路由恢复。
  证据：`deploy/evidence/2026-10-03-schema3-android/native-hy2-222242.json`；脚本、报告回读和原生截图保留在
  同目录 `native-hy2-method/`，所验 APK 摘要与上述构建记录一致。
  空路径已改为明确显示没有已选业务路径，诊断文字按 Service/目标/网络说明真实业务观测；样式与截图基准未重写。
  空配置原生 UI 回归也已通过首次通知同意入口；冒烟脚本删除已失效的旧测试入口、代理/DNS 修改与 VPN
  appops 授权。记录在同目录 `ui-smoke-native.json`。模拟器、独立 adb 和 fixture 进程已退出，专用 namespace
  无存活进程；清理回读在 `cleanup-final.json`，没有启停生产 service 或修改既有 AVD。
  实体机 Keystore、ARM64 原生运行、IPv6、物理切网和正式签名发行仍未验收，模拟器结果不抵扣这些边界。
- Windows amd64/arm64 应用及测试制品构建通过；VM 的 deviceclient 12 项、共享运行时 9 项通过，
  包含真实 Mixed 授权 TLS、错误 SNI 拒绝、拒绝配置替换及 Job 清理。最终 Windows 支持范围内 12 项通过，
  覆盖正式 broker 规范编码、Installed Machine DPAPI 撤权/无 access 恢复、同 View 更高前沿持久接受且不重启。
  该结果明确排除此前已记录失败的两项 Portable User DPAPI 测试，不能称整个客户端通过。
  另一个原生反例验证：配置拉取期间另一正式句柄先接受较高前沿，同 View 的旧网络响应不打断有效运行。
  证据分别位于 `deploy/evidence/windows-vm/demo-schema3-windows-final/evidence.zip` 与
  `deploy/evidence/windows-vm/demo-schema3-windows-frontier/evidence.zip`。CurrentUser DPAPI 在 SSH 会话被拒绝，
  现场没有已登录桌面，GUI/交互会话仍未验证；不改用机器 scope 绕过。VM 已正常 inactive，临时 ACL 精确恢复，
  无活跃测试。TUN 仅做三形态配置 check，未实际执行；VM 也不能抵扣 ARM64、睡眠、物理切网和实体显示器终验。
  本次 Hy2 共用源码更新后已重建双架构应用及测试制品，记录在 `deploy/evidence/demo-schema3-windows-hy2-build.json`；
  上述 VM 原生记录早于这次 Hy2 更新，不能声称新制品已在 Windows 原生执行 Hy2。
- 前期六键 loader 误拒绝用户已有的 `.env`→YAML，历史只读失败记录在
  `deploy/evidence/demo-config-readonly-20261003T200424Z/result.json`。该实现漂移现已删除；当前正式 loader
  严格解码唯一 YAML 引用并已消费原部署输入，定向测试及全仓检查通过。历史失败不再表示当前配置不可用。
- 本轮仓库安全及 diff 格式检查通过；现存控制 Go 文件格式检查无输出。最终提交仍须复核实际变更和制品范围。

### 前一检查点的独立记录

以下记录属于同日较早的 LKG 接受/纯函数阶段，不是本轮替换后源码或制品的复验：

- 当时已分离三端认证接受、preflight 与运行结果；新 LKG/floor 先提交，运行失败不复权。Linux/Windows
  持久读写共用文件锁，GUI Preference 不回写旧授权，Linux reader 不自动重写历史格式。
  删除硬编码公网探测回退；无目标/歧义保持 unknown，主动取消不记成业务失败。
- Linux WG 仅清理本进程创建且精确回读的对象，不恢复旧快照或接管未知既存接口；安装失败不自动启动旧 service。
  该内存所有权不能证明 SIGKILL、主进程崩溃、外部 namespace 清理与重启恢复安全。
- 当次 Go 全仓 build/test/vet、相关 race、格式、安全与 diff 检查通过；纯函数阶段另验证规范往返、严格拒绝、
  DNS/IP matcher 及 KDF，所引 `golang.org/x/net` 只用于严格 A-label 校验。这些结果不代表当时已有新普通控制链。
- 当次 Linux Mixed 的隔离 selector、DNS/TLS 名、授权/未授权目标、HUP 和退出检查保存在
  `deploy/evidence/linux-mixed-runtime/`，范围独立于上方本轮正式 CLI 链。
- 当次 Android 使用重建 AAR 完成 31 项 JVM、lint、debug APK 和 mobile Go test/vet；不包括真机或当前最终 APK。
- 当次 Windows 原生 deviceclient 18 项、客户端 15 项与 Machine DPAPI 2 项通过；CurrentUser DPAPI 在 SSH
  会话返回 Access is denied，交互任务没有完成标记。证据在 `deploy/evidence/windows-lkg-runtime/`，只对应当次制品。
  当次 VM 最初的磁盘路径错误实际为测试用户权限，按既有文档修复精确归属与父目录搜索权限后 verify 通过；
  当次结束已正常停机、读回 inactive 并恢复原 ACL/模式。该记录不推定其他时刻的 VM 或生产 service 状态；
  本轮最终 VM 回读见上文，生产服务以本轮正式替换证据为准。

### Linux 显式应用的隔离 TUN

同一 `loom client run -capture tun` 现在创建专用网络与挂载空间；应用从
`loom client exec -- <command>` 进入。监督进程、私有控制通道及 hybrid 服务监听留在原 underlay，
同一认证 View 派生 access 与 server 配置，不增加持久权威。宿主不增加 veth、路由或防火墙规则，
初始网络空间的 TUN worker 与未隔离的挂载空间均拒绝启动。

本轮验证曾发现数据面通过宿主系统总线改写解析服务，影响开发宿主及测试来宾。已停止相关执行，
按原配置提供者及精确受影响值恢复，并删除数据面自动 `resolvectl` 路径、隔离宿主控制套接字。
详见[事故与恢复记录](incidents/2026-10-06-isolated-tun-host-dns.md)。修正后重新执行全部相关业务与
网络回读，不沿用修正前仅检查 resolver 文件的结论。数据面制品坐标前移；schema 3、既有签名原字节
和接受代保持，不重写已签开发制品。

正式 CLI 已完成真实 DNS/HTTPS、hybrid 服务监听、正常停止、监督进程/数据面/服务数据面/应用执行者
异常退出、完整应用树清理、撤权及恢复。每次比较宿主逐接口 DNS、域、默认 DNS 路由与 resolver 文件；
新 SSH、LAN DNS、默认公网及既有代理也已回读。Go 全仓 build/test/vet、格式与仓库安全检查通过。

同机 Linux 来宾通过签名开发包的正常安装入口完成自定义路径、同邀请重试、Hy2 HTTPS、私有签名报告、
异常重启、撤权后重启仍拒绝、重新授权及整机重启。整机重启后原身份与接受代相同，systemd 自动运行，
实际进程使用原自定义路径，HTTPS 与新报告通过；正常停止关闭 capture。各阶段来宾路由与解析服务
保持基线。重启驱动曾错误等待 QEMU 退出，原失败记录保留；改按来宾启动 ID 和真实业务回读后通过。

干净源码 `8eac4509` 的双架构 Linux 正式签名包及 catalog 已由原 `.env` 引用的 YAML 发布至全部目标，
目标端独立验签、公开 HTTPS 正文字节和 current 条件推进均已回读。只传缺失制品，未变化的 Android、
Windows 制品复用；运行节点只接收必要 Linux 包。同机来宾保留原身份前向升级至该精确包，再次完成
隔离 TUN → Hy2 → HTTPS、私有报告、整机重启自动恢复与正常停止，路由及解析服务保持基线。

全部获准 Linux 节点已激活该程序与审核数据面 `1.11.4-loom.4`，生产保留既有 Mixed capture。
正式认证 CLI 写入精确组件期望，全部 control 的真实 mTLS 浏览器读回实际签名组件匹配；control 重启后
再次核对原始报告保全、成员间历史补齐、指定境外出口及 Auto 的实际 HTTPS。首次浏览器加载超时的
失败记录保留，复查及重启后的页面验收通过，不推定原超时原因。各节点原身份、密钥、认证原件及
floor/latch 保持；新 SSH、LAN DNS、默认公网和既有 WireGuard 代理均通过。逐一核对摘要、路径与
进程退出后删除被替代程序，测试来宾最终停止服务并关机。

证据保存在受保护的 `deploy/evidence/2026-10-06-tun-capture/`，最终结果为 `closure-result.json`。
上述首轮 TUN 业务使用字面资源地址，具名资源的后续修正与复验见下文；其余传输、生产旧发布 floor
前向消费及实体机网络变化仍不在已通过范围。驱动对本程序自有 WG 接口编号及来宾等权 IPv6 下一跳顺序的过严比较已修正，原失败和
原始回读保留；未通过修改网络满足比较。

此次正式切换前的只读检查再次发现一个旧制品 control 在持续运行期间被原内存上限终止。现场历史副本
在同一限制下复现：打开后合并完整集合时 OOM。此前并发读取缓存修复没有消除集合编码/解码的整树临时
内存。现在集合逐份严格编解码，原文件格式和容量拒绝边界保持；
同一副本在原限制下完成打开、合并和重新打开，全部原始报告字节保留。针对当前集合的规范等价及非规范
拒绝检查通过。该修正包含在上述正式制品中；全部 control 已在原内存限制下完成成员历史补齐、浏览器、
重启及业务回读，观察期间没有新 OOM。集合仍受现行容量边界限制，此结果不宣称无限历史或未来规模均可承载。

后续具名资源专项复验在同一正式包及原来宾身份上确认：认证 View 接受成功，但隔离 TUN 在启动前把
Hy2 拨号名称当作字面 IP 拒绝。旧资源路由排除检查未随独立 underlay socket 实现清理，是实际代码缺口。
现已删除这处不再需要的资源地址排除，认证 DNS 和传输仍在固定 underlay，未修改身份、TLS 或授权。
定向回归先复现拒绝，再验证具名资源及认证参数完整保留、缺解析器拒绝。源码 `1d56f2cc` 已提交推送，
完整构建、测试、静态及安全检查通过，正式 CLI 的隔离生命周期重新通过。

该源码的双架构签名包已构建；原同机来宾通过正式安装入口保留身份前向升级，实际进程摘要及接受代匹配。
已观察到具名资源向认证解析器的实际查询，隔离 TUN → 具名 Hy2 → HTTPS、私有签名报告、服务重启、
整机重启自动恢复和正常停止均通过；路由、策略规则和逐接口解析状态保持基线。来宾最终停服并关机。
本次仅影响 TUN 路径，生产 Mixed 服务无须重启或改期望，六个节点已重新读回原精确制品仍在运行。
全部 YAML 发布目标均已独立验签、条件推进和最终读回，认证公开下载地址的全部制品正文核验通过；
各目标只发送缺失文件，其余平台制品复用。全部 control 的真实 mTLS 浏览器已显示新 Linux 包，私有
页面下载的实际字节与签名制品相符，既有运行组件期望保持。另经来宾正常启动后的只读检查确认
被替代包的程序已删除，原 claim、设备公开身份及认证 latch 相同，接受代前移。临时浏览器凭据已清理。
证据在 `deploy/evidence/2026-10-06-tun-named/`，首次失败原件留在前述 TUN 证据目录。

## 当前交付对账

当前结果以[产品交付功能对账](delivery-audit.md)为统一清单，按设计入口使用场景区分：
已完成且有证据、已确认的软件缺口、已实现但缺必要验收、外部条件缺失、用户负责的实体机终验。
每项保留正式入口、实现依据、最新验收范围、具体缺项和完成条件。这里原有的累计 open 表已被替换，
避免把较新已验收的网站管理页面、三端 LAN 软件、成员证明、首跳采样、查询调度等重新列为未实现。
下文和上文的各次实施记录仍保留当时结果及失败范围；它们不决定当前分类。

最新交接证据为 `deploy/evidence/2026-10-11-private-io/result.json`。六 Linux 客户端第 100 代
不代表 control、Android、Windows 或数据面在同轮升级；这些组件按各自原件及运行证据核对。
当前远端只读检查另存 `deploy/evidence/2026-10-12-delivery-audit/`，历史证据不冒充即时状态。
对账结束后继续 Events 完整查询链；Hy2 吞吐真实输入和签名目录前向消费分别保持具体软件缺项。
生产网站根/原 CSR 签回叶、指定生产 LAN 参数、多指标排序目标及实体机终验各自单列，
不再用“完整服务授权整体 open”掩盖已完成结果或作为其他独立交付的前置条件。

## 后续连续推进边界

1. 当前生产普通控制链已替换旧 Raft/QC 权威；维持受保护前向映射及精确制品证据，不恢复旧协议作为 fallback。
2. 继续沿同一 Service/Policy 授权业务补实际平台与服务节点消费，按新增风险做必要验证；动态成员继续
   使用已验证的多数证书和原始票史，不增加治理模式、重复 store 或另一版本。
3. Linux 初始 netns 不能运行 access TUN。显式 Mixed、精确所有权的 WG 与显式应用的隔离 TUN 已通过各自
   回读；未实测网络变化仍须按[事故门禁](incidents/2026-09-21-host-network-takeover.md)验证。
4. 管理页面、配置接受、运行、业务观测和发布应用分别回读；未完成的指标保持缺项可见；观测时效按上文逐层核对，不能扩大为全局健康。
   LAN、Hy2、发布和原型的全部场景不作为简单 Direct 链前置，也不能因该链通过就称它们完成。

## 文档与原型审查记录

本节承接原型说明中的历史检查结果，不把旧记录改成此次复验。原型目标与当前差距仍见
[目标原型与实现对照](clients/prototype-review.md)。

### 既有 Windows 视觉记录

以下沿用此前记录，原记录未单列执行日期；此次未重做原生录制或 VM 验收。

此前记录的标题栏图标修复通过调整 `favicon.svg` 取景和资源栅格化消除了下缘裁切；当时由原生渲染器
重新录制八张 PNG，每张与旧基准仅在标题栏图标区域有 338 个像素变化，侧栏图标没有变化。

此前原型调整记录已完成八张 SVG 的 XML、原有场景文案、控件几何、重复生成和文字重叠核对，并检查了 1×、1.5×、2× 渲染。
展开详情与底部视图统一采用右侧主区滚动，侧栏和标题栏固定。这些检查只验证原型，不能替代原生内容或 DWM 验收。

此前在同机 Windows 11 VM 的交互 RDP 桌面捕获了三档 DWM 合成窗口，`GetDpiForWindow` 分别实读
96、144、192 DPI。96 与 192 DPI 截图可见较小的外角弧度，144 DPI 截图左上角接近直角；三档均未达到
SVG 表达的 10 DIP 目标圆角。截图保存在被忽略的
`deploy/evidence/ui-prototype-rebuild/rdp-window-{96,144,192}.png`。这些单帧只证明各自 RDP 会话中的合成结果，
不抵扣实体显示器、跨屏移动或长期窗口行为的验收。当前源码已设置圆角偏好和非合成回退 region；
`WM_PRINT` 只核对内容，不能用它的方角判断 DWM 外框。后续 Windows 产品实现须修复并再次回读外角差距，
不能改写原生内容基准掩盖它。该次原型视觉调整没有重新执行这些 VM 或原生像素验收。

### 2026-10-02 原型检查

此前修订以 Git 中原有的 `misaka-v1` 图稿作视觉参照，调整 Web 拓扑、按 Service 的路径详情和签名事实页。

当日复核已在 Chrome 检查 Android 的加入错误和诊断两稿，Web 的 LAN 创建、冲突对比/确认、
脚本交付及路径导航。路径从失败、未知、WG、Direct 与 LAN 未确认筛选进入详情，切换页签再返回及前进/后退，
均保留来源服务与筛选。脚本显示与复制的换行一致；合成安装器仅在下载及摘要成功后执行，下载失败、摘要错误与
安装失败分别保留失败结果并清理本次临时目录，Invite 只在标准输入中交付。此项检查使用本地替身，不访问公网或启动业务。
32 张 Web SVG 再次生成的字节保持一致；SVG XML、唯一 ID、链接、生成器语法、仓库安全检查及 diff 格式检查通过。

### 2026-10-03 文档与原型审查修订

按用户确认的清单，统一设计入口、原型说明、视觉审查及两端 README 的目标与证据关系；原型场景表
区分正常流程、异常状态和历史实现对照，并允许暂无原生截图。Web 视觉规格集中到原型说明，字段来源、
操作及状态语义继续由 Web 投影模型负责。旧检查记录移入本节，保留原日期、范围和证据限制。

Windows 目标稿由八张变为九张：新增首次列表空态，补 `join-empty` 异常来源，侧栏导入失败与主体一致，
展开路径区分业务目标/采样/有效期和 selector 回读。Android 目标稿由九张变为十张：运行失败稿保留
已保存认证配置并显示 VPN 启动失败；新增 VPN 仍连接、单个业务目标失败而另一服务未知的状态稿；
配置就绪稿明确认证配置已保存。原生 PNG 仍分别为 Windows 八张、Android 九张，未更新。

选路模型列明多目标归约、指标优先级和平局规则的待决问题；统一契约对照字段缺项与受影响行为；
管理员文档集中签发者、验链锚、多 control 补发能力及 SSH 回环网站 TLS 四项未决边界。没有新增
算法、编码格式、证书方案或协议版本，也没有用原型样例补造规范字段。

已检查所改文档的本地链接与章节锚点、十九张客户端 SVG 的 XML 与唯一 ID、Windows 生成器语法及
九张目标 SVG 重复生成的字节一致性；新增和修改的七张客户端稿已渲染并逐图复看。仓库安全与 diff
格式检查通过。现有三十二张 Web SVG、两张已修订 Android 加入错误/诊断稿和十七张原生 PNG 的
文件摘要保持不变。预览输出位于被忽略的 `out/doc-prototype-review-confirmed/`。
本次未修改业务源码、测试代码或原生基准，未执行业务构建/测试、原生录制、VM 或生产验收。

### 普通 `.loom` DNS 原生与生产验证

普通 DNS 记录已接入现行 schema 3 的 `dns_record.put/delete`、Material 持久与重启恢复、管理 Web 和
可选非空 DeviceView 投影。原空集合与缺席字段的签名字节保持；并发同名不选赢家，相关设备解析关闭，
管理页可见并可删除或改名恢复。记录变更只改变相关 Service 的候选规格摘要，权限和候选身份保持。

数据面进程内执行精确记录，不增加服务或修改宿主解析器。实际 UDP/TCP、A/AAAA、未知名称、删除与
重启，以及显式代理业务已通过；正式 Linux 隔离 TUN CLI 已完成 DNS/HTTPS、记录删除后拒绝、恢复、
正常停止和宿主逐接口 DNS 保持。实际 Chrome 的普通记录创建、保留名拒绝、重启读回及删除通过。
Go 全仓构建、测试与 vet、格式及仓库安全检查通过。四架构数据面构建和 Windows 两架构代码构建已验证。

同一代码已经构建 Linux 双架构包、Android 正式签名 APK、Windows 双架构三种应用形态及数据面包，
经签名目录向全部配置目标正式发布；仅传送目标缺少的必要不可变文件，公开制品正文逐项回读。
既有生产节点已激活精确新程序，原身份、密钥、认证 floor/latch、服务配置、宿主路由/规则及逐接口 DNS
保持；生产继续使用原 Mixed 入口。实际境外出口与 Auto 国际业务通过并恢复原偏好。

Linux 同一测试来宾按正式签名入口升级，隔离 TUN 的解析、业务、进程及整机重启和正常停止通过。
Android 隔离模拟器完成正式导入、私有加入、VPN、认证域名到 Hy2 HTTPS、撤权/再授权及重启报告。
Windows 本轮完成数据面原生测试和 Installed MSI/UI 的实际 TUN、域名 Hy2 HTTPS、报告、进程/控制
重启及停止恢复；MSI 升级保持原 DPAPI 配置字节。本轮不把 Installed UI 结果记作三种形态全部重验，
此前三形态结果仍是此前制品的证据。ARM64、真实睡眠、物理切网和显示硬件仍由用户实体终验。

生产实际 mTLS 浏览器创建普通记录；获准生产节点的 View 与运行配置取得记录，实际解析返回该记录。
只有 DNS 时业务仍被拒；通过正式 Service/Policy 和设备选择授权后，真实代理业务成功。control 重启
后原记录恢复；浏览器删除记录而保留授权后，各节点撤去记录、解析返回 NXDOMAIN、业务停止。
最后从正式入口撤销测试授权并删除测试 Service/Policy；原设备名称、职责、策略、分发配置及 DNS 保持。
签名删除历史保留，临时业务进程与浏览器凭据已移除。验收脚本曾错误假设候选必须有 available 探测、
重复使用已删除的稳定 ID，以及把治理职责放进普通设备授权；已按现行入口修正脚本，没有修改产品语义。

全部 control 的真实管理员浏览器已回读本次签名目录，私有下载的每个制品正文均与目录摘要及长度相符。
生产节点的 agent/数据面期望经正常设备页面更新，与实际进程的签名报告一致；全部 control 重启后再次
完成浏览器回读、原始历史保全和正确出口的实际业务。经核对归属、旧程序摘要及没有进程仍执行后，
各节点对应的旧程序目录已删除；最终读回原身份、认证原件、单调 floor、高水位、服务配置及宿主网络保持。
此处保全已有 floor，不声称尚未实现的旧发布 floor 前向自动消费已完成。汇总证据为受保护目录中的
`ordinary-dns-closure.json`；实际更新只分发必要的缺失不可变文件，未分发源码仓库。

### 网站 CSR 的正式命令与现网待签材料

`control website request` 已在各承载 control 生成独立叶私钥及成员签名的公开请求；相同入口代重试
读回原字节。`control website verify-request` 使用独立可信网络锚、当前成员配置和预期节点/入口核验，
标准 PKCS10 导出经独立验签。正式 CLI 测试及现网各 control 的生成、重试、取回和核验均通过。
私钥留在承载 control，远端临时工具及临时交付目录已清理，原身份、控制事实及服务保持；没有创建或导入网站根私钥。

`control website verify-certificate` 已核验独立指定根的 critical 名称约束和全部 IP 排除、叶用途/名称、
原 CSR 公钥与当前有效期；标准签发工具生成的测试链经正式 CLI 和独立验链通过，错根及多根输入拒绝。
解析器未投影的额外 SAN 也拒绝。此命令不写权威状态或系统信任，不代表生产证书已签回或浏览器已信任。

### 公开网站根的规范交付与隔离验证

`public_trust` 的非空规范值、普通签名增删、持久重启及可选 DeviceView 投影已接通；空初值和原已签 View
的缺席字段字节保持。根证书摘要固定身份，未知用途、无约束根及非规范字节拒绝，并发撤销和显式重新授权
复用原事实规则。网站根不会进入 Service 权限或替代数据面 TLS 信任。

真实 Chrome 已通过 Settings 上传公开 PEM、下载同一证书、daemon 重启回读及删除。独立正式 daemon/CLI
流程完成私有加入、认证配置刷新、`client website-root` 导出原 DER、重启恢复与撤销后拒绝导出；设备身份
和 latch 保持，未修改系统信任。此段只证明隔离程序链；网站根交付的新制品尚未在生产激活，生产未写入测试根。

`control.loom` 的生产网站根交付、叶签回和激活、同名续签轮换及生产浏览器验收仍未完成。
离线签发环境和公开根材料尚待操作者提供；
这项外部输入不代表其余程序已经完成，也不据此关闭 DNS 业务项。
受保护过程证据在 `deploy/evidence/2026-10-06-dns-overlay/`。代码继续使用 schema 3，数据面制品修订
不增加控制协议号。原生与生产运行制品对应普通 DNS 实现提交；CSR 工具另有精确源码及程序摘要证据。


### 网站入口绑定与同端口 SNI 的隔离闭环

新网站入口用同一 schema 3 的可选 `website_trust_id` 绑定公开根；原非网站入口字节不变。
正式输入安装和 prepared/serving 写入核对当前根、原成员签名 CSR、本机原叶私钥与签回叶。
撤根关闭网站会话，仍允许 draining/retired。相同 listener 可按不同 SNI 使用不同证书；
新 prepared 的同名异证书不能替换既有 serving 证书。握手实际使用的证书身份保持到后续认证。

独立 daemon/CLI 已完成真实 CSR、离线测试签回、执行输入安装、prepared/serving、同端口设备加入与刷新；
真实 mTLS Chrome 经 `control.loom` 打开管理页并使用原 DNS 表单提交写入，daemon 重启后回读保持；
撤根关闭网站，设备通道继续刷新，网站随后正式退休。测试浏览器只使用进程内名称覆盖，不抵扣客户端
DNS 接线或生产入口。完整 Go build/test/vet 与相关并发检查通过。

Linux Chrome 和同机 Windows Edge 另以同一组叶证书作受限根/无约束根对照：前者只接受
`control.loom`，后者接受全部测试名称，证实 DNS 越界和 IP 证书确由约束拒绝。未使用忽略证书错误参数。
测试公钥根与临时浏览器配置已清理，Windows 原有用户/机器信任库回读保持；VM 正常停机且宿主目录权限恢复。
这些签发密钥仅为隔离测试材料，未进入生产 control，也不代表操作者生产签回已经完成。


### 保留网站名称的客户端消费与到期回读

同一 schema 3 DeviceView 的可选 `web_endpoints` 只投影当前成员持有、根仍授权、端口一致的 serving
网站入口。已知端口冲突拒绝写入，并发冲突停发保留名称并由管理页面解释；设备认证入口不改变。
客户端在捕获前通过认证 DNS 和平台 underlay socket 解析地址，同一组真实地址形成静态答案与精确
TUN 排除。代理仅增加 `control.loom` 的指定 TCP 端口；普通 Service 权限不扩大。

Linux 正式 daemon/CLI 与 Chrome 已在专用 namespace 中完成加入、公开根从已认证 View 导出、
真实 Mixed 解析、mTLS 页面及表单写入、重启恢复和撤根失效；没有浏览器名称覆盖。隔离 TUN
的正式 `client exec` 完成真实 DNS 查询及经其显式代理的认证管理请求。原身份与 latch 保持。
实际浏览器先断开暴露的 TLS 关闭通知错误已修正：核对准确底层 socket 已关闭后才释放句柄，
真正关闭失败仍保留失败结果。并发测试覆盖两种情况。

管理页面和 `control inspect` 现在按调用方时间显示本机叶与根的有效期，提前 30 天提醒；未知材料
及其他承载者分别说明，诊断不改变事实或宣称可达。

正式 Android 签名包已在隔离模拟器中通过系统 VPN 入口，使用真实系统 DNS 解析 `control.loom`，
普通应用 socket 完成名称、受约束根及管理员身份校验；服务撤权和进程重启后网站访问保持，
普通业务仍按自身 Policy 撤权和恢复。首次验收请求漏带非默认 Host 端口的脚本错误已修正；
产品的精确 Host 校验未放宽，也未为测试增加 ALPN 或最低系统版本要求。

同机 Windows VM 的 Installed 正式包已完成 TUN 运行中的真实 DNS、原生 TLS 管理请求、
普通 Hy2 业务、签名组件报告、进程重启和正常停止。启动时的物理网络基线不再与自身刚建立的
TUN 接口作相等比较，避免把自己的 capture 当成外部切网而反复重启；启动前核对及后续切网清理仍保留。
MSI 升级保留原 DPAPI 配置，临时测试材料已清理，VM 正常停机且原宿主目录权限恢复。
control 重启另按原始签名事实及逐条报告摘要核对保全；没有把持续增长的报告集合文件摘要相等当作门禁。
同一正式制品的 Portable TUN 与 Portable Mixed 随后也已通过正常 UI 加入、网站和普通业务、
实际进程与签名组件报告、期望消费、进程重启、control 重启和正常停止后的路由恢复。
TUN 形态从系统 DNS 取得网站真实地址；Mixed 形态通过显式 HTTP proxy 传递网站名称并完成
TLS 与管理员认证，不依赖宿主系统的 `.loom` 解析，也没有创建 TUN。三种形态均未改系统信任库。
这些 x64 VM 结果不抵扣 ARM64 或实体睡眠、切网和显示硬件。

Linux 的上述 Mixed、隔离 TUN 和真实 Chrome 链又以本轮正式签名包执行通过。完整 Go 构建、测试、
静态检查、相关并发测试、Android 运行代码的双 ABI AAR/JVM/lint/正式 APK 构建，以及 Windows
既定交付制品构建均通过。确切程序、源码和每次原生验收范围分别保存在
`deploy/evidence/2026-10-06-dns-overlay/website-release/` 及其相邻的 Linux 验收目录。
这些测试根没有进入生产，也不代表操作者已完成生产根交付或签回。

### 同名网站证书的隔离续签

沿正式 CLI 为同一网站入口生成下一代本机私钥和成员签名 CSR，离线测试根签回后在另一测试地址
prepared 预检。原 serving 地址仍提供原证书，prepared 新代不进入客户端网站候选。新代 serving
后，旧代正式 draining/retired；持续运行的客户端自动消费新 View，真实浏览器使用原信任根
从不变的网站 URL 完成管理写入，control 重启后新代及写入结果保持。

撤根后新代网站连接失败关闭，原设备认证通道仍可刷新，随后新代也正式退休。身份与 latch 保持，
所有网络和浏览器操作均在专用 namespace 内执行。证据在
`deploy/evidence/2026-10-06-dns-overlay/website-renewal-linux-release/`；
最初将临时 DNS 地址误当成 Mixed 配置文件字段的验收脚本失败原件保留，产品代码未为此改动。

生产公开请求另已整理为受保护的离线交付包并重新核验，不含私钥或密码。仍须操作者提供离线网站根
的公开证书及对应签回叶，才能执行生产网站激活；本项保持未完成。

### 网站客户端程序的正式发布与现有服务回读

上述 Linux、Android 和 Windows 制品已通过同一签名发布入口分发到全部 YAML 目标；每个目标
只发送缺失的不可变文件，公开下载正文、发布指针及最终读回均通过。既有节点的运行程序逐台激活：
发布节点直接复用已验签的包，其余节点只接收新的 agent，未变化的数据面全部在节点本地复用。
正式 `.env` 仍只定位原 YAML，输入和原服务单元未改写。

全部 control 的真实 mTLS 浏览器已读回新目录，私有页面实际下载的制品正文与签名摘要相等。
通过正常设备页面提交精确组件期望后，全部 control 均读回与实际进程相符的签名报告；逐台重启
control、保持客户端进程后，页面、期望和原始历史恢复。指定境外最终出口与 Auto 的真实 HTTPS
在重启前后均通过，原 Auto 偏好恢复。新建 SSH、LAN/系统 DNS、默认公网及既有 WireGuard 代理
均通过；身份、密钥、原认证字节、floor/latch、路由/规则和解析配置保持。被替代的旧程序目录已删除，
当前程序指针与清理结果同步到磁盘。

三端执行材料、精确源码/程序对应、分发、激活与回读证据在
`deploy/evidence/2026-10-06-dns-overlay/website-release/`，软件闭环索引为同级
`website-software-closure.json`。该结果不消费旧运行发布 floor，不激活生产网站根或网站入口，
也不关闭动态成员、其他传输/观测、LAN 等仍未实现的业务缺口。生产网站签回及实体机验收仍分别保留。

## 逐 Link 的真实认证观测

原实现已有显式 WG Link 和 Service HTTPS 观测，但 Link 探测没有运行入口，报告解码也拒绝 transport
观测。纯 forward 起点没有 Service/Policy 授权，不能用握手、HTTP 拒绝或虚构服务凭据补出成功。
现行 schema 3 增加仅向 Link 两端交付的派生探测执行值，沿原 RuntimeKey 按用途隔离；接收 listener
只允许认证，所有转发仍拒绝。Linux 从已回读的 WG 接口及精确源地址发起 Hy2 认证，保留 LinkID、
三个引用资源的规范摘要、实际目标、采样时间和结果，经原签名报告持久化并供设备页面回读。
完整认证耗时不是 WG RTT 或 Service 请求时间；未定义全局寿命与时钟规则时，拓扑当前可用性仍 unknown。

定向检查及完整 Go 构建、测试和 vet 已通过。隔离数据面验证探测登录成功、业务转发拒绝、正常 Service
仍可访问、错误 TLS 名称/密码拒绝及撤销后旧凭据失效。正式 CLI fixture 进一步完成普通加入、资源与 Link
写入、反向发起 WG 上的实际认证往返、私有报告、真实 mTLS Chrome 回读、接收端停止后的失败及恢复、
control 重启、原始报告保全、Link 撤销、正常停止和身份保留；初始宿主路由内容、规则及解析配置保持。
浏览器 fixture 的 TLS 坐标和空观测字段断言曾失败，均修正测试驱动后复验，原失败证据保留；未放宽产品门禁。

原 View 缺席字段及原 ACL 编码逐字节保持。同一事实前沿的不同 View 仍被拒绝；升级必须随正常签名事实
进展接受新投影，不能重置 LKG 或高水位。源码 `847dd3f8` 已提交推送，正式签名包已分发并在全部
获准节点激活。分发仅补传缺失的不可变文件，未变化的原生客户端包与数据面复用；节点准备只接收必要
的 agent 或复用已发布包，原 `.env`、YAML、身份、密钥和服务单元保持。

切换时暂停旧 agent 主进程，保留已有 WG 与数据面，先更新 control，再经真实 Web 页面提交精确组件
期望；全部 control 的事实前沿同步且严格超过每台设备原高水位后，逐节点正常清理旧 generation 并启动
新程序。正式服务原有权限足以绑定探测 socket，未增加权限、路由或捕获入口。

全部 control 均保存了有效 Link 的新原始报告；独立验签与当前 Link、两端 WG、目标 Hy2 的规范摘要
逐项相符，真实浏览器回读设备页面的原始样本，私有下载正文与签名目录一致。逐台重启 control 后，
客户端进程保持，新增样本、组件期望及原始历史再次回读。指定境外最终出口和 Auto 的 HTTPS 在重启前后
均通过，原 Auto 偏好恢复。
被替代程序已删除，当前程序指针耐久保存；原认证材料、floor/latch、主机路由/规则、解析配置及服务单元
逐项保全，新建 SSH、LAN/系统 DNS、默认公网和既有 WireGuard 代理通过。

受保护证据位于 `deploy/evidence/2026-10-06-link-observations/`，部署结果见其
`release/production-final-result.json`，完整软件证据索引为 `link-software-closure.json`。
此次精确程序切换仍不消费旧运行发布 floor，也不激活生产网站根。首跳资源观测、流量与 RTT 统计、
多目标归并和选路算法不因此完成，整个服务授权工作项继续保持未完成。

## 公开 Hy2 首跳样本与报告写入

Linux 已沿正式 CLI 加入、授权与资源输入，在当前实际选择需要时并行采集公开 Hy2 首跳认证，
共享资源只执行一次。继续使用已认证 RuntimeProfile 中的原凭据，Resource Observation 绑定
资源、设备、认证 DNS 及所用凭据摘要；不增加探测用户、View 字段或接收端权限。原报告入口
严格核对当前投影，设备页面和 CLI 状态显示资源样本，与完整 Service 请求分开。

隔离环境中的真实 daemon、数据面及 mTLS Chrome 已完成两个 Service 共用首跳、其中一个
HTTPS 成功而另一个失败、原始样本回读、无关 View 更新、同网络代进程重启、control 重启与
原报告保全。真实拨号坐标变更使旧摘要退出，接收端停机产生失败，原窗口到期后恢复，资源
撤销移除探测和缓存；身份与 latch 保持。初期验收脚本的邀请媒介、进程测试信任、HTTP 响应
定界、启动等待和空观测字段错误均保留原证据后修正；另有网络代变化时缓存依法失效的记录，
补采实际输入后同网络代复验通过，没有为验收修改网络代算法或延长样本期限。
共用认证函数的逐 Link 正式链也已重新通过，包括真实 WG、探测凭据不可转发、接收端失败与
恢复、私有报告、浏览器、control 重启及撤销。

同时读回现网发现报告未确认，而原报告仍持续落盘。受保护历史副本确认，写入每次重编码
旧历史并重复验签，造成不必要的串行工作。现已在原解码缓存中保留规范字节范围和已验证公钥，
新写入复制原字节；外部文件变化重解码并清空验证缓存，公钥改变重验签。新报告验签、原高水位、
分叉保全、严格解码、原文件容量及耐久确认保持。真实原报告副本的连续写入测量显著降低耗时；
该副本结果不抵扣现网确认验收。

完整 Go build/test/vet、相关并发检查、格式和仓库安全检查通过。源码 `9e92d06c` 已提交推送，
正式签名目录已沿原 YAML 发布到全部目标；只补传缺失的不可变文件，公开下载正文和发布指针
均回读通过。发布节点复用已验证的包，其余节点只上传新 agent，未变化的数据面在节点本地复用。
全部获准 control、client、relay 和 edge 已激活同一精确程序，原部署输入及服务单元保持。

真实 Web 表单提交组件期望并完成成员同步后，客户端沿原身份接受向前推进的配置。全部 control
均保存并独立验签新的 Link 和公开首跳原始报告，规范摘要与当前授权逐项相符，真实浏览器回读
对应设备的原始样本。首跳只在当前实际选择需要且没有有效样本时采集；已有样本沿用原始窗口，
未使用样本到期退出，不为维持样本数量而扫描资源或刷新时间，资源认证仍不替代完整 Service 请求。

现网报告确认在 control 重启前后均通过持续多轮回读，观察窗口内没有报告失败，原客户端进程保持。
指定境外最终出口和 Auto 的真实 HTTPS 在两轮均通过，原 Auto 偏好恢复。全部原始报告历史保全并
完成成员补齐；身份、密钥、认证原字节、floor/latch、服务单元、宿主路由/规则和解析配置保持。
新建 SSH、LAN/系统 DNS、默认公网及既有 WireGuard 代理通过，被替代程序已删除并完成耐久回读。

受保护证据位于 `deploy/evidence/2026-10-06-resource-observations/`，生产结果见
`release/production-final-result.json`，软件证据索引为 `resource-software-closure.json`。
此次切换仍不消费旧运行发布 floor，也不激活生产网站根。Android 的首跳采样接线、普通 WG
首跳、首跳参与选路、多目标归并及全局新鲜性规则仍未完成，整个服务授权工作项保持未完成。

### Windows 公开首跳采样与正式交付

Windows 沿原实际 selector 回读执行共享公开 Hy2 首跳认证；原签名 DeviceReport 包含资源样本，
Service 的可用性与选择仍独立。可删除的规范缓存绑定原 profile 身份、资源执行摘要及网络代，
恢复时保留原始采样与截止时间，撤权和输入变化失效；没有增加授权、协议号或第二运行状态。

源码 `130de43f` 已提交推送。同机 Windows x64 VM 的 Installed、Portable TUN 和 Portable Mixed
均通过正常 UI 加入、真实 HTTPS、签名报告、无关 View 更新、同网络代重启保留原采样、真实首跳
失败及原窗口到期恢复、撤权后业务拒绝和正常退出。原始报告逐条独立验签，安静停止写入后的
control 重启逐字节保全历史，真实 mTLS 浏览器回读通过；历史 View 不被重新提升为当前证据。
测试驱动的名称、listener 重启和规范输入错误以及持续报告期间的全文件摘要断言失败原件保留，
修正验收驱动后完成复验，没有放宽产品 TLS、解码或新鲜性门禁。MSI 升级保留原 DPAPI 身份。

六份正式签名交付包已发布到全部 YAML 目标，缺失文件补传、既有 Linux/Android/数据面文件复用；
公开正文、正式目录指针和逐目标回读均通过。全部控制端的真实管理浏览器显示同一签名目录，
正常下载入口取得的实际正文与摘要相等。`.env` 和 YAML 未改写，旧运行发布 floor 未消费。
VM 已正常关闭，原宿主目录权限恢复，原磁盘、TPM 和 profile 身份保留。x64 VM 与双架构构建
不抵扣 ARM64、真实睡眠、物理切网或显示硬件终验。

证据在 `deploy/evidence/2026-10-07-windows-resources/`，索引为
`windows-resource-software-closure.json`。这项完成不关闭整个服务授权工作项。

### 持续报告历史容量故障

上述发布期间再次现场回读发现，报告历史达到当前集合文件的容量边界后，新报告不能获得确认；
control 与既有业务运行不能抵扣报告链故障。已将同一 schema 3 原件集合改为逐条事务持久化，
保留全部原字节、高水位和分叉；不扩大单个网络输入边界，不删历史或修改报告频率。
定向与并发测试、现网历史副本的显式迁移及原字节保全已通过；隔离环境的正式 CLI/daemon、真实
首跳与 HTTPS、签名报告、浏览器回读、撤权和重启也通过。

源码 `c90e77cf` 已提交推送，精确制品已沿原 YAML 发布并由全部获准正式服务消费；只传输缺失的
不可变发布文件，其余节点仅补新 agent，未变化的数据面本地复用。control 逐台停服执行显式前向
迁移，原 JSON 字节进入受保护证据，原运行入口删除；迁移期间客户端进程保持，独立回读逐条原件、
高水位和分叉。没有旧容器双读、启动 fallback 或身份重建。

真实 Web 提交组件期望，全部控制端的浏览器回读与实际程序报告一致。链路和公开首跳原始报告独立
验签，管理页面及精确下载正文通过；控制服务重启前后，全部客户端均持续多轮确认报告，观察窗口
没有报告失败。成员历史补齐、原报告保全、指定境外最终出口及 Auto 的实际 HTTPS 均通过，原偏好
恢复。原身份、密钥、认证原字节、floor/latch、服务单元及宿主基础网络保持，被替代程序已删除。

证据位于 `deploy/evidence/2026-10-07-report-storage/`，结果为
`release/production-final-result.json`，索引为 `report-storage-software-closure.json`。
移动端独立 Go 模块遗漏的共享依赖记录也已修正并测试；此项不改变已部署 Linux 制品。
此次报告故障闭环不抵扣其余平台接线、选路算法或整个服务授权工作项。

### Android 公开首跳采样接线

Android 已接入共享公开 Hy2 认证采样与规范缓存，沿原 selector 回读、Keystore profile 槽和
私有签名报告执行；资源样本与 Service 结果分别保留。共享核心的实际 QUIC/TLS 与 socket
protect、无关刷新保留原窗口、网络代失效、原失败窗口及到期恢复、撤权和签名报告检查通过，
并发检查及双架构 AAR 构建通过。源码 `813b6af7` 的正式签名 APK 已经隔离模拟器正常导入与
VPN 入口完成实际 HTTPS、原窗口复用、同网络代重启、真实失败/恢复、撤权和停止报告；原始
签名独立验证、控制重启保全及 mTLS 浏览器回读通过。测试等待与恢复操作错误的原件保留，
没有重建身份、修改样本期限或报告频率。模拟器正常关闭，原磁盘和 profile 保留。

正式制品已发布到全部 YAML 目标，缺失文件补传、既有文件复用，公开正文及目录指针回读通过。
首次私有浏览器下载在远端持续接收 APK 时被整响应写入期限截断，原失败和实际网络诊断保留。
服务端修正后，同一份 APK 沿三台 control 的正式私有浏览器入口完成整包、原清单和签名下载，
逐项摘要相等，没有重建或替换 APK。原应用发布代继续保留在新的已签名目录中。
受保护证据位于 `deploy/evidence/2026-10-07-android-resources/`，完整索引为
`android-resource-software-closure.json`。本项软件接线和正式交付已完成；实体终验由用户执行，
整个服务授权工作项仍未完成。

### 有效前沿之外的签名分叉原件

两个 control 已各自保存同键同序列异值时，原前沿同步会停在相同的较低位置，却没有交换各自
持有的其他分叉原件。真实成员 TLS 测试已复现；现沿原私有成员入口补稀疏冲突 ID 分页，只取
缺失原件，再按原规则验签、耐久保存并补声明依赖。原 Material 字节、schema、签发禁用和投影
收口保持，没有第二份持久集合、完成状态或旧协议 fallback。

双方相同前沿、离线正常副本发现分叉、中途失败保全及缺失补传、分页、严格输入拒绝和重启检查
通过，无关键继续同步；全仓 build/test/vet、格式、安全和定向并发检查通过。隔离环境的正式
CLI、两个 daemon、成员 TLS、原客户端 Mixed HTTPS、私有报告和控制重启也已通过。
源码 `c13b8f4a` 包含此修正与下面的私有下载修正，已提交推送。精确签名制品发布到全部 YAML
目标并激活所有获准 control、client、relay 和 edge；仅补传缺失文件，原数据面与未改变的平台
制品复用。真实 Web 提交组件期望，所有控制端回读实际进程的签名报告，原事实保全且新事实收敛。

控制服务重启前后，全部客户端均持续多轮获得报告确认，指定境外最终出口与 Auto 的实际 HTTPS
通过，原偏好恢复；正式私有浏览器取得两种 Linux 包及原清单/签名，正文摘要相等。原身份、
密钥、认证字节、floor/latch、服务单元和宿主基础网络保持，被替代程序经所有权核对后删除。
生产没有人为制造签名分叉；分叉故障与恢复由同一精确程序在隔离环境的正式成员链验证。
受保护证据位于 `deploy/evidence/2026-10-07-material-conflicts/`，部署结果为
`release/production-final-result.json`，完整索引为 `material-conflicts-software-closure.json`。
本项完成不关闭整个服务授权工作项。

### 私有制品下载的连续传输

Android 的私有浏览器下载实际取得成功响应和部分正文后，被整响应写入期限截断，浏览器报告
正文长度不符；同一 APK 的公开完整下载已通过。真实 HTTP 测试复现原行为，修正后每块写入
重新设置原写入等待期限，持续传输可跨过原总期限，停止接收仍超时退出。经验证的内存制品
原本会一次写完整包，现显式使用分块复制，使上述期限实际按块生效。其他 API 超时、签名和
下载字节不变，未增加配置、平台制品或另一条下载入口。

全仓及定向并发检查通过，源码 `c13b8f4a` 已提交推送并由全部获准正式服务消费。同一 APK
在三台 control 的实际私有浏览器完整下载，原清单、签名与正文摘要逐项一致；上述 Linux 下载、
报告和重启业务也通过。原截断证据、持续写入和停止接收的真实 HTTP 测试与生产复验保存在
`deploy/evidence/2026-10-07-release-download/`，索引为 `release-download-software-closure.json`。
没有延长普通 API 的总超时或改变客户端报告频率。

### 动态 control 成员与设备认证证明

本项以旧成员多数签名决定成员变化，普通职责继续走现有事实链；新 control 使用原 claim 已证明的
设备公钥，现存 genesis 成员的治理键与设备键保持。schema 3 未升级，源码与三端有效页面保留。
获准部署和本节的软件业务结果已完成回读；其他未完成项继续推进。

- 正式 CLI 与管理页面支持增员、卸任、撤销、整体删除、换键及已绑定加入事务作废；同轮承诺、
  完整票史、原始证书和封笔均耐久保存。重启从这些原件恢复，不增加请求状态数据库。
  已选值按完整票史继承，不能把不同轮次合票；双投证据保全后停止成员写入，冲突多数证书停止权威写入。
- 新成员沿原私有加入入口绑定身份，再取得原始事实并初始化空 control 目录；纯 control 仍维持认证配置
  与报告，不以虚构普通授权或数据面运行表示成功。后续普通职责首次授予、撤销与重新授予保持原身份与根密钥。
- 失格键封存后，原始事实与已认证高水位保留。已有超限撤权必须由留任键有效替代后才交付更宽 View；
  已封笔留任者可经原成员通道补取有效替代事实。丢失换键通知的旧身份只能取得成员证明，不能继续读取普通秘密。
- Linux、Android 与 Windows 的可能复权提示由认证高水位和当前封存证明推导；替换 LKG 前比较可见变化，
  不新增确认状态或第二份 LKG。Android 保护存储重启与配置隔离、Windows DPAPI 及三种形态原生窗口均已回读。
- 精确发布程序通过正式邀请、claim、加入、独立 daemon 签发/同步、纯 control 运行报告和重启恢复；
  真实浏览器完成多数成员变更与纯 control 普通职责授予/撤销/再授予。TLS 场景覆盖失联通知、封笔留任、
  缺少加入原件时的冲突证书保全和重启拒绝。完整构建、测试、vet、竞态、格式及仓库安全检查通过。
- 正式切换中发现共享程序已更新、旧客户端仍写旧临时状态时，control 的启动检查会拒绝缺字段的状态。
  现按客户端先于 control 启动，让客户端沿正常入口重建自己的可删除状态投影；不改认证原件、unit
  或增加旧格式回退。首次失败与原身份恢复证据保留。
- 三端同一源码的签名制品完成发布审查。正式 Android APK 在保留 Keystore 的模拟器覆盖安装，Windows
  正式 MSI 升级和两种便携程序回读原有 DPAPI 配置。测试虚拟机与模拟器正常退出，磁盘、TPM 和配置保留。

全部获准节点已激活同一精确程序；每个 control 的认证成员页与组件报告、原始事实同步、持续签名报告、
预期境外出口及 Auto HTTPS、重启恢复均通过。原身份、原始认证字节、floor、高水位、unit 和宿主网络保持；
只分发缺失的公开制品，节点复用原数据面，被替代的程序目录已在完成业务回读后删除。
生产不执行为了测试而撤销或重新加入既有成员；成员变化的正式业务链在独立同机环境使用相同制品验证。
实体机终验仍由用户完成。真实坐标与原始回执只保存在 deploy/evidence/2026-10-07-control-members/。

### 客户端模式的签名只读回读

此前客户端已保存 Direct、Auto 和指定出口，但报告不携带该设置，Web 只能显示未报告。本轮沿原
schema 3 Report 增加可选 preference，复用原签名、存储和成员同步；本机 Preference 仍是唯一设置
来源。偏好与实际 selector 分别展示，保留原报告时间；停止、执行失败、指定出口暂不可用均不抹去
已保存设置。缺席字段仍是未报告，不从实际候选推断 Auto，也不修改历史签名字节。

Linux、Android 和 Windows 已接入现有报告发送链。规范拒绝、签名绑定、历史字节保全、成员同步和
重启回读检查通过；实际私有浏览器验证三种模式和实际选择分别显示。Windows 同机 VM 验证三种
形态的正式设置入口、原 DPAPI 存储重开及签名报告。Android 保留原 Keystore 和设备身份，通过
配置刷新、实际 VPN、UI 切换三种模式、停止、进程重启及恢复 Auto，控制端独立验签并回读原报告；
控制端重启保持全部原件。Android 验收中恢复了模拟器内部原虚拟 Wi-Fi 连接，未清空应用数据。

全仓 build/test/vet、相关竞态、移动模块、Android unit/lint 和 Windows 两架构构建通过。
软件与原生制品记录位于 deploy/evidence/2026-10-07-reported-preference/，正式部署结果见下文。
实体机终验由用户完成，其他未完成项保持 open。

同一源码的第 59 代三端签名制品和目录已生成并独立验证。Windows 正式 MSI 与两种便携制品完成
原生升级、原 DPAPI 配置保留、窗口及程序坐标回读。Android 正式 APK 覆盖安装后重复上述业务链，
每份报告中的实际 APK 摘要和源码坐标匹配签名清单。测试程序按 release 编译，并先读回保留的系统
VPN 状态，避免在连接已自动恢复时点击开关将其停止；正式 APK 不因测试修正而改变。

第 59 代制品首次发布并激活全部获准 Linux 服务后，组件期望与原始事实同步、持续设备报告通过。
生产 Direct 国内业务及指定境外出口业务在所有 control 的正常浏览器回读通过；Auto 业务请求
成功，但一个 control 的模式回读持续落后，该次整轮验收失败，当时保留旧程序并继续前向修复。

现场只读诊断确认新报告能经成员认证取得；报告库副本的首次历史验签较慢。进一步采样发现，
已经关闭的 Web 页面仍持续重建快照并读取发布包：原 WebSocket 只在投影变化时写入，静止时
没有读取关闭帧或 EOF。正常关闭及连接中断均由回归测试复现，现由原连接的读取取消终止计算；
管理员过期及撤权语义保持。发布解析缓存命中后的完整字节核验改为固定缓冲的流式摘要，仍拒绝
同长度篡改、保留 mtime 的修改、截断和追加，不信任文件元数据或缓存代替正文。真实签名包的
缓存重建、损坏拒绝及有界分配验证通过。没有修改报告签名、原件容器、采样频率、业务目标或
schema，也不把该修正写成历史报告冷验签的优化。

源码 `c86dc30c` 的 Linux 修复程序已进入第 60 代签名目录并激活全部获准正式服务。Android 与
Windows 继续使用源码 `93ff0653` 的已验收精确制品；本次修正没有改变两端的程序或原生库。
全部 YAML 分发目标只补传缺失文件，复用原不可变制品，并分别完成完整 HTTPS 正文校验、
条件切换和落盘读回。原 `.env`、私有输入与数据面程序保留。

Linux 正式 CLI 分别保存 Direct、指定境外出口与 Auto 后，运行时实际完成国内或对应国际 HTTPS
业务，全部 control 的正常认证浏览器回读到对应签名偏好与实际选择；两者分别显示。控制服务
重启前后重复同一完整业务链，原 Auto 设置恢复，持续的新报告确认、组件期望及实际版本、
发布目录和原始事实同步均通过。实体机之外的本项软件与获准部署业务结果已完成。

两轮被替代的程序目录已逐项核对并删除，现网身份、密钥、已认证原始字节、高水位、floor、
unit 和解析器保持。新建 SSH、LAN/系统 DNS、原 WireGuard HTTP proxy 与默认公网 HTTPS
均通过最终回读。本轮不消费旧运行发布 floor、不激活生产网站根，完整服务授权工作项仍未关闭。
部署证据位于 `deploy/evidence/2026-10-07-control-read-cost/release/`，结果索引为
`production-final-result.json`；首次失败、修复前后的关闭连接回归及精确原生制品证据继续保留。

### 共享 WG 资源的多对端执行

用户已明确允许普通客户端 WG 首跳依赖接收节点同机 Hy2。本节先修复其执行基础：原 Linux
投影把共享接口的第二个 peer 视为冲突；现在按接口归组，独立保留每个 peer 的公钥、精确地址、
方向和端点，相反业务方向的重复 peer 去重。同一接口只创建和清理一次；原单对端清理记录
字节不变，多对端仍使用原所有权记录，不增加权威参与者表。跨接口的相同远端公钥分别回读，
同接口重复或异值继续拒绝。此修改没有改变原资源、Link、候选或签名字节。

隔离网络与挂载 namespace 中，两个真实 TCP/UDP 对端共用同一内核接口，混合建连方向、
重启清理、外来 peer 拒绝及单 peer 撤销通过。正式 CLI 另完成两台设备的加入、策略与资源/
Link 写入、共享接口上的 HTTPS、私有签名报告、control 与客户端重启、原报告独立验签和保全。
删除一条 Link 后，旧路径拒绝，接收端只保留另一个 peer，剩余设备的 HTTPS 无干预恢复。
接口与 Hy2 会话重建期间确有请求失败，原失败和恢复采样均保留；此结果不承诺无中断切换。

源码 `8defe09e` 已提交推送，全仓 build/test/vet、相关竞态、格式及仓库安全检查通过。受保护
证据在 `deploy/evidence/2026-10-07-wg-access/`，正式入口结果为 `formal-shared/result.json`。
该检查点尚未生产激活，当时生产使用第 60 代目录和 `c86dc30c` Linux 程序。后续普通 access
的 WG 首跳、目标边界、三端接线与程序部署结果见下一节，完整服务授权工作项保持 open。

### 普通 WG 首跳的共享接入与目标边界

本节记录已被否决的历史实现与当时验证，不是当前目标或可继续执行的启用方案，见[传输实现纠偏](#传输实现纠偏)。

此前实现将“允许依赖接收节点同机 Hy2”解释为协议嵌套，WG 资源通过可选 `access_hy2_resource_id` 显式引用
该节点已有的普通 Hy2 接入。客户端每个 WG 资源使用一个用户态会话，多个 Service 候选复用；
不为 access 创造 NetworkLink。每设备私钥从原 RuntimeKey 规范派生，接收端只得到与现行
Service/Policy 权限精确对应的公钥。旧字段缺席时规范字节保持不变，schema 仍为 3。

接收端共享接口保留原显式 Link peer，并为普通 peer 投影精确 IPv6 地址。每代独立 nft 表只
允许普通 peer 到同机 Hy2 的 UDP 与返回包；其他本机端口、DNS、转发和 peer 间访问拒绝。
不 flush 共享对象，停止时先核对别名、规则内容和内核 handle，再精确删除本代对象。
普通 peer 增删在接口、过滤和资源不变时原地执行；清理记录先保留新旧 peer 并集，失败和
崩溃只按该并集清理，不能由它恢复授权。新增地址与已有本机地址冲突时在修改前拒绝。

隔离 net/mount namespace 已完成正式 CLI 加入、两台普通 access 共用 WG、真实 HTTPS、
认证报告、control/客户端重启、撤权拒绝及重新授权；未撤权 peer 的接口、别名和 nft handle
在其他 peer 增删时保持。共享 Hy2 重建期间仍存在请求失败，后续新连接恢复，不承诺无中断。
内核测试还执行了真实允许/拒绝流量、外来规则拒绝删除、路由添加失败和 peer 修改后强制退出，
精确清理后的网络基线保持。原显式 WG Link 的共享中继与 Hy2 双栈监听回归通过。

Android 模拟器从正常 UI 导入和 VPN 入口完成 WG→同机 Hy2→HTTPS、撤权、同身份进程重启、
重新授权及界面回读；报告原件独立验签并经 control 重启保持。原 AVD 和 Keystore 保留，
模拟器已正常停止。这是软件原生验证，不替代用户负责的 ARM64、睡眠和物理切网终验。

Windows Mixed 同样完成业务、DPAPI 恢复、撤权和再授权，原报告独立验签并经 control 重启保持。
TUN 验证发现固定数据面在空主机 IPv6 UDP 监听上错误执行 IPv4 网卡绑定，导致 WG 启动后留在
Down。新数据面制品 `1.11.4-loom.6` 仅在 Windows 保留该监听的明确 IPv6 地址族；旧已签制品
摘要保持原义，四个平台的新制品已独立重建为相同字节。TUN 修复后已完成真实 HTTPS、撤权、DPAPI 重启、重新授权及正常清理，
前后路由精确恢复；原报告独立验签并经 control 重启保全。新数据面的 Mixed 全链回归也通过，路由保持不变。
同时修复 UI 持有状态读句柄时阻断原子替换的问题：只对可删除的运行状态使用允许替换的读取
与名字替换，身份、profile 和认证 floor 保持原持久化规则；原生并发读/替换/停止测试通过。

正式 Android APK 已在保留原 AVD 和 Keystore 的模拟器中重复上述完整业务链，实际 agent 与
数据面报告逐项匹配签名 manifest。Windows 正式 Installed MSI 经原安装入口更新后，原 DPAPI
配置保持；正常 UI 加入、SCM 服务中的 WG→Hy2→HTTPS、撤权、服务重启后仍拒绝、再授权恢复、
正常断开和路由恢复通过。报告原件独立验签并经 control 重启保全。测试驱动问题和一次
模拟器系统界面故障保留失败记录，修正驱动或恢复系统界面后继续，未清空设备身份。
模拟器与 Windows VM 均已正常停止，宿主临时目录权限恢复，不抵扣实体机终验。

全部获准 Linux 节点已激活 `e7abc26c` 及同一签名包的数据面，实际进程摘要、既有身份、认证
原字节、floor/latch、原 route/rule、服务定义与 DNS 配置已核对。新建管理连接、LAN/系统 DNS、
原 WG 上的 HTTP proxy 和默认公网 HTTPS 通过。未新增 Loom 防火墙对象；一处既有云安全链自行
更新了拒绝规则及入口 jump handle，其余对象保持，原始差异已保存，没有回写或清空该链。
旧发布校验器因尚未包含新数据面的审阅摘要而拒绝导入，目录指针未推进；先完成上述程序更新，
再由新校验器完成正式发布。第 61 代签名目录已在全部 YAML 目标完成缺失文件分发、完整公开
制品正文校验、条件切换和落盘读回。节点程序仅分发必要可执行文件；发布站点保存本次三端
制品及签名清单。实际传输内容量和可核实的阶段时间另存受保护回执，没有逐步骤计时的部分
不归因为带宽不足；串行分发与反复打开浏览器是本次执行中可见的效率问题。

全部 control 的正常认证浏览器已回读精确目录、期望组件及匹配的签名运行报告；控制服务重启
前后原始事实同步、报告回读和连续新报告通过，原客户端进程保持。重启后的 Direct 境内
HTTPS、指定既定境外出口的国际 HTTPS 和 Auto 均完成真实请求与全部 control 的模式、路径回读。
首次切换模式的验收脚本只等待新偏好便检查实际路径，遇到仍携带上一轮选择的报告而失败；
修正为同时等待偏好与实际路径后，只续验尚未通过的模式，保留首次失败与已经通过的结果。
被替代程序目录已逐项核对路径、摘要和运行进程后删除。最终新建 SSH、LAN/系统 DNS、原 WG
上的 HTTP proxy、默认公网 HTTPS，以及身份、认证原件、floor/latch、route/rule 和解析配置回读通过。
发布与现有业务的结果索引为受保护目录中的 `release/program-and-publication-final.json`。

原有 Direct 的境内 HTTPS、固定既定境外出口的国际 HTTPS 及正常浏览器回读已通过。Auto 曾
选择仍有有效成功样本的路径，后续真实请求已失败；Go 探测与 curl 对照均确认当时失败。保留
原样本直到自然到期后，运行时重新探测并自动选择另一获准路径，真实 HTTPS 恢复。没有删除
观测或修改策略使测试通过；首次失败与自然恢复均留证。这也说明现行成功窗口可能延迟识别
后来失效的路径，不能把样本有效描述为所有后续请求都成功。

普通 WG 的生产接入尚未启用。已为具备现场公网地址、操作者既有入站映射或当前明确确认开放
入口的接收节点准备逐项资源、监听、精确地址路由和独立过滤表清单。操作者已纠正一处仅因 YAML
缺少映射记录而排除节点的部署判断，该节点已纳入清单；操作者确认的基础设施条件与部署后的真实
业务结果分别记录。原 LinkOnly 用途暂时保持，但它不是节点不能承担普通接入的架构限制。
该启用方案现已被操作者明确否决，不再等待授权；签名资源写入、实际消费、生产普通
WG 业务与停止恢复均未执行，本项保持 open，须按独立 WG 的要求替换。受保护的成功与失败原件均保存在
`deploy/evidence/2026-10-07-wg-access/`，不以开发验证或程序已更新替代生产接入完成。

### 独立节点的并行发布

工作指引与配置模型已规定独立节点并行；正式 `loom release publish` 的身份核对、目标准备、
条件切换与最终回读按节点有界并发，认证 HTTPS 根也并行核验。同节点顺序与目标端排他锁保持，
全部身份通过才上传，全部制品正文校验通过才允许推进指针。配置/授权读取和输出分别保护，失败
等待正在执行的操作退出并保留逐目标结果。进度增加单调累计耗时和分发根序号，复用与发送量继续回读。

通道屏障验证实际节点操作重叠、同节点失败停止后续操作，以及错误不会遗留后台工作；竞态检查通过。
既有签名目录覆盖身份不符、错误 HTTPS、部分切换、同目录重试、缺失文件补传和授权变化拒绝，
完整协调回归通过。最初使用全部平台整包反复执行失败场景触及测试时限，失败记录保留；随后用
较小的既有签名目录覆盖相同协调风险，并以当前生产目录完成下述正式调用，未修改签名或放宽验签。

本次精确工作站执行器沿正式 CLI 对现有目录完成全 YAML 目标的幂等发布，所有已有文件经核对复用，
没有新增文件正文上传。准备和 HTTPS 校验区间均有实际重叠记录，全部目标完成最终回读，原目录和
现有服务程序保持。执行器源码及摘要、原始输出、测试结果和入口数量更正存于
`deploy/evidence/2026-10-07-parallel-publish/`。验收驱动最初把存储目标数量当作认证 HTTPS 根数量；
已按真实授权和 CLI 输出更正统计，没有因此重复发布。上一轮传输统计原件及更正依据分别保留。

本轮只构建和执行发布工具，没有重打未改的客户端安装包。完整 HTTPS 正文下载及多次规范归档
重压缩仍有实际耗时，不能把并行改动称为全部性能问题解决。普通 WG 的生产网络启用、尚未完成的
业务功能、网站网页交互和生产签回仍按前述清单保留，整个服务授权工作项未关闭。

## 网站证书的管理页面接线

现有 CLI 证书流程已接入 Settings：生成和下载原绑定请求、导入公开签回叶或精确授权链、安装本机输入、
提交 prepared、经原实际 TLS 预检后 serving，以及独立停用和排空退休。新增页面沿原证书、入口事实和
本机文件执行，没有续签任务 store 或新协议；私钥仍留在原 CSR 目录，原请求重试不换键。

本轮已完成隔离 namespace 中的真实 Chrome 验收：通过当前网站生成下一代请求，daemon 重启后原请求
和私钥摘要相同；离线验证并签回后，错误叶被拒绝且不产生入口事实，正确叶经页面准备并启用。旧 TLS
连接不能被查询参数冒充为新代；同一浏览器信任库对新地址完成 `control.loom` 验链、管理员认证和准确
证书摘要回读，再从新代页面排空、退休旧代。再次重启恢复新代及退休事实；原客户端认证刷新只取得新代
网站入口，身份、加入锚和 latch 保留。叶和链下载只含公开证书。

最小 Go 集成覆盖认证跨源拒绝、原字节重试、无效签回、同址异证书拒绝而原 serving 保留、真实认证 TLS
连接绑定与旧连接退休拒绝、零会话约束及权威重开；Chrome 表单覆盖请求、签回、准备、启用与再次续签。
隔离脚本的 CLI 字段读取和浏览器调试端口重启问题已修正，失败记录与最终结果均保留在受保护证据目录。

本轮 Linux 制品已签名发布到全部 YAML 目标，并从全部认证分发根核对实际 HTTPS 正文。Windows、
Android 和数据面没有功能变化，沿用已验证的原制品；节点安装只并行传输缺少的 agent 程序，数据面
使用节点原件。六节点已激活精确程序，组件期望由正式页面提交；三台 control 逐个重启后原签名事实
均可接受，全部节点的实际签名组件报告与期望一致。三种既定选路模式分别访问匹配目标并完成全部
control 的浏览器路径回读，原 Auto 偏好恢复；既有 LAN 网段报告和表单投影保持。

所有 control 的正常管理员浏览器已读到新证书页面，原公开 CSR 下载与受保护本机原文件逐字节一致；
调试连接没有被标为正式网站验收成功。本轮未新建生产网站密钥、根或叶证书。停止及恢复后，原身份、
认证原件、高水位、服务定义、非 Loom 路由、策略规则、解析配置和本次基线防火墙均保持；新建 SSH、
系统 DNS、默认公网，以及开发宿主 LAN 与原 WG HTTP proxy 通过。每节点仍为单一共享 WG 实例。
旧程序目录经精确摘要、进程和 unit 引用核对后删除，受保护身份和证据保留。

Go build/test/vet、格式、仓库安全及 diff 检查通过。实际浏览器、发布和节点证据位于
`deploy/evidence/2026-10-09-website-management/`，结果索引为
`website-management-production-closure.json`。发布耗时和新增/复用字节单独记录；本轮沿用的发布流程仍
对目录引用的全部制品重新做 HTTPS 正文核验，不能将总校验量描述成新增分发量。

生产 `.loom` 根公开证书及离线签回叶仍未提供，不能据此次隔离验收声称生产网站已启用。真实 LAN
目标参数和实体设备验收也仍保持原边界；完整服务授权工作项继续 open。


## 四页 WG 回读与拓扑可读性

本轮先补齐已有 WG 展示的实际入口验收，没有重演已覆盖的传输、停止或恢复风险。
三个正常认证浏览器分别读取 Overview、Nodes、Topology 与设备详情；页面自身的 HTTP 历史响应
及原实时推送与实际 DOM 原子对照，柱图、逐设备总量、速率和 RTT 分布相符。
无当前样本的入口保留 unknown 和空槽，不要求全部成员、节点、链路或 RTT 可用。
受保护证据为 `deploy/evidence/2026-10-12-current-wg-pages/result.json`；它沿用此前三端采集、
原报告验签、持久及重启证据，不把新增页面读取扩大为新的完整传输矩阵。
回读工具最初误把总量单元格当柱图、未授权空 scope 当待查，以及漏掉实时推送；原失败保留，
只修正验收工具，最终结果没有借此改写软件数据或虚构健康。

同次正常页面发现多节点和长名称的拓扑文字重叠与越界；现有分圈还依赖接入方向，
与目标仅用于布局不符。此项属于具体软件显示缺口，与 WG 数值闭环分开。
[拓扑的可读布局](clients/web-ui-projection.md#拓扑的可读布局)先规定有限的纯 UI 修正：
稳定 ID 分圈、完整文字分行、独立左右文字区、原节点引线和随文字增长的高度；
不改变身份、权限、观测、wire、持久或运行时，不删节点或缩小文字遮掩问题。
实现及 Chrome 最小场景正在核对，生产更新和实际入口回读尚未执行，不提前称完成。

自动签名目录消费另有两个具体缺项：安装器不能直接接受保留旧 floor 的实际手工布局，
且尚无正式自动消费接线。六节点原 floor 与最新精确程序、公钥连续性已经只读核对，
现有旧签名记录不对应原 floor，匹配原件仍缺；详见
`deploy/evidence/2026-10-12-automatic-release/current-boundary-map.json`。
不以删除 floor、比较新旧数字或恢复旧 decoder 绕过此条件；已授权显式服务更新继续有效。

首轮第 105 代目录已正式发布，三个 control 激活 `c59c413d` 后，六节点原身份、密钥、floor、
高水位、客户端及数据面、基础网络和两项独立 Service 的 HTTPS 保持；尚未完成布局验收。
正式页面发现样式表后段仍覆盖固定 SVG 高度，且总览实际名称为 13 px，首次合成检查的
容器类与名称长度未覆盖该条件。实际失败与字体、边界证据保存在本项 production/browser 目录，
没有把它改称通过。修正同一布局的容量与删除重复高度覆盖，并以正式页面类和宽度边界名称
检查字体不被固定高度缩小；后续精确制品须重新前向发布，不覆写已签第 105 代原件。


拓扑最终闭环为 `deploy/evidence/2026-10-12-topology-layout/result.json`：
`75c8d79f` 的精确程序随第 106 代目录前向发布，三 control 按独立远端组、管理成员的顺序激活。
只构建所需 Linux amd64 程序包；十项原目录条目复用，Android、Windows、Linux arm64 和数据面
原件不重建。工作站执行器固定到该源码及摘要；三个目标按摘要补缺及完整验证，变化公开正文下载
验摘要，相同原已认证公开制品只核对路径及长度，最后条件推进并重新读回各目录。
具体发送/复用数量、构建、传输、校验和服务应用时间保存在受保护 release 与 production 记录，
不凭总时长归因于带宽。各 control 从已核验公开包原件提取程序，不再次传输程序或数据面。

三个正常认证浏览器回读 Overview 和 Topology，完整名称与说明处于图内、互不重叠；
保留原节点键盘聚焦/锁定、清除以及选中连线对应的两端历史。实际页面资产摘要与精确程序一致。
六节点原身份、密钥、认证原件、floor、高水位、latch、单共享 WG、客户端及数据面保持；
resolver、规则、路由、完整防火墙语义及新建管理连接回读通过，国内和国际 Service 各自 HTTPS 通过。
三个已无运行或启动项引用的首轮 control 程序目录和六份本次临时 unit 备份已 compare-and-delete。
原客户端仍需要的共享程序目录保留；旧分圈语义和固定裁切代码已经删除，不清除签名发布历史。
本项没有新增权威、协议版本、运行时状态或操作者步骤，也不宣称全部副本、路径或 RTT 可用。

本具体布局软件链与四页 WG 数据回读已完成；自动目录消费仍缺旧绑定及安装接受接线，
生产网站材料、LAN 参数、扩展排序取舍和用户实体终验保持独立。下一项核对 Android/Windows
当前生产 UI 的具体原生视觉差异，旧截图不能证明新场景，也不能把已经完成的业务链重新称为未实现。

### Android 逐目标业务观测交付

当前原生诊断仍把多个目标折成最后一次 DNS/HTTPS 汇总，连接页只展示已选候选；
失败服务退出选择后无法回读其目标、来源、采样时间和有效期。这是已确认的显示接线缺口，
不是已有多服务业务执行或签名报告缺失。最小修订从原授权目标、selector 回读和原观测缓存
派生一次性 UI 值；不改变认证、持久、选路、VPN 或报告，正常清除的缓存不会被恢复。
连接与诊断共用逐目标展示，原有效期到达后由外部注入展示时间转为历史，删除汇总文字作为结果依据。
新增业务失败仍连接的原生场景；参考 PNG 尚未整组批准，不更新旧基准。
正式 APK、模拟器真实业务/签名原件、同身份恢复及公开/私有下载仍待本项执行回读，不能据单测或截图关闭。

用户已明确回复没有已知旧发布签名备份；自动目录消费保持原 floor 和未解决的前向证明条件，
不重复搜索已查位置、不把它作为其他已授权正式发布的前置条件。

本项软件闭环证据为 `deploy/evidence/2026-10-12-android-business-ui/result.json`。
`3adb949f` 的正式签名 APK 已在第 107 代目录发布；固定使用已验 `75c8d79f` 工作站执行器，
没有重建该工具、Linux、control、Windows 或其数据面。十二条中十条原条目复用；每个发布目标
实际发送七文件、复用三十一文件，构建、准备、HTTPS 和目录应用耗时分别保留在本项受保护记录。
变化 APK 的两个公开 HTTPS 正文完整验摘要；全部目标条件推进并重新验签/验字节后才认定发布通过。

同机独立 user/network/mount namespace 的模拟器通过原文件导入加入、正常连接及 HTTPS，
两个 Service 的三个实际目标在连接页与诊断页逐项对应报告中的候选、网络代、结果和原时间。
一服务失败并退出选择时，另一服务的两个目标仍成功、实际 HTTPS 继续、VPN 保持连接。
同身份进程重启产生新的真实样本，正常断开清除当前业务健康；关闭 daemon owner 后才读取原数据库
并验全部原始报告签名，两个运行报告的 agent 来源与本次 APK 精确字节相符。原 Android 签名身份
及既有 profiles 保留，没有清数据或复制身份。原业务汇总显示路径已删除，原缓存生命周期和报告不变。

三个正常私有浏览器均回读精确 Android 版本、摘要和附件；其中一入口实际下载 APK、manifest 与签名
并核对原字节，临时下载和浏览器证书目录已删除。六节点实际程序、数据面与旧发布 floor 仍为原件。
只读辅助首次误用不存在的程序定位目录，失败日志保留；改从上次真实当前目录读回后全部通过，
没有为检查修改节点。模拟器、专属 ADB 和隔离 namespace 正常退出，宿主网络与 resolver 对照保持。
实体机终验与十项 current/九项获批基准的整组视觉审查仍单列；本项不宣称自动目录消费或全部产品完成。
下一项继续 Windows 正式原生页面与已确定原型的布局及首次空态覆盖。

### Windows 原生业务详情与既定页面交付

当前正式 Windows 页面从原运行状态取得业务目标，但展开详情没有原有效期，且把业务采样标成读取
时间；被拒绝服务没有自己的原失败依据。现已修订同一展示投影，从原授权/观测生成每目标说明，
将真实 selector 回读完成时间沿既有可删除 runtime status 传给 UI，不写入 DPAPI 或签名协议。
既定面板/画布、正文边界、32 DIP 操作与连续服务组同步接入生产控件；首次空态增加原生场景。
同机 VM 原生业务、布局/键盘/必要 DPI、精确六款应用包及正式发布回读仍待本项验证，
不从交叉编译或截图关闭。本项复用已验其他平台和数据面，不重启未改节点服务。

`59f7d6f0` 的六款 ZIP 与两款 MSI 已按原数据面构建并完成原包签名审查；正式交付仍为两款
Installed MSI 和四款 Portable ZIP，Installed ZIP 仅为构建输入。同机 VM 已直接运行其中的正式
Portable Mixed amd64 EXE，经正常 GUI 加入、连接、两服务三目标、独立 HTTPS、正常断开和同身份
重启回读；原目标、候选、网络代、结果、采样/有效期与正常私有报告逐项相符。关闭 daemon owner 后
原报告全部验签，两次运行的实际 agent 摘要与源码坐标对应原 ZIP 内的精确 EXE，报告序列前进，
没有再次加入或复制 DPAPI 身份。此轮复用既有三种形态的安装/执行验收，不称 ARM64 原生执行通过。

原生生产控件的首次空态、详情、键盘、滚动与必要 DPI 检查通过；九项 Windows current 连续两次
原生渲染的哈希相同，Android 十项 current 一起形成整组图廊。原八项 Windows、九项 Android 基准
保持，整组人工批准仍单列；`WM_PRINT` 内容、VM 合成截图及实体显示验收不相互替代。

VM 验收辅助脚本的失败原件保留。实际程序的局部候选不可用日志被启动器的 native stderr 门禁
当成致命错误，使辅助脚本退出、程序继续运行；最终将该程序输出独立异步读取和保存在证据中，
未修改程序或把失败候选改为成功。仅清理精确所属的失败测试进程，原加入、密钥与认证进度保全。
最终正常程序断开、退出与同身份恢复通过，VM 正常关机、专属桌面进程和本次精确测试根删除，
宿主目录的临时 traverse ACL 恢复原件；磁盘、TPM 与原 profiles 保留。

本项软件闭环证据为 `deploy/evidence/2026-10-12-windows-ui-delivery/result.json`。第 108 代目录已沿
固定 `75c8d79f` 工作站执行器正式发布，Linux、control、Android 与数据面原件复用。每个目标实际
发送二十二文件、复用十六文件；构建、准备、公开 HTTPS、条件推进及最终回读耗时分别保存在受保护
记录。两个公开入口对六款变化 Windows 包完整下载验摘要，其余原已认证制品只查路径和长度；
全部目标的最终签名目录及原件回读通过，没有重启未改服务或消费旧发布 floor。

三个正常私有浏览器均回读六款应用的精确来源、摘要与附件；一个入口经正常链接实际下载正式
Portable Mixed ZIP、原 manifest 与签名并核对字节，临时下载及浏览器证书目录清除。初次辅助检查
误把六款应用当作全部 Windows 页面卡片数；原页面还保留两份数据面包，签名元数据本来相符。
修正为逐个核对六款应用的实际卡片与链接后通过，没有删除页面组件来适应错误检查。
发布后的并行回读再次确认六节点原程序、数据面及旧 floor 保持。旧业务采样冒充 selector 读取时间、
拒绝服务丢失自身依据与固定裁切布局已从生产显示路径删除；不清除签名历史或仍被引用的原件。

本具体 Windows 软件交付已闭环，实体机终验与整组基准批准保留独立。现有三种模式与各已验业务
继续有效；下一核心软件工作是签名目录自动消费及旧 floor 的一次性前向衔接。没有已知旧签名备份，
不能用删 floor 或数字比较伪造旧绑定，必须先形成可审阅的替代证明方案，已授权正式服务更新不受它阻挡。

### 自动签名更新的替代前向起点

Windows 第 108 代交付闭环后，下一核心工作项继续核对自动消费。原旧签名绑定仍缺，用户确认没有
已知备份，不再重复搜索。`deploy/evidence/2026-10-12-automatic-release/forward-alternative-review.json`
独立核验现运行程序对应的原 schema 3 catalog、manifest、完整包及逐文件内容；六节点当前普通期望
也固定到该 agent 原引用，数据面与包内原件相符。较新的下载 current 包含不同程序，不能拿来当现安装起点。
这次只读核对没有写 floor、current、身份、期望或网络，也没有补回缺失的旧签名。

[前向提案](operations/release-forward-cutover.md) 将选择收束为：保持显式更新，或由用户一次性明确授信
已授权、已运行且独立验签的现程序，作为现行包接受起点，保全原 floor 原位原字节、身份和认证进度。
推荐后者；不新增权威 store、协议版本或旧 decoder。用户决定后须在同一核心工作项继续完成安装接受、
私有精确交付、自动消费、持久/失败/重启、生产业务回读及旧入口删除，不能仅以本提案关闭自动更新。

全仓库核对确认 `internal/releasefloor` 没有调用者；其中 schema 1 signed-current floor 的读写器及
对应失效测试已删除。现行安装的接受前沿仍由原规范 Manifest/current 表达；旧原始 floor 文件保持，
旧证据的显式离线验签入口保持。此次源码清理不启用自动消费，也不修改部署或任何认证进度。

### 整组原生基准与自动更新授信决定

用户已批准 Android 十项和 Windows 九项整组新截图。`scripts/ui-review record all`
仅由生产 Compose/Win32 renderer 更新获批基准，再次原生渲染后十九项场景、尺寸与全部 RGBA 像素
严格相同；新增 Android 业务失败与 Windows 首次空态各一项。人工逐图核对与 binary diff 保留，
证据为 `deploy/evidence/2026-10-13-ui-baselines/result.json`。未重建或重发未改的 Android/Windows
应用，不重复既有业务验证，不抵扣 DWM 外框或实体终验。Windows VM 正常停止后恢复原目录访问权限。

用户同时明确选择[已批准前向切换](operations/release-forward-cutover.md)：六节点旧 floor 原位、
原字节保全，以已授权、已运行且独立验签的现程序建立一次性现行包接受起点，继续自动更新。
这取代此前“等待决定”的阻碍；没有恢复或补造丢失的旧签名历史。安装接受、私有精确材料交付、
自动消费、失败/重启、生产业务回读及旧入口删除仍是同一个待完成的软件工作项，立即继续实现。

### 精确期望自动更新与原 floor 接管：已部署并回读

用户已批准的一次性接受通过 `client install -accept-current` 固定原包、原 floor 摘要、公开身份、
原 unit 和执行输入。六节点以原第 104 代签名包建立唯一 Manifest/current 接受起点；原旧 floor
保持原位原字节，未补造丢失旧签名，也未按数字比较不同签名对象。五节点的遗留 v2 状态/配置目录
先确认无当前输入、unit 或进程引用，逐文件保全字节、归属和权限后归档，原入口删除。

私有 device release 只交付已接受 View 的明确期望原签名材料；完整正文、原 manifest 与签名
逐字核验后仍进入原安装锁。新请求不读公开 current 授权、不写身份或报告、不扩展四字段组件坐标。
更新 service/timer 从同一 capture/state/resource-inputs 生成，首次临时工具接管后删除。
正常低代、同代异值拒绝；配置变化、错签名、错平台及未期望的组件变化拒绝本次更新。
同机 Linux VM 完成原包接管、正式期望私有更新、实际 HTTPS、原报告验签、同身份重启与
签名低代拒绝后继续业务；原安装器接受后失败保留新代及同包恢复的既有证据复用。VM 正常停止，
原身份及磁盘保留。Android 十项、Windows 九项整组基准批准与严格复验另有前节记录。

首次发布第 109 代 `c2ee657b`，三 control 分组激活并恢复正式入口。原包预检没有使用运行时的
认证 DNS 执行地址，使三个节点接管在接受前停止；原身份/floor/指针不变，经精确清理恢复原服务。
修正同一模型的预检解析与接线，将升级预检提前到停服之前；原包接受用新工具的当前只读适配器，
不改写原签名或程序。最小 named WG 预检测试和三个实际节点不停服预检通过，修正前失败保留。
随后第 110 代 `4e76b8e0` 正式前向发布，控制面复用 `c2ee657b`，数据面、Android、Windows 和
`75c8d79f` 发布器均复用原件；每个发布目标发送十一文件、复用二十七文件。变化正文六次完整
下载验摘要，原已认证制品十八次路径/长度验证，全部指针和最终签名目录回读通过；阶段耗时保留。

正式 `control write` 提交六个 agent 的精确期望，六节点并行私有拉取并实际激活第 110 代；
原数据面坐标一致、身份/密钥/high_water/latch/report_sequence 保全或单调前进。正常更新 service
重复检查不重装、运行 PID 和 current 不变；六节点同身份重启、精确程序、单一共享 WG、独立
国内/国际实际 HTTPS 与原偏好回读通过。三个正常 mTLS 浏览器回读精确 Linux 包及附件，两个
入口看到六新程序报告，另一个入口在观察窗口内仍为旧报告；不据此宣称客户端故障或全副本已同步。

宿主与节点的身份、受保护输入、route/rule、静态防火墙与解析配置保持；新建管理返回路径不走
被替换 WG。一个国际节点的国内名称基础查询失败保留，使用对应国际目标后 DNS/默认 HTTPS
成立，解析配置摘要不变；没有推定其旧查询曾成功。管理宿主的 LAN/DNS、默认 HTTPS、原 WG
上的 HTTP proxy 和新 SSH 成立。误把重启与同节点快照并行的辅助检查失败保留，最终按顺序回读。

临时两个版本的安装工具、原包副本、绑定输入、被替代 control 程序和空旧执行目录已删除；
退役的原规范 manifest/签名及旧状态证据保留，原 floor 原位不动。六节点最后正常入口再次确认
第 110 代、原身份/偏好/数据面/floor、单一共享 WG 与正式 timer。闭环证据为
`deploy/evidence/2026-10-13-automatic-update/result.json`。

本自动更新核心已闭环。停止原程序的日志另暴露共享 WG 系统栈 dispatcher 与接收竞争引发的
空指针；精确清理和服务恢复已完成，但数据面源修正与相应精确交付仍是新确认软件缺口。下一核心
项集中修复这个关闭竞争；网站离线签回、指定 LAN、扩展排序决定及实体终验仍独立保留。


## 共享 WG 并发关闭与第 111 代交付

目标是正常停止时即使仍在收包也不崩溃，随后从同一身份和授权恢复业务。自动更新接管原程序期间
观察到系统栈 dispatcher 拆除后仍被接收线程调用；同一纯用户态栈也使用该关闭顺序。模型先明确
两种现有设备的接收/关闭互斥：关闭拒绝新交付、等待已开始的交付，再在释放接收锁后拆除系统栈；
附加、读取和拆除 dispatcher 使用短锁，避免系统栈回调的锁依赖。域、wire、持久、权限和 UI 不变，
不新增生命周期实体、store、schema 或选路算法。源码为 `03d3f7f1`。

必要并发验证使用实际 Write/Close 与栈拆除，覆盖在途交付、关闭后收包、重复关闭和 dispatcher
并发读写；原各 peer 批次隔离保留。四个 Linux/Windows 架构的精确数据面与供应源码在独立目录
重新构建后逐字一致；历史签名制品仍按原源码与字节验签，唯一新 writer 使用 `1.11.4-loom.12`。
隔离 Linux 在真实 TCP/UDP 接收期间正常停止，重启业务恢复，所有所属接口精确清理。Android 新 APK
及 Windows 实际 Portable Mixed EXE 都走正式加入/连接、WG HTTPS、正常断开和同身份进程重启；
原报告仅在数据库 owner 退出后读取并逐条验签，精确 APK/EXE/数据面与正常入口相符。沿用已验
安装及 TUN 风险范围，不重做完整矩阵；ARM64、实体切网/睡眠/显示不能由模拟器或 x64 VM 抵扣。

为审查新的数据面字节，仅将必要校验程序交付消费者；三 control 按独立两成员并行、管理成员后续
的顺序恢复并读回。正式 stage 固定第 111 代，各 Linux 包、两个 Windows 数据面、Android 与六款
Windows 应用均从 `03d3f7f1` 的精确原件组成；签名、原包、manifest 和本机输入原字节不重写。
全部身份通过后独立目标并行分发，三个目录完整准备、验签后，按既有授权规则与公开校验并行提交
十二项精确期望、消费私有原签名包。公开指针仍等待全部规定 HTTPS 验证，期望组件的签名事实
不会由 public current 或下载颜色产生。临时管理 CLI 仅用于新制品校验；实际接受指针仍由正常
installer 推进，未重复一次性旧 floor 接管。

六节点全部沿 `client update` 激活第 111 代：原身份、密钥、报告序列、高水位、latch 与旧 floor
保全；正常 update service/timer 再执行为幂等且不重装。真实流量与六节点正常 restart 重叠，全部
新数据面关闭没有 panic，重启后原资源与业务恢复。每节点一个共享原生 WG，WG 与 Hy2 继续独立；
主机 rule、underlay route、静态防火墙、resolver 及受保护输入比较通过，新 SSH、对应地区的 DNS/
默认 HTTPS、管理宿主 LAN 网关解析和原 WG HTTP proxy 成立。更新中途一次国际 HTTPS 失败保留；
全部更新后以及重启后，既定国内/国际各自 Service 的真实目标均成功，未改变 Auto 偏好。

首次公开校验中一个入口的 APK 正文在未到完整长度时 EOF，原发布器正确拒绝推进所有公开指针；
不把之前的其他正文成功当成这一入口成功。工作站发布器因此增加同次内存中的有界重连：最多两次，
以精确 Range 续取剩余正文；206 的范围和长度逐项核对，200 则丢弃前缀、从零重算。只有完整长度
与完整 SHA-256 匹配才通过；取消、范围/摘要错误、压缩及次数耗尽继续拒绝。没有持久验证回执或
新配置键；命令重新开始仍完整校验本次要求的新正文。真实 HTTPS 截断、完整响应、错误范围/摘要、
次数边界和取消的必要测试及仓库规定检查通过。该修正只构建 `5f16e8cb` 的工作站工具，复用原包、
目标已有文件和未改客户端，不重发或重启这些客户端。首次失败及后续正式结果均保留。

正常私有页面及原下载链接读回精确第 111 代 Linux、Android、Windows 原件与附件；六节点运行报告
按实测窗口分别记录，不把报告迟到称为故障。临时工具、旧 control 执行字节和旧接受目录中的程序
移除前比较实际进程、unit 和精确字节；原签名 manifest、历史源材料及旧 floor 原位保全。
Windows 正常退出、owned 演练证书和桌面进程清理、VM 正常关机、父目录原 ACL/模式恢复；Android
正常断开与模拟器退出，原 DPAPI、Keystore、TPM、磁盘和 profiles 均保留。

受保护证据为 `deploy/evidence/2026-10-13-wg-close/result.json`。Windows 辅助请求遗漏加载
.NET HTTP 程序集、演练接收器临时键未保留导致的明确换键与旧池保全、重复请求 ID 拒绝、离线报告筛选
缺设备绑定，以及消费 helper 误读 View 中不存在的 catalog 字段，均保留原失败后按实际契约修正；
不伪报为客户端故障，不重用已消费邀请或重置身份，也不绕过签名、前沿、发布和宿主网络门禁。
本项完成后，当前可独立完成的既有软件缺口已闭环。生产网站离线根/原 CSR 签回叶、指定 LAN 参数、
尚未确定的扩展排序目标、外部 Authenticode 与用户实体终验仍按产品对账各自保留。

## 当前设备列表与拓扑退出已删除及终结记录

操作者正式页面暴露新的交付缺口：验收设备已经撤权并永久删除，未完成邀请已经取消或到期终结，
但 Nodes 的默认列表仍把历史值标为 pending，Overview 计数和两页拓扑也使用整个管理员快照。
现场读取原事实投影后确认其没有当前授权，不重签删除、不清除历史，也不按 Demo 名称隐藏。
此前“旧路径清理”验收覆盖了执行程序，不能抵扣这项正式页面缺口。

最小模型在原 UI 单向投影中定义一个当前设备集合，由现有 Device/TargetState 的删除、终结、
冲突、授权及公开撤权审阅值决定。默认列表、总览计数与拓扑统一消费；原快照和直接详情继续供
公开历史回读，不新增权威、wire/persistent 字段、schema、状态机或隐藏名单。open/bound、无新鲜
观测的有效节点、冲突及可审阅 revoke 保留；普通撤权不删除仍有效的 control 身份，revoked 不再
冒充 pending。原设计仍允许未知观测，不能用收口历史记录制造健康。

真实签名加入/取消/到期/完成/撤权/删除的原生 Chrome 最小验证通过；正式浏览器重新授权后永久
删除，再打开 Nodes、Overview 和 Topology，验证当前集合退出且直接历史详情仍可读。冲突输入
单独作为只读投影反例验证，没有为演练在生产制造冲突。仓库规定 build/test/vet、格式、安全和
diff 检查通过，源码为 `d3b0c1dc`。

仅构建一个 control 程序，复用原数据面生成本地规范签名源包；独立程序验签并核对源包里的实际
程序与部署字节一致。本地源包使用后续发布坐标用于验签，不推进公开 catalog、任何客户端安装
指针或期望事实；未改客户端、Android、Windows 和发布工具全部复用。所有目标身份检查通过后，
仅向独立远端并行发送必要的新程序，本机直接复用构建文件；目标核对精确摘要后，两个独立成员
并行修改原持久 unit 的 ExecStart、重启和回读，管理成员随后应用，原回环坐标与证书始终保持。

第一次辅助回读紧接 simple service 的 restart，早于管理 socket 就绪，两个明确失败结果保留。
实际程序已经正确启动；后续仅有界等待并回读该进程，没有重复应用、回退认证或重启已恢复成员。
所有 control 原身份、签名事实、TLS/管理员材料、成员及授权、客户端实际 PID/程序、floor 和
认证进度保全或单调前进。三个正常 mTLS 浏览器各自读取原快照、精确新静态代码和三页实际 DOM，
当前真实节点完整保留，历史测试记录全部退出，原实际连线完整保留。国内/国际各自 Service
真实 HTTPS 成功，原偏好未改。原程序仍为未改客户端提供执行字节，只从 control 的已替代启动
引用退出；临时上传和 unit 写入文件均已消费，浏览器临时凭据已清理。

闭环证据为 `deploy/evidence/2026-10-13-topology-cleanup/result.json`。页面源码仅替换了把完整历史
集合直接当当前节点的旧消费路径；未删除任何原始权威材料或降低认证进度。六客户端及其他组件
仍使用第 111 代原件，不能由 control 的新源码推定它们已经更新。外部材料、指定 LAN、扩展排序
决定和用户实体终验继续各自保留。


## Web 运行状态与原型结构纠偏

操作者现场截图确认：Overview 和 Nodes 把始终 unknown 的整机 availability 当成节点状态，
拓扑采用另行发明的外侧文字目录，页面结构偏离已确定原型。先前以功能检查和可读性检查替代逐页
视觉对照的交付判断无效；原型文件不作修改。当前工作修正共用顶栏、Overview、Nodes 和 Topology，
运行、Service 业务、接口计数和期望组件回读分别消费原签名输入，报告过期仍为 unknown。

Overview 恢复设备、成员、业务探测和组件回读四项摘要，拓扑/流量/发布、设备/服务路径/签发者前沿
和近期事件的原布局；Nodes 按原型分栏显示运行依据、小时状态与 RX/TX；Topology 恢复 Service
筛选、WG/Hy2 与路线开关、近旁标签、连线纯文字度量、观测/流量侧栏及四列链路历史。
悬停只预览，点击才锁定，Esc 清除；没有符合实际选路的 LinkID 时不擅自选中其他链路。
没有组件期望或合格报告时不产生零完成或安装成功结论。

真实 Chrome 的正式 handler 验收覆盖原签名的 running/error/stopped、缺失/过期/未来报告、
两个 Service 一成一败仍保持独立运行状态、历史范围与刷新、正常管理操作及六/十七节点布局。
真实现网数据的本地只读预览与目标 SVG 已逐页查看；正式部署与原浏览器回读仍待本工作项执行，
不能以这些本地结果关闭交付。其余具体页面差距继续列在产品交付对账中，不称全部 Web 已遵循原型。


正式三个 control 回读发现 Overview 的近期摘要仍请求完整 72 小时分桶，即使只显示三条。
一个入口的本地完整查询超过观察期限，最近一小时查询则完成；因此在同一工作项中将摘要改成
明确的一小时查询并显示其范围，完整 Events 功能保持。前两个浏览器结果及失败重读保留，
不把该失效结果称为三个入口通过，也不通过重新部署未改的客户端消除等待。


本工作项正式回读已成立，受保护证据为 `2026-10-13-node-status/result.json`。三个 control
只替换 Web 执行程序，最终源码为 `8f4b7fad`；六 Linux 客户端、Android、Windows、数据面、
工作站发布器、公开 catalog 与已接受的客户端代继续沿用原件。正常管理员浏览器读回三页原型结构、
原签名运行状态、真实 LinkID 及点选/Esc，国内与国际分别沿原 Service 目标成功；原身份、证书、
私有监听、事实、授权、floor、高水位与 latch 保全，客户端 PID 未改变。原 service 的持久执行引用
经重启消费，先前被替代的两个独立中控程序已按摘要/引用核对后删除，临时传输和浏览器材料清除。

观察窗口内有一个入口只持有过期报告，按 unknown 显示；其他入口已取得新的运行报告。它不表示
客户端故障，也不要求全部副本或链路变绿。先前两个浏览器等待窗口和清理后的本机记录变量错误均保留，
后者只修正读回记录、没有重做已完成的远端清理。原目标 SVG 没有修改。

本项仅关闭共用顶栏、Overview/Nodes/Topology 与状态消费；其余设备流程、Live paths、
Services/Policies/DNS、Releases/Device versions、Events 布局和 Administration 的具体原型差距
继续在产品交付对账中保持 open，不将正常导航或功能测试通过冒充全部页面视觉交付。


## Administration 原型恢复

四个同级视图按原稿恢复为左侧导航、右侧开放对象列表和原位展开。Control nodes 只由原成员链与
真实待加入对象生成，peer receipt 缺失继续 unknown；Administrators 保留公开文件授权、对象指纹详情
和独立撤权；Web certificates 保留根/叶材料、绑定请求、签回、实际激活/验证/退休的原链；
Configuration state 保留同一公开来源、搜索、差异与显式解决草稿。原 `/settings` 页面入口及网站验证
链接已退出，统一从 Administration 进入；没有改原型、成员、授权、现网证书或私钥。

`2026-10-13-administration-prototype/result.json` 记录三个正常认证浏览器的四视图、对象展开、
前进/后退、原管理员材料、实际新静态文件及旧入口 404。必要原生检查覆盖成员多数、管理员公开文件
授权/撤权及重启、网站请求/导入/激活/续签、冲突草稿与重读；仓库规定检查均通过。三个 control
仅更新到源码 `7c3c88ed` 的中控程序，原客户端/数据面/Android/Windows/发布器及客户端接受代不变，
原 unit 的重启消费、身份/数据/floor/高水位/latch、国内与国际各自业务、旧中控程序及临时材料清理读回成立。

本项关闭 Administration 的四视图组织，不抵扣生产离线网站材料、用户笔记本/实体机边界，
也不关闭剩余设备流程、Live paths、Services/Policies/DNS、Releases/Device versions 与 Events 的原型差距。

## Web Live paths 原型恢复：实现与必要验证

本项沿 `/routing` 保留同一 Service/设备/Policy 与原签名报告，恢复 `04-live-paths` 两张原型的
开放式服务侧栏和设备列表、四项只读范围、横向策略摘要、图标节点与无底框分段度量。候选/历史
共用一区，返回、前进/后退保留搜索与互斥筛选；切换服务清除旧设备筛选。实际选择与目标结果、
设备 runtime 分开；服务冲突目录可见，未确认路径不进入当前分组。分组只从共享首跳、独立传输、
有序节点与当前 Link 规范派生；跨服务设备总数去重，目标失败不改写全服务健康。

最小原生验证已覆盖正常加入/签名报告/范围替换、历史查询与返回，及多服务去重、同路成功/失败、
WG/Hy2/一跳分开、未知运行状态与零业务耗时。原有 Hy2 原生展示验证通过；只读真实数据预览已
对照原图，正式部署及三个原管理员浏览器回读仍是本项关闭条件。原始 SVG 未改变。

## Web Live paths：正式部署和回读完成

最终源码 `8891e853` 只前向替换三个 control 的中控程序；Linux/Android/Windows、数据面、发布器、
公开目录及客户端第 111 代接受记录继续沿用。`2026-10-13-live-paths-prototype/result.json` 记录
三个原管理员浏览器的开放列表、设备详情、匹配原快照的路径/目标计数、候选/历史、搜索筛选、
返回与前进/后退、切换服务清除旧筛选，以及精确静态文件。国内与国际各自真实业务成功，
原偏好、身份、认证材料、签名事实/墓碑、客户端 PID、floor、高水位和 latch 保持；持久 unit
消费及旧独立中控程序/临时凭据/上传文件清理读回成立。本项关闭，剩余页面按交付对账继续。

真实预览发现长 Link 度量裁剪，正式实时刷新又暴露内联布局受现有样式策略限制的错位；
失败截图和首次浏览器验证记录保留，修正为外部 CSS 的同一开放节点布局，没有放宽页面策略。
严格样式策略的原生长名称检查及三个正式入口的路线对齐均通过。首次浏览器脚本误把正常的
“刷新历史”按钮当作错误，已修正只核对实际历史错误/24 小时结果；未据此重复部署或修改业务状态。
原型 SVG 始终保持原字节，未生成新基准覆盖差距。

## Web Events 原型恢复：当前实现与必要验证

本项按 `08-events` 恢复一行 42 px 筛选、默认 72h/10m、开放式图表及三列 Local history
原位展开；来源与对象仍能填写任意合法精确 ID，显式 UTC 范围在同一筛选栏下展开，
不增加 wire 字段。历史颜色从现六类实际记录派生；接收结果与当前授权/健康分开，
不从原型合成业务/到期样本补造历史。完整窗口、连续加载、草稿/展开保持、失败重试与
同条件完整 CSV 沿原正式入口，UTC 与图例计数从同组实际查询计算。

完整 72h 实际查询暴露重复解析当前与紧邻前驱的成本；最小修正只复用同次已严格验签返回的
规范报告，原字节仍逐条读取，引用键/签名/历史身份不变，无新缓存或持久索引。状态未变而
applied View 或错误字段变化时说明真正变化。已有完整查询/CSV/重启/分叉/损坏/取消检查及
新增已缓存的窗外前驱损坏拒绝通过；真实 Chrome 的一行筛选、显式窗口/后退、滚动失败/重试、
草稿与详情保持、同过滤导出通过。正式部署、实际 72h 回读及旧程序清理仍是本项关闭条件。

## Web Events：正式布局、完整窗口与导出回读完成

最终源码 `a6d4005a` 仅更新三个 control；`2026-10-13-events-prototype/result.json` 记录三个原
管理员浏览器的单行筛选、完整 72h/432 桶、三列记录/原位详情、真实历史结果、同固定窗口全量 CSV、
对象筛选及后退、精确静态文件，默认筛选后仍保持一行。页面的 `range` 仅保存默认/自定义浏览
选择，不传入严格 API/CSV；显式 UTC 不变，默认窗口刷新固定新截止。原签名操作、报告、接收附注、
身份/认证材料、成员/授权、客户端 PID、旧 floor、高水位及 latch 保全；持久 unit 消费、各自
国内/国际实际业务、被替代独立中控程序及临时凭据/上传文件清理读回成立。原客户端第 111 代、
数据面、Android、Windows、发布器与公开目录保持原件，原 SVG 未变。该原型与既有查询业务链关闭。

全窗口首次读取的实际时间因原件量而异，较大历史仍约为分钟量级；原始超时、首次与最终回读
均保留，不把去除重复解析称为全量查询已快速。没有改写或减少历史、降低验签或从缓存恢复损坏
原件，也没有重复发布未改客户端。剩余设备流程、Services/Policies/DNS 和 Releases/Device versions
继续按对账逐项恢复；外部材料和用户实体终验仍独立。

## Web Releases / Device versions 原型恢复：当前实现

本项恢复 `07-releases` 三平台的目录验签摘要、文件/受众/核验/下载四列、原位文件详情及
所选文件的设备应用区域，保留当前精确下载及 checksum/manifest/signature 附件；Copy link
走同一 URL，不附凭据。签名目录代数及受众来自既有规范原件的同一公开投影，不借发布器状态
或文件名推断。实际文件数按验签目录保留，不把固定示例的三个文件当生产上限。

Device versions 改为稳定设备/组件/平台的三列清单、筛选与原位展开；缩写仅用于行中显示，
完整坐标保留在提示和展开。新鲜同 View 报告与当前期望分开比较；过期、缺项、异平台、
未设置期望及来源不可用分别说明。Archive SHA 与组件 SHA 不混比；选中文件不是设备目标时
明确说明，不能用其他目标的匹配点亮它。旧制品卡片和无消费者的混合发布步骤样式删除，
设备原期望编辑入口与签名操作保持。正常浏览器下载验摘要/复制、必要组件语义与旧发布/期望
检查通过；正式部署、原管理员回读、精确文件及持久消费/旧程序清理仍是关闭条件。

## Web Releases / Device versions：正式回读完成

源码 `267f3d56` 已只替换三个 control 的中控执行引用，闭环证据为
`2026-10-13-releases-prototype/result.json`。三个原管理员浏览器分别读回 Linux/Android/Windows
实际全部文件、签名目录的真实代数和受众、完整精确 URL 与正常 Copy link 点击、原 checksum
附件；管理入口实际完整下载 Linux 包并验摘要，未重传或重建原 APK/Windows/其他包。原先
公开制品真实性与完整字节验收沿用第 111 代，新增读回只核对当前所需入口接线。

三个 Device versions 正式入口的三列组件/平台、完整坐标展开及后退成立；匹配只在新鲜同 View
的相同组件/平台与当前期望成立，目录验签和下载不点亮应用。文件未指向设备当前期望时明确
说明，没有推断新最低版本约束。原期望操作入口保持，客户端 PID/程序、floor/高水位/latch、
身份/证书材料、签名事实/成员/授权、国内/国际各自业务与原偏好保全；持久 unit 消费、旧独立
中控程序、上传与临时管理员凭据清理回读成立，原 SVG 保持原字节。本项关闭，尚余设备详情/
添加交付改权，以及 Services/Policies/DNS 的具体原型差距；外部材料和实体终验仍分别单列。

## Web Services / Policies / DNS 原型恢复：实现与必要验证

本项按 `05/06` 恢复开放目录、搜索与原位编辑；固定 ID 与 Service 归属在原稿位置只读，
新建/复制保留必要 ID 与服务选择。Service 目标改为可增删 matcher 行；显示 suffix 的前导点
只在 UI 与原规范值间格式化，仍经同一严格解析器与签名 operation。相关策略、真实当前
授权 View 中已知探测目标与共享影响分区显示，没有从编辑草稿写回事实或生成假业务状态。

Policy 的 any/only/none 并列，only 使用可搜索标签/持续多选；不可用原引用保留，清空标签
不放宽到 any。节点列表按当前职责筛选，不要求报告或 RTT 变绿；本地出口也使用同一原
集合值。允许/禁止、Direct、入口/出口/转发、固定 LAN 网关、草稿规则摘要与已知共享引用
沿既定模型。CSS/标签 helper 只服务原表单，没有第二授权、manager 或页面持久状态。
DNS 保留一个列表/过滤与同记录原位编辑，原 A/AAAA 多答案、LAN 关系、保留网站名及未知
观测不变。原 Service/Policy/LAN/DNS 正常写入/持久恢复、共享复制/父草稿/重试、节点选择
最小原生检查通过；正式页面、精确中控部署与原业务/旧程序清理仍是关闭条件。

## Web Services / Policies / DNS：正式回读完成

源码 `afd87ccf` 已仅替换三个 control 的中控程序，闭环证据为
`2026-10-13-intent-prototype/result.json`。三个原管理员浏览器读回开放服务/策略目录、搜索、
正常目标行/提交反馈位置、固定服务、原并列范围与连续标签选择、草稿重新加载回到原签名规则，
DNS 唯一记录列表与原位编辑、未知 Service 不打开其他对象、精确当前静态文件。实际生产仅
编辑可丢弃浏览器草稿，没有制造新验收设备、策略或 DNS 记录；原正式写入/复制/依赖/持久与
运行投影由必要同机原生检查覆盖，既有生产业务范围沿用并独立读回国内与国际实际目标。

身份/密钥/认证材料、原签名事实/成员/授权、客户端 PID/程序、原 floor、高水位及 latch、
原偏好保全；持久 unit 消费、旧独立中控程序及上传/临时管理员凭据清理回读成立。六 Linux、
数据面、Android/Windows、发布器、公开目录与客户端接受代不变，原 SVG 字节保持。本项
关闭；设备详情/添加/交付/改权的具体原型差距继续推进，外部网站/LAN/签发及用户实体终验单列。

## Web 统一设备详情与开放交付表单：正式回读完成

源码 `608682da` 与后续加入/撤权语义修正 `51600358` 已完成当前工作项。设备详情沿同一 ID
提供概览、访问策略、转发与 LAN、身份操作的职责分区，默认只显示概览；分区选择、浏览器
返回和报告刷新保持原草稿及身份。配置、runtime、Service 结果与原样历史分别表达，RX/TX
恢复分组柱图。资源监听报告不冒充传输可用；真实 LinkID、LAN 网关与服务目录仍沿原入口。
原堆叠卡片、五阶段详情与双栏添加样式删除，添加、改权、QR/sh/SSH 交付恢复 880 px 开放表单。

策略用可搜索标签同时显示 Service，只读规则摘要进入原 Policies；同服务替换与移除 access
先确认，失效引用保留并阻止提交。创建/复制/取消仍保留原父表单和因果基线。有效未绑定邀请
只从交付入口重开；消费后不再发 capability。SSH 未知先检查同次身份并继续，已完成加入不
因为 runtime 缺失或撤权倒退。原组件期望、报告/历史展开和 LAN 的管理入口保持。
纯 access 的丢失身份快捷流程复用原删除与签发：永久墓碑回读后再签新 ID；删除事实成为
新邀请的依赖，响应丢失重试原字节，重启不复活旧身份。真实私有 bootstrap 的新身份加入及
deny-only 配置通过，旧身份仍拒绝；组合职责不提供该快捷流程。它没有新授权实体或替换任务库。

闭环证据为 `2026-10-13-device-prototype/revision/result.json`。三个原管理员 HTTPS 浏览器
实际回读四分区、真实柱图/报告/历史、正常开放表单、策略复制取消、角色与媒介、组合身份
拒绝，以及精确静态字节；没有在生产制造新验收设备。相关正常写入、持久恢复、重试与加入
由必要同机原生流程验证，国内与国际各自真实业务分别通过。仓库规定检查通过，提交已推送。

独立 control 同时发送所需程序，再分组应用并保留管理入口。首次阶段发现撤权与加入显示
混淆，补原生反例后以修正版接管；两个阶段各仅发送两个远端程序文件，本机复用本地构建，
传输/校验分别计时，未重建或分发客户端和数据面。来源包只在本地独立验签，未推进公开目录
或客户端接受代。身份、密钥、认证原件、floor、高水位/latch、原签名事实和成员/授权、客户端
程序/PID与原偏好保全；持久 unit 消费、两个被替代独立中控程序及临时文件/管理员凭据清理成立。
原 SVG 未改。本次具体界面欠账关闭；Events 大窗口首次读取耗时继续作为软件限制推进，
离线网站材料、指定生产 LAN、扩展指标取舍、外部 Windows 签发与用户实体终验继续分别列明。

## Events 大窗口重复处理：正式修正与实测范围

用户的页面交付工作完成后继续核对大历史首次读取。实际三个原入口的 72h/432 桶基线约为
1、58、21 秒；采样显示主要为 CPU 上的报告解析、重复签名消息构造与反射类型检查，不能
归因为带宽。首次只缓存运行标量的修正收益不足，原失败/时间证据保留；继续确认同一 NodeID
的 control 签名键与设备报告键不同，错键先验导致已有正确缓存仍做重复工作。

`e7508205`、`6e448153`、`cdabe584` 最终沿既有 16 MiB 缓存复用身份位置与三个运行标量；
输入仍来自实际原件并重新验摘要，精确验签键必须在本次历史身份集合内。未命中则完整规范
解码、验证全部字段，并只构造一次原签名消息给合法历史键逐项验证。规范编码在单次遍历
复用静态类型检查；每个具体值的 Validate、UTF-8、空集合及循环拒绝保留，没有跨请求类型库。
缓存清除、错误公钥、改变原件、损坏紧邻前驱、后续同类型非法值、原规范字节及完整窗口/
分桶/连续加载/同过滤导出通过；原 Chrome 流程与仓库全部规定检查通过。旧测试只接受 closed
字符串而误拒真正 EOF 的关闭竞争已按实际不可用连接语义修正，不放宽为接受超时。

最终证据为 `2026-10-13-events-io/types/result.json`。同一修正前固定窗口逐字回读相同结果，
较大历史入口首次约 21/58 秒降为约 7/35 秒，重复/筛选/完整 CSV 约 2/6 秒；较小入口约
1 秒。三个原管理员浏览器完整 72h/432 桶、单行筛选、原位详情、真实历史结果、同窗 CSV、
对象筛选/返回及原静态字节通过，当前轮浏览器加载约 3/13/3 秒，范围和实际耗时保留。
最慢入口重启后首次 72h 仍约 35 秒；本项不将它称为即时响应或承诺未来恒定延迟。

三个 control 分组并行接管最新源码；仅构建、传送发生变化的控制程序，本地源包独立验签，
不推进公开目录或客户端接受代。未改的六 Linux、Android/Windows、数据面和发布器复用原件。
国内与国际各自真实目标通过，偏好、身份、密钥、认证原字节、原事实/授权/成员、客户端
PID/程序、floor/高水位及 latch 保全。持久 unit 已消费当前精确程序，三个被替代独立中控
程序及临时上传/浏览器凭据精确清理；原 32 张 SVG 不变。具体重复工作修正闭环，首次大窗口
读取性能限制、离线网站材料、指定生产 LAN、扩展指标取舍、外部 Windows 签发及用户实体终验
继续按各自事实单列。

## Linux 更新与 WireGuard 内存：正式部署及回读范围

本次现场区分了内核已确认的更新器及数据面内存终止、周期网络观测超时，以及一个此前已落后的
control 管理通路；页面全部未知不能单独证明所有节点停机。原身份、密钥、签名事实和报告原件、
认证 floor、高水位、报告序列与不可回退 latch 继续保留，不降低认证进度或恢复旧协议。

客户端源码 `b0657733` 已通过原私有期望与更新入口部署。下载、规范 archive 重编码比较、ELF 来源
检查、目录复制与耐久回读改用固定缓冲和同一打开文件；整包及解包正文位于受保护磁盘，不再跨阶段
持有正文 map。control 私有下载只深校验所请求的包，小元数据缓存可删除重建。旧更新 unit 的一次性
精确证明仅用于此次前向模板替换，日常 timer 不带该参数；Go 软目标与整个 cgroup 的保护预算分别计量。
WG 的全 peer 负载队列与空闲保留有固定上限，完整数据报、GRO/GSO 边界与原权限保持；周期超时仅在
已运行且资源归属、监听和 ACL 仍可证明时保留执行并报告未知，认证、持久化、清理及其他失败仍关闭。

发布首次准备阶段拒绝了隐式 tmpfs 暂存，未推进指针。仅发布执行器源码 `ad835fed` 改为显式磁盘父目录
与固定文件句柄传输，未重建未变客户端或其他平台制品；随后全部目标身份、字节及公开 HTTPS 验证完成，
各目标才推进同一签名发布代。客户端实际消费的是上述已签源码，不以发布器提交号冒充其程序版本。
最后一个更新目标首次报截止错误，同一认证输入重试成功；原错误缺少更细阶段信息，失败证据保留，
未将其归因为数据面或正文处理，也未回退成功目标。

全部 Linux 的正式更新和无变化 timer 检查已通过，后者不重装或重启业务。运行匿名内存、文件驻留页、
更新 cgroup 当前量和峰值单独留证，未把累计分配或文件映射当作堆需求；这些短时回读不能抵扣长期
数据面内存验收。两个真实授权业务目标、原偏好、
新建 SSH、默认公网、DNS、本机 LAN 与既有 underlay 代理分别回读。原管理员浏览器在可达 control 上
显示全部现有节点的当前组件和同 View 已应用；另一 control 的页面与附件可访问，但历史前沿与报告仍旧。
其双端 WG 元数据证据证明握手到达本机并有响应出站，扩大到任意来源的中继接收窗口仍未收到响应，
采样无内核丢包或缓冲溢出。丢失边界在本机物理接口出站与中继物理接口入站之间；本机私网地址是
既有 NAT 前的实际视角，不因此修改认证公网坐标。既有映射及上游回程仍需操作者现场核对，不能把该
同步缺口称为已修复。本轮临时工具、迁移证明和已知暂存已精确清理。

控制与转发两类 Linux 的正常停止、精确数据面子进程异常退出、同身份重启与宿主基础连接均已验证。
异常退出后自有接口和所有权记录清理成功，父 agent 按现行模型保留认证修复通道并报告 error，未自动
重施数据面；实际接收 control 的新鲜签名错误报告、空应用摘要和退出信号日志分别成立。停掉自身管理 WG
的 control 会暂时停止历史同步，不能用其本地旧快照否定实际接收端的新报告。最初将合法修复状态要求为
父 service 必须 failed 的验证器已按模型纠正，未因此改变运行需求或发布新制品。

其中一个节点的两条既有外部防火墙规则跨原采样期消失，实际删除者未证实；它们不属于 Loom，现行
清理只能 compare-and-delete 自有 inet 表，未修改或恢复该共享链。此限制单独留证，不称防火墙全量
跨时刻恒等。其余共享网络与实际管理连接、新停止状态到重启后的规则定义已回读；全部测试节点均已
恢复运行和报告确认。最终原管理员浏览器再次确认可达 control 的全部当前运行、组件与已应用，落后
control 仍按旧报告显示未知，整体验收不标成功。

证据位于被忽略的 `deploy/evidence/2026-10-14-memory-recovery/`，包括完整签名目录、逐目标发布与私有
消费、真实更新和无变化工作集、浏览器、宿主网络以及系统 TUN 管理互通；源码规定检查通过。隔离互通
与队列压力检查只证明其各自范围，独立吞吐测量保留了资源预算的实际代价，不承诺零吞吐成本。该 control
同步缺口及仅一个已提供独立私有入口的外部可用性条件继续开放；本轮没有登录或修改路由器/NAT，也没有
改宿主共享网络或增加第二运行权威。

## Linux 原生 DNS 连接与 WG 引用：后续纠偏和正式回读

后续同进程读回发现，较长运行后的数据面增长主要是匿名驻留，不能由文件映射、LazyFree 或 swap
解释。只限制 pool 空闲保留没有完成引用所有权闭环：WG 同步批量 I/O 后的局部 slice 仍保留旧 payload，
TCP DNS hijack 在读到上传 EOF 后也没有完成整个连接及路由回调的关闭。实际旧签名程序的隔离正式
探测复现了随请求重复留下的连接；原短时回读不能据此继续表述为长期内存验收完成。

源码 `8e53cee0` 清空已经结束同步 Send/TUN Write 的批次引用，不在 I/O 完成前释放字节。DNS 上传 EOF
先等待已接受请求的响应，再完全关闭连接及完成回调；读写失败或取消关闭并回收其工作，响应写入串行，
不靠强制 GC 或增加权威状态解决所有权问题。逐请求和逐次写入期限仍不等于整个并发 drain 的固定总期限。
模型对应关系见[客户端运行模型](clients/client-runtime-model.md)。原队列的真实 GC/错误/阻塞 I/O 检查、
DNS 并发响应/半关闭/取消/读写失败 race 检查，以及合并后的精确制品经隔离正式探测均通过；实际新连接
完成匹配响应和 EOF，重复探测未再按请求留下 FD。相关及规定的 Go build/test/vet、格式与仓库安全检查通过。

当前 Linux 制品使用组件发布坐标 `1.11.4-loom.14`，契约仍为 schema 3。既有已签 `.13` 的源码、BUILD、
目录和签名原件保持原义验证，不以新常量重解释它们；新增包只写当前坐标。新 agent、control 和发布器均
来自上述源码，两架构 Linux 签名包通过正式目录和公开 HTTPS 字节验收，其余平台原件复用。全部 Linux
经原私有期望、认证交付和正式更新入口实际消费；control 按管理入口依赖分组切换，客户端保持服务入口
和管理节点后切换。身份、密钥、floor、高水位、报告序列和不可回退 latch 分别核对保留。

执行器首次即时启动检查失败，后续精确进程和正常接口回读成立，加入有界就绪等待；首次未保存各瞬时
子条件，不确定具体失败子断言。请求初次使用非规范 JSON，由 CLI 在发送前拒绝，纠正为同一规范编码。
独立更新的首次连接截止原件保留，其具体 DNS/TLS 子阶段未
现场确定；同一私有入口只读认证成立后，同一输入重试完成，不推断是 OOM。早期境外业务请求也曾失败，
随后原 Auto 偏好、同一网络代下的两个既有授权目标均由正常 Mixed 入口成功；不重写首次失败记录。

全部实际 agent/数据面程序及固定进程的约定持续观察窗口通过，FD 未复现旧滞留形态；匿名驻留、PSS、
文件映射与 cgroup 计费单独留证，不把数据面的量称为整个节点内存，也不承诺更长运行绝无增长。
可达 control 的原管理员正常页面、组件、同 View 应用及签名附件回读通过，最终正常入口收到全部当前
报告；落后 control 的前沿和旧报告仍独立失败。全部本轮临时程序及不再引用的旧 control 程序叶子经
严格 systemd/proc 引用读回、摘要和 inode 比较后删除，当前程序与签名原件保留。停止的本轮 transient
worker 仅精确 reset-failed；模板读取失败和权限错误不会被当成无引用。`reported` 只投影当前快照确认，
不是不运行程序的所有权或退役前提，不能因清理完成制造网络成功。

共享 route/rule/resolver 与自有资源、远端新 SSH 和各节点基础连接已回读。此前本机检查继承旧会话
`SSH_CONNECTION`，不能抵扣独立新 SSH；本轮独立登录到达认证但现存凭据被拒绝，这项仍未完成。
另一个节点的外部防火墙表达式跨采样变化，实际操作者未证实，未恢复或修改其规则，不能称全部防火墙
跨时刻恒等。故宿主整体验收与落后 control 同步继续开放，不用局部通过关闭问题。

双端同窗口元数据仍将相关回程缺口限定在响应本机物理接口出站与指定中继物理接口接收之间；其它流的
双向包不能抵扣这些实际 tuple，出站 capture 也不能证明 NIC 后的 wire 字节。隔离实际互通证明 checksum
offload 的抓包标记不能单独判定报文损坏。操作者提供的安全组、交换机和路由截图没有证实必须新增出站
规则、NAT 或路由；本轮不登录或修改上游网络。真实坐标及云侧核对输入只存受保护证据，没有对外发送。
证据位于被忽略的 `deploy/evidence/2026-10-14-wg-return-followup/`；整体验收不标成功。

## 拓扑连线绘制与鼠标命中：正式更新和回读完成

源码 `e675d9ff` 只前向更新三个 control 程序。首跳资源及正反 LinkID 使用分开的确定曲线，
所选路径复用确切原边并只绘制一层蓝色笔画；透明实线命中范围不随可见虚线间隙变化。
Overview 与 Topology 离线生成后按身份更新原 DOM，保留悬停、固定选择和节点键盘操作。
桌面及窄屏原生 Chrome、拓扑与流量回归和仓库规定检查通过。

全部部署节点的当前身份、公钥与网络锚先经正式回读核对；本地源包独立验签后只分发必要控制程序，
独立成员并行应用，管理成员随后切换。首次管理成员回读误将 IPv6 RA 剩余有效时间的倒计时
当成路由变化，原失败和停服结果保留；仅纠正比较后以同一新程序恢复，不修改网络或回退原件。
首次浏览器中心采样未覆盖可选曲线段，原失败亦保留；按整条真实曲线回读后，三个原管理员
HTTPS 入口的两页均确认精确资产、单层路径、真实鼠标停留零拆卸、点击固定与 Escape、
历史刷新和原节点键盘操作正常，没有用合成节点替代生产页面。

持久服务入口与实际程序、身份和密钥、原事实和授权、floor、高水位、报告序列及 latch 保持；
客户端 PID、程序、数据面、安装接受代及公开目录未改变。路由、规则、DNS 与防火墙定义保持，
原偏好下的两个既有授权业务请求分别通过。临时上传、unit 文件、浏览器凭据和转发进程已清理；
仍由客户端引用的原程序保留。落后 control 的原观测与同步缺口仍单独开放，未借页面更新制造健康。
证据位于 `deploy/evidence/2026-10-14-topology-interaction/result.json`；本具体 UI 修复的部署闭环完成。

## 自动中继候选与真实动态选择：正式更新和回读完成

操作者指出人工 Link 清单遗漏合法节点对，并要求中继路由按 Service 的网络测量动态选择。
原实现把管理员维护的邻接当成候选前提，Link 观测主要供页面展示，当前路径成功后备选也缺少恢复
采样。这些行为不满足需求；不能只补一条人工 Link 或画出不存在的健康连接。

源码 `1dd50bdb` 从有效 Device 职责与独立 WG TransportResource 确定性派生有向中继段，
Service/Policy 决定允许的首跳、节点链和最终出口；LinkID 只标识精确段及其测量范围，不成为第二
权威。当前拒绝人工 Link 新写入，历史签名原件按原义保全，既存人工事实经正式签名删除操作退休。
独立 WG 与 Hy2 首跳终止协议后按同一权限投影转发，后续中继使用原生 WG，未恢复嵌套传输。
领域、wire、持久、运行时与 UI 对应见[控制模型](core/control-model.md)、
[私有观测交付](core/current-contract.md#私有设备的中继观测交付)和
[客户端运行模型](clients/client-runtime-model.md#observation-与可用性)。

设备从正式私有认证入口取得当前 View 范围内的来源原始 Link 样本，三端共用精确依赖的选择函数；
相关段失败只排除依赖它的路径，完整且较新的真实业务成功可以覆盖旧失败，段成功不生成 Service
成功。已有认证诊断入口公平轮转必要备选 HTTPS，不为测量切换生产 selector。远端缓存只在 RAM，
同 View/spec 与原截止校验成立才可消费；取件失败不改结果或延长截止，成功的新交付包括空集合均
整体替换旧范围，撤权、换 View 和过期后立即停止使用。缓存可删除，不新增健康 store 或完成判定。

实际扩大的候选集合在 Linux 启动链路触发原 selector 响应上限，Android 独立实现也有相同限制。
源码 `b1e477e5` 修正有界完整回读，并覆盖真实大候选响应及超限拒绝；Windows 共用 adapter
消费相同修正。发布器同时对同目标的独立 HTTPS 制品验证使用有界并发，保留全目标身份、完整字节
验证和指针推进门禁。灰线减淡减细、固定透明实线命中范围、稳定 SVG 身份、蓝色单层笔画及侧栏
顶部对齐一并交付；WG 栏明确表示共享 peer 的发送报文，握手、保活和探测不能证明业务可用，正反
LinkID 也不能相加计算同一 peer 的用量。

第 115 代签名目录及全部平台应用经三个原公开入口完整发布。六 Linux 客户端、三个 control
和既存 relay/edge 执行入口实际运行精确 `b1e477e5`；Linux 与 Android 原生组件沿用
`1.11.4-loom.14`，Windows 沿用其原组件。正式包升级、期望组件写入和全部正常 updater 的无变化
回读成立，没有借源码编号增加协议版本。原身份、密钥、已认证原件、floor、高水位、报告序列和
latch 分别保全，schema 3 不变，`.env` 与 SSH 输入摘要保持。

三个 control 已读回相同事实前沿、配置及全部当前运行组件。既存签名原件先经原成员认证差量接口
补齐，再由只读观察器捕获正常 daemon 的新报告从单成员传播到全部成员；原文与设备签名一致，
没有人工复制报告来证明持续同步。私有观测正式取件、候选依赖和实际选择的只读复核通过。
两个既有 Service 目标在原偏好下经正常 Mixed 入口完成真实 HTTPS；原遗漏节点对有自动双向段及
真实测量，其他失败或过期段仍如实显示 unavailable/unknown，不要求全图变绿。

三个原管理员 mTLS 浏览器入口确认精确资产、自动图、真实鼠标悬停/固定/Escape、历史回读及原
布局；临时凭据、浏览器和转发已清理。同机 Windows VM 的本轮临时执行权限也已恢复。Android
正式 APK 保持原签名身份、双 ABI 和绑定测试，Windows 六种签名包及同机验证通过；不称本轮
重新完成了手机或 Windows 实体机终验。

两类 Linux 节点分别验证正常停止、唯一当前数据面进程异常退出、精确所有权清理及同身份重启；
各停止/错误阶段的新管理连接与基础网络保持，恢复运行与报告确认成立。清理成功后 agent 可保留
认证修复通道并报告 error，不能被验收脚本误要求必然退出，也不能报告 running。首次脚本假设及
错误状态 CLI 的非零退出处理已纠正，原失败保留，未据此发布新的运行行为。

共享路由、规则、resolver 及独立基础连接回读成立。一个节点既存云安全代理维护的特定 ip/filter
链跨采样变化：现场实际进程、启动时间、二进制和供应方脚本证实归属，Loom 原生清理不写该链。
仅该链规则单独记录而不作恒等比较，其余防火墙对象严格保持；没有捕获每条变化规则的 syscall
执行者，不能把结果写成全量防火墙跨时刻不变。未登录或修改路由器/NAT、宿主网络服务或共享规则。

规定的 Go build/test/vet、格式、安全与差异检查通过。逐目标构建、发送/复用、HTTPS 验证和应用
耗时及全部失败原件只存受保护证据，不把发布等待无依据归因于带宽。汇总为
`deploy/evidence/2026-10-15-topology-correction/result.json`；本次自动候选、动态选择、拓扑交互及
授权生产更新闭环完成，外部链路可达性与既有实体终验边界继续如实保留。

## 拓扑单线连接与双向详情：正式控制程序更新完成

操作者确认将同一 WG 连接的正反中继段合为主图一条线，详情保留独立方向。源码 `cdc6d7cc`
只调整控制面只读投影、页面和必要验证；原 NetworkLink 的源/目标资源引用完整投影到 Web，
连接几何由规范节点与资源对、用途和传输确定。单方向缺失、状态更新及切换检查方向不重排连接，
不同资源、首跳及传输不误合并，没有新增领域身份、签名 wire、持久值或运行选路状态。

主图保留原方向 LinkID，悬停同时预览正反测量，点击固定连接；侧栏方向按钮和原深链接定位原始
方向，Escape 从图、侧栏和表格均能解除固定。方向状态和 RTT 不平均，差异标记只提示原结果不同。
蓝色只表示报告中的实际 Service 路径，复用同一连接几何并按实际方向标箭头；双向同时使用仍只
绘制一层笔画。节点聚焦保持关联线细，只加深正在检查的连接。连接表格一行保留双向状态/历史，
共享 peer 发送量显示并累计一次，切方向不更换共用计数范围；详情内容不再将左图拉成长空白。
具体映射见[拓扑可读布局](clients/web-ui-projection.md#拓扑的可读布局)。

相关真实 Chrome 验证覆盖正反合并、不同资源/用途拒绝混并、单向缺失、实际单层路径箭头、原节点
文字与桌面/窄屏布局、鼠标/键盘固定、反向深链接、方向按钮及 Escape、稳定 SVG 和命中区域。
签名原报告中的单向失败、反向成功 RTT、共用计数，以及后续独立测量和成功空历史替换均实际回读。
规定的 Go build/test/vet、格式、安全与差异检查通过。

本轮仅构建并独立验签一个控制程序；三个目标先全部身份与制品检查，再将两个独立成员并行应用，
最后更新管理成员。公开目录和六客户端继续保留第 115 代及原数据面，没有重发未改应用。
首次额外保全检查误将 systemd ExecStart 的动态时间/PID 元数据当作配置变化，按失败处理停止了
对应 control；实际客户端 PID、InvocationID、start ticks、程序及 unit 字节均保持。原失败、旧新
执行器与摘要保全后，只纠正静态参数比较并正常启动同一新程序，未回退、重打包或重复成功节点。

三个正常管理员 mTLS 浏览器入口均确认精确资产、全部原方向身份、合并连接、真实鼠标反向按钮和
侧栏 Escape、稳定 DOM、双向独立度量及每连接唯一发送量。全部 control 的实际程序及持久 unit
分别回读；六客户端进程、原身份/密钥/签名事实、floor、高水位、报告序列、latch、宿主网络和
公开指针保持。两个既有 Service 目标更新后在原偏好下经正常 Mixed 入口完成真实 HTTPS。
临时浏览器凭据、进程和转发已清理，真实桌面截图已查看；不由 UI 合并制造链路健康。

受保护证据为 `deploy/evidence/2026-10-15-topology-single-connection/result.json`，包括逐目标
发送/复用、应用及验收耗时和失败原件。本次单线呈现与双向详情的授权部署闭环完成。

## 拓扑观测线型与单向箭头：正式控制程序更新完成

操作者要求移除连接上的差异圆点，以线型表达当前双向 WG 检查。源码 `1fa56036` 仅修订
Web 单向投影：两个原方向均成功为实线，成功与失败并存为虚线并向成功方向标灰箭头，均失败
为点线；任何现有方向未知或过期为更淡的长虚线。缺失反向候选不补造失败，原方向详情、
来源、历史及共享发送计数保留。蓝色 Service 路径沿用线型，箭头只来自报告中的实际选择。
领域、签名 wire、持久身份、运行候选和选路没有变化，映射见
[拓扑可读布局](clients/web-ui-projection.md#拓扑的可读布局)。

真实 Chrome 的状态切换反例证实历史重绘可保留已过期的旧线型，现每次稳定重绘先调用原有效期
投影；不清除原历史或复活旧样本。像素反例还证实细灰线的端点箭头被节点白边完全遮盖，现使用
独立固定尺寸并移到白边外。桌面与窄屏的正反成功箭头均有真实可见像素，悬停不改变尺寸或位置。
状态等价类、原连接几何、独立命中、固定与方向切换、深链接和侧栏 Escape 的真实浏览器验证
通过；规定的 Go build/test/vet、格式、安全与差异检查通过。

本轮仅构建并独立验签一个控制程序，三个目标并行准备精确制品，再将两个独立成员并行应用，
最后更新管理成员。三个原管理员 mTLS 浏览器入口均核对实际资产、无差异圆点、四种图例、
现场有效样本决定的线型、灰箭头可见性和真实悬停，以及全部原方向身份与单次共享计数。
没有要求生产同时出现所有线型，也没有为验收制造观测。实际程序与持久 unit、六客户端原进程、
安装代、数据面、身份/密钥、签名事实、floor、高水位、报告序列、latch、公开目录和宿主网络
分别回读保持，两个既有 Service 在原偏好下经正常 Mixed 入口完成真实 HTTPS。
临时认证材料、浏览器、转发与抓包进程已清理，正式截图已查看。

本次只读双端诊断分别验证公网 SSH、ICMP 和当前原生 WG；公开 SSH 可达与 WG 内部 TCP 超时
可以同时成立。同时采样定位到原发起端未收到对端已发出的对应握手回包，具体外部设备与原因
尚未确定，没有由页面颜色推定全部协议失败，也没有修改路由器、NAT 或宿主网络。用户随后
提出的换端口对照按现有基础设施输入与真实监听另行核对，不能把建议写成已切换或已恢复。

受保护证据为 `deploy/evidence/2026-10-15-topology-link-states/result.json`，包括精确制品、
逐目标发送/复用与应用耗时、三个正常浏览器、业务请求和分范围诊断。本次拓扑线型的授权部署
闭环完成；外部 WG 返回路径的缺口不由 UI 更新宣称修复。

## 已授权的共享 WG 端口对照与恢复

操作者授权更换一个接收节点的 WG UDP 端口做对照，随后明确确认运营商会间歇阻断特定 UDP
端口连接，应按外部环境处理。本轮只对已有资源的 `dial_port` 签发一个普通 `resource.put`；
候选来自操作者已经提供的同号公网／宿主映射，正式提交前确认空闲与独立 SSH 管理返回路径。
请求只依赖当前资源和承载节点授权，完整保留资源 ID、owner、listener、认证公钥、地址及可选字段。
按实际普通事实签发语义纠正文档将资源与承载 control 专属入口合并描述的错误，没有改 wire、
schema、签发代码或既有原件。

正式 CLI 的规范请求经 daemon 接受、签名持久化后，由独立 `control inspect` 验签重放回读；
六客户端经正常认证配置刷新提交唯一新 LKG 并重建运行代。逐项实际回读确认每节点只有一个
共享 native WG endpoint、固定密钥、接口与 UDP listener，多个 peer 共用它；新接收监听和全部
对端拨号端口一致，其余资源、密钥、本机私有输入及安装制品保持。不构建或发布新程序，不手动
重启 client/control，也不修改 `.env`、路由器、NAT、宿主共享路由、DNS 或防火墙。

旧端口的两向正常 native 探测都在 WG 内 TCP 连接阶段超时，尚未发 DNS；同时元数据抓包再次
看到原发起包到达、对端回复发出，而发起网卡没有对应回复。新端口的两向真实 TCP 与认证 DNS
均成功，故保留新坐标。新采样窗口没有重复握手包，不能将已成功的业务往返写成现场抓到了新握手。
两个原 Service 在既有 Mixed 入口及原偏好下完成 HTTPS；两节点新的 SSH、宿主 DNS、公网 HTTPS
以及三个正常私有管理员 mTLS 页面回读通过，正常页面的新 scope 链路观测也已成功。

身份、认证 floor、高水位、报告序列、latch、原签名事实、安装指针、catalog 与父进程保持。
首次严格比对把本 generation 所属 WG 接口重建后的 resolver 数字 ifindex 当作解析配置变化；
原失败、执行器摘要和每次读回保留后，只归一化已证明拥有的接口展示编号，Global、其他接口及
DNS/domain/default-route 值保持精确比较。后续一个节点的既有云安全链恰有两条非 Loom 规则
被移除，无新增且其余定义相同；已保全精确差异与既有 provider 归属证据，不修复这些外部规则，
也不声称全量防火墙跨时刻字节恒等。原严格失败汇总没有被改成成功。

端口恢复继续复用现有资源、普通操作和观测，见
[切网、故障与恢复](clients/client-runtime-model.md#切网故障与恢复)。本段只记录显式端口对照，
不把人工修改作为自动触发成功；持续故障触发的自动机制及其独立生产验收见下一节。

受保护证据为 `deploy/evidence/2026-10-15-wg-port-comparison/`，包括正式请求与新事实、
前后双端测量、六运行消费、三个私有入口、业务请求、精确比较例外和清理。规定的仓库检查通过，
本次显式端口对照和成功坐标的生产保留已闭环。


## 故障触发共享 WG 自动端口恢复：现网闭环完成

操作者要求将运营商间歇阻断 UDP 端口作为外部环境自动恢复，并明确旧端口一周后可能解封。
源码 `636d3a8d` 已接通[控制侧端口恢复](core/control-model.md#wg-持续失败后的端口恢复)：
由现有部署执行器跟进自己签发的当前资源事实，同一方向持续的原生失败才触发，未知、陈旧与
停止不能触发。候选仅来自已有同号 UDP 映射，排除当前、占用与一周内失败端口，按端口循环递增。
冷却三分钟、每小时最多三次尝试；旧端口一周届满重新参与候选，不建立永久黑名单。
限频及失败避让由原签名事实、因果前序和保护的接收时间派生，重启不清零，没有新权威实体或 wire。

普通认证 `resource.put` 只改原资源的端口；共享中继节点经独立 SSH 和正式 `client sync -view`
领取同一认证资源，普通 access 保留现有私有刷新。每节点仍为一个共享 WG，身份、listener、固定
密钥及授权保持；新端口须取得原故障方向和此前正常方向同时有效的原生 TCP/DNS 成功报告，
并确认全部中继消费者当前执行。失败只在原头和承载节点未被替代时签发一次前向恢复，不回退认证进度。

完整仓库检查通过后，仅构建并独立验签一个控制程序，独立目标并行分发，再按两个远端成员并行、
管理成员后续的顺序应用。管理服务只增加本机设备状态目录的精确可写路径，已在实际 service mount
内通过正式身份与状态锁回读；没有重发客户端、数据面或改变公开目录。发布时间、发送和复用数量
均有逐目标记录，不将全部耗时归于网络传输。

真实生产验收先以一次普通资源修改切回已实证失效的旧坐标，重新得到持续原生失败；之后控制服务
自行选择空闲候选并签发新事实，监听和全部中继 peer 实际消费后，全部原方向恢复成功，没有人工
替它恢复。六节点实际配置、唯一 listener、peer、原密钥、父进程、认证 floor、高水位、报告序列、
不可回退 latch 及原签名原件分别回读；两个原 Service 的正常 Mixed HTTPS 与三个原管理员 mTLS
浏览器通过，正式拓扑截图已查看，临时认证材料、浏览器及转发已清理。

其余历史资源缺少首次接收附注时，先由实际身份、固定密钥与共享监听核验当前值，再通过正式入口
签发相同值的确认事实。新事实提供真实冷却起点；旧原件和缺失附注不改写，全部端口、资源值与
native generation 保持。管理 control 随后正常重启，独立成员保持管理服务，原自动事实和成功端口
保持，当前原生观测恢复且没有立即重复尝试，全部确认事实及限频依据持久存在。

一次严格回读发现既有云安全服务维护的 SSH 拦截规则在采样间变化。原严格失败与每次原始规则集
均保留；后续仅按实际 SSH 端口、精确源地址、TCP/UDP 配对及已核外部 owner 逐条归属，排除管理
与节点地址、WG 端口，其他规则、对象与顺序仍严格比较。没有修改这些外部规则，也不声称原始
防火墙跨时刻全量相等或已抓到具体删除进程。六节点新 SSH、DNS、公网 HTTPS、既有代理与管理
返回路径分别通过；本轮不修改路由器、NAT、宿主共享路由、DNS 或防火墙。

受保护证据为 `deploy/evidence/2026-10-15-wg-auto-port-recovery/`，包含精确源码与制品、
正常签名触发及真正自动事实、原生失败串与成功回读、同值前向确认、重启持久化、限定外部差异、
全部原失败、逐目标耗时及正常业务和浏览器验证。本次授权的自动端口恢复已完成生产闭环。


## Access configuration 四视图与共享探测池：实现与授权部署

正式 Web 源码按已确认原型统一为 Services、Policies、Private DNS、Probe targets 四个同级视图，
顶栏合并访问配置入口，保留原业务 URL。服务目录搜索覆盖目标域名和地址，策略可按服务筛选；
筛选不替换正在编辑的草稿。服务配置、共享影响与保存、关联只读回读分组，策略按入口、中继、
最终出口排列，Direct 独立，LAN 固定网关及原权限规则保留。DNS 展示系统/自定义来源并保留多地址。

共享探测池从有效 NetworkIntent 完整投影，含未使用和未匹配目标。范围匹配由同一服务端 matcher
计算，不扩大设备授权；新增、修改、删除复用原签名 operation、依赖与原请求重试。正式管理员
handler 下的真实 Chrome 已验证维护、回读、重启恢复、删除确认、响应丢失重试及慢完成导航。

验收另发现并修正两个具体问题：窄屏表格的原位编辑区继承宽表尺寸，现保持列表内部横滚且编辑
字段与提交按钮位于视口内；新增记录先经 live 刷新到达时，原无稳定键的表格行可能替换待响应
表单，现用现有对象 ID 派生 DOM 键保留表单。延迟真实 POST 响应的 DNS/Probe 回归验证原表单、
请求 ID 与草稿保持，响应释放后正常回读。宽屏和窄屏四视图、原服务/策略/LAN/DNS 操作均通过
必要浏览器验收；仓库构建、测试、vet、格式与安全检查按本次源码执行。

随后按操作者明确部署授权，将源码 `b647d3ba` 的同一控制程序构建、签名并由独立现行程序验签。
全部六节点身份与原运行基线通过后，仅分发所需控制程序；两个独立 control 并行应用、管理成员
后续切换，逐目标记录实际发送、复用、传输、校验及应用耗时。保留原自动 WG 端口恢复能力和
精确可写目录，只替换 control 的 ExecStart 程序路径，客户端、数据面与公开发布目录保持。

三个原管理员 HTTPS 入口均以原证书信任和 mTLS 完成四视图、导航历史、目录与分组、DNS 来源、
完整共享探测池及宽窄屏原位编辑验收，实际静态字节与冻结源码相同，截图已人工查看。生产既有
数据不含 LAN 策略、自定义 DNS 和未匹配探测目标，这些分支由前述真实 handler 浏览器测试覆盖，
未为部署验收写入演示对象。临时认证材料、浏览器及 SSH 转发已清理。

原两个 Service 的正常 Mixed HTTPS 在部署前后通过，偏好保持。六节点最终回读及独立严格证据
审计确认全部原 targets、签名事实集合与字节、control drop-in、既有挂载和静态服务属性保持；
身份、密钥、floor、latch、客户端与数据面进程、宿主网络及公开指针保持，认证进度单调。
受保护证据为 `deploy/evidence/2026-10-15-access-configuration/result.json`；本次界面部署闭环完成。

## 关联策略分隔线与未引用的错误固定出口策略

关联策略列表的最后一行原有底边框，与下一分组顶边框形成双线。源码 `7b9cc13b` 仅移除末行底边框，
保留中间行分隔与分组边界；独立验签后按原分组顺序部署三个 control。原管理员 HTTPS 的宽窄屏
实际样式、截图及全部身份、原件、客户端和宿主保全回读通过，规定仓库检查通过。受保护证据为
`deploy/evidence/2026-10-15-service-related-divider/result.json`。

操作者随后明确仅清理不能满足业务要求且未引用的固定出口策略。沿正式 CLI 提交三次
`policy.delete`，删除三条国内固定出口访问境外服务的历史迁移产物；全部删除前重新核对有效设备
和邀请均未引用。其余十一条策略，包括两个 Auto 的完整值、Direct、本机出网许可和出口范围，
以及全部 Service、设备 PolicyIDs 和业务候选 ID/spec 均保持原值；国内服务仍可使用国内出口。
本次没有提交 `policy.put`，没有重发程序或重启客户端。

三个 control 已同步精确三条删除事实；六节点完整 LKG、候选、实际原生进程和当前签名运行报告
保持，身份、密钥、floor、latch、原签名字节及宿主网络保全。三个原管理员 HTTPS 的目录、关联列表、
删除对象直达不可用及原 Auto 表单回读通过，临时认证材料和进程已清理。当前新增服务和设备的
正常入口不执行历史模板的批量展开。受保护证据为
`deploy/evidence/2026-10-15-intl-api-policy-delete-only/result.json`，本次限定清理闭环完成。

## 控制面轻面板与设备匿名显示名

按操作者要求，源码 `9df95d80` 为 Live paths、Access configuration 四视图与 Administration
四视图统一轻面板。目录使用浅底，完整编辑区或内容区使用白底，内部保留原表单、列表及分隔；
收紧间距，去除侧栏强制长空白，窄屏改为上下排列。Private DNS 与 Probe targets 保留单个记录
面板和原位编辑。十三张相关原型与生成器同步，其余原型字节保持；未增加领域或运行状态。

指定设备的显示名沿正式 `device.put` 入口改为操作者要求的匿名短名，仅修改名称字段；
原身份、私有授权字段、职责、策略选择、服务及候选 ID/spec 保持。三个 control 同步同一新事实，
六节点正常刷新消费后回读通过，未改写历史签名原件。原十一条策略包括 Direct 的完整值保持，
本次没有策略操作。

规定的构建、测试、vet、格式、安全与 diff 检查通过，真实 handler Chrome 覆盖宽窄屏表单、
路径详情、目录和 Administration 四个导航项边界。仅构建并独立验签控制程序，全部节点身份
基线通过后并行分发；两个独立 control 并行应用，管理成员随后切换。客户端、数据面、公开目录、
原 control 挂载及 drop-in 保持，原件、全部 targets、认证进度与宿主状态严格回读通过。

三个原管理员 mTLS HTTPS 入口分别验证十页的电脑与手机布局、精确静态字节、匿名名称及旧名
不可见，截图已复看，临时认证材料和进程已清理。首次浏览器启动读到尚未写完的调试端口文件，
原失败及清理证据保留；同一冻结执行器重新启动后完整验收通过。发布前一次 SOCKS 连接失败
同样保留，唯一同请求复测及发布后两个原服务 HTTPS 均成功，未为验收改变偏好或权限。

`deploy/evidence/` 中本次面板部署的 `result.json` 汇总受保护证据；本次布局、名称修改与部署闭环完成。

## 国外固定出口策略清理与发布摘要样式

操作者继续要求删除国外固定出口访问国内服务的策略。沿正式 CLI 仅提交三次 `policy.delete`，
删除前均核对设备和有效邀请未引用。其余八条策略、两个 Auto 的完整值、国内固定出口策略、
全部设备选择、Service 与候选 ID/spec 保持；三个 control 同步精确三条删除事实，六节点完整
LKG、进程、身份和认证进度保持，原 HTTPS 页面的目录、关联列表及删除直达回读通过。
受保护证据为 `deploy/evidence/2026-10-16-cn-foreign-policy-delete/result.json`。

随后按操作者要求，源码 `9128b911` 将 Releases、Device versions 及展开详情的真实摘要与
提交号改为 11 px、正常字重和较浅灰色，目录摘要保持 10 px；完整原值、既有截断与 title、
普通版本、文件名、验签/比较状态和下载操作保持。四张原型同步，其余原型字节保持。
既有真实 Chrome 的下载、复制与组件范围回归、宽窄屏视觉检查及规定仓库检查通过。

仅构建并独立验签控制程序，全部身份基线通过后并行分发，两个独立 control 并行应用后再切换
管理成员。三个原管理员 mTLS HTTPS 入口分别核对三平台、设备版本列表和展开详情的宽窄屏
实际字号、颜色、完整摘要与精确下载 URL；截图已复看，临时认证材料和进程已清理。
首次只读验收脚本将新增样式的版本提交号误作文件校验值，已保留原失败及固定修正后的精确字段
选择；实际源文件和发布数据未因该验收修正改变。后续全部检查通过。

两个原服务的正常代理 HTTPS 在发布前后均成功，偏好保持。六节点 LKG、客户端与原生进程、
原件和全部 targets、八条策略、身份密钥、认证 floor、既有 control 挂载与 drop-in、宿主状态及
公开发布指针严格回读通过；受保护证据为
`deploy/evidence/2026-10-16-release-digest-style/result.json`，本次样式调整与授权部署闭环完成。

## Events 候选位置查询：持久索引与正式回读

本轮从操作者报告的空白等待复核正式 Events 入口，确认报告原件已经落在 bbolt，旧查询仍按
整个窗口逐份处理报告；结果条数不能代表输入量。源码 `ec1db308` 在既有 `report-index` 内
维护可重建的候选原件位置，未建立事件正文库、持久验签凭证或扩大原有缓存预算。正常上传及
成员补历史在同一原件事务内重算相邻位置与最早序列，查询只从实际候选和紧邻前驱投影。
同版规范解码、完整领域检查、实际摘要/存储键和查询历史公钥验签继续执行；未消费的相同
运行报告不由页面承担整库完整性核查。模型、合法区间与拒绝边界见[现行契约](core/current-contract.md#events-运行变化的候选位置)。

完整受保护历史副本的冷/热及删除索引后正式重启重建，完整响应、所有事件顺序、分桶与摘要
均同修正前原件相等；原报告和接收附注全部逻辑键值流保持。乱序、迟到分叉、时钟回调、
旧前驱、窗口边界、最早序列改变、取消和消费原件损坏的必要测试，以及仓库全部规定检查通过。
离线回放未配置 Go 软目标的条件单独记录，不冒充线上服务预算下的测量。

精确 control 制品经既装独立验签器验证后分组发布，独立成员并行、提供管理入口的成员最后
接管；停 owner 后沿正式 `prepare-report-index` 初始化，再启动相同持久 unit。全部目标的实际
程序、正式查询、浏览器连续加载/筛选/完整 CSV、正常新报告回读及原实际业务通过。既存策略、
设备选择、事实、身份/密钥、认证进度、latch、客户端与数据面进程及公开发布指针保全。
实际耗时与固定窗口内容只进入 `2026-10-16-events-query-index/` 受保护证据，不承诺未来恒定延迟。

验收脚本的注入错误与一次缺少子条件响应的筛选失败保留，后续原门槛验收及独立审计不覆盖
这些原件；一处旧版原生查询未取得响应，不宣称该入口完成旧响应逐字比较。未部署节点的
外部 SSH 来源拦截规则在巡检间继续追加，完整宿主比较失败与写入者未知均保留；只读新连接
及限定范围审计确认管理、Loom 监听和其余客户端保护值不受影响，没有改写防火墙或基线。

## 共享设备入口失联与前向端口恢复

操作者发现 Topology 的运行报告与方向观测全部未知。正常管理员回读确认，各 control 保存的是
同一批过期报告，客户端仍在运行并推进报告序列。唯一公网设备入口的 TCP 可以建立，但 TLS
无法完成；入口转发节点到私有 control 的 WG 管理连接超时。限定双方地址与用途的元数据采样
看到握手请求到达转发节点、响应从其物理接口发出，却未到达接收节点物理接口。双方密钥、
管理地址、AllowedIPs、host_sources 与实际监听一致，适用宿主规则没有拒绝该流量；具体外部
丢弃位置仍未知。保留日志显示，故障窗口内独立 Hy2 服务与 Loom 数据面均未重启，未发现端口
冲突，不能将此次中断归因于 Hy2 重启。

接收端端口对照未恢复通路，随后沿正式操作用新签名事实恢复原值，原失败证据保留。操作者
明确批准发送端使用已核空闲的备用 UDP 端口后，只修改同一 WG 资源的 dial_port，经正常 daemon
签名持久化和独立 CLI 验签回读，再由既有 SSH adapter 并行交付各设备的认证 View。实际共享
listener 与全部 peer 消费新坐标后，原公网入口的 TLS、设备认证、配置领取及正常报告恢复。
身份、固定密钥、认证 floor、高水位、报告序列及 latch 保留，没有修改历史签名原件或恢复旧配置。

正常私有页面回读全部设备的当前 running 报告，后续报告序列继续增长；方向观测仍分别按原
样本时效显示，不要求全图可用。原业务 HTTPS、基础网络新连接、正常停止与显式重启、原生子
进程异常退出后的精确清理及显式恢复分别验证。清理成功后，既有 daemon 允许以 error 保留
认证修复通道；首版临时验收错误要求整个 service 退出，原失败保留，没有据此修改运行模型。
最终页面取得了晚于恢复后独立回读的新报告，不用重启前样本抵扣恢复。

仅本次明确拥有的运行代变化及计划中的客户端恢复操作发生；程序、成员、权限与其余服务保留。
宿主地址和路由的有效期动态值逐项核对，外部 SSH 防护规则的变化逐条审阅，没有忽略整个链或
声称已确定具体写入进程。没有改写路由器、NAT、共享 route/rule、DNS、防火墙或发布制品。
没有提供实际工作负载的远端物理 LAN 仅完成原地址、路由与邻居回读，不冒充应用验收。

本次恢复没有增加独立设备入口。原自动端口恢复仍依赖已到达 control 的新鲜签名报告；唯一
入口也经过故障 WG 时无法得到触发证据，这一部署限制尚未消除，不能把手工认证恢复称为该
场景已能自动恢复。受保护证据在 `deploy/evidence/2026-10-18-topology-repair/`，包括原失败、
前向恢复与批准后的事实、逐目标交付、独立基础网络回读、生命周期及最终正常浏览器结果；
临时认证材料和交付文件清理后只保留必要受保护证据。

## 私有入口、请求切换与控制恢复纠偏

共享入口恢复后，继续按实际设备请求、成员传输与部署入口核对故障传播。确认原部署只保留一个
device/bootstrap 入口，三个 control 并不自动产生三个可用设备入口；配置领取、报告与恢复所需
观测因而共用同一故障路径。源码现将候选成功边界推进到完整认证业务响应：HTTP 错误、过旧或
无效签名 View、无效发布原件继续尝试其他入口；报告只保留一次序列预留和同一签名原文。发布下载
在原更新磁盘工作区按候选验长度与摘要，确认后才写入调用者，失败正文不污染后续候选。

认证 DNS 使用一个总预算、有界并行 resolver 与 A/AAAA 查询；保留可用地址族并关闭失败连接。
本机 control Authority 与 Unix 管理入口不再依赖 client status、WG 地址或全部 TLS 用途同时成功，
每个网络地址独立恢复。已给公网坐标可经透明 ALPN edge 承载原私有认证协议，网站仍由原 Nginx
服务。证书诊断覆盖所有 serving 模式，不再只显示网站根，页面继续用既有定时投影显示到期。

既有 SSH 恢复执行能力消费任一有效成员签发的资源事实，不再要求最后签发者必须是执行机自身。
这没有复制部署凭据，也不能把单一执行工作站离线解释成具有另一套恢复执行能力。安装清理先核对
实际进程与全部受管 unit 的程序引用，未知则保留并报告；无变化更新可再次清理已解除引用的旧程序。
身份、原始签名事实、认证进度和既有不可回退保护不因这些修订改变。

生产已为各 control 增加使用既有公网映射的独立设备入口，并经正式签名事实交付全部当前 Linux
节点。成员的域名地址使用本机 Authority 中当前授权的认证 DNS，不再读取客户端运行状态或宿主
解析器。完整配置领取及各独立入口的原签名包下载、长度与摘要、签名和规范编码分别回读通过。
冷包校验首响应超过旧期限的真实反例已修复；请求保留独立首响应与正文停滞期限、有界候选和
后续入口预算。服务端取消贯穿磁盘捕获、规范校验及可取消的现有缓存互斥，不持久化完成凭证。

control 保持已验收的 `642c80bc` 精确程序；Linux 随后经正常 Sync/Update 前向更新至第 118 代
`eeefc7c2`，实际进程和新签名报告已回读。Android 与 Windows 复用本轮已验证的 `74119bc0`
原签名应用字节，数据面和其他未变制品保持，没有重签或重复构建。各发布目标的身份、实际文件、
规定 HTTPS 验证与指针回读分别成立，设备期望在发布完成后才经 daemon 正式写入。

其中一节点首轮更新遇到三个入口读取超时，未安装新程序，原程序保持运行；全部并行任务结束后，
仅该节点通过正常入口重试同一已签包并完成前向更新。原失败、其余节点的成功与唯一重试分别保存，
未重发已接受的组件事实、降低认证进度或重复安装其他节点。

最终正常窗口另外证实：原 Link 采样周期与三十秒有效期相等，上传和成员复制的正延迟会造成
周期性 unknown。现 Linux 默认十五秒刷新，原有三十秒时效上限保持，为正常交付留出有限余量；
自然签名报告的连续轮次、全部 control 的消费及原业务和基础连接分别回读。未延长旧样本、未放宽
UI 时效，也不保证超时或丢失报告仍有当前结果；额外本地回读、报告和轻量链路检查机会约为原来的
两倍，成功业务探测仍复用原有效期。真实浏览器等待概览及所选连接的流量历史 API 和 DOM 完成后
再截取，已签计数与相邻增量正常；此前截屏中的 Loading 不被解释为没有采集数据。

代表控制节点正常停止客户端、清理其拥有的 WG 后，重启相同新 control，本地管理、原管理员
浏览器及成员通信仍可用；出站域名验证实际调用生产 PrivateChannel 与当前认证 DNS。其余节点
在故障后产生的新签名报告可从各 control 回读。另一节点的唯一原生子进程经精确身份核对后异常
退出，拥有的网络对象被清理，处于 error 状态的 daemon 继续报告；显式恢复相同已接受程序后，新 running
报告与原业务恢复。正常停止、异常退出及恢复前后的新建管理、DNS、公网、既有代理与 WireGuard
连接分别验证，原 timer 的 enabled/active 状态精确恢复，没有改写共享宿主网络或路由器/NAT。

宿主既有 SSH 防护链在验收窗口出现条目变化。已核对当前防护程序及历史归属，逐条检查保护地址和
端口，并证明其余定义与顺序相同。原变化保持；未现场捕获写规则进程，不把归属核对描述为写入跟踪。
限定范围、原快照与正常新建管理连接的实际结果分别保留，不忽略其他防火墙差异。

最终各原管理员 mTLS 浏览器分别核对真实 Topology、证书诊断、既有导航及精确静态字节，截图已
复看，临时认证材料、浏览器进程及 profile 已清理。失败或未测的方向继续显示真实三态。旧共享
入口在核对当前设备与邀请均不再依赖后，经正式排空、真实会话归零门禁与退休完成退出，专用
转发启动项清理；钉住的原证书与密钥保留，未被原地续签。公网站点使用操作者已有的
有效续签链，未新增 ACME 或 DNS provider。原端口范围的迁移遗漏已从受保护历史与既有授权核对
后修正为严格本机输入，未修改外部映射。

旧内核缺失状态字段由规范 kernel flag 核对，用户进程终态须证明整个线程组已结束；未知或权限
错误仍保留旧程序。实际仍被 edge/relay 引用的精确程序继续保留，未引用的旧启动模板与被替代
页面读回路径已删除。既存身份、密钥、签名原件、floor、高水位、报告序列及 latch 保全。

本次闭环与原失败、前向重试和逐目标耗时保存在 `deploy/evidence/2026-10-18-resilience-fix/`。
单一 SSH 执行工作站离线仍有执行可用性成本；未提供实际目标的远端物理 LAN 仅作元数据回读，
Android 实体及 Windows ARM64、真实睡眠与物理切网终验仍独立保留。未据此宣称所有外部链路或
实体平台完成验收。

## Web 历史指标的重复计算与逐步显示

历史遍历现对同一实际原件只计算一次摘要并完整解码一次，流量、Link、运行状态、服务路径及
端口恢复的既有读取复用该临时值。规范检查、精确公钥验签、位置核对、分叉、时间与序列缺口
语义保持；不增加完整报告缓存、缓存预算或后端并发。

Overview 只请求各授权设备的历史，设备行与网络发送量共享结果并逐步显示。汇总保留来源截止
范围、UTC 小时和部分覆盖，未读与失败不补零；历史读取有有界期限，显式重试替换原请求，迟到
结果不能恢复已撤销范围。宽屏及窄屏保留原卡片与拓扑交互。

相关原件、验签及并发测试、代表性合成历史基准与四项真实 Chrome 验收已完成；全库构建、
测试、vet、格式与仓库安全检查均通过。检查与精确制品准备的证据进入
`deploy/evidence/2026-10-20-metrics-history-optimization/`。
用户授权上线后，首轮已前向激活两台独立 control，原身份、客户端、成员认证通信和宿主基线
回读通过；真实管理员浏览器仍未完成全部设备历史加载，因此管理 control 保留原程序，未称本轮
生产验收完成。进一步正式查询确认同一设备的大报告历史持续超时，已返回的其他响应通过原
前端校验。源码继续复用已规范验证原文构造验签消息，删除冷验签中的重复完整校验和编码；
没有延长期限、增加缓存预算、删除历史或回退已激活程序。后续从各节点真实旧程序坐标前向替换，
须再次通过三台的正式页面、性能、原报告与重启回读；不能以合成基准抵扣生产结果。

第二轮独立成员的正式管理员页面仍有历史读取超时，管理成员继续保持原程序。进一步核对确认
大观测报告的热查询仍反复构造与 WG 统计无关的观测集合，后台中继观测交付也反复计算同请求
的 View 摘要。修订只在实际原文字节摘要及精确验签键命中原有 proof 时解析临时 WG 统计字段，
并在单次交付内复用成功绑定的 View 与摘要；冷路径、公开校验、逐报告签名及当前授权保持。
祖先资源检查未证明额外配额或持续内存回收，未据此调整资源限制；不同观测窗口的 I/O 与 CPU
样本分别保存，不以它们代替失败查询的同窗归因。修订的全库构建、测试、vet、格式及仓库安全
检查均通过，下一轮精确制品的真实页面验收仍待完成。

随后两台独立成员的页面仍未取得全部设备历史，管理成员继续保持原程序。同版本受控慢查询
及用户态采样确认，后台 View 投影与配置签发仍占主要计算，另有同窗缺页读取等待；没有把
这些不同维度相加或统一归因为带宽。进一步修订 Envelope 校验内部重复的 View 校验与编码，
保持原规范 unsigned、摘要域、签名域与全部拒绝约束；尚须完成对应检查和真实页面验收。

## 配置投影、WG 小字段与三端报告生成

用户批准将工作量从逐请求完整重建转移到认证输入变化及报告提交边界。配置复用同一输入下的
View、摘要、证明、前沿及规范签名响应，输入变更、撤权、阻断或发布材料失败不能命中旧值；
Link 只读取接收者当前范围的来源，当前执行及有效期仍逐次核对。配置与原件校验共同保持原总内存预算。

WG 历史改读报告提交事务内派生的小字段，每份原件都有对应行，无计数及分叉不能省略。
当前授权、公钥、时间与原增量算法继续逐次计算；不增加统计结果缓存、小时聚合或追加快路径。
原件保留，旧正文后续损坏由明确的离线完整性检查或重建发现；维护命令新增互斥的只读检查与原子重建。

Linux、Android、Windows 只将报告生成时尚有效的全部候选观测复制到新报告，保留本地缓存、
失败恢复排序及原样本时间。未首报便过期的远端诊断缺失为已确认取舍。Android 报告内部时间保留
固定毫秒精度；报告 schema、旧合法原件及重试字节不变。应用交付坐标前进，不升级协议。

定向并发、取消、撤权、历史键、原子重建与三端过滤检查通过；共享移动模块完整测试与 vet 通过。
全库构建、测试、vet、格式、安全及 diff 检查均通过，渐进显示与报告更新并发的浏览器回归通过。
后续源码 `0289c6aa` 修正 WG 定位仍触及大原件页、配置内存重复收费及 snapshot 重复 View/摘要的问题；
`cd986592` 进一步让一次私有配置构建只严格编码一次 View，其余规范字段、证明、前沿、摘要与签名
检查保持。公开入口的接受和拒绝边界不变，没有后台预热、两阶段缓存或增加预算。

第 121 代目录已沿正式入口完成发布，Linux/control 的实际程序为 `cd986592`；Android、Windows
应用精确复用 `b533e557` 第 119 代字节，未变数据面保留，不能称全部平台由追加控制端源码重建。
独立目标的身份、精确制品及规定 HTTPS 检查通过后才推进公开指针。六台 Linux 沿正常升级入口
消费新程序，三个 control 各自回读每设备两份自然推进的新报告；身份、密钥、认证进度、latch、
既有网络及业务保全通过，拥有的临时文件已经归档并精确清理。
一项升级的 SSH 回执先中断，独立只读回读证实原正式更新自行成功；原失败与实际恢复分别保留，
没有重放更新或补造原成功摘要。既有宿主安全代理增加的两条拒绝规则只在实际快照的分析副本中
逐条资格化，其余防火墙顺序和网络字段严格核对；没有修改宿主网络或暂停该安全代理。

Android 在隔离模拟器完成正式原位升级、独立 WG 的真实 HTTPS、撤权与重授权、新报告、停止及
control 重启后的管理回读；原身份、进度和报告原件保留。Windows amd64 的 Installed、Portable TUN、
Portable Mixed 完成正常 GUI、独立 Hy2 的真实 HTTPS、报告、重启与停止；旧 MSI 的正式原位升级
及 DPAPI 身份和认证进度保全通过。测试 fixture 的领域重新投影修正与产品制品分别绑定；先前失败
和仅测试 overlay 的来源继续保留。同机模拟环境不抵扣物理 Android、ARM64 原生执行、真实睡眠、
物理切网及显示硬件终验；额外旧 Android 基线的独立故障恢复失败也不计为通过。

新 Linux 报告持续运行后，已完成三台 control 各一次精确进程重启首访及两次不同文档刷新的正式测量。
管理成员全部通过既定加载目标；独立成员刷新通过，重启首访仍未通过。全部成员的实际恢复、身份、
网络及临时凭据清理通过，但性能结果仍为失败；不能以发布、功能或刷新成功关闭性能工作。
同窗资源采样将主要冷增量定位到 WG 派生行的磁盘缺页，静态模块逐层发现也占用首值时间。

当前追加修正只改变可重建索引及静态交付：同一完整原件键仍对应一行完整字段，使用严格紧凑编码与
固定页填充率，按稳定序列定位，保留最高位置、分叉、时间和原统计算法。受保护副本的全部字段往返
及相同窗口完整结果对照通过，读取页量和 CPU 均下降；这些本地结果不能替代 VPS 和生产页面验收。
导航 HTML 并行取得已有模块，静态 gzip 确定性派生，不增加跨请求压缩缓存或更改 API、TLS 与交互；
实际 handler 的浏览器对照、原渐进与公平加载回归及静态 HTTP 语义检查通过。
追加控制程序 `3291d7f7` 已完成精确签包、受保护重建、完整验签、非 WG 数据对照与三成员激活。
同 VPS 的独立原件和紧凑副本冷查询结果一致，实际读取量下降；临时查询副本及部署文件已归档并精确清理。
随后真实浏览器完成三成员各一次进程重启首访与两次刷新：全部历史显示达到目标，独立成员首值仍未达到，
不能以整体历史或刷新通过关闭工作。各成员恢复、身份、认证进度、网络及客户端与公开目录保全通过；
另有非 control 节点在发布后停止报告且既有管理路径不可达，不能把先前的新报告验收当作当前仍持续上报。

下一修正仅针对导航所需 snapshot 与静态下载串行、首批冷历史争用，以及成功 snapshot 的交付体积。
模型先明确正常导航内同一次 preload 消费、原错误与刷新路径、首值预算内暂用单槽并在预算到期恢复
原并发，避免挂起首范围拖住其他设备；HTTP 压缩只改变成功 Web snapshot 的交付表示。
不再改 WG 编码或重建数据库，不更新未修改的客户端、期望组件或公开客户端目录。
正式实现仅保留 HTML 的单次 snapshot preload、既有历史队列的预算调度和成功 snapshot 的流式 gzip。
浏览器对照确认单次请求、no-store 后续刷新、原错误重试及挂起首范围的后续进展；相关渐进、公平、实时
更新与业务表单回归通过。随后控制程序 `c86c52dd` 在三成员激活，精确程序、客户端、公开目录、
身份、认证进度及网络回读通过。操作系统文件页较热时，三成员的进程重启首访和刷新均达到目标；
另在分组停服、确认原数据库及独占锁后，仅对该数据库提交页缓存驱逐建议，再启动原精确程序。
同窗读取、缺页和磁盘等待确认了实际冷页成本，独立成员首值仍未达标，全部历史显示达标。
两组九次结果、恢复和清理分别保留，热页通过不抵扣冷页失败，也不声称宿主或物理存储完全冷启动。
三成员的导航 HTML 另经真实私有 HTTPS 浏览器补读，解压正文与精确制品一致；非 control 设备
报告未推进及既有管理路径不可达的缺口仍阻止全部设备自然新报告验收。

进一步核对确认管理快照和 Link 范围验证在缓存未命中时构造完整签名配置，随后却仅使用 View 与
摘要。下一修订在同一缓存键、LRU、预算和有界共享构建内独立复用严格 View 与规范片段，正式配置
请求才按需完成证明、前沿、签名及完整响应；没有第二缓存、持久字段或页面专用生命周期。
正常配置 wire、客户端和数据库编码不变；相关全库检查通过，控制程序 `d7646b02` 已在三成员激活。
相同数据库冷页口径的正式浏览器首访及刷新已执行，独立成员之一首值仍未达到目标，不能关闭性能工作。
同窗采样仍显示首个历史读取的主要增量来自缺页及磁盘等待；静态模块已在 snapshot 完成前取得，
没有据此继续增加前端状态、延长预算或降低报告频率。

本轮进一步将 WG 小字段投影中重复的静态字段，按规范内容摘要在同一子 bucket 内共享；
每份原件的采样行保留全部动态原值，重构后仍运行原统计算法，布局变化不制造间隙。
这是可删除重建投影的无损物理表示，原件、schema、签名、公钥及认证进度不变。
编码往返、历史等价、布局损坏与重建事务风险定向检查和全库构建、测试、vet、格式、安全及 diff
检查均通过，检查前后源码字节一致。前述三端报告过滤、逐步显示、导航交付及按需配置签发的
已验证结果继续保留；未修改的客户端、原生制品、期望组件与公开客户端目录不重复发布。

受保护真实数据库副本已沿正式维护入口完成完整原件验签重建、只读验证，以及仅排除 WG 子桶的
全部非 WG 结构化摘要核对。本机演练与同 VPS 独立副本对照均得到新旧冷、热四份完整查询结果
摘要一致；VPS 对照的查询读取、缺页和 CPU 均下降，但此查询结果不抵扣生产页面验收。
本机还记录了三份自有数据库副本的定时磁盘占用观察峰值，该观察不构成物理存储峰值保证。
临时查询副本的小文件与原始结果已耐久归档，完整数据库复用同摘要的受保护原件保全，随后按
完整清单和文件身份精确清理；原演练和分析记录保持原字节。

精确控制程序 `9e081dbe` 已按独立成员组、管理成员组完成停服、原库保全、完整验证重建与激活。
每成员的正式认证、新管理连接和既有业务回读通过；身份、认证进度、原件、非 WG 数据、客户端、
公开目录与既有网络保全通过。本次拥有的临时部署文件已在耐久归档核对后精确清理，旧程序保留。

在正常后台报告持续运行时，三成员各一次重启首访及两次不同文档刷新均已真实完成，九次全部达到
既定首设备数值和全部历史显示目标。首访前分组停服、核对原数据库及独占锁，只对该数据库提交
页缓存驱逐建议；实际读取、缺页和磁盘等待另有同窗记录，不声称宿主或物理存储完全冷启动。
实际进程、身份、认证进度、网络、浏览器凭据、临时配置和采样清理均核对通过。

全部设备功能验收仍未通过：非 control 设备的新报告未自然推进，既有管理路径最新只读复查仍
不可达。操作者随后明确说明该设备当前无可用流量，预计北京时间 2026-11-01 恢复；停止原因已有
操作者说明，设备当前身份、运行状态及恢复后的新报告仍待现场回读。历史失败与原始测量保持，
不据预期恢复日期改记通过。物理 Android、ARM64 原生执行、真实睡眠、物理切网及
显示硬件终验仍缺；额外旧 Android 的独立故障恢复基线失败继续保留。九次性能通过不抵扣这些
业务缺口，本工作保持未完成，不能据此关闭。真实坐标、原始报告、测量、各目标退出和失败记录
只进入受保护证据；本轮完整索引位于既有指标优化目录的
`implementation/control-shared-wg-001/overall-result-001.json`。

## 设备策略路径可用性与历史自动更新

设备访问策略表、策略选择项及已选摘要已补齐设备范围的路径可用性、原因、候选计数和 Live paths
链接。结果仅来自同设备当前已应用 Policy、报告模式和现有完整业务路径观测；全部失败显示不可用，
仍有成功候选显示可用，缺失、过期及未应用草稿保持未知。当前实际选择的业务结果单独保留，
不修改 Policy 授权，不因运行故障禁用合法选项，也不增加 wire 或持久状态。

运行、Link、WG 流量及路径历史在正常读取时移除重复 Refresh/Reload，只在读取失败或汇总部分失败
时保留 Retry；新报告仍自动更新。正式报告到页面的故障、恢复、到期与草稿保留检查，以及相关
浏览器回归和全库构建、测试、vet、格式、安全及 diff 检查均通过。

控制程序 `8fc23e0e` 已按用户授权只部署三个 control。全部目标身份和精确签名字节通过后，先并行
更新独立成员，真实管理员浏览器回读通过后再更新管理成员；各成员实际进程与全部静态资源摘要一致。
三个真实认证页面均回读策略三处提示、详情导航、历史图表及自然报告更新后的表单、审阅依赖、焦点
和选区保留；桌面和窄屏检查通过。生产当时没有全路径失败的策略，未伪造线上故障代替本地正式报告
测试。原身份、密钥、认证进度、latch、权威事实、客户端进程、公开目录及宿主网络前后核对通过，
没有数据库维护、期望组件写入或客户端发布，临时上传和浏览器凭据已精确清理。

部署原始证据位于被忽略的 `deploy/evidence/2026-10-21-policy-runtime-ui/`，汇总为 `result.json`。
此前已确认的非 control 流量耗尽与不可达情况保持原记录，该节点不在本次写入范围内；本次展示部署
验收通过不抵扣前述设备恢复、原生终验及既有指标工作尚未完成的业务缺口。


## 客户端可选策略集合与按服务选择

本轮将设备 PolicyIDs 改为可选授权集合，同服务多策略可同时授予；本机 Preference 按服务保存
PolicyID 或待选记录。首次单策略初始化、首次多策略待选、增加授权保持选择、撤权后重选和重启
恢复由同一模型表达。候选身份、各传输的凭据与接收规则绑定完整 Policy，不拼接不同策略限制；
待选与没有路径的服务从默认拒绝的 selector 开始。策略内选路沿用现有观测算法。

控制 Web 保留多选标签及草稿交互，删除同服务替换拦截与 Deny 创建/转换入口。历史 deny 原件、
已有引用和原拒绝语义可验签回读，当前签发入口要求先撤回引用再删除。Android 与 Windows 保留
配置管理、连接及既有样式，使用按服务策略选择替换全局模式；Linux 提供 policy list/select。
签名 policy_choices、实际 PolicyID/CandidateID 与业务结果分别投影；未使用策略保持未知。

显式一次性迁移保全原身份、密钥、签名配置、本机偏好、高水位、报告序列及 latch；旧 Auto 对原
单策略服务保留选择，Direct/固定出口仅在完整规则等价时转换，否则待选。正式 device.put 及更高
认证事实前沿是新配置签发前提，同前沿异 View 检查保持。正常启动不读取旧运行表达。

授权、规范编码、历史字节、迁移失败重试及生命周期回归通过；全库 Go 构建、测试、vet、格式和
浏览器回归通过。隔离 Linux 真实代理连接验证了待选拒绝、切换只关闭变更服务、另一服务既有连接
保持，以及撤权/重启不自动重选；独立 WG、管理返回路径、共享入口与 LAN 撤权原生检查通过。
Android 模块、lint、APK 与测试 APK 构建通过；隔离 Emulator 验证正式加入、VPN/Hy2 HTTPS、
撤权后重选、双服务策略切换、国内服务连接保持、停止与重启恢复。四份策略回读匹配原始签名报告，
完整原件独立验签通过。正式签名 APK 又在同一 Keystore/配置上完成策略切换、真实 HTTPS、
停止和进程重启验收，使用匹配 Release variant 的测试包，不替换产品 APK 或清除身份。
Windows VM 的原生界面与失败关闭检查通过；精确 MSI、Portable TUN 和 Portable Mixed 分别完成
正式界面加入、双服务业务、策略切换、另一服务原连接保持、原始签名报告、同 DPAPI 身份重启及
正常退出后的路由恢复。虚拟机正常关闭，测试身份与磁盘保留。

源码 `333fa6e8` 的精确制品已按发布坐标 `122` 发布。本轮范围按操作者明确要求限定为其余可达
节点；全部目标身份通过后并行暂存，control 先并行更新独立成员，认证浏览器回读后再更新管理成员。
各设备经正式 device.put、签名 View 导出、显式一次性迁移和原安装入口激活，重启后选择、精确程序及
签名报告回读通过。原身份、密钥、签名字节、发布 floor 与 latch 保全，认证高水位和报告序列未回退。
全部原配置发布根与认证 HTTPS 完整核验通过后才推进指针；随后仅更新变化的 agent 期望，现有数据面
引用保留。全部 control 已回读实际组件与期望一致，暂存输入经精确文件核对清理，迁移原件留在受保护位置。

已迁移工作站通过正式 Web 同时保存境外最优与固定德国授权；客户端原选择保持。正式 CLI 两次切换
完成实际业务请求，国内服务原 TLS 连接及 daemon 保持；恢复原选择后，签名报告与全部管理员页面回读
一致，未使用策略显示未知。宿主 LAN、DNS、默认公网、既有 HTTP proxy/WG 及新的远端 SSH 回读通过。
额外本机别名 SSH 登录被现有密钥授权拒绝，未添加密钥或修改 SSH 配置，该项新登录仍待操作者补验。

额度耗尽节点的原因已有操作者确认；本次未写入该节点，授权和期望保持，待下月恢复后单独迁移发布，
不能计为已验收。物理 Android、ARM64 原生执行及实体网络、睡眠和显示硬件终验继续开放；其他旧客户端
需先完成自身迁移及版本回读再授予同服务多策略。本轮实现与已授权范围的发布结果不抵扣这些缺项，
工作保持开放。真实材料、首次失败、重试及成功原件仅进入受保护证据
`deploy/evidence/2026-10-22-service-policy-selection/`，以其中的执行结果索引对应实际范围。

## 周期配置领取与远端日志空间

周期领取现在比较已认证 LKG 的完整成员证明、事实前沿和 View 摘要；签发成员不同不改变该传输比较值。
当前身份、授权、发布材料及输入检查通过后，相同配置只返回绑定该摘要的空确认；配置或认证进度变化仍交付
完整签名 envelope。配置及 Link 观测的成功正文沿 HTTP 协商流式压缩，原 schema 3 签名与规范字节保持。
Linux 纯服务节点停止领取没有选路消费者的远端 Link 样本，自身探测和报告频率保持。

相关认证前沿、不同签发成员、撤权、错误短确认、压缩截断与签名拒绝检查，以及全库构建、测试、vet、
格式、安全和 diff 检查通过。检查首次误遍历受保护归档中的旧源码，随后在原件目录外增加可删除的 Go module
边界，原归档字节保持；初次失败及后续完整检查分别保全。

控制程序 `88b23d29` 已完成独立验签、分组激活、原管理员 HTTPS 浏览器及实际进程回读。此前仅替换中控时，
原客户端进程与公开发布指针保持；身份、密钥、认证进度、原报告库 inode 和私有入口保全。

可达远端的旧系统日志已轮转、压缩并逐文件验摘要后清理原件；部分压缩原件在工作站保全，其余保留在各节点
受保护归档。后续活动 journal 设置容量和保留期限限制。遗留上传仅在逐件确认正式目录保有相同字节、
且无进程引用后精确删除。跨机归档中断、局部暂存及首次回读解析失败均保留证据，后续按实际结果续做，
未重施已成功的程序分发或服务切换。额度耗尽节点仍不可达，未进入写入及清理范围。

操作者随后明确授权可达 Linux 客户端升级和重启。第 `123` 代沿正式发布入口完成全部目标身份、
原件与规定 HTTPS 校验后推进公开指针，再经 `control write` 只更新变化的 agent 期望。
数据面及其余平台原件和组件引用复用。独立客户端并行消费私有签名交付，全部 control 连续回读新报告后，
才升级提供管理入口的本机客户端；原 Mixed 配置、身份、密钥、认证进度、latch、业务权限和用户选择保全。
WG 只重建本代明确拥有的接口和精确路由，宿主其他网络定义保持。全部实际进程、接受 manifest、
当前 View、应用摘要和连续推进的签名报告一致；正常无变化 updater 再执行没有重装或重启，并完成安全的旧程序清理。

初次发布源缺少上一代签名目录，使未变制品进入完整下载验证；在任何指针推进前中止后，改用保有两代原件的
已认证发布根，目标文件全部复用。验收脚本曾把原生 WG 的随机创建名当作稳定接口名，以及把未入网条目的
可选字段当作必填；分别按精确 generation 所有权、字段存在性与值纠正。另一次升级期间 SSH 会话中断，
续接先确认实际已激活结果，仅重复回读，没有重做安装。原失败、计时、实际发送与复用数量均保留。

全部原管理员页面与历史、原业务 HTTPS，以及新建 SSH、LAN、DNS、既有 WireGuard、HTTP proxy 和默认公网
连接回读通过。远端日志限额、磁盘余量、原报告库 inode 与下载暂存清理再次核对。短窗实际线路测量已覆盖
上线客户端使用的短确认路径和压缩观测；它们不代表全部监测流量或已经跑满一天的结果。可达范围的节流生产
消费闭环已完成，全天累计效果仍待完整时间窗口验证；额度耗尽节点保持原授权和期望，恢复后另行处理。
真实字节、归档证明、逐目标结果及剩余项位于受保护的 `deploy/evidence/2026-10-22-monitoring-budget/`。

## Linux 共享 WG 的宿主接口名称

按[宿主接口名投影](core/current-contract.md#linux-wg-的宿主接口名)，Linux 不再把稳定
`listener_id` 直接用作接口名；使用 `loom-wg` 前缀与网络、资源 ID 的稳定短摘要。原 schema 3
签名资源、LKG、固定密钥、管理地址、端口、候选和权限保持，名称不表达 peer 或中心节点。
预检、启动及精确返回路由消费同一投影；旧名称仅由原 generation 的停止清理记录消费，
同名未知接口仍失败关闭。

身份字节保全、peer 撤回不改名、名称冲突拒绝及预检一致性检查通过。独立 network/mount
namespace 中的共享 WG 业务、多 peer 管理返回及解析后端点执行通过；全库构建、测试、vet、
格式、安全和 diff 检查通过。源码 `9f976f49` 的 Linux amd64 包按发布坐标 `124` 完成独立验签、
全部原发布目标及规定 HTTPS 验证，数据面和其余平台制品复用原件。

可达节点经正式 agent 期望与私有更新入口切换，独立远端并行应用并由全部 control 回读后，
再更新工作站客户端。各节点原身份、密钥、认证进度、发布 floor、用户策略选择和签名原件保持，
旧接口已清理；control 及独立宿主服务保持原执行。代表服务节点和工作站的正常停止、主进程
SIGKILL、精确清理及同包同身份恢复通过，新接口名称稳定，异常退出不自动反复启动。
停机、异常退出及恢复后的新建远端 SSH、LAN、系统 DNS、既有 WG HTTP proxy 和默认公网通过。
真实 WG DNS、明确指定 WG 的 HTTPS 及正常 Mixed 的各服务 HTTPS 均通过；全部 control 的正常
管理员 mTLS 浏览器读到实际 agent 与期望一致。无变化更新没有重装或重启，并完成既有引用检查和清理。

一台节点的首次安装已成功，但严格回读发现既有云安全链动态增加来源限定的拒绝规则，随后又有
同类变化。原失败与完整差异保留；只读核对确认变化限于该已有链的相同规则形状、当前管理与已配置
WG peer 来源不在变化范围，其余宿主定义一致；新连接和业务另行通过，没有重装该节点或改写防火墙。
不据此声明防火墙全文不变。操作者已确认额度耗尽的节点未进入本次写入范围，原授权及期望保持，
恢复后仍须按既定迁移前提单独升级。真实结果与原件仅进入受保护的
`deploy/evidence/2026-10-22-wg-interface-name/`。

## 监测整体传输开销复核

操作者继续报告周期流量过大。现网程序和升级后的小时增量已重新核对，先前配置领取的短窗降幅
不能证明整体监测开销已经达标。自然 WG 计数与既有连接计数显示，主要新增开销仍在 control 通道；
正式只读成员请求进一步核对了证明、前沿、报告索引和原件批次的实际编码与收发量。

本轮按[报告差量](core/current-contract.md#control-成员之间的报告差量)在原摘要树内比较最高叶之前的
完整历史，只有重算根一致才省去历史展开，最高叶仍取 ID 并验签合入。设备上传按
[签名报告的 HTTP 表示](core/enrollment-endpoint-model.md#observation)压缩原规范正文，接收端限制编码流和
解压正文；原件、签名、报告序列和持久高水位不变。采样频率、有效期、权限及 UI 范围保持，没有新协议版本、
同步游标或报告 store。同叶与跨叶新增、本机较长后缀、旧缺口和分叉、U64 上界、真实成员 TLS、原客户端
重试及压缩失败保全检查通过；全库构建、测试、vet、格式、安全和 diff 检查通过。

源码 `1d5603ba` 的第 125 代精确程序已先应用三个 control，再通过正式发布、期望写入与正常更新
应用五个可达 Linux 客户端。全部控制成员回读了连续递增的匹配原报告；管理员页面、正常 Mixed
及独立 WG 业务、宿主基础网络与无变更更新通过。身份、原件、认证进度、数据面和配置保持；
原报告库 inode 保持，离线节点期望未变。相同采样方式的自然短窗确认控制节点整体 WG 增量下降，
但这不是完整一日或纯监测流量的验收。

补充源码 `d05fa917` 以既有 Authority 原件的强 ETag 确认完全相同的成员证明，保持同步频率、
端到端 TLS 和失格成员的完整停止证明。真实成员 TLS 的完整交付、重复读取、错误确认拒绝及
通知丢失后的失格停止检查通过；全库规定检查通过。只分组更新三个 control 的精确程序与第 126
代签名清单，全部接收端与管理员页面回读通过；公开目录及五个客户端保留第 125 代，客户端与
原生数据面进程没有再次重启。生产既有 TLS 入口逐字验证完整证明后，两远端均确认相同原件且
不再重复发送正文。全部控制成员再次回读五节点连续递增的匹配签名报告，宿主与正常业务通过。

自然观测同时保留修正前、报告修正后及证明修正后的窗口，不选取最低短窗冒充全天结果。
共享 WG 还包含实际业务、探测及不同连接路径的流量；非控制节点的短窗未显示一致下降。
完整日预算仍待后续完整窗口验证，此时不关闭该目标。
真实输入、各次失败、计时及测量只进入受保护的
`deploy/evidence/2026-10-23-monitoring-traffic-audit/`。

## 保持实时性的报告传输节流

操作者明确要求保持十五秒刷新并继续减少传输。按
[报告差量](core/current-contract.md#control-成员之间的报告差量)，真实三成员 TLS 用例复现两个
并行成员在原件落盘前重复下载相同正文，部分重叠批次也会重复传输公共原件。
修正只在正文取件前短暂等待已有批次结束，并从原数据库重新核对仍缺的内容 ID 和范围；慢节点
不能把其他成员串行阻塞到网络期限，取消及时退出。没有新持久实体、游标或成功回执，十五秒
刷新、签名原文、报告库、权限、历史和观测时效保持。原竞争窗口的重复传输断言失败记录已保留；
重叠、部分重叠含分叉、首批损坏、慢节点回退和取消的真实 TLS 检查通过。

全库与并发检查通过，修正程序已仅部署到现有 control；原客户端、原生执行器与公开发布目录保持。
各成员正式页面已回读仍在推进的原签名报告，实际管理入口与业务验证通过。但自然短窗没有
证明整体流量下降，各节点连接分布也有变化，不能以用例省件代替生产整体流量。
现场输入、失败、原件保全、计时和读回只进入受保护的
`deploy/evidence/2026-10-23-monitoring-transfer-overlap/`。

继续核对每轮固定开销，确认未变的成员证明、普通事实前沿及空分叉目录仍分别请求。按
[成员证明与前沿确认](core/current-contract.md)在原前沿响应中确认已知完整证明及空目录，
不变前沿使用严格条件读取；证明未知或变化时仍走原完整证明和新鲜前沿读取，等前沿的旧双签
仍按每轮分叉提示取原件。真实 TLS 修正前测试记录了重复元数据请求，修正后的正式成员通道
读回已确认请求数及实际 TCP 字节减少。全库与并发检查通过；签名控制程序经全部目标身份及
原件摘要验证后分组激活，独立成员先并行恢复并完成管理员浏览器回读，管理成员随后更新。
全部成员已回读每台可达设备连续推进的原报告；宿主基础网络、原 WG 和 Mixed 实际业务通过，
原客户端、公开目录、身份与认证 floor 保留，原报告数据库的 inode 及原有字节保全。

同一原生 WG 实例的自然短窗比较已显示控制节点合计及全部可达节点合计发送量下降，但个别
转发节点总量仍有上升；该计数包含业务、探测和协议开销，不是监测专用统计。此前报告取件
修正未显示整体下降的窗口继续保留，不能只选择有利结果。十五秒刷新保持，全天预算尚未验证，
不能以短窗或条件响应比例宣称全天目标达成。远端清理后的可用空间、日志上限及空更新暂存目录
已重新读回，原签名历史保留。现场指标、实际制品与全部回读证据仅位于受保护的
`deploy/evidence/2026-10-23-monitoring-member-metadata/`。

操作者继续报告转发节点流量上升。上一轮的原 WG 分 peer 计数及保留连接现场证明确有两个控制
方向的新增传输，其中一条成员 HTTP 连接经该转发节点的私有中继坐标持续复用；未将整体下降
当作该节点改善。按[成员连接调度](core/control-model.md#4-普通写入与大规模增量同步)核对到原来
直连和全部中继同时竞速，健康直连仍会打开并可能输给额外中继。真实 TLS 用例已在修正前复现
健康直连仍拨中继。最小修正只给直接认证一个有限先行窗口，失败或窗口到期保留独立中继，
十五秒刷新及原签名对象、成员权限和业务选路不变。该修正已检查、部署并实际复测，结果见下段；
证据仅位于受保护的 `deploy/evidence/2026-10-23-monitoring-direct-first/`。

先行窗口通过全库与并发检查并仅更新控制程序，正式报告、管理页与业务回读通过，但原节点自然
短窗仍未改善，中继连接继续保留；这份不利窗口原样保全。随后在全部控制节点以原成员证书及
原拨号坐标逐项完成直接 TLS 和前沿读取，证明当前直连可用。已选中的池却未重新建连，暴露了
只修改初次竞速不能恢复已有中继的缺口。继续沿同一连接所有权加入只针对中继的有限复核期限，
到期仅回收空闲连接并重新认证；直连保持长期复用，无后台探测或持久状态。真实 TLS 已验证期内
复用、仍不可达时有界续用、恢复后返回直连及直连不被无故轮换。

全库及并发检查通过，签名控制程序已在全部现有 control 分组激活，独立成员先并行恢复并完成
管理员浏览器回读，管理成员随后更新。正式设备报告、宿主基础连接、原 WG 及 Mixed 实际业务
通过。保留完整四分钟自然采样，并单独比较末段两分钟：原非 control 中继连接不再出现在该路径，
该转发节点新增发送量及全部可达节点合计发送量均下降。完整窗口也已保留，不能只保留有利片段。
全部 control 在采样末端仍读到每台可达设备推进的原报告，当前时效、期望与实际组件及运行 View
保持匹配，原签名历史与认证 floor 保全。十五秒刷新、客户端与原生执行器、公开目录和宿主网络
配置保持。各节点变化仍有差异；该计数含业务和探测，全天监测预算仍待验证，不能用本次短窗
代替全天判定。原失败窗口、现场直连证据、准确制品与最终读回关联保存在受保护的
`deploy/evidence/2026-10-23-monitoring-relay-recovery/`。

## 控制同步的直连恢复与中继复用

操作者确认控制同步在满足认证、可靠性和既有时效后优先直连，中继期间每分钟检查一次。
按[成员连接调度](core/control-model.md#4-普通写入与大规模增量同步)删除按连接年龄淘汰中继的行为，
原五秒调度仅为使用中继的成员启动有界直接前沿检查。检查不接受事实或推进认证；通过后由下一轮
正式同步试用候选，正常结束才释放备用中继，失败保留原错误及已持久化原件。完整同步仍逐成员
独立且不重叠，健康直连不额外检查；成员身份变化、停止及迟到结果沿原所有权取消和回收。
直连传输失败允许下一轮中继先参与，认证、协议和持久化错误不被当作线路健康或透明重放依据。

真实成员 TLS 覆盖慢直连输掉初次竞速后的返回、永久只能中继时原连接与报告继续推进、前沿成功
但报告交换失败后的原件保全、检查超时和取消、认证身份替换及稳定直连再次发生传输故障。
全库规定检查与相关并发检查通过。源码 `0ece056a` 的第 131 代签名控制程序在全部目标身份及
精确制品验证后分组激活，独立成员并行恢复及认证浏览器回读通过后才更新保留管理入口的成员。
正常页面再次读回连续推进且匹配原期望的报告，原事实、报告库身份、密钥、认证进度和 latch 保留；
客户端与原生数据面进程、公开客户端目录、业务策略及宿主网络配置保持，管理和实际 WG/Mixed 业务通过。

发布前后各保留完整十分钟观测及不利结果：WG 总发送量上升，增量集中在一对控制节点；其中
已识别的控制方向从公网 TCP 直连改为 WG 直连，不能把 WG 计数的变化当作同步正文量变化或总成本
下降。私有端口也承载管理 HTTP，且公开坐标、解析和入口地址转换限制被动过滤范围，因此被识别的
私有入口流量不是独占控制同步或独占监测计量，loopback 与物理发送也不能相加冒充网络字节。

五台可达 Linux 节点已启动有截止时间的全天聚合采样，原生 WG 计数与受限范围的 TCP/IP 计数分别
保留；不保存报文正文、不在远端保留采样输出，本地单输出文件有容量上限。结果将沿原字节及
计数实例验证自动生成，采样失败或范围不足明确保留。原远端日志上限和磁盘空间已回读，未删除
权威历史。此时全天窗口仍在进行，全天监测流量目标保持未完成；精确制品、检查、全部窗口、
计量范围及后续日结果只进入受保护的 `deploy/evidence/2026-10-23-control-sync-recovery/`。

## 拓扑与完整双向详情的共同布局

操作者确认将拓扑横向收拢、纵向展开，给完整双向详情与共享发送量分配接近一半的页面宽度。
按[拓扑的可读布局](clients/web-ui-projection.md#拓扑的可读布局)，全网方向统计并入页头，筛选栏
跨两列，连接列表全宽紧接。图显式消费容器宽高并分别计算横纵半径，保持节点、字体和命中尺寸；
窗口变化原位更新坐标与文字折行，悬停、固定、方向切换和历史完成不移动节点或列表。
两向独立状态、RTT、波动、来源与采样时间、小时历史以及共用 WG TX 口径继续完整展示，
详情不使用内部滚动、折叠或裁切；更多长名称节点允许页面自然增高，小屏自然单列。
领域、签名 wire、持久身份、报告及运行选路不变，没有新的 UI 权威或布局持久值。

真实 Chrome 通过正式 SPA 与签名报告验证六节点桌面完整详情和列表开头同屏、异步历史及真实
鼠标/方向切换稳定、未知观测与单列展示；十七长名称节点、独立宽高、原 SVG/节点/连线身份、
键盘聚焦/锁定、线型和命中也通过。原型由渲染器同步，其余页面原型字节保持；规定仓库检查
及原流量浏览器回归通过。

源码 `537fe5d7` 的签名控制程序经全部目标身份、前件程序及精确制品检查后分组更新，两个独立
成员并行恢复并完成管理员 mTLS 页面回读，再更新保留管理入口的成员。三个正式入口均核对
精确静态资产、实际鼠标预览/固定、正反方向按钮、Escape、完整双向详情与共享流量、两栏同底
和紧接的全宽列表，以及窄窗口自然单列。首次窄屏验收错误地比较旧 SVG 宽度与自身旧 viewBox，
可能在 ResizeObserver 重排前完成；保留原失败后，等待实际容器尺寸及两帧渲染，原溢出断言全部通过，
没有重复构建、上传或重启已经完成的成员。

实际程序与持久 unit、原身份/密钥/签名事实、报告库身份、认证进度和 latch 分别回读；客户端、
原生数据面、业务策略、公开客户端目录及宿主网络保持，原 WG/Mixed 实际 HTTPS 和基础新连接通过。
旧控制程序经过全部目标的进程文件身份和受管服务执行引用核对后精确删除，签名清单与目录保留。
首次一次性清理工具误把规范的代号字符串读作整数，保留原结果后仅修正并重建该工具；重新审计
及删除均通过，旧新远端临时工具也按原身份清理，没有重发应用或改写签名原件。
受保护证据为 `deploy/evidence/2026-10-23-topology-layout/result.json`；本次布局及正式更新回读闭环完成。

## 局域网服务表单与策略多选交互

按[共享局域网与服务表单](clients/web-ui-projection.md)，新建服务先选择类型，再输入 ID 和名称；
Local network 使用不可编辑的 `local-` 与 `Local-` 前缀，既有稳定身份保留。虚拟地址分配明确为必填，
未取得与当前草稿一致的分配结果时不能保存；网关、网段或 ID 变化会清除失效结果，迟到响应不能
覆盖新草稿。已分配服务的改名和禁用继续可用。策略多选每项最多两行，右侧展示路径状态和原因，
展开期间标签保持单行，连续勾选、搜索与 Enter 添加不会移动菜单或丢失滚动位置。
领域、签名 wire、持久 schema 与运行授权不变。

真实 Chrome 已沿正式入口验证局域网写入、重启回读、过期草稿、设备策略选择及响应式布局；
规定仓库检查通过。源码 `12d3073b` 的精确签名控制程序通过全部目标身份、前件程序及独立验签后，
在两个独立成员并行激活；管理员 mTLS 浏览器回读通过后更新保留管理入口的成员。三个正式入口
均验证精确静态资产、类型顺序与固定前缀、分配前禁用保存、两行选项和连续键鼠多选及窄屏布局，
生产检查只使用未提交草稿，没有新建授权。身份、密钥、原签名事实、认证进度及 latch、原报告库身份、
客户端与原生执行器进程、业务策略、公开客户端目录及宿主网络配置分别读回保留；原 WG、Mixed
实际 HTTPS 与基础新连接通过。旧控制程序经过全部目标执行进程和受管服务引用核对后精确删除，
签名清单与目录保留；本次远端临时工具也已清理，随后三成员最终回读通过。
受保护证据为 `deploy/evidence/2026-10-24-web-configuration/result.json`。

策略多选的搜索框右侧新增“Select all policies”，一次选中当前草稿的全部有效可选策略，包括被搜索
隐藏的项；保留原选择，跳过禁用项，全部已选时禁用按钮，移除一项后重新可用。选择仍是显式
PolicyIDs，仅保存后生效，不自动授权未来策略。真实 Chrome 已验证邀请签发及设备改权两条正式入口、
持久重开与设备 View、过滤期间全选、选择数量、连续交互、职责移除及窄屏布局；规定仓库检查通过。

源码 `ddda9951` 的签名控制程序按原分组流程部署到全部 control，三处管理员 mTLS 正式入口均验证
精确资产、真实鼠标与键盘全选及搜索栏滚动固定。首次验收的 CDP Enter 缺少字符事件，独立原生按钮
复现后只修正验收执行器；原失败保留，没有重复构建、上传或重启应用。全部回读与 WG/Mixed 实际
业务、宿主基础新连接通过，原身份、认证进度、报告库、客户端与原生进程、授权及网络配置保留。
生产浏览器仅改未提交草稿；旧程序和本次临时工具已精确清理，签名历史保留，最终读回通过。
受保护证据为 `deploy/evidence/2026-10-24-policy-select-all/result.json`。

操作者报告全选后的标签裁切与连续选中底色难以辨认。菜单展开改为明确的选择总数，全部选中时
显示“All N policies selected”及“All N selected”；关闭后保留可移除标签，选项改用轻分隔线。
真实 Chrome 用八条同服务策略验证筛选期间全选、连续操作、数量回读、持久重开、设备 View 和窄屏，
规定仓库检查通过。源码 `305e4eb5` 的签名控制程序按原分组流程部署，三处正式管理员 mTLS 页面、
精确资产、真实键鼠、实际 WG/Mixed 业务及宿主基础新连接通过；原身份、认证进度、客户端、原生
进程和网络配置保留。旧程序与本次临时工具精确清理后最终回读通过。
证据为受保护的 `deploy/evidence/2026-10-24-policy-picker-qr-repair/control/result.json`。

同轮操作者报告多策略邀请无法生成二维码，并明确策略选择及内部成员资料不应放入二维码或邀请
链接。已从正式入口确认现行交付仍携带完整 BootstrapInvite，包含策略 ID、签名依赖和成员证明；
实际加入请求不携带 PolicyIDs，服务端从原邀请建立授权。本次菜单部署没有改变扫码交付，也没有
修复其容量与信息暴露问题。后续修正须使授权保留在控制面，码与链接只携带最小连接/验真信息和
受原事务约束的短期凭据，身份绑定后交付设备自身签名配置；已签原件与现有身份保全。该项保持
未完成，真实邀请及诊断只保存在受保护的 `deploy/evidence/2026-10-24-policy-picker-qr-repair/`。

### 扫码交付的容量与隐私修复

操作者明确要求策略及内部资料保留在控制面，二维码和邀请链接仅承载短期凭据及最小连接/验真信息。
前述扫码未完成项现由同一 schema 3 的短 `InvitationReference` 接管：由既有签名 Invite 派生，
不含 PolicyIDs、规则、名称、设备 ID、因果依赖或成员证明，不新增票据权威、数据库、协议版本或旧公共
交付 fallback。规范引用正文有固定资源上限，不随所选策略和成员证明增长；复制、加入文件及 SSH/sh
也交付同一短值。完整 Invite 和原签名字节保留，仅在设备公钥已绑定的私有响应中交付原件及本设备 View。

客户端联网前先持久保存身份、request ID 和短引用；认证绑定后在同一身份值中以原件替换引用。
已有完整身份的规范字节、密钥、latch、认证前沿及报告序列保持。Android 活跃 VPN 的具名 bootstrap
通过 underlying Network 解析并保护连接；文件入口处理下载行尾，二维码/URI 解码仍严格拒绝非规范值。
Linux、Android 和 Windows 接收入口统一消费短引用，既有 device-authenticated 配置与报告字节不变。

真实 Chrome 与独立 QR 解码覆盖多策略、私有输入增长、规范拒绝及图像原文；正式 CLI 覆盖首次连接
中断、持久重开、同身份加入与配置回读，真实 daemon 拒绝错误凭据、入口、锚、媒介及另一密钥抢占。
原生 Android 签名发布包通过独立模拟器的正式下载文件导入、八条策略加入、libbox 实际运行、签名报告、
进程重启恢复与正常断开；执行 APK 摘要与发布包一致，原升级签名证书保持。Windows 受限同机 x64 VM
通过短引用 broker、原件接受、原身份/LKG/前沿及草稿恢复测试；六种交付制品完成构建与签名清单验证。
未以模拟器替代实体摄像头或 ARM64 实体机终验。规定仓库检查、Android 单元测试及 release lint 通过。

控制程序源码 `22c1c8b7` 按独立组、管理组部署到全部 control，原管理员 mTLS 正式页面、精确资产与持久
身份及网络快照回读通过；经完整进程 inode、已安装和已加载 Exec 引用审计后精确删除旧程序，保留签名历史。
Android 文件行尾修正源码 `d5b0b01e` 只重建 Android 应用，版本为 0.5.5；其他已验证制品保持原坐标。
末次 Web 投影源码 `10287838` 将 SSH 检查的未绑定短引用身份显示为已保存事务，提示继续原邀请，
并以真实 Chrome 验证不虚构网络/设备坐标、不覆盖身份；仅重建并按原分组更新 control，客户端不重复打包。
生产正常 UI/CLI 完成多策略短邀请、单张 QR、身份绑定、配置持久回读及同身份同步，验收设备随后沿正式
删除入口清理；原 Service、Policy 和成员未改。既有 WG/Mixed 实际请求与宿主基础新连接通过；一项 WG
DNS 首次超时的原失败保留，仅重试该项并回读成功。

发布代 137 的签名客户端目录已向本次可用目标发布并完成公开制品 HTTPS 核验、发布指针及私有 Releases
回读；先前不可用的非 control 不在写入范围，不能据此宣称全网所有配置目标一致。现有已入网客户端无需
为加入交付重建身份或运行配置；使用新邀请的 Android 设备须升级至 0.5.5。真实材料和证据仅在受保护的
`deploy/evidence/2026-10-24-invitation-privacy/`，不在文档展开设备、地址、凭据或运行指标。

## 局域网源网段优先与自动预览

按[共享局域网映射](core/control-model.md#10-共享局域网映射)，首次分配优先仅将源网段的第一段改成 10，
其余网络位和前缀长度保持；源网段已在 10 段时优先同址。冲突后在同一 10 段确定性避让，耗尽即失败。
既有已签私有映射保留原地址和规范字节；改名、禁用不重新分配。领域、wire 与持久值仍为同一 schema 3 Service。
仅固定网关已读回的精确物理源网段允许同址最终拨号；本机 access 捕获、其他设备和其他相交接口仍须避让。

Services 表单在身份、网关和已报告网段齐备后自动请求只读预览，正常流程直接保存；迟到响应不覆盖当前
选择，失败在映射旁提示并可重试。网关与网段宽屏并排、窄屏纵排，映射、状态与启用开关集中显示，
分配成功不再使用红色错误反馈。分配预览不创建事实，保存仍重新验证依赖及精确地址。

本地真实 Chrome 已覆盖正常保存、持久重开、自动预览、乱序响应、重试、改名和宽窄布局。
专用 network/mount namespace 内，两种映射均通过正式投影的 WG/Hy2 真实 HTTP、重启恢复与撤权清理；
底层测试另覆盖同址 TCP/UDP 的目的范围、地址与对端限制。Linux 两种架构数据面制品已构建、核对来源，
新构建坐标为 `1.11.4-loom.15`；历史制品及其验签元数据保持。仓库规定检查及 mobile 模块测试通过。

经操作者授权，源码 `af241d83` 的精确签名控制程序已按独立成员并行、管理成员后置的顺序部署到全部
control；三个管理员 mTLS 正式入口均回读自动同段预览、精确静态资产、宽窄布局及 Releases。
发布代 138 的签名目录完成公开制品 HTTPS 摘要核验及发布指针回读，包含两种 Linux 架构、Android
0.5.6 和 Windows 六种应用交付；Windows 原生数据面继续复用既有已签制品。

五台可达 Linux 节点经正式更新入口激活同一签名包与新版数据面，全部 control 分别回读期望与实际组件、
已应用 View 及连续推进的签名报告。原身份、密钥、认证前沿、报告序列、floor、latch、业务授权及用户
偏好保留，既有 WG/Mixed 实际请求与宿主基础新连接通过。另一台非 control 仍不可达，未写入或改动其
期望，不能据此宣称全部配置目标一致。末台验收发现既有云防护代理更新 SSH 封禁条目，逐项对照其日志
并独立核对其余防火墙、路由和 DNS；未改写宿主防火墙，原失败记录保留。

生产预览未创建或修改 LAN Service、Policy；操作者指定物理 LAN 的新授权与实际访问仍须沿正式入口
回读，不能用本次只读预览抵扣。Android 和 Windows 下载已更新，未代替操作者终端安装，也未声称完成
实体设备终验。受保护的部署与验收证据为 `deploy/evidence/2026-10-27-lan-prefix/result.json`。

## Service、默认 Policy 与等待反馈

Service 保存及 Policy 新建、保存共用原在途请求标记：按钮和面板显示等待动画，编辑区变灰并暂停操作，
全局导航保持可用；失败后恢复草稿、原禁用字段和焦点，错误就地显示。等待包含操作后的认证回读，
实时更新不替换提交面板，重复点击不重复提交；地址预览使用局部动画，仍可切换网关及网段。
动画遵从减少动态效果设置，领域、wire、持久值及服务端业务处理保持同一模型。

Web 新建服务的保存还会自动保存一条普通默认访问 Policy。两种原操作以新 Service 的精确事实依赖衔接，
全部回读后才提示成功；部分完成保留原字节重试，不回退服务或覆盖另一意图。Policy ID 与显示名继承
服务前缀并避让已占用 ID，新建字段可编辑，切换服务保留手动输入；长 Unicode 前缀保持原文本长度约束。
既有 Service 编辑不补建策略，默认策略不自动分配设备。

真实 Chrome 已覆盖 Service 与 LAN Policy 的正常持久写入、响应丢失后的同字节重试、实时更新期间的
等待反馈、导航后迟到响应和宽窄布局；原局域网保存、重启回读与预览竞争检查通过。
互联网及 LAN 的默认规则、命名冲突、部分保存后的不变重试和持久回读通过；已有设备授权保持。
本轮只更新 control 执行制品，客户端、组件期望和公开下载目录保持；生产认证页面、精确制品与保护项
的实际部署回读记录在受保护的 `deploy/evidence/2026-10-27-intent-submit/result.json`，等待结束不代表设备业务已应用。

## 策略选择收起与详情分页

策略菜单点击外部收起并保留已选策略、搜索和原草稿，内部连续勾选、全选及 Escape 沿原入口处理。
展开时选择框底部和菜单顶部取消圆角，边框对齐连接，关闭后恢复原圆角。下方完整策略详情按每页三条
显示，阅读区限制高度，翻页控件保持在区外；翻页不裁剪待提交的 PolicyIDs，选择减少时页码自动收敛。
页码仅保存在原表单的可丢弃 DOM 属性中，原运行观测继续独立更新，领域、wire 和持久权威保持。

真实 Chrome 已覆盖邀请与设备编辑的外部鼠标点击、搜索及审阅依赖保留、宽窄边框衔接、跨页全量选择、
末页收敛及正式提交。邀请的原策略集合持久回读，设备策略集合进入认证 View；原路径状态更新与草稿保留检查通过。
本轮只更新 control，生产认证页面、精确制品及保护项的实际回读记录在受保护的
`deploy/evidence/2026-10-28-policy-picker-presentation/result.json`。

本轮部署的真实浏览器验收暴露配置复用预算无法容纳数 MiB 合法服务节点视图，未变输入持续重算，
使管理快照触发页面超时。配置 LRU 改为固定 64 MiB，总预算、超大结果不留存及原认证绑定保持；
不增加持久缓存、后台预热、协议版本或页面超时豁免。最小检查覆盖多个大配置反复读取及预算边界。

## Android 扫码弹窗

扫码从配置页滚动内容移到独立居中弹窗，去掉外围卡片，原页面的位置和有效交互保留。
方形取景根据实际窗口与系统栏后的可见宽高适配横竖屏，关闭按钮、空白与返回共用取消入口；
权限及相机错误在取景区域内显示。取消与识别交付共用本次打开的临时一次性交付标记，
先禁止迟到结果，再沿原回调收起；相机仅解绑本次预览和分析，不影响其他配置或 VPN。
现有 profile、邀请、身份、LKG、floor 及 schema 3 wire 均不改变。

原生模拟器检查使用真实 CameraX 流和相机可用性回调，检查实际屏幕居中、横竖屏、背景位置保持、
重新打开及三种关闭后的相机释放；正式签名 APK 的构建及运行回读单独保存在
`deploy/evidence/2026-10-28-android-scanner-dialog/`，不以截图抵扣物理终端安装与相机终验。
旧图廊的三份配置页基准仍含已删除的全局选路控件，本次保留差异证据，不恢复旧控件或覆盖基准。
