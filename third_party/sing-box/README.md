# sing-box 数据面源补丁

本页说明源码与构建坐标，不声明当前生产版本或本轮业务验收已经完成。
目标为按唯一 Policy 的 Service 及实际测量选路，不引入地域分类或分类数据；完整接线仍须按实施状态验收。

源码固定为上游 `v1.11.4`，由 Go module 校验和及 commit 共同核验。`scripts/prepare-sing-box.py`
从该源码重新生成构建目录并应用唯一补丁；不是第二份开发环境或另一套 Loom 协议。

补丁修复 [TUN 域名目标的传递](../../docs/clients/client-runtime-model.md#tun-域名目标的传递)
所需的缓存恢复：返回 DNS 地址前同步保存地址与名称，读取时不删除分配位置，异常退出后跳过已有地址，
地址池耗尽时拒绝而不复用，损坏的缓存拒绝启动而不自动删除。分配锁避免并发查询占用同一地址。
缓存文件仅拥有者可读写。没有新增 Service、授权、选路或签名状态。
同时禁止该 DNS 缓存恢复或保存 selector 与 Clash mode；两者只能消费本次认证运行配置及 Loom 的实际选择。

当前源码构建制品坐标为 `1.11.4-loom.27`，Linux、Windows 与 Android 的新构建使用该坐标。
`.17`、`.18`、`.19`、`.20`、`.21`、`.22`、`.23`、`.24` 原制品及来源保持原义；当前构建坐标不代表生产或手机已经激活。必须记录源码、
补丁与制品摘要，不能冒充未修改的上游二进制。
该坐标是数据面制品修订，控制协议与权威 schema 仍为 3。上游源码和二进制继续遵守其随附许可证；
发布对应二进制时必须同时交付源码来源、该补丁及构建方法。
当前脚本默认构建 Linux 的 amd64 与 arm64，也可显式指定 Windows 目标；Android 沿独立 AAR
构建入口使用同一来源坐标。来源登记按正式参数
及复现字节核对，不登记不同参数的临时开发二进制。源码构建目标不等于生产发布或安装状态。

## 原生数据面自动验证

根仓库的 `go test ./...` 不进入此补丁生成的源码和嵌套 Go module。CI 的独立
`native-dataplane` Job（45 分钟上限）及本机 Linux 使用同一入口：

```bash
python3 scripts/test-native-dataplane.py
```

每次在 `out/native-dataplane-tests/run-*` 新建独立结果目录，保留已有失败日志。
入口按根 `go.mod` 使用 Go 工具链，再调用 `prepare-sing-box.py` 核验五份上游的 commit
与 module sum、补丁正向检查／应用／反向检查，以及 `common/loomprotocol` 与仓库 `protocol/`
全部 Go 文件的精确字节一致性。来源 JSON 记录全部固定依赖、补丁和执行协议摘要。

测试分别在 sing-box 主模块、`.loom-sing-quic`、`.loom-wireguard` 和 `.loom-sing-tun`
工作目录执行；临时 `go.work` 将五个固定模块放在同一依赖图中，不改上游 `go.mod`。
每次 PR 均执行下列关键集及其 race 检查，不依赖平台签名私钥：

- 主模块 `common/loomprotocol`、`common/execution`、`common/sourcepool`、
  `protocol/wireguard`、`protocol/hysteria2`、`protocol/group`、`transport/wireguard`；
- sing-quic 的 `hysteria2`；wireguard-go 的 `conn`、`device`；
- sing-tun 的纯内存 `TestGVisorUDPForwarderPreservesFragmentedPayload`。

随后按正式构建 tags 构建 Linux amd64，记录来源、二进制摘要及 `go version -m`。
下载、来源核验、补丁、测试和构建任一步失败都会使 Job 失败；空测试不算成功。CI 总是保存
逐步日志、来源与测试摘要，仅上传这些诊断文件，不签名、不发布数据面制品、不修改生产配置。
这不是上游所有 package、宿主 TUN／路由、Android／Windows 真机或生产多中继业务验收。
宿主网络验证仍须遵守[隔离边界](../../docs/incidents/2026-09-21-host-network-takeover.md)。

## 既有修订与验收边界

`.27` 独立登记本轮安全回归测试、完整来源元数据与准备／构建脚本的实际字节；`.26` 及更早
来源和二进制审核摘要保持原值。新来源不能套用 `.26` 的登记，即使测试改动未改变业务执行代码。
这是未发布制品的构建坐标，不是协议版本；schema 3、签名原件、发布 generation 与已安装指针不变。
本地来源／历史隔离和构建验证不表示 Windows 原生、Android 真机或生产激活已验收。

`.25` 仅增加 access 业务拒绝分支诊断。连接保留第一次拒绝的固定原因与当时选择 revision
的哈希，后续已 pin 请求缺少上下文或新选择不能覆盖首因。两个元数据字段不进入 JSON、
wire 或持久状态；仅已拒绝的业务连接沿原 context 记固定字段，正常成功不新增日志。
原选择、权限、错误及期限不变；此修订不证明间歇拒绝已经修复。

`.24` 仅增加 WG 拨号的固定阶段诊断：peer 准备、内部 TCP 建连及执行请求确认。失败增加
阶段与耗时并保留原错误原因链；成功只使用既有 debug 日志，不新增正常业务 Info 日志，
不记录目标、Policy、身份或帧正文。原确认期限、权限、解析及执行语义保持。该修订用于
定位尚未复现的真机超时，不代表它已经修复；隔离域名与 TUN 恢复成功不能替代真机结果。

`.23` 修正 WG TCP 确认失败的返回值：具体连接指针失败时先返回真正的 `nil, err`，
再将成功值转换为 `net.Conn`；不让接口中的空指针进入上层清理而崩溃，也不靠空 `Close`
吞掉错误。正式 Endpoint 的原生拒绝和目标拒绝均校验错误时无连接，原错误及旧流断言保持。
`.22` 真机失败制品、实际映射与崩溃原件保留，不因测试通过而视为业务已验收。

`.22` 修正 WG 旧流绑定与当前拨号坐标的合并：旧流只保留精确绑定，当前请求规格优先，
资源退出工作集时从同一实际快照取得最新坐标；同一快照核对身份和绑定并拒绝迟到 CAS，
不从 entry 初值恢复历史地址。域名或端口显式变化后，解析失败也不借用旧目的地；同目的地
的合法刷新和协议学习地址保持原义。资源池、真实 WG TCP／UDP、绑定撤销及 DNS 反例均
先红后绿；接口变化只在进程内部，不修改签名 wire、权限、身份或持久格式。

`.21` 修正实例关闭时的错误合并：检查器关闭尚未启动的平台实例时，保留原关闭错误，
不再因空回调崩溃。正式 `libbox.CheckConfig`、未启动关闭及启动失败清理分别先红后绿；
该修订不增加运行 fallback 或吞掉真实启动错误。`.20` 失败制品及原生现场保持原义。

`.20` 将 forward 的有向图和运行容器纳入同一增量通道。图与优选顺序一次原子读取；
更新保留仍有效的最新测量优选，过期修订不能覆盖新图。容器按需创建、更新和退休，
实际连接继续租用已固定的传输对象，不因新增入口或中继而重启整个实例。

`.19` 将发送资源按需装入常驻实例，权限先提交、资源准备后按当前修订发布。每条连接租用
实际对象，普通工作集和拨号坐标更新保留合法旧流；身份撤销及 Policy 收窄按已固定身份与后继
节点精确校验。WG 来源绑定与诊断复用稳定设施，不通过重启整个内核增减资源；旧绑定在租用
结束后精确回收。接口与失败语义见[按需增量应用](../../docs/core/current-contract.md#发送资源的按需增量应用)。

`.18` 仅纠正 Linux 原生 TUN 的手动路由边界：`AutoRoute=false` 时启动、更新及关闭均不安装或删除路由与策略规则；精确管理路由仍由原 HostAdapter 创建并严格回读。真实混合地址族 `NativeTun.Start`、改名与关闭回归同时核对路由／规则及存量普通 TCP，避免仅用裸 TUN 代替正式创建链。

`.17` 删除互联网 Direct 上重复的逐 Service 目标权限，业务仍由 access／receiver 当前 Policy
快照校验。出口 worker 通过既有回环认证 API 取得受限于公网、认证 DNS 和平台绑定的物理
TCP 通道；成功交接保留绝对期限及实例所有权，取消和停止回收本次通道，半关闭保留返回流。
这只是[本机运行投影](../../docs/core/current-contract.md#本机出口测量的物理-io)，不新增远端
WG／Hy2 wire、Service 权限或权威对象。旧制品的来源与字节摘要保留原义。

当前未发布修订补齐原生 UDP 执行包装的 packet 接口，保留原域名/IP＋端口和载荷；
不能经通用 `UDPAddr` 适配丢掉域名，再由自己的目标校验拒绝。严格目标校验和既有传输保持，
不增加权限、DNS 回退或 wire 字段。gVisor UDP 分片收集另采用
[上游单行分配修复](https://github.com/SagerNet/sing-tun/commit/4cd8fef58105b9237637842e3b17f24cdfacc583)，
避免按载荷字节数预置空分片。实际 packet 适配、越界拒绝、分片载荷及引用释放分别回归；
Android 默认采用 gVisor 已由用户在对照及修复制品回归后明确确认；具体约束见
[Android capture 边界](../../docs/clients/client-runtime-model.md#android-capture-边界)，
对照与修复制品结果另见实施状态。该决定不改变其他平台的接入栈或 WG 的内部用户态实现。

最小验证包括首次域名 DNS/Hy2 HTTPS、原始 IP 与伪造 SNI 拒绝边界、立即强制退出后的缓存地址恢复，
以及正常停止与撤权后的重新授权检查。仅应用补丁或通过首次连接不算部署验收完成。

Linux 隔离 TUN 另以仅运行时派生的 `netns` 定位继承的 underlay namespace 文件描述符。
只有出站 socket 的同步创建进入该 namespace；DNS 查询、TUN、路由及其工作线程仍受各自既定边界约束。
只接受已解析的拨号地址，拒绝跨 namespace 的平台网络选择，接口绑定在 socket 所属 namespace 中解析。
非 Linux 平台拒绝非空引用，空引用保留原出站行为。这不是第二份认证配置或新的业务协议。

源码准备在隔离的 Git 搜索边界内执行补丁和反向检查，防止仓库子目录使 git-format hunks 被静默跳过。
`.1`、`.2`、`.3` 已签制品的字节及含义保留；本修订的原生与交叉制品分别记录新摘要。Windows 的外置签名
Wintun 加载修复继续保留，不回退到嵌入式内存加载器。

Linux TUN 不再执行自动 `resolvectl` 操作；业务 DNS 由 Loom 的显式应用入口在私有挂载空间内设置。
网络 namespace 内的接口编号不能交给宿主系统总线解释。该删除不影响 Windows 的平台 DNS 设置。
详见[隔离 TUN 的系统总线事故](../../docs/incidents/2026-10-06-isolated-tun-host-dns.md)。

`.5` 增加由认证 DeviceView 单向生成的进程内精确 `.loom` DNS transport。固定上游没有静态
地址记录执行器，本补丁在既有 DNS 服务器配置中用 `address: "loom-static"` 和 `static_records`
承载名称到规范地址的映射；它不打开监听或外部连接、不签发记录、不持久化答案，也不是新的网络协议。
未知名称返回 NXDOMAIN，已存在名称无对应类型返回空答案，TTL 固定为零；空非终结名称保留 DNS
名称树语义。其他名称拒绝，不通过宿主解析器补答。TUN fake-IP 只为存在的 overlay 名称还原目标，
真实地址解析由当前授权路径的执行者消费。业务授权继续由原 Service/Policy 和接收端 ACL 判断。
静态记录只在该 transport 有效，其他 DNS transport 携带此值必须拒绝。实现及真实查询、业务、删除和
重启验证见 `internal/clientadapter/overlay_dns_runtime_test.go` 与隔离 TUN 正式 CLI 验证。
历史 `.4` 制品和来源摘要保留原义，不作为新记录的执行 fallback。

`.6` 修复 Windows 用户态 WG 在启用网卡绑定时的 IPv6 UDP 监听。上游 WG 给双地址族均传入
省略主机的 `:port`；IPv6 socket 因而被错误地施加 IPv4 网卡选项，启动返回参数无效并留在 Down。
仅 Windows 的 `udp6` 空主机监听规范化为 `[::]:port`，仍绑定同一端口、网卡与通配范围；IPv4、
其他平台、签名配置、候选和密钥不变。不增加宿主路由或传输 fallback。当时的同机 Windows
WG→Hy2 记录只是历史证据；该嵌套已被明确否决，不能再作为现行验收目标。
此前 `.5` 已签来源与二进制摘要保持原义；新制品使用新的发布坐标，业务协议仍为 schema 3。

`.7` 为[分段传输](../../docs/core/current-contract.md#分段传输的替代执行模型)补齐原生 WG
接收与拨号适配：在共享用户态会话中绑定精确来源地址，按资源的私有 `/96` 承载字面 IPv4，
在接收端恢复 IP 后再检查权限；域名使用接收端执行 DNS 与既有持久 fake-IP 缓存。
直接拨号的 `detour` 与 `inet6_bind_address` 组合仅可指向拥有该地址的原生 WG endpoint，
拒绝混入宿主接口、路由 mark 或其他 socket 配置。没有建立下一段 Hy2、SOCKS 或 HTTP 会话。

实际流关闭检查还发现并修复固定依赖的边界问题：gVisor 的 `CloseWrite` 错调了读方向关闭；
Hy2 的 TCP 适配器缺少半关闭，导致发送结束时同时取消返回流；HTTP 代理在复制未知长度正文
时，内层 pipe 的回调过早关闭 HTTP transport 所有的一端，且错误保留依赖 EOF 分帧的连接。
现在由各自所有者关闭流，FIN 保留另一方向，未知长度 HTTP 响应保持正确的关闭分帧。
`sing-tun`、`sing-quic` 和 `sing` 均使用原来固定的上游版本，源码准备核验各自 module sum 与
commit 后应用同一补丁；不从构建目录或外部工作区读取另一份可写依赖。首次失败及修复后的
HTTP/SOCKS EOF、TCP 半关闭对照都保留在受保护验证记录中。

共享系统接收器复用原 WG 地址及精确管理路由。`host_sources` 是认证节点 peer 的精确来源列表，
只有该来源发往本资源精确地址的包可交给主机；其他 peer 的业务交给公共路由器，不因目标等于
接口地址获得主机权限。系统 endpoint 的宿主地址与管理 peer AllowedIPs 均须为 `/32` 或 `/128`，
Linux 不启用自动路由。补丁还修复上游混合批次把已交业务路由器的包重复写回主机的问题。
这不授权替换生产接口；实际接线、所有权、失败清理和管理连接回读仍由 Loom 节点执行器负责。

`.8` 将收发统一到每节点一个实例和固定密钥。逐资源独立发送器和旧 `/96` IPv4 映射删除；
目的 peer 通过接收端唯一合成 /64 选择，域名和字面两族 IP 均先经过原执行 DNS，接收端恢复
原始类型后执行同一权限。来源绑定不能选择其他 peer 的地址池，返回包也受标准 WG AllowedIPs
验证。系统 endpoint 的 `stack_address` 只在同一用户态栈中保存业务地址，宿主地址和路由不扩大。
UDP 包适配保留原始域名，避免通用 UDPAddr 转换丢失名称。新增目标有一次内部 DNS 往返成本；
没有新增远端代理、密码学封装或授权库。正式控制投影的并发出口与管理返回路径另由
`internal/linuxclient/wireguard_shared_test.go` 和 `wireguard_native_test.go` 验证。

可重复底层验证入口为：

```bash
python3 scripts/test-segmented-transport.py \
  --binary out/dataplane/sing-box-linux-amd64 \
  --evidence deploy/evidence/demo-segmented-transport
```

脚本首先进入独立 network/mount namespace，再启动临时 HTTP/UDP 目标与显式 Mixed 入口。
它覆盖每节点一个 WG 实例、同入口同目标的两个并发出口、域名与两族 IP 的 TCP/UDP、标准内核
peer 冒用来源、撤权和重启；全部使用临时密钥与示例材料。通过不代表 Loom 正式
Service/Policy 投影、真实控制持久化、Windows/Android 原生运行或生产迁移已经验收。

`.9` 增加固定 LAN 网关的等长 IPv4 前缀转换。它位于最终 direct 拨号的名称解析与物理 socket
之间，TCP/UDP 及并行拨号均重新检查虚拟地址范围；主机位和端口保留。UDP 会话限制精确请求目标及
对应回复，TCP 保留半关闭，不添加宿主 NAT、隧道或路由。公开配置只保存两个前缀，Service/Policy
仍是唯一授权来源；不允许与 detour 或目标 override 混用。底层测试在同一补丁内，正式业务与三端
软件及生产验收另按实施状态记录；源补丁存在不表示已经部署。

`.10` 修复共享系统 WG 接收器的并发宿主批次。不同 peer 的接收协程原来复用同一临时切片，
而 TUN 的 GRO 会修改批次元素；并发覆盖会使合并中的长度失效并崩溃。现在只在有宿主报文时
建立调用内的临时批次，不串行化业务栈、不关闭 GRO，也不改变允许交给宿主的来源或目标。
对照测试在旧实现稳定检出跨 peer 覆盖，新实现还须通过 race 与正式节点运行验证；旧 `.9` 已签字节
及来源摘要保留原义。领域映射和验收约束见[分段传输模型](../../docs/core/current-contract.md#分段传输的替代执行模型)。

`.11` 从固定 WireGuard 模块直接读取同一运行实例的 peer 原子计数，新增入口复用现有带认证的
回环 API；没有额外公网监听、peer、隧道、路由或状态库。实例建立时生成运行期 epoch，关闭后
拒绝读取；响应只含接口标识、epoch、公钥及 RX/TX，不调用会导出私钥的 UAPI 配置接口。
计数口径与报告映射见[共享 WG 计数](../../docs/core/current-contract.md#共享-wg-的原始计数与流量派生)。
独立目标构建并行，各自写入精确平台文件；所有子任务结束后统一判定，失败不打包部分产物。

`.14` 修正[消息工作集](../../docs/clients/client-runtime-model.md#数据面的消息工作集)中的两个
所有权边界。WG 同步收发完成后清除临时批次的正文引用，归还消息不再被空闲 peer 的底层切片继续
保留；在途 I/O 仍持有原正文。TCP DNS stream 则在终止前完成已接收请求的响应并关闭本连接，
使正常首跳探测结束后另一端的 socket 和复制协程也能退出。仅读方向 EOF 不能截断合法响应，
失败和取消不能留下永久等待。没有改变密钥、WG endpoint、权限、DNS wire 或控制 schema。
旧 `.13` 签名原件保持原义；测试与隔离测量的结果范围、正式发布及长时间回读另记于实施状态。

`.15` 允许固定 LAN 网关在源前缀与虚拟前缀精确相同且位于 10 段时保持目标地址，继续逐次检查
TCP/UDP 范围、主机位、端口和 UDP 对端。Loom 的物理 LAN 读回只豁免网关最终拨号，本机 access
捕获仍避让 underlay。原 `.14` 及其他已签来源与制品摘要保持原义，不因新分配偏好改写既有映射。

`.16` 是本工作项尚未发布的构建坐标，包含独立 WG／Hy2 的连接上下文、接收权限差量、来源
selector 的完整 Policy／入口／出口 CAS，以及新流登记与撤权共用的校验边界。稳定 View 不再
签入候选、运行 JSON 或逐路径凭据；完整目标和剩余边界见[现行契约](../../docs/core/current-contract.md#稳定-view-与本机运行派生)。

本机 WG 资源输入为 `{resource_id,listen_port}`，只提供显式非零的本机端口 Q；签名资源的
公网拨号端口 P 保持独立，NAT 可以将 P 映射到 Q。既有映射 IP 只定位落点，不限制 WG 绑定
IP 或地址族。Hy2 继续消费原 `listen` 和 TLS 文件引用，既有签名、身份与密钥原件保持原义。
一个 WG Device 使用原生 Std 双栈共享 UDP 端口，每个支持的地址族共用一个 socket 收发；
没有接收资源的发送端使用临时共享端口，不从 socket 存在推导接入权限。同机其他 IP 上相同
UDP 端口也会冲突，预检和实际绑定均须拒绝，不能自动换端口或因占用退成单栈。

端口变更使用原认证运行更新 `wireguard_listener:{port}`。先以新权限和当前已确认端口执行
CAS，再以相同权限和新端口执行 CAS；各次均比较实际读回的 `expected_revision`，并完整核对
成功的 revision 和 `config_hash`。只重绑 WG UDP，保留 Device、内层连接及独立 Hy2；绑定
未完成或失败时保持新权限，`config_hash` 为空、执行 unknown，不宣称旧端口仍在运行。
执行 TCP 包装显式转发半关闭，仍先解析原生响应帧，不能为复制优化绕过协议确认。
Hy2 的 TCP 准入拒绝也使用已有 TCPResponse 编码器；不能把控制操作的响应帧写进 TCP 业务流。
原生业务 Dial 在返回前读完下游建连确认，forward 不能仅写完下一段请求便向上游 Accepted。
WG 保留现有状态，Hy2 仅在原生路径沿现有消息字段传递有限安全码；通用错误仍 unknown，
不能推断全网或最终网站故障。单连接取消等待其回调退出，不关闭共享传输；确认不等应用首包。
Hy2 共用会话创建的等待响应调用方取消，初次 underlay 使用本次期限；关闭可取消在途创建并
拒绝迟到发布，已建立会话及后续端口跳转仍使用原运行生命周期。对应
[逐跳确认契约](../../docs/core/current-contract.md#逐跳-tcp-建连确认)不增加签名对象或持久状态。
普通 access TCP 的实际 Dial 结果另由既有 tracker 采集一次，复用本机认证 API 交付有界快照。
来源、Policy、候选、目标及选择 revision 保留原归属；关闭后的迟到结果、拒绝、取消、通用确认
超时和未知不记目标故障。同刻不同结果保留 unknown，旧慢尝试不覆盖新尝试；缓存限额和本机
消费规则见[普通 TCP 结果](../../docs/core/current-contract.md#普通-tcp-结果的本机消费)。没有额外网络
探测、普通浏览目标的共享测量、签名对象或持久状态；TCP 成功不等于 HTTPS 或网站成功。
access 的权限更新从现有组件表取得实际 transport，先校验当前 Policy 和路径；成员引用表
不充当权限，增减引用不替换仍运行的共享设施。
跨族加密往返、静默后的远端先发、撤权、取消、端口重绑与完整 FIN 响应均须经实际原生调用验证。

共享 socket 不表示规模问题已闭环。现有 peers、keepalive 和 probing 随节点及目标增长的
内存、流量、计算与耗电成本仍待收敛和实测，不能据此宣称已消除全邻接成本。

原生配置的外层字段剥离改为保留嵌套原始 JSON，防止显式空权限表被展示用编码器丢弃；缺失、
null 和未知字段仍拒绝。测试同时覆盖真实渲染配置的原生消费、当前来源的权限更新与旧 CAS
失效，以及性能更新时已有 TCP 保持、新连接采用新选择。回环、内存栈与语法检查不抵扣
正式加入、普通应用访问、手机切网、全路径连续性或生产前向迁移验收。

同一未发布坐标还包含 WG 入站与出站 peer 的原生差量。更新仅下发变化的 endpoint、AllowedIPs、
keepalive 及显式 peer 秘密，不替换设备、bind 或未变 peer；纯发送 endpoint 使用同一更新与
回读入口，不增加接收权限。域名变更只取消相关解析，在途旧结果不能穿过删除或 A→B→A。
同一认证 peer 改址不等于更换业务出口；真实 TCP 验证使用内存栈与回环 UDP，生产及真机仍待验。
