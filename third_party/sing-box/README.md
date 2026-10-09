# sing-box 数据面源补丁

源码固定为上游 `v1.11.4`，由 Go module 校验和及 commit 共同核验。`scripts/prepare-sing-box.py`
从该源码重新生成构建目录并应用唯一补丁；不是第二份开发环境或另一套 Loom 协议。

补丁修复 [TUN 域名目标的传递](../../docs/clients/client-runtime-model.md#tun-域名目标的传递)
所需的缓存恢复：返回 DNS 地址前同步保存地址与名称，读取时不删除分配位置，异常退出后跳过已有地址，
地址池耗尽时拒绝而不复用，损坏的缓存拒绝启动而不自动删除。分配锁避免并发查询占用同一地址。
缓存文件仅拥有者可读写。没有新增 Service、授权、选路或签名状态。
同时禁止该 DNS 缓存恢复或保存 selector 与 Clash mode；两者只能消费本次认证运行配置及 Loom 的实际选择。

构建制品坐标为 `1.11.4-loom.8`，必须记录源码、补丁与制品摘要，不能冒充未修改的上游二进制。
该坐标是数据面制品修订，控制协议与权威 schema 仍为 3。上游源码和二进制继续遵守其随附许可证；
发布对应二进制时必须同时交付源码来源、该补丁及构建方法。

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
