# 私有 Enrollment 连接绑定

本文件说明 `internal/enrollmenttransport` 与私有 HTTP runtime 的接线约束。生产挂载、业务 reducer、
邀请签发和正式配置交付必须另有 daemon 的端到端验收；构造器或通信测试通过不能代表正式入网完成。

bootstrap ingress 在验证 outer transport capability、exact destination、会话有效期和限额之后，
通过独立的节点间 TLS 连接访问 capability 指定的 Enrollment 私有 tuple。节点间协议 ALPN 为
`private-enrollment-relay/1`，使用 ingress 的 Device mTLS；握手后携带长度前缀和 capability ID。
这层连接中的后续字节是客户端原有的 Enrollment inner TLS，ingress 不终止内层连接。

Enrollment 端必须根据当前 certified state 重验 ingress 的 Device 身份、forward 职责、被授权的
ingress set、capability issuer/policy/有效期及 exact service/tuple。capability ID 是查找与绑定信息，
不能单独授权连接，也不能通过客户端 HTTP header 构造 verified context。身份查验成功后才确认
relay，将 opaque verified capability 绑定到连接，再交给内层 TLS 与 Enrollment handler。

`PrivateRuntime` 分别绑定 enroll、device_config、device_report 的私有 tuple。各 role 的 server key、
SPKI pin（包括 overlap pins）、listener 与 subject profile 隔离。所有 listener bind 成功后才启动
HTTP 服务；任一失败关闭本次已创建的 listener。停止这组服务不触碰已经运行的数据平面。

连接绑定只解决服务间传递已验证上下文的问题。Enrollment 的 preflight、challenge、claim、token
CAS、事务认证与结果释放仍由业务服务验证；内层 TLS 本身不能替代这些授权。Device 稳态 API
只接受当前 certified identity/profile/view 下的 Device mTLS 和签名报告。
