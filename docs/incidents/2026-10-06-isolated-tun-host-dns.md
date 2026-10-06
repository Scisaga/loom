# 隔离 TUN 经系统总线改写宿主 DNS

## 事实与影响

隔离 TUN 的开发验收中，数据面已经进入独立 network namespace，路由、规则和 TUN 均未进入宿主。
但数据面的挂载空间仍可访问宿主系统总线。固定依赖内的 Linux TUN 实现启动后异步执行
`resolvectl domain/default-route/dns`：命令在隔离网络中将 TUN 名称转换为接口编号，却通过宿主
系统总线提交这个编号。宿主上的同编号物理或既有接口因此被错误配置为 TUN DNS。

开发宿主及同机测试来宾都出现了此问题。来宾系统 DNS 查询失败；停止 TUN 后错误配置仍存在。
`/etc/resolv.conf` 文件未变，网络空间不同、业务 HTTPS 成功和正常停止测试均没有发现该副作用。
路由、策略规则与 link 配置经前后比较未变；这不能抵扣 DNS 状态被修改的事实。

责任在本轮 HostAdapter 隔离实现和验收覆盖：network namespace 不隔离 pathname Unix socket，
也不隔离经系统总线调用的宿主服务。仅以配置文件字节不变证明宿主 DNS 未变是错误的。

## 恢复与修正

- 停止来宾 TUN，禁止继续运行会写宿主解析服务的数据面。
- 比较实际接口身份和此次写入的 DNS/域值后，按原 networkd 输入恢复受管接口；保留既有 WireGuard
  DNS 约定。无 DNS 的非受管接口移除此轮引入的默认 DNS 路由覆盖，其他解析设置逐项回读不变。
  未重启网络服务，也未修改或清空宿主路由、规则、防火墙。
- 来宾系统 DNS 恢复。宿主新 SSH、LAN DNS、系统 DNS、默认公网 HTTPS 和既有 WireGuard 代理连接通过；
  IPv4/IPv6 路由、规则和 link 配置与本轮启动前一致。精确现场输入及恢复回执只保存在受保护证据。
- 删除数据面 Linux TUN 的自动 `resolvectl` 路径。业务 DNS 只由 Loom 投影到显式应用的私有挂载空间，
  不由数据面修改宿主解析服务。
- 数据面同时克隆 network 与 mount namespace；应用保持独立 mount/PID namespace。执行任何挂载前
  验证与监督进程的 mount namespace 不同，设置私有传播，再屏蔽宿主总线、网络服务及解析服务的控制
  套接字。解析器的数据文件与应用自己的 DNS 绑定保持可用。
- 制品修订坐标推进，旧已签测试制品仍保留原始字节与可验证性；权威 schema 和控制协议仍为 3。

## 必要验收

正式 CLI 需拒绝初始 network namespace 及未隔离的 mount namespace。运行、正常停止、主进程/数据面/
server 进程/应用执行者强制退出、授权收窄及重启时，比较解析服务的逐接口 DNS、域和默认 DNS 路由，
同时比较原有 route/rule 和 resolver 文件。应用不能访问宿主控制套接字。

hybrid 的 server listener 仍留在原 underlay，真实 QUIC/TLS 回读须来自该进程；access TUN 与应用在隔离
空间完成真实 DNS/HTTPS。systemd 原生安装和来宾整机重启必须重新验证，不能沿用修复前的成功业务记录。
本事故修复不代表整个 Linux 工作项或其他缺口已完成，实际结果见[实施状态](../progress.md)。
