# v2 私有控制面运维

本文记录单成员 `ControlSet` 的一次性初始化、管理员材料、systemd 启动与验收方法。命令中的
`<...>` 必须由当前部署事实替换；仓库不记录真实节点地址、成员 ID、证书或私钥。

## 边界

- `control` 是 Device 的正交职责。初始部署为 `N=1,q=1`，不改变普通转发职责。
- `control_api` 与 Raft 分别绑定私有 overlay IP 和不同端口；两者不经公网 Nginx。同端口的
  IPv4 loopback 只提供浏览器 UI，便于通过已认证的 SSH/开发机端口转发访问；
  private status/operation 仍只接受 overlay listener。
- 管理员证书、control peer 证书、control API server 证书使用不同 key 和用途 profile。
- 同一 private HTTPS `control_api` 同时承载浏览器 UI：未提交客户端证书时只能读取脱敏视图；
  提交当前 certified ACL 精确授权的管理员 leaf 时才启用配置处理器。不存在 UI 口令或登录 Cookie。
- 当前没有部署中的 Windows Device；Windows 源码保持不动，其 compatibility/验收不再阻止
  服务端、Linux、Android 发布或 Gate B。Gate B 只按实际活跃调用方和扫描证据判断。
- 当前生产 reducer 只登记 `control_ping`，用于验证管理员签名、Raft commit、QC 和 inclusion proof。
  未实现的 operation kind 会失败关闭，不会返回伪造的“成功”。

## 一次性初始化

先确认目标节点已经具备 control 职责且 `<overlay-ip>` 是该节点真实存在的私有 overlay 地址。状态目录
必须不存在；命令拒绝覆盖，运维人员也不得通过删除状态目录来“重试”。

```bash
sudo /usr/local/bin/loom control bootstrap \
  -state-dir /var/lib/loom-control \
  -admin-out <offline-admin-directory> \
  -cluster-id <cluster-id> \
  -device-id <existing-device-id> \
  -overlay-ip <overlay-ip> \
  -control-port <control-api-port> \
  -raft-port <raft-port>
```

省略 `-member-id` 时会生成符合 wire 约束的随机 ULID。初始化会形成 Raft index 1 的 bootstrap Head、
本机 durable commit、`q=1` replication QC，并以 `0600` 写入所有状态和管理员材料。

完成后安装并启动 unit：

```bash
sudo install -m 0644 packaging/systemd/loom-control.service /etc/systemd/system/loom-control.service
sudo systemctl daemon-reload
sudo systemctl enable --now loom-control.service
```

## 管理员访问

`<offline-admin-directory>` 是完整客户端身份，不是普通 CA 下载目录：

- `admin.crt`：管理员 mTLS leaf；
- `admin.key`：同一 Ed25519 key，也对 `ControlOperationBodyV1` 签名；
- `admin-root.crt`：管理员 profile 的审计根；
- `control-root.crt`：浏览器验证 private control HTTPS 服务端证书所需的公开 trust anchor；
- `endpoint.json`：private service tuple、server SPKI pin、internal CA anchor 与文件绑定。

目录应在加密介质上保持 `0700`，文件保持 `0600`。不要把它放进仓库、聊天、工单附件或分发镜像。
访问端可直接路由到 `<overlay-ip>`，也可经已认证的 SSH/开发机会话把本地同号端口转发到
control Device 的 `127.0.0.1:<control-api-port>`。不能改用公网地址，也不能把 loopback
改成 wildcard/public bind。

### 浏览器证书包

直连时浏览器访问 `https://<overlay-ip>:<control-api-port>/`。端口转发时，远端目标必须是
`127.0.0.1:<control-api-port>`，本地使用同一端口并显式访问
`https://127.0.0.1:<control-api-port>/`；不要使用 `http://` 或 `localhost`。服务端 leaf 只包含
exact overlay IP 和 `127.0.0.1` SAN。`control-root.crt` 与
`admin.p12` 用途不同：前者只让浏览器信任 Loom 的 HTTPS 服务端；后者包含管理员 leaf 和对应私钥，
让 TLS 客户端认证获得配置权限。Root CA **私钥**永远不进入浏览器。

从早期只有 overlay SAN 的安装升级时，先执行一次幂等迁移，再重启服务：

```bash
sudo /usr/local/bin/loom control enable-loopback -state-dir /var/lib/loom-control
sudo systemctl restart loom-control.service
```

迁移只用既有 internal CA 给原 control server 公钥重签 leaf；不更换服务端私钥、SPKI pin、
trust root、admin 材料或 certified Head。已包含 loopback SAN 时命令不改写文件。

首次为已有 `admin.crt` / `admin.key` 生成浏览器包时，在管理员交付目录执行：

```bash
umask 077
openssl rand -base64 -out admin.p12.password 24
openssl pkcs12 -export \
  -inkey admin.key \
  -in admin.crt \
  -name 'Loom control administrator' \
  -passout file:admin.p12.password \
  -out admin.p12
openssl pkcs12 -info -noout -in admin.p12 -passin file:admin.p12.password
```

`admin.p12.password` 只是 PKCS#12 文件的导入/静态保护密码，不是 UI 密码。导入个人证书时读取它，
不要在命令行参数、聊天或截图中写出密码。应分别保管/传输 `.p12` 与密码；导入后重新建立浏览器
HTTPS 连接（必要时彻底关闭原连接或浏览器）。

没有 `admin.p12` 时，已在 Loom overlay 内且已信任 `control-root.crt` 的浏览器仍可看只读状态；
创建 Device、下载邀请材料、修改 SSOT、Service、路由或执行动作都会返回 `403`。错误、过期、
revoked 或不在当前 certified ACL 的证书同样只有只读权限。旧的节点 HTTP 页面始终只读。

读取 certified 状态：

```bash
loom control status -admin-dir <offline-admin-directory>
```

提交一次完整写链路验收：

```bash
loom control request \
  -admin-dir <offline-admin-directory> \
  -kind control_ping \
  -reason '<operator audit reason>'
```

成功响应必须同时满足 `status=certified`、有效 Head QC 和 operation inclusion proof。错误管理员证书、
错误 server pin、过期证书、过期 Head 或公网 listener 都应失败关闭。

浏览器 UI 已经放到 v2 private HTTPS/admin-mTLS 入口之后，但其中现有 SSOT、Device 和 Service 写处理器
仍是 Gate B 前的 v1 compatibility 实现；证书门禁不等于这些写入已经取得 v2 Raft/QC。当前原生 v2
reducer 仍只登记 `control_ping`，不能把兼容 UI 的成功响应误报为 v2 certified operation。

## 重启、备份和避免重复工作

- 正常重启只运行 `control serve`。每次启动重新 campaign，并在已有日志上提交 current-term barrier；
  不重新 bootstrap，不重新生成证书。`enable-loopback` 只是旧 leaf 的一次性、幂等迁移。
- 备份 `/var/lib/loom-control` 的 Raft、control state、operation journal 和服务端密钥；管理员交付目录
  单独离线备份。恢复必须是整组原子恢复，不能混用两次 bootstrap 的文件。
- 发布前记录 exact Git commit、二进制 SHA-256、signed-current generation、ControlSet hash、certified
  Head hash、管理员交付目录位置和证书到期日。真实值只写部署机受限 handoff，不写仓库。
- 若状态目录存在但服务无法启动，先运行只读校验和查看 journal；禁止再次下载镜像、再次 bootstrap 或
  覆盖原状态来掩盖问题。

## 验收清单

1. `systemctl is-active loom-control` 为 `active`；control/Raft 监听出现于已登记 overlay tuple，
   浏览器入口额外出现于 exact IPv4 loopback 同号端口，不出现 wildcard/public bind。
2. 无客户端证书的 HTTPS UI 为只读；带正确管理员材料的 UI 启用配置；随机、过期或 revoked
   client certificate 的写请求返回 `403`。
3. `control_ping` 推进 certified Head，Raft `commit_index == last_applied`，operation tree size 单调增加。
4. 重启服务后 certified Head 不变，再次 `control_ping` 成功且 term/index 前进。
5. 从公网接口探测 control/Raft 端口不可达。
6. compatibility 写处理器仍可用但只经过 private HTTPS/admin mTLS 到达；迁移为 v2 reducer 前不得删除。
   Windows 不再是门禁；Linux/Android 私有通道通过且扫描无活跃旧引用后退役对应旧路径。
7. 经 loopback 可读 UI 且管理员同源写入仍要求 `admin.p12`；private status/operation
   经 loopback 必须拒绝，经 overlay 的 CLI 路径仍通过。
