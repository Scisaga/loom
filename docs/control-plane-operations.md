# v2 私有控制面运维

本文记录单成员 `ControlSet` 的一次性初始化、管理员材料、systemd 启动与验收方法。命令中的
`<...>` 必须由当前部署事实替换；仓库不记录真实节点地址、成员 ID、证书或私钥。

## 边界

- `control` 是 Device 的正交职责。初始部署为 `N=1,q=1`，不改变普通转发职责。
- `control_api` 与 Raft 分别绑定私有 overlay IP 和不同端口；两者不经公网 Nginx。
- 管理员证书、control peer 证书、control API server 证书使用不同 key 和用途 profile。
- Windows 验收只阻止 Gate B（删除 v1 compatibility），不阻止兼容的服务端/Linux/Android发布或
  `N=1` v2 控制面启动。
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
- `endpoint.json`：private service tuple、server SPKI pin、internal CA anchor 与文件绑定。

目录应在加密介质上保持 `0700`，文件保持 `0600`。不要把它放进仓库、聊天、工单附件或分发镜像。
访问端必须能路由到 `<overlay-ip>`；没有 overlay 路由时不能改用公网地址。

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

当前 v2 管理入口是签名 CLI/API，不是浏览器页面；旧的本机 v1 Web UI 只作为 Gate B 前 compatibility
入口保留，不能把它误认为 v2 admin mTLS 控制面。

## 重启、备份和避免重复工作

- 正常重启只运行 `control serve`。每次启动重新 campaign，并在已有日志上提交 current-term barrier；
  不重新 bootstrap，不重新生成证书。
- 备份 `/var/lib/loom-control` 的 Raft、control state、operation journal 和服务端密钥；管理员交付目录
  单独离线备份。恢复必须是整组原子恢复，不能混用两次 bootstrap 的文件。
- 发布前记录 exact Git commit、二进制 SHA-256、signed-current generation、ControlSet hash、certified
  Head hash、管理员交付目录位置和证书到期日。真实值只写部署机受限 handoff，不写仓库。
- 若状态目录存在但服务无法启动，先运行只读校验和查看 journal；禁止再次下载镜像、再次 bootstrap 或
  覆盖原状态来掩盖问题。

## 验收清单

1. `systemctl is-active loom-control` 为 `active`，监听仅出现于已登记 overlay tuple。
2. 带正确管理员材料的 `status` 成功；随机 client certificate 返回 `403`。
3. `control_ping` 推进 certified Head，Raft `commit_index == last_applied`，operation tree size 单调增加。
4. 重启服务后 certified Head 不变，再次 `control_ping` 成功且 term/index 前进。
5. 从公网接口探测 control/Raft 端口不可达。
6. v1 compatibility 仍可用；在 Linux、Windows、Android 全部满足 Gate B 前不得删除。
