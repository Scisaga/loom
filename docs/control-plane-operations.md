# v2 私有控制面运维

本文记录单成员 `ControlSet` 的一次性初始化、管理员材料、systemd 启动与验收方法。命令中的
`<...>` 必须由当前部署事实替换；仓库不记录真实节点地址、成员 ID、证书或私钥。

## 边界

- `control` 是 Device 的正交职责。初始部署为 `N=1,q=1`，不改变普通转发职责。
- `control_api` 与 Raft 分别绑定私有 overlay IP 和不同端口；两者不经公网 Nginx。同一
  `control_api` 端口在 IPv4 loopback 另有一个只提供浏览器 UI 的 listener，便于通过已认证的
  SSH/开发机端口转发访问；private status/operation 仍只接受 overlay listener。
- overlay listener 保留 certified Ed25519 server identity 与 SPKI pin；loopback listener 使用独立的
  P-256 ECDSA browser identity。二者同端口但按 exact local address 隔离，浏览器兼容性不会改变
  Linux、Android 或 CLI 的原生控制协议身份。
- 管理员证书、control peer 证书、control API server 证书使用不同 key 和用途 profile。
- 同一 private HTTPS `control_api` 同时承载浏览器 UI：未提交客户端证书时只能读取脱敏视图；
  提交当前 certified ACL 精确授权的管理员 leaf 时才启用配置处理器。不存在 UI 口令或登录 Cookie。
- Windows v2 客户端已有实现；是否有 Windows Device 参与 Gate B 必须从当前 certified deployment
  inventory 与实际验收证据判断，不能根据本静态文档推断“未实现”或“未部署”。
- 当前生产 reducer 只登记 `control_ping`，用于验证管理员签名、Raft commit、QC 和 inclusion proof。
  未实现的 operation kind 会失败关闭，不会返回伪造的“成功”。

## Gandi DNS 凭据

本部署环境在仓库根目录被忽略的 `.env` 中声明 `GANDI_PAT_TOKEN`。它是 Gandi Personal
Access Token，仅用于 LiveDNS 记录操作和 ACME DNS-01，不是 Device、Enrollment、心跳或
ControlSet token。tracked 文档只记录变量名和用途，不记录其值。

运行 DNS/证书任务前，先用下面的只读检查确认 `.env` 中存在声明；只检查当前进程的
`env` 不足以判定缺失，因为 `.env` 不会自动 export：

```bash
test -f .env &&
  grep -Eq '^[[:space:]]*(export[[:space:]]+)?GANDI_PAT_TOKEN=' .env
```

实际值只由执行 DNS/ACME 操作的受保护进程通过 dotenv/环境边界读取。禁止 `echo`、调试 trace、
命令行参数、日志、截图、证据或生成配置包含该值。Gandi adapter 仍须显式限制 zone 与允许的
record name 前缀，拒绝重定向和 credential proxy，并在写后 readback；变量存在不等于凭据有效，
认证或 scope 失败时只报告状态和失败层。

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
- `admin.key`：同一 P-256 key，用于浏览器/CLI mTLS 与 `ControlOperationBodyV1` 签名；
- `admin-root.crt`：P-256 管理员签发根，随完整证书链交付；
- `control-root.crt`：浏览器验证 loopback HTTPS 服务端证书所需的公开 P-256 trust anchor；
- `endpoint.json`：原生 private service tuple、Ed25519 server SPKI pin 与 internal CA anchor。

目录应在加密介质上保持 `0700`，文件保持 `0600`。不要把它放进仓库、聊天、工单附件或分发镜像。
访问端可直接路由到 `<overlay-ip>`，也可经已认证的 SSH/开发机会话把本地同号端口转发到
control Device 的 `127.0.0.1:<control-api-port>`。不能改用公网地址，也不能把 loopback
改成 wildcard/public bind。

### 浏览器证书包

浏览器的规范入口是端口转发：远端目标必须是 `127.0.0.1:<control-api-port>`，本地使用同一端口并
显式访问 `https://127.0.0.1:<control-api-port>/`；不要使用 `http://` 或 `localhost`。overlay
tuple 上仍是供 Linux、Android 和 CLI 使用的 certified native identity，不要把浏览器兼容根用于替代
`endpoint.json` 的原生 pin/root 验证。`control-root.crt` 与
`admin.p12` 用途不同：前者只让浏览器信任 Loom 的 HTTPS 服务端；后者包含管理员 leaf 和对应私钥，
让 TLS 客户端认证获得配置权限。Root CA **私钥**永远不进入浏览器。

从早期共用 Ed25519 server identity 的安装升级时，先执行一次幂等迁移，再重启服务：

```bash
sudo /usr/local/bin/loom control enable-loopback \
  -state-dir /var/lib/loom-control \
  -admin-dir <offline-admin-directory>
sudo systemctl restart loom-control.service
```

迁移生成独立的 P-256 browser root/leaf，原子写入 control 状态并把交付目录中的
`control-root.crt` 更新为浏览器根。它先核对 `endpoint.json` 与既有 native authority，且不改写
native server 私钥/证书/SPKI pin、admin leaf/private key、certified ACL、Raft 或 Head；重复执行不
重新生成 authority。该拆分用于兼容不声明 Ed25519 TLS 签名算法的浏览器。

### 生成与交付检查

新 `control bootstrap` 自动生成 **P-256 管理员私钥、P-256 签发根、ECDSA/SHA-256
clientAuth 证书与完整 `admin.p12`**。管理员 TLS 与操作签名使用同一身份。旧 Ed25519 profile
仅用于读取历史和完成迁移，不能继续把旧包交付给 Windows Chrome/Edge。

对已经生成的 P-256 身份，使用统一导出命令；不要复制缺少 `-certfile` 的手工 OpenSSL 命令：

```bash
loom control export-admin -admin-dir <offline-admin-directory>
```

该命令校验证书用途、有效期、完整 P-256 链、私钥匹配和 PKCS#12 MAC，再核对包中精确的
leaf + issuer 与唯一的管理员私钥。已有合格包保持字节和密码不变；旧算法、缺链、错 key
或不合格已有包直接失败。Root CA 私钥只留在受保护的控制状态中，不进入交付目录或 `.p12`。

### 既有管理员证书轮换

先部署支持 P-256 管理员 profile 的版本，再在 **N=1 控制节点本机**执行以下维护。
停止控制 daemon；原管理员目录用于轮换认证，输出目录必须另设为临时目录。
不要重新 bootstrap 或手工改写 `config.json`、ACL root、Raft、Head。

```bash
sudo systemctl stop loom-control.service
sudo /usr/local/bin/loom control rotate-admin \
  -state-dir /var/lib/loom-control \
  -admin-dir <offline-admin-directory> \
  -out-dir <temporary-admin-directory> \
  -reason 'Replace administrator certificate with a complete P-256 chain'
sudo systemctl start loom-control.service
```

命令要求状态目录独占锁、所有控制 listener 已释放、当前 certified 管理员的完整证书/私钥，
并核对该身份属于当前控制面。旧 key 签署精确轮换内容，新 key 提供同一内容的持有证明；
管理员 ID、允许的操作、capability、scope 与授权截止时间保持原值。
`local_admin_certificate_rotation` 只用于本机维护，不在网络操作 registry 注册。

轮换作为独立操作写入持久日志，经 Raft commit、状态机 apply 和 QC 后才启用新证书并使旧证书
退出当前 ACL。重启从已认证的操作记录恢复有效身份；初始 config、原生服务证书、浏览器网站
证书、ControlSet 与数据面配置保持原字节。新目录的 `rotation-receipt.json` 记录 certified Head、QC
和 inclusion proof；CA 新私钥保存在控制状态下的 `admin-issuers/`。使用同一新目录重试可核验
已完成结果，不能生成第二把 key 或扩大权限。失败后先按命令错误检查，不能回滚到已经失效的旧包。

轮换与真实管理认证验证通过后，立即把完整交付目录替换回原 `<offline-admin-directory>`，包含
`admin.crt`、`admin.key`、`admin-root.crt`、`admin.p12`、`admin.p12.password`、`control-root.crt`、
`endpoint.json` 和 `rotation-receipt.json`；保持目录 `0700`、文件 `0600`，整套替换避免证书与密码混用。
清理失效旧文件及临时目录，同步更新当前状态与交付说明。失效包没有回滚用途，不另作备份，
不能让原路径继续指向它。交付与再次导出始终使用原固定路径。

### Windows Chrome / Edge 导入

在**运行浏览器的 Windows 用户账户**下操作：

1. 将 `admin.p12` 下载到管理员电脑。密码通过单独的
   `admin.p12.password` 文件交付，在本机读取，不写入聊天、命令参数、截图或文档。
2. 双击 `admin.p12`，选择“当前用户”，输入导入密码，将管理员证书放入“个人”。
3. `certmgr.msc` 的“个人 → 证书”中，新管理员证书应显示有对应私钥。完整签发链已经包含在
   `admin.p12` 中；管理员身份由控制面验证，不要求 Windows 把 `admin-root.crt` 设为受信任根。
   查看器单独显示“根证书不受信任”不能证明客户端认证失败，也不要求为消除红叉安装根。
4. 仅在浏览器尚未信任控制中心网站 HTTPS 时，将 `control-root.crt` 安装到
   “当前用户 → 受信任的根证书颁发机构”；网站信任已经建立则跳过。确认新管理员证书后
   移除旧的个人证书，避免选择过期或已退出 ACL 的身份。
5. 完全退出 Chrome/Edge 后重新打开 `https://127.0.0.1:<control-api-port>/`，保持 SSH/VS Code
   转发连接；客户端证书选择框中选新管理员证书。只刷新页面可能复用旧 TLS 连接。

Firefox 可在“设置 → 隐私与安全 → 证书 → 查看证书 → 您的证书”中导入 `.p12`；网站根由浏览器
的信任设置处理。不得通过忽略 HTTPS 错误来完成验收。

### 验收与故障定位

- 包检查通过只证明生成与打包正确。还必须验证限制为 `ecdsa_secp256r1_sha256` 的真实 TLS 1.3
  双向认证能到达管理员 UI；无证书、未知或旧证书仍为只读，写入仍受同源检查约束。
- Windows 实机验收还需确认网站 TLS 验证通过、私钥可用、Chrome/Edge 选中新证书且服务端
  接受后进入管理态；本地管理员根的信任状态不代替这些结果。
  Go/OpenSSL 成功或手工注入 `request.TLS` 的测试不能宣称完成 Windows 浏览器验收。
- “系统层错误 / 无效数字签名”：先检查 leaf 与 issuer 的公钥和签名算法、证书链是否完整、key
  是否匹配，再检查 Windows 错误码。单凭中文错误不能断言文件损坏，也不能让用户反复重启。
- 新旧证书选择错误、未提供客户端证书、过期/revoked 或未获当前 certified ACL 授权仍会只读。
  `control-root.crt` 只解决网站信任；导入它不会赋予管理员权限。

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
  不重新 bootstrap，不重新生成证书。`enable-loopback` 只是 browser TLS 的一次性、幂等迁移。
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
