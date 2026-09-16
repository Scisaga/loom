# v2 私有控制面运维

**适用范围：** 本仓库提供的 N=1 控制服务初始化、管理员材料、启动与相关验收。
正常业务接线及缺口见[实现对照](../development/implementation.md)；协议按[控制面规范](../protocols/control-plane/README.md)。
本文不表示某环境已部署，也不自行授权初始化、换证、发布或停服。

命令中的 `<...>` 由 `.env` 所指部署配置解析；真实值与执行回执按
[本机部署说明](local-deployment.md)保存，不写入本页。已有状态禁止重新 bootstrap。

## 服务边界

- `control` 为 Device 的正交职责；当前 daemon 仅支持 `N=1,q=1`。
- overlay `control_api` 与 Raft 使用不同端口，均不经公网 Nginx。exact IPv4 loopback 上的同号
  control listener 仅提供浏览器 UI，不开放 private status/operation。
- overlay 保留 certified Ed25519 native identity/SPKI pin；loopback 使用独立 P-256 browser
  identity，不能用浏览器根替代原生 CLI/Linux/Android 的 internal root 与 pin。
- 同一 private HTTPS 中，无有效客户端证书只能读取脱敏 UI；当前 certified ACL 精确授权的
  管理员 leaf 才进入配置处理器。没有 UI 密码或登录 Cookie；同源写校验仍适用。
- 浏览器授权不证明业务写入已取得 Raft/QC。`control_ping` 只验证该操作本身，完整业务交付
  仍按[实施规程](../development/control-plane.md)验收。

## DNS 与部署输入

根 `.env` 中 `GANDI_PAT_TOKEN` 用于 Gandi LiveDNS 和 ACME DNS-01，由受保护进程加载；
声明检查、scope、代理和公网地址发现边界见[本机部署说明](local-deployment.md)。
不能把 SSH 管理地址当作服务公网地址，也不能用 NAT listener 尚未就绪阻止合法 DNS 配置。

## 首次初始化

仅全新控制状态使用此步骤。确认目标 Device 已有 control 职责，`<overlay-ip>` 为其实际私有
地址，状态目录尚不存在。命令拒绝覆盖；不能删除既有目录来“重试”。

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

省略 `-member-id` 时生成符合 wire 约束的随机 ULID。初始化形成 Raft index 1 的 bootstrap Head、
本机 durable commit 和 `q=1` replication QC，以 `0600` 写入状态及管理员材料。

```bash
sudo install -m 0644 packaging/systemd/loom-control.service /etc/systemd/system/loom-control.service
sudo systemctl daemon-reload
sudo systemctl enable --now loom-control.service
```

## 管理员访问与材料

材料保管、算法、证书链及验收边界统一见[管理员证书规则](admin-certificates.md)。
`<offline-admin-directory>` 保持 `0700`，文件 `0600`，它包含完整管理员身份：

| 文件 | 用途 |
|---|---|
| `admin.crt` / `admin.key` | P-256 管理员 leaf 和同一把 mTLS/操作签名私钥 |
| `admin-root.crt` | 管理员完整签发链的公开根 |
| `admin.p12` / `admin.p12.password` | 浏览器完整 PKCS#12 身份包及独立交付的密码 |
| `control-root.crt` | 浏览器验证 loopback HTTPS 的 P-256 trust anchor |
| `endpoint.json` | 原生 private tuple、Ed25519 SPKI pin 与 internal CA anchor |

Root CA 私钥不进入交付目录。该目录不能放进仓库、聊天、工单附件或分发镜像。

### 浏览器端口转发

通过已认证的 SSH/开发机会话，将本地同号端口转发到 control Device 的
`127.0.0.1:<control-api-port>`，显式访问 `https://127.0.0.1:<control-api-port>/`。
不要改用 `http://`、`localhost`、公网地址或 wildcard bind。代理环境须将 loopback 设为直连。
原生 CLI 使用 `endpoint.json` 的 overlay 服务，不复用浏览器根。

只有从旧共用 Ed25519 server identity 安装升级、且缺少 browser TLS 时，执行一次幂等迁移：

```bash
sudo /usr/local/bin/loom control enable-loopback \
  -state-dir /var/lib/loom-control \
  -admin-dir <offline-admin-directory>
sudo systemctl restart loom-control.service
```

命令核对既有 native authority，生成独立 P-256 browser root/leaf，并更新交付的
`control-root.crt`。它不改变 native pin/key、管理员身份、ACL、Raft 或 Head；重试不重新生成 authority。

### 导出与轮换

新 `control bootstrap` 自动生成完整 P-256/ECDSA-SHA256 clientAuth 身份包。
导出已有合格身份使用：

```bash
loom control export-admin -admin-dir <offline-admin-directory>
```

命令检查完整链、私钥匹配、PKCS#12 MAC、精确 leaf/issuer 与唯一管理员 key。
已有合格包保持字节和密码不变；旧算法、缺链、错 key 失败，不用手工 OpenSSL 命令绕过检查。

需要轮换既有管理员证书时，在已部署支持版本的 **N=1 控制节点本机**执行；输出使用独立临时目录：

```bash
sudo systemctl stop loom-control.service
sudo /usr/local/bin/loom control rotate-admin \
  -state-dir /var/lib/loom-control \
  -admin-dir <offline-admin-directory> \
  -out-dir <temporary-admin-directory> \
  -reason 'Replace administrator certificate with a complete P-256 chain'
sudo systemctl start loom-control.service
```

轮换要求独占锁、listener 已释放及当前管理员材料。旧 key 授权，新 key 证明持有同一内容；
不扩大原 ID、scope、capability 或授权期限。操作经持久日志、Raft apply 与 QC 后启用新证书，
旧证书退出 ACL；本机维护操作不在网络 registry 开放。

新目录的 `rotation-receipt.json` 保存 Head/QC/inclusion proof，新 CA 私钥仅在控制状态
`admin-issuers/`。相同新目录可核验重试；失败先定位，不重新 bootstrap 或改 ACL。
新身份通过真实管理认证后，将全部材料连同回执替换回原固定交付目录，清理失效文件与临时目录；
后续导出使用原路径。整组内容和验证边界见[证书规则](admin-certificates.md)。

### Windows Chrome / Edge

1. 在运行浏览器的 Windows 用户账户下导入 `admin.p12`，密码由独立文件在本机读取。
2. 选择“当前用户”，证书存储选择“根据证书类型，自动选择证书存储”。不要将整包强制放入“个人”。
3. “个人 → 证书”中的管理员 leaf 应有对应私钥。完整签发链在包内；无需为消除查看器红叉额外
   信任 `admin-root.crt`。仅在网站 TLS 尚未受信任时导入 `control-root.crt` 为网站根。
4. 确认新身份后移除旧个人证书，完全退出浏览器并重新连接上述 HTTPS 地址，选择新管理员证书。
   只刷新页面可能复用旧 TLS 连接；保留 SSH 转发。Firefox 按其“您的证书”入口导入身份包。

出现“系统层错误/无效数字签名”时，先查 leaf/issuer 算法、完整链与 key 匹配，再看 Windows
错误码；不通过忽略 HTTPS 错误验收，不要求反复导入/重启来替代诊断。

## 原设备迁移与配置交付

先在原控制节点准备将被迁移事务认证的真实 Device CA 与独立私有 TLS 材料：

```bash
loom control prepare-migration-materials -state-dir <original-state-dir> \
  -request-id <fixed-migration-request-id> \
  -enroll-port <private-enrollment-port> -config-port <private-config-port> \
  -report-port <private-report-port> -out <protected-directory>/materials.json
```

该命令持有与 `control serve` 相同的维护锁，须先停止控制 daemon，准备后恢复原服务。
它复用原 internal CA，持久保存独立软件 custody 与封装证据；同请求重试复用原材料。
输出目录必须为 `0700`。它不打开 Raft、不竞选、不修改原日志，也不启动或认证新服务；
这份材料仍须进入完整迁移事务。不能把材料准备成功当作设备迁移或生产接入成功。

恢复密钥使用与 control state 分离的受保护保管目录，由显式维护命令生成：

```bash
loom control prepare-recovery -custody-dir <protected-recovery-directory> \
  -cluster-id <original-cluster-id> -policy-id <recovery-policy-id> \
  -custodian-id <custodian-id> -request-id <fixed-receipt-request-id> \
  -out <protected-directory>/recovery-materials.json
```

单保管人软件模式明确使用一份回执、一个故障域。恢复 key、解封 key 和回执 key 相互独立；
从耐久密文回读、解封并实际签名后才生成回执。控制日志接收 policy、保管证明和 PoP，
不接收保管目录中的解封私钥。此命令不证明材料已经复制到离线介质。
同请求返回原回执；回执超过十五分钟时，用新 request ID 和新输出路径显式刷新，沿用原 key/密文。
缺失或损坏的保管材料不会自动重建。迁移提交必须验证完整私有保管对象及实际提交时间；
历史重放使用原提交时间，不以当前时钟否定已经认证的记录。

已有设备通过 [客户端迁移](../protocols/control-plane/migration.md) 保留原身份和本机 floor。
`control migrate` 输入可附 `device_inputs`：包含按原 Device ID 排序的客户端签名请求、对应原
signed current；Linux 另附原设备证书及原服务器 CA。它从原 registry/证书独立确认身份，再核对
请求签名、平台信任和本机 floor。Device view、原职责与目的授权、真实证书及签发坐标由迁移命令
在原 Raft 加载后生成，不能同时提供手填 Device view。生成的证书和 current 以内容摘要耐久保存，
同一输入重试复用第一次迁移请求与回执，不重新签发，也不伪造 Enrollment。
这一阶段生成的身份没有运行配置，须经正常配置发布后才能交付客户端使用。
完整生产 application 的服务、catalog、public listener 及配置仍须来自经过验证的部署输入；
客户端请求不是可直接提交的完整 application。接线进度以[实现对照](../development/implementation.md)为准。

本次不在用、尚未提供原 key 迁移请求的独立客户端可以在 `deferred_migrations` 中明确保留原
设备 ID、平台与身份摘要。导入时必须匹配原 SSOT 和 registry；该记录不生成 v2 Device view、
证书、wrapping key 或 Enrollment 事务，也不授予旧入口继续运行的权限。在用服务器与本次要求
迁移的客户端仍须完成真实迁移；暂存身份不是迁移成功，不能据此关闭对应客户端验收项。

原身份已进入认证日志、证书与配置材料已就绪后，通过私有管理员入口导出：

```bash
loom control export-migration \
  -admin-dir <offline-admin-directory> -device <device-id> -out <private-output-directory>
```

生成的 `device.loom-migration` 由客户端正常文件导入入口消费。它绑定原平台、身份、
wrapping key、旧 signed current 与实际 v2 Head；不能用新邀请替代迁移，也不能清除本机身份重试。

已迁入认证状态的 Android/Windows 设备可使用 `control publish-client-config`，从当前认证网络
生成运行配置、封装原 wrapping key 对应的凭据，并提交管理员签名操作：

```bash
loom control publish-client-config \
  -admin-dir <offline-admin-directory> -input <private-client-input> \
  -request-id <proposal-id> -out <private-request-directory>
```

`<private-client-input>` 为 `0600` JSON 文件，字段定义见
[生成入口](../../cmd/loom/control_prepare_client.go)。输入包含设备、原 wrapping 公钥、私有控制
WireGuard 分配、固定 sing-box 版本、服务器观测 CA 和 exact 数据面凭据；它不接受另一份网络
或权限清单。控制目的路由从认证服务目录推导。生成所用的本机 artifact reporter 必须已经获得
当前 authority 授权。原始凭据不写入请求日志，响应丢失时复用输出目录和相同输入。

已有生成器材料也可使用 `control publish-device-config`。`<publication-file>` 保存规范配置、
密文与真实证据；`<proposal-id>` 必须与生成材料时的 ID 相同：

```bash
loom control publish-device-config \
  -admin-dir <offline-admin-directory> -payload <publication-file> \
  -request-id <proposal-id> -out <private-request-directory>
```

输出目录以 `0700` 保存发送前的 exact 签名请求和认证回执；重试复用同一目录。
该操作保留身份、职责和 grants，只推进设备配置代。配置发布回执不代替客户端安装与正常流量验收。

## 按变更选择验收

读取认证状态：

```bash
loom control status -admin-dir <offline-admin-directory>
```

验证 ping 的完整认证提交链（会产生持久写操作，仅在当前任务需要该检查时运行）：

```bash
loom control request \
  -admin-dir <offline-admin-directory> \
  -kind control_ping \
  -reason '<operator audit reason>'
```

成功须同时有 `status=certified`、有效 Head QC 和 operation inclusion proof。该结果不代表
邀请、Enrollment、配置、报告或成员变更完成。

- 服务变更：核对 unit 与实际 overlay/loopback/Raft bind；无 wildcard/public listener。
  private status/operation 经 loopback 拒绝，原生 overlay 入口仍通过。
- 管理员变更：分别记录包检查、真实 TLS 管理权限和 Windows 浏览器实机结果。无证书、未知、
  过期或撤销身份不能写入；同源约束不被放松。Go/OpenSSL 或注入 TLS 的测试不证明 Windows 通过。
- 重启恢复变更：已有 Head 保留，current-term barrier 正常；不要把重复 bootstrap 当恢复。
- 业务迁移：正常创建邀请贯穿私有 Enrollment、签发、配置激活和有效上报，回读持久结果；
  核对实际配置和旧路径删除。仅健康检查、模板、端口可达或拒绝路径不足以交付。

## 备份与恢复

正常启动只使用 `control serve`，在既有日志上 campaign 并提交 current-term barrier。
备份控制状态目录中的 Raft、control state、operation journal 与服务端密钥；管理员材料单独离线
保护。恢复使用同一组状态，不混合不同 bootstrap 的文件。状态存在但启动失败时，先做只读校验
和 journal 检查，不能覆盖状态掩盖错误。

发布与验收回执存入 `deploy/evidence/`，包含实际激活提交、制品、配置与认证坐标；不把它们追加到
本规程。备份输入、原子发布和范围检查见[本机部署说明](local-deployment.md)。
