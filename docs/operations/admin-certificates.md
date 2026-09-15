# 浏览器管理员证书

> 类型：操作边界。适用于管理员身份轮换、导出、交付及浏览器验收。
> 具体命令见[控制面操作规程](../control-plane-operations.md)；协议见[控制面规范](../distributed-control-plane.md)。

- 管理员新证书必须使用完整 P-256 leaf/issuer 链，证书签名为 ECDSA/SHA-256，leaf 用途仅为
  clientAuth；同一管理员 key 用于 mTLS 与控制操作签名。旧 Ed25519 身份仅用于历史验证和迁移。
- 统一使用 `loom control export-admin` 打包，它核对完整链、私钥匹配、包内仅一个管理员 key；
  不复制缺少 issuer 的手工 `openssl pkcs12 -export` 命令。Root CA 私钥不得进入交付包。
- 更换管理员证书必须经 [管理员轮换说明](../control-plane-operations.md) 的本机 N=1
  `control rotate-admin` 流程，使新证书进入 certified ACL；不得重新 bootstrap 或手工改 Head/ACL。
- 新证书验证通过后，立即将证书、私钥、完整包、密码和端点文件整套替换回原交付路径，并清理
  失效旧文件与临时目录。不得把失效包当作回滚备份，也不得只给用户新路径却留下原路径的失效文件。
- 验收必须区分“包内材料正确”“真实 TLS 管理权限通过”“Windows Chrome 实机通过”。只读页面
  可打开、Go/OpenSSL 验签通过或测试中注入 TLS 字段，均不能当成浏览器管理员验收。
- Windows 显示系统层错误/无效数字签名时，先查证书及 issuer 的算法、完整链和私钥匹配，不先
  要求用户反复导入或重启。网站根 `control-root.crt` 与管理员签发根 `admin-root.crt` 分别说明。
- 管理员导入的目的是让浏览器使用私钥完成服务端身份认证。不得把 Windows 本地信任
  `admin-root.crt` 或消除证书查看器红叉当作登录前置条件；验收看网站 TLS、客户端证书选择与
  服务端实际授权。网站信任已建立时只需导入 `admin.p12`，不追加根证书安装或安装脚本。
- Windows 完整 PKCS#12 包使用“根据证书类型，自动选择证书存储”，由向导分别放置管理员身份
  与签发链；不得指导用户把包内所有证书强制放进“个人”，再让其手工拆分根证书。
