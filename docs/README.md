# 文档入口

按当前任务阅读对应正文。工作边界见 [AGENTS.md](../AGENTS.md)，源码支持范围见
[实现对照](development/implementation.md)；规范描述要求，不能用来证明实现或部署完成。

| 任务 | 规范与操作入口 |
|---|---|
| 理解模型、渲染、隧道和服务器调度 | [架构总览](architecture/README.md)、[实现依赖](development/dependencies.md) |
| 控制面、共识、Enrollment 与迁移 | [控制面规范](protocols/control-plane/README.md)、[实施规程](development/control-plane.md)、[操作手册](operations/control-plane.md) |
| Device 创建、权限与生命周期 | [Device 生命周期](architecture/device-lifecycle.md) |
| 客户端接入、选路、平台交付 | [客户端规范与操作](clients/README.md) |
| 发布、DNS 与本机部署参数 | [本机配置与部署](operations/local-deployment.md) |
| 管理员证书与代码签名 | [管理员证书](operations/admin-certificates.md)、[代码签名](operations/code-signing.md) |
| 加入网络耗时排查 | [入网排查](operations/enrollment-diagnostics.md) |
| 评估尚未采用的扩展 | [Local Network](proposals/local-network.md)、[密钥保护强化](proposals/key-protection.md) |

## 维护规则

- 每项规则只有一个正文出处，其他文档链接该主题；必要理由就近说明，历史过程由 Git 保留。
- 标明适用版本和状态：已批准规范、迁移输入、提案和源码能力不能互相代替。
- 使用语义标题与直接链接；移动正文时更新所有入链，删除失效入口和重复正文。
- 文档目录只保存正文与配图。部署参数在私有配置，必要回执在 `deploy/evidence/`，制品在 `out/` 或 `dist/`。
- 修改正常入口或持久状态时同步更新实现对照；操作手册不保存临时任务指令或部署流水账。

检查：`python3 scripts/check_documentation.py` 与 `python3 scripts/check_repository_safety.py`。
链接检查保证引用可达；协议与实现的准确性仍须由对应源码和验收证据确认。
