# Loom 项目工作入口

先完整阅读 [AGENTS.md](AGENTS.md)。本文件只是兼容入口，不另建一套执行规则。

工作前按任务阅读：

- [设计总则](docs/README.md)
- [控制权威模型](docs/core/control-model.md)
- [Enrollment 与 Endpoint 模型](docs/core/enrollment-endpoint-model.md)
- [客户端运行时模型](docs/clients/client-runtime-model.md)
- [本机 `.env` 配置模型](docs/operations/configuration-model.md)
- [控制面 Web 投影](docs/clients/web-ui-projection.md)
- [白名单移植项](docs/migration-whitelist.md)

没有完整同构说明的核心实体不得实现。没有完成正式入口、持久结果、运行时消费、正常回读和旧路径删除的功能不得称为完成。最小业务闭环完成前，不增加扩展矩阵、后台审计、兼容分支或“以后可能需要”的状态机。

控制面 Web、Android 和 Windows UI 产品资产必须尽量保留，但旧后端权威不保留；`.env` 的本机节点/部署输入机制必须保留，但无消费者、可推导、重复或属于运行状态/历史证据的变量必须从正式配置契约移除。`GANDI_PAT_TOKEN` 是当前明确保留的 provider secret。真实 `.env`、`.ssh_config` 与 `deploy/evidence/` 不进 Git，也不得输出其秘密内容。

涉及 GitHub、push、release 或其他外部写入时，先执行
[AGENTS.md 的外部写入规则](AGENTS.md#外部写入)；本文件不重复定义认证通道。

提交前执行 AGENTS.md 所列构建、安全、格式和 diff 检查。
