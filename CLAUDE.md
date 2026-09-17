# Loom 重建工作入口

先完整阅读 [AGENTS.md](AGENTS.md)。本文件只是兼容入口，不另建一套执行规则。

当前源码从 `6be9e4c9` 开始最小重建；旧 v2 代码封存在
`archive/v2-overgrown-20260917`，不能把旧代码、旧测试或旧 issue 当成需求。源码基线变化不表示生产回退，现网身份、密钥、数据、floor 和 v2 latch 必须保留。

工作前按任务阅读：

- [重建总则](docs/rebuild/README.md)
- [控制权威模型](docs/rebuild/control-model.md)
- [Enrollment 与 Endpoint 模型](docs/rebuild/enrollment-endpoint-model.md)
- [客户端运行时模型](docs/rebuild/client-runtime-model.md)
- [本机 `.env` 配置模型](docs/rebuild/configuration-model.md)
- [控制面 Web 投影](docs/rebuild/web-ui-projection.md)
- [白名单移植项](docs/rebuild/migration-whitelist.md)

没有完整同构说明的核心实体不得实现。没有完成正式入口、持久结果、运行时消费、正常回读和旧路径删除的功能不得称为完成。最小业务闭环完成前，不增加扩展矩阵、后台审计、兼容分支或“以后可能需要”的状态机。

控制面 Web 产品必须保留，但旧后端权威不保留；`.env` 的本机节点/部署输入机制必须保留，但无消费者、可推导、重复或属于运行状态/历史证据的变量必须从正式配置契约移除。真实 `.env`、`.ssh_config` 与 `deploy/evidence/` 不进 Git，也不得输出其秘密内容。

提交前执行 AGENTS.md 所列构建、安全、格式和 diff 检查。
