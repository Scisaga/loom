# 服务端入网耗时排查提示词

旧版单 registry、单 publisher、公开 Enrollment 的专项实施提示词已退出当前迁移任务。
它原有的“仅提交、不部署”和保留旧协议要求不撤销用户当前对新版上线、旧功能删除的授权；
不得依据旧提示词继续扩建 v1 处理器。

继续执行[控制面实施与交接提示词](control-plane-implementation-prompt.md)。耗时问题沿正常
创建邀请、静态分发与 catalog 验签、bootstrap 隧道、私有 Enrollment、reservation、证书准备、
approval/completion、配置获取与实际激活逐段定位。只有实测数据支持时优化相应步骤，不用
提前返回 ready、减少验证、空制品或静默回退旧协议来制造完成。

保留已有网络、身份与数据；新功能必须接入实际 daemon，完成已授权的部署和相关正常流程
验收，再删除被替换的旧实现。当前代码、部署和实测状态只读 `docs/status/current.md`。
