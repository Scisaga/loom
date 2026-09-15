# 入网耗时排查规程

**适用条件：** 当前任务要求定位或优化正常入网耗时。协议规则按
[控制面规范](distributed-control-plane.md)，交付按[实施规程](control-plane-implementation-prompt.md)。
本页不预设继续某个旧专项，也不以单 registry、公开 Enrollment 等旧实现约束新版。

## 排查步骤

1. 先用[实现对照](implementation.md)确认当前源码有哪些正常入口，再核对实际部署制品和
   相关[验收记录](operations/local-deployment.md)。其他分支或测试组件不能当作正在运行的服务。
2. 沿真实流程分段计时：创建邀请、静态分发/catalog 验签、bootstrap 隧道、私有 Enrollment、
   reservation、证书准备、approval/completion、配置获取、实际激活。标明失败或等待的具体步骤。
3. 只优化证据支持的瓶颈；保留身份与数据、认证及提交语义。不提前返回 ready，不减少验证，
   不使用空制品、伪造结果或静默回退旧协议。客户端排查不授权修改路由器/NAT 或追加业务探测。
4. 服务端修改接入正式 daemon，完成当前授权的发布和相关正常流程验收；新版替换同时移除
   对应旧实现。真实耗时、节点及制品信息存入 `deploy/evidence/`，不在本页追加任务记录。
