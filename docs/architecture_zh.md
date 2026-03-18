# mydns 架构说明（中文）

## 1. 设计目标

`mydns` 采用插件式流水线架构，面向终端访问体验优化。优先关注 `A/AAAA/HTTPS` 查询，其次兼容 `SRV/TXT/rDNS` 等类型。

## 2. 抽象模型

每个请求由 `QueryContext` 承载核心状态：

- 请求抽象：`(clientaddr, qname, qtype, ecs)`
- 响应抽象：`(rcode, list[RRset])`
- 过程状态：路由标签、上游统计、测速结果、选中 IP、调试标签等

实现上尽量复用 `dnspython` 内置结构（如 `Name`、`RRset`、`rdatatype`）。

## 3. 三阶段流水线

流水线顺序固定为：

1. `request` 阶段
2. `upstream` 阶段
3. `response` 阶段

三个阶段均通过 Hook 扩展：

- `before_upstream(context)`：请求预处理、路由、拦截、短路应答
- `after_upstream(context, rcode, answer, resolver_name)`：每个上游返回后的副作用处理（日志、测速、改写）
- `before_response(context)`：最终响应出站前处理

## 4. 上游并发与 A/AAAA 策略

`ResolverManager` 会并发请求符合 tag 的 resolver：

- 普通查询：返回最快可用结果
- `A/AAAA` 查询：收集全部上游结果，结合异步测速结果选取最快的多个 IP

关键点：

- 保留 CNAME 链
- 仅替换目标 `A/AAAA` 的 RRSet
- 可通过 `rules.ip_benchmark_top_n` 控制保留 IP 数量

## 5. 配置要点（YAML）

示例见 `config.example.yaml`，核心字段：

- `upstreams[]`：上游协议、地址、超时、tag、ECS、TLS/DoH 参数
- `rules.domainset_dirs` / `rules.ipset_dirs`：路由规则目录
- `rules.ad_block_tags`：命中后返回 `NOERROR` 空应答
- `rules.ip_benchmark_top_n`：A/AAAA 查询保留的最快 IP 数

## 6. 自检建议

开发后建议至少执行：

```bash
python -m compileall core resolvers selector rules cache app.py config.py main.py
```

并进行最小链路验证：

- 能正确返回 `NOERROR` 与 answer
- 缓存命中后上游调用次数下降
- A/AAAA 返回多个最快 IP 且 CNAME 链完整
