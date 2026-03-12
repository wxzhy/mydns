# mydns

一个简单、可扩展的 UDP DNS 转发器。

## 功能特性

- 异步 UDP DNS 监听
- 支持多个上游 DNS 转发
- 并发请求上游并返回最快成功响应
- 内置基于 TTL 的 LRU DNS 缓存（请求前命中、完成后回写）
- 三阶段 Hook 流水线：
  - 请求阶段：`before_upstream`
  - 上游阶段：`after_upstream`
  - 响应阶段：`before_response`
- 清晰分层：`server -> pipeline -> resolver`
- 基于 YAML 的配置，带默认值

## 项目结构

- `main.py`：进程入口与生命周期管理
- `app.py`：应用装配
- `config.py`：配置模型、加载与校验
- `servers/udp_server.py`：UDP 传输服务
- `core/pipeline.py`：请求处理流水线
- `core/hooks.py`：阶段 Hook 协议与执行器
- `resolvers/resolver.py`：Resolver 抽象
- `resolvers/udp_resolver.py`：UDP 上游解析实现
- `selector/resolver_manager.py`：上游 Resolver 初始化与选择管理
- `rules/request`：请求阶段规则（域名拦截 / hosts / 请求日志）
- `rules/upstream`：上游阶段规则（上游日志 / 响应改写）
- `rules/response`：响应阶段规则（最终结果日志 / 响应改写）

## 快速开始

```bash
uv run python main.py
```

默认读取 `./config.yaml`。

## 配置说明

示例：

```yaml
server:
  host: 0.0.0.0
  port: 5353
  max_packet_size: 4096

logging:
  level: INFO

cache:
  enabled: true
  max_size: 10000

upstreams:
  - host: 223.5.5.5
    port: 53
    timeout: 2.0
  - host: 8.8.8.8
    port: 53
    timeout: 2.0
```

使用自定义配置文件：

```bash
uv run python main.py --config ./config.yaml
```
