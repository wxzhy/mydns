# mydns：插件式流水线 DNS 服务器（Python）

## 项目简介
`mydns` 采用插件化 + 流水线架构实现 DNS 查询处理，目标是为终端设备提供更好的网页访问体验。  
当前优先支持与优化：`A / AAAA / HTTPS`，同时兼容 `SRV / TXT / PTR(rDNS)` 的基础通路。

## 核心抽象
- `Query = (client_addr, qname, qtype, ecs)`
- `Answer = (rcode, list[rrset])`
- `QueryContext = (query, candidates, final_answer, tags, state, stop)`

为简化首版设计，忽略 `qclass`、`authority` 等非关键字段。

## 流水线阶段
```text
request hooks -> upstream (ResolverManager并发) -> response hooks
```
- `request hooks`：请求首部处理，可打标签、短路返回。
- `upstream`：按标签筛选 resolver，并发查询；每个结果返回后立刻执行 `resolver hooks`。
- `response hooks`：响应尾部处理。

### 响应选择策略（首版）
- `A/AAAA`：并发返回后按时延聚合，选最快 2 个去重 IP，并保留 `CNAME chain`。
- `HTTPS/SRV/TXT/PTR`：采用“最快成功结果直通”。

## 目录结构
```text
core/      核心模型、hook接口、pipeline、resolver_manager、selector、wire转换
plugins/   内置示例插件（Noop）
server/    UDP 服务接入层
tests/     单元测试与集成测试
```

## 运行方式
1. 安装依赖：`uv sync`
2. 启动服务：`uv run python main.py --host 127.0.0.1 --port 5353`
3. 示例查询（Windows）：`nslookup -type=A www.example.com 127.0.0.1`

## 测试命令
- 运行单个测试：`uv run python -m unittest -v tests/test_selector_step4.py`
- 运行全量测试：`uv run python -m unittest discover -s tests -v`

## 插件扩展方式（代码注册）
当前版本使用代码注册表装配插件，入口位于 `app.py`：
- 注册 `request_hooks / resolver_hooks / response_hooks`
- 注册 `resolvers`
- 传入 `Pipeline(...)` 统一编排

## 示例配置（说明用途）
项目提供 `config/mydns.example.yaml` 用于展示未来配置化方向。  
当前运行时仍以 `app.py` 代码注册为准。
