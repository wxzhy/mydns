# mydns：插件式流水线 DNS 服务器（Python）

`mydns` 是一个基于 Python 的可扩展 DNS 服务，采用 **三阶段流水线 + 插件机制** 处理请求。

- 请求阶段可打标签、命中规则并短路
- 上游阶段支持多 resolver 并发查询
- 响应阶段可做测速聚合、记录清洗、缓存写回

当前重点优化类型：`A / AAAA / HTTPS`；其余类型（如 `SRV / TXT / PTR`）走通用快速成功策略。

## 核心特性

- **插件化流水线**：`request hooks -> upstream -> response hooks`
- **多协议上游**：UDP / TCP / TLS(DoT) / HTTPS(DoH) / QUIC(DoQ)
- **标签驱动路由**：通过 `ctx.tags` 与 resolver `tags` 做动态匹配
- **域名/地址规则**：`domainset`（marisa-trie）+ `ipset`（py-radix）
- **测速改写**：A/AAAA 按 RTT 选择最快 IP（默认最多返回 2 个）
- **缓存与请求合并**：同 key 并发请求可等待同一 owner 结果，减少击穿
- **HTTPS 记录处理**：支持 h3/hint 清洗与可选 ECH 注入

## 架构总览

### 主入口

- `main.py`
	- 参数：`--config --host --port`
	- 默认读取 `config/mydns.example.yaml`
	- 启动 `UDPDNSServer` 与（可选）`TCPDNSServer`

### 关键调用链

1. `server/*` 接收 DNS 报文
2. `core/wire.py::parse_query_context()` 解析为 `QueryContext`
3. `core/pipeline.py::Pipeline.process()` 执行三阶段流水线
4. `upstream/resolver_manager.py` 并发请求并执行 resolver hooks
5. `core/wire.py::build_response_wire()` 回包

### 核心模型

- `Query`：客户端地址、qname、qtype、txid、ECS、原始 message
- `QueryContext`：`query / candidates / final_answer / tags / state / stop`
- `Answer`：对 `dnspython` 的统一封装，含 rcode 与 rrset 更新逻辑

## 上游并发与选择策略

- `A/AAAA`：**wait_all**
	- 等待所有匹配 resolver 结果
	- 汇总测速结果后按 RTT 排序
	- 默认返回最快 2 个 IP，并保留 CNAME 链
- 其他类型（含 `HTTPS`）：**first_success**
	- 收到首个正常结果即可提前结束
- 若最终没有有效结果：回退 `SERVFAIL`

## 内置插件（plugins）

- `cache.CacheHook`：请求读缓存 + 响应写缓存
- `domain_rule.DomainRuleRequestHook`：domainset 命中后执行 `intercept/hosts`
- `tagset.TagSetResolverHook`：基于 CNAME 链补标签并可做 uncloaking
- `ip_rule.IPRuleResolverHook`：按结果标签改写 A/AAAA 地址
- `speedcheck.SpeedCheckResolverHook`：IP 测速并写入上下文
- `speedcheck.RewriteAnswerByRTTHook`：按 RTT 重写最终 A/AAAA 结果
- `https_record.HttpsRecordResponseHook`：清洗 HTTPS RR（h3/hint）并按需注入 ECH

> Hook 顺序有约束（由 `config.py` 校验）：
>
> - `DomainRuleRequestHook` 必须在 `CacheHook` 之后
> - `TagSetResolverHook` 必须在 `IPRuleResolverHook` 之前
> - `TagSetResolverHook` / `IPRuleResolverHook` 必须在 `SpeedCheckResolverHook` 之前

## 目录结构

```text
core/      核心模型、上下文、流水线、wire、缓存、集合结构
upstream/  并发调度与响应选择
resolver/  上游解析器抽象与协议实现（udp/tcp/tls/https/quic）
plugins/   内置 request/resolver/response 插件
server/    UDP/TCP 接入层
config/    示例配置与规则文件
tests/     单元测试 + 分阶段集成测试（step1~step5）
```

## 环境要求

- Python `>= 3.13`
- 推荐使用 `uv`

依赖定义见 `pyproject.toml`（`dnspython[doh,doq]`、`pydantic`、`pyyaml`、`icmplib`、`marisa-trie`、`py-radix`、`async-lru` 等）。

## 快速开始

### 1) 安装依赖

- 推荐：`uv sync`

### 2) 启动服务

- 使用示例配置启动（默认路径）：`uv run python main.py`
- 指定配置文件：`uv run python main.py --config config/mydns.example.yaml`
- 覆盖监听地址：`uv run python main.py --host 127.0.0.1 --port 5335`

> 默认配置来自 `config/mydns.example.yaml`；若你传入 `--host/--port`，会覆盖配置文件中的监听参数。

### 3) 发起查询（Windows 示例）

- `nslookup -type=A www.example.com 127.0.0.1`
- `nslookup -type=AAAA www.example.com 127.0.0.1`

## 配置说明

完整示例见 `config/mydns.example.yaml`。

主要字段：

- `server`: `host/port/udp/tcp`
- `pipeline`: `upstream_timeout_s`
- `domainset` / `ipset`: tag 到规则文件的映射
- `domain_rules` / `ip_rules`: 规则引擎配置
- `resolvers`: 上游列表（支持 `type` 或自定义 `class`）
- `hooks`: `request/resolver/response` 三段插件链

## 代码装配方式

除 YAML 方式外，也可直接在 `app.py` 中通过代码注册：

- 构建 `request_hooks / resolver_hooks / response_hooks`
- 构建 resolver 列表
- 传入 `Pipeline(...)`

适用于快速实验或本地调试。

## 测试

- 推荐门禁流程（先烟测，后全量）：
	1. 先运行最小烟测：
		- `uv run python -m unittest -v tests.test_config tests.test_resolver_manager_step3 tests.test_https_record_hook tests.test_speedcheck_hooks tests.test_speedcheck_utils`
	2. 烟测通过后再运行全量：
		- `uv run python -m unittest discover -s tests -v`
- 若烟测失败，先定位并修复失败模块，不直接进入全量回归。
- 全量回归：`python -m unittest discover -s tests -v`
- 使用 uv：`uv run python -m unittest discover -s tests -v`
- 单文件示例：`uv run python -m unittest -v tests/test_selector_step4.py`

测试包含：

- 核心模型与 wire 解析
- pipeline 各阶段行为
- resolver manager 并发策略
- selector 选择逻辑
- trick sockets（运行时 / Windows loop）
- UDP/TCP 集成路径

## 平台说明

- Windows 下入口使用 `winuvloop.install()` 优化事件循环
- `resolver/tricks/` 提供可选的自定义 socket 行为（TCP/UDP）

## 贡献建议

1. 优先做最小改动，保持现有 hook 顺序与语义
2. 新增插件时补充对应单元测试
3. 改动策略（选择、缓存、规则）时同步更新本文档与示例配置
