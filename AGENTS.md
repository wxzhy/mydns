# AGENTS.md

本文件为本仓库内的 AI/自动化协作代理提供工作约定，目标是：**先理解架构，再做最小改动，并用测试验证**。

## 1. 项目定位

`mydns` 是一个 **插件式 DNS 流水线服务器**，核心目标是在 DNS 查询链路中提供可插拔处理能力（规则、缓存、测速、改写）。

- 主要查询类型：`A / AAAA / HTTPS`
- 兼容基础通路：`SRV / TXT / PTR`
- 主流程：`request hooks -> upstream collect -> response hooks`

## 2. 关键入口与调用链

- 启动入口：`main.py`
	- 解析 CLI 参数（`--config --host --port`）
	- 默认加载 `config/mydns.example.yaml`
	- 创建并启动 `UDPDNSServer` / `TCPDNSServer`
- 运行时装配：`config.py`
	- `load_runtime_config()` / `build_runtime_config()`
	- 构建 `Pipeline`
- 核心编排：`core/pipeline.py`
	- `Pipeline.process(ctx)`
- 并发上游：`upstream/resolver_manager.py`
	- `collect()` 对匹配标签的 resolver 并发查询
- 请求/响应编解码：`core/wire.py`
	- `parse_query_context()` / `build_response_wire()`

## 3. 核心模型（修改前必须理解）

- `core/models.py`
	- `Query`
	- `ResolverResult`
	- `IPList`
- `core/context.py`
	- `QueryContext`
		- `query`, `candidates`, `final_answer`, `tags`, `state`, `stop`
- `core/answer.py`
	- `Answer`（对 `dns.resolver.Answer` 的封装）
	- 负责 `rcode`、`rrset`、`message`、`chaining_result` 同步

## 4. 插件与阶段约定

Hook 接口在 `core/hooks.py`：

- `RequestHook.on_request(ctx)`
- `ResolverHook.on_resolver_result(ctx, result)`
- `ResponseHook.on_response(ctx)`

内置插件目录：`plugins/`

### 执行顺序要求（非常重要）

来自 `config.py` 的语义校验：

1. `plugins.domain_rule.DomainRuleRequestHook` 必须在 `plugins.cache.CacheHook` **之后**（请求阶段）
2. `plugins.tagset.TagSetResolverHook` 必须在 `plugins.ip_rule.IPRuleResolverHook` **之前**（若同时存在）
3. `plugins.tagset.TagSetResolverHook` 和 `plugins.ip_rule.IPRuleResolverHook` 必须在 `plugins.speedcheck.SpeedCheckResolverHook` **之前**

变更 hook 顺序时，务必同步更新配置测试。

## 5. 上游并发与选择策略

- A/AAAA：`wait_all`，等待所有匹配 resolver 的结果，再由 response 阶段（`RewriteAnswerByRTTHook`）按 RTT 选择最快 IP
- 其他类型：`first_success`，拿到首个正常结果后提前结束
- 若最终无可用结果：`Pipeline` 回退 `SERVFAIL`

## 6. 常见改动注意事项

1. **不要跳过 `core/wire.py` 校验逻辑**：仅接受 `QUERY opcode + IN qclass`
2. 改写 `Answer.response.answer` 后应通过既有方法刷新（如 `replace_rrset()/update_message()`）
3. A/AAAA 改写时应保留 CNAME 链语义，不要直接覆盖整个 response
4. 涉及缓存（`plugins/cache.py` 与 `core/cache.py`）时，注意 pending 合并请求语义，避免击穿
5. 涉及 Windows 网络行为时，注意 `main.py` 的 `winuvloop.install()` 与 tricks socket 相关测试

## 7. 开发与测试

推荐命令：

- 全量测试：`python -m unittest discover -s tests -v`
- 使用 uv：`uv run python -m unittest discover -s tests -v`

分层测试文件已按 step1~step5 组织，优先补充对应阶段的测试，再改实现。

## 8. 文档与代码同步要求

当修改以下内容时，必须同步更新 README：

- 流水线阶段和选择策略
- 配置字段（尤其是 `hooks/resolvers/domain_rules/ip_rules`）
- 启动参数与默认监听行为
- 测试命令

---

如果你是协作代理：

1. 先读 `main.py / config.py / core/pipeline.py / upstream/resolver_manager.py`
2. 再定位插件或 resolver 细节
3. 最后用测试验证，不要只做“静态看起来没问题”的改动
