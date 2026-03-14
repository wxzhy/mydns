# mydns

一个简单、可扩展的 DNS 转发器。

## 功能特性

- 异步 UDP DNS 监听
- 支持多协议上游 DNS 转发：`udp` / `tcp` / `dot` / `doh` / `doq` / `dnscrypt`
- 并发请求上游并返回最快成功响应
- 内置基于 TTL 的 LRU DNS 缓存（请求前命中、完成后回写）
- 支持 `domainset/ipset` 目录化规则，按 tag 路由请求
- 支持按 tag 返回 `NOERROR` 空应答（可用于广告拦截）
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
- `resolvers/dot_resolver.py`：DoT 上游解析实现
- `resolvers/doh_resolver.py`：DoH 上游解析实现
- `resolvers/doq_resolver.py`：DoQ 上游解析实现
- `resolvers/dnscrypt_resolver.py`：DNSCrypt 上游解析实现
- `resolvers/dnscrypt`：DNSCrypt 异步客户端与 stamp 解析
- `selector/resolver_manager.py`：上游 Resolver 初始化与并发选择管理
- `rules/request`：请求阶段规则（domainset/ipset 路由 / 按 tag 空应答 / hosts / 请求日志）
- `rules/upstream`：上游阶段规则（上游日志 / A/AAAA IP 测速与响应改写）
- `rules/upstream/benchmark`：上游阶段测速模块（`ping` / `tcping` / `scorer`）
- `rules/response`：响应阶段规则（最终结果日志 / 响应改写）
- `utils/domainset.py`：域名规则集合（最长后缀优先匹配）
- `utils/ipset.py`：IP 规则集合（最长前缀优先匹配）

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

rules:
  domainset_dirs:
    - ./rulesets/domainset
  ipset_dirs:
    - ./rulesets/ipset
  ad_block_tags:
    - ad

upstreams:
  - host: 223.5.5.5
    protocol: udp
    port: 53
    timeout: 2.0
  - host: 8.8.8.8
    protocol: tcp
    port: 53
    ecs: 1.2.3.0/24
    timeout: 2.0
  - host: 1.1.1.1
    protocol: dot
    port: 853
    verify: true
    hostname: cloudflare-dns.com
    timeout: 2.0
  - host: 1.1.1.1
    protocol: doq
    port: 853
    verify: true
    hostname: cloudflare-dns.com
    timeout: 2.0
  - host: 1.1.1.1
    protocol: doh
    port: 443
    http_host: cloudflare-dns.com
    path: /dns-query
    verify: true
    hostname: cloudflare-dns.com
    timeout: 2.0
  - protocol: dnscrypt
    stamp: sdns://AQYAAAAAAAAACzEyNy4wLjAuMTo0NDMiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmASMyLmRuc2NyeXB0LWNlcnQuZXhhbXBsZS50ZXN0
    timeout: 2.0
```

上游字段说明：

- `protocol`：`udp` / `tcp` / `dot` / `doh` / `doq` / `dnscrypt`，默认 `udp`
- `host`：上游地址（DoH 可作为 bootstrap 地址，兼容别名 `address`）
- `port`：端口，默认值按协议自动推导：`udp=53`、`tcp=53`、`dot=853`、`doh=443`、`doq=853`、`dnscrypt=443`
- `timeout`：超时秒数
- `ecs`：向上游附加/覆盖的 EDNS Client Subnet（如 `1.2.3.0/24` 或 `2001:db8::/56`，兼容别名 `client_subnet`）
- `verify`：TLS 证书校验（`true`/`false` 或证书路径）
- `hostname`：TLS SNI 主机名（主要用于 DoT/DoQ，也可用于 DoH 兜底，兼容别名 `sni`）
- `http_host`：DoH 请求使用的 HTTP Host
- `path`：DoH 请求路径，默认 `/dns-query`
- `stamp`：DNSCrypt stamp（建议优先配置，支持自动提取地址/端口/provider 信息）
- `provider_name`：DNSCrypt provider 名称（未使用 `stamp` 时必填）
- `provider_pk`：DNSCrypt provider 公钥（十六进制，未使用 `stamp` 时必填）

规则字段说明：

- `rules.domainset_dirs`：域名规则目录列表；每个 `.txt` 文件名即 tag，内容为域名规则
- `rules.ipset_dirs`：IP 规则目录列表；每个 `.txt` 文件名即 tag，内容为 IP/CIDR 规则
- `rules.ad_block_tags`：命中这些 tag 时，直接返回 `NOERROR` 空应答

使用自定义配置文件：

```bash
uv run python main.py --config ./config.yaml
```
