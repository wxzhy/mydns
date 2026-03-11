# mydns

Simple, extensible UDP DNS forwarder.

## Features

- Async UDP DNS listener
- Forward to multiple upstream DNS servers
- Upstream failover on timeout/error
- Clear layering: `server -> pipeline -> resolver`
- TOML-based config with sane defaults

## Structure

- `main.py`: process entrypoint and lifecycle handling
- `app.py`: application assembly
- `config.py`: config schema + loading + validation
- `servers/udp_server.py`: UDP transport server
- `core/pipeline.py`: request pipeline / context extraction
- `resolvers/resolver.py`: resolver abstraction
- `resolvers/udp_resolver.py`: UDP upstream forwarder

## Quick Start

```bash
uv run python main.py
```

By default it loads `./config.toml`.

## Config

Example:

```toml
[server]
host = "0.0.0.0"
port = 5353
max_packet_size = 4096

[logging]
level = "INFO"

[[upstreams]]
host = "223.5.5.5"
port = 53
timeout = 2.0

[[upstreams]]
host = "8.8.8.8"
port = 53
timeout = 2.0
```

Use another config:

```bash
uv run python main.py --config ./config.toml
```
