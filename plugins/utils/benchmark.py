"""兼容入口：测速能力已迁移到 plugins.utils.speedcheck。"""

from __future__ import annotations

from plugins.utils.speedcheck import probe_ips, probe_one_ip

__all__ = ["probe_ips", "probe_one_ip"]
