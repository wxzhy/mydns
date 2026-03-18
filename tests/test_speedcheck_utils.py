"""测速工具并发行为测试。"""

from __future__ import annotations

import asyncio
import time
import unittest

from plugins.utils import speedcheck


class TestSpeedcheckUtils(unittest.IsolatedAsyncioTestCase):
    async def test_probe_one_ip_returns_fastest_method(self) -> None:
        original_ping = speedcheck._probe_ping
        original_tcp = speedcheck._probe_tcp
        try:
            async def fake_ping(ip: str, timeout_s: float) -> float | None:
                _ = ip, timeout_s
                await asyncio.sleep(0.2)
                return 200.0

            async def fake_tcp(ip: str, port: int, timeout_s: float) -> float | None:
                _ = ip, timeout_s
                await asyncio.sleep(0.05 if port == 80 else 0.1)
                return 50.0 if port == 80 else 100.0

            speedcheck._probe_ping = fake_ping
            speedcheck._probe_tcp = fake_tcp

            start = time.perf_counter()
            rtt = await speedcheck.probe_one_ip("1.1.1.1", timeout_s=0.5)
            duration = time.perf_counter() - start

            self.assertEqual(rtt, 50.0)
            self.assertLess(duration, 0.12)
        finally:
            speedcheck._probe_ping = original_ping
            speedcheck._probe_tcp = original_tcp

    async def test_probe_ips_runs_in_parallel(self) -> None:
        original_probe_one_ip = speedcheck.probe_one_ip
        try:
            async def fake_probe_one_ip(ip: str, timeout_s: float) -> float | None:
                _ = timeout_s
                delay = {"1.1.1.1": 0.05, "2.2.2.2": 0.10, "3.3.3.3": 0.15}[ip]
                await asyncio.sleep(delay)
                return delay * 1000

            speedcheck.probe_one_ip = fake_probe_one_ip

            start = time.perf_counter()
            result = await speedcheck.probe_ips(
                ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
                timeout_s=0.5,
            )
            duration = time.perf_counter() - start

            self.assertEqual(result["1.1.1.1"], 50.0)
            self.assertEqual(result["2.2.2.2"], 100.0)
            self.assertEqual(result["3.3.3.3"], 150.0)
            self.assertLess(duration, 0.22)
        finally:
            speedcheck.probe_one_ip = original_probe_one_ip


if __name__ == "__main__":
    unittest.main()
