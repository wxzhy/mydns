from selector.benchmark_selector import BenchmarkSelectResult, resolve_with_ip_benchmark
from selector.concurrent_selector import ResolverRaceResult, resolve_fastest
from selector.resolver_manager import ResolverManager

__all__ = [
    "ResolverManager",
    "ResolverRaceResult",
    "BenchmarkSelectResult",
    "resolve_fastest",
    "resolve_with_ip_benchmark",
]
