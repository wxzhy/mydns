"""按 tag 组织的 IP/CIDR 集合。"""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from pathlib import Path

import radix


class IPSet:
    """使用 py-radix 管理按 tag 分组的网段规则。"""

    def __init__(self) -> None:
        # 规则来自 geoip 抽取，CIDR 不重复，统一放在一棵 radix tree 中。
        self._tree = radix.Radix()

    def load_from_file(self, filepath: str | Path, tag: str) -> None:
        path = Path(filepath)
        with path.open("r", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, start=1):
                value = _clean_line(raw_line)
                if value is None:
                    continue
                try:
                    rnode = self._tree.add(_normalize_cidr(value))
                    rnode.data["data"] = tag
                except Exception as exc:
                    raise ValueError(
                        f"ipset 规则非法 file={path} line={line_no}: {exc}"
                    ) from exc

    def load_from_files(self, filepaths: list[str | Path], tag: str) -> None:
        for filepath in filepaths:
            self.load_from_file(filepath, tag)

    def load_from_mapping(
        self,
        mapping: dict[str, list[str | Path]],
        *,
        base_dir: Path | None = None,
    ) -> None:
        for tag, paths in mapping.items():
            resolved = [_resolve_path(path, base_dir=base_dir) for path in paths]
            self.load_from_files(resolved, tag)

    def match(self, ip: str, tag: str) -> bool:
        text = ip.strip()
        if not text:
            return False
        try:
            parsed = ip_address(text)
        except Exception:
            return False
        rnode = self._tree.search_best(str(parsed))
        if rnode is None:
            return False
        return rnode.data.get("data") == tag

    def match_tags(self, ip: str) -> set[str]:
        text = ip.strip()
        if not text:
            return set()
        try:
            parsed = ip_address(text)
        except Exception:
            return set()
        rnode = self._tree.search_best(str(parsed))
        if rnode is None:
            return set()
        tag = rnode.data.get("data")
        if isinstance(tag, str) and tag:
            return {tag}
        return set()

    @property
    def tags(self) -> set[str]:
        result: set[str] = set()
        for rnode in self._tree:
            tag = rnode.data.get("data")
            if isinstance(tag, str) and tag:
                result.add(tag)
        return result

    def clear(self) -> None:
        self._tree = radix.Radix()

    def init(
        self,
        mapping: dict[str, list[str | Path]] | None,
        *,
        base_dir: Path | None = None,
    ) -> None:
        self.clear()
        if mapping:
            self.load_from_mapping(mapping, base_dir=base_dir)


ipset = IPSet()


def init_ipset(
    mapping: dict[str, list[str | Path]] | None,
    *,
    base_dir: Path | None = None,
) -> IPSet:
    ipset.init(mapping, base_dir=base_dir)
    return ipset


def _clean_line(raw_line: str) -> str | None:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None
    if "#" in line:
        line = line.split("#", 1)[0].strip()
    if not line:
        return None
    return line


def _normalize_cidr(text: str) -> str:
    if "/" in text:
        return ip_network(text, strict=False).with_prefixlen
    parsed_ip = ip_address(text)
    mask = 32 if parsed_ip.version == 4 else 128
    return f"{parsed_ip}/{mask}"


def _resolve_path(path: str | Path, *, base_dir: Path | None) -> Path:
    raw = Path(path)
    if raw.is_absolute() or base_dir is None:
        return raw
    return base_dir / raw
