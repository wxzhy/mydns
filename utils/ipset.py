from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from pathlib import Path

import radix


def _strip_comment(raw_line: str) -> str:
    line = raw_line.strip()
    if not line:
        return ""
    if line.startswith("#") or line.startswith("//") or line.startswith(";"):
        return ""
    line = line.split("#", 1)[0].split(";", 1)[0].strip()
    return line


def _normalize_network(value: str) -> str:
    """
    规范化为 CIDR 字符串：
    - `1.2.3.4` -> `1.2.3.4/32`
    - `2001:db8::1` -> `2001:db8::1/128`
    - `1.2.0.0/16` 保持网络格式（strict=False）
    """
    token = value.strip().split(maxsplit=1)[0]
    if not token:
        return ""
    try:
        if "/" in token:
            return ip_network(token, strict=False).with_prefixlen
        addr = ip_address(token)
        return ip_network(f"{addr}/{addr.max_prefixlen}", strict=False).with_prefixlen
    except ValueError:
        return ""


def _iter_txt_files(directory: Path) -> list[Path]:
    if not directory.exists():
        raise FileNotFoundError(f"目录不存在: {directory}")
    if not directory.is_dir():
        raise NotADirectoryError(f"不是目录: {directory}")
    return sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and path.suffix.lower() == ".txt"
    )


def _parse_target_to_query(target: str) -> tuple[bytes, int] | None:
    text = target.strip()
    if not text:
        return None
    try:
        if "/" in text:
            network = ip_network(text, strict=False)
            return network.network_address.packed, network.prefixlen
        addr = ip_address(text)
        return addr.packed, addr.max_prefixlen
    except ValueError:
        return None


@dataclass(slots=True)
class IPSet:
    """
    基于 py-radix（C 扩展）的 IP 集合。

    约定：
    - 指定目录中的每个 `.txt` 文件代表一个标识组，文件名（不含后缀）即标识。
    - 每行支持 IP 或 CIDR。
    """

    _radix: radix.Radix = field(default_factory=radix.Radix)
    _networks_by_identifier: dict[str, set[str]] = field(default_factory=dict)

    @classmethod
    def from_directory(
        cls,
        directory: str | Path,
        *,
        encoding: str = "utf-8",
    ) -> IPSet:
        instance = cls()
        instance.load_directory(directory, encoding=encoding)
        return instance

    @property
    def identifiers(self) -> tuple[str, ...]:
        return tuple(sorted(self._networks_by_identifier.keys()))

    def clear(self) -> None:
        self._radix = radix.Radix()
        self._networks_by_identifier.clear()

    def load_directory(
        self,
        directory: str | Path,
        *,
        encoding: str = "utf-8",
    ) -> None:
        self.clear()
        self.update_directory(directory, encoding=encoding)

    def update_directory(
        self,
        directory: str | Path,
        *,
        encoding: str = "utf-8",
    ) -> None:
        base = Path(directory)
        for file_path in _iter_txt_files(base):
            self.load_file(file_path, identifier=file_path.stem, encoding=encoding)

    def load_file(
        self,
        file_path: str | Path,
        *,
        identifier: str,
        encoding: str = "utf-8",
    ) -> None:
        path = Path(file_path)
        with path.open("r", encoding=encoding) as f:
            for raw_line in f:
                line = _strip_comment(raw_line)
                if not line:
                    continue
                self.add(line, identifier)

    def add(self, item: str, identifier: str) -> bool:
        cidr = _normalize_network(item)
        if not cidr:
            return False

        network = ip_network(cidr, strict=False)
        # 使用 packed+masklen 调用，规避 Windows 下字符串路径的编码问题。
        node = self._radix.add(
            packed=network.network_address.packed,
            masklen=network.prefixlen,
        )
        identifiers = node.data.get("identifiers")
        if identifiers is None:
            identifiers = set()
            node.data["identifiers"] = identifiers
            node.data["cidr"] = network.with_prefixlen
        identifiers.add(identifier)
        self._networks_by_identifier.setdefault(identifier, set()).add(
            network.with_prefixlen
        )
        return True

    def match(self, target: str) -> set[str]:
        """
        查询目标 IP/CIDR 命中的全部标识。
        """
        query = _parse_target_to_query(target)
        if query is None:
            return set()
        packed, masklen = query

        matched: set[str] = set()
        for node in self._radix.search_covering(packed=packed, masklen=masklen):
            identifiers = node.data.get("identifiers")
            if identifiers:
                matched.update(identifiers)
        return matched

    def contains(self, target: str, identifier: str | None = None) -> bool:
        matched = self.match(target)
        if not matched:
            return False
        if identifier is None:
            return True
        return identifier in matched

    def networks(self, identifier: str) -> set[str]:
        return set(self._networks_by_identifier.get(identifier, set()))


__all__ = ["IPSet"]
