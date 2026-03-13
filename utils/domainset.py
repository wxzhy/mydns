from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import marisa_trie


def _strip_comment(raw_line: str) -> str:
    line = raw_line.strip()
    if not line:
        return ""
    if line.startswith("#") or line.startswith("//") or line.startswith(";"):
        return ""
    line = line.split("#", 1)[0].split(";", 1)[0].strip()
    return line


def _normalize_domain(value: str) -> str:
    """
    将输入规范化为可匹配域名：
    - 去掉空白、前导 `*.`、尾部 `.`
    - 支持 Unicode 域名并转为 IDNA
    """
    domain = value.strip()
    if not domain:
        return ""

    token = domain.split(maxsplit=1)[0].strip()
    if not token:
        return ""

    if token.startswith("||"):
        token = token[2:]
    if "^" in token:
        token = token.split("^", 1)[0]
    if token.startswith("*."):
        token = token[2:]
    if token.startswith("."):
        token = token[1:]

    token = token.rstrip(".")
    if not token:
        return ""

    try:
        return token.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""


def _to_reverse_key(domain: str) -> str:
    # 反转标签顺序并追加尾分隔符，避免 `example.com` 误匹配 `example.com.cnx` 这类前缀歧义。
    return f"{'.'.join(reversed(domain.split('.')))}."


def _iter_txt_files(directory: Path) -> list[Path]:
    if not directory.exists():
        raise FileNotFoundError(f"目录不存在: {directory}")
    if not directory.is_dir():
        raise NotADirectoryError(f"不是目录: {directory}")
    return sorted(
        path for path in directory.iterdir() if path.is_file() and path.suffix.lower() == ".txt"
    )


@dataclass(slots=True)
class DomainSet:
    """
    基于 Trie 的域名集合。

    约定：
    - 指定目录中的每个 `.txt` 文件代表一个标识组，文件名（不含后缀）即标识。
    - 查找时按“域名后缀”匹配，例如规则 `example.com` 可匹配 `a.example.com`。
    """

    # marisa-trie 是不可变结构；新增规则后会按需重建索引。
    _trie: marisa_trie.Trie | None = None
    _key_to_identifiers: dict[str, set[str]] = field(default_factory=dict)
    _domains_by_identifier: dict[str, set[str]] = field(default_factory=dict)
    _dirty: bool = False

    @classmethod
    def from_directory(
        cls,
        directory: str | Path,
        *,
        encoding: str = "utf-8",
    ) -> DomainSet:
        instance = cls()
        instance.load_directory(directory, encoding=encoding)
        return instance

    @property
    def identifiers(self) -> tuple[str, ...]:
        return tuple(sorted(self._domains_by_identifier.keys()))

    def clear(self) -> None:
        self._trie = None
        self._key_to_identifiers.clear()
        self._domains_by_identifier.clear()
        self._dirty = False

    def load_directory(
        self,
        directory: str | Path,
        *,
        encoding: str = "utf-8",
    ) -> None:
        """
        清空后重新加载目录下所有 txt 文件。
        """
        self.clear()
        self.update_directory(directory, encoding=encoding)

    def update_directory(
        self,
        directory: str | Path,
        *,
        encoding: str = "utf-8",
    ) -> None:
        """
        增量加载目录下所有 txt 文件。
        """
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

    def add(self, domain: str, identifier: str) -> bool:
        normalized = _normalize_domain(domain)
        if not normalized:
            return False

        key = _to_reverse_key(normalized)
        current = self._key_to_identifiers.get(key)
        if current is None:
            current = set()
            self._key_to_identifiers[key] = current
        current.add(identifier)
        self._domains_by_identifier.setdefault(identifier, set()).add(normalized)
        self._dirty = True
        return True

    def match(self, domain: str) -> set[str]:
        """
        返回命中的所有标识（按域名后缀匹配）。
        """
        normalized = _normalize_domain(domain)
        if not normalized:
            return set()

        self._ensure_trie()
        if self._trie is None:
            return set()

        key = _to_reverse_key(normalized)
        matched: set[str] = set()
        for prefix_key in self._trie.prefixes(key):
            matched.update(self._key_to_identifiers.get(prefix_key, ()))
        return matched

    def contains(self, domain: str, identifier: str | None = None) -> bool:
        matched = self.match(domain)
        if not matched:
            return False
        if identifier is None:
            return True
        return identifier in matched

    def domains(self, identifier: str) -> set[str]:
        return set(self._domains_by_identifier.get(identifier, set()))

    def _ensure_trie(self) -> None:
        if not self._dirty:
            return
        if not self._key_to_identifiers:
            self._trie = None
            self._dirty = False
            return
        self._trie = marisa_trie.Trie(self._key_to_identifiers.keys())
        self._dirty = False


__all__ = ["DomainSet"]
