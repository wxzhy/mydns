"""按 tag 组织的域名集合。"""

from __future__ import annotations

from pathlib import Path

import marisa_trie


class DomainSet:
    """使用 marisa-trie 管理按 tag 分组的域名规则。"""

    def __init__(self) -> None:
        self._records: dict[str, str] = {}
        self._tree = marisa_trie.StringTrie([])
        self._tree_ready = True

    def load_from_file(self, filepath: str | Path, tag: str) -> None:
        path = Path(filepath)
        keys: list[str] = []
        with path.open("r", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, start=1):
                value = _clean_line(raw_line)
                if value is None:
                    continue
                try:
                    keys.append(_domain_to_reversed_key(value))
                except ValueError as exc:
                    raise ValueError(
                        f"domainset 规则非法 file={path} line={line_no}: {exc}"
                    ) from exc
        for key in keys:
            self._records[key] = tag
        self._tree_ready = False

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
            resolved = [_resolve_path(path=path, base_dir=base_dir) for path in paths]
            self.load_from_files(resolved, tag)

    def match(self, domain: str, tag: str) -> bool:
        matched = self._match_best_tag(domain)
        return matched == tag

    def match_tags(self, domain: str) -> set[str]:
        matched = self._match_best_tag(domain)
        if matched is None:
            return set()
        return {matched}

    @property
    def tags(self) -> set[str]:
        return set(self._records.values())

    def rebuild_tree(self) -> None:
        self._tree = marisa_trie.StringTrie(sorted(self._records.items()))
        self._tree_ready = True

    def _match_best_tag(self, domain: str) -> str | None:
        try:
            key = _domain_to_reversed_key(domain)
        except ValueError:
            return None
        prefix_items = self._tree.prefix_items(key)
        if not prefix_items:
            return None
        _, tag = prefix_items[-1]
        return tag

    def clear(self) -> None:
        self._records.clear()
        self._tree = marisa_trie.StringTrie([])
        self._tree_ready = True

    def init(
        self,
        mapping: dict[str, list[str | Path]] | None,
        *,
        base_dir: Path | None = None,
        cache_file: str | Path | None = None,
    ) -> None:
        self.clear()
        cache_path = (
            _resolve_path(cache_file, base_dir=base_dir)
            if cache_file is not None
            else None
        )
        if cache_path is not None and cache_path.exists():
            self.load(cache_path)
            return

        if mapping:
            self.load_from_mapping(mapping, base_dir=base_dir)
        self.rebuild_tree()
        if cache_path is not None:
            self.save(cache_path)

    def save(self, filepath: str | Path) -> None:
        path = Path(filepath)
        if not self._tree_ready:
            self.rebuild_tree()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._tree.save(str(path))

    def load(self, filepath: str | Path) -> None:
        path = Path(filepath)
        loaded = marisa_trie.StringTrie()
        loaded.load(str(path))
        self._tree = loaded
        self._records = dict(loaded.items())
        self._tree_ready = True


domainset = DomainSet()


def init_domainset(
    mapping: dict[str, list[str | Path]] | None,
    *,
    base_dir: Path | None = None,
    cache_file: str | Path | None = None,
) -> DomainSet:
    domainset.init(mapping, base_dir=base_dir, cache_file=cache_file)
    return domainset


def _clean_line(raw_line: str) -> str | None:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None
    if "#" in line:
        line = line.split("#", 1)[0].strip()
    if not line:
        return None
    return line


def _domain_to_reversed_key(domain: str) -> str:
    normalized = domain.strip().rstrip(".").lower()
    labels = [part for part in normalized.split(".") if part]
    if not labels:
        raise ValueError(f"empty domain: {domain!r}")
    # 统一以 "." 结尾，避免 "example.com" 误匹配 "examplex.com"
    return ".".join(reversed(labels)) + "."


def _resolve_path(path: str | Path, *, base_dir: Path | None) -> Path:
    raw = Path(path)
    if raw.is_absolute() or base_dir is None:
        return raw
    return base_dir / raw
