"""cpg/taint_loader.py — Load taint rules from YAML configuration.

Reads ``taint_rules.yaml`` and provides structured access to source /
sink / sanitizer patterns grouped by language and vulnerability category.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

# php/go 目前引擎（parser/languages 适配器）尚未实现，规则已备好待用；
# 加入白名单避免加载 rules/ 备用规则时报未知语言告警。
_VALID_LANGUAGES = {"python", "javascript", "java", "php", "go"}
_VALID_SECTIONS = {"sources", "sinks", "sanitizers", "sink_excludes"}


@dataclass
class TaintCategory:
    """Patterns for a single vulnerability category in one language."""

    category: str  # "sql_injection", "xss", ...
    sources: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)


@dataclass
class LanguageTaintRules:
    """All taint rules for one programming language."""

    language: str
    categories: dict[str, TaintCategory] = field(default_factory=dict)


class TaintRuleLoader:
    """Load and query taint rules from one or more YAML files.

    Usage::

        loader = TaintRuleLoader()
        rules = loader.rules_for("python")

        for cat_name, cat in rules.categories.items():
            print(f"{cat_name}: {len(cat.sources)} sources, {len(cat.sinks)} sinks")

    Multi-file support: pass ``rules_paths`` as a single file, a list of files,
    or a directory (``*.yaml`` / ``*.yml`` are globbed and sorted).  Extra
    files merge ON TOP of the built-in ``taint_rules.yaml``: for each
    ``(language, section, category)`` the pattern lists are appended and
    deduplicated, so custom/CodeQL-adapted rules can live in their own files
    without editing the 4600-line built-in rule base.
    """

    def __init__(self, rules_paths: str | Path | list[str | Path] | None = None) -> None:
        # 内置 taint_rules.yaml 永远在首位：额外规则只负责「追加」，不替换内置。
        builtin = Path(__file__).resolve().parent / "taint_rules.yaml"
        if rules_paths is None:
            rules_paths = [builtin]
        else:
            extra = [rules_paths] if isinstance(rules_paths, (str, Path)) else list(rules_paths)
            rules_paths = [builtin, *extra]
        self._paths = self._resolve_paths(rules_paths)
        self._data: dict = {}
        self._load()

    @staticmethod
    def _resolve_paths(rules_paths: str | Path | list[str | Path]) -> list[Path]:
        """展开为文件列表：目录自动 glob ``*.yaml`` / ``*.yml``（排序）。"""
        if isinstance(rules_paths, (str, Path)):
            rules_paths = [rules_paths]
        files: list[Path] = []
        for raw in rules_paths:
            path = Path(raw)
            if path.is_dir():
                files.extend(sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml")))
            else:
                files.append(path)
        return files

    def _load(self) -> None:
        """Load every source file, merge, and validate structure (BUG 24)."""
        for path in self._paths:
            try:
                with open(path, encoding="utf-8") as fh:
                    chunk = yaml.safe_load(fh) or {}
            except FileNotFoundError:
                logger.warning("规则文件不存在，跳过: %s", path)
                continue
            if isinstance(chunk, dict):
                self._merge(chunk)
            else:
                logger.warning("规则文件顶层应为 dict，忽略: %s", path)
        self._validate()

    def _merge(self, chunk: dict) -> None:
        """把一份 YAML 合并进全局规则：同类别模式追加 + 去重。"""
        for lang, lang_data in chunk.items():
            if not isinstance(lang_data, dict):
                continue
            target_lang = self._data.setdefault(lang, {})
            for section in ("sources", "sinks", "sanitizers"):
                section_data = lang_data.get(section)
                if not isinstance(section_data, dict):
                    continue
                target_section = target_lang.setdefault(section, {})
                for cat, patterns in section_data.items():
                    if not isinstance(patterns, list):
                        continue
                    merged = target_section.setdefault(cat, [])
                    for pat in patterns:
                        if pat not in merged:
                            merged.append(pat)
            excludes = lang_data.get("sink_excludes", [])
            if isinstance(excludes, list):
                merged = target_lang.setdefault("sink_excludes", [])
                for pat in excludes:
                    if pat not in merged:
                        merged.append(pat)

    def _validate(self) -> None:
        """Check YAML structure and warn about issues."""
        if not isinstance(self._data, dict):
            logger.warning(
                "taint_rules.yaml top-level should be a dict, got %s", type(self._data).__name__
            )
            return

        for lang, lang_data in self._data.items():
            if lang not in _VALID_LANGUAGES:
                logger.warning(
                    "Unknown language %r in taint_rules.yaml (expected one of %s)",
                    lang,
                    sorted(_VALID_LANGUAGES),
                )
                continue

            if not isinstance(lang_data, dict):
                logger.warning(
                    "Language %r section should be a dict, got %s", lang, type(lang_data).__name__
                )
                continue

            for section in lang_data:
                if section not in _VALID_SECTIONS:
                    logger.warning(
                        "Unknown section %r in language %r (expected one of %s)",
                        section,
                        lang,
                        sorted(_VALID_SECTIONS),
                    )

                section_data = lang_data.get(section, {})
                if isinstance(section_data, dict):
                    for cat_name, patterns in section_data.items():
                        if not isinstance(patterns, list):
                            logger.warning(
                                "%s.%s.%s should be a list, got %s",
                                lang,
                                section,
                                cat_name,
                                type(patterns).__name__,
                            )
                        elif not patterns:
                            logger.info("%s.%s.%s is empty", lang, section, cat_name)

    def rules_for(self, language: str) -> LanguageTaintRules:
        """Return all taint rules for *language*."""
        lang_data = self._data.get(language, {})
        categories: dict[str, TaintCategory] = {}

        # Collect all category names from sources, sinks, and sanitizers
        all_categories: set[str] = set()
        for section in ("sources", "sinks", "sanitizers"):
            section_data = lang_data.get(section, {})
            all_categories.update(section_data.keys())

        for cat_name in sorted(all_categories):
            sources_data = lang_data.get("sources", {}).get(cat_name, [])
            sinks_data = lang_data.get("sinks", {}).get(cat_name, [])
            sanitizers_data = lang_data.get("sanitizers", {}).get(cat_name, [])

            categories[cat_name] = TaintCategory(
                category=cat_name,
                sources=list(sources_data),
                sinks=list(sinks_data),
                sanitizers=list(sanitizers_data),
            )

        return LanguageTaintRules(language=language, categories=categories)

    def all_sources(self, language: str) -> list[str]:
        """Return all source patterns for *language* (flat list)."""
        rules = self.rules_for(language)
        result: list[str] = []
        for cat in rules.categories.values():
            result.extend(cat.sources)
        return sorted(set(result))

    def all_sinks(self, language: str) -> list[str]:
        """Return all sink patterns for *language* (flat list)."""
        rules = self.rules_for(language)
        result: list[str] = []
        for cat in rules.categories.values():
            result.extend(cat.sinks)
        return sorted(set(result))

    def sink_excludes(self, language: str) -> list[str]:
        """Return sink-exclusion regex patterns for *language*.

        These are generic utility methods (``toString()``, ``I18nUtil.getString``,
        exception ``getMessage()`` …) that contain a sink substring but are not
        injection points.  Callers match them against a candidate sink's source
        text and drop the sink label when they match.
        """
        lang_data = self._data.get(language, {})
        excludes = lang_data.get("sink_excludes", [])
        return list(excludes) if isinstance(excludes, list) else []

    def match_source(self, language: str, text: str) -> str | None:
        """Return the most specific category matching *text*, else None.

        When multiple patterns match, the longest (most specific) pattern wins.
        """
        rules = self.rules_for(language)
        best_len = 0
        best_cat: str | None = None
        for cat_name, cat in rules.categories.items():
            for pat in cat.sources:
                if pat in text and len(pat) > best_len:
                    best_len = len(pat)
                    best_cat = cat_name
        return best_cat

    def match_all_sources(self, language: str, text: str) -> list[str]:
        """Return ALL category names whose source patterns match *text*."""
        rules = self.rules_for(language)
        matches: list[str] = []
        for cat_name, cat in rules.categories.items():
            for pat in cat.sources:
                if pat in text:
                    matches.append(cat_name)
                    break
        return matches

    def match_sink(self, language: str, text: str) -> str | None:
        """Return the most specific category matching *text*, else None.

        When multiple patterns match, the longest (most specific) pattern wins.
        """
        rules = self.rules_for(language)
        best_len = 0
        best_cat: str | None = None
        for cat_name, cat in rules.categories.items():
            for pat in cat.sinks:
                if pat in text and len(pat) > best_len:
                    best_len = len(pat)
                    best_cat = cat_name
        return best_cat

    def match_all_sinks(self, language: str, text: str) -> list[str]:
        """Return ALL category names whose sink patterns match *text*."""
        rules = self.rules_for(language)
        matches: list[str] = []
        for cat_name, cat in rules.categories.items():
            for pat in cat.sinks:
                if pat in text:
                    matches.append(cat_name)
                    break
        return matches

    def match_all_sanitizers(self, language: str, text: str) -> list[str]:
        """Return ALL category names whose sanitizer patterns match *text*.

        供图构建侧做「sanitizer 门控」：容器写调用点若命中任何类别的
        sanitizer（如 ``ps.setString(1, q)`` 命中 sql_injection 的
        ``.setString(``），说明该调用是安全绑定/加固 API，参数污点不应
        通过它写入宿主（见 graph.py::_add_container_state_edges）。
        """
        rules = self.rules_for(language)
        matches: list[str] = []
        for cat_name, cat in rules.categories.items():
            for pat in cat.sanitizers:
                if pat and pat in text:
                    matches.append(cat_name)
                    break
        return matches

    @property
    def available_languages(self) -> list[str]:
        """Languages with rules defined in the YAML file."""
        return list(self._data.keys())
