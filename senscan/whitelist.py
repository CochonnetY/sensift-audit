"""白名单：按值、通配符、正则或「实体:值」放行已知安全项。

文件格式（UTF-8，一行一条）：
    # 注释
    192.168.1.64                # 裸值：忽略所有实体中等于该值的命中
    MAC:001a2b3c4d5e            # 限定实体
    *.corp.example.com          # 通配符
    regex:^04:7[0-9a-f]:        # 正则（匹配原始值与归一化值）
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import utils as U
from .models import Finding


@dataclass(slots=True)
class WhitelistEntry:
    entity: str | None
    kind: str          # exact | glob | regex
    value: str
    pattern: re.Pattern[str] | None = None


@dataclass(slots=True)
class Whitelist:
    entries: list[WhitelistEntry] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: Path) -> "Whitelist":
        if not path.exists():
            raise FileNotFoundError(f"白名单文件不存在: {path}")
        return cls.from_text(path.read_text(encoding="utf-8-sig", errors="replace"))

    @classmethod
    def from_text(cls, text: str) -> "Whitelist":
        """从文本构造，供 Web UI 直接使用（不必落盘临时文件）。"""
        wl = cls()
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            entity: str | None = None
            body = line
            if ":" in line and not line.lower().startswith("regex:"):
                head, tail = line.split(":", 1)
                if head.isupper() or re.fullmatch(r"[A-Z_]{2,32}", head):
                    entity, body = head, tail.strip()
            if body.lower().startswith("regex:"):
                pat = body[6:].strip()
                wl.entries.append(WhitelistEntry(entity, "regex", pat, re.compile(pat, re.I)))
            elif any(ch in body for ch in "*?"):
                wl.entries.append(WhitelistEntry(entity, "glob", body))
            else:
                wl.entries.append(WhitelistEntry(entity, "exact", body))
        return wl

    def matches(self, finding: Finding) -> bool:
        norm = _norm(finding.value)
        entity = finding.entity
        for e in self.entries:
            if e.entity and e.entity != entity:
                continue
            if e.kind == "exact":
                if norm == _norm(e.value) or _norm(finding.normalized) == _norm(e.value):
                    return True
            elif e.kind == "glob":
                if fnmatch.fnmatch(norm, e.value.lower()) or fnmatch.fnmatch(finding.value, e.value):
                    return True
            elif e.kind == "regex" and e.pattern is not None:
                if e.pattern.search(finding.value) or e.pattern.search(finding.normalized):
                    return True
        return False

    def __len__(self) -> int:
        return len(self.entries)


def _norm(v: str) -> str:
    """纯 hex 类（MAC/指纹/密钥）去掉分隔符统一小写；其余只做 trim+lower。"""
    s = v.strip()
    if len(s) >= 8 and re.fullmatch(r"[0-9A-Fa-f:\-.]+", s):
        return U.normalize_hexlike(s)
    return s.lower()
