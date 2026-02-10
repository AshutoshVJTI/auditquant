"""
SWC Knowledge Base — loads and indexes vulnerability knowledge from the
SWC Registry and DeFiVulnLabs for use by the LLM summarisation prompt and
the anti-hallucination verifier.

The underlying data is produced by
``backend/remediation/training/fetch_databases.py`` →
``backend/remediation/training/data/swc_context.json``.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_CONTEXT_PATH = (
    Path(__file__).resolve().parents[2]
    / "remediation"
    / "training"
    / "data"
    / "swc_context.json"
)

# Mapping from common tool-reported vulnerability names to SWC IDs.
# Slither and Mythril already emit SWC IDs for many findings; this table
# fills in the gaps for the rest.
_VULN_TO_SWC: dict[str, str] = {
    "reentrancy": "SWC-107",
    "reentrancy-eth": "SWC-107",
    "reentrancy-no-eth": "SWC-107",
    "external-call": "SWC-107",
    "integer-overflow": "SWC-101",
    "integer-underflow": "SWC-101",
    "overflow": "SWC-101",
    "underflow": "SWC-101",
    "tx-origin": "SWC-115",
    "tx.origin": "SWC-115",
    "access-control": "SWC-105",
    "unprotected-function": "SWC-105",
    "arbitrary-send": "SWC-105",
    "unchecked-return": "SWC-104",
    "unchecked-call": "SWC-104",
    "unchecked-send": "SWC-104",
    "selfdestruct": "SWC-106",
    "suicidal": "SWC-106",
    "delegatecall": "SWC-112",
    "default-visibility": "SWC-100",
    "shadowing-state": "SWC-119",
    "timestamp": "SWC-116",
    "block-timestamp": "SWC-116",
    "weak-randomness": "SWC-120",
    "bad-randomness": "SWC-120",
    "dos": "SWC-128",
    "denial-of-service": "SWC-128",
    "gas-limit": "SWC-128",
    "front-running": "SWC-114",
    "deprecated-functions": "SWC-111",
    "floating-pragma": "SWC-103",
    "outdated-compiler": "SWC-102",
    "unused-variables": "SWC-131",
    "assert-violation": "SWC-110",
    "uninitialized-storage": "SWC-109",
}


class SWCKnowledgeBase:
    """Loads swc_context.json and provides look-ups by SWC ID or vuln type."""

    def __init__(self, context_path: Path | None = None) -> None:
        self._by_swc: dict[str, dict[str, Any]] = {}
        self._by_type: dict[str, dict[str, Any]] = {}
        self._loaded = False
        self._path = context_path or _CONTEXT_PATH
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            logger.warning("SWC context file not found at %s — knowledge base empty", self._path)
            return
        try:
            with open(self._path) as f:
                entries: list[dict] = json.load(f)
            for e in entries:
                swc_id = e.get("swc_id", "")
                self._by_swc[swc_id.upper()] = e
                vuln_type_key = e.get("vuln_type", "").lower().strip()
                if vuln_type_key:
                    self._by_type[vuln_type_key] = e
            self._loaded = True
            logger.info("Loaded SWC knowledge base: %d entries", len(entries))
        except Exception as exc:
            logger.warning("Failed to load SWC knowledge base: %s", exc)

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def get_by_swc_id(self, swc_id: str) -> dict[str, Any] | None:
        return self._by_swc.get(swc_id.upper())

    def get_by_vuln_type(self, vuln_type: str) -> dict[str, Any] | None:
        key = vuln_type.lower().replace("_", "-").strip()
        entry = self._by_type.get(key)
        if entry:
            return entry
        # Try mapping table
        mapped_swc = _VULN_TO_SWC.get(key)
        if mapped_swc:
            return self._by_swc.get(mapped_swc.upper())
        # Substring search as fallback
        for k, v in self._by_type.items():
            if key in k or k in key:
                return v
        return None

    def get_context_for_findings(
        self,
        finding_types: list[str],
        swc_ids: list[str | None] | None = None,
    ) -> str:
        """Build a prompt snippet with SWC context for the given finding types.

        Returns a string ready to be injected into an LLM prompt.
        """
        seen: set[str] = set()
        parts: list[str] = []

        # Try SWC IDs first (most precise)
        if swc_ids:
            for sid in swc_ids:
                if not sid or sid.upper() in seen:
                    continue
                entry = self.get_by_swc_id(sid)
                if entry:
                    seen.add(sid.upper())
                    parts.append(self._format_entry(entry))

        # Then try vuln type names
        for vtype in finding_types:
            entry = self.get_by_vuln_type(vtype)
            if entry and entry.get("swc_id", "").upper() not in seen:
                seen.add(entry.get("swc_id", "").upper())
                parts.append(self._format_entry(entry))

        if not parts:
            return ""
        return (
            "=== Authoritative Vulnerability Reference (SWC Registry) ===\n"
            + "\n\n".join(parts)
            + "\n=== End Reference ===\n"
        )

    def is_known_vulnerability(self, vuln_type: str) -> bool:
        """Return True if the vulnerability type is recognised in the SWC registry."""
        return self.get_by_vuln_type(vuln_type) is not None

    def get_known_exploit_keywords(self, vuln_type: str) -> list[str]:
        """Return characteristic keywords from the SWC description that should
        appear in a legitimate exploit scenario for this vulnerability type."""
        entry = self.get_by_vuln_type(vuln_type)
        if not entry:
            return []
        desc = (entry.get("description", "") + " " + entry.get("remediation", "")).lower()
        keywords: list[str] = []
        for w in ("reentrancy", "external call", "msg.sender", "delegatecall",
                   "selfdestruct", "overflow", "underflow", "tx.origin",
                   "block.timestamp", "require", "assert", "modifier",
                   "access control", "visibility", "send", "transfer", "call"):
            if w in desc:
                keywords.append(w)
        return keywords

    @staticmethod
    def _format_entry(entry: dict[str, Any]) -> str:
        swc = entry.get("swc_id", "?")
        title = entry.get("title", "Unknown")
        cwe = entry.get("cwe_id") or "N/A"
        desc = entry.get("description", "").strip()[:500]
        rem = entry.get("remediation", "").strip()[:500]
        lines = [f"[{swc}] {title} (CWE: {cwe})"]
        if desc:
            lines.append(f"  Description: {desc}")
        if rem:
            lines.append(f"  Remediation: {rem}")
        return "\n".join(lines)


# Module-level singleton so imports are cheap after first load
_instance: SWCKnowledgeBase | None = None


def get_swc_knowledge_base() -> SWCKnowledgeBase:
    global _instance
    if _instance is None:
        _instance = SWCKnowledgeBase()
    return _instance
