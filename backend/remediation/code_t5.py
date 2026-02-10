"""
Remediation via CodeT5.

Uses a fine-tuned checkpoint at ``backend/remediation/models/codet5-solidity-repair``
when present.  Otherwise falls back to the Hugging Face base model
(``Salesforce/codet5-base``) which is downloaded automatically on first use.
"""
from __future__ import annotations

import logging

from remediation.codet5_model import CodeT5Remediator

logger = logging.getLogger(__name__)

_remediator: CodeT5Remediator | None = None


def _get_remediator() -> CodeT5Remediator | None:
    global _remediator
    if _remediator is None:
        try:
            _remediator = CodeT5Remediator()
        except Exception as exc:
            logger.warning("Failed to initialise CodeT5 remediator: %s", exc)
            _remediator = None
    return _remediator


def generate_patch(vulnerable_code: str, vuln_type: str) -> str:
    """Generate a remediation patch using CodeT5 (fine-tuned or base model)."""
    remediator = _get_remediator()
    if remediator is not None:
        try:
            return remediator.generate_patch(vulnerable_code, vuln_type)
        except Exception as exc:
            logger.warning("CodeT5 inference failed: %s", exc)
    return (
        "// CodeT5 inference failed — review and fix manually.\n"
        f"// Vulnerability type: {vuln_type}\n\n"
        f"{vulnerable_code}"
    )
