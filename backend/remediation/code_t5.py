"""Remediation via fine-tuned CodeT5. Uses backend/remediation/models/codet5-solidity-repair when present."""
from __future__ import annotations

from remediation.codet5_model import CodeT5Remediator

_remediator: CodeT5Remediator | None = None


def _get_remediator() -> CodeT5Remediator | None:
    global _remediator
    if _remediator is None:
        try:
            _remediator = CodeT5Remediator()
            if not _remediator.config.fine_tuned_path.exists():
                _remediator = None
        except Exception:
            _remediator = None
    return _remediator


def generate_patch(vulnerable_code: str, vuln_type: str) -> str:
    """Generate a remediation patch using the fine-tuned CodeT5 model (or placeholder if unavailable)."""
    remediator = _get_remediator()
    if remediator is not None:
        try:
            return remediator.generate_patch(vulnerable_code, vuln_type)
        except Exception:
            pass
    # Fallback when model missing or inference fails
    return (
        "// CodeT5 model unavailable or inference failed.\n"
        f"// Vulnerability type: {vuln_type}\n"
        "// Review and fix manually.\n\n"
        "// --- vulnerable code ---\n"
        f"{vulnerable_code}"
    )
