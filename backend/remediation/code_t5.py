# CodeT5 patch generation -- tries local fine-tuned model first, falls back to base.

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
