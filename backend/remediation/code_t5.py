from __future__ import annotations


def generate_patch(vulnerable_code: str, vuln_type: str) -> str:
    """Placeholder for future CodeT5 integration."""
    return (
        "// TODO: CodeT5 remediation placeholder\n"
        f"// Vulnerability type: {vuln_type}\n"
        "// Generated patch will be inserted here in future versions.\n"
        "\n"
        "// --- vulnerable code ---\n"
        f"{vulnerable_code}"
    )
