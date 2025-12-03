#!/usr/bin/env python3
"""Prepare JSONL training pairs for CodeT5 remediation fine-tuning."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

VULN_KEYWORDS = {
    "reentrancy": "reentrancy",
    "re-entrancy": "reentrancy",
    "reentrant": "reentrancy",
    "overflow": "integer-overflow",
    "underflow": "integer-overflow",
    "integer": "integer-overflow",
    "access-control": "access-control",
    "accesscontrol": "access-control",
    "authorization": "access-control",
    "auth": "access-control",
    "unchecked": "unchecked-return",
    "return": "unchecked-return",
    "call": "unchecked-return",
}

VULN_TYPES = {"reentrancy", "integer-overflow", "access-control", "unchecked-return"}


@dataclass
class TrainingPair:
    vulnerable_code: str
    fixed_code: str
    vuln_type: str


def _detect_vuln_type(path: Path) -> str | None:
    lowered_parts = [part.lower() for part in path.parts]
    for part in lowered_parts:
        for key, mapped in VULN_KEYWORDS.items():
            if key in part:
                return mapped
    return None


def _read_json_if_exists(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _apply_reentrancy_fix(code: str) -> str:
    if "ReentrancyGuard" not in code:
        pragma_match = re.search(r"pragma\s+solidity\s+[^;]+;", code)
        import_stmt = 'import "@openzeppelin/contracts/security/ReentrancyGuard.sol";'
        if pragma_match:
            insert_at = pragma_match.end()
            code = code[:insert_at] + "\n" + import_stmt + code[insert_at:]
        else:
            code = import_stmt + "\n" + code

    def contract_repl(match: re.Match) -> str:
        name = match.group(1)
        inherits = match.group(2) or ""
        if "ReentrancyGuard" in inherits:
            return match.group(0)
        inherits = inherits.strip()
        if inherits:
            return f"contract {name} {inherits} ReentrancyGuard {{"
        return f"contract {name} is ReentrancyGuard {{"

    code = re.sub(r"contract\s+(\w+)\s*(is\s+[^\{]+)?\s*\{", contract_repl, code)

    def add_nonreentrant(line: str) -> str:
        if "function" not in line or "nonReentrant" in line:
            return line
        if "view" in line or "pure" in line or "constructor" in line:
            return line
        return line.replace("{", " nonReentrant {")

    lines = [add_nonreentrant(line) for line in code.splitlines()]
    return "\n".join(lines)


def _apply_overflow_fix(code: str) -> str:
    pragma_match = re.search(r"pragma\s+solidity\s+\^?(\d+\.\d+)", code)
    if pragma_match:
        version = pragma_match.group(1)
        major, minor = (int(x) for x in version.split("."))
        if major > 0 or minor >= 8:
            return code
    if "SafeMath" not in code:
        import_stmt = 'import "@openzeppelin/contracts/utils/math/SafeMath.sol";'
        pragma_match = re.search(r"pragma\s+solidity\s+[^;]+;", code)
        if pragma_match:
            insert_at = pragma_match.end()
            code = code[:insert_at] + "\n" + import_stmt + code[insert_at:]
        else:
            code = import_stmt + "\n" + code

    def inject_using(line: str) -> str:
        if line.strip().startswith("contract "):
            return line + "\n    using SafeMath for uint256;"
        return line

    return "\n".join(inject_using(line) for line in code.splitlines())


def _apply_access_control_fix(code: str) -> str:
    if "onlyOwner" not in code:
        def contract_injection(match: re.Match) -> str:
            header = match.group(0)
            injection = (
                "\n    address public owner;"
                "\n\n    modifier onlyOwner() {"
                "\n        require(msg.sender == owner, \"not owner\");"
                "\n        _;"
                "\n    }"
                "\n\n    constructor() {"
                "\n        owner = msg.sender;"
                "\n    }\n"
            )
            return header + injection

        code = re.sub(r"contract\s+\w+\s*(is\s+[^\{]+)?\s*\{", contract_injection, code, count=1)

    def add_only_owner(line: str) -> str:
        if "function" not in line or "onlyOwner" in line:
            return line
        if "view" in line or "pure" in line:
            return line
        return line.replace("{", " onlyOwner {")

    lines = [add_only_owner(line) for line in code.splitlines()]
    return "\n".join(lines)


def _apply_unchecked_return_fix(code: str) -> str:
    lines = []
    call_pattern = re.compile(r"(\w+)\.call\(([^\)]*)\);")
    for line in code.splitlines():
        match = call_pattern.search(line)
        if match and "success" not in line:
            target = match.group(1)
            args = match.group(2)
            indent = re.match(r"\s*", line).group(0)
            lines.append(f"{indent}(bool success, ) = {target}.call({args});")
            lines.append(f"{indent}require(success, \"Call failed\");")
            continue
        lines.append(line)
    return "\n".join(lines)


def apply_secure_patterns(code: str, vuln_type: str) -> str:
    if vuln_type == "reentrancy":
        return _apply_reentrancy_fix(code)
    if vuln_type == "integer-overflow":
        return _apply_overflow_fix(code)
    if vuln_type == "access-control":
        return _apply_access_control_fix(code)
    if vuln_type == "unchecked-return":
        return _apply_unchecked_return_fix(code)
    return code


def iter_smartbugs_samples(root: Path) -> Iterator[TrainingPair]:
    for sol_path in root.rglob("*.sol"):
        vuln_type = _detect_vuln_type(sol_path)
        metadata = _read_json_if_exists(sol_path.with_suffix(".json"))
        if metadata:
            metadata_type = metadata.get("vulnerability") or metadata.get("vuln_type")
            if metadata_type:
                vuln_type = _detect_vuln_type(Path(metadata_type)) or vuln_type
        if vuln_type not in VULN_TYPES:
            continue
        vulnerable_code = sol_path.read_text(encoding="utf-8")
        fixed_code = apply_secure_patterns(vulnerable_code, vuln_type)
        yield TrainingPair(vulnerable_code, fixed_code, vuln_type)


def _possible_fixed_paths(buggy_path: Path) -> Iterable[Path]:
    name = buggy_path.name
    parent = buggy_path.parent
    variants = set()

    replacements = {
        "buggy": ["fixed", "original", "patched", "safe"],
        "vulnerable": ["fixed", "original", "patched", "safe"],
        "bad": ["fixed", "original", "patched", "safe"],
        "unsafe": ["fixed", "original", "patched", "safe"],
    }

    lowered = name.lower()
    for marker, fixed_list in replacements.items():
        if marker in lowered:
            for replacement in fixed_list:
                variants.add(name.lower().replace(marker, replacement))
            variants.add(name.lower().replace(marker, ""))

    if parent.name.lower() in {"buggy", "vulnerable"}:
        variants.add(str(Path("..") / "original" / name))
        variants.add(str(Path("..") / "fixed" / name))

    for variant in variants:
        candidate = parent / variant
        if candidate.exists():
            yield candidate

    for sibling in parent.glob("*.sol"):
        if sibling == buggy_path:
            continue
        if sibling.stem.lower() in name.lower():
            yield sibling


def iter_solidifi_samples(root: Path) -> Iterator[TrainingPair]:
    for sol_path in root.rglob("*.sol"):
        lower_name = sol_path.name.lower()
        if not any(token in lower_name for token in ["buggy", "vulnerable", "unsafe", "bad"]):
            continue
        vuln_type = _detect_vuln_type(sol_path)
        if vuln_type not in VULN_TYPES:
            continue
        fixed_path = next(_possible_fixed_paths(sol_path), None)
        if fixed_path is None:
            continue
        vulnerable_code = sol_path.read_text(encoding="utf-8")
        fixed_code = fixed_path.read_text(encoding="utf-8")
        yield TrainingPair(vulnerable_code, fixed_code, vuln_type)


def write_jsonl(pairs: Iterable[TrainingPair], output_path: Path) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output_path.open("w", encoding="utf-8") as handle:
        for pair in pairs:
            payload = {
                "input": f"fix vulnerability type: {pair.vuln_type}\ncode:\n{pair.vulnerable_code}\n",
                "output": pair.fixed_code,
                "vuln_type": pair.vuln_type,
            }
            handle.write(json.dumps(payload) + "\n")
            count += 1
    return count


def main() -> None:
    training_dir = Path(__file__).resolve().parent
    data_dir = training_dir / "data"
    smartbugs_dir = data_dir / "smartbugs-curated"
    solidifi_dir = data_dir / "solidifi"
    output_path = data_dir / "training_pairs.jsonl"

    pairs = []
    if smartbugs_dir.exists():
        pairs.extend(iter_smartbugs_samples(smartbugs_dir))
    else:
        print("SmartBugs dataset not found. Run download_datasets.py first.")
    if solidifi_dir.exists():
        pairs.extend(iter_solidifi_samples(solidifi_dir))
    else:
        print("SolidiFI dataset not found. Run download_datasets.py first.")

    count = write_jsonl(pairs, output_path)
    print(f"Wrote {count} training pairs to {output_path}")


if __name__ == "__main__":
    main()
