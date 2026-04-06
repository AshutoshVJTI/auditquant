import asyncio
import json
import logging
import shlex
from dataclasses import dataclass
from pathlib import Path

from app.services.slither_runner import parse_stdout_json
from app.services.solidity_version import infer_solc_version

logger = logging.getLogger(__name__)

_SHELL_PREFIX = "export PATH=/usr/local/bin:$PATH; set -e; "


SEVERITY_SCORES = {
    "High": 90.0,
    "Medium": 60.0,
    "Low": 30.0,
}


@dataclass
class MythrilFinding:
    title: str
    severity: str
    base_severity: float
    description: str
    swc_id: str | None
    location: str | None
    reachable: bool
    exploit_trace: list[dict]
    raw: dict


def _extract_exploit_trace(issue: dict) -> list[dict]:
    trace = issue.get("tx_sequence")
    if isinstance(trace, list):
        return trace
    trace = issue.get("transactions")
    if isinstance(trace, list):
        return trace
    trace = issue.get("steps")
    if isinstance(trace, list):
        return trace
    return []


def _extract_location(issue: dict) -> str | None:
    if "sourceMap" in issue and issue["sourceMap"]:
        return str(issue["sourceMap"])
    if "line" in issue and issue["line"]:
        return f"line:{issue['line']}"
    if "source" in issue and issue["source"]:
        return str(issue["source"])
    return None


def parse_mythril_output(payload: dict) -> list[MythrilFinding]:
    issues = payload.get("issues") or []
    findings: list[MythrilFinding] = []
    for issue in issues:
        severity = issue.get("severity", "Unknown")
        exploit_trace = _extract_exploit_trace(issue)
        reachable = len(exploit_trace) > 0
        findings.append(
            MythrilFinding(
                title=issue.get("title", "Unknown"),
                severity=severity,
                base_severity=SEVERITY_SCORES.get(severity, 0.0),
                description=issue.get("description", ""),
                swc_id=issue.get("swc-id"),
                location=_extract_location(issue),
                reachable=reachable,
                exploit_trace=exploit_trace,
                raw=issue,
            )
        )
    return findings


def _container_path(compose_path: str, solidity_path: Path) -> str:
    project_root = Path(compose_path).resolve().parent.parent
    return "/work/" + str(solidity_path.resolve().relative_to(project_root))


async def run_mythril(
    compose_path: str, solidity_path: Path, timeout: int = 300
) -> list[MythrilFinding]:
    container_sol = _container_path(compose_path, solidity_path)
    target_solc = infer_solc_version(solidity_path)
    compose_file = str(Path(compose_path).resolve())

    if target_solc and not target_solc.startswith("0.8."):
        quoted_target = shlex.quote(target_solc)
        quoted_file = shlex.quote(container_sol)
        script = (
            f"{_SHELL_PREFIX}"
            f"if ! /usr/local/bin/solc-select use {quoted_target} >/dev/null; then "
            f"  /usr/local/bin/solc-select install {quoted_target}; "
            f"  /usr/local/bin/solc-select use {quoted_target} >/dev/null; "
            f"fi; "
            f"myth analyze {quoted_file} -o json --execution-timeout 120 --max-depth 22 --solv {quoted_target}"
        )
        command = [
            "docker", "compose",
            "-f", compose_file,
            "run", "--rm", "--no-deps", "--entrypoint", "sh", "mythril",
            "-lc", script,
        ]
    else:
        command = [
            "docker", "compose",
            "-f", compose_file,
            "run", "--rm", "--no-deps", "mythril",
            "analyze",
            container_sol,
            "-o", "json",
            "--execution-timeout", "120",
            "--max-depth", "22",
        ]
        if target_solc:
            command.extend(["--solv", target_solc])
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        raise RuntimeError(f"Mythril timed out after {timeout}s")

    out_dec = stdout.decode().strip()
    err_dec = stderr.decode().strip()

    payload = parse_stdout_json(stdout)

    def _mythril_ok(p: dict | None) -> bool:
        if not p:
            return False
        err = p.get("error")
        if err:
            return False
        if p.get("success") is False:
            return False
        return p.get("success") is True or isinstance(p.get("issues"), list)

    # mythril exits non-zero when it finds issues, annoyingly
    if process.returncode != 0 and not _mythril_ok(payload):
        msg = f"Mythril failed with exit code {process.returncode}: {err_dec or out_dec}"
        logger.warning("Mythril failed. stdout: %s | stderr: %s", out_dec[:2000], err_dec[:2000])
        raise RuntimeError(msg)

    if not payload:
        raise RuntimeError("Mythril produced no JSON output")
    if not payload.get("success") and payload.get("error"):
        logger.warning("Mythril reported error in JSON: %s", payload.get("error", "")[:500])
    return parse_mythril_output(payload)
