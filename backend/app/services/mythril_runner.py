import asyncio
import json
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


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


async def run_mythril(
    compose_path: str, solidity_path: Path, timeout: int = 300
) -> list[MythrilFinding]:
    project_root = Path(__file__).resolve().parents[3]
    compose_file = Path(compose_path)
    if not compose_file.is_absolute():
        compose_file = project_root / compose_file

    relative_target = solidity_path.resolve().relative_to(project_root)

    command = [
        "docker",
        "compose",
        "-f",
        str(compose_file),
        "run",
        "--rm",
        "mythril",
        "analyze",
        f"/work/{relative_target.as_posix()}",
        "-o",
        "json",
        "--execution-timeout",
        "120",
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(project_root),
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

    try:
        payload = json.loads(stdout.decode())
    except json.JSONDecodeError:
        payload = None

    # mythril can exit 1 even when it found issues (valid JSON)
    if process.returncode != 0 and (not payload or not payload.get("success")):
        msg = f"Mythril failed with exit code {process.returncode}: {err_dec or out_dec}"
        logger.warning("Mythril failed. stdout: %s | stderr: %s", out_dec[:2000], err_dec[:2000])
        raise RuntimeError(msg)

    if not payload:
        raise RuntimeError("Mythril produced no JSON output")
    if not payload.get("success") and payload.get("error"):
        logger.warning("Mythril reported error in JSON: %s", payload.get("error", "")[:500])
    return parse_mythril_output(payload)
