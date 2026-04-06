import asyncio
import json
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

SEMGREP_TIMEOUT = 60
# Rules file path relative to project root (mounted at /work in the semgrep container)
_RULES_CONTAINER_PATH = "backend/app/services/data/semgrep_solidity.yaml"


@dataclass
class SemgrepFinding:
    check_id: str
    path: str
    line_start: int
    line_end: int
    col_start: int
    col_end: int
    message: str
    severity: str       # ERROR | WARNING | INFO
    metadata: dict
    raw: dict


def parse_semgrep_output(payload: dict, contract_path: str) -> list[SemgrepFinding]:
    findings: list[SemgrepFinding] = []
    for result in payload.get("results", []):
        extra = result.get("extra", {})
        start = result.get("start", {})
        end = result.get("end", {})
        findings.append(
            SemgrepFinding(
                check_id=result.get("check_id", "unknown"),
                path=result.get("path", contract_path),
                line_start=start.get("line", 0),
                line_end=end.get("line", 0),
                col_start=start.get("col", 0),
                col_end=end.get("col", 0),
                message=extra.get("message", ""),
                severity=extra.get("severity", "WARNING"),
                metadata=extra.get("metadata", {}),
                raw=result,
            )
        )
    return findings


def _container_path(compose_path: str, solidity_path: Path) -> str:
    project_root = Path(compose_path).resolve().parent.parent
    return "/work/" + str(solidity_path.resolve().relative_to(project_root))


async def run_semgrep(
    compose_path: str, solidity_path: Path, timeout: int = SEMGREP_TIMEOUT
) -> list[SemgrepFinding]:
    container_sol = _container_path(compose_path, solidity_path)
    container_config = f"/work/{_RULES_CONTAINER_PATH}"
    command = [
        "docker", "compose",
        "-f", str(Path(compose_path).resolve()),
        "run", "--rm", "--no-deps", "semgrep",
        "--config", container_config,
        "--json",
        "--quiet",
        "--no-git-ignore",
        container_sol,
    ]
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        raise RuntimeError(f"Semgrep timed out after {timeout}s")
    except FileNotFoundError:
        raise RuntimeError("docker not found - ensure Docker Desktop is running")

    out_dec = stdout.decode().strip()
    err_dec = stderr.decode().strip()

    # semgrep exits 1 when it finds issues (normal), 2+ on real errors
    if process.returncode >= 2:
        raise RuntimeError(f"Semgrep error (exit {process.returncode}): {err_dec or out_dec}")

    if not out_dec:
        return []

    try:
        payload = json.loads(out_dec)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Semgrep produced invalid JSON: {exc}") from exc

    return parse_semgrep_output(payload, str(solidity_path))
