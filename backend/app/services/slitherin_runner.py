import asyncio
import json
import logging
import shlex
from dataclasses import dataclass
from pathlib import Path

from app.services.slither_runner import parse_stdout_json
from app.services.solidity_version import infer_solc_version

logger = logging.getLogger(__name__)

_CONTAINER_SOLC = "/usr/local/bin/solc"
_SHELL_PREFIX = "export PATH=/usr/local/bin:$PATH; set -e; "


@dataclass
class SlitherInFinding:
    title: str
    impact: str
    confidence: str
    description: str
    location: str | None
    raw: dict


def parse_slitherin_output(payload: dict) -> list[SlitherInFinding]:
    detectors = payload.get("results", {}).get("detectors", [])
    findings: list[SlitherInFinding] = []
    for detector in detectors:
        elements = detector.get("elements") or []
        location = None
        if elements:
            source = elements[0].get("source_mapping", {})
            filename = source.get("filename_relative") or source.get("filename")
            start = source.get("start")
            length = source.get("length")
            if filename is not None and start is not None and length is not None:
                location = f"{filename}:{start}:{length}"
        findings.append(
            SlitherInFinding(
                title=detector.get("check", "Unknown"),
                impact=detector.get("impact", "Unknown"),
                confidence=detector.get("confidence", "Unknown"),
                description=detector.get("description", ""),
                location=location,
                raw=detector,
            )
        )
    return findings


_SLITHERIN_DETECTORS = ",".join([
    "pess-arbitrary-call",
    "pess-double-entry-token-alert",
    "pess-readonly-reentrancy",
    "pess-timelock-controller",
    "pess-token-fallback",
    "pess-tx-gasprice",
    "pess-unprotected-initialize",
    "pess-ecrecover",
    "pess-strange-setter",
    "pess-uni-v2",
    "pess-unprotected-setter",
    "pess-dubious-typecast",
    "pess-call-forward-to-protected",
    "pess-for-continue-increment",
    "pess-nft-approve-warning",
    "pess-only-eoa-check",
    "pess-inconsistent-nonreentrant",
    "pess-before-token-transfer",
    "pess-event-setter",
    "pess-public-vs-external",
    "pess-magic-number",
    "pess-multiple-storage-read",
])


def _container_path(compose_path: str, solidity_path: Path) -> str:
    project_root = Path(compose_path).resolve().parent.parent
    return "/work/" + str(solidity_path.resolve().relative_to(project_root))


async def run_slitherin(
    compose_path: str, solidity_path: Path, timeout: int = 120
) -> list[SlitherInFinding]:
    container_sol = _container_path(compose_path, solidity_path)
    compose_file = str(Path(compose_path).resolve())
    target_solc = infer_solc_version(solidity_path)

    if target_solc and not target_solc.startswith("0.8."):
        quoted_target = shlex.quote(target_solc)
        quoted_file = shlex.quote(container_sol)
        quoted_detectors = shlex.quote(_SLITHERIN_DETECTORS)
        script = (
            f"{_SHELL_PREFIX}"
            f"if ! /usr/local/bin/solc-select use {quoted_target} >/dev/null; then "
            f"  /usr/local/bin/solc-select install {quoted_target}; "
            f"  /usr/local/bin/solc-select use {quoted_target} >/dev/null; "
            f"fi; "
            f"slither {quoted_file} --solc {_CONTAINER_SOLC} --json - --detect {quoted_detectors} --solc-disable-warnings"
        )
        command = [
            "docker", "compose",
            "-f", compose_file,
            "run", "--rm", "--no-deps", "--entrypoint", "sh", "slitherin",
            "-lc", script,
        ]
    else:
        command = [
            "docker", "compose",
            "-f", compose_file,
            "run", "--rm", "--no-deps", "slitherin",
            container_sol,
            "--solc",
            _CONTAINER_SOLC,
            "--json", "-",
            "--detect", _SLITHERIN_DETECTORS,
            "--solc-disable-warnings",
        ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        raise RuntimeError(f"Slitherin timed out after {timeout}s")

    out_dec = stdout.decode(errors="replace").strip()
    err_dec = stderr.decode(errors="replace").strip()

    payload = parse_stdout_json(stdout)

    def _usable_slither_json(p: dict | None) -> bool:
        """Slither JSON may omit success:true but still include results.detectors."""
        if not p:
            return False
        if p.get("success") is True:
            return True
        res = p.get("results")
        return isinstance(res, dict) and "detectors" in res

    if process.returncode != 0 and not _usable_slither_json(payload):
        logger.warning("Slitherin failed. stdout: %s | stderr: %s", out_dec[:2000], err_dec[:2000])
        detail = (err_dec or out_dec or "").strip()
        if not detail:
            detail = (
                "(no stdout/stderr  -  often Slither aborted before printing; "
                "rebuild: docker compose -f docker/docker-compose.yml build slitherin)"
            )
        raise RuntimeError(f"Slitherin failed (exit {process.returncode}): {detail}")

    if not payload:
        raise RuntimeError("Slitherin produced no JSON output")
    return parse_slitherin_output(payload)
