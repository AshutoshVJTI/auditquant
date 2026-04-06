import asyncio
import json
import logging
import shlex
from dataclasses import dataclass
from pathlib import Path

from app.services.solidity_version import infer_solc_version

logger = logging.getLogger(__name__)

_CONTAINER_SOLC = "/usr/local/bin/solc"
_SHELL_PREFIX = "export PATH=/usr/local/bin:$PATH; set -e; "


def parse_stdout_json(stdout: bytes) -> dict | None:
    text = stdout.decode(errors="replace").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    return None


@dataclass
class SlitherFinding:
    title: str
    impact: str
    confidence: str
    description: str
    location: str | None
    raw: dict


def parse_slither_output(payload: dict) -> list[SlitherFinding]:
    detectors = payload.get("results", {}).get("detectors", [])
    findings: list[SlitherFinding] = []
    for detector in detectors:
        elements = detector.get("elements") or []
        location = None
        if elements:
            element = elements[0]
            source = element.get("source_mapping", {})
            filename = source.get("filename_relative") or source.get("filename")
            start = source.get("start")
            length = source.get("length")
            if filename is not None and start is not None and length is not None:
                location = f"{filename}:{start}:{length}"
        findings.append(
            SlitherFinding(
                title=detector.get("check", "Unknown"),
                impact=detector.get("impact", "Unknown"),
                confidence=detector.get("confidence", "Unknown"),
                description=detector.get("description", ""),
                location=location,
                raw=detector,
            )
        )
    return findings


def _container_path(compose_path: str, solidity_path: Path) -> str:
    project_root = Path(compose_path).resolve().parent.parent
    return "/work/" + str(solidity_path.resolve().relative_to(project_root))


async def run_slither(
    compose_path: str, solidity_path: Path, timeout: int = 120
) -> list[SlitherFinding]:
    container_sol = _container_path(compose_path, solidity_path)
    compose_file = str(Path(compose_path).resolve())
    target_solc = infer_solc_version(solidity_path)

    if target_solc and not target_solc.startswith("0.8."):
        # Legacy pragma handling: install/select matching solc inside container.
        quoted_target = shlex.quote(target_solc)
        quoted_file = shlex.quote(container_sol)
        script = (
            f"{_SHELL_PREFIX}"
            f"if ! /usr/local/bin/solc-select use {quoted_target} >/dev/null; then "
            f"  /usr/local/bin/solc-select install {quoted_target}; "
            f"  /usr/local/bin/solc-select use {quoted_target} >/dev/null; "
            f"fi; "
            f"slither {quoted_file} --solc {_CONTAINER_SOLC} --json - --solc-disable-warnings"
        )
        command = [
            "docker", "compose",
            "-f", compose_file,
            "run", "--rm", "--no-deps", "--entrypoint", "sh", "slither",
            "-lc", script,
        ]
    else:
        command = [
            "docker", "compose",
            "-f", compose_file,
            "run", "--rm", "--no-deps", "slither",
            container_sol,
            "--solc",
            _CONTAINER_SOLC,
            "--json", "-",
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
        raise RuntimeError(f"Slither timed out after {timeout}s")

    out_dec = stdout.decode().strip()
    err_dec = stderr.decode().strip()

    payload = parse_stdout_json(stdout)

    # slither exits 255 sometimes when it finds issues - JSON may still be valid
    if process.returncode != 0 and (not payload or not payload.get("success")):
        msg = f"Slither failed with exit code {process.returncode}: {err_dec or out_dec}"
        logger.warning("Slither failed. stdout: %s | stderr: %s", out_dec[:2000], err_dec[:2000])
        raise RuntimeError(msg)

    if not payload:
        raise RuntimeError("Slither produced no JSON output")
    return parse_slither_output(payload)
