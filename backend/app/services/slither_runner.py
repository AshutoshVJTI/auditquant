from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


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


async def run_slither(
    compose_path: str, solidity_path: Path, timeout: int = 120
) -> list[SlitherFinding]:
    """Run Slither in Docker and return parsed findings."""
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
        "slither",
        f"/work/{relative_target.as_posix()}",
        "--json",
        "-",
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
        raise RuntimeError(f"Slither timed out after {timeout}s")

    out_dec = stdout.decode().strip()
    err_dec = stderr.decode().strip()

    try:
        payload = json.loads(stdout.decode())
    except json.JSONDecodeError:
        payload = None

    # Slither can exit 255 even when it produced valid JSON with findings (e.g. detectors ran).
    if process.returncode != 0 and (not payload or not payload.get("success")):
        msg = f"Slither failed with exit code {process.returncode}: {err_dec or out_dec}"
        logger.warning("Slither failed. stdout: %s | stderr: %s", out_dec[:2000], err_dec[:2000])
        raise RuntimeError(msg)

    if not payload:
        raise RuntimeError("Slither produced no JSON output")
    return parse_slither_output(payload)
