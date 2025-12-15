from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path


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

    if process.returncode != 0:
        raise RuntimeError(
            f"Slither failed with exit code {process.returncode}: {stderr.decode().strip()}"
        )

    payload = json.loads(stdout.decode())
    return parse_slither_output(payload)
