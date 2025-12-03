#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${ROOT_DIR}/../.." && pwd)"

cd "${PROJECT_ROOT}"
export PYTHONPATH="${PROJECT_ROOT}/backend"

echo "Installing Python requirements..."
pip install -r backend/requirements.txt

echo "Downloading datasets..."
python backend/remediation/training/download_datasets.py

echo "Preparing training data..."
python backend/remediation/training/prepare_data.py

echo "Starting fine-tuning..."
python backend/remediation/training/train.py

echo "Validating model output..."
python - <<'PY'
from pathlib import Path
from remediation.codet5_model import CodeT5Remediator

sample_code = """
pragma solidity ^0.8.0;
contract Test {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "call failed");
        balances[msg.sender] -= amount;
    }
}
"""

remediator = CodeT5Remediator()
patched = remediator.generate_patch(sample_code, "reentrancy")
output_path = Path("backend/remediation/training/checkpoints") / "sample_patch.sol"
output_path.write_text(patched, encoding="utf-8")
print(f"Wrote sample patch to {output_path}")
PY

echo "Done."
