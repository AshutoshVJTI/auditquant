# CodeT5 Fine-Tuning

This directory contains the end-to-end pipeline for fine-tuning CodeT5 to remediate Solidity vulnerabilities using SmartBugs Curated and SolidiFI benchmarks.

## Prerequisites

- Python 3.11+
- GPU strongly recommended (NVIDIA, 16GB+ VRAM if available)
- System RAM ~16GB+ (datasets + tokenization)
- Git and Git LFS are not required, but `git` must be installed for cloning datasets.

## Quick Start

Run the automated pipeline:

```bash
./backend/remediation/training/run_training.sh
```

## Step-by-Step

1. Install Python dependencies:

```bash
pip install -r backend/requirements.txt
```

2. Download datasets:

```bash
python backend/remediation/training/download_datasets.py
```

Datasets are cloned into:

- `backend/remediation/training/data/smartbugs-curated`
- `backend/remediation/training/data/solidifi`

3. Prepare training data:

```bash
python backend/remediation/training/prepare_data.py
```

This produces:

- `backend/remediation/training/data/training_pairs.jsonl`

4. Fine-tune CodeT5:

```bash
python backend/remediation/training/train.py
```

Checkpoints are saved to:

- `backend/remediation/training/checkpoints/`

Final model is saved to:

- `backend/remediation/models/codet5-solidity-repair/`

## Expected Training Time

- GPU (V100/A10/A100): ~2-6 hours depending on dataset size and batch size.
- CPU only: can take 24+ hours and is not recommended.

## How To Test The Model

After training, run:

```bash
python - <<'PY'
from remediation.codet5_model import CodeT5Remediator

code = """
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
patch = remediator.generate_patch(code, "reentrancy")
print(patch)
PY
```

The output should include a safer pattern (for example, a reentrancy guard or checks-effects-interactions). If you want deterministic output quality, use a fixed random seed in your generation step.
