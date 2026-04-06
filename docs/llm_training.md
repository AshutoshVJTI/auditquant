# LLM Training Pipeline  -  CodeBERT Fine-Tuning for Vulnerability Detection

## Overview

This document covers AuditQuant's supervised LLM training workflow: fine-tuning
`microsoft/codebert-base` on the SmartBugs-curated dataset for multi-label smart
contract vulnerability detection and risk score prediction.

**Design principle:**  Local repo code handles data preparation and post-training
evaluation; actual GPU training runs on **Google Colab Pro** (T4 or A100).

```
[Local] prepare_llm_dataset.py
           │
           ▼  dataset.json (~5 MB, self-contained)
           │
[Colab] auditquant_colab_training.ipynb
           │  ← CodeBERT fine-tuning (~10–30 min on T4)
           │
           ▼  checkpoint_best.pt + eval_results.json
           │
[Local] run_llm_inference.py  →  evaluation/results/llm_eval.json
           │
[Local] compare_llm_vs_tools.py  →  evaluation/graphs/llm_*.png
```

---

## 1. Dataset Construction

### Sources

| Source | Contracts | Mechanism |
|--------|-----------|-----------|
| SmartBugs manifest (`known_vulnerabilities`) | 99 | Ground-truth labels from manifest + manual DeFi labels |
| Inline annotations (`// <yes> <report> TYPE`) | 87 | Parsed directly from Solidity source |
| SmartBugs-curated full directory | +101 new | Directory name = vulnerability type; deduplicated by filename |
| **Total** | **232** | Union of all sources |

Labels are merged per contract (manifest takes priority; inline annotations and
directory labels add any types not already captured).  Run
`fetch_smartbugs_dataset.py` to download and rebuild.

### Vulnerability Classes (13)

| Class | Typical source | Risk weight |
|-------|---------------|-------------|
| reentrancy | SmartBugs + DeFi manual | 0.90 |
| flash_loan | DeFi manual | 0.88 |
| price_manipulation | DeFi manual | 0.85 |
| liquidation | DeFi manual | 0.82 |
| share_manipulation | DeFi manual | 0.80 |
| access_control | SmartBugs | 0.75 |
| reward_manipulation | DeFi manual | 0.75 |
| governance | DeFi manual | 0.72 |
| arithmetic | SmartBugs | 0.70 |
| bad_randomness | SmartBugs inline | 0.65 |
| front_running | SmartBugs | 0.62 |
| unchecked_low_level_calls | SmartBugs | 0.60 |
| denial_of_service | SmartBugs | 0.55 |

### Risk Score Target

Each sample has a continuous risk score in [0, 1].  For the 100 contracts in the
existing benchmark, the tool-measured composite score is used directly
(`0.5 × r_sast + 0.3 × r_dast + 0.2 × r_comp`).  For the remaining samples, the
score is derived from the vulnerability weight table:

```
risk_score = max(weights) × 0.6 + mean(weights) × 0.4
```

This blends worst-case severity with overall exposure breadth.

### Splits

Stratified 70 / 15 / 15 train / val / test split by primary vulnerability type.
With 232 labeled samples (after SmartBugs-curated expansion):
- Train: 158 contracts
- Val:    37 contracts
- Test:   37 contracts

---

## 2. Model Architecture

**Base model:** `microsoft/codebert-base` (125M parameters, RoBERTa pretrained on
CodeSearchNet, 768-dim hidden state).

**Task heads:**

```
[CLS] token representation (768-dim)
          │
          ├── vuln_head: Linear(768, 13)   →  BCEWithLogitsLoss  (multi-label)
          │
          └── risk_head: Linear(768, 64) → GELU → Dropout → Linear(64, 1) → Sigmoid
                                           →  MSELoss   (risk regression)
```

**Regularisation:**
- Bottom 8 transformer layers frozen (only top 4 layers + heads trained)
- Dropout 0.1 on CLS representation and risk head
- Label smoothing 0.05 on binary targets
- Gradient clipping max_norm=1.0
- Early stopping on val macro-F1 (patience=5)
- Class weights: `sqrt(N_train / (N_classes × N_positive_per_class))`

---

## 3. Colab Training Workflow

### Prerequisites (local)

```bash
# Build and export dataset
python evaluation/scripts/prepare_llm_dataset.py
# Output: evaluation/llm_training/data/dataset.json  (~5 MB)
```

### Colab steps

1. Open [Google Colab](https://colab.research.google.com/) and set Runtime → T4 GPU.
2. Upload or share the notebook: `evaluation/notebooks/auditquant_colab_training.ipynb`
3. Upload `dataset.json` to your Google Drive at `MyDrive/AuditQuant/dataset.json`
   (or adjust `DATASET_PATH` in cell 2).
4. Run all cells in order.  Training takes **~10–30 minutes** on T4 (~5 min on A100).
5. Cell 8 saves artifacts to Drive and cell 9 downloads them.

### Tunable hyperparameters (cell 3 `CONFIG` dict)

| Parameter | Default | Effect |
|-----------|---------|--------|
| `learning_rate` | `2e-5` | Higher → faster convergence, risk overfitting |
| `epochs` | `15` | Capped by early stopping |
| `batch_size` | `8` | Reduce to `4` if OOM |
| `freeze_layers` | `8` | More frozen → less overfitting; fewer frozen → more expressive |
| `dropout` | `0.1` | Increase to `0.2` if overfitting |
| `risk_loss_weight` | `0.3` | Weight of risk regression relative to classification |
| `label_smoothing` | `0.05` | Increase to `0.1` for noisier labels |
| `threshold` | `0.5` | Auto-optimised on val split during evaluation |
| `early_stop_patience` | `5` | Set higher if loss curve is noisy |

### Checkpoint format

`checkpoint_best.pt` is a PyTorch state dict with metadata:

```python
{
    'model_state_dict': {...},   # model weights
    'model_name':  'microsoft/codebert-base',
    'n_labels':    13,
    'risk_head':   True,
    'epoch':       <best epoch>,
    'val_macro_f1': <best val score>,
    'config':      {...},        # full CONFIG dict
}
```

---

## 4. Local Inference and Evaluation

After downloading `checkpoint_best.pt` from Colab:

```bash
# Place checkpoint
mkdir -p evaluation/llm_training/checkpoints/
cp ~/Downloads/checkpoint_best.pt evaluation/llm_training/checkpoints/

# Place eval results (optional  -  skip run_llm_inference if eval_results.json from Colab is sufficient)
cp ~/Downloads/eval_results.json evaluation/results/llm_eval.json

# Re-run inference locally (uses CPU, slower but reproducible)
python evaluation/scripts/run_llm_inference.py \
    --checkpoint evaluation/llm_training/checkpoints/checkpoint_best.pt \
    --split test
```

The script auto-optimises the decision threshold on the val split before
evaluating on test.  Override with `--threshold 0.4` if desired.

---

## 5. Generation Parameter Experiments

Varies GPT-4o-mini `temperature` and `top_p` on test contracts to measure how
decoding parameters affect hallucination rate and vulnerability recall.

```bash
export OPENAI_API_KEY=sk-...

# Default: 10 contracts × 4 temperatures × 3 top_p = 120 API calls
python evaluation/scripts/run_generation_experiments.py

# Custom sweep
python evaluation/scripts/run_generation_experiments.py \
    --contracts 15 \
    --temperatures 0.0 0.3 0.7 1.0 \
    --top-p 0.7 0.9 1.0 \
    --output evaluation/results/generation_experiments.json
```

**Metrics:**
- `avg_hallucination_rate`: claimed vulnerability types not in ground truth
- `avg_mention_rate`: ground-truth vulnerabilities mentioned in output
- `avg_n_claims`: number of vulnerability claims per report

---

## 6. Comparison Graphs

```bash
python evaluation/scripts/compare_llm_vs_tools.py
```

Produces four graphs in `evaluation/graphs/`:

| File | Description |
|------|-------------|
| `llm_comparison_detection.png` | Grouped bar: Precision / Recall / F1 for Slither, Mythril, AuditQuant, CodeBERT |
| `llm_comparison_per_class.png` | Horizontal bars: per-vulnerability-type F1, AuditQuant vs CodeBERT |
| `llm_generation_heatmap.png` | Heatmap: temperature × top_p → hallucination rate and mention rate |
| `llm_risk_calibration.png` | Scatter: predicted vs derived risk score by DeFi category |

All graphs use the same visual style as the existing AuditQuant evaluation graphs.

---

## 7. Full Reproduction Checklist

```bash
# 1a. Download full SmartBugs-curated (256 contracts) and rebuild dataset.json
python evaluation/scripts/fetch_smartbugs_dataset.py

# 1b. Or just rebuild from already-downloaded data
python evaluation/scripts/prepare_llm_dataset.py

# 2. Upload dataset.json to Google Drive / Colab
#    Open: evaluation/notebooks/auditquant_colab_training.ipynb
#    Run all cells.  Download checkpoint_best.pt and eval_results.json.

# 3. Place artifacts
mkdir -p evaluation/llm_training/checkpoints
cp ~/Downloads/checkpoint_best.pt evaluation/llm_training/checkpoints/
cp ~/Downloads/eval_results.json  evaluation/results/llm_eval.json

# 4. (Optional) Re-run inference locally
python evaluation/scripts/run_llm_inference.py

# 5. (Optional) Generation parameter sweep
export OPENAI_API_KEY=sk-...
python evaluation/scripts/run_generation_experiments.py

# 6. Generate comparison graphs
python evaluation/scripts/compare_llm_vs_tools.py
```

---

## 8. How to Interpret the Graphs

**`llm_comparison_detection.png`**
The grouped bar chart shows how the fine-tuned CodeBERT model compares with
standalone tools and the full AuditQuant hybrid pipeline.  A high-precision bar
for CodeBERT indicates it rarely hallucinates vulnerability types; high recall
indicates it catches most ground-truth vulnerabilities.  Expect CodeBERT to score
between Slither (low precision) and Mythril (high precision) given the small
training set; the learning gap over Slither demonstrates that even modest fine-tuning
on domain-specific annotations improves grounding.

**`llm_comparison_per_class.png`**
The AuditQuant bar is a uniform horizontal band (its aggregate F1 has no per-class
breakdown in the benchmark format); the CodeBERT bars show which vulnerability types
the model learned most reliably.  Classes with many training examples (arithmetic,
reentrancy) will have higher F1 than rare classes (governance, denial_of_service).

**`llm_generation_heatmap.png`**
Lower temperature (left columns) → lower hallucination rate, lower mention rate.
The sweet spot for minimum hallucination while preserving vulnerability recall is
typically temperature ≈ 0.3, top_p ≈ 0.9.  The heatmap quantifies how much quality
degrades as generation becomes more random.

**`llm_risk_calibration.png`**
Points close to the diagonal indicate well-calibrated risk predictions.  Points
above the diagonal mean the model over-estimates risk; points below under-estimate.
Colour by DeFi category reveals whether certain contract types are systematically
mis-scored  -  e.g. lending contracts (complex liquidation mechanics) are often harder
to calibrate than simpler token contracts.

---

## 9. File Structure

```
evaluation/
├── llm_training/
│   ├── __init__.py
│   ├── dataset.py          # Dataset builder, label logic, JSON export
│   ├── _model.py           # CodeBERTVulnModel (used by local inference)
│   ├── evaluate.py         # Local inference + metrics
│   ├── generation_tune.py  # GPT generation parameter experiments
│   └── data/
│       └── dataset.json    # Generated by prepare_llm_dataset.py
├── notebooks/
│   └── auditquant_colab_training.ipynb  # Self-contained Colab training notebook
├── scripts/
│   ├── prepare_llm_dataset.py       # LOCAL: build + export dataset
│   ├── run_llm_inference.py         # LOCAL: load checkpoint, eval test set
│   ├── run_generation_experiments.py # LOCAL: GPT param sweep
│   └── compare_llm_vs_tools.py      # LOCAL: produce comparison graphs
└── results/
    ├── llm_eval.json                # Test-set evaluation metrics
    └── generation_experiments_*.json # Generation param sweep results
```

The existing RAG pipeline (`backend/llm/`) and all tool-based evaluation scripts
are unchanged by this addition.
