# CodeBERT inference - loads fine-tuned checkpoint and runs vulnerability classification.
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_model_cache: dict[str, Any] = {}   # path → {model, tokenizer, meta}
def _resolve_project_root() -> Path:
    here = Path(__file__).resolve()
    candidates = [
        here.parents[3],  # <repo>
        here.parents[2],  # <repo>/backend
        here.parents[4],  # fallback for unexpected layouts
    ]
    for c in candidates:
        if (c / "evaluation" / "llm_training" / "_model.py").exists():
            return c
    # Final fallback: preserve previous behavior but avoid crashing on index errors.
    return candidates[0]
@dataclass
class CodeBERTResult:
    available: bool                          # False when checkpoint not found
    vuln_types: list[str] = field(default_factory=list)   # predicted labels
    risk_score: float = 0.0                  # regression output 0–1
    probabilities: dict[str, float] = field(default_factory=dict)  # label → prob
    thresholds: dict[str, float] = field(default_factory=dict)     # label → threshold
    error: str | None = None
def _load_model(checkpoint_path: Path) -> dict[str, Any] | None:
    key = str(checkpoint_path)
    if key in _model_cache:
        return _model_cache[key]

    if not checkpoint_path.exists():
        return None

    try:
        import torch
        from transformers import AutoTokenizer

        ckpt = torch.load(str(checkpoint_path), map_location="cpu")
        model_name = ckpt.get("model_name", "microsoft/codebert-base")
        n_labels   = ckpt.get("n_labels", 13)
        has_risk   = ckpt.get("risk_head", True)
        config     = ckpt.get("config", {})

        # Import model definition from the evaluation package
        import sys
        project_root = _resolve_project_root()
        if str(project_root) not in sys.path:
            sys.path.insert(0, str(project_root))
        from evaluation.llm_training._model import CodeBERTVulnModel, resolve_local_model_ref

        model = CodeBERTVulnModel(
            n_labels=n_labels,
            risk_head=has_risk,
            model_name=model_name,
            dropout=config.get("dropout", 0.1),
            freeze_layers=0,   # all layers active for inference
        )
        model.load_state_dict(ckpt["model_state_dict"])
        model.eval()

        tokenizer = AutoTokenizer.from_pretrained(
            resolve_local_model_ref(model_name),
            local_files_only=True,
        )

        # Retrieve per-class thresholds and label list from checkpoint
        from evaluation.llm_training.dataset import VULN_LABELS
        per_class_thresholds = ckpt.get("per_class_thresholds", [0.5] * n_labels)

        _model_cache[key] = {
            "model":      model,
            "tokenizer":  tokenizer,
            "labels":     VULN_LABELS,
            "thresholds": per_class_thresholds,
            "has_risk":   has_risk,
            "torch":      torch,
        }
        logger.info("CodeBERT checkpoint loaded: val_macro_f1=%.4f", ckpt.get("val_macro_f1", 0))
        return _model_cache[key]

    except Exception as exc:
        logger.warning("Failed to load CodeBERT checkpoint: %s", exc)
        return None
def run_codebert(source_code: str, checkpoint_path: Path) -> CodeBERTResult:
    cache = _load_model(checkpoint_path)
    if cache is None:
        return CodeBERTResult(available=False)

    try:
        import numpy as np
        from scipy.special import expit

        model     = cache["model"]
        tokenizer = cache["tokenizer"]
        labels    = cache["labels"]
        thresholds = cache["thresholds"]
        torch     = cache["torch"]

        enc = tokenizer(
            source_code[:6000],
            truncation=True,
            max_length=512,
            padding="max_length",
            return_tensors="pt",
        )

        with torch.no_grad():
            out = model(enc["input_ids"], enc["attention_mask"])

        logits = out["logits"].squeeze(0).numpy()
        probs  = expit(logits)

        thresholds_arr = np.array(thresholds)
        preds = (probs >= thresholds_arr).astype(int)
        predicted = [labels[i] for i, v in enumerate(preds) if v]

        risk_score = 0.0
        if cache["has_risk"] and "risk" in out:
            risk_score = float(out["risk"].squeeze().item())

        return CodeBERTResult(
            available=True,
            vuln_types=predicted,
            risk_score=round(risk_score, 4),
            probabilities={labels[i]: round(float(probs[i]), 4) for i in range(len(labels))},
            thresholds={labels[i]: round(float(thresholds[i]), 4) for i in range(len(labels))},
        )

    except Exception as exc:
        logger.warning("CodeBERT inference failed: %s", exc)
        return CodeBERTResult(available=True, error=str(exc))
