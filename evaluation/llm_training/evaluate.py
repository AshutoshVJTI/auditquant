"""
Runs CodeBERT inference on the held-out test split and writes llm_eval.json.

Usage:
    python evaluation/llm_training/evaluate.py \
        --checkpoint evaluation/llm_training/checkpoints/checkpoint_best.pt
"""
import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    prec  = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec   = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1    = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    return round(prec, 4), round(rec, 4), round(f1, 4)
def compute_per_class_metrics(
    y_true: np.ndarray,   # (N, C) int
    y_pred: np.ndarray,   # (N, C) int  (thresholded)
    label_names: list[str],
) -> dict[str, dict[str, float]]:
    metrics: dict[str, dict[str, float]] = {}
    for i, name in enumerate(label_names):
        tp = int(((y_true[:, i] == 1) & (y_pred[:, i] == 1)).sum())
        fp = int(((y_true[:, i] == 0) & (y_pred[:, i] == 1)).sum())
        fn = int(((y_true[:, i] == 1) & (y_pred[:, i] == 0)).sum())
        support = int(y_true[:, i].sum())
        p, r, f = _prf(tp, fp, fn)
        metrics[name] = {
            "precision": p, "recall": r, "f1": f,
            "tp": tp, "fp": fp, "fn": fn, "support": support,
        }
    return metrics
def compute_aggregate_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
) -> dict[str, float]:
    # Micro (pool all classes)
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    micro_p, micro_r, micro_f1 = _prf(tp, fp, fn)

    # Macro (unweighted mean over per-class metrics)
    per = compute_per_class_metrics(y_true, y_pred, [str(i) for i in range(y_true.shape[1])])
    macro_p  = float(np.mean([v["precision"] for v in per.values()]))
    macro_r  = float(np.mean([v["recall"]    for v in per.values()]))
    macro_f1 = float(np.mean([v["f1"]        for v in per.values()]))

    # Exact match (all labels correct per sample)
    exact = float((y_true == y_pred).all(axis=1).mean())

    return {
        "micro_precision": round(micro_p, 4),
        "micro_recall":    round(micro_r, 4),
        "micro_f1":        round(micro_f1, 4),
        "macro_precision": round(macro_p, 4),
        "macro_recall":    round(macro_r, 4),
        "macro_f1":        round(macro_f1, 4),
        "exact_match":     round(exact, 4),
        "total_tp": tp, "total_fp": fp, "total_fn": fn,
    }
def optimal_threshold(
    y_true: np.ndarray,
    logits: np.ndarray,
    thresholds: list[float] | None = None,
) -> tuple[float, float]:
    """
    Grid-search threshold that maximises macro-F1 on the given split.
    Returns (best_threshold, best_macro_f1).
    """
    if thresholds is None:
        thresholds = [round(t, 2) for t in np.arange(0.1, 0.9, 0.05).tolist()]

    from scipy.special import expit  # sigmoid
    probs = expit(logits)

    best_t, best_f1 = 0.5, 0.0
    for t in thresholds:
        y_pred = (probs >= t).astype(int)
        agg = compute_aggregate_metrics(y_true, y_pred)
        if agg["macro_f1"] > best_f1:
            best_f1 = agg["macro_f1"]
            best_t = t
    return best_t, round(best_f1, 4)
# Model inference

def load_model_and_tokenizer(checkpoint_path: Path):
    """
    Load the fine-tuned CodeBERT model from a .pt checkpoint.
    Returns (model, tokenizer, config_dict).
    """
    import torch
    from transformers import AutoTokenizer

    ckpt = torch.load(str(checkpoint_path), map_location="cpu")
    model_name = ckpt.get("model_name", "microsoft/codebert-base")
    n_labels   = ckpt.get("n_labels", 13)
    risk_head  = ckpt.get("risk_head", True)

    # Import here to avoid hard dependency when module is imported without torch
    from evaluation.llm_training._model import CodeBERTVulnModel, resolve_local_model_ref

    model = CodeBERTVulnModel(n_labels=n_labels, risk_head=risk_head, model_name=model_name)
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()

    tokenizer = AutoTokenizer.from_pretrained(
        resolve_local_model_ref(model_name),
        local_files_only=True,
    )
    config = {k: ckpt[k] for k in ("model_name", "n_labels", "risk_head", "epoch", "val_macro_f1")
              if k in ckpt}
    return model, tokenizer, config
def run_inference(
    checkpoint_path: Path,
    dataset_path: Path,
    split: str = "test",
    batch_size: int = 8,
    threshold: float | None = None,
) -> dict[str, Any]:
    """
    Run inference on the specified split.  If threshold is None, it is
    optimised on the validation split first.

    Returns a dict with keys: metrics, per_class, per_sample, config.
    """
    import torch

    from evaluation.llm_training.dataset import VULN_LABELS, load_json

    logger.info("Loading dataset from %s", dataset_path)
    samples, meta = load_json(dataset_path)

    model, tokenizer, ckpt_config = load_model_and_tokenizer(checkpoint_path)

    def _encode(texts: list[str]) -> dict[str, torch.Tensor]:
        return tokenizer(
            texts,
            truncation=True,
            max_length=512,
            padding="max_length",
            return_tensors="pt",
        )

    def _predict_split(split_name: str) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        split_samples = [s for s in samples if s.split == split_name]
        all_logits, all_risk, all_labels = [], [], []

        with torch.no_grad():
            for i in range(0, len(split_samples), batch_size):
                batch = split_samples[i:i + batch_size]
                enc = _encode([s.source_code for s in batch])
                out = model(
                    input_ids=enc["input_ids"],
                    attention_mask=enc["attention_mask"],
                )
                all_logits.append(out["logits"].numpy())
                if "risk" in out:
                    all_risk.append(out["risk"].squeeze(-1).numpy())
                all_labels.append(np.array([s.label_vector for s in batch]))

        logits = np.concatenate(all_logits, axis=0)
        risk   = np.concatenate(all_risk, axis=0) if all_risk else np.zeros(len(split_samples))
        labels = np.concatenate(all_labels, axis=0)
        return logits, risk, labels

    # Find optimal threshold on val split
    if threshold is None:
        logger.info("Optimising threshold on val split")
        val_logits, _, val_labels = _predict_split("val")
        threshold, _ = optimal_threshold(val_labels, val_logits)
        logger.info("Optimal threshold: %.2f", threshold)

    logger.info("Running inference on %s split (threshold=%.2f)", split, threshold)
    test_logits, test_risk, test_labels = _predict_split(split)

    from scipy.special import expit
    test_probs = expit(test_logits)
    test_pred  = (test_probs >= threshold).astype(int)

    per_class = compute_per_class_metrics(test_labels, test_pred, VULN_LABELS)
    aggregate = compute_aggregate_metrics(test_labels, test_pred)

    # Risk score MAE/corr
    test_samples = [s for s in samples if s.split == split]
    true_risk    = np.array([s.risk_score for s in test_samples])
    risk_mae     = float(np.mean(np.abs(test_risk - true_risk)))
    risk_corr    = float(np.corrcoef(test_risk, true_risk)[0, 1]) if len(true_risk) > 2 else 0.0

    # Per-sample results
    per_sample = []
    for i, s in enumerate(test_samples):
        per_sample.append({
            "contract_id":     s.contract_id,
            "true_labels":     s.vuln_types,
            "pred_labels":     [VULN_LABELS[j] for j in range(N_LABELS) if test_pred[i, j]],
            "probs":           [round(float(p), 4) for p in test_probs[i]],
            "pred_risk_score": round(float(test_risk[i]), 4),
            "true_risk_score": s.risk_score,
            "defi_category":   s.defi_category,
        })

    return {
        "split":          split,
        "threshold":      threshold,
        "n_samples":      len(test_samples),
        "aggregate":      aggregate,
        "per_class":      per_class,
        "risk_metrics":   {"mae": round(risk_mae, 4), "pearson_r": round(risk_corr, 4)},
        "per_sample":     per_sample,
        "checkpoint_config": ckpt_config,
        "vuln_labels":    VULN_LABELS,
    }
# N_LABELS reference (avoid circular import)
N_LABELS = 13
