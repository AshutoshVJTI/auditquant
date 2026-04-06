"""
CodeBERT multi-label vulnerability classifier with optional risk regression head.
Shared by evaluate.py and the Colab training notebook.
"""
from typing import Any

import torch
import torch.nn as nn
from pathlib import Path
from transformers import AutoModel
def resolve_local_model_ref(model_name: str) -> str:
    """Prefer an already-cached Hugging Face snapshot when available."""
    eval_dir = Path(__file__).resolve().parents[1]
    mirrored = eval_dir / "llm_training" / "cache" / "codebert-base-local"
    if mirrored.exists():
        return str(mirrored)

    if "/" not in model_name:
        return model_name

    org, repo = model_name.split("/", 1)
    hub_dir = Path.home() / ".cache" / "huggingface" / "hub" / f"models--{org}--{repo}"
    snapshots_dir = hub_dir / "snapshots"
    if snapshots_dir.exists():
        snapshots = sorted(p for p in snapshots_dir.iterdir() if p.is_dir())
        preferred = []
        fallback = []
        for snap in snapshots:
            names = {p.name for p in snap.iterdir()}
            has_config = "config.json" in names
            has_tokenizer = ("vocab.json" in names or "vocab.txt" in names) and "tokenizer_config.json" in names
            has_weights = "pytorch_model.bin" in names or "model.safetensors" in names
            if has_config and has_tokenizer and has_weights:
                preferred.append(snap)
            elif has_weights:
                fallback.append(snap)
        if preferred:
            return str(preferred[-1])
        if fallback:
            return str(fallback[-1])
    return model_name
class CodeBERTVulnModel(nn.Module):
    """
    microsoft/codebert-base backbone with two task heads:

    vuln_head   -  multi-label binary classifier over VULN_LABELS
                 loss: BCEWithLogitsLoss (per-class, weighted)

    risk_head   -  scalar risk score regression [0, 1]
                 loss: MSELoss
                 (optional; disable with risk_head=False)

    Forward inputs:  input_ids, attention_mask
    Forward outputs: dict with keys "logits" (N, n_labels) and optionally "risk" (N, 1)
    """

    def __init__(
        self,
        n_labels: int = 13,
        risk_head: bool = True,
        model_name: str = "microsoft/codebert-base",
        dropout: float = 0.1,
        freeze_layers: int = 8,   # freeze bottom N transformer layers
    ) -> None:
        super().__init__()
        self.n_labels  = n_labels
        self.has_risk  = risk_head
        self.model_name = model_name

        # Evaluation often runs in offline environments after the base model
        # has already been cached locally during training.
        model_ref = resolve_local_model_ref(model_name)
        self.backbone = AutoModel.from_pretrained(model_ref, local_files_only=True)
        hidden = self.backbone.config.hidden_size  # 768 for codebert-base

        # Freeze bottom layers to reduce overfitting on small dataset
        for i, layer in enumerate(self.backbone.encoder.layer):
            if i < freeze_layers:
                for p in layer.parameters():
                    p.requires_grad = False

        self.dropout   = nn.Dropout(dropout)
        self.vuln_head = nn.Linear(hidden, n_labels)

        if risk_head:
            self.risk_head: nn.Module = nn.Sequential(
                nn.Linear(hidden, 64),
                nn.GELU(),
                nn.Dropout(dropout),
                nn.Linear(64, 1),
                nn.Sigmoid(),
            )

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> dict[str, torch.Tensor]:
        out = self.backbone(input_ids=input_ids, attention_mask=attention_mask)
        cls = self.dropout(out.last_hidden_state[:, 0, :])   # [CLS] token

        result: dict[str, torch.Tensor] = {
            "logits": self.vuln_head(cls),
        }
        if self.has_risk:
            result["risk"] = self.risk_head(cls)
        return result
