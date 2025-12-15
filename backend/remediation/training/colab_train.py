#!/usr/bin/env python3
"""
CodeT5 fine-tuning script for Google Colab (GPU or TPU).

Usage:
  GPU (default):  python colab_train.py
  TPU:           python colab_train.py --use_tpu

When run from Colab, execute from the repo root (e.g. /content/auditquant)
so that paths like backend/remediation/training/data/ resolve correctly.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TrainConfig:
    data_path: Path
    checkpoints_dir: Path
    final_model_dir: Path
    model_name: str = "Salesforce/codet5-base"
    max_input_tokens: int = 512
    max_output_tokens: int = 512
    epochs: int = 10
    batch_size: int = 2
    gradient_accumulation_steps: int = 4
    learning_rate: float = 5e-5
    validation_split: float = 0.1
    use_tpu: bool = False


def _colab_friendly_base_dir() -> Path:
    """Resolve training dir so it works when run from repo root (e.g. Colab)."""
    # Same repo-root logic as train.py: parent of this file is 'training/'
    this_file = Path(__file__).resolve()
    return this_file.parent


def _load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        raise RuntimeError(f"Training data not found at {path}. Run prepare_data.py first.")
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    if not records:
        raise RuntimeError(f"No training records found in {path}.")
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description="CodeT5 fine-tuning (Colab-friendly, GPU/TPU)")
    parser.add_argument("--use_tpu", action="store_true", help="Use Colab TPU (requires torch_xla)")
    parser.add_argument("--data", type=str, default=None, help="Path to training_pairs.jsonl (default: <script_dir>/data/training_pairs.jsonl)")
    parser.add_argument("--output_dir", type=str, default=None, help="Directory to save final model (default: <script_dir>/../models/codet5-solidity-repair)")
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch_size", type=int, default=2, help="Per-device batch size (default 2 for Colab T4 15GB; use 4–8 if you have more VRAM)")
    parser.add_argument("--gradient_accumulation_steps", type=int, default=4, help="Gradient accumulation steps (effective batch = batch_size * this)")
    parser.add_argument("--lr", type=float, default=5e-5)
    parser.add_argument("--no_load_best", action="store_true", help="Save last epoch only (avoids 'missing keys' on some Colab transformers)")
    args = parser.parse_args()

    base_dir = _colab_friendly_base_dir()
    data_path = Path(args.data) if args.data else base_dir / "data" / "training_pairs.jsonl"
    final_model_dir = Path(args.output_dir) if args.output_dir else base_dir.parent / "models" / "codet5-solidity-repair"
    config = TrainConfig(
        data_path=data_path,
        checkpoints_dir=base_dir / "checkpoints",
        final_model_dir=final_model_dir,
        epochs=args.epochs,
        batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        learning_rate=args.lr,
        use_tpu=args.use_tpu,
    )

    try:
        import torch
        from datasets import Dataset
        from transformers import (
            AutoModelForSeq2SeqLM,
            AutoTokenizer,
            DataCollatorForSeq2Seq,
            Trainer,
            TrainingArguments,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Install deps: pip install transformers torch datasets accelerate sentencepiece"
        ) from exc

    def _load_tokenizer():
        # CodeT5 (RoBERTa) tokenizer can fail on Colab with newer transformers due to
        # extra_special_tokens type strictness (e.g. TypeError in tokenization_utils_base).
        # Try default load, then slow tokenizer. If both fail, install sentencepiece and
        # optionally pin: pip install 'transformers>=4.35.0,<4.44' sentencepiece
        try:
            return AutoTokenizer.from_pretrained(config.model_name)
        except (TypeError, ValueError) as e:
            err_msg = str(e).lower()
            if "extra_special_tokens" in err_msg or "sentencepiece" in err_msg or "addedtoken" in err_msg:
                try:
                    print("Falling back to slow tokenizer (use_fast=False) for compatibility.")
                    return AutoTokenizer.from_pretrained(config.model_name, use_fast=False)
                except (TypeError, ValueError):
                    raise RuntimeError(
                        "Tokenizer load failed. In Colab, run before training:\n"
                        "  !pip install sentencepiece\n"
                        "  !pip install 'transformers>=4.35.0,<4.44'\n"
                        "Then re-run this script."
                    ) from e
            raise

    # Optional: TPU setup (Colab)
    if config.use_tpu:
        try:
            import torch_xla.core.xla_model as xm
            _ = xm.xla_device()
            print("TPU detected. Training on TPU.")
        except Exception as e:
            print(f"TPU requested but not available: {e}. Falling back to CPU/GPU.")
            config.use_tpu = False

    records = _load_jsonl(config.data_path)
    dataset = Dataset.from_list(records)
    split = dataset.train_test_split(test_size=config.validation_split, seed=42)

    tokenizer = _load_tokenizer()
    model = AutoModelForSeq2SeqLM.from_pretrained(config.model_name)

    def tokenize(batch):
        model_inputs = tokenizer(
            batch["input"],
            max_length=config.max_input_tokens,
            truncation=True,
        )
        labels = tokenizer(
            batch["output"],
            max_length=config.max_output_tokens,
            truncation=True,
        )
        model_inputs["labels"] = labels["input_ids"]
        return model_inputs

    tokenized_train = split["train"].map(tokenize, batched=True, remove_columns=dataset.column_names)
    tokenized_eval = split["test"].map(tokenize, batched=True, remove_columns=dataset.column_names)

    config.checkpoints_dir.mkdir(parents=True, exist_ok=True)
    config.final_model_dir.mkdir(parents=True, exist_ok=True)

    # GPU: fp16; TPU: no fp16 (TPU uses bfloat16 via XLA)
    use_fp16 = torch.cuda.is_available() and not config.use_tpu

    # Build TrainingArguments; older transformers lack some args
    # load_best_model_at_end => final save is best by eval loss (reduces overfitting)
    import inspect
    sig = inspect.signature(TrainingArguments.__init__)
    train_kwargs = dict(
        output_dir=str(config.checkpoints_dir),
        per_device_train_batch_size=config.batch_size,
        per_device_eval_batch_size=min(config.batch_size * 2, 8),
        gradient_accumulation_steps=config.gradient_accumulation_steps,
        num_train_epochs=config.epochs,
        learning_rate=config.learning_rate,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=2,
        logging_steps=25,
        remove_unused_columns=True,
        fp16=use_fp16,
    )
    if "warmup_ratio" in sig.parameters:
        train_kwargs["warmup_ratio"] = 0.1
    # load_best_model_at_end can cause "missing keys" on Colab's older transformers;
    # set --no_load_best to save last epoch instead and avoid that warning
    if "load_best_model_at_end" in sig.parameters and not getattr(args, "no_load_best", False):
        train_kwargs["load_best_model_at_end"] = True
        train_kwargs["metric_for_best_model"] = "eval_loss"
        train_kwargs["greater_is_better"] = False
    if "predict_with_generate" in sig.parameters:
        train_kwargs["predict_with_generate"] = True
    if "report_to" in sig.parameters:
        train_kwargs["report_to"] = "none"
    training_args = TrainingArguments(**train_kwargs)

    # TPU: With --use_tpu we disabled fp16. Trainer auto-detects TPU when torch_xla
    # is installed and Colab TPU runtime is selected (no extra args needed).

    data_collator = DataCollatorForSeq2Seq(tokenizer, model=model)

    callbacks = None
    try:
        from transformers import EarlyStoppingCallback
        # Colab transformers may use early_stopping_patience or patience; avoid threshold
        sig = inspect.signature(EarlyStoppingCallback.__init__)
        if "early_stopping_patience" in sig.parameters:
            callbacks = [EarlyStoppingCallback(early_stopping_patience=2)]
        elif "patience" in sig.parameters:
            callbacks = [EarlyStoppingCallback(patience=2)]
    except (ImportError, TypeError):
        pass

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_train,
        eval_dataset=tokenized_eval,
        data_collator=data_collator,
        tokenizer=tokenizer,
        callbacks=callbacks,
    )

    trainer.train()
    # Save best checkpoint (or final if load_best_model_at_end not supported)
    trainer.save_model(str(config.final_model_dir))
    tokenizer.save_pretrained(str(config.final_model_dir))
    print(f"Model saved to {config.final_model_dir}")


if __name__ == "__main__":
    main()
