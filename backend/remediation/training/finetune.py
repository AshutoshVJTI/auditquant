#!/usr/bin/env python3
"""
Fine-tune Salesforce/codet5-base on Solidity vulnerability/fix pairs.

Usage:
    python finetune.py                        # defaults (15 epochs, batch 4)
    python finetune.py --epochs 10 --batch-size 2
    python finetune.py --fp16                 # half-precision (GPU only)

The trained model + tokenizer are saved to:
    backend/remediation/models/codet5-solidity-repair/
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path

import torch
from torch.utils.data import Dataset
from transformers import (
    AutoModelForSeq2SeqLM,
    AutoTokenizer,
    DataCollatorForSeq2Seq,
    Seq2SeqTrainer,
    Seq2SeqTrainingArguments,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "data"
OUTPUT_DIR = SCRIPT_DIR.parent / "models" / "codet5-solidity-repair"

BASE_MODEL = "Salesforce/codet5-base"


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

class SolidityRepairDataset(Dataset):
    """Simple map-style dataset that reads JSONL produced by build_training_data."""

    def __init__(self, path: Path, tokenizer, max_input_len: int, max_target_len: int):
        self.tokenizer = tokenizer
        self.max_input_len = max_input_len
        self.max_target_len = max_target_len
        self.examples: list[dict[str, str]] = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    self.examples.append(json.loads(line))
        logger.info("Loaded %d examples from %s", len(self.examples), path)

    def __len__(self) -> int:
        return len(self.examples)

    def __getitem__(self, idx: int) -> dict:
        ex = self.examples[idx]
        model_inputs = self.tokenizer(
            ex["input"],
            max_length=self.max_input_len,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        labels = self.tokenizer(
            ex["target"],
            max_length=self.max_target_len,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        # Squeeze batch dimension and replace pad tokens with -100 for loss masking
        label_ids = labels["input_ids"].squeeze()
        label_ids[label_ids == self.tokenizer.pad_token_id] = -100
        return {
            "input_ids": model_inputs["input_ids"].squeeze(),
            "attention_mask": model_inputs["attention_mask"].squeeze(),
            "labels": label_ids,
        }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune CodeT5 on Solidity repair pairs")
    parser.add_argument("--epochs", type=int, default=15, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=4, help="Per-device batch size")
    parser.add_argument("--grad-accum", type=int, default=4, help="Gradient accumulation steps")
    parser.add_argument("--lr", type=float, default=5e-5, help="Learning rate")
    parser.add_argument("--max-input-len", type=int, default=512, help="Max source tokens")
    parser.add_argument("--max-target-len", type=int, default=512, help="Max target tokens")
    parser.add_argument("--fp16", action="store_true", help="Use mixed precision (GPU only)")
    parser.add_argument("--train-file", type=str, default=str(DATA_DIR / "train.jsonl"))
    parser.add_argument("--eval-file", type=str, default=str(DATA_DIR / "eval.jsonl"))
    parser.add_argument("--output-dir", type=str, default=str(OUTPUT_DIR))
    args = parser.parse_args()

    device = "cuda" if torch.cuda.is_available() else "mps" if torch.backends.mps.is_available() else "cpu"
    logger.info("Device: %s", device)

    logger.info("Loading tokenizer and model: %s", BASE_MODEL)
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSeq2SeqLM.from_pretrained(BASE_MODEL)

    train_dataset = SolidityRepairDataset(
        Path(args.train_file), tokenizer, args.max_input_len, args.max_target_len,
    )
    eval_dataset = SolidityRepairDataset(
        Path(args.eval_file), tokenizer, args.max_input_len, args.max_target_len,
    )

    training_args = Seq2SeqTrainingArguments(
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        warmup_ratio=0.1,
        weight_decay=0.01,
        fp16=args.fp16 and device == "cuda",
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        predict_with_generate=True,
        logging_steps=10,
        report_to="none",
        remove_unused_columns=False,
        dataloader_pin_memory=device == "cuda",
    )

    data_collator = DataCollatorForSeq2Seq(
        tokenizer=tokenizer,
        model=model,
        padding="longest",
        label_pad_token_id=-100,
    )

    trainer = Seq2SeqTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        data_collator=data_collator,
        tokenizer=tokenizer,
    )

    logger.info("Starting training: %d epochs, batch %d x %d accum, lr %s",
                args.epochs, args.batch_size, args.grad_accum, args.lr)
    trainer.train()

    # Save the best model
    final_dir = Path(args.output_dir)
    final_dir.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(final_dir))
    tokenizer.save_pretrained(str(final_dir))
    logger.info("Model saved to %s", final_dir)

    # Verify weights exist
    for name in ("model.safetensors", "pytorch_model.bin"):
        if (final_dir / name).exists():
            size_mb = (final_dir / name).stat().st_size / (1024 * 1024)
            logger.info("  %s: %.1f MB", name, size_mb)
            break
    else:
        logger.warning("No weight file found in output — check training!")


if __name__ == "__main__":
    main()
