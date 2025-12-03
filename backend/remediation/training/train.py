from __future__ import annotations

from dataclasses import dataclass
import json
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
    batch_size: int = 8
    learning_rate: float = 5e-5
    validation_split: float = 0.1


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
    base_dir = Path(__file__).resolve().parent
    config = TrainConfig(
        data_path=base_dir / "data" / "training_pairs.jsonl",
        checkpoints_dir=base_dir / "checkpoints",
        final_model_dir=base_dir.parent / "models" / "codet5-solidity-repair",
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
            "Transformers + datasets are required for CodeT5 training. "
            "Install with: pip install transformers torch datasets accelerate sentencepiece"
        ) from exc

    records = _load_jsonl(config.data_path)
    dataset = Dataset.from_list(records)
    split = dataset.train_test_split(test_size=config.validation_split, seed=42)

    tokenizer = AutoTokenizer.from_pretrained(config.model_name)
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

    training_args = TrainingArguments(
        output_dir=str(config.checkpoints_dir),
        per_device_train_batch_size=config.batch_size,
        per_device_eval_batch_size=config.batch_size,
        num_train_epochs=config.epochs,
        learning_rate=config.learning_rate,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=3,
        logging_steps=25,
        remove_unused_columns=True,
        predict_with_generate=True,
        fp16=torch.cuda.is_available(),
    )

    data_collator = DataCollatorForSeq2Seq(tokenizer, model=model)

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_train,
        eval_dataset=tokenized_eval,
        data_collator=data_collator,
        tokenizer=tokenizer,
    )

    trainer.train()
    trainer.save_model(str(config.final_model_dir))
    tokenizer.save_pretrained(str(config.final_model_dir))


if __name__ == "__main__":
    main()
