from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from remediation.training.data_loader import load_dataset


@dataclass
class TrainConfig:
    dataset_root: Path
    output_dir: Path
    model_name: str = "Salesforce/codet5-base"
    max_input_tokens: int = 512
    max_output_tokens: int = 256


def main() -> None:
    config = TrainConfig(
        dataset_root=Path("datasets/merged"),
        output_dir=Path("artifacts/codet5"),
    )

    try:
        from transformers import AutoModelForSeq2SeqLM, AutoTokenizer, Trainer, TrainingArguments
    except ImportError as exc:
        raise RuntimeError(
            "Transformers is required for CodeT5 training. "
            "Install with: pip install transformers torch"
        ) from exc

    tokenizer = AutoTokenizer.from_pretrained(config.model_name)
    model = AutoModelForSeq2SeqLM.from_pretrained(config.model_name)

    samples = list(load_dataset(config.dataset_root))
    if not samples:
        raise RuntimeError(
            f"No training samples found in {config.dataset_root}. "
            "Expected dataset layout: <vuln_type>/<sample>/vulnerable.sol + patched.sol"
        )

    def tokenize(sample):
        prompt = f"fix vulnerability type: {sample.vuln_type}\ncode:\n{sample.vulnerable_code}\n"
        inputs = tokenizer(
            prompt,
            truncation=True,
            max_length=config.max_input_tokens,
        )
        labels = tokenizer(
            sample.patched_code,
            truncation=True,
            max_length=config.max_output_tokens,
        )
        inputs["labels"] = labels["input_ids"]
        return inputs

    tokenized = [tokenize(sample) for sample in samples]

    training_args = TrainingArguments(
        output_dir=str(config.output_dir),
        per_device_train_batch_size=2,
        num_train_epochs=1,
        save_total_limit=2,
        logging_steps=10,
        save_steps=50,
        remove_unused_columns=True,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized,
    )

    trainer.train()
    trainer.save_model(str(config.output_dir))


if __name__ == "__main__":
    main()
