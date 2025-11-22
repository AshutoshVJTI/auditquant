from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CodeT5Config:
    model_name: str = "Salesforce/codet5-base"
    max_input_tokens: int = 512
    max_output_tokens: int = 256


class CodeT5Remediator:
    def __init__(self, config: CodeT5Config | None = None):
        self.config = config or CodeT5Config()
        self._tokenizer = None
        self._model = None

    def _lazy_load(self) -> None:
        if self._tokenizer and self._model:
            return
        try:
            from transformers import AutoModelForSeq2SeqLM, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError(
                "Transformers is required for CodeT5 inference. "
                "Install with: pip install transformers torch"
            ) from exc

        self._tokenizer = AutoTokenizer.from_pretrained(self.config.model_name)
        self._model = AutoModelForSeq2SeqLM.from_pretrained(self.config.model_name)

    def generate_patch(self, vulnerable_code: str, vuln_type: str) -> str:
        self._lazy_load()
        prompt = (
            "fix vulnerability type: "
            f"{vuln_type}\n"
            "code:\n"
            f"{vulnerable_code}\n"
        )
        inputs = self._tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=self.config.max_input_tokens,
        )
        output_ids = self._model.generate(
            **inputs,
            max_length=self.config.max_output_tokens,
            num_beams=4,
            early_stopping=True,
        )
        return self._tokenizer.decode(output_ids[0], skip_special_tokens=True)
