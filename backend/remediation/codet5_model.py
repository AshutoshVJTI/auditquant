from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import Lock
import re


_DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "models" / "codet5-solidity-repair"


@dataclass
class CodeT5Config:
    model_name: str = "Salesforce/codet5-base"
    fine_tuned_path: Path = _DEFAULT_MODEL_PATH
    max_input_tokens: int = 512
    max_output_tokens: int = 512


class CodeT5Remediator:
    _instance = None
    _lock = Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config: CodeT5Config | None = None):
        if hasattr(self, "_initialized") and self._initialized:
            return
        self.config = config or CodeT5Config()
        self._tokenizer = None
        self._model = None
        self._initialized = True

    def _resolve_model_name(self) -> str:
        if self.config.fine_tuned_path.exists():
            return str(self.config.fine_tuned_path)
        return self.config.model_name

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

        model_name = self._resolve_model_name()
        self._tokenizer = AutoTokenizer.from_pretrained(model_name)
        self._model = AutoModelForSeq2SeqLM.from_pretrained(model_name)

    def _post_process(self, text: str) -> str:
        text = text.strip()
        if not text:
            return text
        if "pragma solidity" not in text:
            pragma_match = re.search(r"pragma\s+solidity\s+[^;]+;", text)
            if pragma_match is None:
                text = "pragma solidity ^0.8.0;\n" + text
        if not text.endswith("\n"):
            text += "\n"
        return text

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
        decoded = self._tokenizer.decode(output_ids[0], skip_special_tokens=True)
        return self._post_process(decoded)
