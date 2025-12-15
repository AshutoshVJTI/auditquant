# Running CodeT5 Fine-Tuning on Google Colab

## Do I need to clone the entire repo?

**No.** You only need:

- The **training scripts** (and, if you’re building data in Colab, the two dataset repos), **or**
- A **pre-made `training_pairs.jsonl`** plus the **training script** `colab_train.py`.

See **Minimal setup** below if you want to avoid cloning the full AuditQuant repo.

---

## Minimal setup (no full repo clone)

### Option 1: Only the training folder

Upload or clone **just** the `backend/remediation/training/` folder (e.g. zip it locally and upload to Colab, or use a sparse checkout). Then in Colab:

```python
# Unzip or cd into the training folder, then (sentencepiece + transformers pin avoid tokenizer errors):
!pip install -q sentencepiece "transformers>=4.35.0,<4.44" torch datasets accelerate
!python download_datasets.py
!python prepare_data.py
!python colab_train.py
```

No `PYTHONPATH` or repo root needed; the scripts use paths relative to the script directory. The model is saved to `../models/codet5-solidity-repair` (relative to the training folder); use `--output_dir /content/my_model` to choose another path.

### Option 2: Pre-made JSONL only (fastest)

If you already have `training_pairs.jsonl` (e.g. from running `prepare_data.py` once locally, or from a shared link):

1. Upload **only** `colab_train.py` and `training_pairs.jsonl` to Colab (e.g. to `/content/`).
2. Run:

```python
!pip install -q sentencepiece "transformers>=4.35.0,<4.44" torch datasets accelerate
!python colab_train.py --data /content/training_pairs.jsonl --output_dir /content/codet5-solidity-repair
```

Then zip and download `/content/codet5-solidity-repair/`. No dataset clone or prepare step.

---

## GPU vs TPU: Which to use?

| | **Colab GPU (T4 / A100)** | **Colab TPU (v2/v3)** |
|---|---|---|
| **Recommendation** | ✅ **Use this** – works with the repo as-is | ⚠️ Possible but more setup |
| **Why** | Hugging Face Trainer + PyTorch are built for GPU. One-click runtime, no extra deps. | Requires `torch_xla`; Colab TPU can have GCS/data constraints; debugging is harder. |
| **Speed** | T4: ~2–4 h, A100: ~1–2 h (typical) | Can be faster for large batches if everything is wired correctly. |
| **Ease** | Runtime → Change runtime type → GPU → run cells | Runtime → TPU → install XLA → run; paths and env differ. |

**Bottom line:** Prefer **Colab GPU** unless you specifically need TPU (e.g. for a course or comparison). The notebook below works on both; GPU is the default and simplest.

---

## Option A: Colab with GPU (recommended)

*If you cloned the full repo (or only the training folder), use these steps.*

1. Open [Google Colab](https://colab.research.google.com).
2. **Runtime → Change runtime type → T4 GPU** (or A100 if available).
3. In the first cell, clone the repo and go to the repo root (or skip and use **Minimal setup** above):

```python
!git clone https://github.com/YOUR_USERNAME/auditquant.git
%cd auditquant
```

4. Run the Colab training script (install deps with transformers pin to avoid tokenizer errors, then download data, prepare, train):

```python
!pip install -q sentencepiece "transformers>=4.35.0,<4.44" torch datasets accelerate
import os; os.environ["PYTHONPATH"] = os.getcwd() + "/backend"
!python backend/remediation/training/download_datasets.py
!python backend/remediation/training/prepare_data.py
!python backend/remediation/training/colab_train.py
```

5. Download the saved model (or sync to Drive):

```python
from google.colab import files
import shutil
# Zip and download
shutil.make_archive("codet5-solidity-repair", "zip", "backend/remediation/models/codet5-solidity-repair")
files.download("codet5-solidity-repair.zip")
```

---

## Option B: Colab with TPU

1. **Runtime → Change runtime type → TPU**.
2. Clone repo and install TPU-enabled PyTorch + deps:

```python
!git clone https://github.com/YOUR_USERNAME/auditquant.git
%cd auditquant
!pip install -q cloud-tpu-client torch-xla
!pip install -q sentencepiece "transformers>=4.35.0,<4.44" torch datasets accelerate
```

3. Download and prepare data (same as GPU):

```python
import os
os.environ["PYTHONPATH"] = os.getcwd() + "/backend"
!python backend/remediation/training/download_datasets.py
!python backend/remediation/training/prepare_data.py
```

4. Run the Colab-aware training script with TPU:

```python
!python backend/remediation/training/colab_train.py --use_tpu
```

5. If you hit TPU/VM or GCS-related errors, prefer **Option A (GPU)**.

---

## Saving the model for use in AuditQuant

After training, the model is under:

`backend/remediation/models/codet5-solidity-repair/`

- **From Colab:** Zip it and download (see step 5 in Option A), then unzip into `backend/remediation/models/codet5-solidity-repair/` in your local repo.
- **From Colab + Drive:** Copy the folder to Google Drive, then download to the same path locally.

Once that path exists locally, the AuditQuant backend will use the fine-tuned model instead of the placeholder.

---

## Troubleshooting

### "extra_special_tokens must be a list/tuple" or "sentencepiece" when loading tokenizer

Colab’s default `transformers` can be incompatible with the CodeT5 (RoBERTa) tokenizer. Do this **before** running `colab_train.py`:

```python
!pip install -q sentencepiece
!pip install -q "transformers>=4.35.0,<4.44"
```

Then run the training again. The script also tries a slow-tokenizer fallback; if that still fails, the version pin above should fix it.

### CUDA out of memory (OOM) during training

The script defaults to `--batch_size 2` and `--gradient_accumulation_steps 4` so it fits Colab’s free T4 (15GB). If you still hit OOM:

- Use a smaller batch: `!python colab_train.py --batch_size 1 --gradient_accumulation_steps 8`
- Or disable fp16 if you’re on an odd setup (edit the script to set `use_fp16 = False`).

If you have more VRAM (e.g. A100), you can increase batch size: `--batch_size 8 --gradient_accumulation_steps 1`.

---

## Was the training good? Can it be better?

### How to tell if it trained well

- **Loss**: Train and eval loss should go down and stay low (e.g. eval loss &lt; 0.02 by the end). Your run (eval loss ~0.011) is in a good range.
- **Overfitting**: If train loss keeps dropping but eval loss goes up after a few epochs, you’re overfitting. Reducing epochs or using the “best” checkpoint (see below) helps.
- **Real test**: Generate patches on a few held-out Solidity snippets and check that they compile and look sensible.

### Improvements already in the script

- **Best checkpoint**: When supported, the script saves the **best** model by eval loss (`load_best_model_at_end`), not the last epoch, which often generalizes better.
- **Warmup**: 10% of steps are warmup (`warmup_ratio=0.1`) for more stable training.
- **Early stopping**: If your `transformers` has `EarlyStoppingCallback`, training can stop after 2 epochs with no eval-loss improvement, which can reduce overfitting.

### Things you can try for better quality

| Change | Why it helps |
|--------|----------------|
| **More data** | 749 pairs is small for ~220M params. Add more Solidity fix pairs (e.g. more repos, more SolidiFI/SmartBugs) if you can. |
| **Fewer epochs** | With small data, 5–7 epochs is often enough; 10 can overfit. Use `--epochs 5` or rely on early stopping. |
| **Lower LR** | Try `--lr 3e-5` for a more stable, sometimes better final model. |
| **Longer sequences** | If many fixes need more context, increase max length in the script (e.g. 768) and accept slower training / more VRAM. |
| **Evaluate patches** | After training, run the model on a small test set and check: does the output compile? Does it match the expected fix? That’s the real quality signal. |
| **Label smoothing** | In `TrainingArguments`, if your version supports it, set `label_smoothing_factor=0.1` to reduce overconfidence and sometimes improve generalization. |

### "Missing keys" when loading best checkpoint

If you see: `There were missing keys in the checkpoint model loaded: ['encoder.embed_tokens.weight', ...]` at the end of training, Colab's older `transformers` sometimes doesn't save/load the best checkpoint correctly. The final saved model is still usable (usually the last epoch). To avoid that and always save the **last** epoch only, run: `python colab_train.py --no_load_best`.

---

So: **your run looked good** (low eval loss, smooth curve). To make it “better”, focus on (1) saving the best checkpoint (already in the script when supported), (2) checking patch quality on real examples, and (3) optionally more data, fewer epochs, or a slightly lower LR.
