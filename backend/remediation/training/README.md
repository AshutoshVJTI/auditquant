# CodeT5 Fine-Tuning

This folder contains the scaffolding for fine-tuning CodeT5 on the combined SmartBugs + SolidiFI remediation corpus.

## Dataset Layout

Place merged datasets under `datasets/merged` using the following structure:

```
datasets/merged/
  Reentrancy/
    sample-001/
      vulnerable.sol
      patched.sol
  AccessControl/
    sample-002/
      vulnerable.sol
      patched.sol
```

## Training

```
python -m remediation.training.train
```

The script will:

- load the dataset using `data_loader.py`
- fine-tune `Salesforce/codet5-base`
- save the model under `artifacts/codet5`

## Notes

- Install dependencies with `pip install transformers torch`.
- Adjust training hyperparameters in `train.py` as needed.
