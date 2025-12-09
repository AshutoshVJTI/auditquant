#!/usr/bin/env python3
"""
Run DeFi Classifier on Evaluation Dataset

Applies the DeFi classifier to all contracts and updates the manifest
with classification results.
"""
import json
import sys
from pathlib import Path

# Add backend to path
EVAL_DIR = Path(__file__).parent.parent
PROJECT_ROOT = EVAL_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.services.defi_classifier import classify_contract, get_business_context, DeFiCategory

LABELS_DIR = EVAL_DIR / "labels"
DATASETS_DIR = EVAL_DIR / "datasets" / "selected"


def run_classifier():
    """Run classifier on all contracts and update manifest."""
    manifest_path = LABELS_DIR / "dataset_manifest.json"
    
    with open(manifest_path) as f:
        manifest = json.load(f)
    
    print("Running DeFi classifier on contracts...\n")
    
    classification_results = []
    category_counts = {cat.value: 0 for cat in DeFiCategory}
    
    for contract in manifest["contracts"]:
        contract_id = contract["id"]
        selected_path = Path(contract["selected_path"])
        
        if not selected_path.exists():
            print(f"  ✗ {contract_id}: File not found")
            continue
        
        try:
            source = selected_path.read_text(encoding="utf-8", errors="ignore")
            result = classify_contract(source)
            context = get_business_context(result)
            
            # Update contract entry
            contract["classifier_result"] = {
                "category": result.primary_category.value,
                "confidence": round(result.confidence, 3),
                "all_scores": {k.value: round(v, 3) for k, v in result.all_scores.items()},
                "detected_patterns": result.detected_patterns[:5],
            }
            contract["business_context"] = context
            
            category_counts[result.primary_category.value] += 1
            
            # Determine if classification differs from initial guess
            initial = contract["defi_category"]
            classified = result.primary_category.value
            match = "✓" if initial == classified else "≠"
            
            classification_results.append({
                "id": contract_id,
                "initial": initial,
                "classified": classified,
                "confidence": result.confidence,
                "match": initial == classified,
            })
            
            print(f"  {match} {contract_id}: {initial} → {classified} ({result.confidence:.1%})")
            
        except Exception as e:
            print(f"  ✗ {contract_id}: Error - {e}")
    
    # Save updated manifest
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    
    print(f"\n✓ Updated manifest with classifier results")
    
    # Save classification summary
    summary = {
        "total_classified": len(classification_results),
        "category_distribution": category_counts,
        "agreement_rate": sum(1 for r in classification_results if r["match"]) / len(classification_results) if classification_results else 0,
        "results": classification_results,
    }
    
    summary_path = LABELS_DIR / "classification_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"✓ Saved classification summary to {summary_path}")
    
    # Print distribution
    print("\nClassification Distribution:")
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count}")
    
    print(f"\nAgreement with initial classification: {summary['agreement_rate']:.1%}")


if __name__ == "__main__":
    run_classifier()
