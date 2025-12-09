#!/usr/bin/env python3
"""
Export Labeling CSV

Creates a CSV file for manual labeling of contracts.
"""
import csv
import json
from pathlib import Path

EVAL_DIR = Path(__file__).parent.parent
LABELS_DIR = EVAL_DIR / "labels"


def export_csv():
    """Export labeling data to CSV for easy editing."""
    manifest_path = LABELS_DIR / "dataset_manifest.json"
    
    with open(manifest_path) as f:
        manifest = json.load(f)
    
    csv_path = LABELS_DIR / "labeling_sheet.csv"
    
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        
        # Header
        writer.writerow([
            "id",
            "filename",
            "source_lines",
            "initial_category",
            "classifier_category",
            "classifier_confidence",
            "known_vulnerabilities",
            "confirmed_category",  # Manual: Fill this
            "exploitability",      # Manual: confirmed/potential/false_positive
            "loss_percentage",     # Manual: 0-100
            "notes",               # Manual: Any notes
        ])
        
        for contract in manifest["contracts"]:
            classifier_result = contract.get("classifier_result", {})
            
            writer.writerow([
                contract["id"],
                contract["filename"],
                contract["source_lines"],
                contract["defi_category"],
                classifier_result.get("category", ""),
                f"{classifier_result.get('confidence', 0):.1%}",
                "; ".join(contract.get("known_vulnerabilities", [])),
                "",  # confirmed_category - to fill
                "",  # exploitability - to fill
                "",  # loss_percentage - to fill
                "",  # notes - to fill
            ])
    
    print(f"✓ Exported labeling sheet to {csv_path}")
    print(f"  Total contracts: {len(manifest['contracts'])}")
    print("\nInstructions:")
    print("1. Open labeling_sheet.csv in Excel/Google Sheets")
    print("2. Fill in: confirmed_category, exploitability, loss_percentage")
    print("3. Save as CSV and run import_labels.py")


if __name__ == "__main__":
    export_csv()
