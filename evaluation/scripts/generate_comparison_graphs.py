#!/usr/bin/env python3
# Generates comparison graphs from test_split_comparison JSON results.
# Usage: python evaluation/scripts/generate_comparison_graphs.py --input <results.json>
import argparse
import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

EVAL_DIR    = Path(__file__).resolve().parents[1]
RESULTS_DIR = EVAL_DIR / "results"
GRAPHS_DIR  = EVAL_DIR / "graphs"
GRAPHS_DIR.mkdir(exist_ok=True)

SYSTEM_LABELS = {
    "auditquant_tools":    "AuditQuant\n(Tools Only)",
    "auditquant_codebert": "AuditQuant\n+ CodeBERT",
    "gpt4o":               "GPT-4o",
    "claude":              "Claude\nSonnet 4.6",
    "gemini":              "Gemini\n2.5 Flash",
}

VULN_ABBREV = {
    "reentrancy":                "RE",
    "arithmetic":                "IO",
    "access_control":            "AC",
    "unchecked_low_level_calls": "USE",
    "denial_of_service":         "DOS",
    "front_running":             "TOD",
    "bad_randomness":            "BR",
    "flash_loan":                "FL",
    "price_manipulation":        "PM",
    "liquidation":               "LQ",
}

FINAL_HEATMAP_TYPES = [
    "reentrancy",
    "access_control",
    "unchecked_low_level_calls",
    "denial_of_service",
    "front_running",
]

COLORS = ["#4878A8", "#5A9470", "#B85858", "#7B6BAA", "#A89050"]

def load_results(path: Path | None = None, clean: bool = False) -> dict:
    if path and path.exists():
        return json.loads(path.read_text())
    if clean:
        p = RESULTS_DIR / "llm_comparison_clean.json"
        if p.exists():
            return json.loads(p.read_text())
    p = RESULTS_DIR / "llm_comparison_latest.json"
    if p.exists():
        return json.loads(p.read_text())
    candidates = sorted(RESULTS_DIR.glob("llm_comparison_*.json"),
                        key=lambda f: f.stat().st_mtime)
    if candidates:
        return json.loads(candidates[-1].read_text())
    raise FileNotFoundError("No comparison results found in evaluation/results/")

def _abbr(vuln_type: str) -> str:
    if vuln_type in VULN_ABBREV:
        return VULN_ABBREV[vuln_type]
    parts = [p for p in vuln_type.split("_") if p]
    if not parts:
        return vuln_type.upper()
    if len(parts) == 1:
        return parts[0][:3].upper()
    return "".join(p[0].upper() for p in parts[:3])

def active_vuln_types(results: dict) -> list[str]:
    systems = results["systems_evaluated"]
    all_types: set[str] = set()
    support_by_type: dict[str, int] = {}

    for s in systems:
        per_type = results["system_metrics"][s].get("per_vuln_type", {})
        for vt, metrics in per_type.items():
            all_types.add(vt)
            support_by_type[vt] = max(support_by_type.get(vt, 0), int(metrics.get("support", 0)))

    supported = [vt for vt in all_types if support_by_type.get(vt, 0) > 0]
    return sorted(supported, key=lambda vt: (-support_by_type[vt], vt))

def graph1_tp_fp_stacked(results: dict) -> None:
    systems = results["systems_evaluated"]
    labels  = [SYSTEM_LABELS[s] for s in systems]
    tp_vals = [results["system_metrics"][s]["metrics"]["tp"] for s in systems]
    fp_vals = [results["system_metrics"][s]["metrics"]["fp"] for s in systems]

    fig, ax = plt.subplots(figsize=(9, 5))

    b1 = ax.bar(labels, tp_vals, color="#5A9470", label="True Positives")
    b2 = ax.bar(labels, fp_vals, bottom=tp_vals, color="#B85858", label="False Positives")

    max_val = max(tp + fp for tp, fp in zip(tp_vals, fp_vals)) or 1
    for bar, tp, fp in zip(b1, tp_vals, fp_vals):
        if tp > max_val * 0.04:
            ax.text(bar.get_x() + bar.get_width() / 2, tp / 2,
                    str(tp), ha="center", va="center", fontsize=9, color="white")
        elif tp > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, tp + max_val * 0.015,
                    str(tp), ha="center", va="bottom", fontsize=8, color="#5A9470")
    for bar, tp, fp in zip(b2, tp_vals, fp_vals):
        if fp > max_val * 0.04:
            ax.text(bar.get_x() + bar.get_width() / 2, tp + fp / 2,
                    str(fp), ha="center", va="center", fontsize=9, color="white")
        elif fp > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, tp + fp + max_val * 0.015,
                    str(fp), ha="center", va="bottom", fontsize=8, color="#B85858")

    ax.set_ylabel("Number of Findings")
    ax.set_title("Prediction Breakdown: True vs False Positives")
    ax.legend()
    ax.yaxis.grid(True, alpha=0.3)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    fig.tight_layout()
    fig.savefig(GRAPHS_DIR / "1_tp_fp_stacked.png", dpi=150)
    plt.close(fig)
    print("  saved  1_tp_fp_stacked.png")

def graph2_f1_heatmap(results: dict) -> None:
    systems = results["systems_evaluated"]
    vtypes  = FINAL_HEATMAP_TYPES
    xlabels = [VULN_ABBREV[v] for v in vtypes]
    ylabels = [SYSTEM_LABELS[s].replace("\n", " ") for s in systems]

    data = np.array([
        [results["system_metrics"][s]["per_vuln_type"].get(vt, {}).get("f1", 0.0)
         for vt in vtypes]
        for s in systems
    ])

    fig, ax = plt.subplots(figsize=(len(vtypes) * 1.4 + 1, len(systems) * 0.85 + 1))
    im = ax.imshow(data, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")

    for i in range(len(systems)):
        for j in range(len(vtypes)):
            val = data[i, j]
            text_color = "white" if val > 0.75 or val < 0.2 else "black"
            ax.text(j, i, f"{val:.2f}", ha="center", va="center",
                    fontsize=10, color=text_color)

    ax.set_xticks(range(len(vtypes)))
    ax.set_xticklabels(xlabels, fontsize=11)
    ax.set_yticks(range(len(systems)))
    ax.set_yticklabels(ylabels, fontsize=10)
    ax.set_title("F1 Score per Vulnerability Type")
    plt.colorbar(im, ax=ax, shrink=0.6, label="F1")

    fig.tight_layout()
    fig.savefig(GRAPHS_DIR / "2_f1_heatmap.png", dpi=150)
    plt.close(fig)
    print("  saved  2_f1_heatmap.png")

def graph3_precision_recall(results: dict) -> None:
    systems = results["systems_evaluated"]
    fig, ax = plt.subplots(figsize=(10, 7))

    xs, ys, labels = [], [], []
    for i, s in enumerate(systems):
        m   = results["system_metrics"][s]["metrics"]
        lbl = SYSTEM_LABELS[s].replace("\n", " ")
        ax.scatter(m["recall"], m["precision"], s=120, color=COLORS[i], zorder=3)
        xs.append(m["recall"])
        ys.append(m["precision"])
        labels.append(lbl)

    # Set axis limits first so pixel transforms are stable
    pad = 0.08
    ax.set_xlim(max(0, min(xs) - pad), min(1.05, max(xs) + pad + 0.1))
    ax.set_ylim(max(0, min(ys) - pad * 2), min(1.05, max(ys) + pad + 0.25))
    fig.canvas.draw()

    # Place labels centered above dots; nudge up on pixel-level collision.
    order = sorted(range(len(xs)), key=lambda i: (ys[i], xs[i]))
    placed_px = []  # (x0, y0, x1, y1) in display pixels

    renderer = fig.canvas.get_renderer()
    inv = ax.transData.inverted()
    gap_px = 24   # pixels between dot center and label bottom
    pad_px = 10   # minimum pixel gap between labels

    for idx in order:
        x, y, lbl = xs[idx], ys[idx], labels[idx]
        dot_px = ax.transData.transform((x, y))
        label_y_px = dot_px[1] + gap_px

        # Measure text size via a temporary text object at (0,0)
        tmp = ax.text(0, 0, lbl, fontsize=9, fontweight="bold",
                      ha="center", va="bottom",
                      transform=None)
        fig.canvas.draw_idle()
        bb_raw = tmp.get_window_extent(renderer=renderer)
        tmp.remove()
        tw, th = bb_raw.width, bb_raw.height

        def _bbox(yp):
            cx = dot_px[0]
            return (cx - tw / 2, yp, cx + tw / 2, yp + th)

        bb = _bbox(label_y_px)

        # Nudge up past collisions
        for _ in range(20):
            collision = False
            for pb in placed_px:
                if (bb[0] < pb[2] + pad_px and bb[2] > pb[0] - pad_px and
                        bb[1] < pb[3] + pad_px and bb[3] > pb[1] - pad_px):
                    label_y_px = pb[3] + pad_px
                    bb = _bbox(label_y_px)
                    collision = True
                    break
            if not collision:
                break

        placed_px.append(bb)
        data_pos = inv.transform((dot_px[0], label_y_px))
        ax.annotate(
            lbl, xy=(x, y), xytext=(data_pos[0], data_pos[1]),
            fontsize=9, fontweight="bold", ha="center", va="bottom",
            arrowprops=dict(arrowstyle="-", color="grey", lw=0.6),
        )

    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision vs Recall")
    ax.xaxis.grid(True, alpha=0.3)
    ax.yaxis.grid(True, alpha=0.3)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    fig.tight_layout()
    fig.savefig(GRAPHS_DIR / "3_precision_recall.png", dpi=150)
    plt.close(fig)
    print("  saved  3_precision_recall.png")

def graph4_hallucination(results: dict) -> None:
    systems = results["systems_evaluated"]
    def _hallu(s):
        lm = results["system_metrics"][s].get("llm_metrics")
        if lm:
            return lm["hallucination_rate"]
        m = results["system_metrics"][s]["metrics"]
        tp, fp = m["tp"], m["fp"]
        return fp / (tp + fp) if (tp + fp) > 0 else 0.0

    labels  = [SYSTEM_LABELS[s] for s in systems]
    hallu   = [_hallu(s) for s in systems]

    pred_counts = {s: (results["system_metrics"][s]["metrics"]["tp"]
                       + results["system_metrics"][s]["metrics"]["fp"])
                   for s in systems}

    fig, ax = plt.subplots(figsize=(9, 5.5))
    bars = ax.bar(labels, hallu, color=COLORS, width=0.5)

    pct_labels = []
    for s, v in zip(systems, hallu):
        n = pred_counts[s]
        if n <= 10:
            pct_labels.append(f"{v:.1%}*")
        else:
            pct_labels.append(f"{v:.1%}")
    ax.bar_label(bars, labels=pct_labels, padding=3, fontsize=9)

    footnote_lines = []
    for s in systems:
        n = pred_counts[s]
        if n <= 10:
            lbl = SYSTEM_LABELS[s].replace("\n", " ")
            m = results["system_metrics"][s]["metrics"]
            footnote_lines.append(
                f"* {lbl}: only {n} predictions total "
                f"({m['tp']} TP, {m['fp']} FP, {m['fn']} FN)  -  rate is trivially 0%"
            )
    if footnote_lines:
        fig.text(0.02, 0.01, "\n".join(footnote_lines),
                 fontsize=7, color="grey", va="bottom")

    ax.set_ylabel("False Discovery Rate  FP / (TP + FP)")
    ax.set_ylim(0, max(hallu) * 1.25 + 0.02)
    ax.set_title("Hallucination Rate  (FP as share of all predictions)")
    ax.yaxis.grid(True, alpha=0.3)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    fig.tight_layout()
    fig.savefig(GRAPHS_DIR / "4_hallucination_rate.png", dpi=150)
    plt.close(fig)
    print("  saved  4_hallucination_rate.png")

def graph5_per_class_f1(results: dict) -> None:
    systems  = results["systems_evaluated"]
    vtypes   = FINAL_HEATMAP_TYPES
    xlabels  = [_abbr(v) for v in vtypes]

    x      = np.arange(len(vtypes))
    width  = 0.15
    offsets = np.linspace(-(len(systems) - 1) / 2, (len(systems) - 1) / 2, len(systems)) * width

    fig, ax = plt.subplots(figsize=(10, 5))
    for i, (s, col) in enumerate(zip(systems, COLORS)):
        pvt  = results["system_metrics"][s].get("per_vuln_type", {})
        vals = [pvt.get(v, {}).get("f1", 0.0) for v in vtypes]
        lbl  = SYSTEM_LABELS[s].replace("\n", " ")
        ax.bar(x + offsets[i], vals, width, label=lbl, color=col, alpha=0.85)

    ax.set_xticks(x)
    ax.set_xticklabels(xlabels, fontsize=11)
    ax.set_ylabel("F1 Score")
    ax.set_ylim(0, 1.1)
    ax.set_title("F1 Score by Vulnerability Type")
    ax.legend(fontsize=8, loc="upper right")
    ax.yaxis.grid(True, alpha=0.3)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    fig.tight_layout()
    fig.savefig(GRAPHS_DIR / "5_per_class_f1.png", dpi=150)
    plt.close(fig)
    print("  saved  5_per_class_f1.png")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=None,
                        help="Path to comparison JSON (default: llm_comparison_clean.json)")
    args = parser.parse_args()

    results = load_results(path=args.input, clean=True)
    n    = results.get("n_labeled_contracts") or results.get("n_contracts", "?")
    excl = results.get("n_excluded_dataset_overlap", 0)
    note = f"{n} contracts" + (f" (excluded {excl} dataset-overlapping)" if excl else "")
    print(f"Loaded: {note}, {len(results['systems_evaluated'])} systems\n")

    graph1_tp_fp_stacked(results)
    graph2_f1_heatmap(results)
    graph3_precision_recall(results)
    graph4_hallucination(results)
    graph5_per_class_f1(results)

    print("\nDone.")
if __name__ == "__main__":
    sys.exit(main())
