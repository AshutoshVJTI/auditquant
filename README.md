# AuditQuant

**A Hybrid Framework for Smart Contract Auditing Integrating Static/Dynamic Analysis and Quantitative Risk Scoring**

AuditQuant unifies the auditing workflow by combining Slither (static), Mythril (symbolic), and Oyente (bytecode) analysis with LLM-assisted summarization, a **Claim Verification Layer** to suppress hallucinations, and a **Multi-Vector RiskQuant Engine** for business-aware risk scoring.

## Features

- **Multi-tool orchestration** — Slither 0.9.0, Mythril 0.23.15, Oyente 0.2.7 (Dockerized), run in parallel with normalized findings and cross-tool validation
- **LLM summarization** — Structured summaries (vulnerability description, exploit scenario, technical impact, fix recommendation) applied only after tool aggregation
- **Anti-hallucination verification** — Factual claims from the LLM are checked against tool evidence; unsupported claims are filtered and a hallucination rate is reported
- **RiskQuant engine** — R_SAST (static density), R_DAST (dynamic certainty), R_COMP (cyclomatic complexity); 4-part business risk rubric (Exploitability, Financial Impact, Exposure, Evidence Strength) → 0–100 score
- **Financial loss quantification** — L_perc formula with drain probabilities (total/partial/zero impact) and rubric-vs-LLM loss-bucket comparison
- **DeFi classification** — AMM/DEX, Lending, Vault/Yield, Staking (four domains) for exposure and business context
- **Remediation** — CodeT5-based patch generation (fine-tuned model when present, otherwise Hugging Face base model)
- **React UI** — Dashboard (upload .sol), Results (risk gauges, validated findings, executive summary), Remediation (diff viewer + explanation)

## Stack

- **Backend:** FastAPI, Python 3.11+
- **Analysis tools:** Slither, Mythril, Oyente (Docker)
- **LLM:** OpenAI API (GPT-4o or configurable model) for structured summaries
- **RiskQuant:** R_SAST, R_DAST, R_COMP + business rubric + L_perc
- **Frontend:** React 19, Vite, Tailwind CSS, Monaco Editor (diff viewer)

## Pipeline

```
Smart Contract → Audit Tools (Slither, Mythril, Oyente) → Aggregation →
LLM Summarization → Claim Verification → Manual Rubric →
LLM Risk Estimation → Comparative Evaluation → Remediation
```

## Quick Start

### 1. Backend

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt
uvicorn app.main:app --reload --app-dir backend
```

### 2. Tool Docker images

Build the three analysis tools (Slither, Mythril, Oyente):

```bash
docker compose -f docker/docker-compose.yml build slither mythril oyente
```

On Apple Silicon, Oyente runs via emulation (`platform: linux/amd64`). Ensure Docker is running before starting an analysis.

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open the app (e.g. http://localhost:5173), upload a `.sol` file from the Dashboard, then view Results and Remediation.

## Environment

Create a `.env` file (see `.env.example`) in the project root or backend:

- `OPENAI_API_KEY` — required for LLM summarization and claim verification
- `OPENAI_MODEL` — e.g. `gpt-4o` (default)
- `OPENAI_BASE_URL` — optional, for proxy or Azure
- `ANALYSIS_STORAGE_PATH` — directory for uploaded contracts (default: `./analysis_storage`)
- `DOCKER_COMPOSE_PATH` — path to `docker/docker-compose.yml`

## API Endpoints

- `GET /api/health` — service health
- `POST /api/analyze` — upload a `.sol` file; starts the full pipeline (Slither, Mythril, Oyente + LLM + verification + risk + remediation). Returns `analysis_id`; poll for results.
- `GET /api/analysis/{id}` — get results (scores, findings, verification status, hallucination rate, summary, remediation patches)
- `GET /api/analysis/{id}/business-risk` — 4-part business risk rubric and rubric-vs-LLM comparison

## Evaluation & Benchmark

The evaluation suite uses **100 Solidity contracts** across four DeFi domains (AMM/DEX, Lending, Vault/Yield, Staking) plus Other. Run from the project root with the backend on `PYTHONPATH`:

```bash
cd evaluation/scripts
python run_benchmark.py --limit 10           # standard benchmark (optional --real for real Docker/API)
python run_benchmark.py --mode compare       # RQ4: hybrid vs standalone tools vs ChatGPT-only
```

With `--real`, the pipeline uses real tool runs and (for compare mode) real ChatGPT API calls. Results are written to `evaluation/results/`; **performance graphs** (tool coverage, hallucination suppression, FPR, F1, time to audit) are generated in `evaluation/results/graphs/`.

Install matplotlib for graph generation: `pip install matplotlib` (included in `backend/requirements.txt`).

## Sample Contracts

The `contracts/` folder contains intentionally vulnerable Solidity files for testing:

- **VulnerableBank.sol** — reentrancy (ETH)
- **VulnerableVault.sol** — missing access control
- **UncheckedCall.sol** — unchecked low-level call return
- **SimpleStorage.sol** — minimal, no critical issues

See `contracts/README.md` for details.

## Notes

- Start the backend from the repo root (e.g. `uvicorn app.main:app --reload --app-dir backend`) so the storage path and Docker volume paths resolve correctly.
- Slither/Mythril use solc 0.8.x in their images. For best results, use `pragma solidity ^0.8.0` or compatible. Oyente uses solc 0.4.25.
- If analysis stays "pending", ensure Docker is running and the three images are built. The frontend polls until the analysis completes or times out.
- CodeT5 remediation uses a fine-tuned checkpoint under `backend/remediation/models/codet5-solidity-repair` when present; otherwise it downloads and uses the base model `Salesforce/codet5-base` from Hugging Face.
