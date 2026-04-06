# AuditQuant

AuditQuant is a hybrid smart contract auditing system built for my Master's project at Sacramento State. It runs four static/symbolic analysis tools in parallel, cross-validates findings, runs a fine-tuned CodeBERT model for vulnerability classification, and computes a DeFi-aware business risk score.

## What it does

- Runs **Slither**, **Slitherin**, **Semgrep**, and **Mythril** via Docker
- Normalizes all tool outputs into a common finding format
- Cross-validates findings by vuln type + location, applies confidence boosts when multiple tools agree
- Runs a fine-tuned **CodeBERT** classifier to catch vuln types tools miss
- Computes risk scores: R_SAST (static), R_DAST (symbolic), R_COMP (complexity), composite
- Classifies contracts by DeFi category and computes a business risk rubric
- Optionally generates an executive summary via OpenAI and verifies claims against tool findings

## Stack

- **Backend:** Python 3.11+, FastAPI, Pydantic v2
- **Tools:** Slither, Slitherin, Semgrep, Mythril (Docker Compose)
- **ML model:** Fine-tuned CodeBERT (multi-label vulnerability classifier)
- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS

## Prerequisites

- Python 3.11+
- Node.js 18+
- Docker Desktop (must be running for analysis)

## Setup

From the repo root:

### 1. Python environment

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt
```

### 2. Environment variables

```bash
cp .env.example .env
# edit .env and add your API keys
```

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | No | If set, enables LLM executive summary + claim verification |
| `OPENAI_MODEL` | No | Default: `gpt-4o-mini` |
| `OPENAI_BASE_URL` | No | Custom OpenAI-compatible endpoint |
| `CODEBERT_CHECKPOINT_PATH` | No | Path to fine-tuned checkpoint. Default: `evaluation/llm_training/checkpoints/checkpoint_best.pt` |
| `DOCKER_COMPOSE_PATH` | No | Default: `docker/docker-compose.yml` |
| `ANALYSIS_STORAGE_PATH` | No | Default: `backend/.analysis` |

### 3. Build Docker images

```bash
docker compose -f docker/docker-compose.yml build slither slitherin semgrep mythril
```

### 4. Start backend

```bash
uvicorn app.main:app --reload --app-dir backend
```

API: `http://localhost:8000` — Swagger docs: `http://localhost:8000/docs`

### 5. Start frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend: `http://localhost:5173`

### 6. Run analysis

Upload a `.sol` file from the Dashboard. The frontend polls `/api/analysis/{id}` until done.

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/analyze` | Upload `.sol` file, returns `analysis_id` |
| `GET` | `/api/analysis/{id}` | Get results (`202` while pending) |
| `GET` | `/api/analysis/{id}/business-risk` | Business risk report |

The analysis response includes `scores`, `findings`, `tool_results`, `model_prediction`, `business_risk`, and optionally `summary` + `verification`.

## Sample contracts

`contracts/` has a few test contracts: `VulnerableBank.sol`, `VulnerableVault.sol`, `UncheckedCall.sol`, `SimpleStorage.sol`.

## Evaluation

Re-run the 5-system comparison (AuditQuant tools, AuditQuant+CodeBERT, GPT-4o, Claude, Gemini):

```bash
python evaluation/scripts/run_test_split_comparison.py
```

Regenerate comparison graphs:

```bash
python evaluation/scripts/generate_comparison_graphs.py
```

Rebuild the training dataset from SmartBugs:

```bash
python evaluation/scripts/prepare_dataset_v2.py
```

Results are written to `evaluation/results/` and graphs to `evaluation/graphs/`.

## Troubleshooting

- **Analysis stuck:** make sure Docker Desktop is running and images are built
- **Tool failures:** check that `DOCKER_COMPOSE_PATH` is correct
- **No CodeBERT predictions:** checkpoint file is missing — check `CODEBERT_CHECKPOINT_PATH`
- **No LLM summary:** expected when `OPENAI_API_KEY` is not set
- **Results gone after restart:** analysis state is in-memory, not persisted to disk
