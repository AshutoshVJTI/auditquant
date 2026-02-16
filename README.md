# AuditQuant

Hybrid smart contract auditing framework that combines static/dynamic analysis tools with LLM summarization and quantitative risk scoring.

## What it does

- Runs **Slither**, **Mythril**, and **Oyente** (all Dockerized) in parallel on uploaded `.sol` files
- Normalizes and cross-validates findings across tools
- Uses an LLM (OpenAI) to generate structured summaries, then verifies claims against actual tool evidence (anti-hallucination layer)
- Computes risk scores: R_SAST (static density), R_DAST (dynamic certainty), R_COMP (complexity)
- Business risk rubric with 4 dimensions (Exploitability, Financial Impact, Exposure, Evidence Strength) scored 0-5, aggregated to 0-100
- Generates remediation patches using a fine-tuned CodeT5 model
- React frontend with risk gauges, findings list, and a diff viewer for patches

## Tech Stack

- **Backend:** Python 3.11+, FastAPI
- **Analysis:** Slither, Mythril, Oyente (Docker)
- **LLM:** OpenAI API (GPT-4o-mini by default)
- **ML:** CodeT5 (Salesforce/codet5-base), PyTorch, Transformers
- **Frontend:** React 19, Vite, TypeScript, Tailwind, Monaco Editor

## Setup

### Backend

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn app.main:app --reload --app-dir backend
```

### Docker images (analysis tools)

```bash
docker compose -f docker/docker-compose.yml build slither mythril oyente
```

On Apple Silicon Oyente runs via emulation (`platform: linux/amd64`).

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Then open http://localhost:5173.

## Environment Variables

Copy `.env.example` to `.env` and fill in:

- `OPENAI_API_KEY` -- required
- `OPENAI_MODEL` -- defaults to `gpt-4o-mini`
- `ANALYSIS_STORAGE_PATH` -- where uploaded contracts go
- `DOCKER_COMPOSE_PATH` -- path to `docker/docker-compose.yml`

## API

- `GET /api/health`
- `POST /api/analyze` -- upload `.sol` file, returns `analysis_id`
- `GET /api/analysis/{id}` -- poll for results
- `GET /api/analysis/{id}/business-risk` -- detailed rubric breakdown

## Sample Contracts

`contracts/` has some intentionally vulnerable Solidity files for testing:
VulnerableBank (reentrancy), VulnerableVault (access control), UncheckedCall, SimpleStorage.

## Evaluation

```bash
cd evaluation/scripts
python run_benchmark.py --limit 10
python run_benchmark.py --mode compare   # hybrid vs standalone vs ChatGPT-only
```

Add `--real` for actual Docker/API runs instead of mocked results.

## Notes

- Make sure Docker is running before uploading contracts
- If analysis stays "pending", check Docker and backend logs
- CodeT5 uses a local fine-tuned checkpoint if present, otherwise downloads the base model from HuggingFace
