# AuditQuant MVP

AuditQuant is a hybrid smart contract auditing framework that unifies static analysis, risk quantification, and AI-assisted validation/remediation.

## Stack
- Backend: FastAPI + Python 3.11
- RiskQuant: Multi-vector scoring (R_SAST, R_DAST, R_COMP)
- Analysis: Slither (Dockerized)
- LLM: GPT-4o integration for validation and summaries
- Frontend: React 19 + Vite + Tailwind + Monaco Editor

## Quick Start

### 1. Backend
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn app.main:app --reload --app-dir backend
```

### 2. Slither Docker
```bash
docker compose -f docker/docker-compose.yml build slither
```

### 3. Frontend
```bash
cd frontend
npm install
npm run dev
```

## Environment
Create a `.env` file based on `.env.example` and configure:
- `OPENAI_API_KEY`
- `OPENAI_MODEL`
- `ANALYSIS_STORAGE_PATH`
- `DOCKER_COMPOSE_PATH`

## API Endpoints
- `POST /api/analyze` — upload a Solidity file
- `GET /api/analysis/{id}` — fetch analysis results
- `GET /api/health` — health check

## Testing with sample contracts
The `contracts/` folder contains intentionally vulnerable Solidity files for testing the pipeline:
- **VulnerableBank.sol** — reentrancy (ETH)
- **VulnerableVault.sol** — missing access control
- **UncheckedCall.sol** — unchecked low-level call return
- **SimpleStorage.sol** — minimal, no critical issues

Upload any of these from the Dashboard to run Slither, Mythril, RiskQuant, and remediation. See `contracts/README.md` for details.

## Notes
- Slither runs in a container and expects the project root mounted at `/work`.
- If no OpenAI key is provided, AI validation falls back to permissive defaults.
- **Start the backend from the repo root** (e.g. `uvicorn app.main:app --reload --app-dir backend`) so uploaded files are stored under the repo and Docker can read them.
- Analysis has a 7‑minute overall timeout; if it stays "pending" longer, it will switch to "failed" with a timeout message. Ensure Docker is running and Slither/Mythril images are built (`docker compose -f docker/docker-compose.yml build slither mythril`).
