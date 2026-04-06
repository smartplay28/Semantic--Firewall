# Project Structure

This repo is organized by responsibility, with compatibility shims kept at root (`api.py`, `app.py`) to avoid breaking existing commands.

## Core Runtime

- `agents/`: individual threat detectors (PII, secrets, abuse, injection, unsafe content, threat intel, custom rules)
- `orchestrator/`: decision pipeline, policy store, audit logging, session logic, risk scoring, explainability, compliance
- `orchestrator/session_judge.py`: dedicated session/context aggregation layer for multi-turn judgment and escalation
- `semantic_firewall/`: SDK, middleware, and integrations (LangChain wrapper)

## Application Layers

- `api_app/`: FastAPI app modules
- `api_app/routes/`: route groups (firewall, rules/policies, sessions/audit, threat intel, workspaces)
- `api_app/schemas.py`: API request/response models
- `ui_app/`: Streamlit UI module and page-level split

## Evaluation + Tuning

- `benchmarking/`: dataset extraction and benchmark runners
- `datasets/`: benchmark/golden/canary datasets
- `tools/`: tuning and recommendation utilities
- `results/`: generated benchmark/tuning outputs (metrics history, recommendations)
- `scripts/`: helper/dev scripts (`evaluate.py`, debug helpers, DB inspection)

## Integrations + Ops

- `browser_extension/`: Chrome extension popup/content scripts
- `.github/workflows/ci.yml`: test + benchmark + artifact pipeline
- `docker-compose.yml`, `Dockerfile`: containerized local setup

## Conventions

- Keep generated artifacts in `results/` (not root).
- Keep standalone helper scripts in `scripts/`; root script names may remain as wrappers for compatibility.
- Keep docs in `docs/` unless they are root onboarding entrypoints (`README.md`, `CONTRIBUTING.md`).
- Add tests for new detector or policy behavior in `tests/`.
- Preserve compatibility shims (`api.py`, `app.py`) when refactoring internals.
- Keep session-aware logic centralized in `orchestrator/session_judge.py` rather than scattering multi-turn escalation rules across entrypoints.
