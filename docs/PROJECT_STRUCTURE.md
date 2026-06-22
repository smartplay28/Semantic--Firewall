# Project Structure

This repo is organized into a few larger responsibility-based buckets with minimal root-level entrypoints.

## Core Runtime

- `semantic_firewall/core/agents/`: individual threat detectors
- `semantic_firewall/core/orchestrator/`: decision pipeline, policy store, audit logging, session logic, and risk scoring
- `semantic_firewall/`: SDK, middleware, API, UI, and integrations

## Application Layers

- `semantic_firewall/apps/`: runnable app entrypoints (`dashboard.py`, `api_server.py`)
- `semantic_firewall/api/`: FastAPI modules, route groups, and schemas
- `semantic_firewall/ui/`: Streamlit UI modules and page-level split

## Evaluation + Tuning

- `semantic_firewall/benchmarks/`: dataset extraction, benchmark runners, and research experiments
- `data/datasets/`: benchmark/golden/canary datasets
- `data/results/`: generated benchmark/tuning outputs
- `data/var/`: runtime data such as SQLite and vector-store state
- `semantic_firewall/tools/`: tuning and maintenance utilities

## Integrations + Ops

- `browser_extension/`: Chrome extension popup/content scripts
- `.github/workflows/ci.yml`: test + benchmark + artifact pipeline
- `docker-compose.yml`, `Dockerfile`: containerized local setup

## Conventions

- Keep generated artifacts in `data/results/` (not root).
- Keep helper scripts in `semantic_firewall/tools/`.
- Keep runnable apps and evaluations in `semantic_firewall/apps/` and `semantic_firewall/benchmarks/`.
- Keep docs in `docs/` unless they are root onboarding entrypoints (`README.md`, `CONTRIBUTING.md`).
- Add tests for new detector or policy behavior in `tests/`.
- Keep session-aware logic centralized in `semantic_firewall/core/orchestrator/session_judge.py`.

