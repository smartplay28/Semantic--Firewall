# Structure Roadmap (Low-Risk Refactor Plan)

This project is already functional. The goal of this roadmap is to make structure cleaner without breaking behavior.

## Current Strengths

- Clear domain folders: `agents/`, `orchestrator/`, `benchmarking/`, `tools/`, `tests/`.
- Package boundary exists: `semantic_firewall/`.
- Test-generated files are now redirected away from `tests/`.

## Main Pain Points

- `api.py` combines routes, request/response models, and app wiring.
- `app.py` combines multiple UI concerns in one file.
- Some runtime data files still live at repository root.

## Target Shape (Incremental)

### 1) API split (no behavior change)

Create:

- `api_app/__init__.py`
- `api_app/main.py` (FastAPI app creation + middleware)
- `api_app/schemas.py` (Pydantic models)
- `api_app/routes/health.py`
- `api_app/routes/scan.py`
- `api_app/routes/policies.py`
- `api_app/routes/rules.py`
- `api_app/routes/threat_intel.py`

Keep `api.py` as a compatibility entrypoint:

- Import app from `api_app.main`
- Re-export `app` so existing commands keep working.

### 2) UI split (Streamlit)

Create:

- `ui_app/__init__.py`
- `ui_app/main.py`
- `ui_app/pages/overview.py`
- `ui_app/pages/leaderboard.py`
- `ui_app/pages/policy_admin.py`
- `ui_app/components/charts.py`
- `ui_app/components/tables.py`

Keep `app.py` as compatibility entrypoint:

- Import and run from `ui_app.main`.

### 3) Runtime artifact boundaries

Standardize:

- `config/` for editable static config (`custom_rules.json`, presets, feeds).
- `results/` for generated benchmark output.
- `var/` for local runtime databases (`audit.db`) in dev.

Environment variables should control runtime paths so Docker and local dev stay consistent.

## Safe Execution Rules

- Move one route/page group at a time.
- After each step, run targeted tests and smoke checks.
- Keep old entrypoints (`api.py`, `app.py`) until the end to avoid command breakage.
- No rename/removal of public API endpoints during the split.

## Suggested Order

1. Extract API app factory and keep route code unchanged.
2. Move API routes into `api_app/routes/*` with tests green.
3. Extract Streamlit pages/components.
4. Move runtime artifact paths behind env config.
5. Remove dead glue only after all references are updated.

