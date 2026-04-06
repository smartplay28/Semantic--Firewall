# Contributing

Thanks for contributing to Semantic Firewall.

## 1) Local Setup

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate

pip install --upgrade pip
pip install -e .[dev]
```

Optional `.env` values for full detector behavior:

- `GROQ_API_KEY`
- Alerting variables (see README)

## 2) Run The Project

API:

```bash
python -m uvicorn api:app --host 0.0.0.0 --port 8000
```

UI:

```bash
streamlit run app.py
```

## 3) Run Tests Before PR

Quick smoke (Windows):

```powershell
.\smoke_test.ps1 -SkipPytest
```

Full tests:

```bash
pytest -q
```

Focused safety suites:

```bash
pytest -q tests/test_injection_detector.py tests/test_unsafe_content_detector.py tests/test_firewall_safety.py tests/test_canary_prompts.py
```

## 4) Benchmark + Tuning Workflow

```bash
python tools/run_tuning_cycle.py --quiet
```

Generated outputs are written to `results/`.

## 5) Code Organization Rules

- Add new API endpoints in `api_app/routes/`.
- Add request/response models in `api_app/schemas.py`.
- Add UI pages in `ui_app/pages/`.
- Add detector logic in `agents/` and orchestration logic in `orchestrator/`.
- Put helper/maintenance scripts in `scripts/` (root script names are compatibility wrappers).
- Keep `api.py` and `app.py` as compatibility entrypoints.

## 6) Pull Request Checklist

- Tests pass locally (`pytest -q`).
- New behavior has tests.
- README/docs updated for new flags, scripts, or endpoints.
- No unrelated generated artifacts committed from local runs.
