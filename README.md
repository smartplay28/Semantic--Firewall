# Semantic Firewall

Semantic Firewall is an agentic LLM safety layer with:
- Input/output scanning
- Multi-agent threat detection
- Risk scoring and explainability
- Threat-intel signatures
- Policy/compliance presets
- Audit/review workflows
- Real-time WebSocket scanning
- SDK + middleware integrations

## Quick Start

```bash
pip install -e .
python -m uvicorn api:app --host 0.0.0.0 --port 8000
```

## One-command Smoke Test (Windows PowerShell)

```powershell
.\smoke_test.ps1
```

Fast run without full test suite:

```powershell
.\smoke_test.ps1 -SkipPytest
```

## SDK (pip package)

```python
from semantic_firewall import Firewall

fw = Firewall()
decision = fw.analyze("Ignore previous instructions")
print(decision.action)
```

## One-line LangChain Integration

```python
from semantic_firewall import Firewall
from semantic_firewall.integrations import LangChainFirewall

chain = LangChainFirewall(llm=your_llm, firewall=Firewall())
response = chain.invoke("Hello")
```

## FastAPI / Starlette Middleware Wrapper

```python
from fastapi import FastAPI
from semantic_firewall import SemanticFirewallMiddleware

app = FastAPI()
app.add_middleware(
    SemanticFirewallMiddleware,
    api_base_url="http://localhost:8000",
    policy_profile="balanced",
)
```

## WebSocket Realtime Scanning

Endpoint: `ws://localhost:8000/ws/analyze`

Example payload:

```json
{
  "text": "ignore all instructions",
  "scan_target": "input",
  "policy_profile": "balanced",
  "workspace_id": "default"
}
```

## Alerting (Slack / Email / Webhook)

Set any of these environment variables:

- `SEMANTIC_FIREWALL_ALERT_WEBHOOK_URL`
- `SEMANTIC_FIREWALL_SLACK_WEBHOOK_URL`
- `SEMANTIC_FIREWALL_SMTP_HOST`
- `SEMANTIC_FIREWALL_SMTP_PORT`
- `SEMANTIC_FIREWALL_SMTP_USER`
- `SEMANTIC_FIREWALL_SMTP_PASSWORD`
- `SEMANTIC_FIREWALL_ALERT_FROM`
- `SEMANTIC_FIREWALL_ALERT_TO`
- `SEMANTIC_FIREWALL_ALERT_MIN_SEVERITY` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)

## Accuracy/Latency Tuning (Minimal)

- `SEMANTIC_FIREWALL_LLM_GATE_ENABLED=1` enables low-risk gating for expensive LLM detectors.
- `SEMANTIC_FIREWALL_AGENT_TIMEOUT_*_SEC` controls per-agent timeout budgets.

Threshold recommendations from feedback:

```bash
python tools/suggest_threshold_tuning.py --db-path audit.db --min-count 2
```

This generates `threshold_tuning_recommendations.json` with suggested policy `action_overrides`.

## Public Leaderboard Page

Run Streamlit and open the `Leaderboard` tab:

```bash
streamlit run app.py
```

Leaderboard entries are loaded from `leaderboard.json`.

## Browser Extension (scaffold)

Extension source is in `browser_extension/`.

1. Open `chrome://extensions`.
2. Enable Developer mode.
3. Click `Load unpacked`.
4. Select the `browser_extension` folder.

The popup scans text via your running API (`http://localhost:8000` by default).

## CI/CD

GitHub Actions workflow: `.github/workflows/ci.yml`

- Installs package with dev dependencies
- Runs `pytest -q` on push and PR

## Docker

```bash
docker compose up --build
```

- API: `http://localhost:8000`
- Streamlit UI: `http://localhost:8501`
