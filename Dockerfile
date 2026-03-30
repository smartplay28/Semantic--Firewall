FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml README.md /app/
COPY semantic_firewall /app/semantic_firewall
COPY agents /app/agents
COPY orchestrator /app/orchestrator
COPY api.py app.py main.py requirements.txt /app/
COPY custom_rules.json policy_presets.json workspaces.json threat_intel_feed.json /app/

RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -e .

EXPOSE 8000

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]

