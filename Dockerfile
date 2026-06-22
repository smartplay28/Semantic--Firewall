FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml README.md /app/
COPY browser_extension /app/browser_extension
COPY config /app/config
COPY data /app/data
COPY docs /app/docs
COPY semantic_firewall /app/semantic_firewall
COPY tests /app/tests
COPY requirements.txt CONTRIBUTING.md docker-compose.yml Dockerfile /app/

RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -e .

EXPOSE 8000

CMD ["uvicorn", "semantic_firewall.apps.api_server:app", "--host", "0.0.0.0", "--port", "8000"]
