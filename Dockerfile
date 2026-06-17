FROM python:3.11-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11-slim
WORKDIR /app
RUN addgroup --gid 1001 appgroup \
    && adduser --uid 1001 --ingroup appgroup --no-create-home --disabled-password appuser
COPY --from=builder /install /usr/local
COPY --chown=appuser:appgroup ./app ./app
USER appuser
EXPOSE 8011
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8011/health')"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8011"]
