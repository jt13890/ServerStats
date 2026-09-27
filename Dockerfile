FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SERVERSTATS_CONFIG=/config/config.yaml \
    SERVERSTATS_DATA=/data \
    SERVERSTATS_AGENT_SCRIPT=/app/agent/serverstats_agent.py

WORKDIR /app
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server/app ./app
COPY agent/serverstats_agent.py agent/install.sh ./agent/

RUN useradd --system --uid 10001 --home-dir /data serverstats \
    && mkdir -p /data /config \
    && chown serverstats:serverstats /data
USER serverstats

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"

# --proxy-headers makes client IPs/scheme in logs come from the reverse proxy.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header"]
