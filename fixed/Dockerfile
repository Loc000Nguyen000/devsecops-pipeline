# FIX (container): slim, current base image = small attack surface, far fewer OS CVEs.
FROM python:3.12-slim

WORKDIR /app

# FIX (IaC): install dependencies first for layer caching, then COPY (not ADD).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# FIX (IaC): COPY instead of ADD — no implicit URL fetch / archive extraction.
COPY . /app

# FIX (IaC): create and switch to an unprivileged user — no longer runs as root.
RUN adduser --disabled-password --gecos "" app && chown -R app /app
USER app

EXPOSE 5000

# FIX (IaC): container healthcheck.
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/').status==200 else 1)"

CMD ["python", "app.py"]
