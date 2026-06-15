# VULN (IaC/container): full, outdated base image = large attack surface + many OS CVEs.
# Caught by: Trivy image scan (HARD GATE on HIGH/CRITICAL) and Trivy config scan.
FROM python:3.9

WORKDIR /app

# VULN (IaC): ADD used instead of COPY; copies the whole context (incl. secrets).
ADD . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

# VULN (IaC): no USER directive -> container runs as root.
# VULN (IaC): no HEALTHCHECK.
CMD ["python", "app.py"]
