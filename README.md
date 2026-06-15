# Applied DevSecOps for IT Infrastructure Security

A minimal but complete **DevSecOps CI/CD pipeline** that shifts security *left*
into the development workflow. Every commit is automatically scanned for
secrets, insecure code, vulnerable dependencies, infrastructure
misconfiguration, vulnerable container layers, and runtime web flaws — and the
build is **blocked** when a critical issue is found.

The repo ships the app in **two side-by-side folders** so the pipeline can
prove the gates work *both ways* in a single run:

- **`vulnerable/`** — an intentionally insecure Flask app; every scanner
  produces real findings and the hard gates go **red**.
- **`fixed/`** — the remediated counterpart; the same scanners pass and the
  gates go **green**.

Each folder holds the same four files: `app.py`, `Dockerfile`,
`requirements.txt`, and `docker-compose.yml`.

## Pipeline architecture

```
  commit / pull request
          |
          v
  +-------------------+   +------------------+   +----------------------+
  | 1. SECRETS        |   | 2. SAST          |   | 3. SCA + IaC         |
  |    Gitleaks       |   |    Semgrep       |   |    Trivy (fs)        |
  |    [HARD GATE]    |   |    report-only   |   |    report-only       |
  +-------------------+   +------------------+   +----------------------+
          \                       |                       /
           \                      v                      /
            \            findings -> GitHub Security tab (SARIF)
             \                                            /
              v                                          v
        +-------------------------------------------------------+
        | 4. CONTAINER SECURITY                                 |
        |    build image                                        |
        |    Trivy image scan  [HARD GATE: HIGH/CRITICAL]       |
        |    deploy + OWASP ZAP baseline (DAST)                 |
        +-------------------------------------------------------+
```

### How each stage maps to DevSecOps

| Stage | Tool | DevSecOps category | Enforcement |
|-------|------|--------------------|-------------|
| 1 | Gitleaks | Secrets detection | **Hard gate** — fails on any leaked credential |
| 2 | Semgrep | SAST (static code) | Report-only -> Security tab |
| 3 | Trivy (fs) | SCA + IaC misconfiguration | Report-only -> Security tab |
| 4 | Trivy (image) | Container image CVEs | **Hard gate** — fails on HIGH/CRITICAL |
| 4 | OWASP ZAP | DAST (running app) | Report-only artifact |

Two enforced gates demonstrate the core principle that security can *block a
release*, while the report-only stages feed a single triage surface (the
Security tab) without halting every build on noise.

## Run it

1. Create a **new GitHub repository** (public is easiest for the Security tab).
2. From the repo root, push it:
   ```bash
   git init && git add . && git commit -m "DevSecOps pipeline"
   git branch -M main
   git remote add origin <your-repo-url>
   git push -u origin main
   ```
3. Open the **Actions** tab — the pipeline runs automatically. Stage 4 runs as
   a **matrix over both folders**: the `vulnerable` leg goes **red** (gate
   catching the planted vulnerabilities) while the `fixed` leg goes **green**.
   The `secrets-scan` gate also goes red on `vulnerable/`. That red/green split
   is your headline before/after result.
4. Open the **Security -> Code scanning** tab to see Semgrep + Trivy findings.
5. Download the **ZAP baseline report** artifacts (`...-vulnerable`,
   `...-fixed`) from the run.

### Run the app locally (optional)
```bash
docker compose -f vulnerable/docker-compose.yml up --build   # insecure version
docker compose -f fixed/docker-compose.yml      up --build   # hardened version
# app on http://localhost:5000
```

## The before/after: what `fixed/` remediates

The same Stage-4 gate runs against both folders, so the passing run needs no
separate branch — it is the `fixed` matrix leg. What changed:

- `Dockerfile`: `FROM python:3.12-slim`, add `RUN adduser --disabled-password app && USER app`, replace `ADD . /app` with `COPY . /app`, add a `HEALTHCHECK`.
- `requirements.txt`: bump to patched versions (`requests>=2.32`, `PyYAML>=6.0`, `urllib3>=2.2`, `Jinja2>=3.1`).
- `app.py`: parameterize the SQL query, replace `os.system` with `subprocess.run([...])` (no shell), remove the hardcoded keys, set `debug=False`.
- `docker-compose.yml`: remove `privileged: true` and the hardcoded `SECRET_TOKEN`; add `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`.

Before/after screenshots of the two matrix legs are the strongest evidence in
your write-up.

## Notes
- The pinned `aquasecurity/trivy-action@0.28.0` may need bumping — if a job
  errors with "not found", update to the latest tag on that action's repo.
- `gitleaks-action@v2` is free for personal/public repos.
- Everything runs on GitHub-hosted `ubuntu-latest` runners — no servers, no cost
  on a public repo.
