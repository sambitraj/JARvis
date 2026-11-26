# JARvis AI: Java dependency vulnerability remediation

React + Tailwind frontend, FastAPI backend, OpenAI for code-impact analysis.

## Run

```bash
# backend
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # set OPENAI_API_KEY; VALIDATION_MODE=docker needs Docker, local needs Maven
set -a; source .env; set +a
uvicorn app.main:app --reload --port 8000

# frontend (new terminal)
cd frontend && npm install && npm run dev      # http://localhost:5173
```
Try it with `sample-project/` (zip it, or upload its `pom.xml`).

## Pipeline

1. **Scan**: parses every `pom.xml` (literals, `${properties}`, dependencyManagement) and queries OSV.dev (Maven ecosystem).
2. **Secure version resolution**: reads Maven Central metadata, takes stable releases at or above each advisory's fixed version (same major preferred), and picks the lowest one OSV reports as clean.
3. **AI code-impact**: finds Java files importing the library and asks OpenAI for breaking changes, affected files and a risk level. Advisory only; code is never rewritten. Falls back to a rule-based estimate without a key.
4. **Controlled auto-fix policy**: auto-apply patch/minor, same major, AI risk below high. Major or high-risk changes need explicit approval in the UI.
5. **Isolated validation**: changes go into a throw-away copy and run `mvn clean verify` in a resource-limited Docker container (or local Maven). A failed batch is checked against the baseline, then retried one dependency at a time; breaking upgrades are rejected.
6. **Reports**: HTML, Markdown, JSON, plus the updated `pom.xml` and a remediated project zip.

## Limits

- Direct dependencies only; versions inherited from an external parent/BOM are listed as skipped.
- Job state is in memory (restart clears it). Add auth before exposing this beyond localhost; uploaded code is sent to OpenAI only as import lines and short usage snippets.
- Docker validation needs network access to Maven Central for dependencies.
