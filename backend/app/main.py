import asyncio
from fastapi import FastAPI, File, HTTPException, UploadFile, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

from . import config, pipeline, reports

app = FastAPI(title="JARvis AI", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=config.CORS_ORIGINS, allow_methods=["*"], allow_headers=["*"])


class GithubBody(BaseModel):
    url: str


class RemediateBody(BaseModel):
    approved_ids: list[str] = []
    only_ids: list[str] = []  # manual mode: fix only these findings
    overrides: dict[str, str] = {}  # finding id -> version picked in the dropdown


def _job(jid):
    if jid not in pipeline.JOBS:
        raise HTTPException(404, "Job not found")
    return pipeline.JOBS[jid]


@app.get("/api/health")
def health():
    return {"ok": True, "openai_configured": bool(config.OPENAI_API_KEY), "model": config.OPENAI_MODEL,
            "validation_mode": config.VALIDATION_MODE}


@app.post("/api/jobs")
async def create_job(bg: BackgroundTasks, file: UploadFile = File(...)):
    data = await file.read()
    if len(data) > config.MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, "File too large")
    job = pipeline.new_job(file.filename or "project")
    try:
        pipeline.ingest(job, file.filename or "", data)
    except Exception as e:
        pipeline.JOBS.pop(job["id"], None)
        raise HTTPException(400, str(e))
    bg.add_task(pipeline.run_scan, job["id"])
    return {"id": job["id"]}


@app.post("/api/jobs/github")
async def create_job_from_github(body: GithubBody, bg: BackgroundTasks):
    try:
        name, data = await pipeline.fetch_github(body.url)
        job = pipeline.new_job(name)
        pipeline.ingest(job, "repo.zip", data)
    except Exception as e:
        raise HTTPException(400, str(e))
    bg.add_task(pipeline.run_scan, job["id"])
    return {"id": job["id"]}


@app.get("/api/jobs/{jid}")
def get_job(jid: str):
    return _job(jid)


@app.post("/api/jobs/{jid}/remediate")
async def remediate(jid: str, body: RemediateBody, bg: BackgroundTasks):
    job = _job(jid)
    if job["status"] not in ("scanned", "completed"):
        raise HTTPException(409, f"Job is {job['status']}")
    bg.add_task(pipeline.run_remediation, jid, body.approved_ids, body.only_ids, body.overrides)
    job["status"] = "remediating"
    return {"ok": True}


@app.get("/api/jobs/{jid}/reports/{fmt}")
def report(jid: str, fmt: str):
    job = _job(jid)
    if fmt == "json":
        body, mt = reports.to_json(job), "application/json"
    elif fmt == "md":
        body, mt = reports.to_markdown(job), "text/markdown"
    elif fmt == "html":
        body, mt = reports.to_html(job), "text/html"
    else:
        raise HTTPException(404, "Unknown format")
    return Response(body, media_type=mt, headers={"Content-Disposition": f'attachment; filename="jarvis-report-{jid}.{fmt}"'})


@app.get("/api/jobs/{jid}/downloads/{kind}")
def download(jid: str, kind: str):
    job = _job(jid)
    base = pipeline.job_dir(jid)
    if kind not in ("project", "pom", "full"):
        raise HTTPException(404, "Unknown download")
    if not (base / "remediated").exists():
        raise HTTPException(404, "Run remediation first")
    if kind == "full":
        p, name = reports.full_package(job, base), "jarvis-full-package.zip"
    elif kind == "project":
        p, name = base / "remediated-project.zip", "remediated-project.zip"
    else:
        p, name = base / "remediated" / "pom.xml", "pom.xml"
    if not p.exists():
        raise HTTPException(404, "Run remediation first")
    return FileResponse(p, filename=name)
