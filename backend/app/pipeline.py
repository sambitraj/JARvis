"""Job orchestration: scan -> resolve -> AI impact -> controlled auto-fix -> isolated validation -> report."""
import asyncio
import re
import httpx
import shutil
import time
import uuid
import zipfile
from pathlib import Path

from . import config, scanner, resolver, pomutil, ai_analyzer, validator

JOBS: dict[str, dict] = {}


def log(job, msg):
    job["events"].append({"t": time.strftime("%H:%M:%S"), "msg": msg})


def job_dir(jid) -> Path:
    return config.WORK_DIR / jid


def new_job(filename: str) -> dict:
    jid = uuid.uuid4().hex[:10]
    job = {"id": jid, "filename": filename, "status": "queued", "stage": "upload", "events": [], "findings": [],
           "summary": {}, "remediation": None, "error": None, "created": time.strftime("%Y-%m-%d %H:%M:%S")}
    JOBS[jid] = job
    return job


def ingest(job: dict, filename: str, data: bytes):
    src = job_dir(job["id"]) / "source"
    src.mkdir(parents=True, exist_ok=True)
    if filename.lower().endswith(".zip"):
        tmp = job_dir(job["id"]) / "upload.zip"
        tmp.write_bytes(data)
        with zipfile.ZipFile(tmp) as z:
            total = 0
            for m in z.infolist():
                target = (src / m.filename).resolve()
                if not str(target).startswith(str(src.resolve())):
                    raise ValueError("Unsafe path in zip")
                total += m.file_size
                if total > config.MAX_UPLOAD_MB * 10 * 1024 * 1024:
                    raise ValueError("Archive too large when extracted")
            z.extractall(src)
    elif filename.lower().endswith("pom.xml") or filename.lower().endswith(".xml"):
        (src / "pom.xml").write_bytes(data)
    else:
        raise ValueError("Upload a .zip of the project or a pom.xml")
    # GitHub/zip archives usually wrap everything in one top-level folder: flatten it so pom.xml sits at the root
    entries = list(src.iterdir())
    if len(entries) == 1 and entries[0].is_dir() and not (src / "pom.xml").exists():
        inner = entries[0]
        for child in list(inner.iterdir()):
            shutil.move(str(child), str(src / child.name))
        inner.rmdir()
    if not find_poms(src):
        raise ValueError("No pom.xml found (JARvis currently supports Maven projects only)")


GH_RE = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


async def fetch_github(url: str) -> tuple[str, bytes]:
    m = GH_RE.match(url.strip())
    if not m:
        raise ValueError("Enter a public GitHub URL like https://github.com/owner/repo")
    owner, repo = m.groups()
    async with httpx.AsyncClient(follow_redirects=True, timeout=90) as c:
        for ref in ("HEAD", "main", "master"):
            r = await c.get(f"https://github.com/{owner}/{repo}/archive/{ref}.zip")
            if r.status_code == 200:
                size_mb = len(r.content) / (1024 * 1024)
                if size_mb > config.MAX_REPO_MB:
                    raise ValueError(f"Repository is too large ({size_mb:.0f} MB, limit {config.MAX_REPO_MB} MB). Set MAX_REPO_MB to raise the limit.")
                return f"{owner}/{repo}", r.content
    raise ValueError("Could not download that repository. Is it public?")


def find_poms(src: Path) -> list[Path]:
    return sorted((p for p in src.rglob("pom.xml") if "target" not in p.parts), key=lambda p: len(p.parts))


def _read_poms(src: Path) -> dict[str, str]:
    return {str(p.relative_to(src)): p.read_text(encoding="utf-8") for p in find_poms(src)}


# ------------------------------------------------------------------ scan
async def run_scan(jid: str):
    job = JOBS[jid]
    src = job_dir(jid) / "source"
    try:
        job.update(status="scanning", stage="scan")
        poms = _read_poms(src)
        deps = []
        for path, xml in poms.items():
            try:
                deps += pomutil.parse_pom(xml, path)
            except Exception as e:
                log(job, f"Could not parse {path}: {e}")
        known = [d for d in deps if d.version]
        log(job, f"Parsed {len(poms)} POM(s), {len(known)} dependencies with resolvable versions "
                 f"({len(deps) - len(known)} inherit versions from a parent/BOM and were skipped).")
        async with scanner.client() as c:
            res = await scanner.query_batch(c, [(d.group, d.artifact, d.version) for d in known])
            findings = []
            for d, ids in zip(known, res):
                if not ids:
                    continue
                vulns = [await scanner.vuln_detail(c, i, d.group, d.artifact) for i in ids]
                findings.append({"id": f"f{len(findings) + 1}", "pom_path": d.pom_path, "group": d.group, "artifact": d.artifact,
                                 "current": d.version, "source": d.source, "prop": d.prop, "scope": d.scope, "vulns": vulns,
                                 "severity": scanner.worst(vulns), "target": None, "change_type": None, "analysis": None,
                                 "auto_eligible": False, "policy_reason": "", "status": "pending"})
            log(job, f"{len(findings)} vulnerable dependencies found.")
            job["stage"] = "resolve"
            for f in findings:
                try:
                    r = await resolver.resolve(c, f["group"], f["artifact"], f["current"], f["vulns"])
                except Exception as e:
                    r = None
                    log(job, f"Version lookup failed for {f['group']}:{f['artifact']}: {e}")
                f["options"] = r["options"] if r else []
                if r and r["target"]:
                    f.update(target=r["target"], change_type=r["change_type"])
                else:
                    f.update(status="no_fix", policy_reason="No stable release without known vulnerabilities was found.")
                f["suggested"], f["suggested_type"] = f["target"], f["change_type"]
        job["stage"] = "ai"
        fixable = [f for f in findings if f["target"]]
        log(job, f"Secure versions resolved for {len(fixable)}/{len(findings)}. Running AI impact analysis...")
        sem = asyncio.Semaphore(4)

        async def _an(f):
            async with sem:
                f["analysis"] = await ai_analyzer.analyze(f, src)
        await asyncio.gather(*[_an(f) for f in fixable])
        for f in fixable:  # controlled auto-fix policy
            if f["change_type"] == "major":
                f["policy_reason"] = "Major version bump: needs human approval."
            elif f["analysis"]["risk_level"] == "high":
                f["policy_reason"] = "AI flagged high upgrade risk: needs human approval."
            elif f["source"] == "unresolved":
                f["policy_reason"] = "Version not editable in this POM."
            else:
                f["auto_eligible"] = True
                f["policy_reason"] = f"{f['change_type'].capitalize()} upgrade within the same major, risk {f['analysis']['risk_level']}."
        job["findings"] = findings
        job["summary"] = _summary(job, len(known))
        job.update(status="scanned", stage="review")
        log(job, "Scan complete. Review the plan, then run controlled remediation.")
    except Exception as e:
        job.update(status="failed", error=f"{type(e).__name__}: {e}")
        log(job, f"Scan failed: {type(e).__name__}: {e!r}")


def _summary(job, total):
    f = job["findings"]
    sev = {}
    for x in f:
        sev[x["severity"]] = sev.get(x["severity"], 0) + 1
    return {"dependencies_scanned": total, "vulnerable": len(f), "fixable": sum(1 for x in f if x["target"]),
            "auto_eligible": sum(1 for x in f if x["auto_eligible"]), "needs_approval": sum(1 for x in f if x["target"] and not x["auto_eligible"]),
            "severity": sev, "fixed": sum(1 for x in f if x["status"] == "fixed")}


# ------------------------------------------------------------------ remediate
def _why(text: str) -> str:
    errs = []
    for line in text.splitlines():
        s = line.replace("[ERROR]", "").strip()
        if "[ERROR]" in line and s and s not in errs and not s.startswith(("-> [Help", "Re-run", "For more", "To see")):
            errs.append(s[:220])
    return " | ".join(errs[:3]) or "see the build log in the validation panel"


def _apply(poms: dict[str, str], items: list[dict]) -> dict[str, str]:
    out = dict(poms)
    for f in items:
        out[f["pom_path"]], ok = pomutil.apply_update(out[f["pom_path"]], f["group"], f["artifact"], f["current"], f["target"], f["prop"])
        if not ok:
            raise ValueError(f"Could not locate version of {f['group']}:{f['artifact']} in {f['pom_path']}")
    return out


async def _validate(jid: str, poms: dict[str, str], label: str, image: str | None = None) -> dict:
    vdir = job_dir(jid) / "validate"
    shutil.rmtree(vdir, ignore_errors=True)
    shutil.copytree(job_dir(jid) / "source", vdir, ignore=shutil.ignore_patterns("target", ".git"))
    for path, xml in poms.items():
        (vdir / path).write_text(xml, encoding="utf-8")
    res = await validator.run(vdir, image or JOBS[jid].get("image"))
    res["label"] = label
    shutil.rmtree(vdir, ignore_errors=True)
    return res


async def _find_working_image(job: dict, jid: str, original: dict, base: dict, validations: list):
    """If the original project does not build, try other JDK versions (old Lombok/Spring Boot break on new Java)."""
    if config.VALIDATION_MODE != "docker" or config.MAVEN_IMAGE:
        return None
    tried = {base.get("image")}
    for v in (17, 11, 8, 21):
        img = f"maven:3.9-eclipse-temurin-{v}"
        if img in tried:
            continue
        log(job, f"Trying the original project on {img}...")
        r = await _validate(jid, original, f"baseline on {img}", image=img)
        validations.append(r)
        tried.add(img)
        if r["status"] == "failed":
            log(job, f"Failed on {img}: " + _why(r["log_tail"]))
        if r["status"] == "passed":
            job["image"] = img
            return img
    return None


async def _reanalyze(f: dict, src: Path):
    f["analysis"] = await ai_analyzer.analyze(f, src)


async def run_remediation(jid: str, approved: list[str], only: list[str] | None = None, overrides: dict[str, str] | None = None):
    job = JOBS[jid]
    src = job_dir(jid) / "source"
    try:
        job.update(status="remediating", stage="remediate")
        original = _read_poms(src)
        for f in job["findings"]:  # start from the recommended version, then apply any version picked in the dropdown
            f["target"], f["change_type"], f["chosen"] = f.get("suggested"), f.get("suggested_type"), False
            v = (overrides or {}).get(f["id"])
            if v and any(o["version"] == v for o in f.get("options", [])):  # only versions we offered are accepted
                f["target"], f["change_type"], f["chosen"] = v, resolver.change_type(f["current"], v), True
        for f in job["findings"]:
            f["status"] = "pending" if f["target"] else "no_fix"
        if only:  # manual mode: the person picked exactly these, which counts as approval (even for major upgrades)
            selected = [f for f in job["findings"] if f["target"] and f["id"] in only]
            log(job, f"Manual fix: {len(selected)} selected dependency(ies); all others are left untouched.")
        else:
            selected = [f for f in job["findings"] if f["target"] and (f["auto_eligible"] or f["id"] in approved)]
        for f in job["findings"]:
            if f["target"] and f not in selected:
                f["status"] = "not_selected" if only else "awaiting_approval"
        chosen = [f for f in selected if f.get("chosen")]
        if chosen:
            log(job, f"Manual version choice for {len(chosen)} dependency(ies): " + ", ".join(f"{f['artifact']} {f['target']}" for f in chosen))
            await asyncio.gather(*[_reanalyze(f, src) for f in chosen])
        validations, accepted, current = [], [], dict(original)
        if selected:
            job["stage"] = "validate"
            log(job, f"Applying {len(selected)} fix(es) in an isolated copy and running build + tests ({config.VALIDATION_MODE})...")
            res = await _validate(jid, _apply(original, selected), "batch: all selected fixes")
            validations.append(res)
            if res["status"] == "error":
                raise RuntimeError("Validation could not run: " + res["log_tail"][-300:])
            one_by_one = False
            if res["status"] in ("passed", "skipped"):
                accepted, current = selected, _apply(original, selected)
            else:
                log(job, "Batch failed. Checking whether the baseline already fails...")
                base = await _validate(jid, original, "baseline (no changes)")
                validations.append(base)
                if base["status"] == "failed":
                    log(job, "Baseline build already fails. Why: " + _why(base["log_tail"]))
                    img = await _find_working_image(job, jid, original, base, validations)
                    if img:
                        log(job, f"The original project builds on {img}. Re-testing the fixes on that image...")
                        res = await _validate(jid, _apply(original, selected), f"batch retry on {img}")
                        validations.append(res)
                        if res["status"] in ("passed", "skipped"):
                            accepted, current = selected, _apply(original, selected)
                        else:
                            one_by_one = True
                    else:
                        for f in selected:
                            f["status"] = "baseline_failing"
                        if config.VALIDATION_MODE == "docker" and not config.MAVEN_IMAGE:
                            log(job, "No Java version let the original project build, so nothing was changed.")
                        else:
                            log(job, "The original project does not build with the Java on this setup, so nothing was changed.")
                else:
                    one_by_one = True
            if one_by_one:
                log(job, "Falling back to one-by-one validation to isolate the breaking upgrade.")
                for f in selected:
                    trial = _apply(current, [f])
                    r = await _validate(jid, trial, f"{f['group']}:{f['artifact']} {f['current']} -> {f['target']}")
                    validations.append(r)
                    if r["status"] in ("passed", "skipped"):
                        accepted.append(f)
                        current = trial
                    else:
                        f["status"] = "rejected_build_failed"
                        log(job, f"Rejected {f['artifact']} {f['target']}: build/tests failed.")
        unvalidated = bool(validations) and all(v["status"] == "skipped" for v in validations if v["label"] != "baseline (no changes)")
        for f in accepted:
            f["status"] = "fixed_unvalidated" if unvalidated else "fixed"
        job["findings"] = job["findings"]
        out = job_dir(jid) / "remediated"
        shutil.rmtree(out, ignore_errors=True)
        shutil.copytree(src, out)
        for path, xml in current.items():
            (out / path).write_text(xml, encoding="utf-8")
        shutil.make_archive(str(job_dir(jid) / "remediated-project"), "zip", out)
        job["remediation"] = {"validations": validations, "validation_mode": config.VALIDATION_MODE,
                              "applied": [f["id"] for f in accepted], "finished": time.strftime("%Y-%m-%d %H:%M:%S")}
        job["summary"] = _summary(job, job["summary"].get("dependencies_scanned", 0))
        job.update(status="completed", stage="report")
        log(job, f"Done: {len(accepted)} fix(es) applied. Reports are ready.")
    except Exception as e:
        job.update(status="failed", error=f"{type(e).__name__}: {e}")
        log(job, f"Remediation failed: {type(e).__name__}: {e!r}")
