import html
import json
import zipfile
from pathlib import Path

STATUS = {"fixed": "Fixed & validated", "fixed_unvalidated": "Fixed (build not validated)", "pending": "Pending",
          "awaiting_approval": "Awaiting approval", "no_fix": "No safe version", "rejected_build_failed": "Rejected: build/tests failed",
          "baseline_failing": "Skipped: baseline build already failing", "not_selected": "Not selected (manual mode)"}


def build(job: dict) -> dict:
    return {"report_title": "JARvis AI Remediation Report", "job_id": job["id"], "project": job["filename"],
            "created": job["created"], "summary": job["summary"], "findings": job["findings"],
            "validation": (job.get("remediation") or {}).get("validations", []), "events": job["events"]}


def to_markdown(job: dict) -> str:
    r, s = build(job), job["summary"]
    L = [f"# JARvis AI Remediation Report", f"Project: **{job['filename']}**  |  Job: `{job['id']}`  |  {job['created']}", "",
         "## Summary", f"- Dependencies scanned: {s.get('dependencies_scanned', 0)}", f"- Vulnerable: {s.get('vulnerable', 0)}",
         f"- Fixed: {s.get('fixed', 0)}", f"- Needing approval: {s.get('needs_approval', 0)}", f"- Severity: {s.get('severity', {})}", "",
         "## Findings"]
    for f in job["findings"]:
        a = f.get("analysis") or {}
        L += [f"### {f['group']}:{f['artifact']} ({f['pom_path']})",
              f"- Current: `{f['current']}` -> Target: `{f['target'] or 'n/a'}` ({f['change_type'] or '-'}){' (chosen manually)' if f.get('chosen') else ''}",
              f"- Severity: {f['severity']}  |  Status: {STATUS.get(f['status'], f['status'])}", f"- Policy: {f['policy_reason']}",
              "- Vulnerabilities: " + ", ".join(f"{v['cve'] or v['id']} ({v['severity']})" for v in f["vulns"])]
        if a:
            L += [f"- AI impact ({a.get('source')}): risk **{a.get('risk_level')}**. {a.get('summary', '')}"]
            L += [f"  - Breaking: {b}" for b in a.get("breaking_changes", [])]
            L += [f"  - `{x.get('file')}`: {x.get('reason')} -> {x.get('suggested_change')}" for x in a.get("affected_files", [])]
        L.append("")
    L.append("## Build & test validation")
    for v in r["validation"]:
        L.append(f"- {v['label']}: **{v['status']}** ({v['mode']}, {v['duration']}s)")
    return "\n".join(L)


def to_html(job: dict) -> str:
    e = html.escape
    rows = ""
    for f in job["findings"]:
        a = f.get("analysis") or {}
        rows += (f"<tr><td>{e(f['group'])}:{e(f['artifact'])}</td><td>{e(f['current'])}</td><td>{e(f['target'] or '-')}</td>"
                 f"<td>{e(f['severity'])}</td><td>{e(STATUS.get(f['status'], f['status']))}</td>"
                 f"<td>{e(', '.join(v['cve'] or v['id'] for v in f['vulns']))}</td><td>{e(a.get('risk_level', '-'))}: {e(a.get('summary', ''))}</td></tr>")
    val = "".join(f"<li>{e(v['label'])}: <b>{e(v['status'])}</b> ({e(v['mode'])}, {v['duration']}s)</li>" for v in build(job)["validation"])
    s = job["summary"]
    return f"""<!doctype html><meta charset=utf-8><title>JARvis report {e(job['id'])}</title>
<style>body{{font:15px system-ui;margin:2rem auto;max-width:1100px;color:#14232b}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #d5dbd9;padding:6px 8px;text-align:left;vertical-align:top;font-size:13px}}th{{background:#eef2f1}}</style>
<h1>JARvis AI Remediation Report</h1><p>Project <b>{e(job['filename'])}</b> &middot; job {e(job['id'])} &middot; {e(job['created'])}</p>
<p>Scanned {s.get('dependencies_scanned', 0)} &middot; vulnerable {s.get('vulnerable', 0)} &middot; fixed {s.get('fixed', 0)} &middot; awaiting approval {s.get('needs_approval', 0)}</p>
<table><tr><th>Dependency</th><th>Current</th><th>Target</th><th>Severity</th><th>Status</th><th>Advisories</th><th>AI impact</th></tr>{rows}</table>
<h2>Build &amp; test validation</h2><ul>{val}</ul>"""


def to_json(job: dict) -> str:
    return json.dumps(build(job), indent=2)


SKIP_DIRS = {"target", ".git", "node_modules", "__pycache__"}


def full_package(job: dict, base: Path) -> Path:
    """One zip with everything: the remediated project, all three reports, and the original pom.xml files as a backup."""
    rem, src = base / "remediated", base / "source"
    out = base / "full-package.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(rem.rglob("*")):
            if p.is_file() and not SKIP_DIRS & set(p.relative_to(rem).parts):
                z.write(p, f"project/{p.relative_to(rem).as_posix()}")
        z.writestr("reports/jarvis-report.html", to_html(job))
        z.writestr("reports/jarvis-report.md", to_markdown(job))
        z.writestr("reports/jarvis-report.json", to_json(job))
        for pom in sorted(src.rglob("pom.xml")):
            if not SKIP_DIRS & set(pom.relative_to(src).parts):
                z.write(pom, f"original-poms/{pom.relative_to(src).as_posix()}")
    return out
