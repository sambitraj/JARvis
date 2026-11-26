"""Dependency scanning against OSV.dev (aggregates GitHub Advisories / NVD for Maven)."""
import httpx
from . import config

_cache: dict = {}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=30, headers={"User-Agent": "jarvis-ai/1.0"})


async def query_batch(c: httpx.AsyncClient, coords: list[tuple[str, str, str]]) -> list[list[str]]:
    out: list[list[str]] = []
    for i in range(0, len(coords), 100):
        chunk = coords[i:i + 100]
        r = await c.post(f"{config.OSV_URL}/v1/querybatch", json={"queries": [
            {"package": {"name": f"{g}:{a}", "ecosystem": "Maven"}, "version": v} for g, a, v in chunk]})
        r.raise_for_status()
        out += [[v["id"] for v in res.get("vulns", [])] for res in r.json()["results"]]
    return out


async def vuln_detail(c: httpx.AsyncClient, vid: str, g: str, a: str) -> dict:
    if vid not in _cache:
        r = await c.get(f"{config.OSV_URL}/v1/vulns/{vid}")
        r.raise_for_status()
        _cache[vid] = r.json()
    raw, name = _cache[vid], f"{g}:{a}"
    fixed = [ev["fixed"] for aff in raw.get("affected", []) if aff.get("package", {}).get("name") == name
             for rg in aff.get("ranges", []) for ev in rg.get("events", []) if "fixed" in ev]
    sev = ((raw.get("database_specific") or {}).get("severity") or "UNKNOWN").upper()
    sev = "MEDIUM" if sev == "MODERATE" else sev
    aliases = raw.get("aliases", [])
    return {"id": vid, "cve": next((x for x in aliases if x.startswith("CVE-")), None), "severity": sev,
            "summary": raw.get("summary") or (raw.get("details") or "")[:200], "fixed": sorted(set(fixed)),
            "url": f"https://osv.dev/{vid}"}


def worst(vulns: list[dict]) -> str:
    return max((v["severity"] for v in vulns), key=lambda s: SEV_ORDER.get(s, 0), default="UNKNOWN")
