"""Secure version resolution: lowest stable release that clears every known advisory."""
import re
import xml.etree.ElementTree as ET
import httpx
from . import config, scanner

_PRE = re.compile(r"alpha\d*|beta\d*|rc\d*|cr\d*|m\d+|b\d+|snapshot|milestone|preview|dev|ea|pr\d*", re.I)


def vkey(v: str) -> tuple:
    n = [int(x) for x in re.findall(r"\d+", v)[:4]]
    return tuple(n + [0] * (4 - len(n)))


def is_stable(v: str) -> bool:
    return not any(_PRE.fullmatch(t) for t in re.split(r"[.\-_]", v))


def flavor(v: str):
    """Guava-style build flavor suffix (-jre / -android). A candidate must keep the same flavor as the current version."""
    last = re.split(r"[-_]", v.lower())[-1]
    return last if last in ("jre", "android") else None


def change_type(old: str, new: str) -> str:
    o, n = vkey(old), vkey(new)
    return "major" if n[0] != o[0] else "minor" if n[1] != o[1] else "patch"


async def list_versions(c: httpx.AsyncClient, g: str, a: str) -> list[str]:
    r = await c.get(f"{config.MAVEN_CENTRAL}/{g.replace('.', '/')}/{a}/maven-metadata.xml")
    r.raise_for_status()
    return [e.text.strip() for e in ET.fromstring(r.text).iter("version") if e.text]


def _floor(vuln: dict, cur: str):
    fx = sorted((f for f in vuln["fixed"] if vkey(f) > vkey(cur)), key=vkey)
    same = [f for f in fx if vkey(f)[0] == vkey(cur)[0]]
    return (same or fx or [None])[0]


async def resolve(c: httpx.AsyncClient, g: str, a: str, cur: str, vulns: list[dict]) -> dict:
    """Returns the recommended target (or None) plus `options`: versions the person can pick from a dropdown."""
    versions = await list_versions(c, g, a)
    above = sorted({v for v in versions if is_stable(v) and flavor(v) == flavor(cur) and vkey(v) > vkey(cur)},
                   key=lambda v: (vkey(v), v))
    floors = [f for f in (_floor(v, cur) for v in vulns) if f]
    floor = max(floors, key=vkey) if floors else cur
    cands = [v for v in above if vkey(v) >= vkey(floor)][:80]
    target = None
    for i in range(0, len(cands), 20):
        chunk = cands[i:i + 20]
        res = await scanner.query_batch(c, [(g, a, v) for v in chunk])
        target = next((v for v, ids in zip(chunk, res) if not ids), None)
        if target:
            break
    options = []
    pool = above[:300]
    if pool:
        res = await scanner.query_batch(c, [(g, a, v) for v in pool])
        safe = [v for v, ids in zip(pool, res) if not ids]  # versions with known vulnerabilities are never offered
        safe = list(dict.fromkeys(safe[:75] + safe[-5:]))  # nearest safe versions plus the newest
        options = [{"version": v, "safe": True, "change_type": change_type(cur, v)} for v in safe]
        options.sort(key=lambda o: (vkey(o["version"]), o["version"]), reverse=True)
    return {"target": target, "change_type": change_type(cur, target) if target else None, "options": options}
