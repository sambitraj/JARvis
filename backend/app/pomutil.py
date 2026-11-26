"""POM parsing and format-preserving updates (string edits, so comments/indentation survive)."""
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from typing import Optional

_NS = re.compile(r"^\{.*?\}")


def _tag(e):
    return _NS.sub("", e.tag)


def _child(e, name):
    if e is None:
        return None
    return next((c for c in e if _tag(c) == name), None)


def _text(e, name) -> Optional[str]:
    c = _child(e, name)
    return c.text.strip() if c is not None and c.text else None


@dataclass
class Dep:
    group: str
    artifact: str
    raw_version: Optional[str]
    version: Optional[str]
    source: str  # literal | property | unresolved
    prop: Optional[str]
    scope: str
    pom_path: str

    def dict(self):
        return asdict(self)


def _subst(val, props, depth=0):
    if val is None or depth > 5:
        return val
    return re.sub(r"\$\{([^}]+)\}", lambda m: _subst(props.get(m.group(1), m.group(0)), props, depth + 1), val)


def parse_pom(xml_text: str, pom_path: str) -> list[Dep]:
    root = ET.fromstring(xml_text)
    props = {_tag(c): (c.text or "").strip() for c in (_child(root, "properties") or [])}
    props["project.version"] = _text(root, "version") or _text(_child(root, "parent"), "version") or ""
    dm = _child(_child(root, "dependencyManagement"), "dependencies")
    managed = {}
    for d in dm or []:
        g, a, v = _text(d, "groupId"), _text(d, "artifactId"), _text(d, "version")
        if g and a and v:
            managed[(g, a)] = v

    out = []
    for container in (_child(root, "dependencies"), dm):
        for d in container or []:
            g, a = _text(d, "groupId"), _text(d, "artifactId")
            if not g or not a:
                continue
            raw = _text(d, "version") or managed.get((g, a))
            scope = _text(d, "scope") or "compile"
            if raw is None:  # inherited from parent/BOM we cannot see
                out.append(Dep(g, a, None, None, "unresolved", None, scope, pom_path))
                continue
            m = re.fullmatch(r"\$\{([^}]+)\}", raw)
            out.append(Dep(g, a, raw, _subst(raw, props), "property" if m else "literal",
                           m.group(1) if m else None, scope, pom_path))
    seen, uniq = set(), []
    for d in out:
        k = (d.group, d.artifact, d.version)
        if k not in seen:
            seen.add(k)
            uniq.append(d)
    return uniq


def apply_update(xml_text: str, group: str, artifact: str, old: str, new: str, prop: Optional[str]) -> tuple[str, bool]:
    """Return (new_xml, changed). Edits the <properties> entry or every matching <dependency> block."""
    if prop:
        pat = re.compile(r"(<%s>\s*)%s(\s*</%s>)" % (re.escape(prop), re.escape(old), re.escape(prop)))
        xml_text, n = pat.subn(lambda m: m.group(1) + new + m.group(2), xml_text)
        return xml_text, n > 0
    changed = False

    def fix(m):
        nonlocal changed
        blk = m.group(0)
        if f"<groupId>{group}</groupId>" in blk and f"<artifactId>{artifact}</artifactId>" in blk:
            nb, n = re.subn(r"(<version>\s*)%s(\s*</version>)" % re.escape(old),
                            lambda x: x.group(1) + new + x.group(2), blk)
            if n:
                changed = True
                return nb
        return blk

    return re.sub(r"<dependency>.*?</dependency>", fix, xml_text, flags=re.S), changed


def _jv(v):
    m = re.fullmatch(r"(?:1\.)?(\d+)", (v or "").strip())
    return int(m.group(1)) if m else None


def detect_java_version(xml_text: str):
    """Best-effort Java version the project targets (8, 11, 17, 21...), or None if unknown."""
    try:
        root = ET.fromstring(xml_text)
        props = {_tag(c): (c.text or "").strip() for c in (_child(root, "properties") or [])}
    except ET.ParseError:
        props = {}
    for k in ("maven.compiler.release", "java.version", "maven.compiler.source", "maven.compiler.target"):
        if _jv(props.get(k)):
            return _jv(props[k])
    m = re.search(r"<release>\s*(\d+)\s*</release>", xml_text) or re.search(r"<source>\s*(?:1\.)?(\d+)\s*</source>", xml_text)
    if m:
        return int(m.group(1))
    m = re.search(r"<artifactId>spring-boot-starter-parent</artifactId>\s*<version>(\d+)\.", xml_text)
    if m:  # Spring Boot 1.x/2.x default to Java 8, 3.x needs 17+
        return 8 if int(m.group(1)) <= 2 else 17
    return None
