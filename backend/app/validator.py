"""Isolated build/test validation. Always runs on a throw-away copy of the project."""
import asyncio
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from . import config, pomutil


def mvn_args() -> list[str]:
    a = ["mvn", "-B", "-ntp", "clean", "verify"]
    return a + ["-DskipTests"] if config.VALIDATION_SKIP_TESTS else a


def pick_image(project_dir: Path) -> tuple[str, str]:
    """Choose the Maven+JDK image: explicit MAVEN_IMAGE wins, otherwise match the project's Java version."""
    if config.MAVEN_IMAGE:
        return config.MAVEN_IMAGE, f"Using image {config.MAVEN_IMAGE} (set by MAVEN_IMAGE)."
    pom = project_dir / "pom.xml"
    n = pomutil.detect_java_version(pom.read_text(encoding="utf-8", errors="ignore")) if pom.exists() else None
    shown = f"Java {n} detected" if n else "Java version not detected, defaulting to 17"
    for v in (8, 11, 17, 21, 22, 23, 24, 25):  # smallest available JDK that is >= what the project targets
        if (n or 17) <= v:
            return f"maven:3.9-eclipse-temurin-{v}", f"Using image maven:3.9-eclipse-temurin-{v} ({shown})."
    return "maven:3.9-eclipse-temurin-25", f"Using image maven:3.9-eclipse-temurin-25 ({shown}; newest known image)."


def _run_sync(cmd: list[str], cwd, timeout: int, container: str | None):
    """Blocking subprocess call. Runs in a worker thread so it also works on Windows event loops."""
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, errors="replace",
                           timeout=timeout, stdin=subprocess.DEVNULL)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        if container:  # killing the docker CLI does not stop the container
            subprocess.run(["docker", "rm", "-f", container], capture_output=True)
        return None, "Build timed out."


async def run(project_dir: Path, image: str | None = None) -> dict:
    mode = config.VALIDATION_MODE
    if mode == "skip":
        return {"status": "skipped", "mode": mode, "duration": 0, "log_tail": "Validation disabled (VALIDATION_MODE=skip)."}
    container, note = None, ""
    if mode == "docker":
        if not shutil.which("docker"):
            return {"status": "error", "mode": mode, "duration": 0, "log_tail": "docker CLI not found on PATH."}
        if image:
            why = f"Using image {image} (chosen after the first image failed to build the project)."
        else:
            image, why = pick_image(project_dir)
        note = f"[JARvis] {why}\n"
        container = f"jarvis-{uuid.uuid4().hex[:8]}"
        cmd = ["docker", "run", "--rm", "--name", container, "--cpus", "2", "--memory", "3g", "--pids-limit", "1024",
               "--security-opt", "no-new-privileges", "-v", f"{project_dir}:/workspace", "-w", "/workspace",
               image, *mvn_args()]
        cwd = None
    else:
        if not shutil.which("mvn"):
            return {"status": "error", "mode": mode, "duration": 0, "log_tail": "mvn not found on PATH."}
        cmd, cwd = [shutil.which("mvn"), *mvn_args()[1:]], str(project_dir)  # full path: Windows needs mvn.cmd resolved
    t0 = time.time()
    try:
        code, text = await asyncio.to_thread(_run_sync, cmd, cwd, config.VALIDATION_TIMEOUT, container)
    except Exception as e:  # e.g. docker not running / not permitted
        return {"status": "error", "mode": mode, "duration": round(time.time() - t0, 1),
                "log_tail": f"Could not start build: {type(e).__name__}: {e}"}
    status = "passed" if code == 0 else "failed"
    if mode == "docker" and code is not None and code != 0 and "daemon" in text.lower() and "docker" in text.lower()[:400]:
        status = "error"  # Docker Desktop not running etc.
    return {"status": status, "mode": mode, "image": image if mode == "docker" else None, "duration": round(time.time() - t0, 1),
            "log_tail": note + "\n".join(text.splitlines()[-120:])}