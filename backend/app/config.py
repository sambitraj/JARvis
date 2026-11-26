import os
from pathlib import Path

WORK_DIR = Path(os.getenv("JARVIS_WORK_DIR", "./workdir")).resolve()
WORK_DIR.mkdir(parents=True, exist_ok=True)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
VALIDATION_MODE = os.getenv("VALIDATION_MODE", "docker")  # docker | local | skip
# empty = auto-detect the Java version from the project's pom.xml and pick a matching Maven image
MAVEN_IMAGE = os.getenv("MAVEN_IMAGE", "")
VALIDATION_SKIP_TESTS = os.getenv("VALIDATION_SKIP_TESTS", "0") == "1"  # compile-only check
VALIDATION_TIMEOUT = int(os.getenv("VALIDATION_TIMEOUT", "900"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
OSV_URL = "https://api.osv.dev"
MAVEN_CENTRAL = "https://repo1.maven.org/maven2"
MAX_UPLOAD_MB = 300

MAX_REPO_MB = int(os.getenv("MAX_REPO_MB", "300"))
