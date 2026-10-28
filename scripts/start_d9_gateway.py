#!/usr/bin/env python3
"""
Dedicated D9 Gateway Runner for Port 8080
Authoritative Target: 127.0.0.1:5433 (Database: ZKP_SBOM_LOCAL_DEV, PostgreSQL 16)
Governance: Injects process-scoped environment variables to bypass root .env and protect Port 5432.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# Paths
_repo_root = Path(__file__).resolve().parent.parent
_backend_root = _repo_root / "backend"

# Retrieve container db password dynamically from zkp_sbom_local_dev without exposing it
try:
    raw_env = subprocess.check_output(
        ["docker", "inspect", "zkp_sbom_local_dev", "--format", "{{json .Config.Env}}"],
        text=True,
    )
    env_list = json.loads(raw_env.strip())
    db_pass = None
    for item in env_list:
        if item.startswith("POSTGRES_PASSWORD="):
            db_pass = item.split("=", 1)[1]
            break
except Exception as exc:
    sys.exit(f"FATAL: Unable to inspect docker container zkp_sbom_local_dev: {exc}")

if not db_pass:
    sys.exit("FATAL: POSTGRES_PASSWORD not found in container environment.")

# Inject process-level configuration targeting port 5433 before any application imports
os.environ["ENVIRONMENT"] = "local_dev"
os.environ["DB_HOST"] = "127.0.0.1"
os.environ["DB_PORT"] = "5433"
os.environ["DB_NAME"] = "ZKP_SBOM_LOCAL_DEV"
os.environ["DB_USER"] = "postgres"
os.environ["DB_PASSWORD"] = db_pass
os.environ["DB_SSL_MODE"] = "disable"
os.environ["CRYPTO_PROFILE"] = "prod"
os.environ["JWT_SECRET_KEY"] = "local_dev_jwt_secret_key_32bytes_minimum_length_ok"
os.environ["CERTIFICATE_SECRET_KEY"] = "local_dev_cert_secret_key_32bytes_minimum_length_ok"
os.environ["CERTIFICATE_ACTIVE_KID"] = "v1"
os.environ["CERTIFICATE_SECRET_KEYS"] = json.dumps({"v1": "local_dev_cert_secret_key_32bytes_minimum_length_ok"})

if str(_backend_root) not in sys.path:
    sys.path.insert(0, str(_backend_root))

if __name__ == "__main__":
    import uvicorn
    from shared.config import get_db_settings, validate_config

    settings = get_db_settings()
    validate_config(settings)
    print(
        f"[*] D9 Gateway initializing on 127.0.0.1:8080 targeting {settings.host}:{settings.port}/{settings.name} (SSL: {settings.normalized_ssl_mode})...",
        flush=True,
    )
    uvicorn.run("verification_service.app.main:app", host="127.0.0.1", port=8080, log_level="info")
