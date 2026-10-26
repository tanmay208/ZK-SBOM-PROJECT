"""Test-only environment defaults for isolated backend tests."""

import os


os.environ.setdefault("JWT_SECRET_KEY", "stage-test-jwt-secret-not-for-deployment")
os.environ.setdefault("CERTIFICATE_SECRET_KEY", "stage-test-cert-secret-not-for-deployment")
os.environ.setdefault("DB_PASSWORD", "test-db-password")
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_NAME", "test-db")
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("CRYPTO_PROFILE", "prod")