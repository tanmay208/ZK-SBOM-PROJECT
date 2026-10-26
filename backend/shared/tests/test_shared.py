"""
Tests for the shared backend library.
"""

import sys
import os

# Ensure shared is importable from the test runner
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def test_config_defaults():
    """ServiceSettings can be created with just a name."""
    from shared.config import get_settings

    settings = get_settings("test_service")
    assert settings.service_name == "test_service"
    assert settings.log_level == "INFO"


def test_db_settings_url_format():
    """DatabaseSettings.url produces a valid postgresql+psycopg2 connection string."""
    from shared.config import DatabaseSettings

    db = DatabaseSettings()
    assert db.url.startswith("postgresql+psycopg2://")
    assert db.name in db.url


class TestDatabaseSettingsUrlAndTLS:
    """Gate 5E-PRE: Comprehensive URL safety and TLS configuration tests."""

    def test_default_credentials_and_ssl_mode(self):
        """1. Ordinary existing credentials and default SSL behavior."""
        from shared.config import DatabaseSettings

        db = DatabaseSettings(host="localhost", port=5432, user="postgres", password="secret_password", name="ZKP_SBOM")
        assert db.url == "postgresql+psycopg2://postgres:secret_password@localhost:5432/ZKP_SBOM?sslmode=require"
        assert db.connect_args == {"sslmode": "require"}
        assert "secret_password" not in db.safe_url
        assert "****" in db.safe_url

    def test_special_characters_in_username(self):
        """2. Usernames containing @, :, /, %, +, spaces, and Unicode."""
        from sqlalchemy.engine import make_url
        from shared.config import DatabaseSettings

        complex_user = "üser@sub.domain:tag/path+extra%20name"
        db = DatabaseSettings(user=complex_user, password="simple_password")
        parsed = make_url(db.url)
        assert parsed.username == complex_user

    def test_special_characters_in_password(self):
        """3. Passwords containing @, :, /, %, +, spaces, and Unicode."""
        from sqlalchemy.engine import make_url
        from shared.config import DatabaseSettings

        complex_pass = "p@ss:w/ord+1 %🔒"
        db = DatabaseSettings(user="simple_user", password=complex_pass)
        parsed = make_url(db.url)
        assert parsed.password == complex_pass

    def test_url_round_trip_with_all_special_characters(self):
        """4. URL parsing round-tripping to original credentials."""
        from sqlalchemy.engine import make_url
        from shared.config import DatabaseSettings

        complex_user = "üser@pooler:5432/test+extra %"
        complex_pass = "p@ss:w/ord+1 %🔒#special"
        db = DatabaseSettings(
            host="db.staging.example.com",
            port=6543,
            user=complex_user,
            password=complex_pass,
            name="ZKP_SBOM_STAGING",
        )
        parsed = make_url(db.url)
        assert parsed.username == complex_user
        assert parsed.password == complex_pass
        assert parsed.host == "db.staging.example.com"
        assert parsed.port == 6543
        assert parsed.database == "ZKP_SBOM_STAGING"

    def test_valid_and_invalid_ssl_modes(self):
        """5. Valid SSL modes and rejection of invalid modes."""
        import pytest
        from shared.config import ConfigurationError, DatabaseSettings

        for mode in ("disable", "allow", "prefer", "require"):
            db = DatabaseSettings(ssl_mode=mode)
            assert db.ssl_mode == mode
            assert db.connect_args["sslmode"] == mode

        # Invalid modes fail closed
        for bad_mode in ("invalid", "none", "no-ssl", "verify", ""):
            db = DatabaseSettings(ssl_mode=bad_mode)
            with pytest.raises(ConfigurationError, match="Invalid DB_SSL_MODE"):
                _ = db.url
            with pytest.raises(ConfigurationError, match="Invalid DB_SSL_MODE"):
                _ = db.connect_args

    def test_ssl_mode_normalization_uppercase_and_whitespace(self, tmp_path):
        """5b. Valid SSL modes with uppercase characters and whitespace are normalized."""
        import pytest
        from sqlalchemy.engine import make_url
        from shared.config import ConfigurationError, DatabaseSettings

        # Valid mode with uppercase and surrounding whitespace
        db_req = DatabaseSettings(ssl_mode="  REQUIRE  ")
        assert db_req.normalized_ssl_mode == "require"
        assert db_req.connect_args["sslmode"] == "require"
        parsed_req = make_url(db_req.url)
        assert parsed_req.query["sslmode"] == "require"

        # Verifying mode with whitespace, uppercase, and valid cert
        valid_cert = tmp_path / "valid_ca.crt"
        valid_cert.write_text("CERT DATA")
        db_vf = DatabaseSettings(ssl_mode="\tVerify-Full \n", ssl_root_cert=str(valid_cert))
        assert db_vf.normalized_ssl_mode == "verify-full"
        assert db_vf.connect_args["sslmode"] == "verify-full"
        parsed_vf = make_url(db_vf.url)
        assert parsed_vf.query["sslmode"] == "verify-full"
        assert parsed_vf.query["sslrootcert"] == str(valid_cert)

        # Verifying mode with whitespace and missing CA still fails closed
        db_missing = DatabaseSettings(ssl_mode="  VERIFY-CA  ", ssl_root_cert=None)
        with pytest.raises(ConfigurationError, match="DB_SSL_ROOT_CERT is required"):
            _ = db_missing.url

        # Unsupported modes with whitespace still fail closed
        for bad in ("  invalid  ", "  none\n", "\trequire-all "):
            db_bad = DatabaseSettings(ssl_mode=bad)
            with pytest.raises(ConfigurationError, match="Invalid DB_SSL_MODE"):
                _ = db_bad.url
            with pytest.raises(ConfigurationError, match="Invalid DB_SSL_MODE"):
                _ = db_bad.connect_args

    def test_missing_root_cert_with_verify_modes(self):
        """6. Missing DB_SSL_ROOT_CERT with verify-ca or verify-full."""
        import pytest
        from shared.config import ConfigurationError, DatabaseSettings

        for mode in ("verify-ca", "verify-full"):
            for empty_val in (None, "", "   "):
                db = DatabaseSettings(ssl_mode=mode, ssl_root_cert=empty_val)
                with pytest.raises(ConfigurationError, match="DB_SSL_ROOT_CERT is required"):
                    _ = db.url

    def test_invalid_ca_paths(self, tmp_path, monkeypatch):
        """7. Missing, unreadable, empty, or non-regular CA paths."""
        import pytest
        from shared.config import ConfigurationError, DatabaseSettings

        # Non-existent path
        missing_cert = str(tmp_path / "does_not_exist.crt")
        db_missing = DatabaseSettings(ssl_mode="verify-full", ssl_root_cert=missing_cert)
        with pytest.raises(ConfigurationError, match="does not exist or is not a regular file"):
            _ = db_missing.url

        # Directory instead of regular file
        cert_dir = tmp_path / "cert_directory"
        cert_dir.mkdir()
        db_dir = DatabaseSettings(ssl_mode="verify-full", ssl_root_cert=str(cert_dir))
        with pytest.raises(ConfigurationError, match="does not exist or is not a regular file"):
            _ = db_dir.url

        # Empty file
        empty_cert = tmp_path / "empty_ca.crt"
        empty_cert.write_text("")
        db_empty = DatabaseSettings(ssl_mode="verify-full", ssl_root_cert=str(empty_cert))
        with pytest.raises(ConfigurationError, match="file is empty"):
            _ = db_empty.url

        # Unreadable file (simulated via monkeypatch for cross-platform reliability)
        readable_cert = tmp_path / "unreadable_ca.crt"
        readable_cert.write_text("DUMMY CERTIFICATE")
        monkeypatch.setattr(os, "access", lambda path, mode: False if str(path) == str(readable_cert) else True)
        db_unreadable = DatabaseSettings(ssl_mode="verify-full", ssl_root_cert=str(readable_cert))
        with pytest.raises(ConfigurationError, match="is not readable"):
            _ = db_unreadable.url

    def test_valid_cert_configuration_construction(self, tmp_path):
        """8. Valid-looking certificate file passed to connection settings without live handshake."""
        from sqlalchemy.engine import make_url
        from shared.config import DatabaseSettings

        valid_cert = tmp_path / "valid_ca.crt"
        valid_cert.write_text("-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n")

        db = DatabaseSettings(ssl_mode="verify-full", ssl_root_cert=str(valid_cert))
        parsed = make_url(db.url)
        assert parsed.query["sslmode"] == "verify-full"
        assert parsed.query["sslrootcert"] == str(valid_cert)

    def test_sslrootcert_and_sslmode_in_dialect_args(self, tmp_path):
        """9. sslrootcert and sslmode passed correctly to dialect connect args."""
        from sqlalchemy.dialects.postgresql.psycopg2 import PGDialect_psycopg2
        from shared.config import DatabaseSettings

        valid_cert = tmp_path / "ca.crt"
        valid_cert.write_text("CERT DATA")

        db = DatabaseSettings(ssl_mode="verify-full", ssl_root_cert=str(valid_cert))
        dialect = PGDialect_psycopg2()
        cargs, ckw = dialect.create_connect_args(db.as_url())
        assert ckw["sslmode"] == "verify-full"
        assert ckw["sslrootcert"] == str(valid_cert)
        assert db.connect_args == {"sslmode": "verify-full", "sslrootcert": str(valid_cert)}

    def test_password_masking_with_special_characters(self):
        """10. Password masking in safe_url, __repr__, and __str__."""
        from shared.config import DatabaseSettings

        secret = "p@ss:w/ord+1 %🔒"
        db = DatabaseSettings(user="my_user", password=secret)
        assert secret not in db.safe_url
        assert "****" in db.safe_url
        assert secret not in repr(db)
        assert "****" in repr(db)
        assert secret not in str(db)
        assert "****" in str(db)

    def test_validate_config_integration(self, tmp_path):
        """11. validate_config integrates TLS validation and fails closed."""
        import pytest
        from unittest.mock import patch
        from shared.config import ConfigurationError, DatabaseSettings, validate_config

        # Invalid mode fails in validate_config
        db_invalid = DatabaseSettings(
            host="localhost", port=5432, user="u", password="strong_password_1234567890_abcdef",
            name="db", ssl_mode="invalid_ssl_mode"
        )
        with patch.dict(os.environ, {"DEBUG": "true", "JWT_SECRET_KEY": "a"*32, "CERTIFICATE_SECRET_KEY": "b"*32}), patch("shared.crypto.config.get_crypto_profile"):
            with pytest.raises(ConfigurationError, match="Invalid DB_SSL_MODE"):
                validate_config(db_invalid)

        # verify-full with missing CA fails in validate_config
        db_no_ca = DatabaseSettings(
            host="localhost", port=5432, user="u", password="strong_password_1234567890_abcdef",
            name="db", ssl_mode="verify-full", ssl_root_cert=None
        )
        with patch.dict(os.environ, {"DEBUG": "true", "JWT_SECRET_KEY": "a"*32, "CERTIFICATE_SECRET_KEY": "b"*32}), patch("shared.crypto.config.get_crypto_profile"):
            with pytest.raises(ConfigurationError, match="DB_SSL_ROOT_CERT is required"):
                validate_config(db_no_ca)


def test_health_response_schema():
    """HealthResponse accepts expected fields."""
    from shared.schemas import HealthResponse

    resp = HealthResponse(service="test", status="healthy", version="0.1.0")
    assert resp.service == "test"
    assert resp.status == "healthy"


def test_exception_classes():
    """ServiceError hierarchy has correct status codes."""
    from shared.exceptions import NotFoundError, ConflictError, ServiceError

    assert ServiceError("x").status_code == 400
    assert NotFoundError().status_code == 404
    assert ConflictError().status_code == 409


class TestLocalDevDatabaseAllowlist:
    """Validate exact database isolation in local development mode (ENVIRONMENT=local_dev)."""

    VALID_ENV = {
        "ENVIRONMENT": "local_dev",
        "JWT_SECRET_KEY": "jwt-test-secret-string-32-chars-long-abc123",
        "CERTIFICATE_SECRET_KEY": "cert-test-secret-string-32-chars-long-xyz789",
    }

    def test_local_dev_rejects_protected_port_on_loopback(self):
        from unittest.mock import patch
        import pytest
        from shared.config import DatabaseSettings, ConfigurationError, validate_config

        with patch.dict(os.environ, self.VALID_ENV), patch("shared.crypto.config.get_crypto_profile"):
            db = DatabaseSettings(host="127.0.0.1", port=5432, name="ZKP_SBOM_LOCAL_DEV", password="pw"*16, ssl_mode="disable")
            with pytest.raises(ConfigurationError, match="must target port 5433"):
                validate_config(db)

    def test_local_dev_rejects_protected_db_name(self):
        from unittest.mock import patch
        import pytest
        from shared.config import DatabaseSettings, ConfigurationError, validate_config

        with patch.dict(os.environ, self.VALID_ENV), patch("shared.crypto.config.get_crypto_profile"):
            db = DatabaseSettings(host="127.0.0.1", port=5433, name="ZKP_SBOM", password="pw"*16, ssl_mode="disable")
            with pytest.raises(ConfigurationError, match="must target database 'ZKP_SBOM_LOCAL_DEV'"):
                validate_config(db)

    def test_local_dev_rejects_wrong_container_port(self):
        from unittest.mock import patch
        import pytest
        from shared.config import DatabaseSettings, ConfigurationError, validate_config

        with patch.dict(os.environ, self.VALID_ENV), patch("shared.crypto.config.get_crypto_profile"):
            db = DatabaseSettings(host="zkp_sbom_local_dev", port=5433, name="ZKP_SBOM_LOCAL_DEV", password="pw"*16, ssl_mode="disable")
            with pytest.raises(ConfigurationError, match="must target internal port 5432"):
                validate_config(db)

    def test_local_dev_rejects_unauthorized_external_host(self):
        from unittest.mock import patch
        import pytest
        from shared.config import DatabaseSettings, ConfigurationError, validate_config

        with patch.dict(os.environ, self.VALID_ENV), patch("shared.crypto.config.get_crypto_profile"):
            for bad_host, bad_port in (("db.remote-supabase.com", 5432), ("localhost", 5433)):
                db = DatabaseSettings(host=bad_host, port=bad_port, name="ZKP_SBOM_LOCAL_DEV", password="pw"*16, ssl_mode="disable")
                with pytest.raises(ConfigurationError, match="only permits host '127.0.0.1'"):
                    validate_config(db)

    def test_local_dev_accepts_valid_host_and_container_targets(self):
        from unittest.mock import patch
        from shared.config import DatabaseSettings, validate_config

        with patch.dict(os.environ, self.VALID_ENV), patch("shared.crypto.config.get_crypto_profile"):
            # Valid host-run target
            db_host = DatabaseSettings(host="127.0.0.1", port=5433, name="ZKP_SBOM_LOCAL_DEV", password="pw"*16, ssl_mode="disable")
            assert validate_config(db_host) == db_host

            # Valid container-run target
            db_cont = DatabaseSettings(host="zkp_sbom_local_dev", port=5432, name="ZKP_SBOM_LOCAL_DEV", password="pw"*16, ssl_mode="disable")
            assert validate_config(db_cont) == db_cont
