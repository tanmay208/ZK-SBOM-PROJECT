import os
import pytest
from unittest.mock import patch, MagicMock
from shared.app_factory import create_app
from shared.config import ConfigurationError
from shared.crypto.config import CryptoProfileConfigError

@pytest.fixture
def clean_env():
    # Make a copy of env vars and restore them after
    old_env = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(old_env)

def test_missing_jwt_fails_startup(clean_env):
    os.environ["DEBUG"] = "false"
    os.environ["DB_PASSWORD"] = "test_password"
    os.environ["DB_HOST"] = "test_host"
    os.environ["DB_NAME"] = "test_name"
    # Ensure JWT is NOT set
    if "JWT_SECRET_KEY" in os.environ:
        del os.environ["JWT_SECRET_KEY"]
    os.environ["CRYPTO_PROFILE"] = "prod"
    from shared.config import ConfigurationError
    with pytest.raises(ConfigurationError, match="JWT_SECRET_KEY"):
            # The lifespan context manager must be entered to test startup
            app = create_app("test_service", "Test", "Test Desc")
            with patch('shared.app_factory.init_engine'):
                import asyncio
                async def run_lifespan():
                    async with app.router.lifespan_context(app):
                        pass
                asyncio.run(run_lifespan())


def test_whitespace_only_jwt_fails_startup_even_at_production_length(clean_env):
    os.environ.update(
        {
                "DEBUG": "false",
                "DB_PASSWORD": "test_password",
                "DB_HOST": "test_host",
                "DB_NAME": "test_name",
                "JWT_SECRET_KEY": " " * 32,
                "CERTIFICATE_SECRET_KEY": "cert-test-secret-9a2d6e1f4b7c8a3d",
                "CRYPTO_PROFILE": "prod",
        }
    )
    app = create_app("test_service", "Test", "Test Desc")
    with patch("shared.app_factory.init_engine"):
        import asyncio

        async def run_lifespan():
                async with app.router.lifespan_context(app):
                    pass

        with pytest.raises(ConfigurationError, match="JWT_SECRET_KEY"):
                asyncio.run(run_lifespan())


def test_one_character_secrets_fail_in_debug_mode(clean_env):
    os.environ.update(
        {
                "DEBUG": "true",
                "DB_PASSWORD": "test_password",
                "DB_HOST": "test_host",
                "DB_NAME": "test_name",
                "JWT_SECRET_KEY": "x",
                "CERTIFICATE_SECRET_KEY": "y",
                "CRYPTO_PROFILE": "dev",
        }
    )
    app = create_app("test_service", "Test", "Test Desc")
    with patch("shared.app_factory.init_engine"):
        import asyncio

        async def run_lifespan():
                async with app.router.lifespan_context(app):
                    pass

        with pytest.raises(ConfigurationError, match="JWT_SECRET_KEY"):
                asyncio.run(run_lifespan())

def test_missing_cert_secret_fails_startup(clean_env):
    os.environ["DEBUG"] = "false"
    os.environ["DB_PASSWORD"] = "test_password"
    os.environ["DB_HOST"] = "test_host"
    os.environ["DB_NAME"] = "test_name"
    os.environ["JWT_SECRET_KEY"] = "jwt-test-secret-7f3c9a1d5b8e2c4f"
    if "CERTIFICATE_SECRET_KEY" in os.environ:
        del os.environ["CERTIFICATE_SECRET_KEY"]
    os.environ["CRYPTO_PROFILE"] = "prod"
    from shared.config import ConfigurationError
    with pytest.raises(ConfigurationError, match="CERTIFICATE_SECRET_KEY"):
        app = create_app("test_service", "Test", "Test Desc")
        with patch('shared.app_factory.init_engine'):
            import asyncio
            async def run_lifespan():
                async with app.router.lifespan_context(app):
                    pass
            asyncio.run(run_lifespan())

def test_db_initialization_failure_fails_startup(clean_env):
    os.environ["DEBUG"] = "false"
    os.environ["DB_PASSWORD"] = "test_password"
    os.environ["DB_HOST"] = "test_host"
    os.environ["DB_NAME"] = "test_name"
    os.environ["JWT_SECRET_KEY"] = "jwt-test-secret-7f3c9a1d5b8e2c4f"
    os.environ["CERTIFICATE_SECRET_KEY"] = "cert-test-secret-9a2d6e1f4b7c8a3d"
    os.environ["CRYPTO_PROFILE"] = "prod"
    
    app = create_app("test_service", "Test", "Test Desc")
    with patch('shared.app_factory.init_engine', side_effect=RuntimeError("DB Init Failed")):
        import asyncio
        async def run_lifespan():
            async with app.router.lifespan_context(app):
                pass
        with pytest.raises(RuntimeError, match="DB Init Failed"):
            asyncio.run(run_lifespan())

def test_invalid_crypto_profile_fails_startup(clean_env):
    os.environ["DEBUG"] = "false"
    os.environ["DB_PASSWORD"] = "test_password"
    os.environ["DB_HOST"] = "test_host"
    os.environ["DB_NAME"] = "test_name"
    os.environ["JWT_SECRET_KEY"] = "jwt-test-secret-7f3c9a1d5b8e2c4f"
    os.environ["CERTIFICATE_SECRET_KEY"] = "cert-test-secret-9a2d6e1f4b7c8a3d"
    
    app = create_app("test_service", "Test", "Test Desc")
    # Setting an explicitly missing/invalid profile
    os.environ["CRYPTO_PROFILE"] = "invalid_nonexistent_profile"
    
    import asyncio
    async def run_lifespan():
        async with app.router.lifespan_context(app):
            pass
    from shared.config import ConfigurationError
    with pytest.raises(ConfigurationError, match="Invalid crypto profile"):
        asyncio.run(run_lifespan())

def test_missing_crypto_profile_env(clean_env):
    os.environ["DEBUG"] = "false"
    os.environ["DB_PASSWORD"] = "test_password"
    os.environ["DB_HOST"] = "test_host"
    os.environ["DB_NAME"] = "test_name"
    os.environ["JWT_SECRET_KEY"] = "jwt-test-secret-7f3c9a1d5b8e2c4f"
    os.environ["CERTIFICATE_SECRET_KEY"] = "cert-test-secret-9a2d6e1f4b7c8a3d"
    if "CRYPTO_PROFILE" in os.environ:
        del os.environ["CRYPTO_PROFILE"]
        
    app = create_app("test_service", "Test", "Test Desc")
    with patch('shared.app_factory.init_engine'):
        import asyncio
        async def run_lifespan():
            async with app.router.lifespan_context(app):
                pass
        from shared.config import ConfigurationError
        with pytest.raises(ConfigurationError, match="Invalid crypto profile: CRYPTO_PROFILE environment variable is required"):
            asyncio.run(run_lifespan())

def test_missing_vk_fails_startup(clean_env):
    os.environ["DEBUG"] = "false"
    os.environ["DB_PASSWORD"] = "test_password"
    os.environ["DB_HOST"] = "test_host"
    os.environ["DB_NAME"] = "test_name"
    os.environ["JWT_SECRET_KEY"] = "jwt-test-secret-7f3c9a1d5b8e2c4f"
    os.environ["CERTIFICATE_SECRET_KEY"] = "cert-test-secret-9a2d6e1f4b7c8a3d"
    os.environ["CRYPTO_PROFILE"] = "prod"
    
    app = create_app("test_service", "Test", "Test Desc")
    with patch('shared.app_factory.init_engine'):
        with patch('os.path.exists', return_value=False):
            import asyncio
            async def run_lifespan():
                async with app.router.lifespan_context(app):
                    pass
            from shared.config import ConfigurationError
            with pytest.raises(ConfigurationError, match="Invalid crypto profile: Missing required decomposed artifact"):
                asyncio.run(run_lifespan())

def test_wrong_vk_hash_fails_startup(clean_env):
    os.environ["DEBUG"] = "false"
    os.environ["DB_PASSWORD"] = "test_password"
    os.environ["DB_HOST"] = "test_host"
    os.environ["DB_NAME"] = "test_name"
    os.environ["JWT_SECRET_KEY"] = "jwt-startup-test-secret-9f2c7b4a6d8e1f30"
    os.environ["CERTIFICATE_SECRET_KEY"] = "cert-startup-test-secret-4a8e2d6f9b1c7e30"
    os.environ["CRYPTO_PROFILE"] = "prod"
    
    app = create_app("test_service", "Test", "Test Desc")
    with patch('shared.app_factory.init_engine'):
        with patch('hashlib.sha256') as mock_sha:
            mock_sha.return_value.hexdigest.return_value = "wronghash"
            import asyncio
            async def run_lifespan():
                async with app.router.lifespan_context(app):
                    pass
            from shared.config import ConfigurationError
            with pytest.raises(ConfigurationError, match="Invalid crypto profile: Decomposed circuit hash mismatch"):
                asyncio.run(run_lifespan())
