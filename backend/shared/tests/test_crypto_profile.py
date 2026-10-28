import os
import json
import pytest
from unittest.mock import patch, mock_open

from shared.crypto.config import get_crypto_profile, CryptoProfileConfigError

@pytest.fixture
def mock_profile_json():
    return {
        "active_profile": "prod",
        "profiles": {
            "dev": {
                "circuit_dir": "circuits_dev",
                "circuit_artifact_hash": "mock_hash_1",
                "vk_hash": "mock_hash_2",
                "max_components": 8,
                "merkle_depth": 3,
                "smt_depth": 256,
                "nargo_version": "0.32.0"
            },
            "prod": {
                "circuit_dir": "circuits",
                "circuit_artifact_hash": None,
                "vk_hash": None,
                "max_components": 1024,
                "merkle_depth": 10,
                "smt_depth": 256,
                "nargo_version": "0.32.0",
                "decomposed_artifacts": {
                    "segment_init_32": {
                        "circuit_artifact_hash": "init_c_hash",
                        "vk_hash": "init_v_hash"
                    },
                    "segment_mid_32": {
                        "circuit_artifact_hash": "mid_c_hash",
                        "vk_hash": "mid_v_hash"
                    },
                    "segment_final_32": {
                        "circuit_artifact_hash": "final_c_hash",
                        "vk_hash": "final_v_hash"
                    }
                }
            }
        }
    }

def test_invalid_profile_name(mock_profile_json):
    with patch("builtins.open", mock_open(read_data=json.dumps(mock_profile_json))):
        with patch.dict(os.environ, {"CRYPTO_PROFILE": "invalid"}):
            with pytest.raises(CryptoProfileConfigError, match="Invalid CRYPTO_PROFILE specified"):
                get_crypto_profile()

@patch("shared.crypto.config.hashlib.sha256")
def test_valid_decomposed_profile(mock_sha256, mock_profile_json):
    with patch("builtins.open", mock_open(read_data=json.dumps(mock_profile_json))):
        with patch.dict(os.environ, {"CRYPTO_PROFILE": "prod", "DEBUG": "true"}):
            with patch("os.path.exists", return_value=True):
                mock_hash_obj = mock_sha256.return_value
                mock_hash_obj.hexdigest.side_effect = [
                    "init_c_hash", "init_v_hash",
                    "mid_c_hash", "mid_v_hash",
                    "final_c_hash", "final_v_hash"
                ]
                profile = get_crypto_profile()
                assert profile.max_components == 1024

@patch("shared.crypto.config.hashlib.sha256")
def test_missing_decomposed_artifacts_config(mock_sha256, mock_profile_json):
    del mock_profile_json["profiles"]["prod"]["decomposed_artifacts"]
    with patch("builtins.open", mock_open(read_data=json.dumps(mock_profile_json))):
        with patch.dict(os.environ, {"CRYPTO_PROFILE": "prod"}):
            with pytest.raises(CryptoProfileConfigError, match="requires decomposed_artifacts"):
                get_crypto_profile()

@patch("shared.crypto.config.hashlib.sha256")
def test_missing_decomposed_artifact_file(mock_sha256, mock_profile_json):
    with patch("builtins.open", mock_open(read_data=json.dumps(mock_profile_json))):
        with patch.dict(os.environ, {"CRYPTO_PROFILE": "prod"}):
            with patch("os.path.exists", return_value=False):
                with pytest.raises(CryptoProfileConfigError, match="Missing required decomposed artifact"):
                    get_crypto_profile()

@patch("shared.crypto.config.hashlib.sha256")
def test_missing_decomposed_vk_file(mock_sha256, mock_profile_json):
    def fake_exists(path):
        return not path.endswith("vk")
        
    with patch("builtins.open", mock_open(read_data=json.dumps(mock_profile_json))):
        with patch.dict(os.environ, {"CRYPTO_PROFILE": "prod"}):
            with patch("os.path.exists", side_effect=fake_exists):
                # mock hash to match circuit to get to VK check
                mock_hash_obj = mock_sha256.return_value
                mock_hash_obj.hexdigest.return_value = "init_c_hash"
                with pytest.raises(CryptoProfileConfigError, match="Missing required decomposed VK"):
                    get_crypto_profile()
                    
@patch("shared.crypto.config.hashlib.sha256")
def test_incorrect_decomposed_artifact_hash(mock_sha256, mock_profile_json):
    with patch("builtins.open", mock_open(read_data=json.dumps(mock_profile_json))):
        with patch.dict(os.environ, {"CRYPTO_PROFILE": "prod"}):
            with patch("os.path.exists", return_value=True):
                mock_hash_obj = mock_sha256.return_value
                mock_hash_obj.hexdigest.return_value = "WRONG_HASH"
                with pytest.raises(CryptoProfileConfigError, match="Decomposed circuit hash mismatch"):
                    get_crypto_profile()

def test_obsolete_monolithic_artifact_absent(mock_profile_json):
    # This test verifies that if circuit_artifact_hash is None, it doesn't fail on missing monolithic artifact
    # It will instead proceed to decomposed validation. We'll mock that to succeed.
    with patch("builtins.open", mock_open(read_data=json.dumps(mock_profile_json))):
        with patch.dict(os.environ, {"CRYPTO_PROFILE": "prod"}):
            with patch("shared.crypto.config.CryptoProfile._validate_artifacts") as mock_val:
                profile = get_crypto_profile()
                assert profile.circuit_artifact_hash is None
                assert profile.vk_hash is None
