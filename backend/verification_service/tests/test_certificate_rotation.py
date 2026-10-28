import pytest
import jwt
from uuid import uuid4
from datetime import datetime, timedelta
import json
import os

from verification_service.app.services.verification_service import VerificationService
from verification_service.app.models.verification_models import VerificationCertificate, VerificationRequest

class DummyRepo:
    def __init__(self, cert):
        self.cert = cert
    
    def get_certificate_by_request_id(self, request_id):
        if self.cert and str(self.cert.verification_request_id) == str(request_id):
            return self.cert
        return None

    def get_certificate(self, certificate_id):
        if self.cert and str(self.cert.id) == str(certificate_id):
            return self.cert
        return None

class DummySession:
    def __init__(self, req):
        self.req = req
        self.query_result = self

    def query(self, *args):
        return self

    def filter(self, *args):
        return self

    def first(self):
        return self.req

def test_issuance_default_kid_v1(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "secret_v1")
    monkeypatch.delenv("CERTIFICATE_ACTIVE_KID", raising=False)
    
    from verification_service.app.repositories.verification_repository import VerificationRepository
    
    req_id = uuid4()
    
    class MockSession:
        def __init__(self):
            self.cert = None
        def add(self, obj):
            if hasattr(obj, "verification_request_id"):
                self.cert = obj
            else:
                obj.id = req_id
        def flush(self): pass
        def commit(self): pass
        def refresh(self, obj): pass
        def query(self, *args): return self
        def filter(self, *args): return self
        def first(self): return None

    session = MockSession()
    repo = VerificationRepository(session)
    
    class DummyReq:
        id = req_id
        sbom_root = "root"
        vulnerability_db_root = "vuln"
        policy_hash = "hash"
        proof_job_id = uuid4()
    
    repo.create_verification_record(DummyReq(), "verified", uuid4())
    
    assert session.cert is not None
    token = session.cert.certificate_data
    unverified = jwt.get_unverified_header(token)
    assert unverified.get("kid") == "v1"

def test_issuance_explicit_active_kid(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "secret_v2")
    monkeypatch.setenv("CERTIFICATE_SECRET_KEYS", json.dumps({"v1": "secret_v1", "v2": "secret_v2"}))
    monkeypatch.setenv("CERTIFICATE_ACTIVE_KID", "v2")
    
    from verification_service.app.repositories.verification_repository import VerificationRepository
    req_id = uuid4()
    
    class MockSession:
        def __init__(self):
            self.cert = None
        def add(self, obj):
            if hasattr(obj, "verification_request_id"):
                self.cert = obj
            else:
                obj.id = req_id
        def flush(self): pass
        def commit(self): pass
        def refresh(self, obj): pass
        def query(self, *args): return self
        def filter(self, *args): return self
        def first(self): return None

    session = MockSession()
    repo = VerificationRepository(session)
    
    class DummyReq:
        id = req_id
        sbom_root = "root"
        vulnerability_db_root = "vuln"
        policy_hash = "hash"
        proof_job_id = uuid4()
    
    repo.create_verification_record(DummyReq(), "verified", uuid4())
    token = session.cert.certificate_data
    unverified = jwt.get_unverified_header(token)
    assert unverified.get("kid") == "v2"

def test_issuance_inconsistent_config_fails(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "secret_v2")
    monkeypatch.setenv("CERTIFICATE_SECRET_KEYS", json.dumps({"v1": "secret_v1", "v2": "wrong_secret"}))
    monkeypatch.setenv("CERTIFICATE_ACTIVE_KID", "v2")
    
    from verification_service.app.repositories.verification_repository import VerificationRepository
    
    class MockSession:
        def add(self, obj): pass
        def flush(self): pass
        def commit(self): pass
        def refresh(self, obj): pass
        def query(self, *args): return self
        def filter(self, *args): return self
        def first(self): return None

    session = MockSession()
    repo = VerificationRepository(session)
    
    class DummyReq:
        id = uuid4()
        sbom_root = "root"
        vulnerability_db_root = "vuln"
        policy_hash = "hash"
        proof_job_id = uuid4()
        
    with pytest.raises(ValueError, match="Inconsistent configuration"):
        repo.create_verification_record(DummyReq(), "verified", uuid4())

def test_issuance_unknown_active_kid_fails(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "secret_v2")
    monkeypatch.setenv("CERTIFICATE_SECRET_KEYS", json.dumps({"v1": "secret_v1"}))
    monkeypatch.setenv("CERTIFICATE_ACTIVE_KID", "v2")
    
    from verification_service.app.repositories.verification_repository import VerificationRepository
    
    class MockSession:
        def add(self, obj): pass
        def flush(self): pass
        def commit(self): pass
        def refresh(self, obj): pass
        def query(self, *args): return self
        def filter(self, *args): return self
        def first(self): return None

    session = MockSession()
    repo = VerificationRepository(session)
    
    class DummyReq:
        id = uuid4()
        sbom_root = "root"
        vulnerability_db_root = "vuln"
        policy_hash = "hash"
        proof_job_id = uuid4()
        
    with pytest.raises(ValueError, match="missing from verification map"):
        repo.create_verification_record(DummyReq(), "verified", uuid4())

def test_rollback_preserves_validation(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEYS", json.dumps({"legacy": "old_secret", "v1": "new_secret"}))
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "old_secret")
    monkeypatch.setenv("CERTIFICATE_ACTIVE_KID", "legacy")
    
    req_id1 = uuid4()
    cert_id1 = uuid4()
    payload1 = {"sub": str(req_id1), "iss": "antigravity-zkp-authority", "exp": datetime.utcnow() + timedelta(days=1)}
    # Token 1 issued during active window (v1 with new_secret)
    token1 = jwt.encode(payload1, "new_secret", algorithm="HS256", headers={"kid": "v1"})
    
    req_id2 = uuid4()
    cert_id2 = uuid4()
    payload2 = {"sub": str(req_id2), "iss": "antigravity-zkp-authority", "exp": datetime.utcnow() + timedelta(days=1)}
    # Token 2 issued after rollback (legacy with old_secret)
    token2 = jwt.encode(payload2, "old_secret", algorithm="HS256", headers={"kid": "legacy"})
    
    # We will test validate_certificate_token for both
    # For token1
    cert1 = VerificationCertificate(id=cert_id1, verification_request_id=req_id1, is_revoked=False)
    req1 = VerificationRequest(id=req_id1, result="verified")
    service1 = VerificationService(session=DummySession(req1), verifier=None)
    service1._repo = DummyRepo(cert1)
    
    result1 = service1.validate_certificate_token(token1)
    assert result1["valid"] is True
    
    # For token2
    cert2 = VerificationCertificate(id=cert_id2, verification_request_id=req_id2, is_revoked=False)
    req2 = VerificationRequest(id=req_id2, result="verified")
    service2 = VerificationService(session=DummySession(req2), verifier=None)
    service2._repo = DummyRepo(cert2)
    
    result2 = service2.validate_certificate_token(token2)
    assert result2["valid"] is True

def test_historical_key_validation(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEYS", json.dumps({"v1": "old_secret", "v2": "new_secret"}))
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "new_secret")
    
    req_id = uuid4()
    cert_id = uuid4()
    payload = {"sub": str(req_id), "iss": "antigravity-zkp-authority", "exp": datetime.utcnow() + timedelta(days=1)}
    token = jwt.encode(payload, "old_secret", algorithm="HS256", headers={"kid": "v1"})
    
    cert = VerificationCertificate(id=cert_id, verification_request_id=req_id, is_revoked=False)
    req = VerificationRequest(id=req_id, result="verified")
    
    service = VerificationService(session=DummySession(req), verifier=None)
    service._repo = DummyRepo(cert)
    
    result = service.validate_certificate_token(token)
    assert result["valid"] is True
    assert result["reason"] == "certificate_active"
    assert result["certificate_id"] == str(cert_id)

def test_legacy_token_without_kid(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEYS", json.dumps({"v1": "new_secret", "legacy": "old_legacy_secret"}))
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "new_secret")
    
    req_id = uuid4()
    cert_id = uuid4()
    payload = {"sub": str(req_id), "iss": "antigravity-zkp-authority", "exp": datetime.utcnow() + timedelta(days=1)}
    # Legacy token lacks kid header
    token = jwt.encode(payload, "old_legacy_secret", algorithm="HS256")
    
    cert = VerificationCertificate(id=cert_id, verification_request_id=req_id, is_revoked=False)
    req = VerificationRequest(id=req_id, result="verified")
    
    service = VerificationService(session=DummySession(req), verifier=None)
    service._repo = DummyRepo(cert)
    
    result = service.validate_certificate_token(token)
    assert result["valid"] is True
    assert result["reason"] == "certificate_active"

def test_unknown_kid_fails_closed(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEYS", json.dumps({"v1": "new_secret"}))
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "new_secret")
    
    payload = {"sub": str(uuid4()), "iss": "antigravity-zkp-authority", "exp": datetime.utcnow() + timedelta(days=1)}
    token = jwt.encode(payload, "new_secret", algorithm="HS256", headers={"kid": "unknown_v3"})
    
    service = VerificationService(session=None, verifier=None)
    result = service.validate_certificate_token(token)
    assert result["valid"] is False
    assert result["reason"] == "unknown_key_id"

def test_invalid_signature_fails_closed(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEYS", json.dumps({"v1": "new_secret"}))
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "new_secret")
    
    payload = {"sub": str(uuid4()), "iss": "antigravity-zkp-authority", "exp": datetime.utcnow() + timedelta(days=1)}
    # Signed with wrong secret
    token = jwt.encode(payload, "wrong_secret", algorithm="HS256", headers={"kid": "v1"})
    
    service = VerificationService(session=None, verifier=None)
    result = service.validate_certificate_token(token)
    assert result["valid"] is False
    assert result["reason"] == "token_invalid"

def test_expired_token_fails_closed(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "new_secret")
    
    payload = {"sub": str(uuid4()), "iss": "antigravity-zkp-authority", "exp": datetime.utcnow() - timedelta(days=1)}
    token = jwt.encode(payload, "new_secret", algorithm="HS256", headers={"kid": "v1"})
    
    service = VerificationService(session=None, verifier=None)
    result = service.validate_certificate_token(token)
    assert result["valid"] is False
    assert result["reason"] == "token_expired"

def test_wrong_issuer_fails_closed(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "new_secret")
    
    payload = {"sub": str(uuid4()), "iss": "wrong_issuer", "exp": datetime.utcnow() + timedelta(days=1)}
    token = jwt.encode(payload, "new_secret", algorithm="HS256", headers={"kid": "v1"})
    
    service = VerificationService(session=None, verifier=None)
    result = service.validate_certificate_token(token)
    assert result["valid"] is False
    assert result["reason"] == "token_invalid"

def test_subject_mismatch_fails_closed(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "new_secret")
    
    # Missing sub
    payload = {"iss": "antigravity-zkp-authority", "exp": datetime.utcnow() + timedelta(days=1)}
    token = jwt.encode(payload, "new_secret", algorithm="HS256", headers={"kid": "v1"})
    
    service = VerificationService(session=None, verifier=None)
    result = service.validate_certificate_token(token)
    assert result["valid"] is False
    assert result["reason"] == "token_missing_subject"

def test_revoked_certificate_fails_closed(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "new_secret")
    
    req_id = uuid4()
    cert_id = uuid4()
    payload = {"sub": str(req_id), "iss": "antigravity-zkp-authority", "exp": datetime.utcnow() + timedelta(days=1)}
    token = jwt.encode(payload, "new_secret", algorithm="HS256", headers={"kid": "v1"})
    
    # Certificate is revoked
    cert = VerificationCertificate(id=cert_id, verification_request_id=req_id, is_revoked=True)
    req = VerificationRequest(id=req_id, result="verified")
    
    service = VerificationService(session=DummySession(req), verifier=None)
    service._repo = DummyRepo(cert)
    
    result = service.validate_certificate_token(token)
    assert result["valid"] is False
    assert result["reason"] == "certificate_revoked"
    assert result["certificate_id"] == str(cert_id)

def test_missing_config_fails_closed(monkeypatch):
    monkeypatch.delenv("CERTIFICATE_SECRET_KEY", raising=False)
    monkeypatch.delenv("CERTIFICATE_SECRET_KEYS", raising=False)
    
    payload = {"sub": str(uuid4()), "iss": "antigravity-zkp-authority", "exp": datetime.utcnow() + timedelta(days=1)}
    token = jwt.encode(payload, "test", algorithm="HS256")
    
    service = VerificationService(session=None, verifier=None)
    result = service.validate_certificate_token(token)
    assert result["valid"] is False
    assert result["reason"] == "server_configuration_error"

def test_end_to_end_rollback_scenario(monkeypatch):
    monkeypatch.setenv("CERTIFICATE_SECRET_KEYS", json.dumps({"legacy": "old_secret", "v1": "new_secret"}))
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "new_secret")
    monkeypatch.setenv("CERTIFICATE_ACTIVE_KID", "v1")
    
    from verification_service.app.repositories.verification_repository import VerificationRepository
    
    class MockSession:
        def __init__(self):
            self.certs = {}
            self.reqs = {}
        def add(self, obj):
            if hasattr(obj, "verification_request_id"):
                self.certs[obj.verification_request_id] = obj
            else:
                if getattr(obj, "id", None) is None:
                    obj.id = uuid4()
                self.reqs[obj.id] = obj
        def flush(self): pass
        def commit(self): pass
        def refresh(self, obj): pass
        def query(self, *args): return self
        def filter(self, *args): return self
        def first(self): return None
        
    class DummyReq:
        sbom_root = "root"
        vulnerability_db_root = "vuln"
        policy_hash = "hash"
        proof_job_id = uuid4()
        
    session = MockSession()
    repo = VerificationRepository(session)
    
    # 1. Issue with v1 / new_secret
    req1 = repo.create_verification_record(DummyReq(), "verified", uuid4())
    cert1 = session.certs[req1.id]
    token1 = cert1.certificate_data
    
    # Validation Service logic uses DummySession and DummyRepo which are global in this test file
    service1 = VerificationService(session=DummySession(req1), verifier=None)
    service1._repo = DummyRepo(cert1)
    
    result1 = service1.validate_certificate_token(token1)
    assert result1["valid"] is True
    
    # 2. Simulate rollback to legacy
    monkeypatch.setenv("CERTIFICATE_SECRET_KEY", "old_secret")
    monkeypatch.setenv("CERTIFICATE_ACTIVE_KID", "legacy")
    
    repo2 = VerificationRepository(session)
    req2 = repo2.create_verification_record(DummyReq(), "verified", uuid4())
    cert2 = session.certs[req2.id]
    token2 = cert2.certificate_data
    
    # Validate token 1 AFTER rollback
    service2_for_1 = VerificationService(session=DummySession(req1), verifier=None)
    service2_for_1._repo = DummyRepo(cert1)
    result2_1 = service2_for_1.validate_certificate_token(token1)
    assert result2_1["valid"] is True
    
    # Validate token 2 AFTER rollback
    service2_for_2 = VerificationService(session=DummySession(req2), verifier=None)
    service2_for_2._repo = DummyRepo(cert2)
    result2_2 = service2_for_2.validate_certificate_token(token2)
    assert result2_2["valid"] is True
