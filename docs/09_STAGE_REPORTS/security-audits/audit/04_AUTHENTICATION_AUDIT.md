# Authentication Audit

## Findings

- `shared/auth.py` uses bcrypt with 12 rounds and truncates passwords to bcrypt's 72-byte input limit. The truncation is explicit but means passwords differing only after byte 72 authenticate identically: SECURITY WEAKNESS.
- Login performs a pre-query and runs a precomputed dummy bcrypt check when the user is absent. Error text is shared for absent user and bad password. This is a verified enumeration mitigation at the application logic level, with no timing benchmark.
- JWT uses HS256, explicitly restricts decode algorithms to HS256, and requires `exp` and `sub`. Expiration is checked by PyJWT. No issuer, audience, token ID, not-before, or revocation claim is required.
- `role` is included in issued tokens but `get_current_user` ignores the token role and reloads the user by username. This prevents direct role claim spoofing in identity lookup, but there is no route role enforcement.
- `JWT_SECRET_KEY` is read at runtime, but an unset secret creates a process-local ephemeral secret. Tokens become invalid after process restart and are not interoperable across worker processes. There is no fail-closed config validation for JWT secret: SECURITY WEAKNESS / deployment availability risk.
- `SECRET_KEY` is initialized at import but token functions call `get_jwt_secret()` again. Environment changes after import can make behavior inconsistent with code that uses the constant. No rotation protocol exists.
- Registration is unauthenticated and accepts OAuth2 form fields; role is hardcoded to `auditor`. No disabled/deleted user state is modeled or checked.
- Frontend source inspection found no token storage, login flow, or Authorization header construction. Frontend build success therefore does not establish browser authentication security.

## False-Positive/Verified Controls

The apparent algorithm-confusion concern is a FALSE POSITIVE for this code path: encoding fixes `HS256`, decoding passes `algorithms=["HS256"]`, and no user-controlled algorithm is accepted. Malformed and expired tokens are caught as `jwt.PyJWTError` and converted to 401. Password hashes are not returned by the three auth handlers inspected.

## Required Evidence Gaps

UNVERIFIED — INSUFFICIENT EVIDENCE for secret strength policy, multi-worker behavior in deployment, token replay policy, refresh/logout behavior, TLS termination, and real browser token storage. Relevant code: `backend/shared/auth.py` and `backend/shared/api/auth_routes.py`.
