import base64
import hashlib
import secrets
import time
from typing import Any

from jose import jwt

from .a3_client import A3Issuer


class InvalidToken(Exception):
    pass


def gen_state() -> str:
    return secrets.token_urlsafe(16)


def gen_nonce() -> str:
    return secrets.token_urlsafe(16)


def gen_pkce_challenge() -> tuple[str, str]:
    verifier = (
        base64.urlsafe_b64encode(secrets.token_bytes(32))
        .rstrip(b"=")
        .decode("ascii")
    )
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def verify_token(
    token: str,
    issuer: A3Issuer,
    nonce: str | None,
    jwks: dict[str, Any],
    expected_aud: str,
) -> dict[str, Any]:

    def find_jwk(jwks: dict[str, Any], kid: str | None):
        for key in jwks.get("keys", []):
            if key.get("kid") == kid or kid is None:
                return key
        return None

    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")
    key = find_jwk(jwks, kid)
    if not key:
        raise InvalidToken("No matching JWK found")

    options = {
        "verify_signature": True,
        "verify_iss": True,
        "verify_exp": True,
        "verify_nbf": True,
        "verify_iat": True,
    }

    claims: dict[str, Any] = jwt.decode(
        token,
        key,
        algorithms=key.get("alg", "RS256") if key.get("alg") else "RS256",
        audience=expected_aud,
        issuer=issuer.issuer_url(),
        options=options,
    )

    claim_nonce = claims.get("nonce")
    if claim_nonce is not None and nonce is not None and claim_nonce != nonce:
        raise InvalidToken("Invalid nonce")

    now = int(time.time())
    if claims.get("exp", 0) < now:
        raise InvalidToken("ID Token expired")

    return claims
