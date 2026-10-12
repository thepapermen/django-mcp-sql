"""The OAuth flow the refresh-token tests drive: consent, code exchange,
refresh (shared by `test_refresh_tokens` and `test_revocation_race`)."""

import base64
import hashlib
import secrets
from http import HTTPStatus
from urllib.parse import parse_qs
from urllib.parse import urlparse

from django.urls import reverse

LOOPBACK = "http://127.0.0.1:9999"
CAP = 3600


def s256_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def consent(client, user) -> tuple[str, str]:
    """Authorize the canonical client (consent POST: it requires consent since
    migration 0016); the code and its PKCE verifier."""
    client.force_login(user)
    verifier, challenge = s256_pair()
    params = {
        "client_id": "mcp-sql",
        "response_type": "code",
        "redirect_uri": LOOPBACK,
        "scope": "mcp:sql",
        "state": "st4te",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    location = client.post(reverse("authorize"), {**params, "allow": "Authorize"})[
        "Location"
    ]
    return parse_qs(urlparse(location).query)["code"][0], verifier


def exchange(client, code: str, verifier: str):
    return client.post(
        reverse("token"),
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": LOOPBACK,
            "client_id": "mcp-sql",
            "code_verifier": verifier,
        },
    )


def consent_and_exchange(client, user) -> dict:
    """`consent`, then exchange the code."""
    response = exchange(client, *consent(client, user))
    assert response.status_code == HTTPStatus.OK, response.content
    return response.json()


def refresh(client, refresh_token: str):
    return client.post(
        reverse("token"),
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "mcp-sql",
        },
    )
