"""Revocation racing refresh-token rotations, on real PostgreSQL connections.

A logout / password change deletes the user's MCP tokens
(`signals._revoke_and_audit`) while the user's MCP client may be rotating
its refresh token on another connection. Under READ COMMITTED each delete
sees only rows committed before it starts, so a rotation that commits
during the refresh-token delete, followed by a second one that straddles the
access-token delete, used to leave a live refresh / access pair behind — and
the revocation was logged as complete.

The interleaving is forced, not hoped for: rotations pause inside their
token transaction (`_create_refresh_token`, after DOT has locked and revoked
the presented refresh token and inserted the new access token), the
revocation pauses before its access-token delete, and the test waits on
`pg_stat_activity` to see a connection blocked on a row lock before it lets
the holder go on. Every wait is bounded, so a regression fails instead of
hanging.
"""

import contextlib
import threading
import time
from collections.abc import Callable
from collections.abc import Iterator
from dataclasses import dataclass
from dataclasses import field
from http import HTTPStatus

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.db import connections
from django.db.models.query import QuerySet
from django.test import Client
from mcp_sql.models import MCPRefreshTokenFamily
from mcp_sql.oauth import MCPOAuth2Validator
from mcp_sql.tests.refresh_flow import CAP
from mcp_sql.tests.refresh_flow import consent
from mcp_sql.tests.refresh_flow import consent_and_exchange
from mcp_sql.tests.refresh_flow import exchange
from mcp_sql.tests.refresh_flow import refresh
from oauth2_provider.models import AccessToken
from oauth2_provider.models import RefreshToken

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.usefixtures("mcp_mfa_on", "mcp_app"),
]

_WAIT = 15  # seconds; any single step of the choreography


@pytest.fixture(autouse=True)
def _refresh_on_without_session_gate(settings):
    settings.MCP_SQL = {
        **settings.MCP_SQL,
        "REFRESH_TOKEN_MAX_AGE_SECONDS": CAP,
        "SESSION_MODEL": None,
    }


@dataclass
class _Gate:
    """A pause point: `arrived` once the thread reaches it; it goes on when
    `release` is set. `at` names where a token request pauses: on entering
    `save_bearer_token` (validated, before its transaction), or inside that
    transaction just before the new access / refresh token is written; the
    revoking thread pauses before its access-token delete (`delete`)."""

    at: str = "refresh"
    arrived: threading.Event = field(default_factory=threading.Event)
    release: threading.Event = field(default_factory=threading.Event)

    def pause(self) -> None:
        self.arrived.set()
        if not self.release.wait(_WAIT):
            msg = "gate never released"
            raise TimeoutError(msg)


class _Worker(threading.Thread):
    """Runs `target` on its own database connection, keeping its result or
    exception."""

    def __init__(self, name: str, target: Callable[[], object]) -> None:
        super().__init__(name=name, daemon=True)
        self._target_fn = target
        self.result: object = None
        self.error: BaseException | None = None

    def run(self) -> None:
        try:
            self.result = self._target_fn()
        except BaseException as exc:  # noqa: BLE001 - reported by the test
            self.error = exc
        finally:
            connections.close_all()

    def finish(self) -> object:
        self.join(_WAIT)
        assert not self.is_alive(), f"{self.name} did not finish"
        if self.error is not None:
            raise self.error
        return self.result


def _until(condition: Callable[[], bool], what: str) -> None:
    deadline = time.monotonic() + _WAIT
    while not condition():
        if time.monotonic() > deadline:
            msg = f"timed out waiting for {what}"
            raise AssertionError(msg)
        time.sleep(0.01)


def _someone_waits_on_a_lock() -> bool:
    """Another backend of this database is blocked on a lock."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM pg_stat_activity "
            "WHERE datname = current_database() AND pid <> pg_backend_pid() "
            "AND wait_event_type = 'Lock'"
        )
        return bool(cursor.fetchone()[0])


@contextlib.contextmanager
def _gates(monkeypatch) -> Iterator[dict[str, _Gate]]:
    """Pause points keyed by thread name: a rotating thread pauses inside
    its token transaction, the revoking thread before its access-token
    delete. Every gate is released on the way out, so nothing hangs."""
    gates: dict[str, _Gate] = {}
    real_delete = QuerySet.delete

    def pausing(at: str, real: Callable[..., object]) -> Callable[..., object]:
        def method(self, *args, **kwargs):
            gate = gates.get(threading.current_thread().name)
            if gate is not None and gate.at == at:
                gate.pause()
            return real(self, *args, **kwargs)

        return method

    for at, name in (
        ("save", "save_bearer_token"),
        ("access", "_create_access_token"),
        ("refresh", "_create_refresh_token"),
    ):
        monkeypatch.setattr(
            MCPOAuth2Validator, name, pausing(at, getattr(MCPOAuth2Validator, name))
        )

    def delete(self):
        gate = gates.get(threading.current_thread().name)
        if gate is not None and gate.at == "delete" and self.model is AccessToken:
            gate.pause()
        return real_delete(self)

    monkeypatch.setattr(QuerySet, "delete", delete)
    try:
        yield gates
    finally:
        for gate in gates.values():
            gate.release.set()


def _rotate(refresh_token: str) -> Callable[[], object]:
    return lambda: refresh(Client(), refresh_token)


def _exchange_in_thread(code: str, verifier: str) -> Callable[[], object]:
    return lambda: exchange(Client(), code, verifier)


def _no_token_left(user) -> bool:
    return not (
        AccessToken.objects.filter(user=user).exists()
        or RefreshToken.objects.filter(user=user).exists()
    )


def _refused(response) -> bool:
    """`invalid_grant`, answered as oauthlib answers it (JSON, no-store)."""
    return (
        response.status_code == HTTPStatus.BAD_REQUEST
        and response["Content-Type"] == "application/json"
        and response["Cache-Control"] == "no-store"
        and response.json()["error"] == "invalid_grant"
    )


def _change_password(user_pk: int) -> Callable[[], None]:
    def change() -> None:
        # Autocommit: the deferred revocation runs right after the save, in
        # this thread, on this thread's connection.
        user = get_user_model()._base_manager.get(pk=user_pk)
        user.set_password("a-new-password-after-a-race")
        user.save()

    return change


def test_rotations_racing_a_password_change_leave_no_live_token(
    client, mcp_user, monkeypatch
):
    """Rotation A (R1 -> R2) is in flight when the revocation starts;
    rotation B (R2 -> R3) starts after A commits, before the revocation's
    access-token delete. Nothing of the chain may survive, and B must not
    hand out a working token."""
    first = consent_and_exchange(client, mcp_user)

    with _gates(monkeypatch) as gates:
        gates["rotate-a"] = gate_a = _Gate()
        gates["revoke"] = gate_t = _Gate(at="delete")
        gates["rotate-b"] = gate_b = _Gate()

        rotate_a = _Worker("rotate-a", _rotate(first["refresh_token"]))
        rotate_a.start()
        assert gate_a.arrived.wait(_WAIT), "rotation A never reached its pause"

        # A holds the lock on R1 (and its new access token is written, not
        # committed). The revocation starts and blocks behind it.
        revoke = _Worker("revoke", _change_password(mcp_user.pk))
        revoke.start()
        _until(_someone_waits_on_a_lock, "the revocation to block behind A")

        gate_a.release.set()
        second = rotate_a.finish()
        assert second.status_code == HTTPStatus.OK, second.content
        r2 = second.json()["refresh_token"]
        assert gate_t.arrived.wait(_WAIT), "revocation never reached its pause"

        # Rotation B starts from R2 while the revocation is paused before its
        # access-token delete; it either pauses inside its own transaction or
        # blocks on a lock the revocation holds.
        rotate_b = _Worker("rotate-b", _rotate(r2))
        rotate_b.start()
        _until(
            lambda: gate_b.arrived.is_set() or _someone_waits_on_a_lock(),
            "rotation B to pause or block",
        )

        gate_t.release.set()
        _until(
            lambda: not revoke.is_alive() or _someone_waits_on_a_lock(),
            "the revocation to finish or block behind B",
        )
        gate_b.release.set()
        revoke.finish()
        third = rotate_b.finish()

    survivors = {
        "access": AccessToken.objects.filter(user=mcp_user).count(),
        "refresh": RefreshToken.objects.filter(user=mcp_user).count(),
    }
    assert survivors == {"access": 0, "refresh": 0}, (
        f"tokens survived the revocation: {survivors}; "
        f"rotation B answered {third.status_code}"
    )
    assert _refused(third), third.content
    # And nothing the chain ever produced still refreshes.
    for token in (first["refresh_token"], r2):
        assert refresh(client, token).json()["error"] == "invalid_grant"
    assert not MCPRefreshTokenFamily.objects.exists()


def test_a_rotation_validated_before_a_revocation_is_refused_after_it(
    client, mcp_user, monkeypatch
):
    """`validate_refresh_token` runs before the rotation's transaction; a
    password change committing in between must leave it nothing to mint
    from (the chain's consent record is gone)."""
    first = consent_and_exchange(client, mcp_user)
    with _gates(monkeypatch) as gates:
        gates["rotate"] = gate = _Gate(at="save")
        rotate = _Worker("rotate", _rotate(first["refresh_token"]))
        rotate.start()
        assert gate.arrived.wait(_WAIT)
        _change_password(mcp_user.pk)()
        assert _no_token_left(mcp_user)
        gate.release.set()
        response = rotate.finish()
    assert _no_token_left(mcp_user)
    assert _refused(response), response.content


@pytest.mark.parametrize(
    "refresh_enabled", [True, False], ids=["refresh-on", "refresh-off"]
)
def test_an_exchange_validated_before_a_revocation_is_refused_after_it(
    client, mcp_user, monkeypatch, settings, refresh_enabled
):
    """The code was checked (`validate_code`) before the revocation deleted
    it; the exchange must not mint tokens from it afterwards. Before, it
    did, and only the code's own deletion failed afterwards (the tokens
    stayed, undelivered)."""
    if not refresh_enabled:
        settings.MCP_SQL = {**settings.MCP_SQL, "REFRESH_TOKEN_MAX_AGE_SECONDS": 0}
    code, verifier = consent(client, mcp_user)
    with _gates(monkeypatch) as gates:
        gates["exchange"] = gate = _Gate(at="save")
        exchange = _Worker("exchange", _exchange_in_thread(code, verifier))
        exchange.start()
        assert gate.arrived.wait(_WAIT)
        _change_password(mcp_user.pk)()
        gate.release.set()
        response = exchange.finish()
    assert _no_token_left(mcp_user)
    assert _refused(response), response.content


@pytest.mark.parametrize(
    "refresh_enabled", [True, False], ids=["refresh-on", "refresh-off"]
)
def test_an_exchange_in_flight_when_a_revocation_starts_loses_its_tokens(
    client, mcp_user, monkeypatch, settings, refresh_enabled
):
    """The exchange holds its code's lock, its access token about to be
    written, when the password change's revocation starts: the revocation
    waits for it, and its tokens are deleted with the rest."""
    if not refresh_enabled:
        settings.MCP_SQL = {**settings.MCP_SQL, "REFRESH_TOKEN_MAX_AGE_SECONDS": 0}
    code, verifier = consent(client, mcp_user)
    with _gates(monkeypatch) as gates:
        gates["exchange"] = gate = _Gate(at="access")
        exchange = _Worker("exchange", _exchange_in_thread(code, verifier))
        exchange.start()
        assert gate.arrived.wait(_WAIT)
        revoke = _Worker("revoke", _change_password(mcp_user.pk))
        revoke.start()
        _until(
            lambda: _someone_waits_on_a_lock() or not revoke.is_alive(),
            "the revocation to block behind it",
        )
        gate.release.set()
        response = exchange.finish()
        revoke.finish()
    # Whichever deleted the code first, nothing the exchange minted is left:
    # it either answered with tokens since deleted, or was refused.
    assert _no_token_left(mcp_user)
    assert response.status_code == HTTPStatus.OK or _refused(response)


def test_concurrent_refreshes_of_one_token_share_the_rotation(
    client, mcp_user, monkeypatch
):
    """Two refreshes of the same token, both validated before either saves
    (a client firing two at once), serialize on the chain's consent record:
    the later gets the earlier's tokens, and reuse protection does not see
    a replay (docs/oauth.md → "Refresh tokens (opt-in)")."""
    first = consent_and_exchange(client, mcp_user)
    with _gates(monkeypatch) as gates:
        gates["rotate-a"] = gate_a = _Gate()
        gates["rotate-b"] = gate_b = _Gate(at="save")
        rotate_a = _Worker("rotate-a", _rotate(first["refresh_token"]))
        rotate_b = _Worker("rotate-b", _rotate(first["refresh_token"]))
        rotate_a.start()
        assert gate_a.arrived.wait(_WAIT)
        rotate_b.start()
        assert gate_b.arrived.wait(_WAIT)  # B validated; A has not committed
        gate_b.release.set()
        _until(_someone_waits_on_a_lock, "B to block behind A")
        gate_a.release.set()
        a, b = rotate_a.finish(), rotate_b.finish()
    assert a.status_code == b.status_code == HTTPStatus.OK, (a.content, b.content)
    assert a.json()["refresh_token"] == b.json()["refresh_token"]
    assert a.json()["access_token"] == b.json()["access_token"]
    assert refresh(client, a.json()["refresh_token"]).status_code == HTTPStatus.OK
