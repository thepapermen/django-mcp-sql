"""Revocation racing refresh-token rotations, on real PostgreSQL connections.

A logout / password change deletes the user's MCP tokens
(`signals._revoke_and_audit`) while the user's MCP client may be rotating
its refresh token on another connection. Under READ COMMITTED each delete
sees only rows committed before it starts, so a rotation that commits
during the refresh-token delete, followed by a second one that straddles the
access-token delete, used to leave a live refresh / access pair behind — and
the revocation was logged as complete. Also here: two exchanges of one
code, and the revocation's lock order against an exchange's prune of
expired consent records, DOT's `/o/revoke_token/` and DOT's `cleartokens`
(deadlocks, and the retry that answers the one the package cannot avoid).

The interleaving is forced, not hoped for: rotations pause inside their
token transaction (`_create_refresh_token`, after DOT has locked and revoked
the presented refresh token and inserted the new access token), the
revocation pauses before its access-token delete, and the test waits on
`pg_stat_activity` to see a connection blocked on a row lock before it lets
the holder go on. Every wait is bounded, so a regression fails instead of
hanging.
"""

import contextlib
import hashlib
import logging
import threading
import time
from collections.abc import Callable
from collections.abc import Iterator
from dataclasses import dataclass
from dataclasses import field
from datetime import timedelta
from http import HTTPStatus

import pytest
from django.conf import settings as django_settings
from django.contrib.auth import get_user_model
from django.db import DatabaseError
from django.db import OperationalError
from django.db import connection
from django.db import connections
from django.db import transaction
from django.db.models.query import QuerySet
from django.test import Client
from django.urls import reverse
from django.utils import timezone
from mcp_sql import oauth
from mcp_sql.models import MCPAuthRejectionLog
from mcp_sql.models import MCPRefreshTokenFamily
from mcp_sql.oauth import MCPOAuth2Validator
from mcp_sql.tests.refresh_flow import CAP
from mcp_sql.tests.refresh_flow import consent
from mcp_sql.tests.refresh_flow import consent_and_exchange
from mcp_sql.tests.refresh_flow import exchange
from mcp_sql.tests.refresh_flow import refresh
from oauth2_provider.models import AccessToken
from oauth2_provider.models import Grant
from oauth2_provider.models import RefreshToken
from oauth2_provider.models import clear_expired
from oauthlib.common import Request as OAuthlibRequest
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.usefixtures("mcp_mfa_on", "mcp_app"),
]

_WAIT = 15  # seconds; any single step of the choreography
SECOND = getattr(django_settings, "SECOND_DB_ALIAS", "second")


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
    `save_bearer_token` (validated, before its transaction), inside that
    transaction just before the new access / refresh token is written, or
    once it has returned, on entering `invalidate_authorization_code`
    (`invalidate`); the revoking thread pauses before its access-token
    delete (`delete`); a refresh token's revocation (`RefreshToken.revoke`)
    pauses with the refresh token locked, before its access token's
    (`revoke-access`)."""

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


_Gates = dict[str | tuple[str, str], _Gate]


def _gate_at(gates: _Gates, at: str) -> _Gate | None:
    """The current thread's gate at `at`: keyed by `(thread name, at)`
    (a thread pausing at more than one point) or by the thread name."""
    name = threading.current_thread().name
    gate = gates.get((name, at)) or gates.get(name)
    return gate if gate is not None and gate.at == at else None


@contextlib.contextmanager
def _gates(monkeypatch) -> Iterator[_Gates]:
    """Pause points keyed by thread name (or thread name and point): a
    rotating thread pauses inside its token transaction, the revoking
    thread before its access-token delete. Every gate is released on the
    way out, so nothing hangs."""
    gates: _Gates = {}
    real_delete = QuerySet.delete

    def pausing(at: str, real: Callable[..., object]) -> Callable[..., object]:
        def method(self, *args, **kwargs):
            gate = _gate_at(gates, at)
            if gate is not None:
                gate.pause()
            return real(self, *args, **kwargs)

        return method

    for at, name in (
        ("save", "save_bearer_token"),
        ("access", "_create_access_token"),
        ("refresh", "_create_refresh_token"),
        ("invalidate", "invalidate_authorization_code"),
    ):
        monkeypatch.setattr(
            MCPOAuth2Validator, name, pausing(at, getattr(MCPOAuth2Validator, name))
        )
    monkeypatch.setattr(
        AccessToken, "revoke", pausing("revoke-access", AccessToken.revoke)
    )

    def delete(self):
        gate = _gate_at(gates, "delete")
        if gate is not None and self.model is AccessToken:
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


def _backend_pid() -> int:
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_backend_pid()")
        return cursor.fetchone()[0]


def _blockers(pid: int) -> set[int]:
    """The backends `pid` is waiting for (empty when it waits for none)."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_blocking_pids(%s)", [pid])
        return set(cursor.fetchone()[0])


def _by_index(pids: dict[str, int], target: Callable[[], object]):
    """`target`, on a connection that plans its family-row statements as a
    large table does (an index scan: the revocation's `token_family IN`
    in primary-key order, the prune's `consented_at <=` in time order), its
    backend pid recorded under the thread's name."""

    def run() -> object:
        with connection.cursor() as cursor:
            cursor.execute("SET enable_seqscan = off")
            cursor.execute("SET enable_bitmapscan = off")
        pids[threading.current_thread().name] = _backend_pid()
        return target()

    return run


@contextlib.contextmanager
def _row_held(token_family) -> Iterator[tuple[Callable[[], None], int]]:
    """A transaction on a connection of its own holding the family row's
    lock; yields a callable ending it (a rollback) and its backend pid."""
    holder = connections.create_connection("default")
    try:
        with holder.cursor() as cursor:
            cursor.execute("SELECT pg_backend_pid()")
            pid = cursor.fetchone()[0]
            cursor.execute("BEGIN")
            cursor.execute(
                f"SELECT 1 FROM {MCPRefreshTokenFamily._meta.db_table} "  # noqa: S608
                "WHERE token_family = %s FOR UPDATE",
                [token_family],
            )

        def release() -> None:
            with holder.cursor() as cursor:
                cursor.execute("ROLLBACK")

        yield release, pid
    finally:
        holder.close()


def test_a_revocation_never_deadlocks_with_a_concurrent_prune(  # noqa: PLR0913
    client, mcp_user, mcp_user_factory, use_mcp_perm, monkeypatch, caplog
):
    """Another user's exchange prunes family records past the cap
    (`oauth._record_refresh_family`) while a revocation deletes the revoked
    user's records — two statements over the same rows (the revoked user's
    expired chains). Taking them in opposite orders (the prune by
    `consented_at`, the revocation by `token_family`) deadlocked; whichever
    PostgreSQL aborted, a revocation that was only logged (the user's
    tokens living on) or a 500 on the exchange; the revocation now retries
    a deadlock, but none may happen. Forced here: two records,
    the older with the greater `token_family`, each held by a transaction
    of the test's until both statements wait on them."""
    for _ in range(2):
        consent_and_exchange(client, mcp_user)
    older, newer = sorted(
        RefreshToken.objects.filter(user=mcp_user).values_list(
            "token_family", flat=True
        ),
        reverse=True,
    )
    expired = timezone.now() - timedelta(seconds=2 * CAP)
    MCPRefreshTokenFamily.objects.filter(token_family=older).update(
        consented_at=expired
    )
    MCPRefreshTokenFamily.objects.filter(token_family=newer).update(
        consented_at=expired + timedelta(seconds=1)
    )
    other = mcp_user_factory(is_active=True, is_staff=True)
    other.user_permissions.add(use_mcp_perm)
    code, verifier = consent(Client(), other)

    pids: dict[str, int] = {}
    with (
        caplog.at_level(logging.WARNING, logger="mcp_sql.signals"),
        _row_held(older) as (release_older, _),
        _row_held(newer) as (release_newer, newer_holder),
    ):
        revoke = _Worker("revoke", _by_index(pids, _change_password(mcp_user.pk)))
        revoke.start()
        _until(
            lambda: "revoke" in pids and _blockers(pids["revoke"]),
            "the revocation to wait on the newer record",
        )
        prune = _Worker("prune", _by_index(pids, _exchange_in_thread(code, verifier)))
        prune.start()
        _until(
            lambda: not prune.is_alive()
            or ("prune" in pids and _blockers(pids["prune"])),
            "the prune to finish or wait on the older record",
        )
        release_newer()
        _until(
            lambda: not revoke.is_alive()
            or (_blockers(pids["revoke"]) - {newer_holder}),
            "the revocation to take the newer record and wait for the older",
        )
        release_older()
        revoke.finish()
        response = prune.finish()

    assert response.status_code == HTTPStatus.OK, response.content
    assert "deadlock" not in caplog.text  # not even one retried
    assert _no_token_left(mcp_user)
    assert not MCPRefreshTokenFamily.objects.filter(
        token_family__in=[older, newer]
    ).exists()


@pytest.mark.parametrize(
    "refresh_enabled", [True, False], ids=["refresh-on", "refresh-off"]
)
def test_two_exchanges_of_one_code_mint_one_token_pair(
    client, mcp_user, monkeypatch, settings, refresh_enabled
):
    """Exchange A holds the code's lock, its tokens about to be written;
    exchange B of the same code was validated before A committed and waits
    for the lock. oauthlib deletes the code only after `save_token` returns
    (`invalidate_authorization_code`): B took the lock in between, found
    the code and minted a second pair, then A's delete of the code failed —
    one response `invalid_grant`, both pairs live. The code is consumed in
    A's saving transaction now: B finds none and mints nothing."""
    if not refresh_enabled:
        settings.MCP_SQL = {**settings.MCP_SQL, "REFRESH_TOKEN_MAX_AGE_SECONDS": 0}
    code, verifier = consent(client, mcp_user)
    with _gates(monkeypatch) as gates:
        gates[("a", "access")] = a_saving = _Gate(at="access")
        gates[("a", "invalidate")] = a_saved = _Gate(at="invalidate")
        gates["b"] = b_validated = _Gate(at="save")
        a = _Worker("a", _exchange_in_thread(code, verifier))
        b = _Worker("b", _exchange_in_thread(code, verifier))
        a.start()
        assert a_saving.arrived.wait(_WAIT)
        b.start()
        assert b_validated.arrived.wait(_WAIT)  # the code is still there
        b_validated.release.set()
        _until(_someone_waits_on_a_lock, "B to wait for the code's lock")
        a_saving.release.set()
        # A's transaction has committed; B gets the lock now.
        assert a_saved.arrived.wait(_WAIT)
        _until(lambda: not b.is_alive(), "B to answer")
        a_saved.release.set()
        responses = [a.finish(), b.finish()]

    ok = [r for r in responses if r.status_code == HTTPStatus.OK]
    assert len(ok) == 1, [r.content for r in responses]
    assert sum(_refused(r) for r in responses) == 1, [r.content for r in responses]
    minted = AccessToken.objects.filter(user=mcp_user)
    assert minted.count() == 1
    assert (
        minted.get().token_checksum
        == hashlib.sha256(ok[0].json()["access_token"].encode()).hexdigest()
    )
    assert RefreshToken.objects.filter(user=mcp_user).count() == int(refresh_enabled)
    assert not Grant.objects.filter(user=mcp_user).exists()


def test_a_code_exchanges_once(client, mcp_user):
    """The plain replay: the code the first exchange consumed is gone for
    the second, which `invalidate_authorization_code` never accepts as this
    request's own."""
    code, verifier = consent(client, mcp_user)
    assert exchange(client, code, verifier).status_code == HTTPStatus.OK
    assert _refused(exchange(client, code, verifier))
    assert AccessToken.objects.filter(user=mcp_user).count() == 1


def test_an_openid_spelled_exchange_locks_its_code(client, mcp_user):
    """oauthlib's authorization-code grant also answers `grant_type=openid`;
    an exchange in that spelling locks the code it names like any other
    (DOT 3.4.1 asserts the spelling away earlier, in `validate_grant_type`),
    and is refused once that code is gone."""
    code, _verifier = consent(client, mcp_user)
    grant = Grant.objects.get(code=code)
    request = OAuthlibRequest("https://testserver/o/token/")
    request.grant_type = "openid"
    request.code = code
    request.client = grant.application
    with transaction.atomic():
        oauth._lock_token_source(request, "default")
    grant.delete()
    with transaction.atomic(), pytest.raises(InvalidGrantError):
        oauth._lock_token_source(request, "default")


def test_an_openid_spelled_save_consumes_its_code(client, mcp_user, monkeypatch):
    """The save treats `openid` as the code exchange it is: it deletes the
    code in its own transaction and records the refresh chain's consent."""
    code, verifier = consent(client, mcp_user)
    real = MCPOAuth2Validator.save_bearer_token
    seen = {}

    def as_openid(self, token, request, *args, **kwargs):
        request.grant_type = "openid"
        result = real(self, token, request, *args, **kwargs)
        seen["code_left"] = Grant.objects.filter(code=code).exists()
        return result

    monkeypatch.setattr(MCPOAuth2Validator, "save_bearer_token", as_openid)
    assert exchange(client, code, verifier).status_code == HTTPStatus.OK
    assert seen == {"code_left": False}
    family = RefreshToken.objects.get(user=mcp_user).token_family
    assert MCPRefreshTokenFamily.objects.filter(token_family=family).exists()


def test_a_failed_save_does_not_burn_the_code(client, mcp_user, monkeypatch):
    """The code is deleted in the transaction that saves the tokens: a save
    that fails afterwards rolls the delete back with them, and the code
    still exchanges."""
    code, verifier = consent(client, mcp_user)
    real = MCPOAuth2Validator._create_access_token
    calls = []

    def failing_once(self, *args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            msg = "the database went away"
            raise DatabaseError(msg)
        return real(self, *args, **kwargs)

    monkeypatch.setattr(MCPOAuth2Validator, "_create_access_token", failing_once)
    with pytest.raises(DatabaseError):
        exchange(client, code, verifier)
    assert Grant.objects.filter(user=mcp_user).exists()
    assert exchange(client, code, verifier).status_code == HTTPStatus.OK
    assert AccessToken.objects.filter(user=mcp_user).count() == 1


def test_invalidating_a_code_this_request_did_not_consume_is_refused(mcp_user, mcp_app):
    """`invalidate_authorization_code` accepts only the code the request's
    own save consumed; a missing code is otherwise DOT's `invalid_grant` —
    also when the client sends the mark's name as a parameter (oauthlib's
    `Request` answers unknown attributes from its parameters)."""
    from oauthlib.common import Request
    from oauthlib.oauth2.rfc6749.errors import InvalidGrantError

    validator = MCPOAuth2Validator()
    request = Request(
        "https://testserver/o/token/?_mcp_sql_consumed_code=gone",
        http_method="POST",
        body="_mcp_sql_consumed_code=gone",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    request.client = mcp_app
    assert request._mcp_sql_consumed_code == "gone"  # the parameter
    with pytest.raises(InvalidGrantError):
        validator.invalidate_authorization_code("mcp-sql", "gone", request)
    request._mcp_sql_consumed_code = "another"
    with pytest.raises(InvalidGrantError):
        validator.invalidate_authorization_code("mcp-sql", "gone", request)
    request._mcp_sql_consumed_code = "gone"
    validator.invalidate_authorization_code("mcp-sql", "gone", request)


def _revoke_endpoint(refresh_token: str) -> Callable[[], object]:
    return lambda: Client().post(
        reverse("revoke-token"),
        {
            "token": refresh_token,
            "token_type_hint": "refresh_token",
            "client_id": "mcp-sql",
        },
    )


def test_a_revocation_waits_for_an_rfc7009_revocation_without_deadlocking(
    client, mcp_user, monkeypatch, caplog
):
    """The client revokes its rotated refresh token R2 at `/o/revoke_token/`
    (DOT's `RefreshToken.revoke`: R2 locked, then its access token deleted)
    while a password change revokes everything. The revocation locks the
    user's refresh tokens before it touches an access token, as DOT does;
    deleting them unlocked instead nulled their successors' link first
    (`AccessToken.source_refresh_token`), locking R2's access token while
    waiting for R2: a deadlock, and either the endpoint answered 500 or the
    revocation was only logged (now: retried — but none may happen)."""
    first = consent_and_exchange(client, mcp_user)
    r2 = refresh(client, first["refresh_token"]).json()["refresh_token"]
    with (
        caplog.at_level(logging.WARNING, logger="mcp_sql.signals"),
        _gates(monkeypatch) as gates,
    ):
        gates["endpoint"] = holding_r2 = _Gate(at="revoke-access")
        endpoint = _Worker("endpoint", _revoke_endpoint(r2))
        endpoint.start()
        assert holding_r2.arrived.wait(_WAIT)
        revoke = _Worker("revoke", _change_password(mcp_user.pk))
        revoke.start()
        _until(_someone_waits_on_a_lock, "the revocation to wait for R2")
        holding_r2.release.set()
        response = endpoint.finish()
        revoke.finish()
    assert response.status_code == HTTPStatus.OK, response.content
    assert "deadlock" not in caplog.text
    assert _no_token_left(mcp_user)


def test_a_revocation_locks_no_application_row(
    client, mcp_user, mcp_user_factory, use_mcp_perm, monkeypatch
):
    """The refresh-token lock covers the refresh-token rows only
    (`of=("self",)`): the query joins the Application, and a lock on its
    row blocked every token insert for that client (the foreign-key check
    takes a share lock on it) — every user's exchange and rotation waited
    for the revocation to finish."""
    consent_and_exchange(client, mcp_user)
    other = mcp_user_factory(is_active=True, is_staff=True)
    other.user_permissions.add(use_mcp_perm)
    code, verifier = consent(Client(), other)
    with _gates(monkeypatch) as gates:
        gates["revoke"] = paused = _Gate(at="delete")
        revoke = _Worker("revoke", _change_password(mcp_user.pk))
        revoke.start()
        assert paused.arrived.wait(_WAIT)  # its refresh-token lock is taken
        other_exchange = _Worker("other", _exchange_in_thread(code, verifier))
        other_exchange.start()
        _until(
            lambda: not other_exchange.is_alive() or _someone_waits_on_a_lock(),
            "the other user's exchange to finish or wait",
        )
        blocked = other_exchange.is_alive()
        paused.release.set()
        revoke.finish()
        response = other_exchange.finish()
    assert not blocked, "another user's exchange waited for the revocation"
    assert response.status_code == HTTPStatus.OK, response.content
    assert _no_token_left(mcp_user)


class _ConsentRecordsOnSecond:
    """The consent records on the second database, DOT's tokens on the
    default one."""

    def _route(self, model):
        return SECOND if model is MCPRefreshTokenFamily else None

    def db_for_read(self, model, **hints):
        return self._route(model)

    def db_for_write(self, model, **hints):
        return self._route(model)


@pytest.mark.skipif(
    SECOND not in django_settings.DATABASES,
    reason="needs the second database alias of the package's test settings",
)
@pytest.mark.django_db(transaction=True, databases=["default", SECOND])
def test_a_rotation_holds_its_consent_record_until_its_tokens_commit(
    client, mcp_user, monkeypatch, settings
):
    """With the consent records on another database than the tokens, the
    rotation's transaction on the records must commit last: its lock on the
    chain's record is what a revocation's delete of the record waits on, so
    the revocation can see the new tokens once it has the record. Checked
    the moment the tokens have committed: the record is still locked."""
    settings.DATABASE_ROUTERS = [
        f"{__name__}.{_ConsentRecordsOnSecond.__name__}",
        "mcp_sql.db_router.McpSqlRouter",
    ]
    first = consent_and_exchange(client, mcp_user)
    family = MCPRefreshTokenFamily.objects.using(SECOND).get().token_family
    tokens_committed = _Gate()
    real_lock = oauth._lock_token_source

    def locking(request, using):
        real_lock(request, using)
        if threading.current_thread().name == "rotate":
            transaction.on_commit(tokens_committed.pause, using=using)

    monkeypatch.setattr(oauth, "_lock_token_source", locking)
    try:
        rotate = _Worker("rotate", _rotate(first["refresh_token"]))
        rotate.start()
        assert tokens_committed.arrived.wait(_WAIT)
        with pytest.raises(OperationalError), connections[SECOND].cursor() as cursor:
            cursor.execute(
                f"SELECT 1 FROM {MCPRefreshTokenFamily._meta.db_table} "  # noqa: S608
                "WHERE token_family = %s FOR UPDATE NOWAIT",
                [family],
            )
    finally:
        tokens_committed.release.set()
    assert rotate.finish().status_code == HTTPStatus.OK


def test_a_revocation_racing_cleartokens_still_completes(
    client, mcp_user, monkeypatch, settings
):
    """DOT's `cleartokens` deletes a rotated-out refresh token R1 the user
    still has: in one transaction it nulls the link of R1's successor
    access token (`source_refresh_token`), locking it, then deletes R1 —
    access token, then refresh token, the reverse of DOT's own
    `RefreshToken.revoke`, which the revocation follows. With R1 locked
    and the successor's link to null, the revocation waits for
    `cleartokens`, which then waits for R1: a deadlock PostgreSQL breaks
    by aborting the revocation (it waited first). It is retried, and the
    user's tokens go."""
    settings.OAUTH2_PROVIDER = {
        **settings.OAUTH2_PROVIDER,
        "REFRESH_TOKEN_EXPIRE_SECONDS": CAP,
    }
    first = consent_and_exchange(client, mcp_user)
    assert refresh(client, first["refresh_token"]).status_code == HTTPStatus.OK
    RefreshToken.objects.filter(user=mcp_user, revoked__isnull=False).update(
        revoked=timezone.now() - timedelta(seconds=2 * CAP)
    )
    cleartokens_deleting = _Gate()

    def pause_before_the_refresh_token_delete(execute, sql, params, many, context):
        if sql.startswith(f'DELETE FROM "{RefreshToken._meta.db_table}"'):  # noqa: S608
            cleartokens_deleting.pause()
        return execute(sql, params, many, context)

    def run_cleartokens() -> None:
        with connection.execute_wrapper(pause_before_the_refresh_token_delete):
            clear_expired()

    with contextlib.ExitStack() as stack:
        stack.callback(cleartokens_deleting.release.set)
        cleartokens = _Worker("cleartokens", run_cleartokens)
        cleartokens.start()
        assert cleartokens_deleting.arrived.wait(_WAIT)
        revoke = _Worker("revoke", _change_password(mcp_user.pk))
        revoke.start()
        _until(_someone_waits_on_a_lock, "the revocation to wait for cleartokens")
        cleartokens_deleting.release.set()
        revoke.finish()
        cleartokens.finish()
    assert _no_token_left(mcp_user)


class _DriverError(Exception):
    """A database driver's exception, carrying PostgreSQL's SQLSTATE."""

    def __init__(self, sqlstate: str) -> None:
        super().__init__(sqlstate)
        self.sqlstate = sqlstate


@pytest.mark.parametrize(
    ("failures", "sqlstate", "revoked", "attempts"),
    [
        (2, "40P01", True, 3),  # deadlocks, then it goes through
        (3, "40P01", False, 3),  # the last attempt's deadlock is a failure
        (1, "57014", False, 1),  # anything else is not retried
    ],
    ids=["deadlocked-twice", "deadlocked-every-time", "other-error"],
)
def test_only_a_deadlock_is_retried_and_only_so_often(  # noqa: PLR0913
    client, mcp_user, monkeypatch, caplog, failures, sqlstate, revoked, attempts
):
    consent_and_exchange(client, mcp_user)
    real_delete = QuerySet.delete
    calls = []

    def delete(self):
        if self.model is Grant:
            calls.append(1)
            if len(calls) <= failures:
                error = OperationalError(sqlstate)
                raise error from _DriverError(sqlstate)
        return real_delete(self)

    monkeypatch.setattr(QuerySet, "delete", delete)
    with caplog.at_level(logging.WARNING, logger="mcp_sql.signals"):
        _change_password(mcp_user.pk)()
    assert len(calls) == attempts
    assert _no_token_left(mcp_user) is revoked
    assert MCPAuthRejectionLog.objects.filter(user=mcp_user).exists() is revoked
    retries = [r for r in caplog.records if "deadlock, retrying" in r.getMessage()]
    assert len(retries) == (2 if sqlstate == "40P01" else 0)
    failed = "Failed to revoke MCP tokens on password change" in caplog.text
    assert failed is not revoked
