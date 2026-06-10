"""Tests for `decorators.cap_request_body` — the 64 KiB body cap on the
package's OAuth endpoints.

The header check is enough on its own (Django's `LimitedStream` truncates an
under-declared body to the lie), so these tests drive the decorator off
`CONTENT_LENGTH` directly. The `/mcp/sql/` cap (1 MiB, separate) lives in the
auth class and is covered by `test_auth_class.py::TestBodySizeCap`.
"""

from http import HTTPStatus

import pytest
from django.http import HttpResponse
from django.test import RequestFactory
from django.urls import reverse

from mcp_sql.decorators import OAUTH_REQUEST_BODY_MAX_BYTES
from mcp_sql.decorators import cap_request_body
from mcp_sql.decorators import normalize_content_length


def _stub_view(request):
    return HttpResponse("ok")


class TestCapRequestBody:
    def test_oversize_content_length_returns_413(self):
        calls = []
        wrapped = cap_request_body()(lambda r: calls.append(r) or HttpResponse("ok"))
        request = RequestFactory().post("/o/register")
        request.META["CONTENT_LENGTH"] = str(OAUTH_REQUEST_BODY_MAX_BYTES + 1)
        response = wrapped(request)
        assert response.status_code == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
        assert calls == []  # view never ran — rejected before the body read

    def test_exactly_at_cap_passes(self):
        wrapped = cap_request_body()(_stub_view)
        request = RequestFactory().post("/o/register")
        request.META["CONTENT_LENGTH"] = str(OAUTH_REQUEST_BODY_MAX_BYTES)
        response = wrapped(request)
        assert response.status_code == HTTPStatus.OK

    def test_under_cap_passes_through(self):
        wrapped = cap_request_body()(_stub_view)
        request = RequestFactory().post("/o/register")
        request.META["CONTENT_LENGTH"] = "100"
        assert wrapped(request).status_code == HTTPStatus.OK

    def test_missing_content_length_passes(self):
        wrapped = cap_request_body()(_stub_view)
        request = RequestFactory().get("/o/authorize/")
        request.META.pop("CONTENT_LENGTH", None)
        assert wrapped(request).status_code == HTTPStatus.OK

    def test_malformed_content_length_treated_as_zero(self):
        # Malformed → treated as 0 (so it passes the cap) and normalised in
        # place so Django's later `int(CONTENT_LENGTH)` body handling can't
        # raise. Assert via the return value + a safe body read — NOT via
        # `request.headers`, a cached_property that wouldn't reflect the
        # in-place META rewrite.
        request = RequestFactory().post(
            "/o/register", data=b"", content_type="application/json"
        )
        request.META["CONTENT_LENGTH"] = "not-an-int"
        assert normalize_content_length(request) == 0
        assert request.body == b""  # would raise ValueError without the rewrite

    def test_custom_max_bytes(self):
        wrapped = cap_request_body(max_bytes=100)(_stub_view)
        request = RequestFactory().post("/o/register")
        request.META["CONTENT_LENGTH"] = "101"
        assert wrapped(request).status_code == HTTPStatus.REQUEST_ENTITY_TOO_LARGE

    def test_csrf_exempt_preserved_on_dot_cbv_as_view(self):
        # Production wraps CBV `.as_view()` results (DOT's TokenView /
        # RevokeTokenView), not plain functions. DOT exempts via
        # `@method_decorator(csrf_exempt, name="dispatch")`, which
        # `View.as_view()` copies onto the view fn's __dict__; `functools.wraps`
        # must propagate it through the cap wrapper, or wrapping would re-arm
        # CSRF and break the token POST. Assert against the real shape.
        from oauth2_provider import views as oauth2_views

        wrapped = cap_request_body()(oauth2_views.TokenView.as_view())
        assert getattr(wrapped, "csrf_exempt", False) is True

    def test_non_exempt_view_stays_non_exempt(self):
        wrapped = cap_request_body()(_stub_view)
        assert getattr(wrapped, "csrf_exempt", False) is False


@pytest.mark.django_db
class TestCapAppliedToOAuthEndpoint:
    def test_oversize_post_to_register_is_413(self, client):
        # Real body just over the cap → truthful CONTENT_LENGTH → 413 from the
        # decorator, before the registration view (or its DB writes) runs.
        response = client.post(
            reverse("oauth_dynamic_client_registration"),
            data="x" * (OAUTH_REQUEST_BODY_MAX_BYTES + 1),
            content_type="application/json",
        )
        assert response.status_code == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
