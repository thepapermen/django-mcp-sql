"""Pure-stock test factory — no consumer-project imports.

The package's own suite must run against whatever `AUTH_USER_MODEL` the
consumer configures (the extractable-package discipline: an extracted
`django-mcp-sql` ships these tests and they must not import a host
project's factory). The `mcp_user_factory` conftest fixture delegates here
so there is a single user-creation path; a consumer wanting richer fixtures
overrides that fixture in their own conftest.
"""

import secrets

from django.contrib.auth import get_user_model


def UserFactory(**kwargs):  # noqa: N802 — factory-cased to mirror factory_boy's UserFactory and keep the `UserFactory()` call convention
    """Create and return a saved user via the configured `AUTH_USER_MODEL`.

    Keyed on the model's `USERNAME_FIELD`, so it works with any user model
    (email-as-username, plain `username`, a custom field) without importing
    a consumer-specific factory. Mirrors the `UserFactory()` call shape the
    package's tests use.
    """
    user_model = get_user_model()
    kwargs.setdefault(
        user_model.USERNAME_FIELD, f"mcp-test-{secrets.token_urlsafe(6)}@example.com"
    )
    kwargs.setdefault("password", "test")
    return user_model.objects.create_user(**kwargs)
