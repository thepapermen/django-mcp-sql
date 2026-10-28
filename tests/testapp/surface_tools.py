"""The tool surface the package's own tests mount (`tests/conftest.py`'s
`tool_surface` fixture): a few small tools, each exercising one property of
`mcp_sql.surfaces` — no consumer imports."""

from typing import Any

from mcp_sql.surfaces import SurfaceContext
from mcp_sql.surfaces import SurfaceServer
from mcp_sql.surfaces import ToolError
from mcp_sql.surfaces import fence_untrusted
from mcp_sql.tests.testapp.models import Widget

# Text a failing tool raises; the tests assert it never reaches the agent.
INTERNAL_FAILURE_DETAIL = "internal detail that must stay on the server"


def register(server: SurfaceServer, ctx: SurfaceContext) -> None:
    @server.tool(
        title="Echo",
        read_only=True,
        destructive=False,
        idempotent=True,
        open_world=False,
    )
    async def echo(text: str) -> dict[str, Any]:
        """Return `text` with the caller's user pk."""
        return {"text": text, "user_pk": ctx.user.pk}

    @server.tool(
        title="Add a widget",
        read_only=False,
        destructive=False,
        idempotent=False,
        open_world=False,
    )
    async def add_widget(name: str) -> dict[str, Any]:
        """Create a widget through the ORM (off the event loop)."""
        widget = await ctx.run_sync(Widget.objects.create, name=name)
        return {"id": widget.pk, "count": await ctx.run_sync(Widget.objects.count)}

    @server.tool(
        title="Quote",
        read_only=True,
        destructive=False,
        idempotent=True,
        open_world=True,
    )
    async def quote(text: str) -> dict[str, Any]:
        """Return `text` as third-party content, fenced."""
        return {"length": len(text), **fence_untrusted(text)}

    @server.tool(
        title="Refuse",
        read_only=True,
        destructive=False,
        idempotent=True,
        open_world=False,
    )
    async def refuse() -> str:
        """Fail with a message meant for the agent."""
        msg = "refused on purpose"
        raise ToolError(msg)

    @server.tool(
        title="Break",
        read_only=True,
        destructive=False,
        idempotent=True,
        open_world=False,
    )
    async def explode() -> str:
        """Fail with an unexpected exception."""
        raise RuntimeError(INTERNAL_FAILURE_DETAIL)


# A non-callable a validation test points `TOOLS` at.
NOT_CALLABLE = "not a function"
