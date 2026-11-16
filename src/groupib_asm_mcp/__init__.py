"""MCP server for the Group-IB Attack Surface Management API."""

from groupib_asm_mcp.client import AsmError
from groupib_asm_mcp.server import client_from_env, create_server


def main() -> None:
    """Run the MCP server over stdio. Exits at startup if credentials are not configured."""
    try:
        client = client_from_env()
    except AsmError as exc:
        raise SystemExit(str(exc)) from exc
    create_server(client).run("stdio")


__all__ = ["create_server", "main"]
