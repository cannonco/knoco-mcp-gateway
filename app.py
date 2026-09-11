import os

from fastmcp import FastMCP
from fastmcp.server.auth.providers.azure import AzureProvider


def required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Required environment variable is missing: {name}")
    return value


def wordpress_server(prefix: str, url: str, token_env: str) -> dict:
    token = required_env(token_env)
    return {
        "transport": "http",
        "url": url,
        "headers": {"Authorization": f"Bearer {token}"},
    }


def build_gateway() -> FastMCP:
    # Protect the public gateway with Microsoft Entra ID. These values are
    # supplied as Azure Container App secrets/environment variables and are
    # never committed to GitHub.
    auth = AzureProvider(
        client_id=required_env("AZURE_MCP_CLIENT_ID"),
        client_secret=required_env("AZURE_MCP_CLIENT_SECRET"),
        tenant_id=required_env("AZURE_MCP_TENANT_ID"),
        base_url=required_env("MCP_PUBLIC_BASE_URL"),
        required_scopes=["mcp-access"],
        additional_authorize_scopes=["openid", "profile", "email", "offline_access"],
    )

    upstream_config = {
        "mcpServers": {
            "knoco_main": wordpress_server(
                "knoco_main",
                "https://knoco.com/wp-json/easy-mcp-ai/v1/mcp",
                "KNOCO_MAIN_TOKEN",
            ),
            "knoco_institute": wordpress_server(
                "knoco_institute",
                "https://institute.knoco.com/wp-json/easy-mcp-ai/v1/mcp",
                "KNOCO_INSTITUTE_TOKEN",
            ),
            "knoco_trainingtest": wordpress_server(
                "knoco_trainingtest",
                "https://trainingtest.knoco.com/wp-json/easy-mcp-ai/v1/mcp",
                "KNOCO_TRAININGTEST_TOKEN",
            ),
            "cannonco_main": wordpress_server(
                "cannonco_main",
                "https://cannonco.net/wp-json/easy-mcp-ai/v1/mcp",
                "CANNONCO_MAIN_TOKEN",
            ),
            "cannonco_books": wordpress_server(
                "cannonco_books",
                "https://books.cannonco.net/wp-json/easy-mcp-ai/v1/mcp",
                "CANNONCO_BOOKS_TOKEN",
            ),
        }
    }

    upstream_proxy = FastMCP.as_proxy(
        upstream_config,
        name="Knoco WordPress Upstreams",
    )

    gateway = FastMCP(
        name="Knoco Enterprise MCP Gateway",
        instructions=(
            "Unified, authenticated gateway for Knoco International and CannonCo "
            "WordPress properties. Tool names are prefixed with their target site."
        ),
        auth=auth,
    )
    gateway.mount(upstream_proxy, namespace="wordpress")
    return gateway


mcp = build_gateway()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    mcp.run(transport="http", host="0.0.0.0", port=port, path="/mcp")
