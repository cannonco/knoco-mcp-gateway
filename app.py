import os

from fastmcp import FastMCP
from fastmcp.server.auth.providers.azure import AzureProvider


def required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Required environment variable is missing: {name}")
    return value


def env_enabled(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def wordpress_server(url: str, token_env: str) -> dict:
    token = required_env(token_env)
    return {
        "transport": "http",
        "url": url,
        "headers": {"Authorization": f"Bearer {token}"},
    }


def mount_wordpress_proxy(
    gateway: FastMCP,
    *,
    site_name: str,
    url: str,
    token_env: str,
    enabled_env: str,
    default_enabled: bool = True,
) -> None:
    """Mount one WordPress MCP server as an independent proxy."""
    if not env_enabled(enabled_env, default_enabled):
        print(f"Skipping disabled WordPress upstream: {site_name}")
        return

    proxy_config = {
        "mcpServers": {
            site_name: wordpress_server(url, token_env),
        }
    }
    proxy = FastMCP.as_proxy(
        proxy_config,
        name=f"{site_name} WordPress Upstream",
    )
    gateway.mount(proxy, namespace=f"wordpress_{site_name}")
    print(f"Mounted WordPress upstream: {site_name} -> {url}")


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

    gateway = FastMCP(
        name="Knoco Enterprise MCP Gateway",
        instructions=(
            "Unified, authenticated gateway for Knoco International and CannonCo "
            "WordPress properties. WordPress tools are namespaced by target site."
        ),
        auth=auth,
    )

    mount_wordpress_proxy(
        gateway,
        site_name="knoco_main",
        url="https://knoco.com/wp-json/easy-mcp-ai/v1/mcp",
        token_env="KNOCO_MAIN_TOKEN",
        enabled_env="KNOCO_MAIN_ENABLED",
    )
    mount_wordpress_proxy(
        gateway,
        site_name="knoco_institute",
        url="https://institute.knoco.com/wp-json/easy-mcp-ai/v1/mcp",
        token_env="KNOCO_INSTITUTE_TOKEN",
        enabled_env="KNOCO_INSTITUTE_ENABLED",
    )
    mount_wordpress_proxy(
        gateway,
        site_name="knoco_trainingtest",
        url="https://trainingtest.knoco.com/wp-json/easy-mcp-ai/v1/mcp",
        token_env="KNOCO_TRAININGTEST_TOKEN",
        enabled_env="KNOCO_TRAININGTEST_ENABLED",
    )
    mount_wordpress_proxy(
        gateway,
        site_name="cannonco_main",
        url="https://cannonco.net/wp-json/easy-mcp-ai/v1/mcp",
        token_env="CANNONCO_MAIN_TOKEN",
        enabled_env="CANNONCO_MAIN_ENABLED",
    )
    mount_wordpress_proxy(
        gateway,
        site_name="cannonco_books",
        url="https://books.cannonco.net/wp-json/easy-mcp-ai/v1/mcp",
        token_env="CANNONCO_BOOKS_TOKEN",
        enabled_env="CANNONCO_BOOKS_ENABLED",
        default_enabled=False,
    )

    return gateway


mcp = build_gateway()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    mcp.run(transport="http", host="0.0.0.0", port=port, path="/mcp")
