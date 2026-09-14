import os
import base64
import hashlib

import msal
import requests

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from fastmcp import FastMCP
from fastmcp.server.auth.providers.azure import AzureProvider


GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"

BUILD_ID = "20260914-knoco-m365-diagnostic-v1"


def required_env(name: str) -> str:
    value = os.getenv(name)

    if not value:
        raise RuntimeError(
            f"Required environment variable is missing: {name}"
        )

    return value


def env_enabled(
    name: str,
    default: bool = True,
) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


# ============================================================
# Cannon Microsoft Graph authentication
# ============================================================

def cannon_graph_token() -> str:
    """
    Acquire an app-only Microsoft Graph access token for
    Cannon-Lear Enterprises using certificate authentication.
    """

    tenant_id = required_env(
        "CANNON_TENANT_ID"
    )

    client_id = required_env(
        "CANNON_CLIENT_ID"
    )

    pfx_base64 = required_env(
        "CANNON_CERT_PFX_BASE64"
    )

    pfx_password = required_env(
        "CANNON_CERT_PASSWORD"
    )

    try:
        pfx_bytes = base64.b64decode(
            pfx_base64
        )

        (
            private_key,
            certificate,
            _additional_certificates,
        ) = pkcs12.load_key_and_certificates(
            pfx_bytes,
            pfx_password.encode(
                "utf-8"
            ),
        )

        if private_key is None:
            raise RuntimeError(
                "Cannon certificate does not "
                "contain a private key."
            )

        if certificate is None:
            raise RuntimeError(
                "Cannon certificate does not "
                "contain a public certificate."
            )

        private_key_pem = (
            private_key.private_bytes(
                encoding=(
                    serialization.Encoding.PEM
                ),
                format=(
                    serialization.PrivateFormat.PKCS8
                ),
                encryption_algorithm=(
                    serialization.NoEncryption()
                ),
            ).decode("utf-8")
        )

        cert_der = certificate.public_bytes(
            encoding=(
                serialization.Encoding.DER
            )
        )

        thumbprint = hashlib.sha1(
            cert_der
        ).hexdigest()

        app = msal.ConfidentialClientApplication(
            client_id=client_id,
            authority=(
                "https://login.microsoftonline.com/"
                f"{tenant_id}"
            ),
            client_credential={
                "private_key": private_key_pem,
                "thumbprint": thumbprint,
            },
        )

        result = app.acquire_token_for_client(
            scopes=[
                "https://graph.microsoft.com/.default"
            ]
        )

        if "access_token" not in result:
            error = result.get(
                "error",
                "unknown_error",
            )

            description = result.get(
                "error_description",
                "No additional error information returned.",
            )

            raise RuntimeError(
                "Microsoft Entra token acquisition failed: "
                f"{error}: {description}"
            )

        return result[
            "access_token"
        ]

    except Exception as exc:
        raise RuntimeError(
            "Unable to authenticate "
            f"CANNON-Jarvis-MCP: {exc}"
        ) from exc


def cannon_graph_request(
    method: str,
    endpoint: str,
    *,
    json_body: dict | None = None,
    params: dict | None = None,
) -> dict:
    """
    Execute an authenticated Microsoft Graph request
    using the Cannon service principal.
    """

    token = cannon_graph_token()

    response = requests.request(
        method=method,
        url=(
            f"{GRAPH_BASE_URL}"
            f"{endpoint}"
        ),
        headers={
            "Authorization": (
                f"Bearer {token}"
            ),
            "Accept": (
                "application/json"
            ),
            "Content-Type": (
                "application/json"
            ),
        },
        json=json_body,
        params=params,
        timeout=30,
    )

    if not response.ok:
        raise RuntimeError(
            "Cannon Graph request failed "
            f"({response.status_code}) "
            f"{method} {endpoint}: "
            f"{response.text}"
        )

    if not response.content:
        return {}

    return response.json()


# ============================================================
# Knoco Microsoft Graph authentication
# ============================================================

def knoco_graph_token() -> str:
    """
    Acquire an app-only Microsoft Graph access token for
    Knoco International using certificate authentication.

    Uses the Knoco M365 Operations MCP Entra application.
    """

    tenant_id = required_env(
        "KNOCO_TENANT_ID"
    )

    client_id = required_env(
        "KNOCO_CLIENT_ID"
    )

    pfx_base64 = required_env(
        "KNOCO_CERT_PFX_BASE64"
    )

    pfx_password = required_env(
        "KNOCO_CERT_PASSWORD"
    )

    try:
        pfx_bytes = base64.b64decode(
            pfx_base64
        )

        (
            private_key,
            certificate,
            _additional_certificates,
        ) = pkcs12.load_key_and_certificates(
            pfx_bytes,
            pfx_password.encode(
                "utf-8"
            ),
        )

        if private_key is None:
            raise RuntimeError(
                "Knoco certificate does not "
                "contain a private key."
            )

        if certificate is None:
            raise RuntimeError(
                "Knoco certificate does not "
                "contain a public certificate."
            )

        private_key_pem = (
            private_key.private_bytes(
                encoding=(
                    serialization.Encoding.PEM
                ),
                format=(
                    serialization.PrivateFormat.PKCS8
                ),
                encryption_algorithm=(
                    serialization.NoEncryption()
                ),
            ).decode("utf-8")
        )

        cert_der = certificate.public_bytes(
            encoding=(
                serialization.Encoding.DER
            )
        )

        thumbprint = hashlib.sha1(
            cert_der
        ).hexdigest()

        app = msal.ConfidentialClientApplication(
            client_id=client_id,
            authority=(
                "https://login.microsoftonline.com/"
                f"{tenant_id}"
            ),
            client_credential={
                "private_key": private_key_pem,
                "thumbprint": thumbprint,
            },
        )

        result = app.acquire_token_for_client(
            scopes=[
                "https://graph.microsoft.com/.default"
            ]
        )

        if "access_token" not in result:
            error = result.get(
                "error",
                "unknown_error",
            )

            description = result.get(
                "error_description",
                "No additional error information returned.",
            )

            raise RuntimeError(
                "Microsoft Entra token acquisition failed: "
                f"{error}: {description}"
            )

        return result[
            "access_token"
        ]

    except Exception as exc:
        raise RuntimeError(
            "Unable to authenticate "
            "Knoco M365 Operations MCP: "
            f"{exc}"
        ) from exc


def knoco_graph_request(
    method: str,
    endpoint: str,
    *,
    json_body: dict | None = None,
    params: dict | None = None,
) -> dict:
    """
    Execute an authenticated Microsoft Graph request
    using the Knoco service principal.
    """

    token = knoco_graph_token()

    response = requests.request(
        method=method,
        url=(
            f"{GRAPH_BASE_URL}"
            f"{endpoint}"
        ),
        headers={
            "Authorization": (
                f"Bearer {token}"
            ),
            "Accept": (
                "application/json"
            ),
            "Content-Type": (
                "application/json"
            ),
        },
        json=json_body,
        params=params,
        timeout=30,
    )

    if not response.ok:
        raise RuntimeError(
            "Knoco Graph request failed "
            f"({response.status_code}) "
            f"{method} {endpoint}: "
            f"{response.text}"
        )

    if not response.content:
        return {}

    return response.json()


# ============================================================
# WordPress proxy configuration
# ============================================================

def wordpress_server(
    url: str,
    token_env: str,
) -> dict:
    token = required_env(
        token_env
    )

    return {
        "transport": "http",
        "url": url,
        "headers": {
            "Authorization": (
                f"Bearer {token}"
            ),
        },
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
    """
    Mount one WordPress MCP server
    as an independent proxy.
    """

    if not env_enabled(
        enabled_env,
        default_enabled,
    ):
        print(
            "Skipping disabled "
            "WordPress upstream: "
            f"{site_name}",
            flush=True,
        )

        return

    proxy_config = {
        "mcpServers": {
            site_name: wordpress_server(
                url,
                token_env,
            )
        }
    }

    proxy = FastMCP.as_proxy(
        proxy_config,
        name=(
            f"{site_name} "
            "WordPress Upstream"
        ),
    )

    gateway.mount(
        proxy,
        namespace=(
            f"wordpress_{site_name}"
        ),
    )

    print(
        "Mounted WordPress upstream: "
        f"{site_name} -> {url}",
        flush=True,
    )


# ============================================================
# Gateway diagnostics
# ============================================================

def register_gateway_diagnostics(
    gateway: FastMCP,
) -> None:
    """
    Register harmless diagnostic tools used to verify
    which gateway build ChatGPT is actually reaching.
    """

    @gateway.tool()
    def gateway_build_info() -> dict:
        """
        Return the running gateway build marker and
        integration-registration state.

        READ ONLY.
        """

        return {
            "build_id": BUILD_ID,
            "gateway": (
                "Knoco Enterprise MCP Gateway"
            ),
            "cannon_m365_enabled": env_enabled(
                "CANNON_M365_ENABLED",
                default=True,
            ),
            "knoco_m365_enabled": env_enabled(
                "KNOCO_M365_ENABLED",
                default=True,
            ),
            "cannon_environment_present": {
                "tenant_id": bool(
                    os.getenv(
                        "CANNON_TENANT_ID"
                    )
                ),
                "client_id": bool(
                    os.getenv(
                        "CANNON_CLIENT_ID"
                    )
                ),
                "certificate": bool(
                    os.getenv(
                        "CANNON_CERT_PFX_BASE64"
                    )
                ),
                "certificate_password": bool(
                    os.getenv(
                        "CANNON_CERT_PASSWORD"
                    )
                ),
            },
            "knoco_environment_present": {
                "tenant_id": bool(
                    os.getenv(
                        "KNOCO_TENANT_ID"
                    )
                ),
                "client_id": bool(
                    os.getenv(
                        "KNOCO_CLIENT_ID"
                    )
                ),
                "certificate": bool(
                    os.getenv(
                        "KNOCO_CERT_PFX_BASE64"
                    )
                ),
                "certificate_password": bool(
                    os.getenv(
                        "KNOCO_CERT_PASSWORD"
                    )
                ),
            },
        }

    print(
        "Registered gateway diagnostic tools. "
        f"Build ID: {BUILD_ID}",
        flush=True,
    )


# ============================================================
# Cannon Microsoft 365 read-only tools
# ============================================================

def register_cannon_m365_tools(
    gateway: FastMCP,
) -> None:
    """
    Register Cannon Microsoft 365
    read-only tools.
    """

    @gateway.tool()
    def cannon_sharepoint_test() -> dict:
        """
        Verify Cannon SharePoint access
        through Microsoft Graph.

        READ ONLY.
        """

        data = cannon_graph_request(
            "GET",
            (
                "/sites/"
                "cannonconet.sharepoint.com:/"
            ),
        )

        return {
            "success": True,
            "organization": (
                "Cannon-Lear "
                "Enterprises L.L.C."
            ),
            "tenant": (
                "cannonconet.sharepoint.com"
            ),
            "site": {
                "id": data.get(
                    "id"
                ),
                "name": data.get(
                    "name"
                ),
                "displayName": data.get(
                    "displayName"
                ),
                "webUrl": data.get(
                    "webUrl"
                ),
            },
        }

    @gateway.tool()
    def cannon_sharepoint_get_site(
        hostname: str,
        site_path: str = "/",
    ) -> dict:
        """
        Retrieve metadata for a
        Cannon SharePoint site.

        READ ONLY.
        """

        if (
            hostname.lower()
            != "cannonconet.sharepoint.com"
        ):
            raise ValueError(
                "This tool is restricted "
                "to cannonconet.sharepoint.com."
            )

        if not site_path.startswith(
            "/"
        ):
            site_path = (
                f"/{site_path}"
            )

        data = cannon_graph_request(
            "GET",
            (
                f"/sites/{hostname}:"
                f"{site_path}"
            ),
        )

        return {
            "id": data.get(
                "id"
            ),
            "name": data.get(
                "name"
            ),
            "displayName": data.get(
                "displayName"
            ),
            "webUrl": data.get(
                "webUrl"
            ),
            "description": data.get(
                "description"
            ),
            "createdDateTime": data.get(
                "createdDateTime"
            ),
            "lastModifiedDateTime": (
                data.get(
                    "lastModifiedDateTime"
                )
            ),
        }

    @gateway.tool()
    def cannon_sharepoint_list_lists(
        site_id: str,
    ) -> dict:
        """
        List Cannon SharePoint lists
        and document libraries.

        READ ONLY.
        """

        data = cannon_graph_request(
            "GET",
            (
                f"/sites/{site_id}"
                "/lists"
            ),
            params={
                "$select": (
                    "id,name,displayName,"
                    "webUrl,list,"
                    "createdDateTime,"
                    "lastModifiedDateTime"
                )
            },
        )

        return {
            "count": len(
                data.get(
                    "value",
                    [],
                )
            ),
            "items": data.get(
                "value",
                [],
            ),
        }

    @gateway.tool()
    def cannon_sharepoint_list_drives(
        site_id: str,
    ) -> dict:
        """
        List Cannon document libraries
        exposed as drives.

        READ ONLY.
        """

        data = cannon_graph_request(
            "GET",
            (
                f"/sites/{site_id}"
                "/drives"
            ),
        )

        return {
            "count": len(
                data.get(
                    "value",
                    [],
                )
            ),
            "drives": data.get(
                "value",
                [],
            ),
        }

    @gateway.tool()
    def cannon_sharepoint_get_list_items(
        site_id: str,
        list_id: str,
        top: int = 25,
    ) -> dict:
        """
        Retrieve Cannon SharePoint
        list items.

        READ ONLY.
        """

        if top < 1:
            top = 1

        if top > 200:
            top = 200

        data = cannon_graph_request(
            "GET",
            (
                f"/sites/{site_id}"
                f"/lists/{list_id}"
                "/items"
            ),
            params={
                "$expand": "fields",
                "$top": str(top),
            },
        )

        return {
            "count": len(
                data.get(
                    "value",
                    [],
                )
            ),
            "items": data.get(
                "value",
                [],
            ),
            "nextLink": data.get(
                "@odata.nextLink"
            ),
        }

    @gateway.tool()
    def cannon_sharepoint_list_drive_root(
        drive_id: str,
    ) -> dict:
        """
        List files and folders in
        the root of a Cannon
        document library.

        READ ONLY.
        """

        data = cannon_graph_request(
            "GET",
            (
                f"/drives/{drive_id}"
                "/root/children"
            ),
        )

        return {
            "count": len(
                data.get(
                    "value",
                    [],
                )
            ),
            "items": data.get(
                "value",
                [],
            ),
            "nextLink": data.get(
                "@odata.nextLink"
            ),
        }

    print(
        "Registered Cannon "
        "Microsoft 365 read-only "
        "diagnostic tools.",
        flush=True,
    )


# ============================================================
# Knoco Microsoft 365 read-only tools
# ============================================================

def register_knoco_m365_tools(
    gateway: FastMCP,
) -> None:
    """
    Register Knoco Microsoft 365
    read-only tools.
    """

    @gateway.tool()
    def knoco_sharepoint_test() -> dict:
        """
        Verify Knoco SharePoint access
        through Microsoft Graph.

        READ ONLY.
        """

        data = knoco_graph_request(
            "GET",
            (
                "/sites/"
                "knoco.sharepoint.com:/"
            ),
        )

        return {
            "success": True,
            "organization": (
                "Knoco International"
            ),
            "tenant": (
                "knoco.sharepoint.com"
            ),
            "site": {
                "id": data.get(
                    "id"
                ),
                "name": data.get(
                    "name"
                ),
                "displayName": data.get(
                    "displayName"
                ),
                "webUrl": data.get(
                    "webUrl"
                ),
            },
        }

    @gateway.tool()
    def knoco_sharepoint_get_site(
        hostname: str,
        site_path: str = "/",
    ) -> dict:
        """
        Retrieve metadata for a
        Knoco SharePoint site.

        READ ONLY.
        """

        if (
            hostname.lower()
            != "knoco.sharepoint.com"
        ):
            raise ValueError(
                "This tool is restricted "
                "to knoco.sharepoint.com."
            )

        if not site_path.startswith(
            "/"
        ):
            site_path = (
                f"/{site_path}"
            )

        data = knoco_graph_request(
            "GET",
            (
                f"/sites/{hostname}:"
                f"{site_path}"
            ),
        )

        return {
            "id": data.get(
                "id"
            ),
            "name": data.get(
                "name"
            ),
            "displayName": data.get(
                "displayName"
            ),
            "webUrl": data.get(
                "webUrl"
            ),
            "description": data.get(
                "description"
            ),
            "createdDateTime": data.get(
                "createdDateTime"
            ),
            "lastModifiedDateTime": (
                data.get(
                    "lastModifiedDateTime"
                )
            ),
        }

    @gateway.tool()
    def knoco_sharepoint_list_lists(
        site_id: str,
    ) -> dict:
        """
        List Knoco SharePoint lists
        and document libraries.

        READ ONLY.
        """

        data = knoco_graph_request(
            "GET",
            (
                f"/sites/{site_id}"
                "/lists"
            ),
            params={
                "$select": (
                    "id,name,displayName,"
                    "webUrl,list,"
                    "createdDateTime,"
                    "lastModifiedDateTime"
                )
            },
        )

        return {
            "count": len(
                data.get(
                    "value",
                    [],
                )
            ),
            "items": data.get(
                "value",
                [],
            ),
        }

    @gateway.tool()
    def knoco_sharepoint_list_drives(
        site_id: str,
    ) -> dict:
        """
        List Knoco document libraries
        exposed as drives.

        READ ONLY.
        """

        data = knoco_graph_request(
            "GET",
            (
                f"/sites/{site_id}"
                "/drives"
            ),
        )

        return {
            "count": len(
                data.get(
                    "value",
                    [],
                )
            ),
            "drives": data.get(
                "value",
                [],
            ),
        }

    @gateway.tool()
    def knoco_sharepoint_get_list_items(
        site_id: str,
        list_id: str,
        top: int = 25,
    ) -> dict:
        """
        Retrieve Knoco SharePoint
        list items.

        READ ONLY.
        """

        if top < 1:
            top = 1

        if top > 200:
            top = 200

        data = knoco_graph_request(
            "GET",
            (
                f"/sites/{site_id}"
                f"/lists/{list_id}"
                "/items"
            ),
            params={
                "$expand": "fields",
                "$top": str(top),
            },
        )

        return {
            "count": len(
                data.get(
                    "value",
                    [],
                )
            ),
            "items": data.get(
                "value",
                [],
            ),
            "nextLink": data.get(
                "@odata.nextLink"
            ),
        }

    @gateway.tool()
    def knoco_sharepoint_list_drive_root(
        drive_id: str,
    ) -> dict:
        """
        List files and folders in
        the root of a Knoco
        document library.

        READ ONLY.
        """

        data = knoco_graph_request(
            "GET",
            (
                f"/drives/{drive_id}"
                "/root/children"
            ),
        )

        return {
            "count": len(
                data.get(
                    "value",
                    [],
                )
            ),
            "items": data.get(
                "value",
                [],
            ),
            "nextLink": data.get(
                "@odata.nextLink"
            ),
        }

    print(
        "Registered Knoco "
        "Microsoft 365 read-only "
        "diagnostic tools.",
        flush=True,
    )


# ============================================================
# Gateway
# ============================================================

def build_gateway() -> FastMCP:
    """
    Build the unified Knoco/Cannon
    MCP gateway.
    """

    print(
        "Starting Knoco Enterprise MCP Gateway. "
        f"Build ID: {BUILD_ID}",
        flush=True,
    )

    auth = AzureProvider(
        client_id=required_env(
            "AZURE_MCP_CLIENT_ID"
        ),
        client_secret=required_env(
            "AZURE_MCP_CLIENT_SECRET"
        ),
        tenant_id=required_env(
            "AZURE_MCP_TENANT_ID"
        ),
        base_url=required_env(
            "MCP_PUBLIC_BASE_URL"
        ),
        required_scopes=[
            "mcp-access"
        ],
        additional_authorize_scopes=[
            "openid",
            "profile",
            "email",
            "offline_access",
        ],
    )

    gateway = FastMCP(
        name=(
            "Knoco Enterprise "
            "MCP Gateway"
        ),
        instructions=(
            "Unified authenticated MCP gateway "
            "for Knoco International and "
            "CannonCo. Provides governed access "
            "to WordPress and Microsoft 365 "
            "services. Tools are explicitly "
            "namespaced by organization and "
            "target system."
        ),
        auth=auth,
    )

    # --------------------------------------------------------
    # Diagnostic marker
    # --------------------------------------------------------

    register_gateway_diagnostics(
        gateway
    )

    # --------------------------------------------------------
    # WordPress - Knoco main
    # --------------------------------------------------------

    mount_wordpress_proxy(
        gateway,
        site_name="knoco_main",
        url=(
            "https://knoco.com/"
            "wp-json/easy-mcp-ai/v1/mcp"
        ),
        token_env=(
            "KNOCO_MAIN_TOKEN"
        ),
        enabled_env=(
            "KNOCO_MAIN_ENABLED"
        ),
    )

    # --------------------------------------------------------
    # WordPress - Knoco Institute
    # --------------------------------------------------------

    mount_wordpress_proxy(
        gateway,
        site_name="knoco_institute",
        url=(
            "https://institute.knoco.com/"
            "wp-json/easy-mcp-ai/v1/mcp"
        ),
        token_env=(
            "KNOCO_INSTITUTE_TOKEN"
        ),
        enabled_env=(
            "KNOCO_INSTITUTE_ENABLED"
        ),
    )

    # --------------------------------------------------------
    # WordPress - Knoco Training Test
    # --------------------------------------------------------

    mount_wordpress_proxy(
        gateway,
        site_name="knoco_trainingtest",
        url=(
            "https://trainingtest.knoco.com/"
            "wp-json/easy-mcp-ai/v1/mcp"
        ),
        token_env=(
            "KNOCO_TRAININGTEST_TOKEN"
        ),
        enabled_env=(
            "KNOCO_TRAININGTEST_ENABLED"
        ),
    )

    # --------------------------------------------------------
    # WordPress - CannonCo main
    # --------------------------------------------------------

    mount_wordpress_proxy(
        gateway,
        site_name="cannonco_main",
        url=(
            "https://cannonco.net/"
            "wp-json/easy-mcp-ai/v1/mcp"
        ),
        token_env=(
            "CANNONCO_MAIN_TOKEN"
        ),
        enabled_env=(
            "CANNONCO_MAIN_ENABLED"
        ),
    )

    # --------------------------------------------------------
    # WordPress - Cannon-Lear Publishing
    # --------------------------------------------------------

    mount_wordpress_proxy(
        gateway,
        site_name="cannonco_books",
        url=(
            "https://books.cannonco.net/"
            "wp-json/easy-mcp-ai/v1/mcp"
        ),
        token_env=(
            "CANNONCO_BOOKS_TOKEN"
        ),
        enabled_env=(
            "CANNONCO_BOOKS_ENABLED"
        ),
        default_enabled=False,
    )

    # --------------------------------------------------------
    # Cannon Microsoft 365
    # --------------------------------------------------------

    if env_enabled(
        "CANNON_M365_ENABLED",
        default=True,
    ):
        register_cannon_m365_tools(
            gateway
        )

    else:
        print(
            "Skipping disabled Cannon "
            "Microsoft 365 integration.",
            flush=True,
        )

    # --------------------------------------------------------
    # Knoco Microsoft 365
    # --------------------------------------------------------

    if env_enabled(
        "KNOCO_M365_ENABLED",
        default=True,
    ):
        register_knoco_m365_tools(
            gateway
        )

    else:
        print(
            "Skipping disabled Knoco "
            "Microsoft 365 integration.",
            flush=True,
        )

    print(
        "Gateway build complete. "
        f"Build ID: {BUILD_ID}",
        flush=True,
    )

    return gateway


mcp = build_gateway()


if __name__ == "__main__":
    port = int(
        os.getenv(
            "PORT",
            "8000",
        )
    )

    mcp.run(
        transport="http",
        host="0.0.0.0",
        port=port,
        path="/mcp",
    )
