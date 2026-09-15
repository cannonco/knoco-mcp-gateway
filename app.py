"""Knoco Enterprise MCP Gateway.

Unified MCP gateway for:
- WordPress: knoco.com, institute.knoco.com, trainingtest.knoco.com,
  cannonco.net, books.cannonco.net
- Microsoft 365 / Microsoft Graph: Knoco and Cannon tenants
- SharePoint Online: Graph + SharePoint REST (tenant-scoped)
- Power Platform admin APIs
- Dataverse Web API (used for solution-aware Power Apps / Power Automate work)

This file intentionally keeps Knoco and Cannon credentials isolated while exposing
full administrative operations permitted by each tenant's Entra/Power Platform
service principal. Destructive HTTP DELETE calls require explicit confirmation.

Required Microsoft permissions are enforced by Microsoft, not bypassed here.
The application still must be granted the appropriate Entra permissions and, for
Power Platform, registered as a Power Platform management application / Dataverse
application user where required.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import msal
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from fastmcp import Client, FastMCP
from fastmcp.server.auth.providers.azure import AzureProvider


BUILD_ID = "20260915-unified-fullaccess-v1"
GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
POWER_PLATFORM_BASE_URL = "https://api.bap.microsoft.com"
DEFAULT_TIMEOUT = 60
MAX_RESPONSE_TEXT = 12000


def required_env(name: str) -> str:
    value = os.getenv(name)
    if value is None or not value.strip():
        raise RuntimeError(f"Required environment variable is missing: {name}")
    return value.strip()


def optional_env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip()


def env_enabled(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _safe_json_or_text(response: requests.Response) -> dict[str, Any]:
    if not response.content:
        return {"status_code": response.status_code, "ok": response.ok}
    content_type = response.headers.get("content-type", "")
    if "json" in content_type.lower():
        try:
            payload = response.json()
            if isinstance(payload, dict):
                return payload
            return {"value": payload}
        except ValueError:
            pass
    text = response.text
    if len(text) > MAX_RESPONSE_TEXT:
        text = text[:MAX_RESPONSE_TEXT] + "...[truncated]"
    return {
        "status_code": response.status_code,
        "ok": response.ok,
        "content_type": content_type,
        "text": text,
    }


def _validate_method(method: str, confirm_destructive: bool = False) -> str:
    method = method.upper().strip()
    allowed = {"GET", "POST", "PUT", "PATCH", "DELETE"}
    if method not in allowed:
        raise ValueError(f"Unsupported HTTP method: {method}. Allowed: {sorted(allowed)}")
    if method == "DELETE" and not confirm_destructive:
        raise ValueError("DELETE requires confirm_destructive=true")
    return method


def _normalize_api_path(path: str) -> str:
    if not path:
        raise ValueError("path is required")
    if path.startswith("http://") or path.startswith("https://"):
        raise ValueError("Pass an API-relative path, not a full URL")
    return path if path.startswith("/") else f"/{path}"


@dataclass(frozen=True)
class TenantConfig:
    prefix: str
    organization: str
    tenant_id_env: str
    client_id_env: str
    cert_pfx_env: str
    cert_password_env: str
    sharepoint_host: str
    dataverse_url_env: str


KNOCO = TenantConfig(
    prefix="knoco",
    organization="Knoco International",
    tenant_id_env="KNOCO_TENANT_ID",
    client_id_env="KNOCO_CLIENT_ID",
    cert_pfx_env="KNOCO_CERT_PFX_BASE64",
    cert_password_env="KNOCO_CERT_PASSWORD",
    sharepoint_host="knoco.sharepoint.com",
    dataverse_url_env="KNOCO_DATAVERSE_URL",
)

CANNON = TenantConfig(
    prefix="cannon",
    organization="Cannon-Lear Enterprises L.L.C.",
    tenant_id_env="CANNON_TENANT_ID",
    client_id_env="CANNON_CLIENT_ID",
    cert_pfx_env="CANNON_CERT_PFX_BASE64",
    cert_password_env="CANNON_CERT_PASSWORD",
    sharepoint_host="cannonconet.sharepoint.com",
    dataverse_url_env="CANNON_DATAVERSE_URL",
)


# ---------------------------------------------------------------------------
# Certificate / token helpers
# ---------------------------------------------------------------------------


def _certificate_credential(config: TenantConfig) -> tuple[str, str, dict[str, str]]:
    tenant_id = required_env(config.tenant_id_env)
    client_id = required_env(config.client_id_env)
    pfx_bytes = base64.b64decode(required_env(config.cert_pfx_env))
    password = required_env(config.cert_password_env).encode("utf-8")
    private_key, certificate, _ = pkcs12.load_key_and_certificates(pfx_bytes, password)
    if private_key is None or certificate is None:
        raise RuntimeError(f"{config.prefix}: PFX must contain private key and certificate")
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    thumbprint = hashlib.sha1(cert_der).hexdigest()
    return tenant_id, client_id, {"private_key": private_key_pem, "thumbprint": thumbprint}


def acquire_app_token(config: TenantConfig, scope: str) -> str:
    tenant_id, client_id, credential = _certificate_credential(config)
    app = msal.ConfidentialClientApplication(
        client_id=client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=credential,
    )
    result = app.acquire_token_for_client(scopes=[scope])
    token = result.get("access_token")
    if not token:
        raise RuntimeError(
            f"{config.prefix}: token acquisition failed: "
            f"{result.get('error', 'unknown_error')}: "
            f"{result.get('error_description', 'no description')}"
        )
    return token


def graph_token(config: TenantConfig) -> str:
    return acquire_app_token(config, "https://graph.microsoft.com/.default")


def sharepoint_token(config: TenantConfig) -> str:
    return acquire_app_token(config, f"https://{config.sharepoint_host}/.default")


def powerplatform_token(config: TenantConfig) -> str:
    return acquire_app_token(config, "https://service.powerapps.com/.default")


def dataverse_token(config: TenantConfig) -> tuple[str, str]:
    url = optional_env(config.dataverse_url_env)
    if not url:
        raise RuntimeError(
            f"{config.dataverse_url_env} is not configured. Set it to the environment URL, "
            "for example https://org.crm.dynamics.com"
        )
    url = url.rstrip("/")
    return url, acquire_app_token(config, f"{url}/.default")


# ---------------------------------------------------------------------------
# Generic HTTP helpers
# ---------------------------------------------------------------------------


def _request(
    *,
    token: str,
    method: str,
    url: str,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | list[Any] | None = None,
    data: bytes | str | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if json_body is not None:
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)
    response = requests.request(
        method=method,
        url=url,
        headers=headers,
        params=params,
        json=json_body,
        data=data,
        timeout=timeout,
    )
    if not response.ok:
        safe = _safe_json_or_text(response)
        raise RuntimeError(f"HTTP {response.status_code} {method} {url}: {safe}")
    return _safe_json_or_text(response)


def graph_request(
    config: TenantConfig,
    method: str,
    endpoint: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | list[Any] | None = None,
    data: bytes | str | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    endpoint = _normalize_api_path(endpoint)
    return _request(
        token=graph_token(config),
        method=method,
        url=f"{GRAPH_BASE_URL}{endpoint}",
        params=params,
        json_body=json_body,
        data=data,
        extra_headers=headers,
    )


def sharepoint_rest_request(
    config: TenantConfig,
    method: str,
    api_path: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | list[Any] | None = None,
    data: bytes | str | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    path = _normalize_api_path(api_path)
    if not path.startswith("/_api/") and path != "/_api":
        raise ValueError("SharePoint REST path must begin with /_api/")
    sp_headers = {"Accept": "application/json;odata=nometadata"}
    if headers:
        sp_headers.update(headers)
    return _request(
        token=sharepoint_token(config),
        method=method,
        url=f"https://{config.sharepoint_host}{path}",
        params=params,
        json_body=json_body,
        data=data,
        extra_headers=sp_headers,
    )


def powerplatform_request(
    config: TenantConfig,
    method: str,
    api_path: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | list[Any] | None = None,
) -> dict[str, Any]:
    path = _normalize_api_path(api_path)
    return _request(
        token=powerplatform_token(config),
        method=method,
        url=f"{POWER_PLATFORM_BASE_URL}{path}",
        params=params,
        json_body=json_body,
    )


def dataverse_request(
    config: TenantConfig,
    method: str,
    api_path: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | list[Any] | None = None,
) -> dict[str, Any]:
    base_url, token = dataverse_token(config)
    path = _normalize_api_path(api_path)
    if not path.startswith("/api/data/"):
        raise ValueError("Dataverse path must begin with /api/data/")
    return _request(
        token=token,
        method=method,
        url=f"{base_url}{path}",
        params=params,
        json_body=json_body,
        extra_headers={
            "OData-MaxVersion": "4.0",
            "OData-Version": "4.0",
            "Accept": "application/json",
        },
    )


# ---------------------------------------------------------------------------
# WordPress MCP proxy support
# ---------------------------------------------------------------------------

WORDPRESS_UPSTREAMS: dict[str, dict[str, Any]] = {}


def wordpress_server(url: str, token_env: str) -> dict[str, Any]:
    token = required_env(token_env).strip()
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
    enabled = env_enabled(enabled_env, default_enabled)
    token_present = bool(os.getenv(token_env, "").strip())
    WORDPRESS_UPSTREAMS[site_name] = {
        "url": url,
        "token_env": token_env,
        "enabled_env": enabled_env,
        "enabled": enabled,
        "token_present": token_present,
        "namespace": f"wordpress_{site_name}",
        "mounted": False,
    }
    if not enabled:
        print(f"Skipping disabled WordPress upstream: {site_name}", flush=True)
        return
    if not token_present:
        print(f"Skipping WordPress upstream {site_name}: missing {token_env}", flush=True)
        return
    proxy_config = {"mcpServers": {site_name: wordpress_server(url, token_env)}}
    proxy = FastMCP.as_proxy(proxy_config, name=f"WordPress {site_name}")
    gateway.mount(proxy, namespace=f"wordpress_{site_name}")
    WORDPRESS_UPSTREAMS[site_name]["mounted"] = True
    print(f"Mounted WordPress upstream: {site_name} -> {url}", flush=True)


async def probe_wordpress_upstream(site_name: str) -> dict[str, Any]:
    state = WORDPRESS_UPSTREAMS[site_name]
    result = {"site": site_name, **state, "checked_at": datetime.now(timezone.utc).isoformat()}
    if not state["enabled"]:
        return {**result, "status": "disabled"}
    if not state["token_present"]:
        return {**result, "status": "missing_token"}

    async def discover():
        config = {"mcpServers": {site_name: wordpress_server(state["url"], state["token_env"])}}
        async with Client(config) as client:
            return await client.list_tools()

    try:
        discovered = await asyncio.wait_for(discover(), timeout=30)
        return {
            **result,
            "status": "ok" if discovered else "no_tools",
            "tool_count": len(discovered),
            "tool_names": sorted(tool.name for tool in discovered),
        }
    except Exception as exc:  # intentionally redact upstream response bodies
        errors = [exc]
        seen: set[int] = set()
        statuses: set[int] = set()
        kinds: set[str] = set()
        while errors:
            error = errors.pop()
            if id(error) in seen:
                continue
            seen.add(id(error))
            kinds.add(type(error).__name__)
            response = getattr(error, "response", None)
            status = getattr(response, "status_code", None)
            if isinstance(status, int):
                statuses.add(status)
            errors.extend(getattr(error, "exceptions", ()))
            if error.__cause__:
                errors.append(error.__cause__)
            elif error.__context__:
                errors.append(error.__context__)
        return {
            **result,
            "status": "error",
            "error_types": sorted(kinds),
            "http_status_codes": sorted(statuses),
        }


# ---------------------------------------------------------------------------
# FastMCP tool registration utilities
# ---------------------------------------------------------------------------


def register_named_tool(gateway: FastMCP, name: str, fn, description: str):
    fn.__name__ = name
    fn.__qualname__ = name
    fn.__doc__ = description
    gateway.tool()(fn)


def register_gateway_diagnostics(gateway: FastMCP) -> None:
    @gateway.tool()
    def gateway_build_info() -> dict[str, Any]:
        """Return gateway build and integration configuration without secrets."""
        return {
            "build_id": BUILD_ID,
            "gateway": "Knoco Enterprise MCP Gateway",
            "wordpress_upstreams": {k: dict(v) for k, v in WORDPRESS_UPSTREAMS.items()},
            "m365": {
                "knoco_enabled": env_enabled("KNOCO_M365_ENABLED", True),
                "cannon_enabled": env_enabled("CANNON_M365_ENABLED", True),
                "knoco_dataverse_configured": bool(optional_env("KNOCO_DATAVERSE_URL")),
                "cannon_dataverse_configured": bool(optional_env("CANNON_DATAVERSE_URL")),
            },
        }

    @gateway.tool()
    async def gateway_wordpress_audit(site_name: str = "all") -> dict[str, Any]:
        """READ ONLY. Test WordPress MCP authentication and discover exposed tools."""
        if site_name != "all" and site_name not in WORDPRESS_UPSTREAMS:
            return {"error": "Unknown site", "allowed_sites": sorted(WORDPRESS_UPSTREAMS)}
        names = list(WORDPRESS_UPSTREAMS) if site_name == "all" else [site_name]
        return {
            "build_id": BUILD_ID,
            "sites": await asyncio.gather(*(probe_wordpress_upstream(name) for name in names)),
        }


# ---------------------------------------------------------------------------
# Microsoft / SharePoint / Power Platform tools per tenant
# ---------------------------------------------------------------------------


def register_tenant_tools(gateway: FastMCP, config: TenantConfig) -> None:
    prefix = config.prefix

    def m365_test() -> dict[str, Any]:
        root = graph_request(config, "GET", f"/sites/{config.sharepoint_host}:/")
        return {
            "success": True,
            "organization": config.organization,
            "sharepoint_host": config.sharepoint_host,
            "root_site": root,
        }

    register_named_tool(
        gateway,
        f"{prefix}_m365_test",
        m365_test,
        "READ ONLY. Verify app-only Microsoft Graph access for this tenant.",
    )

    def graph_admin_request(
        method: str,
        endpoint: str,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        confirm_destructive: bool = False,
    ) -> dict[str, Any]:
        """Governed generic Microsoft Graph request using this tenant service principal."""
        method2 = _validate_method(method, confirm_destructive)
        return graph_request(config, method2, endpoint, params=params, json_body=json_body)

    register_named_tool(
        gateway,
        f"{prefix}_graph_admin_request",
        graph_admin_request,
        "FULL ACCESS subject to Entra permissions. Execute a Microsoft Graph GET/POST/PUT/PATCH/DELETE. DELETE requires confirm_destructive=true. endpoint must be relative to https://graph.microsoft.com/v1.0.",
    )

    def sharepoint_get_site(site_path: str = "/") -> dict[str, Any]:
        if not site_path.startswith("/"):
            site_path = f"/{site_path}"
        return graph_request(config, "GET", f"/sites/{config.sharepoint_host}:{site_path}")

    register_named_tool(
        gateway,
        f"{prefix}_sharepoint_get_site",
        sharepoint_get_site,
        f"READ ONLY. Resolve a SharePoint site under {config.sharepoint_host}.",
    )

    def sharepoint_list_sites(search: str = "*") -> dict[str, Any]:
        data = graph_request(config, "GET", "/sites", params={"search": search})
        values = data.get("value", [])
        return {"count": len(values), "sites": values, "nextLink": data.get("@odata.nextLink")}

    register_named_tool(
        gateway,
        f"{prefix}_sharepoint_list_sites",
        sharepoint_list_sites,
        "READ ONLY. Search/list SharePoint sites visible to the tenant service principal.",
    )

    def sharepoint_list_lists(site_id: str) -> dict[str, Any]:
        data = graph_request(config, "GET", f"/sites/{site_id}/lists")
        values = data.get("value", [])
        return {"count": len(values), "items": values, "nextLink": data.get("@odata.nextLink")}

    register_named_tool(gateway, f"{prefix}_sharepoint_list_lists", sharepoint_list_lists,
                        "READ ONLY. List SharePoint lists and document libraries for a site.")

    def sharepoint_create_list(site_id: str, display_name: str, template: str = "genericList", description: str = "") -> dict[str, Any]:
        body = {"displayName": display_name, "list": {"template": template}}
        if description:
            body["description"] = description
        return graph_request(config, "POST", f"/sites/{site_id}/lists", json_body=body)

    register_named_tool(gateway, f"{prefix}_sharepoint_create_list", sharepoint_create_list,
                        "WRITE. Create a SharePoint list. Common templates: genericList, documentLibrary.")

    def sharepoint_update_list(site_id: str, list_id: str, display_name: str | None = None, description: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if display_name is not None:
            body["displayName"] = display_name
        if description is not None:
            body["description"] = description
        if not body:
            raise ValueError("At least one field must be supplied")
        return graph_request(config, "PATCH", f"/sites/{site_id}/lists/{list_id}", json_body=body)

    register_named_tool(gateway, f"{prefix}_sharepoint_update_list", sharepoint_update_list,
                        "WRITE. Update SharePoint list metadata.")

    def sharepoint_delete_list(site_id: str, list_id: str, confirm_destructive: bool = False) -> dict[str, Any]:
        _validate_method("DELETE", confirm_destructive)
        return graph_request(config, "DELETE", f"/sites/{site_id}/lists/{list_id}")

    register_named_tool(gateway, f"{prefix}_sharepoint_delete_list", sharepoint_delete_list,
                        "DESTRUCTIVE. Delete a SharePoint list. Requires confirm_destructive=true.")

    def sharepoint_list_columns(site_id: str, list_id: str) -> dict[str, Any]:
        data = graph_request(config, "GET", f"/sites/{site_id}/lists/{list_id}/columns")
        values = data.get("value", [])
        return {"count": len(values), "columns": values, "nextLink": data.get("@odata.nextLink")}

    register_named_tool(gateway, f"{prefix}_sharepoint_list_columns", sharepoint_list_columns,
                        "READ ONLY. List SharePoint list columns including internal names and schema.")

    def sharepoint_create_column(site_id: str, list_id: str, column_definition: dict[str, Any]) -> dict[str, Any]:
        return graph_request(config, "POST", f"/sites/{site_id}/lists/{list_id}/columns", json_body=column_definition)

    register_named_tool(gateway, f"{prefix}_sharepoint_create_column", sharepoint_create_column,
                        "WRITE. Create a SharePoint list column from a Microsoft Graph columnDefinition JSON object.")

    def sharepoint_update_column(site_id: str, list_id: str, column_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        return graph_request(config, "PATCH", f"/sites/{site_id}/lists/{list_id}/columns/{column_id}", json_body=updates)

    register_named_tool(gateway, f"{prefix}_sharepoint_update_column", sharepoint_update_column,
                        "WRITE. Update a SharePoint list column.")

    def sharepoint_delete_column(site_id: str, list_id: str, column_id: str, confirm_destructive: bool = False) -> dict[str, Any]:
        _validate_method("DELETE", confirm_destructive)
        return graph_request(config, "DELETE", f"/sites/{site_id}/lists/{list_id}/columns/{column_id}")

    register_named_tool(gateway, f"{prefix}_sharepoint_delete_column", sharepoint_delete_column,
                        "DESTRUCTIVE. Delete a SharePoint list column. Requires confirm_destructive=true.")

    def sharepoint_get_list_items(site_id: str, list_id: str, top: int = 100) -> dict[str, Any]:
        top = max(1, min(top, 999))
        data = graph_request(
            config,
            "GET",
            f"/sites/{site_id}/lists/{list_id}/items",
            params={"$expand": "fields", "$top": str(top)},
        )
        values = data.get("value", [])
        return {"count": len(values), "items": values, "nextLink": data.get("@odata.nextLink")}

    register_named_tool(gateway, f"{prefix}_sharepoint_get_list_items", sharepoint_get_list_items,
                        "READ ONLY. Get SharePoint list items with fields expanded.")

    def sharepoint_create_list_item(site_id: str, list_id: str, fields: dict[str, Any]) -> dict[str, Any]:
        return graph_request(config, "POST", f"/sites/{site_id}/lists/{list_id}/items", json_body={"fields": fields})

    register_named_tool(gateway, f"{prefix}_sharepoint_create_list_item", sharepoint_create_list_item,
                        "WRITE. Create a SharePoint list item. fields must use internal column names.")

    def sharepoint_update_list_item(site_id: str, list_id: str, item_id: str, fields: dict[str, Any]) -> dict[str, Any]:
        return graph_request(config, "PATCH", f"/sites/{site_id}/lists/{list_id}/items/{item_id}/fields", json_body=fields)

    register_named_tool(gateway, f"{prefix}_sharepoint_update_list_item", sharepoint_update_list_item,
                        "WRITE. Update SharePoint list item fields using internal column names.")

    def sharepoint_delete_list_item(site_id: str, list_id: str, item_id: str, confirm_destructive: bool = False) -> dict[str, Any]:
        _validate_method("DELETE", confirm_destructive)
        return graph_request(config, "DELETE", f"/sites/{site_id}/lists/{list_id}/items/{item_id}")

    register_named_tool(gateway, f"{prefix}_sharepoint_delete_list_item", sharepoint_delete_list_item,
                        "DESTRUCTIVE. Delete a SharePoint list item. Requires confirm_destructive=true.")

    def sharepoint_list_drives(site_id: str) -> dict[str, Any]:
        data = graph_request(config, "GET", f"/sites/{site_id}/drives")
        values = data.get("value", [])
        return {"count": len(values), "drives": values, "nextLink": data.get("@odata.nextLink")}

    register_named_tool(gateway, f"{prefix}_sharepoint_list_drives", sharepoint_list_drives,
                        "READ ONLY. List document libraries exposed as drives.")

    def sharepoint_list_drive_children(drive_id: str, item_id: str = "root") -> dict[str, Any]:
        endpoint = f"/drives/{drive_id}/root/children" if item_id == "root" else f"/drives/{drive_id}/items/{item_id}/children"
        data = graph_request(config, "GET", endpoint)
        values = data.get("value", [])
        return {"count": len(values), "items": values, "nextLink": data.get("@odata.nextLink")}

    register_named_tool(gateway, f"{prefix}_sharepoint_list_drive_children", sharepoint_list_drive_children,
                        "READ ONLY. List files/folders under a drive root or folder item.")

    def sharepoint_create_folder(drive_id: str, parent_item_id: str, folder_name: str, conflict_behavior: str = "rename") -> dict[str, Any]:
        endpoint = f"/drives/{drive_id}/root/children" if parent_item_id == "root" else f"/drives/{drive_id}/items/{parent_item_id}/children"
        return graph_request(
            config,
            "POST",
            endpoint,
            json_body={"name": folder_name, "folder": {}, "@microsoft.graph.conflictBehavior": conflict_behavior},
        )

    register_named_tool(gateway, f"{prefix}_sharepoint_create_folder", sharepoint_create_folder,
                        "WRITE. Create a folder in a SharePoint document library.")

    def sharepoint_upload_base64_file(drive_id: str, parent_item_id: str, file_name: str, content_base64: str) -> dict[str, Any]:
        raw = base64.b64decode(content_base64)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("Simple upload limited to 4 MiB. Use Graph upload-session endpoints through graph_admin_request for larger files.")
        quoted = quote(file_name, safe="")
        endpoint = (
            f"/drives/{drive_id}/root:/{quoted}:/content"
            if parent_item_id == "root"
            else f"/drives/{drive_id}/items/{parent_item_id}:/{quoted}:/content"
        )
        return graph_request(config, "PUT", endpoint, data=raw, headers={"Content-Type": "application/octet-stream"})

    register_named_tool(gateway, f"{prefix}_sharepoint_upload_base64_file", sharepoint_upload_base64_file,
                        "WRITE. Upload a small file (<=4 MiB) from base64. For larger files use a Graph upload session via graph_admin_request.")

    def sharepoint_update_drive_item(drive_id: str, item_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        return graph_request(config, "PATCH", f"/drives/{drive_id}/items/{item_id}", json_body=updates)

    register_named_tool(gateway, f"{prefix}_sharepoint_update_drive_item", sharepoint_update_drive_item,
                        "WRITE. Rename/move/update a drive item using Graph driveItem PATCH fields.")

    def sharepoint_delete_drive_item(drive_id: str, item_id: str, confirm_destructive: bool = False) -> dict[str, Any]:
        _validate_method("DELETE", confirm_destructive)
        return graph_request(config, "DELETE", f"/drives/{drive_id}/items/{item_id}")

    register_named_tool(gateway, f"{prefix}_sharepoint_delete_drive_item", sharepoint_delete_drive_item,
                        "DESTRUCTIVE. Delete a SharePoint file/folder. Requires confirm_destructive=true.")

    def sharepoint_list_pages(site_id: str) -> dict[str, Any]:
        data = graph_request(config, "GET", f"/sites/{site_id}/pages/microsoft.graph.sitePage")
        values = data.get("value", [])
        return {"count": len(values), "pages": values, "nextLink": data.get("@odata.nextLink")}

    register_named_tool(gateway, f"{prefix}_sharepoint_list_pages", sharepoint_list_pages,
                        "READ ONLY. List modern SharePoint site pages.")

    def sharepoint_get_page(site_id: str, page_id: str, expand_canvas: bool = True) -> dict[str, Any]:
        params = {"$expand": "canvasLayout"} if expand_canvas else None
        return graph_request(config, "GET", f"/sites/{site_id}/pages/{page_id}/microsoft.graph.sitePage", params=params)

    register_named_tool(gateway, f"{prefix}_sharepoint_get_page", sharepoint_get_page,
                        "READ ONLY. Get a modern SharePoint site page and optionally its canvas layout.")

    def sharepoint_create_page(site_id: str, page_definition: dict[str, Any]) -> dict[str, Any]:
        return graph_request(config, "POST", f"/sites/{site_id}/pages", json_body=page_definition)

    register_named_tool(gateway, f"{prefix}_sharepoint_create_page", sharepoint_create_page,
                        "WRITE. Create a modern SharePoint page from a Graph sitePage definition.")

    def sharepoint_update_page(site_id: str, page_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        return graph_request(config, "PATCH", f"/sites/{site_id}/pages/{page_id}/microsoft.graph.sitePage", json_body=updates)

    register_named_tool(gateway, f"{prefix}_sharepoint_update_page", sharepoint_update_page,
                        "WRITE. Update a modern SharePoint page.")

    def sharepoint_publish_page(site_id: str, page_id: str) -> dict[str, Any]:
        return graph_request(config, "POST", f"/sites/{site_id}/pages/{page_id}/microsoft.graph.sitePage/publish", json_body={})

    register_named_tool(gateway, f"{prefix}_sharepoint_publish_page", sharepoint_publish_page,
                        "WRITE. Publish a modern SharePoint page.")

    def sharepoint_delete_page(site_id: str, page_id: str, confirm_destructive: bool = False) -> dict[str, Any]:
        _validate_method("DELETE", confirm_destructive)
        return graph_request(config, "DELETE", f"/sites/{site_id}/pages/{page_id}/microsoft.graph.sitePage")

    register_named_tool(gateway, f"{prefix}_sharepoint_delete_page", sharepoint_delete_page,
                        "DESTRUCTIVE. Delete a modern SharePoint page. Requires confirm_destructive=true.")

    def sharepoint_list_site_permissions(site_id: str) -> dict[str, Any]:
        data = graph_request(config, "GET", f"/sites/{site_id}/permissions")
        values = data.get("value", [])
        return {"count": len(values), "permissions": values, "nextLink": data.get("@odata.nextLink")}

    register_named_tool(gateway, f"{prefix}_sharepoint_list_site_permissions", sharepoint_list_site_permissions,
                        "READ ONLY. List application permissions assigned to a SharePoint site through Graph.")

    def sharepoint_grant_site_permission(site_id: str, roles: list[str], application_id: str, application_display_name: str) -> dict[str, Any]:
        body = {
            "roles": roles,
            "grantedToIdentities": [
                {"application": {"id": application_id, "displayName": application_display_name}}
            ],
        }
        return graph_request(config, "POST", f"/sites/{site_id}/permissions", json_body=body)

    register_named_tool(gateway, f"{prefix}_sharepoint_grant_site_permission", sharepoint_grant_site_permission,
                        "ADMIN. Grant an application selected-site permission to a SharePoint site. Requires corresponding Entra authority.")

    def sharepoint_rest_admin_request(
        method: str,
        api_path: str,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        confirm_destructive: bool = False,
    ) -> dict[str, Any]:
        method2 = _validate_method(method, confirm_destructive)
        return sharepoint_rest_request(config, method2, api_path, params=params, json_body=json_body)

    register_named_tool(gateway, f"{prefix}_sharepoint_rest_admin_request", sharepoint_rest_admin_request,
                        f"FULL ACCESS subject to SharePoint permissions. Execute a SharePoint REST request against https://{config.sharepoint_host}/_api/. DELETE requires confirm_destructive=true.")

    def termstore_list_groups() -> dict[str, Any]:
        data = graph_request(config, "GET", "/sites/termStore/groups")
        values = data.get("value", [])
        return {"count": len(values), "groups": values, "nextLink": data.get("@odata.nextLink")}

    register_named_tool(gateway, f"{prefix}_termstore_list_groups", termstore_list_groups,
                        "READ ONLY. List SharePoint Term Store groups through Microsoft Graph.")

    def powerplatform_test() -> dict[str, Any]:
        return powerplatform_request(
            config,
            "GET",
            "/providers/Microsoft.BusinessAppPlatform/adminApplications",
            params={"api-version": "2020-10-01"},
        )

    register_named_tool(gateway, f"{prefix}_powerplatform_test", powerplatform_test,
                        "READ ONLY. Verify this service principal is registered as a Power Platform management application.")

    def powerplatform_admin_request(
        method: str,
        api_path: str,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        confirm_destructive: bool = False,
    ) -> dict[str, Any]:
        method2 = _validate_method(method, confirm_destructive)
        return powerplatform_request(config, method2, api_path, params=params, json_body=json_body)

    register_named_tool(gateway, f"{prefix}_powerplatform_admin_request", powerplatform_admin_request,
                        "POWER PLATFORM ADMIN. Generic request to api.bap.microsoft.com using the tenant service principal. The app must first be registered as a Power Platform management application. DELETE requires confirm_destructive=true.")

    def dataverse_admin_request(
        method: str,
        api_path: str,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        confirm_destructive: bool = False,
    ) -> dict[str, Any]:
        method2 = _validate_method(method, confirm_destructive)
        return dataverse_request(config, method2, api_path, params=params, json_body=json_body)

    register_named_tool(gateway, f"{prefix}_dataverse_admin_request", dataverse_admin_request,
                        "POWER APPS / POWER AUTOMATE / DATAVERSE. Generic Web API request to the configured Dataverse environment. Use solution-aware Dataverse tables/APIs for supported cloud-flow management. The service principal must be an application user with required security roles. DELETE requires confirm_destructive=true.")


# ---------------------------------------------------------------------------
# Gateway assembly
# ---------------------------------------------------------------------------


def build_gateway() -> FastMCP:
    print(f"Starting Knoco Enterprise MCP Gateway. Build ID: {BUILD_ID}", flush=True)
    WORDPRESS_UPSTREAMS.clear()

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
            "Unified authenticated enterprise gateway for Knoco International and Cannon-Lear Enterprises. "
            "Provides governed WordPress, Microsoft Graph, SharePoint, Power Platform, and Dataverse access. "
            "Tools are tenant- and system-namespaced. Destructive Microsoft operations require explicit confirmation."
        ),
        auth=auth,
    )

    register_gateway_diagnostics(gateway)

    wordpress_sites = [
        ("knoco_main", "https://knoco.com/wp-json/easy-mcp-ai/v1/mcp", "KNOCO_MAIN_TOKEN", "KNOCO_MAIN_ENABLED", True),
        ("knoco_institute", "https://institute.knoco.com/wp-json/easy-mcp-ai/v1/mcp", "KNOCO_INSTITUTE_TOKEN", "KNOCO_INSTITUTE_ENABLED", True),
        ("knoco_trainingtest", "https://trainingtest.knoco.com/wp-json/easy-mcp-ai/v1/mcp", "KNOCO_TRAININGTEST_TOKEN", "KNOCO_TRAININGTEST_ENABLED", True),
        ("cannonco_main", "https://cannonco.net/wp-json/easy-mcp-ai/v1/mcp", "CANNONCO_MAIN_TOKEN", "CANNONCO_MAIN_ENABLED", True),
        ("cannonco_books", "https://books.cannonco.net/wp-json/easy-mcp-ai/v1/mcp", "CANNONCO_BOOKS_TOKEN", "CANNONCO_BOOKS_ENABLED", True),
    ]
    for site_name, url, token_env, enabled_env, default_enabled in wordpress_sites:
        mount_wordpress_proxy(
            gateway,
            site_name=site_name,
            url=url,
            token_env=token_env,
            enabled_env=enabled_env,
            default_enabled=default_enabled,
        )

    if env_enabled("KNOCO_M365_ENABLED", True):
        register_tenant_tools(gateway, KNOCO)
    if env_enabled("CANNON_M365_ENABLED", True):
        register_tenant_tools(gateway, CANNON)

    print(f"Gateway build complete. Build ID: {BUILD_ID}", flush=True)
    return gateway


mcp = build_gateway()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    mcp.run(transport="http", host="0.0.0.0", port=port, path="/mcp")
