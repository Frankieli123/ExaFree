import json
import logging
import os
from typing import Optional, List, Dict, Any, Callable
from urllib.parse import urlparse

import httpx
from mcp.server.fastmcp import FastMCP, Context
from mcp.server.transport_security import TransportSecuritySettings

try:
    from mcp.server.dependencies import get_http_headers as _get_http_headers  # type: ignore
except Exception:  # pragma: no cover - optional dependency path
    _get_http_headers = None  # type: ignore

logger = logging.getLogger(__name__)


def _dedupe(values: List[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for value in values:
        value = (value or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _parse_public_origin(value: str) -> Optional[str]:
    raw = (value or "").strip()
    if not raw:
        return None

    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    if not parsed.scheme or not parsed.netloc:
        return None

    return f"{parsed.scheme}://{parsed.netloc}"


def _host_patterns_from_value(value: str) -> List[str]:
    raw = (value or "").strip()
    if not raw:
        return []

    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    candidate = (parsed.netloc or parsed.path).strip()
    if not candidate:
        return []

    if candidate.startswith("[") and "]" in candidate:
        base_host = candidate.split("]", 1)[0] + "]"
    else:
        base_host = candidate.split(":", 1)[0]

    return [candidate, base_host, f"{base_host}:*"]


def _collect_configured_origins(raw_values: List[str]) -> List[str]:
    origins: List[str] = []
    for value in raw_values:
        origin = _parse_public_origin(value)
        if origin:
            origins.append(origin)
    return _dedupe(origins)


def _build_transport_security() -> TransportSecuritySettings:
    default_hosts = [
        "127.0.0.1",
        "127.0.0.1:*",
        "localhost",
        "localhost:*",
        "[::1]",
        "[::1]:*",
    ]
    default_origins = [
        "http://127.0.0.1",
        "http://127.0.0.1:*",
        "http://localhost",
        "http://localhost:*",
        "http://[::1]",
        "http://[::1]:*",
    ]

    raw_origin_values = [
        os.getenv("MCP_PUBLIC_BASE_URL", ""),
        os.getenv("FRONTEND_ORIGIN", ""),
        os.getenv("BASE_URL", ""),
    ]
    raw_origin_values.extend(os.getenv("MCP_ALLOWED_ORIGINS", "").split(","))
    configured_origins = _collect_configured_origins(raw_origin_values)

    raw_host_values = [
        os.getenv("MCP_PUBLIC_BASE_URL", ""),
        os.getenv("FRONTEND_ORIGIN", ""),
        os.getenv("BASE_URL", ""),
    ]
    raw_host_values.extend(configured_origins)
    raw_host_values.extend(os.getenv("MCP_ALLOWED_HOSTS", "").split(","))

    configured_hosts: List[str] = []
    for value in raw_host_values:
        configured_hosts.extend(_host_patterns_from_value(value))

    settings = TransportSecuritySettings(
        enable_dns_rebinding_protection=os.getenv("MCP_ENABLE_DNS_REBINDING_PROTECTION", "1") != "0",
        allowed_hosts=_dedupe(default_hosts + configured_hosts),
        allowed_origins=_dedupe(default_origins + configured_origins),
    )
    logger.info(
        "MCP transport security enabled=%s hosts=%s origins=%s",
        settings.enable_dns_rebinding_protection,
        settings.allowed_hosts,
        settings.allowed_origins,
    )
    return settings


# Initialize MCP server
mcp = FastMCP(
    "exa-pool",
    streamable_http_path="/",
    transport_security=_build_transport_security(),
)

# HTTP client timeout settings
TIMEOUT = httpx.Timeout(30.0, connect=5.0)


def _get_mcp_config() -> Dict[str, str]:
    base_url = "http://127.0.0.1:7860"
    return {"base_url": base_url}


def _extract_bearer_token(auth_header: str) -> str:
    auth = (auth_header or "").strip()
    if not auth:
        return ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return auth


def _get_request_api_key(context: Optional[Context] = None) -> str:
    if context is not None:
        try:
            request = context.request_context.request
            if request is not None and hasattr(request, "headers"):
                auth_header = request.headers.get("authorization") or request.headers.get("Authorization") or ""
                token = _extract_bearer_token(auth_header)
                if token:
                    return token
        except Exception as exc:
            logger.error("Failed to read MCP request headers from context: %s", exc)

    if _get_http_headers is None:
        return ""
    try:
        headers = _get_http_headers() or {}
    except Exception as exc:
        logger.error("Failed to read MCP HTTP headers: %s", exc)
        return ""

    return _extract_bearer_token(headers.get("authorization") or headers.get("Authorization") or "")


def format_error(status_code: int, message: str) -> str:
    """Format error messages consistently."""
    return f"Error {status_code}: {message}"


def format_json_response(data: dict) -> str:
    """Format JSON response for readability."""
    try:
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error("Failed to format JSON: %s", exc)
        return str(data)


async def make_exa_request(
    endpoint: str,
    method: str = "POST",
    data: Optional[dict] = None,
    params: Optional[dict] = None,
    context: Optional[Context] = None,
) -> str:
    """
    Make a request to the Exa Pool API with proper error handling.
    """
    config = _get_mcp_config()
    base_url = config["base_url"]
    api_key = _get_request_api_key(context)
    if not api_key:
        return "Error: Authorization Bearer token is required."

    url = f"{base_url.rstrip('/')}{endpoint}"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "exa-pool-mcp-server/1.0",
    }

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            if method == "POST":
                response = await client.post(url, json=data, headers=headers)
            elif method == "GET":
                response = await client.get(url, params=params, headers=headers)
            else:
                return f"Error: Unsupported HTTP method: {method}"

            if response.status_code == 401:
                logger.error("Authentication failed - API key may be invalid")
                return format_error(401, "Authentication failed. API key may be invalid.")
            if response.status_code == 403:
                logger.error("Access forbidden")
                return format_error(403, "Access denied.")
            if response.status_code == 404:
                logger.error("Endpoint not found: %s", endpoint)
                return format_error(404, f"Endpoint not found: {endpoint}")
            if response.status_code == 429:
                logger.warning("Rate limited")
                return format_error(429, "Rate limited. Please try again later.")
            if response.status_code >= 500:
                logger.error("Server error: %s", response.status_code)
                return format_error(
                    response.status_code,
                    "Exa Pool server error. The service may be temporarily unavailable.",
                )

            response.raise_for_status()
            result = response.json()
            return format_json_response(result)

    except httpx.TimeoutException:
        logger.error("Request timeout for %s", endpoint)
        return "Error: Request timed out after 30 seconds. The Exa Pool API may be slow or unavailable."
    except httpx.ConnectError as exc:
        logger.error("Connection error: %s", exc)
        return f"Error: Unable to connect to Exa Pool API at {base_url}. Please check the service status."
    except httpx.HTTPStatusError as exc:
        logger.error("HTTP error %s: %s", exc.response.status_code, exc)
        return format_error(
            exc.response.status_code, f"HTTP request failed: {exc.response.reason_phrase}"
        )
    except ValueError as exc:
        logger.error("Invalid JSON response: %s", exc)
        return "Error: Received invalid JSON response from Exa Pool API."
    except Exception as exc:
        logger.error("Unexpected error: %s", exc, exc_info=True)
        return f"Error: {type(exc).__name__}: {str(exc)}"


@mcp.tool()
async def exa_search(
    query: str,
    num_results: int = 10,
    search_type: str = "auto",
    include_text: bool = False,
    ctx: Optional[Context] = None,
) -> str:
    """Search the web using Exa's AI-powered search engine."""
    if not query or not query.strip():
        return "Error: query parameter is required and cannot be empty"
    if not 1 <= num_results <= 100:
        return "Error: num_results must be between 1 and 100"
    if search_type not in ["auto", "neural", "fast", "deep"]:
        return "Error: search_type must be one of: auto, neural, fast, deep"

    payload: Dict[str, Any] = {
        "query": query.strip(),
        "numResults": num_results,
        "type": search_type,
    }
    if include_text:
        payload["contents"] = {"text": True}

    logger.info(
        "MCP search: query='%s', num_results=%s, type=%s",
        query,
        num_results,
        search_type,
    )
    return await make_exa_request("/search", data=payload, context=ctx)


@mcp.tool()
async def exa_get_contents(
    urls: List[str],
    include_text: bool = True,
    include_html: bool = False,
    ctx: Optional[Context] = None,
) -> str:
    """Get clean, parsed content from one or more web pages."""
    if not urls or len(urls) == 0:
        return "Error: urls parameter is required and cannot be empty"
    if len(urls) > 100:
        return "Error: Maximum 100 URLs allowed per request"
    for url in urls:
        if not url.startswith(("http://", "https://")):
            return f"Error: Invalid URL format: {url}. URLs must start with http:// or https://"

    payload: Dict[str, Any] = {"urls": urls, "text": include_text}
    if include_html:
        payload["htmlContent"] = True

    logger.info("MCP contents: %s urls", len(urls))
    return await make_exa_request("/contents", data=payload, context=ctx)


@mcp.tool()
async def exa_find_similar(
    url: str,
    num_results: int = 10,
    include_text: bool = False,
    ctx: Optional[Context] = None,
) -> str:
    """Find web pages similar to a given URL using semantic similarity."""
    if not url or not url.strip():
        return "Error: url parameter is required and cannot be empty"
    if not url.startswith(("http://", "https://")):
        return "Error: Invalid URL format. URLs must start with http:// or https://"
    if not 1 <= num_results <= 100:
        return "Error: num_results must be between 1 and 100"

    payload: Dict[str, Any] = {"url": url.strip(), "numResults": num_results}
    if include_text:
        payload["contents"] = {"text": True}

    logger.info("MCP findSimilar: %s", url)
    return await make_exa_request("/findSimilar", data=payload, context=ctx)


@mcp.tool()
async def exa_answer(query: str, include_text: bool = False, ctx: Optional[Context] = None) -> str:
    """Get an AI-generated answer to a question using Exa's Answer API."""
    if not query or not query.strip():
        return "Error: query parameter is required and cannot be empty"

    payload = {"query": query.strip(), "text": include_text}
    logger.info("MCP answer: %s", query)
    return await make_exa_request("/answer", data=payload, context=ctx)


@mcp.tool()
async def exa_create_research(
    instructions: str,
    model: str = "exa-research",
    ctx: Optional[Context] = None,
) -> str:
    """Create an asynchronous deep research task."""
    if not instructions or not instructions.strip():
        return "Error: instructions parameter is required and cannot be empty"
    if len(instructions) > 4096:
        return "Error: instructions must be 4096 characters or less"
    if model not in ["exa-research-fast", "exa-research", "exa-research-pro"]:
        return "Error: model must be one of: exa-research-fast, exa-research, exa-research-pro"

    payload = {"instructions": instructions.strip(), "model": model}
    logger.info("MCP create research: model=%s", model)
    return await make_exa_request("/research/v1", data=payload, context=ctx)


@mcp.tool()
async def exa_get_research(research_id: str, ctx: Optional[Context] = None) -> str:
    """Get the status and results of a research task."""
    if not research_id or not research_id.strip():
        return "Error: research_id parameter is required and cannot be empty"

    logger.info("MCP get research: %s", research_id)
    return await make_exa_request(
        f"/research/v1/{research_id.strip()}",
        method="GET",
        context=ctx,
    )


def get_mcp_http_app():
    if hasattr(mcp, "streamable_http_app"):
        return mcp.streamable_http_app()
    if hasattr(mcp, "http_app"):
        return mcp.http_app(path="/")
    if hasattr(mcp, "sse_app"):
        return mcp.sse_app(mount_path="/")
    raise RuntimeError("MCP server does not support HTTP transport")


def get_mcp_session_manager():
    if hasattr(mcp, "streamable_http_app"):
        try:
            if getattr(mcp, "_session_manager", None) is None:
                mcp.streamable_http_app()
            return mcp.session_manager
        except Exception as exc:
            logger.warning("MCP session manager not available: %s", exc)
            return None
    return None
