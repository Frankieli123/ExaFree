"""
代理设置工具函数

支持格式:
- http://127.0.0.1:7890
- http://user:pass@127.0.0.1:7890
- socks5h://127.0.0.1:7890
- socks5h://user:pass@127.0.0.1:7890 | no_proxy=localhost,127.0.0.1,.local

NO_PROXY 格式:
- 逗号分隔的主机名或域名后缀
- 支持通配符前缀，如 .local 匹配 *.local
"""

import logging
import re
import secrets
import string
from typing import Tuple, Callable, Any, Optional
from urllib.parse import urlparse, unquote, quote
import functools

logger = logging.getLogger("exa.proxy")
_SESSION_PARAM_RE = re.compile(r"_(?:hard)?session-[a-z0-9]+", re.IGNORECASE)
_LIFETIME_PARAM_RE = re.compile(r"_lifetime-\d+", re.IGNORECASE)


def parse_proxy_setting(proxy_str: str) -> Tuple[str, str]:
    """
    解析代理设置字符串，提取代理 URL 和 NO_PROXY 列表

    Args:
        proxy_str: 代理设置字符串，格式如 "http://127.0.0.1:7890 | no_proxy=localhost,127.0.0.1"

    Returns:
        Tuple[str, str]: (proxy_url, no_proxy_list)
        - proxy_url: 代理地址，如 "http://127.0.0.1:7890"
        - no_proxy_list: NO_PROXY 列表字符串，如 "localhost,127.0.0.1"
    """
    if not proxy_str:
        return "", ""

    proxy_str = proxy_str.strip()
    if not proxy_str:
        return "", ""

    # 检查是否包含 no_proxy 设置
    # 支持格式: proxy_url | no_proxy=host1,host2
    no_proxy = ""
    proxy_url = proxy_str

    # 使用 | 分隔代理和 no_proxy
    if "|" in proxy_str:
        parts = proxy_str.split("|", 1)
        proxy_url = parts[0].strip()
        no_proxy_part = parts[1].strip()

        # 解析 no_proxy=xxx 格式
        no_proxy_match = re.match(r"no_proxy\s*=\s*(.+)", no_proxy_part, re.IGNORECASE)
        if no_proxy_match:
            no_proxy = no_proxy_match.group(1).strip()

    return normalize_proxy_url(proxy_url), no_proxy


def extract_host(url: str) -> str:
    """
    从 URL 中提取主机名

    Args:
        url: 完整 URL，如 "https://mail.chatgpt.org.uk/api/emails"

    Returns:
        str: 主机名，如 "mail.chatgpt.org.uk"
    """
    if not url:
        return ""

    url = url.strip()
    if not url:
        return ""

    # 如果没有协议前缀，添加一个以便解析
    if not url.startswith(("http://", "https://", "socks5://", "socks5h://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""


def no_proxy_matches(host: str, no_proxy: str) -> bool:
    """
    检查主机是否在 NO_PROXY 豁免列表中

    Args:
        host: 要检查的主机名，如 "mail.chatgpt.org.uk"
        no_proxy: NO_PROXY 列表字符串，如 "localhost,127.0.0.1,.local"

    Returns:
        bool: 如果主机在豁免列表中返回 True，否则返回 False

    匹配规则:
        - 精确匹配: "localhost" 匹配 "localhost"
        - 域名后缀匹配: ".local" 匹配 "foo.local", "bar.foo.local"
        - IP 地址匹配: "127.0.0.1" 精确匹配
    """
    if not host or not no_proxy:
        return False

    host = host.lower().strip()
    if not host:
        return False

    # 解析 no_proxy 列表
    no_proxy_list = [item.strip().lower() for item in no_proxy.split(",") if item.strip()]

    for pattern in no_proxy_list:
        if not pattern:
            continue

        # 精确匹配
        if host == pattern:
            return True

        # 域名后缀匹配 (如 .local 匹配 foo.local)
        if pattern.startswith("."):
            if host.endswith(pattern) or host == pattern[1:]:
                return True
        else:
            # 也支持不带点的后缀匹配 (如 local 匹配 foo.local)
            if host.endswith("." + pattern):
                return True

    return False


def normalize_proxy_url(proxy_str: str) -> str:
    """
    标准化代理 URL 格式

    支持的输入格式:
    - http://127.0.0.1:7890
    - http://user:pass@127.0.0.1:7890
    - socks5://127.0.0.1:7890
    - socks5h://127.0.0.1:7890
    - 127.0.0.1:7890 (自动添加 http://)
    - host:port:user:pass (旧格式，自动转换)

    Returns:
        str: 标准化的代理 URL
    """
    if not proxy_str:
        return ""

    proxy_str = proxy_str.strip()
    if not proxy_str:
        return ""

    def _normalize_with_scheme(scheme: str, remainder: str) -> str:
        remainder = (remainder or "").strip()
        if not remainder:
            return f"{scheme}://"
        if "@" in remainder:
            return f"{scheme}://{remainder}"
        parts = remainder.split(":")
        if len(parts) == 4:
            host, port, user, password = parts
            return f"{scheme}://{user}:{password}@{host}:{port}"
        return f"{scheme}://{remainder}"

    for scheme in ("http", "https", "socks5", "socks5h"):
        prefix = f"{scheme}://"
        if proxy_str.startswith(prefix):
            return _normalize_with_scheme(scheme, proxy_str[len(prefix):])

    # 尝试解析旧格式 host:port:user:pass
    parts = proxy_str.split(":")
    if len(parts) == 4:
        host, port, user, password = parts
        return f"http://{user}:{password}@{host}:{port}"
    elif len(parts) == 2:
        # host:port 格式
        return f"http://{proxy_str}"

    # 无法识别的格式，尝试添加 http:// 前缀
    return f"http://{proxy_str}"


def normalize_runtime_proxy_url(proxy_str: str) -> str:
    """
    规范化运行时代理 URL。

    说明：
    - 配置层允许用户输入 socks5h://，便于表达“代理端远程 DNS 解析”
    - 但 httpx 0.27.x 与 Playwright 文档均只声明支持 socks5://
    - 因此运行时对不兼容的 socks5h:// 做降级转换，避免客户端初始化失败
    """
    normalized = normalize_proxy_url(proxy_str)
    if normalized.startswith("socks5h://"):
        return "socks5://" + normalized[len("socks5h://"):]
    return normalized


def _mask_text(value: str, keep_start: int = 2, keep_end: int = 1) -> str:
    value = str(value or "")
    if not value:
        return ""
    if len(value) <= keep_start + keep_end:
        return "***"
    return f"{value[:keep_start]}***{value[-keep_end:]}"


def sanitize_proxy_url(proxy_str: str) -> str:
    """
    返回适合日志输出的代理地址（自动隐藏账号密码）。
    """
    normalized = normalize_proxy_url(proxy_str)
    if not normalized:
        return ""

    try:
        parsed = urlparse(normalized)
    except Exception:
        return normalized

    if not parsed.scheme or not parsed.hostname:
        return normalized

    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    auth = ""
    if parsed.username is not None:
        auth = _mask_text(parsed.username)
        if parsed.password is not None:
            auth += ":***"
        auth += "@"

    netloc = f"{auth}{host}"
    if parsed.port:
        netloc += f":{parsed.port}"

    return f"{parsed.scheme}://{netloc}"


def format_no_proxy(no_proxy: str) -> str:
    items = [item.strip() for item in str(no_proxy or "").split(",") if item.strip()]
    return ",".join(items) if items else "none"


def generate_proxy_session_id(length: int = 8) -> str:
    size = max(6, min(int(length or 8), 10))
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(size))


def is_evomi_proxy(proxy_str: str) -> bool:
    normalized = normalize_proxy_url(proxy_str)
    if not normalized:
        return False
    try:
        parsed = urlparse(normalized)
    except Exception:
        return False
    host = str(parsed.hostname or "").lower()
    return "evomi.com" in host and parsed.username is not None and parsed.password is not None


def build_evomi_session_proxy(
    proxy_str: str,
    *,
    session_id: Optional[str] = None,
    hard_session: bool = False,
    lifetime_minutes: Optional[int] = None,
) -> tuple[str, str]:
    """
    为 Evomi 代理生成带 session/hardsession 的新代理地址。

    Evomi 的 session 参数附加在密码段中，例如：
    http://user:pass_country-US_session-abc123@rp.evomi.com:1000
    """
    normalized = normalize_proxy_url(proxy_str)
    if not normalized:
        return "", ""

    parsed = urlparse(normalized)
    if parsed.username is None or parsed.password is None:
        return normalized, ""

    session_token = str(session_id or generate_proxy_session_id()).strip().lower()
    session_token = re.sub(r"[^a-z0-9]", "", session_token)[:10]
    if len(session_token) < 6:
        session_token = generate_proxy_session_id()

    password = unquote(parsed.password or "")
    password = _SESSION_PARAM_RE.sub("", password)
    password = _LIFETIME_PARAM_RE.sub("", password)

    suffix = f"_{'hardsession' if hard_session else 'session'}-{session_token}"
    if not hard_session and lifetime_minutes:
        lifetime = max(1, min(int(lifetime_minutes), 120))
        suffix += f"_lifetime-{lifetime}"
    password = f"{password}{suffix}"

    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = f"{quote(unquote(parsed.username or ''), safe='-._~')}:{quote(password, safe='-._~')}@{host}"
    if parsed.port:
        netloc += f":{parsed.port}"
    return f"{parsed.scheme}://{netloc}", session_token


def build_playwright_proxy_settings(proxy_str: str, no_proxy: str = "") -> Optional[dict]:
    """
    将代理 URL 转为 Playwright proxy 配置。

    Playwright 对代理的推荐结构是：
    - server: scheme://host:port
    - username/password: 单独字段
    - bypass: 可选 no_proxy
    """
    normalized = normalize_runtime_proxy_url(proxy_str)
    if not normalized:
        return None

    try:
        parsed = urlparse(normalized)
    except Exception:
        return {"server": normalized}

    if not parsed.scheme or not parsed.hostname:
        return {"server": normalized}

    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    server = f"{parsed.scheme}://{host}"
    if parsed.port:
        server += f":{parsed.port}"

    settings = {"server": server}
    bypass = format_no_proxy(no_proxy)
    if bypass != "none":
        settings["bypass"] = bypass
    if parsed.username is not None:
        settings["username"] = unquote(parsed.username)
    if parsed.password is not None:
        settings["password"] = unquote(parsed.password)
    return settings


def _extract_proxy_for_log(proxies: Any) -> str:
    if isinstance(proxies, dict):
        for key in ("https", "http", "all"):
            value = proxies.get(key)
            if value:
                return str(value)
        return ""
    return str(proxies or "")


def _emit_proxy_log(level: str, message: str, log_callback=None) -> None:
    try:
        if level == "error":
            logger.error(message)
        elif level == "warning":
            logger.warning(message)
        else:
            logger.info(message)
    except Exception:
        pass

    if log_callback:
        try:
            log_callback(level, message)
        except Exception:
            pass


def request_with_proxy_fallback(request_func: Callable, *args, **kwargs) -> Any:
    """
    带代理失败回退的请求包装器

    如果代理连接失败，自动禁用代理重试一次

    Args:
        request_func: 原始请求函数
        *args, **kwargs: 传递给请求函数的参数

    Returns:
        请求响应对象

    Raises:
        原始异常（如果直连也失败）
    """
    proxy_log_cb = kwargs.pop("proxy_log_cb", None)
    proxy_log_context = str(kwargs.pop("proxy_log_context", "") or "request").strip()

    # 代理相关的错误类型
    PROXY_ERRORS = (
        "ProxyError",
        "ConnectTimeout",
        "ConnectionError",
        "407",  # Proxy Authentication Required
        "502",  # Bad Gateway (代理问题)
        "503",  # Service Unavailable (代理问题)
    )

    try:
        # 首次尝试（使用代理）
        return request_func(*args, **kwargs)
    except Exception as e:
        error_str = str(e)
        error_type = type(e).__name__

        # 检查是否是代理相关错误
        is_proxy_error = any(err in error_str or err in error_type for err in PROXY_ERRORS)
        original_proxies = kwargs.get("proxies")

        if is_proxy_error and original_proxies:
            # 禁用代理重试
            proxy_text = sanitize_proxy_url(_extract_proxy_for_log(original_proxies)) or "disabled"
            _emit_proxy_log(
                "warning",
                f"[PROXY] {proxy_log_context} 代理请求失败，回退直连: "
                f"proxy={proxy_text}, error={error_type}: {error_str[:160]}",
                proxy_log_cb,
            )
            kwargs["proxies"] = None

            try:
                # 直连重试
                response = request_func(*args, **kwargs)
                _emit_proxy_log(
                    "warning",
                    f"[PROXY] {proxy_log_context} 直连重试成功",
                    proxy_log_cb,
                )
                return response
            except Exception as direct_exc:
                # 直连也失败，恢复原始代理设置并抛出原始异常
                kwargs["proxies"] = original_proxies
                _emit_proxy_log(
                    "error",
                    f"[PROXY] {proxy_log_context} 直连重试也失败: "
                    f"{type(direct_exc).__name__}: {str(direct_exc)[:160]}",
                    proxy_log_cb,
                )
                raise e
        else:
            # 不是代理错误，直接抛出
            raise
