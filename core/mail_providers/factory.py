import logging
from typing import Callable, Optional

from core.config import config
from core.proxy_utils import extract_host, no_proxy_matches, parse_proxy_setting, sanitize_proxy_url, format_no_proxy
from core.cfmail_client import CloudflareMailClient
from core.duckmail_client import DuckMailClient
from core.freemail_client import FreemailClient
from core.gptmail_client import GPTMailClient
from core.moemail_client import MoemailClient

logger = logging.getLogger("exa.mail")


def _emit_proxy_log(log_cb: Optional[Callable[[str, str], None]], level: str, message: str) -> None:
    if level == "warning":
        logger.warning(message)
    elif level == "error":
        logger.error(message)
    else:
        logger.info(message)

    if log_cb:
        try:
            log_cb(level, message)
        except Exception:
            pass


def _resolve_mail_proxy(
    provider: str,
    effective_base_url: str,
    proxy: str,
    no_proxy: str,
    proxy_source_label: str,
    log_cb: Optional[Callable[[str, str], None]],
) -> str:
    target_host = extract_host(effective_base_url)
    bypassed = no_proxy_matches(target_host, no_proxy)
    effective_proxy = "" if bypassed else proxy
    _emit_proxy_log(
        log_cb,
        "info",
        f"[PROXY] mail provider={provider} source={proxy_source_label} "
        f"target={target_host or effective_base_url or 'unknown'} "
        f"proxy={sanitize_proxy_url(effective_proxy) or 'disabled'} "
        f"no_proxy={format_no_proxy(no_proxy)} bypass={'yes' if bypassed else 'no'}",
    )
    return effective_proxy


def create_temp_mail_client(
    provider: str,
    *,
    domain: Optional[str] = None,
    proxy: Optional[str] = None,
    log_cb: Optional[Callable[[str, str], None]] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    jwt_token: Optional[str] = None,
    verify_ssl: Optional[bool] = None,
):
    """
    创建临时邮箱客户端

    参数优先级：传入参数 > 全局配置
    """
    provider = (provider or "duckmail").lower()
    if proxy is None:
        proxy_source = config.basic.proxy_for_auth if config.basic.mail_proxy_enabled else ""
        proxy_source_label = "account_proxy" if config.basic.mail_proxy_enabled else "disabled"
    else:
        proxy_source = proxy
        proxy_source_label = "explicit"
    proxy, no_proxy = parse_proxy_setting(proxy_source)

    if provider == "moemail":
        effective_base_url = base_url or config.basic.moemail_base_url
        proxy = _resolve_mail_proxy(provider, effective_base_url, proxy, no_proxy, proxy_source_label, log_cb)
        return MoemailClient(
            base_url=effective_base_url,
            proxy=proxy,
            api_key=api_key or config.basic.moemail_api_key,
            domain=domain or config.basic.moemail_domain,
            log_callback=log_cb,
        )

    if provider == "freemail":
        effective_base_url = base_url or config.basic.freemail_base_url
        proxy = _resolve_mail_proxy(provider, effective_base_url, proxy, no_proxy, proxy_source_label, log_cb)
        return FreemailClient(
            base_url=effective_base_url,
            jwt_token=jwt_token or config.basic.freemail_jwt_token,
            proxy=proxy,
            verify_ssl=verify_ssl if verify_ssl is not None else config.basic.freemail_verify_ssl,
            log_callback=log_cb,
        )

    if provider == "gptmail":
        effective_base_url = base_url or config.basic.gptmail_base_url
        proxy = _resolve_mail_proxy(provider, effective_base_url, proxy, no_proxy, proxy_source_label, log_cb)
        return GPTMailClient(
            base_url=effective_base_url,
            api_key=api_key or config.basic.gptmail_api_key,
            proxy=proxy,
            verify_ssl=verify_ssl if verify_ssl is not None else config.basic.gptmail_verify_ssl,
            domain=domain or config.basic.gptmail_domain,
            log_callback=log_cb,
        )

    if provider == "cfmail":
        effective_base_url = base_url or config.basic.cfmail_base_url
        proxy = _resolve_mail_proxy(provider, effective_base_url, proxy, no_proxy, proxy_source_label, log_cb)
        return CloudflareMailClient(
            base_url=effective_base_url,
            proxy=proxy,
            api_key=api_key or config.basic.cfmail_api_key,
            admin_password=getattr(config.basic, "cfmail_admin_password", "") or "",
            domain=domain or config.basic.cfmail_domain,
            verify_ssl=verify_ssl if verify_ssl is not None else config.basic.cfmail_verify_ssl,
            log_callback=log_cb,
        )

    effective_base_url = base_url or config.basic.duckmail_base_url
    proxy = _resolve_mail_proxy(provider, effective_base_url, proxy, no_proxy, proxy_source_label, log_cb)
    return DuckMailClient(
        base_url=effective_base_url,
        proxy=proxy,
        verify_ssl=verify_ssl if verify_ssl is not None else config.basic.duckmail_verify_ssl,
        api_key=api_key or config.basic.duckmail_api_key,
        log_callback=log_cb,
    )
