"""
Exa 自动化登录与 API Key 提取。

流程：
1. 通过邮箱验证码登录 auth.exa.ai
2. 完成 onboarding（若存在）
3. 在 billing 页面兑换优惠码
4. 在 API Keys 页面创建 key 并提取
"""

from __future__ import annotations

import random
import re
import os
import shutil
import subprocess
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from core.config import config
from core.playwright_proxy_bridge import (
    proxy_needs_playwright_bridge,
    PlaywrightSocksBridge,
)
from core.proxy_utils import (
    normalize_proxy_url,
    normalize_runtime_proxy_url,
    sanitize_proxy_url,
    format_no_proxy,
    build_playwright_proxy_settings,
)

try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright
except Exception:  # pragma: no cover - runtime dependency check
    sync_playwright = None
    PlaywrightTimeoutError = Exception


UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    flags=re.IGNORECASE,
)
CHECKPOINT_CODE_RE = re.compile(r"\bcode\s*(\d+)\b", flags=re.IGNORECASE)
DEBUG_ARTIFACT_TTL_SECONDS = 7 * 24 * 3600
DEBUG_ARTIFACT_MAX_FILES = 30


class ExaAutomationError(RuntimeError):
    """带错误码的自动化异常，便于上层做更明确的产品提示。"""

    def __init__(self, message: str, code: str = "exa_automation_failed") -> None:
        super().__init__(message)
        self.code = code


class ExaAutomation:
    """Exa 自动化流程封装（同步，适合 run_in_executor 调用）。"""

    def __init__(
        self,
        proxy: str = "",
        no_proxy: str = "",
        timeout_ms: int = 90_000,
        log_callback=None,
        headless: Optional[bool] = None,
    ) -> None:
        self.proxy_source = normalize_proxy_url(proxy or "")
        self.proxy = normalize_runtime_proxy_url(self.proxy_source)
        self.no_proxy = str(no_proxy or "").strip()
        self.proxy_bridge = None
        self.needs_proxy_bridge = proxy_needs_playwright_bridge(self.proxy_source)
        self.playwright_proxy = build_playwright_proxy_settings(self.proxy_source, self.no_proxy)
        self.timeout_ms = timeout_ms
        self.log_callback = log_callback
        self.headless = self._resolve_headless(headless)
        self.browser_mode = "headless" if self.headless else "headful"

    def register_and_setup(
        self,
        email: str,
        mail_client,
        coupon_code: str = "",
        redeem_coupon: bool = False,
    ) -> Dict[str, Any]:
        """
        执行 Exa 登录 + 初始化流程，返回可落库配置。
        """
        if sync_playwright is None:
            return {
                "success": False,
                "error": "playwright 未安装，请先安装 playwright 并执行 playwright install chromium",
            }

        start_time = datetime.now()
        self._log("info", f"🌐 打开 Exa 登录页: {email}")

        xvfb_process = None
        try:
            self._ensure_proxy_bridge()
            with sync_playwright() as p:
                xvfb_process, launch_env = self._prepare_browser_launch_env()
                launch_kwargs: Dict[str, Any] = {
                    "headless": self.headless,
                }
                if self.playwright_proxy:
                    launch_kwargs["proxy"] = dict(self.playwright_proxy)
                launch_kwargs["args"] = ["--no-sandbox", "--disable-dev-shm-usage"]
                if launch_env:
                    launch_kwargs["env"] = launch_env

                browser = p.chromium.launch(**launch_kwargs)
                context = browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
                    ),
                    locale="en-US",
                    viewport={"width": 1366, "height": 768},
                )
                context.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
                )
                page = context.new_page()

                try:
                    self._login_with_otp(page, email, mail_client, start_time)
                    onboarding_key = self._complete_onboarding(page)

                    balance = None
                    coupon_status = "not_attempted"
                    if redeem_coupon:
                        balance, coupon_status = self._redeem_coupon(page, coupon_code)

                    created_api_key = self._create_api_key(page)
                    account_config = self._build_account_config(
                        email=email,
                        api_key=created_api_key,
                        coupon_status=coupon_status,
                        balance=balance,
                    )

                    return {
                        "success": True,
                        "config": account_config,
                        "created_api_key": created_api_key,
                        "onboarding_api_key": onboarding_key,
                        "coupon_status": coupon_status,
                        "balance": balance,
                    }
                finally:
                    try:
                        context.close()
                    except Exception:
                        pass
                    try:
                        browser.close()
                    except Exception:
                        pass
        except Exception as exc:
            exc = self._map_proxy_error(exc)
            # 产品层会统一输出最终失败结论；这里避免对可预期业务错误重复记一条相同错误。
            if not isinstance(exc, ExaAutomationError):
                self._log("error", f"❌ Exa 自动化失败: {exc}")
            result = {"success": False, "error": str(exc)}
            if isinstance(exc, ExaAutomationError):
                result["error_code"] = exc.code
            return result
        finally:
            self._stop_virtual_display(xvfb_process)
            self._close_proxy_bridge()

    def refresh_api_key(
        self,
        email: str,
        mail_client,
    ) -> Dict[str, Any]:
        """刷新账号 key（登录 + 重新创建 key，不重复兑换优惠码）。"""
        return self.register_and_setup(
            email=email,
            mail_client=mail_client,
            coupon_code="",
            redeem_coupon=False,
        )

    def check_browser_environment(self) -> Dict[str, Any]:
        """仅检查浏览器环境是否能正常打开 Exa 登录入口，不执行注册。"""
        if sync_playwright is None:
            return {
                "success": False,
                "error": "playwright 未安装，请先安装 playwright 并执行 playwright install chromium",
                "error_code": "playwright_not_installed",
                "browser_mode": self.browser_mode,
            }

        xvfb_process = None
        try:
            self._ensure_proxy_bridge()
            with sync_playwright() as p:
                xvfb_process, launch_env = self._prepare_browser_launch_env()
                launch_kwargs: Dict[str, Any] = {
                    "headless": self.headless,
                    "args": ["--no-sandbox", "--disable-dev-shm-usage"],
                }
                if self.playwright_proxy:
                    launch_kwargs["proxy"] = dict(self.playwright_proxy)
                if launch_env:
                    launch_kwargs["env"] = launch_env

                browser = p.chromium.launch(**launch_kwargs)
                context = browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
                    ),
                    locale="en-US",
                    viewport={"width": 1366, "height": 768},
                )
                context.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
                )
                page = context.new_page()

                try:
                    self._safe_goto(
                        page,
                        "https://auth.exa.ai/?callbackUrl=https%3A%2F%2Fdashboard.exa.ai%2F",
                        wait_until="domcontentloaded",
                        timeout=self.timeout_ms,
                        retries=1,
                        stage="浏览器自检",
                    )
                    selectors = [
                        'input[placeholder="Email"]',
                        'button:has-text("Continue with Google")',
                        'button:has-text("Continue")',
                    ]
                    if not self._wait_for_any_selector(page, selectors, timeout_ms=15_000):
                        self._dump_page_debug(page, "browser_check_unknown")
                        raise ExaAutomationError(
                            "Exa 登录页未在预期时间内加载完成，请检查网络、代理和运行环境。",
                            code="exa_browser_check_unknown",
                        )

                    self._raise_if_email_login_unavailable(page, "浏览器自检")
                    return {
                        "success": True,
                        "browser_mode": self.browser_mode,
                        "message": "浏览器环境基础检查通过，已能正常打开 Exa 登录页。",
                    }
                finally:
                    try:
                        context.close()
                    except Exception:
                        pass
                    try:
                        browser.close()
                    except Exception:
                        pass
        except Exception as exc:
            exc = self._map_proxy_error(exc)
            result = {
                "success": False,
                "error": str(exc),
                "browser_mode": self.browser_mode,
            }
            if isinstance(exc, ExaAutomationError):
                result["error_code"] = exc.code
            return result
        finally:
            self._stop_virtual_display(xvfb_process)
            self._close_proxy_bridge()

    def _login_with_otp(self, page, email: str, mail_client, start_time: datetime) -> None:
        auth_url = "https://auth.exa.ai/?callbackUrl=https%3A%2F%2Fdashboard.exa.ai%2F"
        self._safe_goto(
            page,
            auth_url,
            wait_until="domcontentloaded",
            timeout=self.timeout_ms,
            retries=1,
            stage="OTP 登录",
        )

        page.wait_for_selector('input[placeholder="Email"]', timeout=60_000)
        page.fill('input[placeholder="Email"]', email)
        page.locator('form:has(input[placeholder="Email"]) button[type="submit"]').first.click()
        otp_ready = self._wait_for_any_selector(
            page,
            [
                'text="Verify your email"',
                'text="Check your email"',
                'input[placeholder="Enter verification code"]',
            ],
            timeout_ms=60_000,
        )
        if not otp_ready:
            self._raise_if_email_login_unavailable(page, "邮箱提交")
            self._raise_if_browser_verification_blocked(page, "邮箱提交")
            self._dump_page_debug(page, "otp_email_submit")
            raise RuntimeError("提交邮箱后未进入 OTP 验证页")
        self._log("info", "📬 等待验证码邮件...")
        code = mail_client.poll_for_code(timeout=240, interval=3, since_time=start_time)
        if not code:
            raise RuntimeError("未收到 Exa OTP 验证码")
        self._log("info", f"✅ 收到 OTP: {code}")

        page.fill('input[placeholder="Enter verification code"]', code)
        page.locator('button:has-text("VERIFY CODE")').first.click()

        # 某些会话为 SPA 跳转，不触发 commit/load，直接等 wait_for_url 会卡住到超时。
        # 这里改为短轮询 URL，尽快识别是否已进入 dashboard 域名。
        entered_dashboard = False
        otp_wait_start = time.time()
        page.wait_for_timeout(700)
        self._raise_if_email_login_unavailable(page, "OTP 登录")
        self._raise_if_browser_verification_blocked(page, "OTP 登录")
        deadline = time.time() + 22.0
        while time.time() < deadline:
            self._raise_if_email_login_unavailable(page, "OTP 登录")
            self._raise_if_browser_verification_blocked(page, "OTP 登录")
            current_url = page.url
            if self._get_url_host(current_url) == "dashboard.exa.ai":
                entered_dashboard = True
                break
            if self._is_otp_invalid_tip_visible(page):
                raise RuntimeError("OTP 无效，Exa 返回 Invalid verification code")
            try:
                page.wait_for_load_state("domcontentloaded", timeout=1200)
            except Exception:
                pass
            page.wait_for_timeout(300)

        if not entered_dashboard:
            current_url = page.url
            if self._is_otp_invalid_tip_visible(page):
                raise RuntimeError("OTP 无效，Exa 返回 Invalid verification code")
            # 若仍停留在 auth.exa.ai，尝试手动打开 dashboard 触发会话写入
            if self._get_url_host(current_url) == "auth.exa.ai":
                self._log("warning", "⚠️ OTP 后未自动跳转 Dashboard，尝试手动打开...")
                self._safe_goto(
                    page,
                    "https://dashboard.exa.ai/",
                    wait_until="domcontentloaded",
                    timeout=self.timeout_ms,
                    retries=2,
                    stage="Dashboard 跳转",
                )
                if self._get_url_host(page.url) == "dashboard.exa.ai":
                    entered_dashboard = True
            if not entered_dashboard:
                raise RuntimeError(f"OTP 提交后未进入 Exa Dashboard，当前页面: {current_url}")

        otp_wait_cost = time.time() - otp_wait_start
        if otp_wait_cost > 8:
            self._log("warning", f"⚠️ OTP 跳转耗时较长: {otp_wait_cost:.1f}s，当前页面: {page.url}")

        if self._is_otp_invalid_tip_visible(page):
            raise RuntimeError("OTP 无效，Exa 返回 Invalid verification code")

        self._log("info", f"✅ OTP 提交后已进入: {page.url}")

    def _complete_onboarding(self, page) -> Optional[str]:
        onboarding_key = None
        self._safe_goto(
            page,
            "https://dashboard.exa.ai/onboarding",
            wait_until="domcontentloaded",
            timeout=self.timeout_ms,
            retries=2,
            stage="onboarding",
        )
        page.wait_for_timeout(1200)
        self._raise_if_browser_verification_blocked(page, "onboarding")

        if "onboarding" not in page.url:
            return None

        next_selectors = [
            'button:has-text("Next")',
            'button:has-text("Continue")',
            'button:has-text("Continue to Step 2")',
            'button:has-text("Proceed")',
        ]

        # Step 1 需要完成三组选择才能点亮 Next：
        # 1) coding with   2) API client   3) building
        # 按旧流程优先选择 Codex / Python / Coding agent，并做重试。
        step1_choice_groups = [
            ["Codex", "Cursor", "Claude", "Devin", "Other"],
            ["Python", "OpenAI SDK", "JavaScript", "cURL", "MCP", "Other"],
            ["Coding agent", "Coding Agent", "Web search tool", "News monitoring", "E-commerce", "People + Company search", "Other"],
        ]

        step1_deadline = time.time() + 15.0
        while time.time() < step1_deadline:
            for labels in step1_choice_groups:
                selectors = [f'button:has-text("{label}")' for label in labels]
                if self._click_any_visible(page, selectors):
                    page.wait_for_timeout(250)

            next_btn = self._first_visible_locator(page, next_selectors)
            if next_btn is not None and next_btn.is_enabled():
                next_btn.click()
                page.wait_for_timeout(1200)
                break

            page.wait_for_timeout(350)

        # Step 2（生成代码）使用多文案兼容，直到拿到 key 或超时。
        generate_selectors = [
            'button:has-text("Generate Code")',
            'button:has-text("Generate")',
            'button:has-text("Generate API Key")',
            'button:has-text("Create Code")',
        ]
        generate_deadline = time.time() + 18.0
        while time.time() < generate_deadline and onboarding_key is None and "onboarding" in page.url:
            if self._click_any_visible(page, generate_selectors):
                page.wait_for_timeout(2200)

            onboarding_key = self._extract_first_uuid(page.inner_text("body"))
            if onboarding_key:
                break

            # 如果仍在 step1，继续尝试推进到下一步
            next_btn = self._first_visible_locator(page, next_selectors)
            if next_btn is not None and next_btn.is_enabled():
                next_btn.click()
                page.wait_for_timeout(1000)
            else:
                page.wait_for_timeout(400)

        go_dashboard_selectors = [
            'button:has-text("Go to Dashboard")',
            'button:has-text("Continue to Dashboard")',
            'button:has-text("Back to Dashboard")',
            'button:has-text("Open Dashboard")',
            'a:has-text("Go to Dashboard")',
            'a:has-text("Continue to Dashboard")',
        ]
        exit_deadline = time.time() + 10.0
        while time.time() < exit_deadline and "onboarding" in page.url:
            if self._click_any_visible(page, go_dashboard_selectors):
                page.wait_for_timeout(900)
                continue
            page.wait_for_timeout(300)

        # onboarding 仍未完成时直接失败，避免产出“未领新手奖励”的账号。
        if "dashboard.exa.ai" in page.url and "onboarding" in page.url:
            self._dump_onboarding_debug(page)
            raise RuntimeError(f"onboarding 未完成，仍停留在: {page.url}")

        if not onboarding_key:
            self._log("warning", "⚠️ onboarding 未提取到生成 key，可能未触发完整新手引导奖励")

        return onboarding_key

    def _redeem_coupon(self, page, coupon_code: str) -> tuple[Optional[str], str]:
        self._safe_goto(
            page,
            "https://dashboard.exa.ai/billing",
            wait_until="domcontentloaded",
            timeout=self.timeout_ms,
            retries=1,
            stage="billing",
        )
        page.wait_for_timeout(1200)
        self._raise_if_browser_verification_blocked(page, "billing")

        def read_balance_with_retry(timeout_sec: float = 12.0) -> Optional[str]:
            deadline = time.time() + timeout_sec
            while time.time() < deadline:
                text = page.inner_text("body")
                bal = self._extract_balance(text)
                if bal:
                    return bal
                page.wait_for_timeout(400)
            return None

        coupon_status = "not_attempted"
        balance_before = read_balance_with_retry()

        # 先尝试展开优惠码输入区域，兼容折叠/弹窗样式。
        coupon_expand_selectors = [
            'button:has-text("Have a coupon")',
            'button:has-text("Add coupon")',
            'button:has-text("Add Coupon")',
            'button:has-text("Promo code")',
            'button:has-text("Coupon code")',
            'button:has-text("Redeem code")',
        ]
        self._click_any_visible(page, coupon_expand_selectors)
        page.wait_for_timeout(300)

        coupon_input_selectors = [
            'input[placeholder="Enter coupon code"]',
            'input[placeholder*="coupon" i]',
            'input[placeholder*="promo" i]',
            'input[aria-label*="coupon" i]',
            'input[aria-label*="promo" i]',
            'input[name*="coupon" i]',
            'input[name*="promo" i]',
            'input[id*="coupon" i]',
            'input[id*="promo" i]',
        ]
        coupon_input = self._first_visible_locator(page, coupon_input_selectors)

        if coupon_input is not None:
            coupon_input.fill(coupon_code)
            page.wait_for_timeout(250)

            redeem_btn_selectors = [
                'button:has-text("Redeem")',
                'button:has-text("Apply")',
                'button:has-text("Apply Code")',
                'button:has-text("Apply Coupon")',
                'button:has-text("Use Code")',
            ]
            redeem_btn = self._first_visible_locator(page, redeem_btn_selectors)
            if redeem_btn is not None and redeem_btn.is_enabled():
                redeem_btn.click()
                coupon_status = "submitted"
                page.wait_for_timeout(3400)
            else:
                try:
                    coupon_input.press("Enter")
                    coupon_status = "submitted"
                    page.wait_for_timeout(3400)
                except Exception:
                    coupon_status = "redeem_disabled"
        else:
            coupon_status = "coupon_input_not_found"

        body = page.inner_text("body").lower()
        if (
            "successfully redeemed" in body
            or ("redeemed" in body and "coupon" in body)
            or ("applied" in body and ("coupon" in body or "promo" in body))
        ):
            coupon_status = "redeemed_successfully"
        elif ("already redeemed" in body) or ("already used" in body) or ("already" in body and "coupon" in body):
            coupon_status = "already_redeemed"
        elif ("invalid" in body and ("coupon" in body or "promo" in body)) or ("expired" in body and "coupon" in body):
            coupon_status = "invalid_coupon"

        balance = read_balance_with_retry() or balance_before
        self._log("info", f"🎟️ 优惠码状态: {coupon_status}")
        if balance_before:
            self._log("info", f"💰 兑换前余额: {balance_before}")
        if balance:
            self._log("info", f"💰 兑换后余额: {balance}")
        if balance_before and balance:
            try:
                before_num = float(balance_before.replace(",", ""))
                after_num = float(balance.replace(",", ""))
                delta = after_num - before_num
                self._log("info", f"📈 余额变化: {delta:+.2f}")
            except Exception:
                pass

        return balance, coupon_status

    def _create_api_key(self, page) -> str:
        self._safe_goto(
            page,
            "https://dashboard.exa.ai/api-keys",
            wait_until="domcontentloaded",
            timeout=self.timeout_ms,
            retries=1,
            stage="API Keys",
        )
        page.wait_for_timeout(1000)
        self._raise_if_browser_verification_blocked(page, "API Keys")

        create_btn = page.locator('button:has-text("Create Key")').first
        if not create_btn.count() or not create_btn.is_visible():
            raise RuntimeError("未找到 Create Key 按钮")
        create_btn.click()
        page.wait_for_timeout(500)

        name_input = page.locator('input[placeholder="Project name"]').first
        if not name_input.count() or not name_input.is_visible():
            raise RuntimeError("未找到 API key 名称输入框")
        name_input.fill(f"pool-{int(time.time())}-{random.randint(100, 999)}")

        create_confirm = page.locator('button:has-text("Create a Key")').first
        if not create_confirm.count() or not create_confirm.is_enabled():
            raise RuntimeError("Create a Key 按钮不可用")
        create_confirm.click()

        key_input = page.locator("input[readonly]").first
        key_input.wait_for(timeout=15_000)
        key_value = key_input.input_value().strip()
        if not UUID_RE.fullmatch(key_value):
            raise RuntimeError(f"创建后的 Key 格式异常: {key_value[:24]}")

        self._click_if_visible(page, 'button:has-text("Done")') or self._click_if_visible(page, 'button:has-text("Close")')
        page.wait_for_timeout(300)
        masked = f"{key_value[:6]}...{key_value[-4:]}"
        self._log("info", f"🔑 已提取 API key: {masked}")
        return key_value

    def _build_account_config(
        self,
        email: str,
        api_key: str,
        coupon_status: str,
        balance: Optional[str],
    ) -> Dict[str, Any]:
        return {
            "id": email,
            "exa_api_key": api_key,
            "coupon_status": coupon_status,
            "balance": balance,
            # 保留旧字段，兼容当前前端与账户加载逻辑
            "secure_c_ses": api_key,
            "host_c_oses": "",
            "csesidx": "exa",
            "config_id": "exa",
            "expires_at": None,
            "disabled": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _extract_first_uuid(text: str) -> Optional[str]:
        m = UUID_RE.search(text or "")
        return m.group(0) if m else None

    @staticmethod
    def _extract_balance(text: str) -> Optional[str]:
        m = re.search(r"Remaining Balance\s*\$([0-9][0-9,]*(?:\.[0-9]{2})?)", text or "", flags=re.I)
        return m.group(1) if m else None

    @staticmethod
    def _is_otp_invalid_tip_visible(page) -> bool:
        """
        OTP 提交后页面可能正在跳转，旧 execution context 会被销毁。
        这里每次重建 locator 并吞掉瞬时异常，避免误中断自动化流程。
        """
        try:
            tip = page.locator('text="Invalid verification code."').first
            return tip.count() > 0 and tip.is_visible()
        except Exception:
            return False

    @staticmethod
    def _click_if_visible(page, selector: str) -> bool:
        loc = page.locator(selector).first
        if loc.count() and loc.is_visible() and loc.is_enabled():
            loc.click()
            return True
        return False

    @staticmethod
    def _click_any_visible(page, selectors) -> bool:
        for selector in selectors:
            if ExaAutomation._click_if_visible(page, selector):
                return True
        return False

    @staticmethod
    def _first_visible_locator(page, selectors):
        for selector in selectors:
            loc = page.locator(selector).first
            if loc.count() and loc.is_visible():
                return loc
        return None

    def _wait_for_any_selector(self, page, selectors, timeout_ms: int) -> bool:
        deadline = time.time() + max(1, timeout_ms) / 1000.0
        while time.time() < deadline:
            if self._first_visible_locator(page, selectors) is not None:
                return True
            self._raise_if_browser_verification_blocked(page, "页面等待")
            self._raise_if_email_login_unavailable(page, "页面等待")
            try:
                page.wait_for_load_state("domcontentloaded", timeout=1000)
            except Exception:
                pass
            page.wait_for_timeout(250)
        return self._first_visible_locator(page, selectors) is not None

    @staticmethod
    def _get_url_host(url: str) -> str:
        try:
            return urlparse(url).hostname or ""
        except Exception:
            return ""

    def _safe_goto(
        self,
        page,
        url: str,
        wait_until: str = "domcontentloaded",
        timeout: Optional[int] = None,
        retries: int = 1,
        stage: str = "",
    ) -> None:
        last_exc = None
        effective_timeout = timeout or self.timeout_ms
        for attempt in range(retries + 1):
            try:
                page.goto(url, wait_until=wait_until, timeout=effective_timeout)
                self._raise_if_browser_verification_blocked(page, stage or url)
                return
            except Exception as exc:
                last_exc = exc
                if "net::ERR_ABORTED" not in str(exc) or attempt >= retries:
                    raise
                self._log("warning", f"⚠️ 页面跳转被中止，重试 {attempt + 1}/{retries}")
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=3000)
                except Exception:
                    pass
                page.wait_for_timeout(500 + attempt * 300)
        if last_exc:
            raise last_exc

    def _log(self, level: str, message: str) -> None:
        if not self.log_callback:
            return
        try:
            self.log_callback(level, message)
        except Exception:
            return

    def _map_proxy_error(self, exc: Exception) -> Exception:
        text = str(exc or "")
        known_markers = (
            "ERR_SOCKS_CONNECTION_FAILED",
            "ERR_PROXY_CONNECTION_FAILED",
            "ERR_NO_SUPPORTED_PROXIES",
            "ERR_TUNNEL_CONNECTION_FAILED",
            "NS_ERROR_PROXY_CONNECTION_REFUSED",
            "Browser does not support socks5 proxy authentication",
        )
        marker = next((item for item in known_markers if item in text), "")
        if not marker:
            return exc
        return ExaAutomationError(
            f"浏览器代理连接失败（{marker}），当前代理={sanitize_proxy_url(self.proxy) or 'disabled'}，"
            f"请检查代理协议、地址、端口和账号密码是否正确。",
            code="exa_proxy_connection_failed",
        )

    def _close_proxy_bridge(self) -> None:
        if self.proxy_bridge is None:
            return
        try:
            self.proxy_bridge.close()
        except Exception:
            pass
        self.proxy_bridge = None

    def _ensure_proxy_bridge(self) -> None:
        if not self.needs_proxy_bridge or self.proxy_bridge is not None:
            return
        self.proxy_bridge = PlaywrightSocksBridge(self.proxy_source).start()
        self.playwright_proxy = {"server": self.proxy_bridge.local_url}
        bypass = format_no_proxy(self.no_proxy)
        if bypass != "none":
            self.playwright_proxy["bypass"] = bypass

    def _dump_onboarding_debug(self, page) -> None:
        self._dump_page_debug(page, "onboarding")

    def _dump_page_debug(self, page, label: str) -> None:
        """输出当前页面诊断信息，便于快速定位选择器或风控页面问题。"""
        try:
            title_text = (page.title() or "").strip()
        except Exception:
            title_text = ""

        try:
            body_text = (page.inner_text("body") or "").strip()
        except Exception:
            body_text = ""

        try:
            button_texts = page.eval_on_selector_all(
                "button",
                "els => els.map(el => (el.innerText || '').trim()).filter(Boolean)",
            )
        except Exception:
            button_texts = []

        short_body = re.sub(r"\s+", " ", body_text)[:1200] if body_text else ""
        self._log("warning", f"⚠️ {label} 页面标题: {title_text}")
        self._log("warning", f"⚠️ {label} 页面按钮: {button_texts}")
        self._log("warning", f"⚠️ {label} 页面正文片段: {short_body}")

        try:
            debug_dir = Path("data") / "debug"
            debug_dir.mkdir(parents=True, exist_ok=True)
            self._cleanup_debug_artifacts(debug_dir)
            ts = int(time.time())
            safe_label = re.sub(r"[^a-z0-9_-]+", "_", (label or "page").strip().lower())
            screenshot_path = debug_dir / f"exa_{safe_label}_{ts}.png"
            page.screenshot(path=str(screenshot_path), full_page=True)
            self._log("warning", f"🖼️ {label} 截图已保存: {screenshot_path.resolve()}")
        except Exception as exc:
            self._log("warning", f"⚠️ 保存 {label} 截图失败: {exc}")

    def _detect_browser_verification_block(self, page) -> Optional[Dict[str, Any]]:
        try:
            title_text = (page.title() or "").strip()
        except Exception:
            title_text = ""

        try:
            body_text = (page.inner_text("body", timeout=1200) or "").strip()
        except Exception:
            body_text = ""

        combined = "\n".join(part for part in (title_text, body_text) if part).strip()
        if not combined:
            return None

        haystack = combined.lower()
        has_checkpoint_title = "vercel security checkpoint" in haystack
        has_verifying_browser = (
            "we're verifying your browser" in haystack
            or "we are verifying your browser" in haystack
        )
        has_failed_verify = "failed to verify your browser" in haystack

        blocked = (
            has_failed_verify
            or has_checkpoint_title
            or has_verifying_browser
            or ("code 21" in haystack and "browser" in haystack)
        )
        if not blocked:
            return None

        code_match = CHECKPOINT_CODE_RE.search(combined)
        excerpt = re.sub(r"\s+", " ", combined)[:240]
        markers = []
        if has_checkpoint_title:
            markers.append("Vercel Security Checkpoint")
        if code_match:
            markers.append(f"Code {code_match.group(1)}")
        if has_verifying_browser:
            markers.append("We're verifying your browser")
        if has_failed_verify:
            markers.append("Failed to verify your browser")
        return {
            "code": code_match.group(1) if code_match else "",
            "title": title_text,
            "excerpt": excerpt,
            "markers": markers,
        }

    def _raise_if_browser_verification_blocked(self, page, stage: str) -> None:
        details = self._detect_browser_verification_block(page)
        if not details:
            return

        self._log("warning", f"⚠️ 检测到浏览器校验拦截: {details['excerpt']}")
        self._dump_page_debug(page, f"browser_checkpoint_{stage}")

        if self.headless:
            guidance = (
                "当前系统设置为无头浏览器模式。请到后台设置 -> 自动注册，将“Exa 浏览器模式”切换为"
                "“有头浏览器（兼容性优先）”后重新执行注册。"
            )
        else:
            guidance = (
                "当前已使用有头浏览器模式。请继续排查代理/IP 信誉、网络出口环境，"
                "或稍后重试。"
            )

        details_text = " / ".join(details.get("markers") or []) or details.get("excerpt") or "Vercel Security Checkpoint"
        raise ExaAutomationError(
            f"检测到 Exa/Vercel 浏览器校验拦截（{details_text}），"
            f"发生在{stage}阶段。{guidance}",
            code="exa_browser_verification_blocked",
        )

    def _detect_email_login_unavailable(self, page) -> bool:
        try:
            body_text = (page.inner_text("body", timeout=1200) or "").strip().lower()
        except Exception:
            return False
        return (
            "unable to sign in with email" in body_text
            and "try signing in with google instead" in body_text
        )

    def _raise_if_email_login_unavailable(self, page, stage: str) -> None:
        if not self._detect_email_login_unavailable(page):
            return
        self._dump_page_debug(page, f"email_login_unavailable_{stage}")
        raise ExaAutomationError(
            f"Exa 当前拒绝邮箱 OTP 登录，发生在{stage}阶段。页面提示“Unable to sign in with email”。"
            "这通常是 Exa 侧临时风控或当前网络/IP 被限制，和浏览器是否无头不完全等价。"
            "建议稍后重试，或更换代理/IP 后再执行注册。",
            code="exa_email_login_unavailable",
        )

    def _prepare_browser_launch_env(self) -> tuple[Optional[subprocess.Popen], Optional[Dict[str, str]]]:
        self._log("info", f"🧭 Exa 浏览器模式: {self.browser_mode}")
        if self.proxy_bridge is not None:
            self._log(
                "info",
                f"🔁 检测到 SOCKS5 认证代理，已启用本地桥接: "
                f"{sanitize_proxy_url(self.proxy_source)} -> {self.proxy_bridge.local_url}",
            )
        auth_enabled = bool(self.playwright_proxy and (self.playwright_proxy.get("username") or self.playwright_proxy.get("password")))
        self._log(
            "info",
            f"🔌 Exa 浏览器代理: "
            f"{(self.playwright_proxy or {}).get('server') if self.proxy_bridge is not None else (sanitize_proxy_url(self.proxy) or 'disabled')} "
            f"(auth={'yes' if auth_enabled else 'no'}, bypass={format_no_proxy(self.no_proxy)})",
        )
        if self.headless:
            return None, None

        current_display = str(os.environ.get("DISPLAY") or "").strip()
        if current_display:
            self._log("info", f"🖥️ 检测到 DISPLAY={current_display}，将使用有头浏览器")
            return None, None

        xvfb_path = shutil.which("Xvfb")
        if not xvfb_path:
            raise ExaAutomationError(
                "当前已切换为有头浏览器模式，但运行环境没有 DISPLAY，且未安装 Xvfb。"
                "请安装 xvfb，或改回无头浏览器模式后重试。",
                code="exa_browser_display_unavailable",
            )

        for display_num in range(90, 110):
            display_name = f":{display_num}"
            proc = subprocess.Popen(
                [
                    xvfb_path,
                    display_name,
                    "-screen",
                    "0",
                    "1366x768x24",
                    "-nolisten",
                    "tcp",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if self._wait_for_xvfb_ready(proc, display_num):
                launch_env = dict(os.environ)
                launch_env["DISPLAY"] = display_name
                self._log("info", f"🖥️ 未检测到 DISPLAY，已自动启动 Xvfb {display_name}")
                return proc, launch_env
            self._stop_virtual_display(proc)

        raise ExaAutomationError(
            "当前已切换为有头浏览器模式，但自动启动 Xvfb 失败。请检查系统图形环境后重试。",
            code="exa_browser_display_unavailable",
        )

    @staticmethod
    def _wait_for_xvfb_ready(proc: subprocess.Popen, display_num: int, timeout_sec: float = 4.0) -> bool:
        socket_path = Path("/tmp/.X11-unix") / f"X{display_num}"
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            if proc.poll() is not None:
                return False
            if socket_path.exists():
                return True
            time.sleep(0.1)
        return False

    def _stop_virtual_display(self, proc: Optional[subprocess.Popen]) -> None:
        if proc is None:
            return
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _cleanup_debug_artifacts(self, debug_dir: Path) -> None:
        try:
            files = sorted(
                [p for p in debug_dir.glob("exa_*") if p.is_file()],
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
        except Exception:
            return

        now = time.time()
        expired = []
        for file_path in files:
            try:
                if now - file_path.stat().st_mtime > DEBUG_ARTIFACT_TTL_SECONDS:
                    expired.append(file_path)
            except Exception:
                continue

        overflow = files[DEBUG_ARTIFACT_MAX_FILES:]
        to_delete = {str(path): path for path in [*expired, *overflow]}
        for file_path in to_delete.values():
            try:
                file_path.unlink(missing_ok=True)
            except Exception:
                continue

    @staticmethod
    def _parse_bool_text(value: str, default: bool) -> bool:
        text = (value or "").strip().lower()
        if not text:
            return default
        if text in ("1", "true", "yes", "y", "on"):
            return True
        if text in ("0", "false", "no", "n", "off"):
            return False
        return default

    @staticmethod
    def _parse_browser_mode_text(value: str, default: str) -> str:
        text = (value or "").strip().lower()
        if text in ("headless", "headful"):
            return text
        return default

    def _resolve_headless(self, explicit: Optional[bool]) -> bool:
        if explicit is not None:
            return bool(explicit)
        configured_mode = self._parse_browser_mode_text(
            str(getattr(config.basic, "exa_browser_mode", "headless") or "headless"),
            "headless",
        )
        env_value = os.environ.get("EXA_BROWSER_HEADLESS", "")
        return self._parse_bool_text(env_value, configured_mode == "headless")
