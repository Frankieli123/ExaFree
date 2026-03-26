import asyncio
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from core.account import load_accounts_from_source
from core.base_task_service import BaseTask, BaseTaskService, TaskCancelledError, TaskStatus
from core.config import config
from core.exa_automation import ExaAutomation
from core.mail_providers import create_temp_mail_client
from core.proxy_utils import parse_proxy_setting, sanitize_proxy_url

logger = logging.getLogger("exa.login")

CONFIG_CHECK_INTERVAL_SECONDS = 60
EMAIL_LOGIN_RETRY_LIMIT = 3
EMAIL_LOGIN_RETRY_SLEEP_SECONDS = 5


@dataclass
class LoginTask(BaseTask):
    """刷新任务数据类"""
    account_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        base_dict = super().to_dict()
        base_dict["account_ids"] = self.account_ids
        return base_dict


class LoginService(BaseTaskService[LoginTask]):
    """Exa 账号刷新服务（重建 API Key）。"""

    def __init__(
        self,
        multi_account_mgr,
        http_client,
        user_agent: str,
        retry_policy,
        session_cache_ttl_seconds: int,
        global_stats_provider: Callable[[], dict],
        set_multi_account_mgr: Optional[Callable[[Any], None]] = None,
    ) -> None:
        super().__init__(
            multi_account_mgr,
            http_client,
            user_agent,
            retry_policy,
            session_cache_ttl_seconds,
            global_stats_provider,
            set_multi_account_mgr,
            log_prefix="REFRESH",
        )
        self._is_polling = False
        self._refresh_timestamps: Dict[str, float] = {}
        self._triggered_today: set = set()

    def _get_running_task(self) -> Optional[LoginTask]:
        for task in self._tasks.values():
            if isinstance(task, LoginTask) and task.status in (TaskStatus.PENDING, TaskStatus.RUNNING):
                return task
        return None

    async def start_login(self, account_ids: List[str]) -> LoginTask:
        async with self._lock:
            if not account_ids:
                raise ValueError("账户列表不能为空")

            running_task = self._get_running_task()
            if running_task:
                new_accounts = [aid for aid in account_ids if aid not in running_task.account_ids]
                if new_accounts:
                    running_task.account_ids.extend(new_accounts)
                    self._append_log(
                        running_task,
                        "info",
                        f"📝 添加 {len(new_accounts)} 个账户到现有任务 (总计: {len(running_task.account_ids)})",
                    )
                else:
                    self._append_log(running_task, "info", "📝 所有账户已在当前任务中")
                return running_task

            task = LoginTask(id=str(uuid.uuid4()), account_ids=list(account_ids))
            self._tasks[task.id] = task
            self._append_log(task, "info", f"📝 创建 Exa 刷新任务 (账号数量: {len(task.account_ids)})")
            self._current_task_id = task.id
            asyncio.create_task(self._run_task_directly(task))
            return task

    async def _run_task_directly(self, task: LoginTask) -> None:
        try:
            await self._run_one_task(task)
        finally:
            async with self._lock:
                if self._current_task_id == task.id:
                    self._current_task_id = None

    def _execute_task(self, task: LoginTask):
        return self._run_login_async(task)

    async def _run_login_async(self, task: LoginTask) -> None:
        loop = asyncio.get_running_loop()
        self._append_log(task, "info", f"🚀 Exa 刷新任务已启动 (共 {len(task.account_ids)} 个账号)")

        for idx, account_id in enumerate(task.account_ids, 1):
            if task.cancel_requested:
                self._append_log(task, "warning", f"login task cancelled: {task.cancel_reason or 'cancelled'}")
                task.status = TaskStatus.CANCELLED
                task.finished_at = time.time()
                return

            try:
                self._append_log(task, "info", f"📊 进度: {idx}/{len(task.account_ids)}")
                result = await loop.run_in_executor(self._executor, self._refresh_one, account_id, task)
            except TaskCancelledError:
                task.status = TaskStatus.CANCELLED
                task.finished_at = time.time()
                return
            except Exception as exc:
                result = {"success": False, "email": account_id, "error": str(exc)}

            task.progress += 1
            task.results.append(result)

            if result.get("success"):
                task.success_count += 1
                self._refresh_timestamps[account_id] = time.time()
                self._append_log(task, "info", f"✅ 刷新成功: {account_id}")
            else:
                task.fail_count += 1
                self._append_log(task, "error", f"❌ 刷新失败: {account_id} - {result.get('error', '未知错误')}")

            if idx < len(task.account_ids) and not task.cancel_requested:
                self._append_log(task, "info", "⏳ 等待 8 秒后处理下一个账号...")
                await asyncio.sleep(8)

        task.status = TaskStatus.CANCELLED if task.cancel_requested else (TaskStatus.SUCCESS if task.fail_count == 0 else TaskStatus.FAILED)
        task.finished_at = time.time()
        self._append_log(task, "info", f"🏁 刷新任务完成 (成功: {task.success_count}, 失败: {task.fail_count}, 总计: {len(task.account_ids)})")
        self._current_task_id = None

    def _refresh_one(self, account_id: str, task: LoginTask) -> dict:
        accounts = load_accounts_from_source()
        account_data = next((acc for acc in accounts if acc.get("id") == account_id), None)
        if not account_data:
            return {"success": False, "email": account_id, "error": "账号不存在"}
        if account_data.get("disabled"):
            return {"success": False, "email": account_id, "error": "账号已禁用"}

        provider = (account_data.get("mail_provider") or config.basic.temp_mail_provider or "duckmail").lower()
        mail_address = account_data.get("mail_address") or account_id
        mail_password = account_data.get("mail_password") or account_data.get("email_password") or ""

        def log_cb(level: str, message: str) -> None:
            self._append_log(task, level, f"[{account_id}] {message}")

        log_cb("info", f"📧 邮件提供商: {provider}")

        # 构建账户级邮件配置（优先账户字段）
        account_cfg = {}
        if account_data.get("mail_base_url"):
            account_cfg["base_url"] = account_data.get("mail_base_url")
        if account_data.get("mail_api_key"):
            account_cfg["api_key"] = account_data.get("mail_api_key")
        if account_data.get("mail_jwt_token"):
            account_cfg["jwt_token"] = account_data.get("mail_jwt_token")
        if account_data.get("mail_verify_ssl") is not None:
            account_cfg["verify_ssl"] = account_data.get("mail_verify_ssl")
        if account_data.get("mail_domain"):
            account_cfg["domain"] = account_data.get("mail_domain")

        client = create_temp_mail_client(provider, log_cb=log_cb, **account_cfg)
        if provider in ("freemail", "gptmail"):
            client.set_credentials(mail_address, "")
        else:
            if not mail_password and provider not in ("cfmail",):
                return {"success": False, "email": account_id, "error": "邮箱凭据缺失，无法刷新"}
            client.set_credentials(mail_address, mail_password)
            if provider == "moemail":
                client.email_id = mail_password

        proxy_for_auth, _ = parse_proxy_setting(config.basic.proxy_for_auth)
        automation = ExaAutomation(
            proxy=proxy_for_auth,
            log_callback=log_cb,
        )
        if proxy_for_auth and automation.proxy != proxy_for_auth:
            log_cb(
                "info",
                f"🔁 浏览器代理兼容转换: {sanitize_proxy_url(proxy_for_auth)} -> {sanitize_proxy_url(automation.proxy)}",
            )
        else:
            log_cb("info", f"🔌 账户操作代理: {sanitize_proxy_url(proxy_for_auth) or 'disabled'}")
        log_cb("info", f"🌐 刷新流程浏览器模式: {automation.browser_mode}")
        self._add_cancel_hook(task.id, lambda: None)
        log_cb("info", "🔐 执行 Exa 登录并重建 API key...")
        result = None
        for attempt in range(1, EMAIL_LOGIN_RETRY_LIMIT + 1):
            if attempt > 1:
                log_cb("warning", f"⚠️ Exa 邮箱登录暂不可用，开始第 {attempt}/{EMAIL_LOGIN_RETRY_LIMIT} 次重试...")
            result = automation.refresh_api_key(mail_address, client)
            if result.get("success"):
                break
            if result.get("error_code") != "exa_email_login_unavailable" or attempt >= EMAIL_LOGIN_RETRY_LIMIT:
                break
            log_cb("warning", f"⏳ 等待 {EMAIL_LOGIN_RETRY_SLEEP_SECONDS} 秒后重试 Exa 邮箱登录...")
            time.sleep(EMAIL_LOGIN_RETRY_SLEEP_SECONDS)

        if not result or not result.get("success"):
            return {
                "success": False,
                "email": account_id,
                "error": (result or {}).get("error", "刷新流程失败"),
                "error_code": (result or {}).get("error_code"),
            }

        cfg = result["config"]
        account_data.update(cfg)
        account_data["mail_provider"] = provider
        account_data["mail_address"] = mail_address
        account_data["mail_password"] = mail_password
        if "coupon_code" not in account_data:
            account_data["coupon_code"] = ""
        account_data["disabled"] = False
        account_data["quota_cooldowns"] = {}
        account_data["disabled_reason"] = None

        self._apply_accounts_update(accounts)
        return {"success": True, "email": account_id, "config": account_data}

    def _get_expiring_accounts(self) -> List[str]:
        """
        Exa 模式下沿用“即将过期”逻辑：
        - 优先依据 expires_at
        - 未设置 expires_at 但存在 key 的账号，不参与自动刷新
        """
        accounts = load_accounts_from_source()
        expiring: List[str] = []
        beijing_tz = timezone(timedelta(hours=8))
        now = datetime.now(beijing_tz)

        for account_data in accounts:
            account_id = account_data.get("id")
            if not account_id:
                continue
            if account_data.get("disabled"):
                continue
            if not account_data.get("exa_api_key"):
                continue

            expires_at = account_data.get("expires_at")
            if not expires_at:
                continue
            try:
                expire_time = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=beijing_tz)
                remaining = (expire_time - now).total_seconds() / 3600
            except Exception:
                continue

            if remaining > config.basic.refresh_window_hours:
                continue

            cooldown_seconds = config.retry.refresh_cooldown_hours * 3600
            if account_id in self._refresh_timestamps:
                elapsed = time.time() - self._refresh_timestamps[account_id]
                if elapsed < cooldown_seconds:
                    continue
            expiring.append(account_id)

        return expiring

    async def check_and_refresh(self) -> Optional[LoginTask]:
        if os.environ.get("ACCOUNTS_CONFIG"):
            logger.info("[LOGIN] ACCOUNTS_CONFIG set, skipping refresh")
            return None
        expiring = self._get_expiring_accounts()
        if not expiring:
            return None
        try:
            return await self.start_login(expiring)
        except Exception as exc:
            logger.warning("[LOGIN] refresh enqueue failed: %s", exc)
            return None

    @staticmethod
    def _parse_cron(cron_str: str) -> dict:
        cron_str = cron_str.strip()
        if cron_str.startswith("*/"):
            try:
                minutes = int(cron_str[2:])
                return {"mode": "interval", "minutes": max(minutes, 5)}
            except ValueError:
                return {"mode": "interval", "minutes": 120}

        times = [t.strip() for t in cron_str.split(",") if t.strip()]
        valid = []
        for item in times:
            parts = item.split(":")
            if len(parts) != 2:
                continue
            try:
                h = int(parts[0])
                m = int(parts[1])
                if 0 <= h <= 23 and 0 <= m <= 59:
                    valid.append(f"{h:02d}:{m:02d}")
            except ValueError:
                continue
        return {"mode": "daily", "times": valid or ["08:00", "20:00"]}

    async def _wait_for_next_trigger(self) -> None:
        cron_str = config.retry.scheduled_refresh_cron
        if (not cron_str or cron_str == "08:00,20:00") and config.retry.scheduled_refresh_interval_minutes > 0:
            cron_str = f"*/{config.retry.scheduled_refresh_interval_minutes}"
        cron = self._parse_cron(cron_str)

        if cron["mode"] == "interval":
            await asyncio.sleep(cron["minutes"] * 60)
            return

        beijing_tz = timezone(timedelta(hours=8))
        while self._is_polling:
            now = datetime.now(beijing_tz)
            current_time = now.strftime("%H:%M")
            today = now.strftime("%Y-%m-%d")
            self._triggered_today = {k for k in self._triggered_today if k.startswith(today)}

            for t in cron["times"]:
                key = f"{today}_{t}"
                if current_time == t and key not in self._triggered_today:
                    self._triggered_today.add(key)
                    return
            await asyncio.sleep(30)

    async def _wait_task_complete(self, task: LoginTask) -> None:
        while task.status in (TaskStatus.PENDING, TaskStatus.RUNNING):
            await asyncio.sleep(5)

    async def start_polling(self) -> None:
        if self._is_polling:
            return
        self._is_polling = True
        logger.info("[LOGIN] Exa 刷新调度器已启动")

        try:
            while self._is_polling:
                if not config.retry.scheduled_refresh_enabled:
                    await asyncio.sleep(CONFIG_CHECK_INTERVAL_SECONDS)
                    continue

                await self._wait_for_next_trigger()
                if not self._is_polling:
                    break

                expiring = self._get_expiring_accounts()
                if not expiring:
                    continue

                batch_size = config.retry.refresh_batch_size
                for idx in range(0, len(expiring), batch_size):
                    if not self._is_polling:
                        break
                    batch = expiring[idx: idx + batch_size]
                    task = await self.start_login(batch)
                    await self._wait_task_complete(task)
                    if idx + batch_size < len(expiring):
                        await asyncio.sleep(config.retry.refresh_batch_interval_minutes * 60)
        except asyncio.CancelledError:
            logger.info("[LOGIN] polling stopped")
        except Exception as exc:
            logger.error("[LOGIN] polling error: %s", exc)
        finally:
            self._is_polling = False

    def stop_polling(self) -> None:
        self._is_polling = False
        logger.info("[LOGIN] stopping polling")
