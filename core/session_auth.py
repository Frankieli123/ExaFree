"""
Session认证模块
提供基于Session的登录认证功能
"""
import secrets
from functools import wraps
from typing import Optional
from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse


def generate_session_secret() -> str:
    """生成随机的session密钥"""
    return secrets.token_hex(32)


def is_logged_in(request: Request) -> bool:
    """检查用户是否已登录"""
    return request.session.get("authenticated", False)


def get_session_user(request: Request) -> dict:
    """获取当前会话用户信息"""
    return {
        "user_id": request.session.get("user_id") or "",
        "username": request.session.get("username") or "",
        "role": request.session.get("role") or "",
    }


def login_user(request: Request, *, user_id: str = "", username: str = "", role: str = "admin"):
    """标记用户为已登录状态"""
    request.session["authenticated"] = True
    request.session["user_id"] = user_id or ""
    request.session["username"] = username or ""
    request.session["role"] = role or "user"


def logout_user(request: Request):
    """清除用户登录状态"""
    request.session.clear()


def require_login(redirect_to_login: bool = True, admin_only: bool = True):
    """
    要求用户登录的装饰器

    Args:
        redirect_to_login: 未登录时是否重定向到登录页面（默认True）
                          False时返回404错误
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, request: Request, **kwargs):
            if not is_logged_in(request):
                if redirect_to_login:
                    accept_header = (request.headers.get("accept") or "").lower()
                    wants_html = "text/html" in accept_header or request.url.path.endswith("/html")

                    if wants_html:
                        # 清理掉 URL 中可能重复的 PATH_PREFIX
                        # 避免重定向路径出现多层前缀
                        path = request.url.path

                        # 兼容 main 中 PATH_PREFIX 为空的情况
                        import main
                        prefix = getattr(main, "PATH_PREFIX", "")

                        if prefix:
                            login_url = f"/{prefix}/login"
                        else:
                            login_url = "/login"

                        return RedirectResponse(url=login_url, status_code=302)

                raise HTTPException(401, "Unauthorized")

            if admin_only:
                role = request.session.get("role") or ""
                if role != "admin":
                    raise HTTPException(403, "Forbidden")

            return await func(*args, request=request, **kwargs)
        return wrapper
    return decorator
