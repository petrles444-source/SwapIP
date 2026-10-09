# -*- coding: utf-8 -*-
"""Определение уровня анонимности прокси по заголовкам (httpbin.org/headers)."""

from typing import Optional

import aiohttp

HEADERS_TEST_URL = "https://httpbin.org/headers"
# Запасной сервис: httpbin бывает недоступен, а наша цель — не потерять
# уже проверенные прокси из-за второстепенной проверки.
HEADERS_TEST_FALLBACK = "https://api.ipify.org/?format=json"


async def check_anonymity(session: aiohttp.ClientSession, proxy: str, timeout: int = 10) -> Optional[dict]:
    """elite — ничего не раскрывает; anonymous — выдаёт Via; transparent — выдаёт реальный IP."""
    try:
        async with session.get(
            HEADERS_TEST_URL, proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout)
        ) as resp:
            if resp.status != 200:
                return None
            data = await resp.json(content_type=None)
            h = {k.lower(): v for k, v in (data.get("headers") or {}).items()}

            via = h.get("via", "")
            forwarded_for = h.get("x-forwarded-for", "")
            real_ip = h.get("x-real-ip", "")
            proxy_connection = h.get("proxy-connection", "")
            forwarded = h.get("forwarded", "")

            leaked = []
            for name, val in (("X-Forwarded-For", forwarded_for), ("X-Real-IP", real_ip), ("Forwarded", forwarded)):
                if val:
                    leaked.append(f"{name}: {val}")
            for name, val in (("Via", via), ("Proxy-Connection", proxy_connection)):
                if val:
                    leaked.append(f"{name}: {val}")

            if forwarded_for or real_ip or forwarded:
                level = "transparent"
            elif via or proxy_connection:
                level = "anonymous"
            else:
                level = "elite"

            return {"level": level, "leaked_headers": leaked, "via": via, "forwarded_for": forwarded_for}
    except Exception:
        return None


def get_anonymity_emoji(level: str) -> str:
    return {"elite": "🟢", "anonymous": "🟡", "transparent": "🔴"}.get(level, "⚪")


def get_anonymity_label(level: str) -> str:
    return {"elite": "Элитный", "anonymous": "Анонимный", "transparent": "Прозрачный"}.get(level, "Неизвестно")
