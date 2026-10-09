# -*- coding: utf-8 -*-
"""
Асинхронная проверка прокси.

Ключевое отличие от «просто пингаем httpbin»: проверка идёт по HTTPS
с проверкой сертификата. Это отсеивает ровно те прокси, из-за которых
Chrome показывает NETERR_CERT_AUTHORITY_INVALID и ERR_CONNECTION_CLOSED:

  * прокси без поддержки CONNECT → HTTPS-запрос не пройдёт;
  * MITM-прокси, подсовывающие свой сертификат → SSL-верификация упадёт;
  * одноразовые «живые на 1 запрос» → отсеиваются проверкой стабильности.
"""

import asyncio
import time
from typing import Dict, List, Optional, Tuple

import aiohttp

from config import (
    CHECK_TIMEOUT,
    MAX_CONCURRENT_CHECKS,
    TEST_URL,
    TEST_URL_FALLBACKS,
    REQUIRE_HTTPS,
    STABILITY_CHECKS,
    STABILITY_DELAY,
)

try:
    from aiohttp_socks import ProxyConnector
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False


# Причины отказа. Расширение использует их как подсказки пользователю.
FAIL_DEAD = 'dead'              # не отвечает / таймаут
FAIL_NO_HTTPS = 'no_https'      # нет CONNECT → HTTPS-сайты не откроются
FAIL_MITM = 'mitm'              # подмена TLS-сертификата
FAIL_UNSTABLE = 'unstable'      # не проходит стабильность
FAIL_BAD_PAYLOAD = 'bad_payload'


def _extract_ip(data) -> str:
    """Достаёт IP из ответа разных сервисов."""
    if not isinstance(data, dict):
        return ''
    for key in ('ip', 'query', 'origin'):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().split(',')[0].strip()
    return ''


def _is_ssl_error(exc: BaseException) -> bool:
    """Отличает проблему сертификата от обычной сетевой ошибки."""
    if isinstance(exc, aiohttp.ClientSSLError):
        return True
    if isinstance(exc, aiohttp.ClientConnectorCertificateError):
        return True
    # aiohttp оборачивает ошибки в ClientConnectorError; смотрим по цепочке.
    inner = getattr(exc, 'os_error', None) or getattr(exc, '__cause__', None)
    seen = 0
    while inner is not None and seen < 5:
        if isinstance(inner, aiohttp.ClientSSLError):
            return True
        if isinstance(inner, __import__('ssl').SSLError):
            return True
        inner = getattr(inner, '__cause__', None) or getattr(inner, 'os_error', None)
        seen += 1
    # asyncio таймауты на TLS-рукопожатии тоже часто именно из-за сертификата,
    # но надёжно отличить их нельзя — считаем это «нет HTTPS».
    return False


async def _fetch_json(session: aiohttp.ClientSession, url: str, proxy: str,
                      timeout: int) -> Tuple[bool, Optional[Dict], Optional[BaseException]]:
    try:
        async with session.get(
            url, proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout)
        ) as resp:
            if resp.status != 200:
                return False, None, RuntimeError(f'HTTP {resp.status}')
            try:
                data = await resp.json(content_type=None)
            except Exception as exc:  # noqa: BLE001 — причина нам не нужна
                return False, None, exc
            return True, data, None
    except Exception as exc:  # noqa: BLE001
        return False, None, exc


async def check_proxy(
    session: aiohttp.ClientSession,
    proxy: str,
    timeout: int = CHECK_TIMEOUT,
    test_url: str = TEST_URL,
) -> Optional[Dict]:
    """
    Проверяет один прокси. None — не работает (или не годен для браузера).
    """
    protocol = proxy.split('://')[0]

    # SOCKS требует отдельного коннектора — сессию с session.get(proxy=) нельзя.
    own_session = None
    if protocol in ('socks4', 'socks5'):
        if not SOCKS_AVAILABLE:
            return None
        try:
            connector = ProxyConnector.from_url(proxy)
            own_session = aiohttp.ClientSession(connector=connector)
            session = own_session
        except Exception:
            return None

    try:
        return await _check_with_session(session, proxy, timeout, test_url, protocol)
    finally:
        if own_session is not None:
            await own_session.close()


async def _check_with_session(session: aiohttp.ClientSession, proxy: str,
                              timeout: int, test_url: str,
                              protocol: str = 'http') -> Optional[Dict]:
    urls = [test_url] + [u for u in TEST_URL_FALLBACKS if u != test_url]

    first_error: Optional[BaseException] = None
    started = time.perf_counter()

    for url in urls:
        ok, data, exc = await _fetch_json(session, url, proxy, timeout)
        if ok:
            external_ip = _extract_ip(data)
            if not external_ip:
                first_error = first_error or RuntimeError(FAIL_BAD_PAYLOAD)
                continue
            latency = time.perf_counter() - started

            # Стабильность: несколько запросов подряд через один и тот же IP.
            if STABILITY_CHECKS > 1:
                stable = True
                for _ in range(STABILITY_CHECKS - 1):
                    await asyncio.sleep(STABILITY_DELAY)
                    ok2, data2, exc2 = await _fetch_json(session, url, proxy, timeout)
                    if not ok2:
                        stable = False
                        first_error = first_error or exc2
                        break
                    if _extract_ip(data2) != external_ip:
                        # Выходной IP «прыгает» между запросами — это не прокси,
                        # а какая-то ротация или подмена на стороне сервера.
                        stable = False
                        first_error = RuntimeError(FAIL_UNSTABLE)
                        break
                if not stable:
                    return None

            return {
                "proxy": proxy,
                "latency": round(latency, 4),
                "external_ip": external_ip,
                "protocol": protocol,
                "https": True,
                "checked_at": time.time(),
            }
        if exc is not None:
            first_error = first_error or exc

    # HTTPS не прошёл. Разбираемся почему — это нужно и для отчёта,
    # и для того, чтобы отличать MITM от «просто мёртвый».
    if first_error is not None and _is_ssl_error(first_error):
        if REQUIRE_HTTPS:
            return None
        return {
            "proxy": proxy,
            "latency": round(time.perf_counter() - started, 4),
            "external_ip": '',
            "protocol": protocol,
            "https": False,
            "fail_reason": FAIL_MITM,
            "checked_at": time.time(),
        }
    return None


async def check_proxies_batch(
    proxies: List[str],
    timeout: int = CHECK_TIMEOUT,
    max_concurrent: int = MAX_CONCURRENT_CHECKS,
    progress_callback=None,
) -> List[Dict]:
    """Проверяет список прокси с ограничением конкурентности; сортирует по скорости."""
    semaphore = asyncio.Semaphore(max_concurrent)
    results: List[Dict] = []
    checked = 0
    valid = 0
    total = len(proxies)
    lock = asyncio.Lock()

    # ВАЖНО: ssl=True (по умолчанию). Раньше здесь стояло ssl=False, и именно
    # поэтому MITM-прокси с самоподписанным сертификатом проходили проверку
    # и доходили до пользователя как «рабочие».
    connector = aiohttp.TCPConnector(limit=max_concurrent)
    async with aiohttp.ClientSession(connector=connector) as session:

        async def limited_check(proxy: str):
            nonlocal checked, valid
            async with semaphore:
                result = await check_proxy(session, proxy, timeout)
                async with lock:
                    checked += 1
                    if result:
                        valid += 1
                        results.append(result)
                    if progress_callback and checked % 100 == 0:
                        progress_callback(checked, total, valid)

        await asyncio.gather(*[limited_check(p) for p in proxies], return_exceptions=True)

    results.sort(key=lambda x: x['latency'])
    return results
