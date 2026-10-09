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
    MAX_ACCEPTABLE_LATENCY_MS,
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

    Причина отказа кладётся в check_proxy.LAST_REJECT — по ней потом
    собирается статистика в check_proxies_batch, чтобы прогон показывал,
    ЧЁ именно отсеило прокси, а не просто «0 найдено».
    """
    protocol = proxy.split('://')[0]
    check_proxy.LAST_REJECT = 'dead'

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
    """Проверяет один прокси. Причину отказа пишет в check_proxy.LAST_REJECT."""
    urls = [test_url] + [u for u in TEST_URL_FALLBACKS if u != test_url]

    first_error: Optional[BaseException] = None
    started = time.perf_counter()
    deadline = started + timeout
    urls = [test_url] + [u for u in TEST_URL_FALLBACKS if u != test_url]

    first_error: Optional[BaseException] = None
    started = time.perf_counter()
    deadline = started + timeout

    for i, url in enumerate(urls):
        # Бюджет на весь прокси общий, а не на каждый эндпоинт. Иначе три
        # недоступных адреса дают 3 × 10 = 30 секунд на один прокси, и весь
        # прогон встаёт колом на медленных адресах.
        left = deadline - time.perf_counter()
        if left <= 0.5:
            break
        budget = left if i == 0 else max(1.0, left / 2)

        attempt_started = time.perf_counter()
        ok, data, exc = await _fetch_json(session, url, proxy, budget)

        if ok:
            external_ip = _extract_ip(data)
            if not external_ip:
                check_proxy.LAST_REJECT = 'no_ip'
                first_error = first_error or RuntimeError(FAIL_BAD_PAYLOAD)
                continue

            # Задержка ВАЖНО меряется от начала успешной попытки, а не от
            # начала проверки: иначе быстрый рабочий прокси, до которого
            # дошли только с третьего эндпоинта, попадёт в список как
            # «медленный на 30 секунд».
            latency = time.perf_counter() - attempt_started

            # Отсев по скорости. Опциональный: если порог не задан
            # (None или 0) — пропускаем всё, что ответило.
            # Осторожно с величиной: в задержку входит TLS-хендшейк,
            # поэтому слишком низкий порог убьёт весь список.
            if MAX_ACCEPTABLE_LATENCY_MS and latency * 1000 > MAX_ACCEPTABLE_LATENCY_MS:
                check_proxy.LAST_REJECT = 'too_slow'
                return None

            # Стабильность: несколько запросов подряд через один и тот же IP.
            #
            # Проверка стабильности идёт В ТОМ ЖЕ бюджете, что и первый
            # запрос. Раньше каждая проверка получала полный таймаут
            # сверху, и живой нестабильный прокси занимал 20+ секунд —
            # при пуле в сотни тысяч адресов это десятки минут впустую.
            if STABILITY_CHECKS > 1:
                stable = True
                for _ in range(STABILITY_CHECKS - 1):
                    left = deadline - time.perf_counter()
                    # Не хватает времени даже на паузу — не тратим её.
                    if left <= STABILITY_DELAY + 0.5:
                        break
                    await asyncio.sleep(STABILITY_DELAY)
                    ok2, data2, exc2 = await _fetch_json(
                        session, url, proxy, min(left, timeout))
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
                    check_proxy.LAST_REJECT = 'unstable'
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
    result_callback=None,
) -> List[Dict]:
    """
    Проверяет список прокси с ограничением конкурентности; сортирует по скорости.

    result_callback(record) вызывается на каждый НАЙДЕННЫЙ прокси. Он нужен,
    чтобы сохранять результаты на лету: если проверку прервут, уже найденное
    не потеряется. Сам колбэк обязан быть быстрым — он зовётся из горячего
    пути под локом, поэтому тяжёлую запись лучше делать пачками внутри него.
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    results: List[Dict] = []
    checked = 0
    valid = 0
    total = len(proxies)

    # Счётчики причин отказа. Без них непонятно, ПОЧЕМУ список пустой:
    # то ли пулы мёртвые, то ли настройки слишком жёсткие.
    stats = {'too_slow': 0, 'unstable': 0, 'no_ip': 0, 'dead': 0}
    lock = asyncio.Lock()

    # ВАЖНО: ssl=True (по умолчанию). Раньше здесь стояло ssl=False, и именно
    # поэтому MITM-прокси с самоподписанным сертификатом проходили проверку
    # и доходили до пользователя как «рабочие».
    connector = aiohttp.TCPConnector(limit=max_concurrent)

    # Мёртвый прокси закрывает соединение на своей стороне. На Windows это
    # штатно вызывает ConnectionResetError внутри служебного колбэка
    # proactor_events._call_connection_lost, и asyncio печатает для этого
    # трейсбек — хотя проверить такой прокси мы и так не смогли, то есть
    # это ожидаемый исход, а не сбой. Молча отсекаем такой шум, иначе он
    # перемешивается с прогресс-баром и выглядит как падение программы.
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(_quiet_reset_handler)

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
                    else:
                        reason = getattr(check_proxy, 'LAST_REJECT', 'dead')
                        stats[reason] = stats.get(reason, 0) + 1
                    # Сообщаем о найденном сразу — по нему пишем
                    # промежуточный файл (см. main.py: Flusher).
                    if result and result_callback:
                        result_callback(result)
                    # Обновляем прогресс каждые 100 проверок, но в конце
                    # сообщаем всегда — иначе на небольшом списке (меньше
                    # 100 адресов) пользователь вообще не увидит от progress.
                    if progress_callback and (checked % 100 == 0 or checked == total):
                        progress_callback(checked, total, valid)

        try:
            await asyncio.gather(*[limited_check(p) for p in proxies], return_exceptions=True)
        finally:
            loop.set_exception_handler(previous_handler)
            # Даём циклу обработать отложенные колбэки connection_lost,
            # пока наш обработчик ещё установлен.
            await asyncio.sleep(0.05)

    results.sort(key=lambda x: x['latency'])
    # Отчёт по причинам отказа: без него непонятно, почему список пустой.
    check_proxies_batch.last_stats = {
        **stats,
        'checked': checked,
        'accepted': valid,
    }
    return results


def _quiet_reset_handler(loop, context):
    """
    Обработчик исключений asyncio: глушит обрыв соединения с прокси.

    Всё остальное отдаём стандартному обработчику, чтобы настоящие ошибки
    не потерялись.
    """
    exc = context.get('exception')
    if isinstance(exc, ConnectionResetError):
        return
    message = str(context.get('message', ''))
    if 'connection lost' in message or 'ConnectionResetError' in message:
        return
    loop.default_exception_handler(context)
