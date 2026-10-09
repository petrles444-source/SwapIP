# -*- coding: utf-8 -*-
"""
Проверяем SOCKS5-прокси из списков: они туннелируют HTTPS нативно,
поэтому в отличие от HTTP-прокси не ломают защищённые сайты.

Заодно убеждаемся, что analyzer/scraper.py корректно разбирает строки
вида socks5://ip:port из реальных источников.

Запуск: python tools/test-socks-live.py [сколько]
"""
import asyncio
import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

import aiohttp

from checker import check_proxy
from scraper import normalize_proxy, parse_txt

LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else 200

URL = ("https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main"
       "/proxies/protocols/socks5/data.txt")


async def main():
    async with aiohttp.ClientSession() as s:
        async with s.get(URL, timeout=aiohttp.ClientTimeout(total=30)) as r:
            raw = await r.text()

    lines = [ln for ln in raw.splitlines() if ln.strip()]
    print(f"Источник отдал {len(lines)} строк")

    # Нормализация analyzer'ом
    parsed = set()
    for ln in lines:
        n = normalize_proxy(ln)
        if n:
            parsed.add(n)
    print(f"scraper.py распознал: {len(parsed)} ({len(parsed)*100//max(1,len(lines))}%)")

    socks5 = [p for p in parsed if p.startswith('socks5://')]
    print(f"из них socks5: {len(socks5)}")
    if not socks5:
        print("SOCKS5 не найдены — нечего проверять.")
        return

    step = max(1, len(socks5) // LIMIT)
    sample = socks5[::step][:LIMIT]
    print(f"\nПроверяем {len(sample)} SOCKS5 по HTTPS...\n")

    t0 = time.time()
    async with aiohttp.ClientSession() as s:
        results = await asyncio.gather(*[check_proxy(s, p, timeout=12) for p in sample])
    alive = [(p, r) for p, r in zip(sample, results) if r]

    print(f"Выдержали: {len(alive)} из {len(sample)} за {time.time()-t0:.1f}с\n")
    for p, r in alive[:15]:
        print(f"  {p:<34} {r['latency']*1000:>7.0f} мс  exit={r['external_ip']}")

    if alive:
        print("\n✓ SOCKS5 остаются рабочим путём: они не ломают HTTPS.")
    else:
        print("\nSOCKS5 сейчас тоже все мертвы — качество публичных пулов.")


asyncio.run(main())
