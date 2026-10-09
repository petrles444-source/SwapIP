# -*- coding: utf-8 -*-
"""
Живая проверка: берём публичные прокси и прогоняем через analyzer/checker.py.

Показывает, что именно отсеивает HTTPS-проверка с верификацией сертификата
(именно эти прокси роняли сеть и давали ошибки сертификата в Chrome).

Запуск: python tools/test-checker-live.py [сколько прокси]
"""

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

import aiohttp  # noqa: E402

from checker import check_proxies_batch  # noqa: E402
from config import PROXY_SOURCES  # noqa: E402
from scraper import parse_txt  # noqa: E402

LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else 150


async def collect() -> set:
    got = set()
    async with aiohttp.ClientSession() as s:
        for src in PROXY_SOURCES[:5]:
            try:
                async with s.get(src['url'], timeout=aiohttp.ClientTimeout(total=20)) as r:
                    got |= parse_txt(await r.text())
            except Exception as exc:  # noqa: BLE001
                print(f"  источник недоступен: {src['name']}: {exc}")
    return got


async def main():
    print(f"Собираем прокси из {len(PROXY_SOURCES[:5])} источников...")
    all_proxies = await collect()
    if not all_proxies:
        print("Не удалось получить списки. Проверьте интернет.")
        return
    sample = sorted(all_proxies)[:LIMIT]
    print(f"Всего спарсено {len(all_proxies)}, проверяем {len(sample)} по HTTPS...\n")

    # Берём разброс по всему списку, а не первые N по алфавиту: первые
    # ip:port в отсортированном списке идут подряд и часто принадлежат
    # одному и тому же мёртвому подсету оператора.
    if len(all_proxies) > LIMIT:
        step = len(all_proxies) // LIMIT
        sample = sorted(all_proxies)[::step][:LIMIT]
        print(f"(разброс по списку: шаг {step}, {len(sample)} прокси)\n")

    t0 = time.time()
    alive = await check_proxies_batch(sample, timeout=10)
    elapsed = time.time() - t0

    print(f"\nВыдержали HTTPS-проверку: {len(alive)} из {len(sample)} "
          f"({len(alive) * 100 // max(1, len(sample))}%) за {elapsed:.1f}с\n")
    for p in alive[:10]:
        print(f"  {p['proxy']:<40} {p['latency']*1000:>7.0f} мс  exit={p['external_ip']}")

    print("\nОтсеяно (не поддерживают CONNECT / подменяют сертификат / мёртвые):")
    alive_urls = {p['proxy'] for p in alive}
    for url in sample[:5]:
        if url not in alive_urls:
            print(f"  {url}  ← не прошёл HTTPS")

    print("\nИменно такие прокси и вызывали в Chrome "
          "ERR_CONNECTION_CLOSED / NETERR_CERT_AUTHORITY_INVALID.")


if __name__ == '__main__':
    asyncio.run(main())
