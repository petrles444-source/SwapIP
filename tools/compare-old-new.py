# -*- coding: utf-8 -*-
"""
Сравнение «было / стало» на прокси из твоей базы.

Берём реальные адреса из analyzer/data/valid_proxies.json (там те, что
реально работали недавно) и проверяем их:
  * со старой логикой — задержка считалась от начала всех попыток,
    каждый эндпоинт получал полный таймаут (до 3 × 10 = 30 с на прокси);
  * с новой — общий бюджет на прокси и задержка от успешной попытки.

Запуск: python tools/compare-old-new.py [сколько]
"""
import asyncio
import io
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

import aiohttp  # noqa: E402

from checker import check_proxy  # noqa: E402
from config import (  # noqa: E402
    CHECK_TIMEOUT, MAX_ACCEPTABLE_LATENCY_MS, TEST_URL, TEST_URL_FALLBACKS,
)

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
BASE = os.path.join(ROOT, 'analyzer', 'data', 'valid_proxies.json')
N = int(sys.argv[1]) if len(sys.argv) > 1 else 60


async def old_logic(session, proxy, timeout=10):
    """Как было раньше: задержка от старта, каждому эндпоинту полный таймаут."""
    urls = [TEST_URL] + [u for u in TEST_URL_FALLBACKS if u != TEST_URL]
    started = time.perf_counter()
    for url in urls:
        try:
            async with session.get(url, proxy=proxy,
                                   timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    ip = data.get('ip') or data.get('query') or ''
                    if ip:
                        return (time.perf_counter() - started) * 1000
        except Exception:
            continue
    return None


async def main():
    if not os.path.exists(BASE):
        print('нет базы — сначала прогони анализатор')
        return
    with io.open(BASE, encoding='utf-8') as f:
        data = json.load(f)
    alive = [p['proxy'] for p in data if p.get('alive', True)]
    if not alive:
        print('в базе нет живых')
        return
    step = max(1, len(alive) // N)
    sample = alive[::step][:N]
    print(f'берём {len(sample)} адресов из базы (живых всего {len(alive)})\n')

    async with aiohttp.ClientSession() as s:
        print('--- СТАРАЯ логика (таймаут 10 с на эндпоинт) ---')
        t0 = time.perf_counter()
        old = await asyncio.gather(*[old_logic(s, p) for p in sample])
        old_dt = time.perf_counter() - t0
        old_ok = [x for x in old if x is not None]
        if old_ok:
            old_sorted = sorted(old_ok)
            print(f'  время:   {old_dt:.1f} с ({old_dt/len(sample)*1000:.0f} мс/адрес)')
            print(f'  ответили: {len(old_ok)} из {len(sample)}')
            print(f'  медиана:  {old_sorted[len(old_sorted)//2]:.0f} мс')
            print(f'  максимум: {old_sorted[-1]:.0f} мс')
        print()

        print(f'--- НОВАЯ логика (лимит {MAX_ACCEPTABLE_LATENCY_MS} мс, '
              f'таймаут {CHECK_TIMEOUT} с) ---')
        t0 = time.perf_counter()
        new = await asyncio.gather(*[
            check_proxy(s, p, timeout=CHECK_TIMEOUT) for p in sample
        ])
        new_dt = time.perf_counter() - t0
        new_ok = [r for r in new if r]
        print(f'  время:   {new_dt:.1f} с ({new_dt/len(sample)*1000:.0f} мс/адрес)')
        print(f'  принято: {len(new_ok)} из {len(sample)}')
        if new_ok:
            lat = sorted(r['latency'] * 1000 for r in new_ok)
            print(f'  медиана: {lat[len(lat)//2]:.0f} мс')
            print(f'  максимум:{lat[-1]:.0f} мс')

    print()
    print(f'Ускорение: {old_dt/max(new_dt,0.01):.1f}x')
    if old_ok:
        print(f'Медиана задержки упала: '
              f'{sorted(old_ok)[len(old_ok)//2]:.0f} -> '
              f'{(sorted(r["latency"]*1000 for r in new_ok)[len(new_ok)//2] if new_ok else 0):.0f} мс')


asyncio.run(main())
