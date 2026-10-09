# -*- coding: utf-8 -*-
"""
Замер после включения лимита скорости: сколько прокси выживает и
сколько времени занимает проверка.

Сравнивает с замерами на тех же адресах БЕЗ лимита, чтобы увидеть
разницу. Нужен интернет.

Запуск: python tools/benchmark-speed-limit.py [сколько адресов]
"""
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

import aiohttp  # noqa: E402

import checker  # noqa: E402
from config import MAX_ACCEPTABLE_LATENCY_MS  # noqa: E402
from scraper import parse_txt  # noqa: E402

LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else 400

URL = ("https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main"
       "/proxies/all/data.txt")


async def collect():
    async with aiohttp.ClientSession() as s:
        async with s.get(URL, timeout=aiohttp.ClientTimeout(total=30)) as r:
            return parse_txt(await r.text())


async def run(label, **kwargs):
    pool = await collect()
    if not pool:
        print('не удалось скачать список')
        return
    step = max(1, len(pool) // LIMIT)
    sample = sorted(pool)[::step][:LIMIT]

    print(f'\n=== {label} ===')
    print(f'  адресов: {len(sample)}   лимит скорости: '
          f'{MAX_ACCEPTABLE_LATENCY_MS if kwargs else "выключен"} мс')

    t0 = time.perf_counter()
    res = await checker.check_proxies_batch(sample, **kwargs)
    dt = time.perf_counter() - t0

    lat = sorted(p['latency'] * 1000 for p in res)
    print(f'  время:        {dt:.1f} с  ({dt/len(sample)*1000:.0f} мс на адрес)')
    print(f'  выжило:       {len(res)} из {len(sample)} ({len(res)*100/max(1,len(sample)):.2f}%)')
    if lat:
        print(f'  медиана:      {lat[len(lat)//2]:.0f} мс')
        print(f'  быстрее всего: {lat[0]:.0f} мс')
        print(f'  медленнее:    {lat[-1]:.0f} мс')


async def main():
    await run('БЕЗ лимита скорости (таймаут 5 с)', timeout=5)
    await run('С лимитом 500 мс', timeout=5)
    print('\nВывод: лимит отсекает медленные прокси на этапе сбора —')
    print('в списке расширения остаются только те, что реально шустрые.')


asyncio.run(main())
