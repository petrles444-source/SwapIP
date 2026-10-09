# -*- coding: utf-8 -*-
"""Оценка: сколько рабочих прокси дадут новые источники (без проверки)."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

import aiohttp  # noqa: E402

from scraper import parse_txt  # noqa: E402
from storage import load_raw_proxies  # noqa: E402

NEW = [
    ('ErcinDedeoglu', 'https://cdn.jsdelivr.net/gh/ErcinDedeoglu/proxies@main/proxies/http.txt'),
    ('MuRongPIG', 'https://cdn.jsdelivr.net/gh/MuRongPIG/Proxy-Master@main/http.txt'),
    ('clarketm', 'https://cdn.jsdelivr.net/gh/clarketm/proxy-list@master/proxy-list-raw.txt'),
]

YIELD_RATE = 0.004  # наблюдаемый выход: ~0.4% прошедших HTTPS-проверку


async def main():
    have = load_raw_proxies()
    print(f'текущий пул (из прошлого прогона): {len(have)}')

    fresh = set()
    async with aiohttp.ClientSession() as s:
        for name, url in NEW:
            try:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=40)) as r:
                    parsed = parse_txt(await r.text())
                new_only = parsed - have
                print(f'  {name:<16} распознано {len(parsed):>7}   новых: {len(new_only):>7}')
                fresh |= parsed
            except Exception as exc:  # noqa: BLE001
                print(f'  {name:<16} ошибка: {exc}')

    combined = have | fresh
    print()
    print(f'адресов сейчас : {len(have)}')
    print(f'адресов станет : {len(combined)}  (прирост +{len(combined) - len(have)})')
    print()
    print(f'при выходе ~0.4%: сейчас ~{len(have) * YIELD_RATE:.0f}, '
          f'станет ~{len(combined) * YIELD_RATE:.0f} рабочих')


asyncio.run(main())
