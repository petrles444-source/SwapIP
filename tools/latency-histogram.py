# -*- coding: utf-8 -*-
"""
Диагностика: какое реальное распределение задержек у прокси?

Отключает лимит MAX_ACCEPTABLE_LATENCY_MS и таймаут увеличивает, чтобы
посмотреть настоящее распределение. По нему уже решаем, какой порог
оставить — 500 мс может оказаться слишком жёстким: в задержку входит
TLS-хендшейк до удалённого сервера.

Запуск: python tools/latency-histogram.py [сколько]
"""
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

import aiohttp  # noqa: E402

import checker  # noqa: E402
from config import TEST_URL_FALLBACKS  # noqa: E402
from scraper import parse_txt  # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 1500
TIMEOUT = float(os.environ.get('PROBE_TIMEOUT', '12'))

URL = ("https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main"
       "/proxies/all/data.txt")

BUCKETS = [(0, 500), (500, 1000), (1000, 2000), (2000, 3000), (3000, 5000),
           (5000, 8000), (8000, 12000), (12000, 99999)]


async def collect():
    got = set()
    async with aiohttp.ClientSession() as s:
        for u in [
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
            "https://cdn.jsdelivr.net/gh/ErcinDedeoglu/proxies@main/proxies/http.txt",
        ]:
            try:
                async with s.get(u, timeout=aiohttp.ClientTimeout(total=30)) as r:
                    got |= parse_txt(await r.text())
            except Exception:
                pass
    return got


async def probe(session, proxy):
    """Одна попытка, без фильтра по скорости. Возвращает мс или None."""
    t0 = time.perf_counter()
    try:
        async with session.get(TEST_URL_FALLBACKS[0], proxy=proxy,
                               timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as r:
            if r.status != 200:
                return None
            await r.json(content_type=None)
            return (time.perf_counter() - t0) * 1000
    except Exception:
        return None


async def main():
    pool = await collect()
    if not pool:
        print('нет списков')
        return
    step = max(1, len(pool) // N)
    sample = sorted(pool)[::step][:N]
    print(f'проверяем {len(sample)} адресов, таймаут {TIMEOUT} с, '
          f'без фильтра по скорости\n')

    sem = asyncio.Semaphore(300)
    async with aiohttp.ClientSession() as s:
        async def one(p):
            async with sem:
                return await probe(s, p)
        t0 = time.perf_counter()
        results = await asyncio.gather(*[one(p) for p in sample])
        dt = time.perf_counter() - t0

    ok = sorted(x for x in results if x is not None)
    print(f'ответили: {len(ok)} из {len(sample)} '
          f'({len(ok)*100/max(1,len(sample)):.1f}%) за {dt:.0f} с\n')

    if not ok:
        print('нет ни одного ответившего — пул мёртв, порог ни при чём')
        return

    print('распределение задержек ответивших:')
    for lo, hi in BUCKETS:
        cnt = sum(1 for x in ok if lo <= x < hi)
        bar = '█' * int(cnt * 40 / max(1, len(ok)))
        label = f'{lo//1000}–{hi//1000} с' if hi < 99999 else f'>{lo//1000} с'
        print(f'  {label:>9}: {cnt:>5}  {bar}')

    print()
    for thr in (500, 1000, 1500, 2000, 3000, 5000):
        n = sum(1 for x in ok if x <= thr)
        pct = n * 100 / len(sample)
        print(f'  порог {thr:>5} мс -> {n:>4} прокси ({pct:.2f}% от всех проверенных)')
    print()
    print('порог выбирают так, чтобы из проверенных осталось хотя бы')
    print('несколько десятков — иначе список будет пустым.')


asyncio.run(main())
