# -*- coding: utf-8 -*-
"""Замер скорости проверки на реальных адресах из базы."""
import asyncio
import io
import json
import os
import sys
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, os.path.join(ROOT, 'analyzer'))

import checker  # noqa: E402
from config import CHECK_TIMEOUT, VALID_PROXIES_FILE  # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 300


def load():
    if not os.path.exists(VALID_PROXIES_FILE):
        return []
    with io.open(VALID_PROXIES_FILE, encoding='utf-8') as f:
        return [p['proxy'] for p in json.load(f)]


async def run(sample, label):
    t0 = time.perf_counter()
    res = await checker.check_proxies_batch(sample, timeout=CHECK_TIMEOUT)
    dt = time.perf_counter() - t0
    st = checker.check_proxies_batch.last_stats
    print(f'{label}: {dt:.1f} с, принято {len(res)} из {len(sample)}')
    return dt, len(res)


async def main():
    all_p = load()
    if not all_p:
        print('база пуста — сначала прогони анализатор')
        return
    step = max(1, len(all_p) // N)
    sample = all_p[::step][:N]
    print(f'адресов: {len(sample)} (таймаут {CHECK_TIMEOUT} с)\n')

    dt, ok = await run(sample, 'проверка')
    print()
    print(f'  на адрес: {dt/len(sample)*1000:.0f} мс')
    if dt > 0:
        print(f'  при пуле 139 193 это ~= {dt/len(sample)*139193/60:.0f} мин')
    st = checker.check_proxies_batch.last_stats
    print()
    print('  разбор отказов:')
    for k, v in st.items():
        if k not in ('checked', 'accepted'):
            print(f'    {k:<12} {v}')

    # Сколько стоил бы прогон при разной конкурентности
    print()
    print('  оценка полного прогона (139 193 адреса):')
    for conc in (200, 500, 1000):
        print(f'    {conc:>4} одновременно -> ~{dt/len(sample)*139193/(conc/500)/60:.0f} мин')


asyncio.run(main())
