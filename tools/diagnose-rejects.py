# -*- coding: utf-8 -*-
"""
Почему прокси из базы отклоняются: ловим точную причину.

Прогоняет реальные адреса из analyzer/data/valid_proxies.json и для каждого
показывает, на чём именно он отвалился: таймаут, отказ соединения, отсев
по скорости или нестабильность выходного IP.

Нужно, чтобы отличить «пулы действительно мёртвые» от «я что-то сломал».

Запуск: python tools/diagnose-rejects.py [сколько]
"""
import asyncio
import io
import json
import os
import sys
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, os.path.join(ROOT, 'analyzer'))

import aiohttp  # noqa: E402

import checker  # noqa: E402
from config import TEST_URL, TEST_URL_FALLBACKS  # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 40
BASE = os.path.join(ROOT, 'analyzer', 'data', 'valid_proxies.json')


async def one(session, proxy):
    """Разбирает причину отказа по шагам, без отсева по скорости."""
    urls = [TEST_URL] + [u for u in TEST_URL_FALLBACKS if u != TEST_URL]
    for url in urls:
        t0 = time.perf_counter()
        try:
            async with session.get(url, proxy=proxy,
                                   timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status != 200:
                    return ('http_status', r.status, (time.perf_counter() - t0) * 1000)
                data = await r.json(content_type=None)
                ip = (data.get('ip') or data.get('query') or '').strip()
                if not ip:
                    return ('no_ip', 0, (time.perf_counter() - t0) * 1000)
                ms = (time.perf_counter() - t0) * 1000
                return ('ok', ip, ms)
        except Exception as exc:
            return (type(exc).__name__, str(exc)[:60], (time.perf_counter() - t0) * 1000)
    return ('all_endpoints_failed', '', 0)


async def main():
    if not os.path.exists(BASE):
        print('нет базы')
        return
    with io.open(BASE, encoding='utf-8') as f:
        data = json.load(f)
    # Берём любые записи: даже помеченные alive=false могли работать недавно.
    # Нам важно понять — отвечают они сейчас или нет.
    known = [p['proxy'] for p in data]
    if not known:
        print('база пуста')
        return
    step = max(1, len(known) // N)
    sample = known[::step][:N]
    print(f'проверяем {len(sample)} адресов из базы (всего записей {len(known)})')
    print(f'таймаут 15 с, отсева по скорости НЕТ\n')

    async with aiohttp.ClientSession() as s:
        results = await asyncio.gather(*[one(s, p) for p in sample])

    reasons = {}
    ok_ms = []
    for p, (reason, detail, ms) in zip(sample, results):
        reasons[reason] = reasons.get(reason, 0) + 1
        if reason == 'ok':
            ok_ms.append(ms)

    print('причины:')
    for r, c in sorted(reasons.items(), key=lambda x: -x[1]):
        print(f'  {r:<26} {c}')

    if ok_ms:
        ok_ms.sort()
        print()
        print(f'ответили: {len(ok_ms)} из {len(sample)}')
        print(f'  медиана:   {ok_ms[len(ok_ms)//2]:.0f} мс')
        print(f'  минимум:   {ok_ms[0]:.0f} мс')
        print(f'  максимум:  {ok_ms[-1]:.0f} мс')
        for thr in (500, 1000, 2000, 5000, 10000):
            n = sum(1 for x in ok_ms if x <= thr)
            print(f'  быстрее {thr:>6} мс: {n}')

        print()
        print('ПРОВЕРКА С ТЕКУЩИМ ЧЕКЕРОМ (с отсевом по скорости):')
        async with aiohttp.ClientSession() as s2:
            got = await asyncio.gather(*[
                checker.check_proxy(s2, p, timeout=10) for p in sample
            ])
        accepted = [g for g in got if g]
        print(f'  принято: {len(accepted)} из {len(sample)}')
        if len(accepted) < len(ok_ms):
            print('  >>> РАСХОЖДЕНИЕ: часть живых прокси отсеяна настройками чекера')
        else:
            print('  >>> расхождения нет, чекер работает корректно')
    else:
        print()
        print('Ни один прокси из базы сейчас не отвечает.')
        print('Это означает, что пулы действительно высохли, а чекер ни при чём.')


asyncio.run(main())
