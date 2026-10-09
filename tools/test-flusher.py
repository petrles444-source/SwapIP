# -*- coding: utf-8 -*-
"""
Проверяет Flusher: результаты сохраняются на лету, и прерывание не теряет
уже найденные прокси.

Также меряет, сколько стоит промежуточная запись — важно, чтобы она не
замедляла проверку.

Запуск: python tools/test-flusher.py
"""
import asyncio
import io
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

from config import VALID_PROXIES_FILE  # noqa: E402
from main import Flusher  # noqa: E402
from storage import load_valid_proxies, merge_proxy_records, save_valid_proxies  # noqa: E402

passed = failed = 0


def check(name, cond, detail=''):
    global passed, failed
    if cond:
        passed += 1
        print(f'PASS  {name}')
    else:
        failed += 1
        print(f'FAIL  {name}' + (f' — {detail}' if detail else ''))


def fake(i):
    return {'proxy': f'http://10.0.0.{i}:8080', 'latency': 0.1 + i * 0.001,
            'external_ip': f'10.0.0.{i}', 'protocol': 'http', 'https': True}


def main():
    backup = None
    if os.path.exists(VALID_PROXIES_FILE):
        with io.open(VALID_PROXIES_FILE, encoding='utf-8') as f:
            backup = f.read()
        # Убираем файл, иначе тест не сможет отличить «создан Flusher'ом»
        # от «остался с прошлого запуска».
        os.remove(VALID_PROXIES_FILE)

    try:
        # --- 1. Файл появляется ДО конца проверки ---
        old = [{'proxy': 'http://1.1.1.1:80', 'latency': 0.5, 'alive': True}]
        flusher = Flusher(old)
        saved_early = 0
        for i in range(1, 61):
            flusher(fake(i))
            if not saved_early and os.path.exists(VALID_PROXIES_FILE):
                saved_early = i
        check('файл создан до конца проверки (на %d-й находке)' % saved_early,
              0 < saved_early < 60, str(saved_early))

        # --- 2. Прерванная проверка: сохранены все завершённые партии ---
        # Flusher пишет пачками по FLUSH_EVERY, поэтому «хвост» последней
        # неполной партии может не попасть в файл — это ожидаемо и не важно:
        # на реальном прогоне это единицы прокси из сотен.
        data = load_valid_proxies()
        urls = {p['proxy'] for p in data}
        expected = {fake(i)['proxy'] for i in range(1, 61)}
        flushed = expected & urls
        check('сохранена большая часть найденного',
              len(flushed) >= 50, f'{len(flushed)} из 60')
        check('потерян только хвост последней партии (< FLUSH_EVERY)',
              len(expected - urls) < Flusher.FLUSH_EVERY,
              f'не сохранено {len(expected - urls)}')
        check('старая запись не потеряна', 'http://1.1.1.1:80' in urls)
        check('запись, которой не было в проверке, помечена alive=False',
              any(p['proxy'] == 'http://1.1.1.1:80' and p.get('alive') is False for p in data))

        # --- 3. Сколько стоит промежуточная запись ---
        fl2 = Flusher([])
        t0 = time.perf_counter()
        for i in range(1, 201):
            fl2(fake(i))
            if i % 25 == 0:
                fl2.flush()
        dt = time.perf_counter() - t0
        per_write = dt / max(1, fl2.saves)
        check('запись на 200 находок укладывается в разумное время',
              dt < 3.0, f'{dt:.3f} с на 200 находок')
        print(f'      {fl2.saves} сохранений, ~{per_write*1000:.1f} мс на запись')

        # --- 4. Нет дублей при частых сохранениях ---
        final = load_valid_proxies()
        proxy_list = [p['proxy'] for p in final]
        check('дубликатов нет', len(proxy_list) == len(set(proxy_list)),
              f'{len(proxy_list)} записей, {len(set(proxy_list))} уникальных')

        # --- 5. Слияние не теряет старые данные ---
        merged = merge_proxy_records(
            [{'proxy': 'http://9.9.9.9:80', 'latency': 0.9, 'geo': {'country_code': 'DE'}}],
            [{'proxy': 'http://8.8.8.8:80', 'latency': 0.1}],
            keep_old=True,
        )
        urls = {p['proxy'] for p in merged}
        check('новый и старый вместе после слияния',
              'http://9.9.9.9:80' in urls and 'http://8.8.8.8:80' in urls, str(urls))
        check('гео старого сохранено',
              (next(p for p in merged if p['proxy'] == 'http://9.9.9.9:80').get('geo') or {})
              .get('country_code') == 'DE')

    finally:
        if backup is not None:
            with io.open(VALID_PROXIES_FILE, 'w', encoding='utf-8') as f:
                f.write(backup)
        elif os.path.exists(VALID_PROXIES_FILE):
            os.remove(VALID_PROXIES_FILE)

    print(f'\nИтого: {passed} PASS / {failed} FAIL')
    return 1 if failed else 0


sys.exit(main())
