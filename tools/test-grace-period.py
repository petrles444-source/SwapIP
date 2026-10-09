# -*- coding: utf-8 -*-
"""
Проверяет, что старые рабочие прокси НЕ пропадают при новом прогоне.

Ситуация, которая и вызывала жалобу: прогон находит 58 новых прокси,
а прежние 164 (которые недавно работали) выпадают из экспорта, потому что
новый список источников их не содержал. Итог — список сжимается вместо
того, чтобы расти.

Запуск: python tools/test-grace-period.py
"""
import io
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

from config import GRACE_PERIOD_DAYS  # noqa: E402
from storage import merge_proxy_records  # noqa: E402

passed = failed = 0


def check(name, cond, detail=''):
    global passed, failed
    if cond:
        passed += 1
        print(f'PASS  {name}')
    else:
        failed += 1
        print(f'FAIL  {name}' + (f' — {detail}' if detail else ''))


def rec(url, days_ago=0, **kw):
    d = {'proxy': url, 'latency': 0.5, 'external_ip': '1.2.3.4',
         'https': True, 'alive': True,
         'last_seen': time.time() - days_ago * 86400}
    d.update(kw)
    return d


def main():
    # Имена без 'rec', чтобы не затенять счётчики passed/failed.
    fresh = [rec('http://new1:80'), rec('http://new2:80')]

    # --- 1. Недавно работавшие прокси остаются живыми ---
    old = [
        rec('http://old-fresh:80', days_ago=0),      # работал час назад
        rec('http://old-yesterday:80', days_ago=1),  # вчера
        rec('http://old-week:80', days_ago=6),       # неделю назад
    ]
    merged = merge_proxy_records(old, fresh)
    alive = [p['proxy'] for p in merged if p.get('alive', True)]
    dead = [p['proxy'] for p in merged if not p.get('alive', True)]

    check('новые прокси добавлены',
          'http://new1:80' in alive and 'http://new2:80' in alive)
    check('недавно работавший прокси остался живым',
          'http://old-fresh:80' in alive, str(alive))
    check('работавший вчера — тоже жив', 'http://old-yesterday:80' in alive)
    check('работавший неделю назад — жив (в пределах grace)',
          'http://old-week:80' in alive)
    check('старых прокси в архиве нет', not dead, str(dead))
    check('всего записей 5', len(merged) == 5, str(len(merged)))

    # --- 2. Реальная жалоба: прогон нашёл 58, старых 164 не должно пропасть ---
    old_many = [rec(f'http://old{i}:80', days_ago=0.2) for i in range(164)]
    new_few = [rec(f'http://new{i}:80') for i in range(58)]
    merged = merge_proxy_records(old_many, new_few)
    alive = [p for p in merged if p.get('alive', True)]
    check('164 старых + 58 новых = 222 живых',
          len(alive) == 222, str(len(alive)))
    check('ни один старый не потерян',
          all(p.get('alive') for p in merged if p['proxy'].startswith('http://old')))

    # --- 3. Давно не работавшие — в архив, но не удаляются ---
    ancient = [rec(f'http://ancient{i}:80', days_ago=GRACE_PERIOD_DAYS + 5)
               for i in range(10)]
    merged = merge_proxy_records(ancient, fresh)
    alive_urls = {p['proxy'] for p in merged if p.get('alive', True)}
    check('давно не работавшие не в выдаче',
          not any(u.startswith('http://ancient') for u in alive_urls))
    check('но остались в базе ( могут вернуться)',
          len(merged) == 12, str(len(merged)))

    # --- 4. Реально проверенные и не ответившие — честный alive ---
    old_ok = [rec('http://confirmed:80', days_ago=0.1)]
    # Прокси, который ПРОВЕРЯЛИ и он не ответил: verified_at свежее, чем
    # last_seen (последний успех был раньше последней неудачной проверки).
    dead_rec = rec('http://failed:80', days_ago=0.1)
    dead_rec['alive'] = False
    dead_rec['verified_at'] = time.time() + 1  # только что проверили, упал
    old_failed = [dead_rec]
    merged = merge_proxy_records(old_ok + old_failed, fresh)
    urls = {p['proxy']: p.get('alive', True) for p in merged}
    check('подтверждённый прокси жив', urls['http://confirmed:80'] is True)
    check('только что упавший при проверке — в архиве',
          urls['http://failed:80'] is False, str(urls.get('http://failed:80')))

    # --- 5. Никаких дублей при многократных прогонах ---
    base = [rec('http://keepme:80', days_ago=0.1)]
    cur = base
    for _ in range(5):
        cur = merge_proxy_records(cur, fresh)
    urls = [p['proxy'] for p in cur]
    check('после 5 прогонов дублей нет', len(urls) == len(set(urls)),
          f'{len(urls)} записей')
    check('постоянный прокси всё ещё жив',
          any(p['proxy'] == 'http://keepme:80' and p.get('alive') for p in cur))

    print(f'\nИтого: {passed} PASS / {failed} FAIL')
    return 1 if failed else 0


sys.exit(main())
