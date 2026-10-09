# -*- coding: utf-8 -*-
"""Почему живые прокси попадают в архив при новом прогоне."""
import io
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

from config import VALID_PROXIES_FILE  # noqa: E402

with io.open(VALID_PROXIES_FILE, encoding='utf-8') as f:
    data = json.load(f)

alive = [p for p in data if p.get('alive', True)]
arch = [p for p in data if not p.get('alive', True)]

print(f'в базе: {len(data)} | alive: {len(alive)} | архив: {len(arch)}')
print()

print('почему в архиве:')
print('  есть last_seen :', sum(1 for p in arch if p.get('last_seen')))
print('  есть checked_at:', sum(1 for p in arch if p.get('checked_at')))
print('  есть checks    :', sum(1 for p in arch if p.get('checks')))
print()

arch.sort(key=lambda p: -(p.get('last_seen') or 0))
print('самые свежие в архиве (недавно работали, но выпали из выдачи):')
for p in arch[:8]:
    ls = p.get('last_seen') or 0
    when = time.strftime('%d.%m %H:%M', time.localtime(ls)) if ls else '-'
    print(f"   {p['proxy'][:34]:<34} last_seen={when}")

print()
print('--- ключевой вопрос ---')
recent = [p for p in arch if (p.get('last_seen') or 0) >
          time.time() - 3600 * 12]
print(f'в архиве, но работали менее 12 часов назад: {len(recent)}')
if recent:
    print('Это и есть «пропавшие» прокси: они живые, но в этом прогоне')
    print('их не проверяли (новый список их не содержал), поэтому alive=False,')
    print('и persist() не пускает их в экспорт для расширения.')
