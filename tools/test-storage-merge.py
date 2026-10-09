# -*- coding: utf-8 -*-
"""
Тесты слияния списков прокси (analyzer/storage.py).

Проверяют требование «повторная проверка не перезаписывает файл,
а сохраняет старые записи без дублирования».

Запуск: python tools/test-storage-merge.py
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

from storage import merge_proxy_records  # noqa: E402

passed = 0
failed = 0


def check(name, condition, detail=''):
    global passed, failed
    if condition:
        passed += 1
        print(f'PASS  {name}')
    else:
        failed += 1
        print(f'FAIL  {name}' + (f' — {detail}' if detail else ''))


# --- 1. Новый прокси добавляется, старый не теряется ---
old = [
    {'proxy': 'http://1.1.1.1:80', 'latency': 0.5, 'geo': {'country_code': 'US'}, 'alive': True},
    {'proxy': 'http://2.2.2.2:80', 'latency': 0.4, 'geo': {'country_code': 'DE'}, 'alive': True},
]
new = [
    {'proxy': 'http://2.2.2.2:80', 'latency': 0.3, 'external_ip': '2.2.2.2'},
    {'proxy': 'http://3.3.3.3:80', 'latency': 0.2, 'external_ip': '3.3.3.3'},
]
merged = merge_proxy_records(old, new)
urls = [r['proxy'] for r in merged]

check('новый прокси добавлен', 'http://3.3.3.3:80' in urls)
check('не проверенный в этом проходе прокси сохранён', 'http://1.1.1.1:80' in urls)
check('нет дублей', len(urls) == len(set(urls)), f'{urls}')
check('всего записей 3', len(merged) == 3, str(len(merged)))

# --- 2. У обновлённого прокси берётся свежее измерение, но сохраняется гео ---
updated = next(r for r in merged if r['proxy'] == 'http://2.2.2.2:80')
check('задержка обновлена новым замером', updated['latency'] == 0.3, str(updated.get('latency')))
check('гео не потеряно при слиянии', (updated.get('geo') or {}).get('country_code') == 'DE')
check('внешний IP из нового замера сохранён', updated.get('external_ip') == '2.2.2.2')

# --- 3. Пометки alive / сортировка ---
dead = next(r for r in merged if r['proxy'] == 'http://1.1.1.1:80')
check('не прошедший прокси помечен как не alive', dead['alive'] is False)
check('живые идут раньше архивных', merged[0]['proxy'] != 'http://1.1.1.1:80')
check('живые отсортированы по задержке',
      merged[0]['latency'] <= merged[1]['latency'], str([r['latency'] for r in merged[:2]]))

# --- 4. Повторная проверка тех же прокси не плодит дубли ---
merged2 = merge_proxy_records(merged, [
    {'proxy': 'http://2.2.2.2:80', 'latency': 0.25},
    {'proxy': 'http://3.3.3.3:80', 'latency': 0.22},
])
urls2 = [r['proxy'] for r in merged2]
check('повторная проверка не создаёт дублей', len(urls2) == len(set(urls2)), f'{urls2}')
check('размер базы не вырос', len(merged2) == 3, str(len(merged2)))
r22 = next(r for r in merged2 if r['proxy'] == 'http://2.2.2.2:80')
check('счётчик проверок растёт', r22['checks'] >= 2, str(r22.get('checks')))

# --- 5. keep_old=False — режим «строгая перепроверка» ---
strict = merge_proxy_records(old, [{'proxy': 'http://3.3.3.3:80', 'latency': 0.2}], keep_old=False)
check('keep_old=False выбрасывает непроверенные',
      [r['proxy'] for r in strict] == ['http://3.3.3.3:80'], str(strict))

# --- 6. Пустые и мусорные входы не ломают слияние ---
check('пустой new не теряет старые',
      len(merge_proxy_records(old, [])) == 2)
check('мусорные записи игнорируются',
      len(merge_proxy_records([{'no_proxy': 1}, None], [{'proxy': 'http://4.4.4.4:80'}])) == 1)
check('оба пустые дают пустой результат', merge_proxy_records([], []) == [])

print(f'\nИтого: {passed} PASS / {failed} FAIL')
sys.exit(1 if failed else 0)
