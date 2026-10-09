# -*- coding: utf-8 -*-
"""Проверяет README: оглавление соответствует заголовкам, якоря существуют."""
import io
import os
import re
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
text = io.open(os.path.join(ROOT, 'README.md'), encoding='utf-8').read()
lines = text.splitlines()

failed = 0


def check(name, cond, detail=''):
    global failed
    if cond:
        print(f'PASS  {name}')
    else:
        failed += 1
        print(f'FAIL  {name}' + (f' — {detail}' if detail else ''))


def slug(title):
    """Как GitHub превращает заголовок в якорь."""
    s = title.strip().lower()
    s = re.sub(r'`', '', s)
    # убираем эмодзи и пунктуацию, оставляем буквы/цифры/пробелы/дефисы
    s = re.sub(r'[^\w\s\-]', '', s, flags=re.UNICODE)
    s = re.sub(r'\s+', '-', s)
    return s


# Заголовки уровней 2 и 3
headings = {}
for ln in lines:
    m = re.match(r'^(#{2,3})\s+(.+)$', ln)
    if m:
        t = m.group(2).strip()
        headings[slug(t)] = t

toc = re.search(r'## Содержание\n(.*?)\n---', text, re.S)
check('раздел «Содержание» есть', toc is not None)

links = re.findall(r'\[([^\]]+)\]\(#([^)]+)\)', text)
broken = [(t, a) for t, a in links if a not in headings]
check('все якоря оглавления существуют', not broken,
      '; '.join(f'{t} -> #{a}' for t, a in broken))
print(f'      проверено ссылок: {len(links)}, заголовков: {len(headings)}')

# Каждый пункт оглавления ведёт в раздел
if toc:
    items = re.findall(r'\[([^\]]+)\]\(#([^)]+)\)', toc.group(1))
    missing = [a for _, a in items if a not in headings]
    check('все пункты оглавления найдены среди заголовков', not missing, str(missing))

# Нет незакрытых оговорок про старые цифры
check('нет устаревшей цифры «34 из 150»', '34 из 150' not in text)
check('нет слов-мусор в описании прокси',
      'это мусор' not in text.lower().replace('не мусор', ''))

# Обязательные разделы для новичка
for must in ['Быстрый старт', 'Анализатор', 'Если что-то пошло не так',
             'Что нужно знать про бесплатные прокси', 'Безопасность и приватность',
             'Тесты', 'Структура проекта']:
    check(f'раздел «{must}» есть', must in text)

print()
print('ИТОГ:', 'README в порядке' if not failed else f'{failed} проблем')
sys.exit(1 if failed else 0)
