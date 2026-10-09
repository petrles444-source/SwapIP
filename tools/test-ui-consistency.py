# -*- coding: utf-8 -*-
"""Сверяет, что popup/options HTML согласован с JS и CSS (нет битых id)."""
import io
import os
import re
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))


def read(p):
    return io.open(os.path.join(ROOT, p), encoding='utf-8').read()


html, js, css = read('extension/popup.html'), read('extension/popup.js'), read('extension/popup.css')
ohtml, ojs = read('extension/options.html'), read('extension/options.js')

failed = 0


def check(name, cond, detail=''):
    global failed
    if cond:
        print(f'PASS  {name}')
    else:
        failed += 1
        print(f'FAIL  {name}' + (f' — {detail}' if detail else ''))


ID_RE = re.compile(r'id="([^"]+)"')
GET_RE = re.compile(r"getElementById\('([^']+)'\)")

ids_html = set(ID_RE.findall(html))
used = set(GET_RE.findall(js))
check('popup: нет обращений к несуществующим id', not (used - ids_html), str(sorted(used - ids_html)))

# Контейнеры (страницы вкладок, карточки) адресуются из CSS и разметки,
# а не из JS — их отсутствие в getElementById не является проблемой.
STRUCTURAL = {'page-main', 'page-servers', 'page-countries', 'statusCard', 'locationCard'}
interactive = ids_html - used - STRUCTURAL
check('popup: все интерактивные элементы задействованы', not interactive, str(sorted(interactive)))

# Структурные id обязаны присутствовать в разметке и не быть лишними
check('popup: структурные контейнеры на месте', STRUCTURAL <= ids_html,
      str(sorted(STRUCTURAL - ids_html)))

oids = set(ID_RE.findall(ohtml))
oused = set(GET_RE.findall(ojs))
check('options: нет обращений к несуществующим id', not (oused - oids), str(sorted(oused - oids)))

NEW_CLASSES = [
    'connect-progress', 'progress-track', 'progress-bar', 'progress-text',
    'emergency', 'emergency-btn', 'emergency-hint', 'wide-btn'
]
missing_css = [c for c in NEW_CLASSES if f'.{c}' not in css]
check('popup.css: стили новых элементов на месте', not missing_css, str(missing_css))
check('popup.css: есть стиль для кнопки в состоянии подключения',
      '.connect-btn.connecting' in css)

# background.js: actions, на которые ссылается UI, должны существовать
bg = read('extension/background.js')
for action in ['getState', 'connect', 'connectTo', 'disconnect', 'toggle',
               'switchCountry', 'refresh', 'checkNow', 'import', 'loadBundled',
               'emergencyReset', 'reconcile', 'cancelConnect', 'getSettings',
               'setSettings', 'activateLicense']:
    check(f'background.js: action «{action}»', f"case '{action}'" in bg)

# каждое PROBE-эндпоинт-хоста должно быть в PAC, иначе зонд пойдёт мимо прокси
hosts = re.findall(r"url: 'https://([a-z0-9.\-]+)/", bg)
pac_block = bg[bg.index('const PROBE_HOSTS'):bg.index('const PROBE_HOSTS') + 300]
missing_hosts = [h for h in hosts if f"'{h}'" not in pac_block]
check('PAC: все хосты зондов попали в PROBE_HOSTS', not missing_hosts, str(missing_hosts))

# ключи настроек должны совпадать между DEFAULT_SETTINGS и pick()
default_block = bg[bg.index('const DEFAULT_SETTINGS'):bg.index('const DEFAULT_SETTINGS') + 500]
settings_keys = set(re.findall(r'^\s{2}(\w+):', default_block, re.M))
pick_block = bg[bg.index('pick(msg.settings,'):]
pick_block = pick_block[:pick_block.index(']')]
picked = set(re.findall(r"'(\w+)'", pick_block))
check('настройки: pick() принимает все поля DEFAULT_SETTINGS',
      settings_keys <= picked, str(sorted(settings_keys - picked)))

print()
print('ИТОГ:', 'всё согласовано' if not failed else f'{failed} расхождений')
sys.exit(1 if failed else 0)
