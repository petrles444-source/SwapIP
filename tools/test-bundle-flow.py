# -*- coding: utf-8 -*-
"""
Сквозной сценарий «как это будет у пользователя»:

  1. Анализатор собрал прокси и записал их в extension/data/proxies.json
  2. Пользователь нажал ⟳ в chrome://extensions
  3. Расширение подхватило список изнутри пакета — без импорта и без URL

Шаг 3 проверяется на настоящем background.js через стенд
tools/test-background-e2e.js (совместно с node tools/test-background-e2e.js).

Запуск: python tools/test-bundle-flow.py
"""
import io
import json
import os
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, os.path.join(ROOT, 'analyzer'))

from storage import EXTENSION_BUNDLE_FILE, export_to_extension_bundle, load_valid_proxies  # noqa: E402

passed = failed = 0


def check(name, cond, detail=''):
    global passed, failed
    if cond:
        passed += 1
        print(f'PASS  {name}')
    else:
        failed += 1
        print(f'FAIL  {name}' + (f' — {detail}' if detail else ''))


def main():
    print('1) Анализатор готовит список и встраивает его в расширение...')
    demo = [
        {
            'proxy': 'http://10.20.30.40:8080', 'latency': 0.35, 'external_ip': '10.20.30.40',
            'https': True, 'alive': True,
            'geo': {'country_code': 'NL', 'country': 'Netherlands', 'isp': 'DemoISP'},
            'anonymity': {'level': 'elite'},
        },
        {
            'proxy': 'socks5://10.20.30.41:1080', 'latency': 0.21, 'external_ip': '10.20.30.41',
            'https': True, 'alive': True,
            'geo': {'country_code': 'DE', 'country': 'Germany', 'isp': 'DemoISP2'},
            'anonymity': {'level': 'anonymous'},
        },
    ]
    path = export_to_extension_bundle(demo)

    check('файл создан', os.path.exists(path), path)
    check('лежит внутри папки extension/',
          os.path.normpath(path).startswith(os.path.join(ROOT, 'extension')))

    with io.open(path, encoding='utf-8') as f:
        data = json.load(f)

    check('формат совпадает с ожидаемым расширением',
          isinstance(data.get('proxies'), list) and 'updated' in data and 'count' in data,
          str(list(data.keys())))
    check('count совпадает с числом записей',
          data['count'] == len(data['proxies']) == 2)
    check('компактные ключи (p/l/c/n/a/i/https)',
          all(k in data['proxies'][0] for k in ('p', 'l', 'c', 'n', 'a', 'i', 'https')),
          str(sorted(data['proxies'][0].keys())))
    check('SOCKS5 сохранился с протоколом',
          any(p['p'].startswith('socks5://') for p in data['proxies']))
    check('записи отсортированы по задержке',
          data['proxies'][0]['l'] <= data['proxies'][1]['l'])
    # секунды из анализатора → миллисекунды в расширении
    check('задержка переведена в миллисекунды',
          sorted(p['l'] for p in data['proxies']) == [210, 350],
          str([p['l'] for p in data['proxies']]))

    print('\n2) Файл лежит по пути, который читает background.js:')
    expected = os.path.join(ROOT, 'extension', 'data', 'proxies.json')
    check('совпадает с BUNDLED_LIST_PATH в background.js',
          os.path.normpath(path) == os.path.normpath(expected),
          f'{path} != {expected}')

    src = io.open(os.path.join(ROOT, 'extension', 'background.js'), encoding='utf-8').read()
    check('background.js читает data/proxies.json',
          "BUNDLED_LIST_PATH = 'data/proxies.json'" in src)
    check('список подхватывается при обновлении расширения',
          "details.reason === 'update'" in src)
    check('есть кнопка ручной загрузки', "case 'loadBundled'" in src)

    print('\n3) Помечаем файл как «только что собранный» (для стенда):')
    print(f'   {path}')
    print('   → node tools/test-background-e2e.js проверит шаг «loadBundled»')

    print(f'\nИтого: {passed} PASS / {failed} FAIL')
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
