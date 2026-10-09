# -*- coding: utf-8 -*-
"""
Проверяет, что шум от ConnectionResetError на прокси больше не появляется.

На Windows мёртвый прокси вызывает трейсбек внутри служебного колбэка
asyncio — выглядит как падение, хотя проверка идёт нормально.

Тест гоняет настоящий batch на заведомо мёртвых адресах (localhost на
закрытых портах) и падает, если в выводе мелькнет 'Traceback'.

Запуск: python tools/test-no-reset-noise.py
"""
import asyncio
import io
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

import checker  # noqa: E402


async def main():
    # Заведомо мёртвые адреса: порты, где никто не слушает.
    # 127.0.0.1:1 и пустые порты обрываются с RESET/отказом — как в жизни.
    dead = [f'http://127.0.0.1:{p}' for p in
            list(range(1, 40)) + list(range(70000, 70040))]
    # Плюс заведомо несуществующие внешние адреса
    dead += ['http://0.0.0.0:80', 'http://10.255.255.1:8080']

    print(f'Проверяем {len(dead)} мёртвых адресов...')

    calls = {'n': 0}

    def progress(checked, total, valid):
        calls['n'] += 1

    loop = asyncio.get_running_loop()

    # Перехватываем стандартный вывод, чтобы поймать трейсбек.
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        results = await checker.check_proxies_batch(dead, timeout=4, progress_callback=progress)

    output = buf.getvalue()

    ok = True

    if results:
        print(f'FAIL  мёртвые адреса неожиданно признаны рабочими: {len(results)}')
        ok = False
    else:
        print('PASS  все мёртвые адреса отклонены')

    if 'Traceback' in output or 'ConnectionResetError' in output:
        print('FAIL  в выводе остался шум ConnectionResetError')
        print('  --- фрагмент ---')
        for line in output.splitlines()[:8]:
            print('   ', line)
        ok = False
    else:
        print('PASS  шума ConnectionResetError нет')

    if calls['n'] > 0:
        print(f'PASS  прогресс отработал ({calls["n"]} раз)')
    else:
        print('FAIL  прогресс-бар не вызывался')
        ok = False

    print()
    print('ИТОГ:', 'шум устранён' if ok else 'есть проблемы')
    return 0 if ok else 1


sys.exit(asyncio.run(main()))
