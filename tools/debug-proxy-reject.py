# -*- coding: utf-8 -*-
"""Отладка: почему локальный CONNECT-прокси отклоняется."""
import asyncio
import importlib.util
import os
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, os.path.join(ROOT, 'analyzer'))

spec = importlib.util.spec_from_file_location(
    'tlt', os.path.join(ROOT, 'tools', 'test-latency-threshold.py')
)
tlt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tlt)

import aiohttp  # noqa: E402
import checker  # noqa: E402
from config import TEST_URL  # noqa: E402


async def main():
    port = tlt.make_delayed_proxy(0.2)
    url = f'http://127.0.0.1:{port}'
    print('локальный CONNECT-прокси:', url)

    async with aiohttp.ClientSession() as s:
        ok, data, exc = await checker._fetch_json(s, TEST_URL, url, 15)
        print(f'_fetch_json: ok={ok}  exc={type(exc).__name__ if exc else None}')
        if exc:
            print('   ', str(exc)[:250])
        print('   data =', data)

        r = await checker.check_proxy(s, url, timeout=15)
        print('check_proxy ->', 'ПРИНЯТ ' + str(r) if r else 'отклонён')

        print()
        print('--- прямой запрос без прокси (для контроля) ---')
        ok2, data2, exc2 = await checker._fetch_json(s, TEST_URL, 'http://127.0.0.1:1', 5)
        print(f'   контрольный (заведомо мёртвый): ok={ok2} exc={type(exc2).__name__}')


asyncio.run(main())
