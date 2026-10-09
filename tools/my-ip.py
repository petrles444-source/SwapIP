# -*- coding: utf-8 -*-
"""Показывает, через кого идёт трафик прямо сейчас."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

import aiohttp  # noqa: E402


async def main():
    async with aiohttp.ClientSession() as s:
        for url in ['https://ipwho.is/', 'https://ipinfo.io/json']:
            try:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=12)) as r:
                    d = await r.json(content_type=None)
                    ip = d.get('ip') or d.get('query') or '?'
                    cc = d.get('country_code') or ''
                    cn = d.get('country') or ''
                    conn = d.get('connection') or {}
                    org = conn.get('org') or conn.get('isp') or ''
                    print('твой текущий IP   :', ip)
                    print('страна            :', cc, cn)
                    if org:
                        print('через провайдера  :', org)
                    return
            except Exception as exc:
                print(url, 'ошибка:', exc)


asyncio.run(main())
