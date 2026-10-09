# -*- coding: utf-8 -*-
"""
Ищет живые источники прокси и проверяет, что они отдают данные.

Берёт список репозиториев, обходящихся через jsDelivr (GitHub CDN без
лимитов), и печатает те, что отвечают. Результат вставляется
в analyzer/config.py → PROXY_SOURCES.

Запуск: python tools/find-proxy-sources.py
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

import aiohttp  # noqa: E402

from scraper import parse_txt  # noqa: E402

# Репозитории, обновлённые недавно и крупные по числу звёзд
REPOS = [
    'monosans/proxy-list',
    'mmpx12/proxy-list',
    'sunny9577/proxy-scraper',
    'themiralay/Proxy-List-World',
    'watchttvv/free-proxy-list',
    'dpangestuw/Free-Proxy',
    'SoliSpirit/proxy-list',
    'MrMarble/proxy-list',
    'VPSLabCloud/VPSLab-Free-Proxy-List',
    'hproxy-com/free-proxy-list',
    'zloi-user/hideip.me',
    'xyzs996/free-proxy-health-list',
    'vmheaven/VMHeaven.io-Free-Proxy-List',
]

# Варианты путей внутри репозитория (пробуем все, берём первый живой)
PATHS = [
    'proxies/all.txt',
    'proxies/all/data.txt',
    'http.txt',
    'https.txt',
    'http/data.txt',
    'https/data.txt',
    'proxies/http.txt',
    'proxies/https.txt',
    'proxy.txt',
    'proxies.txt',
    'list.txt',
]

# Явно интересуют HTTPS-рабочие (они умеют CONNECT)
HTTPS_PATHS = ('https.txt', 'proxies/https.txt', 'https/data.txt')


async def try_url(session, url):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=25)) as r:
            if r.status != 200:
                return None
            text = await r.text(errors='ignore')
            if len(text) < 500:
                return None
            return text
    except Exception:
        return None


async def main():
    found = []
    async with aiohttp.ClientSession() as s:
        for repo in REPOS:
            owner, _, name = repo.partition('/')
            # сначала https-специфичные пути — именно они нам нужны,
            # ведь такие прокси умеют CONNECT
            for path in list(HTTPS_PATHS) + [p for p in PATHS if p not in HTTPS_PATHS]:
                url = f'https://cdn.jsdelivr.net/gh/{repo}/@main/{path}'
                text = await try_url(s, url)
                if text:
                    parsed = parse_txt(text)
                    if len(parsed) > 50:
                        tag = 'HTTPS' if path in HTTPS_PATHS else 'any'
                        print(f'  OK   {repo:<40} {path:<22} {len(parsed):>7}  [{tag}]')
                        print(f'       {url}')
                        found.append({'name': name, 'url': url,
                                      'count': len(parsed),
                                      'https_first': path in HTTPS_PATHS})
                    break

    print(f'\nитого рабочих источников: {len(found)}')
    if found:
        print('\nГотовые записи для config.py:')
        print('    {')
        print('        "name": "...",')
        print('        "url": "...",')
        print('        "format": "txt",')
        print('        "protocol": "http",')
        print('    },')


asyncio.run(main())
