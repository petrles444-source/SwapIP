# -*- coding: utf-8 -*-
"""
Предупреждает, если анализатор запущен через прокси или VPN.

Почему это важно: проверка идёт С ТВОЕГО адреса. Если трафик идёт через
прокси, то отбираются прокси, доступные ИЗ ЭТОГО прокси, а не из твоей
домашней сети. Список получается смещённым: например, при запуске из
Германии в него попадают европейские серверы (близко => быстро), а
азиатские и ближневосточные отсеиваются по таймауту.

Если задача — «с России на зарубежные», анализатор надо запускать
напрямую, без прокси и без VPN.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

import aiohttp  # noqa: E402

# Признаки, что трафик идёт через прокси/туннель.
SUSPICIOUS = {
    'cloudflare': 'Cloudflare (WARP)',
    'warp': 'Cloudflare WARP',
    'nordvpn': 'NordVPN',
    'expressvpn': 'ExpressVPN',
    'surfshark': 'Surfshark',
    'mullvad': 'Mullvad',
    'windscribe': 'Windscribe',
    'protonvpn': 'ProtonVPN',
    'private internet access': 'Private Internet Access',
    'vpns': 'VPN',
}


async def main():
    info = None
    async with aiohttp.ClientSession() as s:
        for url in ('https://ipwho.is/', 'https://ipinfo.io/json'):
            try:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=12)) as r:
                    info = await r.json(content_type=None)
                    break
            except Exception:
                continue

    if not info:
        print('Не удалось определить свой адрес — проверка пропущена.')
        return

    ip = info.get('ip') or info.get('query') or '?'
    cc = info.get('country_code') or ''
    country = info.get('country') or ''
    conn = info.get('connection') or {}
    org = str(conn.get('org') or conn.get('isp') or '')

    print('=' * 62)
    print(f'  Сейчас ты подключён как: {ip}')
    print(f'  Страна: {cc} {country}')
    if org:
        print(f'  Через:  {org}')

    low = org.lower()
    hit = next((name for key, name in SUSPICIOUS.items() if key in low), None)

    if hit:
        print()
        print('  ⚠ ВНИМАНИЕ: похоже, трафик идёт через ' + hit)
        print()
        print('  Проверка прокси идёт ОТ ТВОЕГО адреса. При запуске через')
        print('  прокси отбираются серверы, доступные из этого прокси,')
        print('  а не из твоей домашней сети — список получается смещённым.')
        print()
        print('  Если задача «с России на зарубежные», отключи прокси/VPN')
        print('  и запусти анализатор напрямую.')
    else:
        print()
        print('  Прямое соединение — список будет релевантен твоей сети.')
    print('=' * 62)


asyncio.run(main())
