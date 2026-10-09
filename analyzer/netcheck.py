# -*- coding: utf-8 -*-
"""
Определяет, не идёт ли трафик анализатора через прокси.

Возвращает True, если соединение выглядит туннелированным (VPN/WARP).
"""
import asyncio
import os
import sys
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

import aiohttp  # noqa: E402

# Признаки туннеля в поле «через кого».
TUNNEL_HINTS = (
    'cloudflare', 'warp', 'nordvpn', 'expressvpn', 'surfshark', 'mullvad',
    'windscribe', 'protonvpn', 'private internet access', 'cyberghost',
    'hotspot shield', 'tunnelbear', 'psiphon', 'lantern', 'outline',
)


async def detect(timeout: int = 12) -> Optional[dict]:
    """Возвращает сведения о текущем подключении или None."""
    async with aiohttp.ClientSession() as s:
        for url in ('https://ipwho.is/', 'https://ipinfo.io/json'):
            try:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                    data = await r.json(content_type=None)
                    conn = data.get('connection') or {}
                    org = str(conn.get('org') or conn.get('isp') or '')
                    return {
                        'ip': data.get('ip') or data.get('query') or '?',
                        'country_code': data.get('country_code') or '',
                        'country': data.get('country') or '',
                        'org': org,
                        'tunnelled': any(h in org.lower() for h in TUNNEL_HINTS),
                    }
            except Exception:
                continue
    return None


async def main():
    info = await detect()
    if not info:
        print('  (не удалось определить подключение — проверка пропущена)')
        return
    print(f"  подключение: {info['ip']}  {info['country_code']} {info['country']}")
    if info['org']:
        print(f"  через:       {info['org']}")
    if info['tunnelled']:
        print('  ⚠ похоже на VPN/WARP: список прокси будет смещённым')


if __name__ == '__main__':
    asyncio.run(main())
