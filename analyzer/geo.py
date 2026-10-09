# -*- coding: utf-8 -*-
"""Геолокация IP через бесплатный ip-api.com (без ключа, 45req/мин)."""

import asyncio
from typing import Dict, Optional

import aiohttp

from storage import load_geo_cache, save_geo_cache

GEO_API_URL = ("http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
               "regionName,city,timezone,isp,org,as,query")

_geo_cache: Dict[str, Dict] = load_geo_cache()


async def get_geo_info(session: aiohttp.ClientSession, ip: str, use_cache: bool = True) -> Optional[Dict]:
    if use_cache and ip in _geo_cache:
        return _geo_cache[ip]
    try:
        async with session.get(GEO_API_URL.format(ip=ip), timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
            if data.get("status") != "success":
                return None
            result = {
                "country": data.get("country", "Unknown"),
                "country_code": data.get("countryCode", ""),
                "region": data.get("regionName", ""),
                "city": data.get("city", ""),
                "timezone": data.get("timezone", ""),
                "isp": data.get("isp", "Unknown"),
                "org": data.get("org", ""),
                "asn": data.get("as", ""),
            }
            if use_cache:
                _geo_cache[ip] = result
            return result
    except Exception:
        return None


async def enrich_proxies_with_geo(proxies: list, max_concurrent: int = 10) -> list:
    """Добавляет поле geo каждому прокси (по external_ip или из строки proxy)."""
    import re
    semaphore = asyncio.Semaphore(max_concurrent)

    async with aiohttp.ClientSession() as session:

        async def enrich_one(p: dict):
            async with semaphore:
                ip = p.get("external_ip")
                if not ip:
                    m = re.search(r'@?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):', p.get("proxy", ""))
                    ip = m.group(1) if m else None
                p["geo"] = await get_geo_info(session, ip) if ip else None
                return p

        return await asyncio.gather(*[enrich_one(p) for p in proxies])


def get_country_flag(country_code: str) -> str:
    """'US' -> '🇺🇸'."""
    if not country_code or len(country_code) != 2:
        return "🌍"
    return chr(ord(country_code[0]) + 127397) + chr(ord(country_code[1]) + 127397)


def flush_geo_cache():
    """Сохраняет накопленный кэш гео на диск (ip-api лимитирован, кэш ценен)."""
    save_geo_cache(_geo_cache)
