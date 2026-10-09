# -*- coding: utf-8 -*-
"""Парсинг прокси из внешних источников + ручные файлы."""

import os
import re
import json
import asyncio
import aiohttp
from typing import Optional, Set

from config import PROXY_SOURCES, MAX_PROXIES_PER_SOURCE, MANUAL_PROXY_DIR

PROXY_PATTERN = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$')


def normalize_proxy(proxy_str: str, default_protocol: str = "http") -> Optional[str]:
    """Нормализует строку к виду protocol://[user:pass@]ip:port или None."""
    proxy_str = str(proxy_str).strip().strip('"\' ,')
    if not proxy_str:
        return None

    if '://' in proxy_str:
        m = re.match(r'^(\w+)://(?:([^:]+):([^@]+)@)?(.+)$', proxy_str)
        if m:
            protocol, user, password, host_port = m.groups()
            hp = PROXY_PATTERN.match(host_port)
            if hp:
                ip, port = hp.groups()
                if user and password:
                    return f"{protocol}://{user}:{password}@{ip}:{port}"
                return f"{protocol}://{ip}:{port}"

    parts = proxy_str.split(':')
    if len(parts) == 4:
        ip, port, user, password = parts
        if PROXY_PATTERN.match(f"{ip}:{port}"):
            return f"{default_protocol}://{user}:{password}@{ip}:{port}"

    if PROXY_PATTERN.match(proxy_str):
        return f"{default_protocol}://{proxy_str}"
    return None


def parse_txt(content: str, default_protocol: str = "http") -> Set[str]:
    proxies = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        n = normalize_proxy(line, default_protocol)
        if n:
            proxies.add(n)
    return proxies


def parse_json(content: str, default_protocol: str = "http") -> Set[str]:
    proxies = set()
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return proxies

    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                n = normalize_proxy(item, default_protocol)
                if n:
                    proxies.add(n)
            elif isinstance(item, dict):
                ip = item.get('ip') or item.get('host') or item.get('address')
                port = item.get('port')
                protocol = item.get('protocol') or item.get('type') or default_protocol
                if ip and port:
                    n = normalize_proxy(f"{protocol}://{ip}:{port}", protocol)
                    if n:
                        proxies.add(n)
    elif isinstance(data, dict):
        for key in ('data', 'proxies', 'list', 'results'):
            if key in data and isinstance(data[key], list):
                proxies.update(parse_json(json.dumps(data[key]), default_protocol))
    return proxies


async def fetch_source(session: aiohttp.ClientSession, source: dict) -> Set[str]:
    name, url = source["name"], source["url"]
    fmt = source.get("format", "txt")
    protocol = source.get("protocol", "http")
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                print(f"  [!] {name}: HTTP {resp.status}")
                return set()
            content = await resp.text(errors='ignore')
    except Exception as e:
        print(f"  [!] {name}: {e}")
        return set()

    proxies = parse_json(content, protocol) if fmt == "json" else parse_txt(content, protocol)
    if len(proxies) > MAX_PROXIES_PER_SOURCE:
        proxies = set(list(proxies)[:MAX_PROXIES_PER_SOURCE])
    print(f"  [+] {name}: {len(proxies)} прокси")
    return proxies


async def scrape_all_sources() -> Set[str]:
    """Асинхронно собирает прокси со всех источников."""
    all_proxies: Set[str] = set()
    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        results = await asyncio.gather(
            *[fetch_source(session, src) for src in PROXY_SOURCES],
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, set):
                all_proxies.update(r)
    return all_proxies


def load_manual_proxies() -> Set[str]:
    """Прокси из папки proxies/ (.txt и .json) — ручное добавление."""
    proxies = set()
    if not os.path.exists(MANUAL_PROXY_DIR):
        return proxies
    for filename in os.listdir(MANUAL_PROXY_DIR):
        filepath = os.path.join(MANUAL_PROXY_DIR, filename)
        if not os.path.isfile(filepath):
            continue
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            continue
        if filename.endswith('.json'):
            proxies.update(parse_json(content))
        elif filename.endswith('.txt'):
            proxies.update(parse_txt(content))
    return proxies
