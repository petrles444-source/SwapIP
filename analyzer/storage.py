# -*- coding: utf-8 -*-
"""Локальное хранилище результатов + экспорт для расширения."""

import json
import os
import shutil
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from config import (
    RAW_PROXIES_FILE,
    VALID_PROXIES_FILE,
    TOP_PROXIES_FILE,
    GEO_CACHE_FILE,
    DATA_DIR,
    EXTENSION_EXPORT_FILE,
    EXTENSION_BUNDLE_FILE,
    EXTENSION_DATA_DIR,
    EXPORT_LIMIT,
    MERGE_KEEP_OLD,
)


def save_raw_proxies(proxies: Set[str]):
    with open(RAW_PROXIES_FILE, 'w', encoding='utf-8') as f:
        for p in sorted(proxies):
            f.write(p + '\n')
    print(f"[Storage] {len(proxies)} сырых прокси -> {RAW_PROXIES_FILE}")


def load_raw_proxies() -> Set[str]:
    proxies = set()
    if os.path.exists(RAW_PROXIES_FILE):
        with open(RAW_PROXIES_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    proxies.add(line)
    return proxies


def save_valid_proxies(proxies: List[Dict]):
    with open(VALID_PROXIES_FILE, 'w', encoding='utf-8') as f:
        json.dump(proxies, f, ensure_ascii=False, indent=2)
    print(f"[Storage] {len(proxies)} рабочих прокси -> {VALID_PROXIES_FILE}")


def load_valid_proxies() -> List[Dict]:
    if not os.path.exists(VALID_PROXIES_FILE):
        return []
    try:
        with open(VALID_PROXIES_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    return data if isinstance(data, list) else []


def save_top_proxies(proxies: List[Dict], limit: int = 200):
    top = proxies[:limit]
    with open(TOP_PROXIES_FILE, 'w', encoding='utf-8') as f:
        json.dump(top, f, ensure_ascii=False, indent=2)
    print(f"[Storage] {len(top)} топ-прокси -> {TOP_PROXIES_FILE}")


def load_top_proxies() -> List[Dict]:
    if not os.path.exists(TOP_PROXIES_FILE):
        return []
    try:
        with open(TOP_PROXIES_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    return data if isinstance(data, list) else []


# ================= СЛИЯНИЕ БЕЗ ДУБЛИРОВАНИЯ =================

def merge_proxy_records(old: List[Dict], new: List[Dict],
                        keep_old: bool = MERGE_KEEP_OLD) -> List[Dict]:
    """
    Объединяет старый и новый списки прокси БЕЗ дублирования.

    Правила:
      * ключ записи — нормализованная строка 'proxy';
      * если прокси есть и там, и там — берём новые измерения, но сохраняем
        гео/анонимность/историю из старой записи (они не перезапрашиваются
        при каждой проверке и не должны теряться);
      * записи только из старого списка сохраняются (если keep_old),
        помечаются как не проверенные в этом проходе, и тянутся в конец;
      * сортировка: живые — по задержке, архивные — в конце.
    """
    merged: Dict[str, Dict] = {}
    now = time_now()

    for rec in old or []:
        key = _record_key(rec)
        if not key:
            continue
        base = dict(rec)
        base.setdefault('first_seen', base.get('checked_at', now))
        merged[key] = base

    fresh_keys = set()
    added = 0
    updated = 0

    for rec in new or []:
        key = _record_key(rec)
        if not key:
            continue
        fresh_keys.add(key)
        prev = merged.get(key)
        if prev is not None:
            updated += 1
            combined = {**prev, **rec}
            # Гео и анонимность — дорогие внешние запросы; не затираем их
            # пустыми значениями, если в новом замере их не было.
            for field in ('geo', 'anonymity'):
                if not rec.get(field) and prev.get(field):
                    combined[field] = prev[field]
            combined['first_seen'] = prev.get('first_seen', now)
            combined['last_seen'] = now
            combined['alive'] = True
            combined['checks'] = int(prev.get('checks', 0)) + 1
            merged[key] = combined
        else:
            added += 1
            fresh = dict(rec)
            fresh['first_seen'] = now
            fresh['last_seen'] = now
            fresh['alive'] = True
            fresh['checks'] = 1
            merged[key] = fresh

    kept_old = 0
    if keep_old:
        for key, rec in merged.items():
            if key in fresh_keys:
                continue
            rec['alive'] = False
            rec['last_checked'] = rec.get('last_checked') or rec.get('checked_at')
            kept_old += 1
    else:
        merged = {k: v for k, v in merged.items() if k in fresh_keys}

    result = list(merged.values())
    result.sort(key=_sort_key)

    if added or updated or kept_old:
        print(f"[Merge] +{added} новых, ~{updated} обновлено, "
              f"{kept_old} сохранено из прошлых (без дублей: {len(result)})")
    return result


def _record_key(rec: Dict) -> str:
    proxy = rec.get('proxy') if isinstance(rec, dict) else None
    return str(proxy).strip() if proxy else ''


def _sort_key(rec: Dict):
    alive = 0 if rec.get('alive', True) else 1
    return (alive, rec.get('latency', 99.0), -(rec.get('last_seen') or 0))


def time_now() -> float:
    import time
    return time.time()


# ================= ЭКСПОРТ =================

def export_for_extension(proxies: list, output_file: Optional[str] = None,
                         limit: int = EXPORT_LIMIT) -> str:
    """
    Компактный JSON для расширения SwapIP:
    короткие ключи (p/l/c/n/a/i/https), сортировка по скорости.
    """
    output_file = output_file or EXTENSION_EXPORT_FILE
    compact = []
    for p in proxies:
        geo = p.get("geo") or {}
        anon = p.get("anonymity") or {}
        compact.append({
            "p": p["proxy"],
            "l": round(p.get("latency", 0) * 1000),
            "c": geo.get("country_code", ""),
            "n": geo.get("country", ""),
            "a": anon.get("level", "unknown"),
            "i": (geo.get("isp") or "")[:30],
            "https": bool(p.get("https", True)),
        })
    compact.sort(key=lambda x: x["l"])
    compact = compact[:limit]
    output = {
        "updated": datetime.now(timezone.utc).isoformat(),
        "count": len(compact),
        "proxies": compact,
    }
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, ensure_ascii=False, separators=(',', ':'))
    print(f"[Export] {len(compact)} прокси -> {output_file}")
    return output_file


def export_to_extension_bundle(proxies: list, limit: int = EXPORT_LIMIT) -> Optional[str]:
    """
    Кладёт список ПРЯМО В РАСШИРЕНИЕ (extension/data/proxies.json).

    После этого достаточно нажать «Обновить» (⟳) в chrome://extensions —
    расширение подхватит список изнутри пакета. Никакой импорт, никакого
    URL, никакого анализатора у другого человека не нужно.
    """
    try:
        os.makedirs(EXTENSION_DATA_DIR, exist_ok=True)
        path = export_for_extension(proxies, EXTENSION_BUNDLE_FILE, limit)
        size_kb = os.path.getsize(EXTENSION_BUNDLE_FILE) / 1024
        print(f"[Bundle] Список встроен в расширение ({size_kb:.1f} КБ)")
        print(f"[Bundle] → chrome://extensions → SwapIP → ⟳ Обновить")
        return path
    except Exception as exc:  # noqa: BLE001
        print(f"[Bundle] Не удалось записать список в расширение: {exc}")
        return None


# ================= ГЕО-КЭШ =================

def load_geo_cache() -> Dict:
    if not os.path.exists(GEO_CACHE_FILE):
        return {}
    try:
        with open(GEO_CACHE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_geo_cache(cache: Dict):
    with open(GEO_CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(cache, f, ensure_ascii=False)


# ================= СТАТИСТИКА =================

def get_stats() -> Dict:
    raw = load_raw_proxies()
    valid = load_valid_proxies()
    top = load_top_proxies()
    alive = [p for p in valid if p.get('alive', True)]
    fastest = min((p['latency'] for p in alive), default=None)
    return {
        "raw_count": len(raw),
        "valid_count": len(alive),
        "archived_count": len(valid) - len(alive),
        "top_count": len(top),
        "fastest_latency": fastest,
    }
