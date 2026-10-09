# -*- coding: utf-8 -*-
"""SwapIP Analyzer — CLI: полный парсинг / перепроверка / топ / экспорт."""

import asyncio
import os
import shutil
import sys

from colorama import Fore, Style, init

from anonymity import check_anonymity
from checker import check_proxies_batch
from config import (
    ANONYMITY_CHECK,
    ANONYMITY_LIMIT,
    DATA_DIR,
    GEO_CHECK,
    MANUAL_PROXY_DIR,
    MERGE_KEEP_OLD,
)
from geo import enrich_proxies_with_geo, flush_geo_cache
from scraper import load_manual_proxies, scrape_all_sources
from storage import (
    export_for_extension,
    export_to_extension_bundle,
    get_stats,
    load_valid_proxies,
    merge_proxy_records,
    save_raw_proxies,
    save_top_proxies,
    save_valid_proxies,
)

init(autoreset=True)


def progress(checked, total, valid):
    percent = checked / total * 100 if total else 0
    filled = int(30 * checked / total) if total else 0
    bar = '█' * filled + '░' * (30 - filled)
    print(f"\r  [{bar}] {checked}/{total} ({percent:.1f}%) | Рабочих: {valid}", end='', flush=True)


async def enrich(results):
    """Обогащает результаты гео и анонимностью (и то, и другое — внешние запросы)."""
    if GEO_CHECK:
        print(f"\n{Fore.YELLOW}  Геолокация {len(results)} IP...{Style.RESET_ALL}", end='', flush=True)
        results = await enrich_proxies_with_geo(results)
        flush_geo_cache()
        print(f"{Fore.GREEN} готово{Style.RESET_ALL}")

    if ANONYMITY_CHECK and results:
        import aiohttp
        subset = results[:ANONYMITY_LIMIT]
        print(f"{Fore.YELLOW}  Анонимность {len(subset)} прокси...{Style.RESET_ALL}", end='', flush=True)
        connector = aiohttp.TCPConnector(limit=20)
        async with aiohttp.ClientSession(connector=connector) as session:
            sem = asyncio.Semaphore(20)

            async def one(p):
                async with sem:
                    p['anonymity'] = await check_anonymity(session, p['proxy'], timeout=10)

            await asyncio.gather(*[one(p) for p in subset])
        print(f"{Fore.GREEN} готово{Style.RESET_ALL}")
    return results


def persist(results, old=None):
    """Сохраняет результаты с учётом слияния и обновляет оба экспорта."""
    merged = merge_proxy_records(old or [], results, keep_old=MERGE_KEEP_OLD)
    save_valid_proxies(merged)
    save_top_proxies([p for p in merged if p.get('alive', True)])
    alive = [p for p in merged if p.get('alive', True)]
    export_for_extension(alive)
    export_to_extension_bundle(alive)
    return merged, alive


async def run_full_parse():
    """Парсинг всех источников + проверка + сохранение + экспорт в расширение."""
    print(f"\n{Fore.CYAN}[*] Полный парсинг всех источников...{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}[Фаза 1/4] Парсинг:{Style.RESET_ALL}")
    scraped = await scrape_all_sources()
    manual = load_manual_proxies()
    if manual:
        print(f"  [+] Ручные прокси: {len(manual)}")
        scraped.update(manual)
    if not scraped:
        print(f"{Fore.RED}[!] Ни одного прокси не спарсено.{Style.RESET_ALL}")
        return

    print(f"\n{Fore.GREEN}[✓] Уникальных прокси: {len(scraped)}{Style.RESET_ALL}")
    save_raw_proxies(scraped)

    print(f"\n{Fore.YELLOW}[Фаза 2/4] Проверка {len(scraped)} прокси (HTTPS)...{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Прокси без поддержки CONNECT и с подменой сертификата отбрасываются.{Style.RESET_ALL}")
    valid = await check_proxies_batch(list(scraped), progress_callback=progress)
    print(f"\n\n{Fore.GREEN}[✓] Рабочих прокси: {len(valid)}{Style.RESET_ALL}")

    print(f"\n{Fore.YELLOW}[Фаза 3/4] Обогащение данными...{Style.RESET_ALL}")
    valid = await enrich(valid)

    print(f"\n{Fore.YELLOW}[Фаза 4/4] Сохранение и экспорт...{Style.RESET_ALL}")
    _merged, alive = persist(valid)

    if alive:
        print(f"{Fore.GREEN}  Лучшая скорость: {alive[0]['latency']*1000:.0f} мс{Style.RESET_ALL}")


async def run_quick_recheck():
    """
    Перепроверка уже известных рабочих прокси.

    Не перезаписывает файл: результаты сливаются со старыми записями
    без дублирования (см. storage.merge_proxy_records).
    """
    valid = load_valid_proxies()
    if not valid:
        print(f"{Fore.YELLOW}[!] Нет сохранённых прокси. Сначала пункт 1.{Style.RESET_ALL}")
        return

    alive_old = [p for p in valid if p.get('alive', True)]
    targets = [p['proxy'] for p in (alive_old or valid)]
    print(f"\n{Fore.CYAN}[*] Перепроверка {len(targets)} прокси...{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Найденные снова добавятся к прежним записям — дубликатов не будет.{Style.RESET_ALL}")

    fresh = await check_proxies_batch(targets, progress_callback=progress)
    print(f"\n\n{Fore.GREEN}[✓] Живых: {len(fresh)} из {len(targets)}{Style.RESET_ALL}")

    # Гео/анонимность из старых записей подтянутся при слиянии.
    _merged, alive = persist(fresh, old=valid)
    print(f"{Fore.GREEN}  Всего в базе (без дублей): {len(alive)}{Style.RESET_ALL}")


def show_top_proxies():
    from geo import get_country_flag

    top_path = os.path.join(DATA_DIR, "top_proxies.json")
    if not os.path.exists(top_path):
        print(f"{Fore.YELLOW}[!] Нет данных. Сначала пункт 1.{Style.RESET_ALL}")
        return
    import json
    with open(top_path, 'r', encoding='utf-8') as f:
        top = json.load(f)

    print(f"\n{Fore.GREEN}  ТОП-50 ПРОКСИ ПО СКОРОСТИ{Style.RESET_ALL}")
    header = f"  {'#':<4} {'Прокси':<40} {'Скорость':<11} {'Страна':<18} {'Анонимность':<14} {'ISP'}"
    print(f"{Fore.WHITE}{header}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-' * 110}{Style.RESET_ALL}")

    for i, p in enumerate(top[:50], 1):
        ms = p['latency'] * 1000
        color = Fore.GREEN if ms < 500 else (Fore.YELLOW if ms < 1500 else Fore.RED)
        geo = p.get('geo') or {}
        anon = p.get('anonymity') or {}
        flag = get_country_flag(geo.get('country_code', ''))
        country = f"{flag} {(geo.get('country') or '?')[:14]}"
        proxy_str = p['proxy'][:38]
        print(f"  {i:<4} {proxy_str:<40} {color}{ms:>7.1f} мс{Style.RESET_ALL}   {country:<18} "
              f"{anon.get('level', '?'):<14} {(geo.get('isp') or '?')[:25]}")


def export_only():
    """Пересобирает экспорт из уже сохранённой базы, ничего не проверяя."""
    valid = load_valid_proxies()
    alive = [p for p in valid if p.get('alive', True)]
    if not alive:
        print(f"{Fore.YELLOW}[!] Нет живых прокси в базе. Сначала пункт 1 или 2.{Style.RESET_ALL}")
        return
    export_for_extension(alive)
    export_to_extension_bundle(alive)


def clear_all_data():
    if input(f"\n{Fore.RED}Удалить все данные? (y/N): {Style.RESET_ALL}").lower() != 'y':
        print(f"{Fore.YELLOW}Отменено.{Style.RESET_ALL}")
        return
    if os.path.exists(DATA_DIR):
        shutil.rmtree(DATA_DIR)
        os.makedirs(DATA_DIR, exist_ok=True)
    print(f"{Fore.GREEN}[✓] Данные очищены.{Style.RESET_ALL}")


def print_menu():
    stats = get_stats()
    print(f"\n{Fore.CYAN}{'─' * 58}")
    print(f"  Живых: {Fore.GREEN}{stats['valid_count']}{Fore.CYAN} | "
          f"Топ: {stats['top_count']}", end="")
    if stats.get('archived_count'):
        print(f" | В архиве: {Fore.YELLOW}{stats['archived_count']}", end="")
    if stats['fastest_latency']:
        print(f" | Лучшая: {Fore.GREEN}{stats['fastest_latency']*1000:.0f} мс{Fore.CYAN}", end="")
    print()
    print(f"{'─' * 58}{Style.RESET_ALL}")
    print(f"""
  {Fore.GREEN}[1]{Fore.WHITE} 🔍 Полный парсинг (все источники + папка proxies/)
  {Fore.GREEN}[2]{Fore.WHITE} ⚡ Перепроверка (сливает с базой, без дублей)
  {Fore.GREEN}[3]{Fore.WHITE} 📂 Инструкция: добавить свои прокси
  {Fore.GREEN}[4]{Fore.WHITE} 📊 Показать топ прокси
  {Fore.GREEN}[5]{Fore.WHITE} 📦 Только экспорт в расширение (без проверки)
  {Fore.GREEN}[6]{Fore.WHITE} 🗑️  Очистить все данные
  {Fore.GREEN}[0]{Fore.WHITE} 🚪 Выход{Style.RESET_ALL}""")


async def main():
    while True:
        print_menu()
        choice = input(f"\n{Fore.CYAN}  Выбор: {Style.RESET_ALL}").strip()
        if choice == '1':
            await run_full_parse()
        elif choice == '2':
            await run_quick_recheck()
        elif choice == '3':
            print(f"\n{Fore.WHITE}Положите файлы в {Fore.YELLOW}{MANUAL_PROXY_DIR}{Style.RESET_ALL}")
            print(f"  Форматы: ip:port | protocol://ip:port | protocol://user:pass@ip:port")
            print(f"  .txt — по строке на прокси; .json — массив строк/объектов.")
            print(f"  Затем запустите пункт 1.")
        elif choice == '4':
            show_top_proxies()
        elif choice == '5':
            export_only()
        elif choice == '6':
            clear_all_data()
        elif choice == '0':
            print(f"\n{Fore.CYAN}До свидания!{Style.RESET_ALL}\n")
            sys.exit(0)
        else:
            print(f"{Fore.RED}[!] Неверный выбор.{Style.RESET_ALL}")
        input(f"\n{Fore.WHITE}Enter для продолжения...{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Прервано.{Style.RESET_ALL}\n")
