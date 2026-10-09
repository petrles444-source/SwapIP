# -*- coding: utf-8 -*-
"""
Конфигурация анализатора прокси SwapIP.
Источники, таймауты, пути к файлам.
"""

import os

# --- Пути ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MANUAL_PROXY_DIR = os.path.join(BASE_DIR, "proxies")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MANUAL_PROXY_DIR, exist_ok=True)

# Файлы хранилища
RAW_PROXIES_FILE = os.path.join(DATA_DIR, "raw_proxies.txt")          # все спарсенные (до проверки)
VALID_PROXIES_FILE = os.path.join(DATA_DIR, "valid_proxies.json")     # рабочие (после проверки)
TOP_PROXIES_FILE = os.path.join(DATA_DIR, "top_proxies.json")         # топ по скорости
GEO_CACHE_FILE = os.path.join(DATA_DIR, "geo_cache.json")             # кэш гео (ip-api лимитирован)
EXTENSION_EXPORT_FILE = os.path.join(DATA_DIR, "extension_proxies.json")  # компактный экспорт

# Куда анализатор кладёт список, ВСТРОЕННЫЙ в расширение.
# После этого достаточно нажать «Обновить» в chrome://extensions —
# прокси уже будут внутри, без импорта и без анализатора у пользователя.
EXTENSION_DIR = os.path.normpath(os.path.join(BASE_DIR, "..", "extension"))
EXTENSION_DATA_DIR = os.path.join(EXTENSION_DIR, "data")
EXTENSION_BUNDLE_FILE = os.path.join(EXTENSION_DATA_DIR, "proxies.json")

# --- Источники прокси ---
PROXY_SOURCES = [
    {
        "name": "ProxyScrape (GitHub CDN)",
        "url": "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/all/data.txt",
        "format": "txt",
        "protocol": "http",
    },
    {
        "name": "Proxifly",
        "url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
        "format": "txt",
        "protocol": "http",
    },
    {
        "name": "MuRongPIG Proxy-Master",
        "url": "https://cdn.jsdelivr.net/gh/MuRongPIG/Proxy-Master@main/http.txt",
        "format": "txt",
        "protocol": "http",
    },
    {
        # Вместо мёртвого gfpcom/free-proxy-list (репозиторий удалён, отдавал 404)
        "name": "ErcinDedeoglu",
        "url": "https://cdn.jsdelivr.net/gh/ErcinDedeoglu/proxies@main/proxies/http.txt",
        "format": "txt",
        "protocol": "http",
    },
    {
        "name": "clarketm",
        "url": "https://cdn.jsdelivr.net/gh/clarketm/proxy-list@master/proxy-list-raw.txt",
        "format": "txt",
        "protocol": "http",
    },
    {
        "name": "TheSpeedX",
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "format": "txt",
        "protocol": "http",
    },
    {
        "name": "Monosans",
        "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
        "format": "txt",
        "protocol": "http",
    },
    {
        "name": "Vakhov",
        "url": "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
        "format": "txt",
        "protocol": "http",
    },
    {
        "name": "Stormsia",
        "url": "https://sunny9577.github.io/proxy-scraper/proxies.txt",
        "format": "txt",
        "protocol": "http",
    },
    {
        "name": "TheRiturajPS",
        "url": "https://raw.githubusercontent.com/theriturajps/proxy-list/main/proxies.txt",
        "format": "txt",
        "protocol": "http",
    },
    {
        "name": "ProxyScrape API",
        "url": "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
        "format": "txt",
        "protocol": "http",
    },
]

# --- Параметры проверки ---
# Таймаут на ОДИН прокси целиком (на все эндпоинты сразу), а не на каждый.
# Раньше каждый эндпоинт получал полный таймаут, и мёртвый адрес мог
# занимать 3 × 10 = 30 секунд. Теперь общий бюджет на прокси.
#
# Замерен на 220 реальных адресах: 10 с → 120 мин на пул в 139 000,
# 5 с → 57 мин, качество при этом почти не теряется (33 против 46 принятых).
# 5 секунд — разумный компромисс: медленный прокси всё равно бесполезен
# в браузере, а проверять 139 тысяч адресов по 10 секунд каждый слишком долго.
# Если нужен максимум качества — поставь 8.
CHECK_TIMEOUT = 5               # сек

# Отсев по скорости. None — НЕ отсеивать по скорости вовсе (по умолчанию).
#
# Почему по умолчанию выключено. Замер на реальных прокси из пула:
# медиана 4 000 мс, и только 1 из 40 быстрее 500 мс. При жёстком пороге
# список выходит пустым — это и случилось: прогон дал 0 из 139 373,
# хотя прокси были живые (9 из 40 отвечали при проверке без отсева).
#
# Бесплатные прокси объективно медленные: это домашние роутеры и VPS с
# чужой нагрузкой. Отсеивать их по скорости — значит оставлять пустой
# список. Если нужен именно быстрый список — поставь 3000–5000, но
# будь готов, что прокси останется мало.
#
# Проверяется тестом tools/test-latency-threshold.py.
MAX_ACCEPTABLE_LATENCY_MS = None   # мс; число — отсеивать медленнее; 0/None — не отсеивать

MAX_CONCURRENT_CHECKS = 500     # максимум одновременных проверок

# Проверка идёт по HTTPS: это ключевой фильтр. HTTP-прокси без поддержки
# CONNECT не умеет пробрасывать HTTPS — Chrome на таком выдаёт
# ERR_CONNECTION_CLOSED. HTTPS-запрос через прокси заодно вскрывает
# MITM-подмену сертификата (NETERR_CERT_AUTHORITY_INVALID).
TEST_URL = "https://api.ipify.org/?format=json"

# Запасные HTTPS-эндпоинты: если первый недоступен (сам api.ipify.org бывает
# недоступен из ряда стран), пробуем следующий.
TEST_URL_FALLBACKS = [
    "https://ipinfo.io/json",
    "https://api.ip.sb/geoip",
]

# Требовать ли HTTPS. Выключать только ради экспериментов: без HTTPS
# расширение будет ронять сеть на любом защищённом сайте.
REQUIRE_HTTPS = True

# Сколько успешных запросов подряд делаем, чтобы принять прокси.
# Один «удачный» ответ у мусорного прокси — часто ложное срабатывание.
STABILITY_CHECKS = 2
STABILITY_DELAY = 0.3           # пауза между проверками стабильности, сек

# --- Параметры гео/анонимности ---
GEO_MAX_CONCURRENT = 10         # ip-api.com: лимит 45 запросов/мин

# Геолокацию всех прокси по умолчанию НЕ делаем.
# Причина практическая: ip-api.com отдаёт 45 запросов в минуту, поэтому на
# тысяче прокси геолокация растягивается на 20+ минут и упирается в лимит.
# Вместо этого страна определяется двумя способами:
#   * расширение показывает страну сразу после подключения (по реальному
#     выходному IP — это точнее, чем гео адреса прокси);
#   * в списке серверов есть кнопка «📍» — узнать страну конкретного
#     прокси по запросу, без проверки всех разом.
ANONYMITY_CHECK = True
GEO_CHECK = False
# Анонимность проверяем только для тех, что уже прошли HTTPS — это дорого.
ANONYMITY_LIMIT = 300

# --- Параметры парсинга ---
MAX_PROXIES_PER_SOURCE = 50000  # лимит на источник

# Сколько прокси максимум отдаём в расширение (файл не должен разрастаться).
EXPORT_LIMIT = 2000

# --- Слияние при повторной проверке ---
# Не выбрасывать старые записи, которые не попали в новый результат.
MERGE_KEEP_OLD = True

# Сколько дней прокси, который недавно работал, но не попал в свежую
# выдачу источников, ещё считается живым.
#
# Почему это важно: публичные списки прокси постоянно ротируются. Адрес,
# который работал вчера, может просто отсутствовать в сегодняшней выдаче —
# это не значит, что он умер. Без этого допуска каждый новый прогон стирал
# бы часть предыдущего результата, и список только уменьшался бы
# (наблюдалось: 222 -> 58 за один прогон).
GRACE_PERIOD_DAYS = 14
