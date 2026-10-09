/*
 * SwapIP — источники публичных прокси и нормализация форматов.
 *
 * Файл подключается в service worker через importScripts() и работает
 * как обычный скрипт, определяющий глобальные константы/функции.
 * Он сознательно не зависит от chrome.* API, чтобы его можно было
 * тестировать в Node.js (см. tools/test-sources.js).
 *
 * Поддерживаемые входные форматы строк:
 *   ip:port
 *   protocol://ip:port
 *   protocol://user:pass@ip:port
 *   ip:port:user:pass
 *   "ip:port http", "http ip port" (разделённые пробелами колонки списков)
 */

// Публичные источники для гибридного режима (когда кураторский список
// недоступен). Форматы: 'txt' — строки прокси; 'protocol' — протокол по умолчанию
// для строк без явного указания.
const DIRECT_SOURCES = [
  {
    name: 'Proxifly',
    url: 'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt',
    defaultProtocol: 'http'
  },
  {
    name: 'Monosans',
    url: 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt',
    defaultProtocol: 'http'
  },
  {
    name: 'TheSpeedX',
    url: 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
    defaultProtocol: 'http'
  },
  {
    name: 'Vakhov',
    url: 'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt',
    defaultProtocol: 'http'
  },
  {
    name: 'Sunny9577',
    url: 'https://sunny9577.github.io/proxy-scraper/proxies.txt',
    defaultProtocol: 'http'
  },
  {
    name: 'ProxyScrape API',
    url: 'https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
    defaultProtocol: 'http'
  }
];

// Лимит прокси, сохраняемых из прямых источников: chrome.storage.local
// в MV3 даёт ~10 МБ, но держать компактный список выгоднее по скорости
// сериализации service worker'а.
const DIRECT_MODE_MAX_PROXIES = 5000;

const PROXY_PROTOCOLS = new Set(['http', 'https', 'socks4', 'socks5']);

// Строгая проверка IPv4:port
const IPV4_PORT_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):(\d{1,5})$/;

function isValidIpv4(ip) {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  return m.slice(1).every((oct) => Number(oct) >= 0 && Number(oct) <= 255);
}

function isValidPort(port) {
  const n = Number(port);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}

/**
 * Нормализует одну строку прокси к виду protocol://[user:pass@]ip:port.
 * Возвращает null для мусора.
 */
function normalizeProxy(rawLine, defaultProtocol = 'http') {
  if (typeof rawLine !== 'string') return null;
  let s = rawLine.trim().replace(/["',;\t]+/g, ' ').trim();
  if (!s || s.startsWith('#') || s.startsWith('//')) return null;

  // protocol://[user:pass@]ip:port
  const urlMatch = s.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(?:([^:@\s]+):([^@\s]+)@)?([^:\s]+):(\d+)$/);
  if (urlMatch) {
    const [, proto, user, pass, host, port] = urlMatch;
    const protocol = proto.toLowerCase();
    if (!PROXY_PROTOCOLS.has(protocol)) return null;
    if (!isValidIpv4(host) || !isValidPort(port)) return null;
    return user && pass
      ? `${protocol}://${user}:${pass}@${host}:${port}`
      : `${protocol}://${host}:${port}`;
  }

  // ip:port:user:pass
  const fourParts = s.split(':');
  if (fourParts.length === 4) {
    const [ip, port, user, pass] = fourParts;
    if (isValidIpv4(ip) && isValidPort(port) && user && pass) {
      return `${defaultProtocol}://${user}:${pass}@${ip}:${port}`;
    }
  }

  // ip:port — возможно, с суффиксом/префиксом протокола ("1.2.3.4:8080 http")
  const loose = s.match(/^(?:(https?|socks[45])\s+)?(\d{1,3}(?:\.\d{1,3}){3})[:\s]+(\d{2,5})(?:\s+(https?|socks[45]))?$/i);
  if (loose) {
    const proto = (loose[1] || loose[4] || defaultProtocol).toLowerCase();
    const ip = loose[2];
    const port = loose[3];
    if (PROXY_PROTOCOLS.has(proto) && isValidIpv4(ip) && isValidPort(port)) {
      return `${proto}://${ip}:${port}`;
    }
  }

  // "http 1.2.3.4 8080" — ip и port разделены пробелом
  const spaced = s.match(/^(https?|socks[45])\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{2,5})$/i);
  if (spaced) {
    const proto = spaced[1].toLowerCase();
    const ip = spaced[2];
    const port = spaced[3];
    if (isValidIpv4(ip) && isValidPort(port)) {
      return `${proto}://${ip}:${port}`;
    }
  }

  return null;
}

/**
 * Парсит текстовый список (по одной записи на строку) в Set
 * нормализованных URL прокси.
 */
function parseProxyText(text, defaultProtocol = 'http') {
  const result = new Set();
  if (typeof text !== 'string') return result;
  for (const line of text.split(/\r?\n/)) {
    const normalized = normalizeProxy(line, defaultProtocol);
    if (normalized) result.add(normalized);
  }
  return result;
}

/**
 * Преобразует Set/массив нормализованных URL в компактные записи
 * внутреннего формата расширения: { p, l, c, n, a, i }.
 * l — задержка в мс (null — неизвестна), c/n — код и название страны,
 * a — уровень анонимности, i — провайдер.
 */
function toCompactEntries(urls, meta = {}) {
  const entries = [];
  for (const url of urls) {
    entries.push({
      p: url,
      l: meta.l ?? null,
      c: meta.c ?? '',
      n: meta.n ?? '',
      a: meta.a ?? 'unknown',
      i: meta.i ?? ''
    });
  }
  return entries;
}

// Экспорт для тестов в Node.js (в браузере файл просто определяет глобалы).
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    DIRECT_SOURCES,
    DIRECT_MODE_MAX_PROXIES,
    PROXY_PROTOCOLS,
    isValidIpv4,
    isValidPort,
    normalizeProxy,
    parseProxyText,
    toCompactEntries
  };
}
