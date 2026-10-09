/*
 * SwapIP — service worker (Manifest V3).
 *
 * Обязанности:
 *   1. Загрузка списка прокси (встроенный → URL → прямые источники).
 *   2. Управление прокси браузера через PAC-скрипты + защита от WebRTC-утечек.
 *   3. Проверка кандидатов ДО включения (режим trial) и автоматический failover.
 *   4. Сторож: автоснятие мёртвого прокси + самовосстановление после
 *      перезапуска браузера (главная защита от «сеть легла до переустановки»).
 *   5. Ответы на сообщения popup и страницы настроек.
 *
 * КЛЮЧЕВОЕ ОТЛИЧИЕ ОТ ПРЕЖНЕЙ ВЕРСИИ
 * -----------------------------------
 * Раньше прокси включался глобально и ТОГДА проверялся. Мёртвый прокси
 * мгновенно ронял весь браузер, а если service worker успевал зависнуть —
 * настройка оставалась в Chrome навсегда (chrome.proxy переживает перезапуск
 * браузера), и сеть «оживала» только после удаления расширения.
 *
 * Теперь проверка идёт через PAC в режиме trial: через прокси направляется
 * ТОЛЬКО один запрос-зонд, весь остальной трафик идёт напрямую. Поэтому
 * нерабочий кандидат не влияет на сеть вообще.
 */

importScripts('lib/sources.js');

// ============ КОНСТАНТЫ ============

const STORAGE_KEYS = {
  PROXIES: 'proxies',               // массив {p,l,c,n,a,i,https}
  ENABLED: 'enabled',               // bool — прокси включён
  CONNECTING: 'connecting',         // bool — идёт попытка подключения
  CONNECT_PROGRESS: 'connectProgress', // {i,total,current} — для popup
  CANCEL: 'cancelConnect',          // bool — запрос отмены
  APPLIED: 'appliedProxy',          // что реально применено в chrome.proxy
  BASE_IP: 'baseIp',                // реальный IP без прокси (детектор fallback'а)
  ACTIVE_META: 'activeMeta',        // метаданные активного прокси
  LAST_UPDATE: 'lastUpdate',        // ISO-время последнего обновления списка
  LIST_SOURCE: 'listSource',        // 'bundled' | 'remote' | 'direct' | 'import'
  SELECTED_COUNTRY: 'selectedCountry',
  SETTINGS: 'settings',             // {listUrl, mode, testTimeoutMs, failSafe, allowHttpOnly}
  STATS: 'stats',                   // {url: {f,s,t}} — счётчики успеха/провала
  CONSEC_FAILS: 'consecFails',      // подряд идущие неудачные проверки
  LICENSE: 'license'                // {key, valid, activatedAt} — задел под PRO
};

const DEFAULT_SETTINGS = {
  listUrl: '',          // пусто → встроенный список, затем прямые источники
  mode: 'auto',         // 'auto' | 'bundled' | 'remote' | 'direct'
  testTimeoutMs: 10000,
  failSafe: true,       // PAC: PROXY x; DIRECT — сеть не лежит никогда
  allowHttpOnly: false  // разрешать прокси без CONNECT (почти всегда ломает HTTPS)
};

// Эндпоинты проверки. Все — HTTPS: только так можно отсечь прокси без
// CONNECT и MITM-прокси, из-за которых Chrome показывает
// ERR_CONNECTION_CLOSED и NETERR_CERT_AUTHORITY_INVALID.
const PROBE_ENDPOINTS = [
  { url: 'https://ipwho.is/', json: true },
  { url: 'https://ipinfo.io/json', json: true },
  { url: 'https://api.ip.sb/geoip', json: true },
  { url: 'https://api.ipify.org/?format=json', json: true }
];

// Хосты, которые PAC направляет через прокси в режиме trial.
const PROBE_HOSTS = ['ipwho.is', 'ipinfo.io', 'api.ip.sb', 'api.ipify.org'];

// Встроенный список, который готовит Python-анализатор (extension/data/proxies.json).
const BUNDLED_LIST_PATH = 'data/proxies.json';

const ALARM_REFRESH = 'swapip_refreshList';   // обновление списка, раз в 6 ч
const ALARM_HEALTH = 'swapip_healthCheck';    // контроль активного прокси, раз в 1 мин
const ALARM_WATCHDOG = 'swapip_watchdog';     // страховка от «осиротевшего» прокси

const CONNECT_TRIES = {
  bundled: 6,   // список уже проверен анализатором
  remote: 6,
  import: 6,
  direct: 10    // прямые списки не проверены — пробуем больше кандидатов
};

// Сколько подряд неудачных проверок терпим, прежде чем снять прокси.
const FAIL_THRESHOLD = 2;

// ============ УТИЛИТЫ ============

function log(...args) {
  console.log('[SwapIP]', ...args);
}

async function storageGet(keys) {
  return chrome.storage.local.get(keys);
}

async function storageSet(obj) {
  return chrome.storage.local.set(obj);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============ НАСТРОЙКИ / ЛИЦЕНЗИЯ ============

async function getSettings() {
  const { [STORAGE_KEYS.SETTINGS]: s } = await storageGet(STORAGE_KEYS.SETTINGS);
  return { ...DEFAULT_SETTINGS, ...(s || {}) };
}

async function getLicense() {
  const { [STORAGE_KEYS.LICENSE]: lic } = await storageGet(STORAGE_KEYS.LICENSE);
  return { key: '', valid: false, activatedAt: null, ...(lic || {}) };
}

function isValidLicenseKey(key) {
  return /^SWIP-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/i.test(String(key || '').trim());
}

// ============ РАЗБОР URL ПРОКСИ ============

/** Разбирает protocol://[user:pass@]host:port в объект. */
function parseProxyUrl(proxyUrl) {
  if (typeof proxyUrl !== 'string') return null;
  const m = proxyUrl.trim().match(
    /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(?:([^:@\s]+):([^@\s]+)@)?([^:\s]+):(\d{1,5})$/
  );
  if (!m) return null;
  const [, protocol, username, password, host, port] = m;
  const scheme = ['http', 'https', 'socks4', 'socks5'].includes(protocol.toLowerCase())
    ? protocol.toLowerCase()
    : 'http';
  const portNum = parseInt(port, 10);
  if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) return null;
  const out = { scheme, host, port: portNum };
  if (username && password) {
    out.username = username;
    out.password = password;
  }
  return out;
}

/** Схема для chrome.proxy: socks4 в API не поддерживается, отдаём как socks4 в PAC. */
function pacToken(p) {
  if (p.scheme === 'socks5') return `SOCKS5 ${p.host}:${p.port}`;
  if (p.scheme === 'socks4') return `SOCKS4 ${p.host}:${p.port}`;
  if (p.scheme === 'https') return `HTTPS ${p.host}:${p.port}`;
  return `PROXY ${p.host}:${p.port}`;
}

/**
 * Строит PAC-скрипт.
 *
 * trial=true  → через прокси уходит ТОЛЬКО запрос-зонд, весь остальной
 *               трафик идёт напрямую. Так проверка кандидата не может
 *               уронить сеть пользователя.
 * trial=false → весь трафик идёт через прокси; при failSafe добавляется
 *               запасной маршрут DIRECT, чтобы браузер не остался без сети.
 */
function buildPacScript(parsed, trial, failSafe) {
  const hosts = PROBE_HOSTS.map((h) => JSON.stringify(h)).join(',');
  return [
    `var SWAPIP_PROXY = ${JSON.stringify(pacToken(parsed))};`,
    `var SWAPIP_PROBE_HOSTS = [${hosts}];`,
    `var SWAPIP_TRIAL = ${trial ? 'true' : 'false'};`,
    `var SWAPIP_FAILSAFE = ${failSafe ? 'true' : 'false'};`,
    '',
    'function FindProxyForURL(url, host) {',
    '  host = ("" + host).toLowerCase();',
    '  if (isPlainHostName(host)) return "DIRECT";',
    '  if (host === "localhost" || host === "127.0.0.1" || host === "::1" ||',
    '      shExpMatch(host, "*.local") || shExpMatch(host, "*.localhost")) return "DIRECT";',
    '  for (var i = 0; i < SWAPIP_PROBE_HOSTS.length; i++) {',
    '    if (host === SWAPIP_PROBE_HOSTS[i]) return SWAPIP_PROXY;',
    '  }',
    // В trial-режиме всё, кроме зонда, идёт напрямую — иначе проверяемый
    // прокси действительно сломал бы пользователю интернет.
    '  if (SWAPIP_TRIAL) return "DIRECT";',
    '  return SWAPIP_FAILSAFE ? (SWAPIP_PROXY + "; DIRECT") : SWAPIP_PROXY;',
    '}',
    ''
  ].join('\n');
}

// ============ УПРАВЛЕНИЕ ПРОКСИ БРАУЗЕРА ============

/**
 * Применяет прокси. mode: 'trial' (проверка, трафик мимо) | 'active' (весь трафик).
 * Всегда фиксирует APPLIED, чтобы watchdog знал, что именно мы включили.
 */
async function applyProxyConfig(proxyUrl, mode = 'active', failSafe = true) {
  const parsed = parseProxyUrl(proxyUrl);
  if (!parsed) throw new Error(`Неверный формат прокси: ${proxyUrl}`);

  const pacScript = {
    data: buildPacScript(parsed, mode === 'trial', failSafe),
    mandatory: true
  };

  await chrome.proxy.settings.set({
    value: { mode: 'pac_script', pacScript },
    scope: 'regular'
  });
  await storageSet({ [STORAGE_KEYS.APPLIED]: { proxyUrl, mode, failSafe } });
}

/** Читает фактическую конфигурацию прокси в браузере. */
async function getAppliedBrowserProxy() {
  try {
    const cfg = await chrome.proxy.settings.get({ scope: 'regular' });
    return cfg && cfg.value ? cfg.value : null;
  } catch {
    return null;
  }
}

/** Включает защиту от WebRTC-утечки реального IP. */
async function enableWebRTCGuard() {
  try {
    await chrome.privacy.network.webRTCIPHandlingPolicy.set({
      value: 'disable_non_proxied_udp'
    });
  } catch (err) {
    log('privacy API недоступен:', err.message);
  }
}

/** Полностью снимает прокси и возвращает настройки WebRTC. */
async function clearProxy() {
  await chrome.proxy.settings.clear({ scope: 'regular' });
  try {
    await chrome.privacy.network.webRTCIPHandlingPolicy.clear({});
  } catch (err) {
    log('privacy API недоступен:', err.message);
  }
  await storageSet({
    [STORAGE_KEYS.ENABLED]: false,
    [STORAGE_KEYS.ACTIVE_META]: null,
    [STORAGE_KEYS.CONSEC_FAILS]: 0,
    [STORAGE_KEYS.APPLIED]: null,
    [STORAGE_KEYS.CONNECTING]: false,
    [STORAGE_KEYS.CONNECT_PROGRESS]: null,
    [STORAGE_KEYS.CANCEL]: false
  });
  await updateBadge(false);
}

/**
 * Аварийный сброс: снимает прокси в браузере, что бы ни думало наше хранилище.
 * Именно это нужно, когда сеть уже легла и обычные кнопки не работают.
 */
async function emergencyReset() {
  let browserCleared = false;
  try {
    await chrome.proxy.settings.clear({ scope: 'regular' });
    browserCleared = true;
  } catch (err) {
    log('Аварийный сброс: не удалось снять прокси:', err.message);
  }
  try {
    await chrome.privacy.network.webRTCIPHandlingPolicy.clear({});
  } catch { /* не критично */ }
  await storageSet({
    [STORAGE_KEYS.ENABLED]: false,
    [STORAGE_KEYS.ACTIVE_META]: null,
    [STORAGE_KEYS.CONSEC_FAILS]: 0,
    [STORAGE_KEYS.APPLIED]: null,
    [STORAGE_KEYS.CONNECTING]: false,
    [STORAGE_KEYS.CONNECT_PROGRESS]: null,
    [STORAGE_KEYS.CANCEL]: false
  });
  await updateBadge(false);
  return { ok: true, browserCleared };
}

/**
 * Сверяет состояние расширения с состоянием браузера.
 *
 * Настройки chrome.proxy переживают перезапуск браузера и перезапуск
 * service worker'а. Если мы «забыли» включить прокси, а в браузере он
 * остался — сеть лежит, а UI показывает «Отключено». Именно это и было
 * причиной «сеть в браузере заблокирована, пока не удалишь расширение».
 */
async function reconcileProxyState(reason) {
  const { [STORAGE_KEYS.ENABLED]: enabled } = await storageGet(STORAGE_KEYS.ENABLED);
  const { [STORAGE_KEYS.APPLIED]: applied } = await storageGet(STORAGE_KEYS.APPLIED);
  const browser = await getAppliedBrowserProxy();
  const browserActive = !!browser && browser.mode !== 'system' && browser.mode !== 'direct';

  if (!browserActive) {
    if (applied || enabled) {
      log(`Сверка (${reason}): в браузере прокси нет — сбрасываю состояние`);
      await storageSet({
        [STORAGE_KEYS.ENABLED]: false,
        [STORAGE_KEYS.ACTIVE_META]: null,
        [STORAGE_KEYS.APPLIED]: null,
        [STORAGE_KEYS.CONSEC_FAILS]: 0
      });
      await updateBadge(false);
    }
    return { ok: true, changed: false };
  }

  if (!enabled || !applied) {
    log(`Сверка (${reason}): в браузере прокси есть, а расширение считает себя выключенным — снимаю`);
    await emergencyReset();
    return { ok: true, changed: true, cleared: true };
  }

  return { ok: true, changed: false };
}

// ============ ЗАГРУЗКА СПИСКА ПРОКСИ ============

function sanitizeEntries(rawProxies) {
  const out = [];
  if (!Array.isArray(rawProxies)) return out;
  const seen = new Set();
  for (const item of rawProxies) {
    let p = null;
    let meta = {};
    if (typeof item === 'string') {
      p = normalizeProxy(item);
    } else if (item && typeof item === 'object' && typeof item.p === 'string') {
      p = normalizeProxy(item.p);
      meta = item;
    }
    if (!p || seen.has(p)) continue;
    seen.add(p);
    out.push({
      p,
      l: Number.isFinite(meta.l) && meta.l > 0 ? Math.round(meta.l) : null,
      c: typeof meta.c === 'string' ? meta.c.slice(0, 2).toUpperCase() : '',
      n: typeof meta.n === 'string' ? meta.n.slice(0, 40) : '',
      a: typeof meta.a === 'string' ? meta.a.slice(0, 16) : 'unknown',
      i: typeof meta.i === 'string' ? meta.i.slice(0, 30) : '',
      https: meta.https !== false
    });
  }
  return out;
}

/**
 * Загружает встроенный список из пакета расширения (data/proxies.json).
 * Его кладёт Python-анализатор: после «Обновить» в chrome://extensions
 * прокси уже внутри — пользователю не нужен ни импорт, ни анализатор.
 * staleAfterHours > 0 — список считается протухшим (в `auto` это включает
 * добор свежих прокси из публичных источников).
 */
async function fetchBundledList(staleAfterHours = 0) {
  const url = chrome.runtime.getURL(BUNDLED_LIST_PATH);
  const resp = await fetch(url, { cache: 'no-store' });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  const data = await resp.json();
  const proxies = sanitizeEntries(data && data.proxies);
  if (proxies.length === 0) throw new Error('Встроенный список пуст');

  const updated = data.updated || new Date().toISOString();
  const ageHours = (Date.now() - new Date(updated).getTime()) / 3600000;
  const stale = Number.isFinite(ageHours) && staleAfterHours > 0 && ageHours > staleAfterHours;

  await storageSet({
    [STORAGE_KEYS.PROXIES]: proxies,
    [STORAGE_KEYS.LAST_UPDATE]: updated,
    [STORAGE_KEYS.LIST_SOURCE]: 'bundled'
  });
  log(`Встроенный список: ${proxies.length} прокси${stale ? ` (протух на ${Math.round(ageHours)} ч)` : ''}`);
  return { count: proxies.length, stale };
}

/** Сколько часов встроенный список считается свежим. */
const BUNDLED_STALE_HOURS = 24;

/** Загружает кураторский список по URL (формат анализатора). */
async function fetchRemoteList(listUrl) {
  const resp = await fetch(listUrl, { cache: 'no-store' });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  const data = await resp.json();
  const proxies = sanitizeEntries(data && data.proxies);
  if (proxies.length === 0) throw new Error('Список пуст или формат неверен');
  await storageSet({
    [STORAGE_KEYS.PROXIES]: proxies,
    [STORAGE_KEYS.LAST_UPDATE]: data.updated || new Date().toISOString(),
    [STORAGE_KEYS.LIST_SOURCE]: 'remote'
  });
  log(`Кураторский список: ${proxies.length} прокси`);
  return proxies.length;
}

/** Загружает и объединяет прямые публичные списки. */
async function fetchDirectList() {
  const seen = new Set();
  let fetchedAny = false;

  const results = await Promise.allSettled(DIRECT_SOURCES.map(async (src) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 15000);
    try {
      const resp = await fetch(src.url, { cache: 'no-store', signal: ctrl.signal });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const text = await resp.text();
      return { src, set: parseProxyText(text, src.defaultProtocol) };
    } finally {
      clearTimeout(timer);
    }
  }));

  for (const res of results) {
    if (res.status !== 'fulfilled' || res.value.set.size === 0) continue;
    fetchedAny = true;
    for (const url of res.value.set) {
      if (seen.size >= DIRECT_MODE_MAX_PROXIES) break;
      seen.add(url);
    }
  }

  if (!fetchedAny) throw new Error('Все прямые источники недоступны');

  const proxies = toCompactEntries(seen, {});
  for (let i = proxies.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [proxies[i], proxies[j]] = [proxies[j], proxies[i]];
  }

  await storageSet({
    [STORAGE_KEYS.PROXIES]: proxies,
    [STORAGE_KEYS.LAST_UPDATE]: new Date().toISOString(),
    [STORAGE_KEYS.LIST_SOURCE]: 'direct'
  });
  log(`Прямые источники: ${proxies.length} прокси (уникальных)`);
  return proxies.length;
}

/**
 * Обновляет список по режиму. Пробуем в порядке убывания качества и
 * всегда снимаем прокси на время загрузки — мёртвый прокси иначе не даст
 * нам скачать собственный список.
 */
async function refreshList() {
  const settings = await getSettings();
  const { [STORAGE_KEYS.PROXIES]: hadProxies } = await storageGet(STORAGE_KEYS.PROXIES);
  const { [STORAGE_KEYS.ENABLED]: enabled } = await storageGet(STORAGE_KEYS.ENABLED);
  const { [STORAGE_KEYS.APPLIED]: applied } = await storageGet(STORAGE_KEYS.APPLIED);

  const steps = [];
  if (settings.mode === 'remote') {
    if (!settings.listUrl) throw new Error('Режим «только кураторский», но URL не задан');
    steps.push(() => fetchRemoteList(settings.listUrl));
  } else if (settings.mode === 'bundled') {
    steps.push(() => fetchBundledList());
  } else if (settings.mode === 'direct') {
    steps.push(fetchDirectList);
  } else {
    // auto: URL → встроенный → прямые источники.
    if (settings.listUrl) steps.push(() => fetchRemoteList(settings.listUrl));
    // Встроенный список — снимок на момент его сбора. Как только он
    // протухает (а он почти протухает мгновенно: публичные прокси живут
    // минутами), подключаем прямые источники, иначе список устареет навсегда.
    steps.push(
      () => fetchBundledList(BUNDLED_STALE_HOURS),
      fetchDirectList
    );
  }

  const wasActive = enabled && applied;
  if (wasActive) await chrome.proxy.settings.clear({ scope: 'regular' });

  const errors = [];
  try {
    for (const step of steps) {
      try {
        const res = await step();
        // fetchBundledList возвращает {count, stale}; остальные — число.
        const count = typeof res === 'number' ? res : res.count;
        if (res && typeof res === 'object' && res.stale) {
          log('Встроенный список протух — добираю прокси из публичных источников');
          continue;
        }
        return count;
      } catch (err) {
        log('Источник списка недоступен:', err.message);
        errors.push(err.message);
      }
    }
    if (!wasActive && hadProxies && hadProxies.length) {
      log('Обновление не удалось, оставляю прежний список');
      return hadProxies.length;
    }
    throw new Error(errors[0] || 'Не удалось загрузить список прокси');
  } finally {
    if (wasActive && applied) {
      try {
        await applyProxyConfig(applied.proxyUrl, applied.mode, applied.failSafe);
      } catch (err) {
        log('Не удалось вернуть прокси после обновления списка:', err.message);
      }
    }
  }
}

// ============ ПРОВЕРКА ПРОКСИ ============

function extractIp(data) {
  if (!data || typeof data !== 'object') return '';
  for (const key of ['ip', 'query', 'origin']) {
    const value = data[key];
    if (typeof value === 'string' && value.trim()) return value.trim().split(',')[0].trim();
  }
  return '';
}

async function fetchJson(url, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  const t0 = performance.now();
  try {
    const resp = await fetch(url, { cache: 'no-store', signal: ctrl.signal });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const ms = Math.round(performance.now() - t0);
    const data = await resp.json().catch(() => null);
    const ip = extractIp(data);
    if (!ip) throw new Error('bad payload');
    return {
      ok: true,
      ip,
      ms,
      country: typeof data.country === 'string' ? data.country.slice(0, 2).toUpperCase()
        : (typeof data.country_code === 'string' ? data.country_code.slice(0, 2).toUpperCase() : ''),
      countryName: typeof data.country_name === 'string' ? data.country_name.slice(0, 40)
        : (typeof data.country === 'string' && data.country.length > 2 ? data.country.slice(0, 40) : '')
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Проверяет соединение через ТЕКУЩУЮ конфигурацию прокси.
 * Только HTTPS-эндпоинты: прокси без CONNECT для нас бесполезен.
 *
 * Уложена в общий бюджет времени (timeoutMs). Без этого один мёртвый
 * кандидат съедал бы 4 × 8 = 32 секунды, а десять кандидатов — пять минут,
 * в течение которых popup выглядит «зависшим». Проверяем первый эндпоинт
 * с полным таймаутом, остальные — с коротким: если первый не ответил,
 * скорее всего не ответит и второй.
 */
async function probeCurrentProxy(timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  let lastError = 'нет ответа';

  for (let i = 0; i < PROBE_ENDPOINTS.length; i++) {
    const left = deadline - Date.now();
    if (left <= 1000) break;
    // Первому эндпоинту — почти весь бюджет: если он не ответил, скорее
    // всего не ответит и второй. Остальным — остаток, но не больше 4 с.
    const budget = i === 0 ? left : Math.min(left, 4000);
    const ep = PROBE_ENDPOINTS[i];
    try {
      const res = await fetchJson(ep.url, budget);
      return { ok: true, ...res };
    } catch (err) {
      lastError = String((err && err.message) || err);
    }
  }
  return { ok: false, error: lastError };
}

/** Замеряет реальный IP при ПРЯМОМ соединении (нужен для детектора fallback'а). */
async function probeDirect() {
  return probeCurrentProxy(8000).then((r) => (r.ok ? r.ip : null));
}

// Сервис геокодирования по IP. Используется только по запросу пользователя
// (кнопка «📍»), а не для всех прокси сразу: у бесплатных сервисов есть лимиты,
// и прогон по тысяче адресов занимал бы десятки минут.
const GEO_URLS = ['https://ipwho.is/'];

/**
 * Определяет страну и провайдера по IP-адресу.
 * ВАЖНО: адрес — это сам прокси, а не наш выход. Мы НЕ подключаемся к нему,
 * поэтому чужие страницы не грузятся, слот не занимается и ответ приходит
 * за ~200 мс вместо секунд ожидания CONNECT.
 */
async function lookupGeo(ip, timeoutMs = 6000) {
  let lastError = 'нет ответа';
  for (const base of GEO_URLS) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const resp = await fetch(base + encodeURIComponent(ip), {
        cache: 'no-store',
        signal: ctrl.signal
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      if (!data || data.success === false) throw new Error('нет данных');
      return {
        country: typeof data.country_code === 'string' ? data.country_code.toUpperCase().slice(0, 2) : '',
        countryName: typeof data.country === 'string' ? data.country.slice(0, 40) : '',
        isp: String((data.connection && data.connection.isp) || '').slice(0, 30)
      };
    } catch (err) {
      lastError = String((err && err.message) || err);
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error(lastError);
}

// ============ СТАТИСТИКА И ВЫБОР КАНДИДАТА ============

async function getStats() {
  const { [STORAGE_KEYS.STATS]: stats } = await storageGet(STORAGE_KEYS.STATS);
  return stats || {};
}

async function recordStat(url, success) {
  const stats = await getStats();
  const cur = stats[url] || { f: 0, s: 0, t: 0 };
  if (success) {
    cur.s += 1;
    cur.f = 0;
  } else {
    cur.f += 1;
  }
  cur.t = Date.now();
  stats[url] = cur;

  const keys = Object.keys(stats);
  if (keys.length > 3000) {
    keys.sort((a, b) => stats[a].t - stats[b].t);
    for (const k of keys.slice(0, keys.length - 3000)) delete stats[k];
  }
  await storageSet({ [STORAGE_KEYS.STATS]: stats });
}

/**
 * Выбирает кандидата: фильтр по стране и по HTTPS-поддержке, штраф за
 * прошлые отказы, случайный выбор из топа (чтобы не перегружать сервер).
 */
function pickBestProxy(proxies, countryCode, excluded, stats, allowHttpOnly) {
  let pool = proxies;
  if (countryCode) {
    const filtered = proxies.filter((e) => e.c === countryCode);
    if (filtered.length) pool = filtered;
  }
  // Прокси без CONNECT ломают HTTPS — не пускаем их в ход, если явно
  // не разрешено пользователем в настройках.
  if (!allowHttpOnly) pool = pool.filter((e) => e.https !== false);
  pool = pool.filter((e) => !excluded.has(e.p));
  if (pool.length === 0) return null;

  const score = (e) => {
    const st = stats && stats[e.p];
    const base = Number.isFinite(e.l) && e.l > 0 ? e.l : 2000;
    const fails = st ? st.f : 0;
    const succ = st ? Math.min(st.s, 10) : 0;
    const noHttps = e.https === false ? 5000 : 0;
    return base + fails * 800 - succ * 50 + noHttps;
  };

  pool = pool.slice().sort((a, b) => score(a) - score(b));
  const topN = pool.slice(0, Math.min(5, pool.length));
  return topN[Math.floor(Math.random() * topN.length)];
}

function getCountryStats(proxies) {
  const stats = {};
  for (const p of proxies) {
    const code = p.c || '';
    if (!code) continue;
    if (!stats[code]) {
      stats[code] = { code, name: p.n || code, count: 0, bestLatency: Infinity };
    }
    stats[code].count += 1;
    if (Number.isFinite(p.l) && p.l < stats[code].bestLatency) {
      stats[code].bestLatency = p.l;
    }
  }
  return Object.values(stats)
    .map((s) => ({ ...s, bestLatency: Number.isFinite(s.bestLatency) ? s.bestLatency : null }))
    .sort((a, b) => (a.bestLatency ?? 99999) - (b.bestLatency ?? 99999));
}

// ============ ПОДКЛЮЧЕНИЕ / ОТКЛЮЧЕНИЕ ============

async function updateBadge(enabled, connecting) {
  try {
    let text = '';
    let color = '#22c55e';
    if (connecting) {
      text = '…';
      color = '#eab308';
    } else if (enabled) {
      text = 'ON';
    }
    await chrome.action.setBadgeText({ text });
    await chrome.action.setBadgeBackgroundColor({ color });
  } catch (err) {
    log('badge API:', err.message);
  }
}

async function isCancelled() {
  const { [STORAGE_KEYS.CANCEL]: c } = await storageGet(STORAGE_KEYS.CANCEL);
  return !!c;
}

async function updateMeasuredLatency(proxyUrl, ms) {
  const { [STORAGE_KEYS.PROXIES]: proxies } = await storageGet(STORAGE_KEYS.PROXIES);
  if (!Array.isArray(proxies)) return;
  const idx = proxies.findIndex((e) => e.p === proxyUrl);
  if (idx === -1) return;
  if (proxies[idx].l === ms) return;
  proxies[idx] = { ...proxies[idx], l: ms };
  await storageSet({ [STORAGE_KEYS.PROXIES]: proxies });
}

/**
 * Подключение. Ключевое отличие от прошлой версии: кандидат сначала
 * проверяется в режиме trial (через прокси идёт только зонд, сеть
 * пользователя не затрагивается), и лишь потом включается глобально.
 */
async function connect(countryCode) {
  const { [STORAGE_KEYS.CONNECTING]: already } = await storageGet(STORAGE_KEYS.CONNECTING);
  if (already) return { ok: false, error: 'Подключение уже выполняется' };

  await storageSet({
    [STORAGE_KEYS.CONNECTING]: true,
    [STORAGE_KEYS.CANCEL]: false,
    [STORAGE_KEYS.CONNECT_PROGRESS]: { i: 0, total: 0, current: '' }
  });
  await updateBadge(false, true);

  const finish = async () => {
    await storageSet({
      [STORAGE_KEYS.CONNECTING]: false,
      [STORAGE_KEYS.CANCEL]: false,
      [STORAGE_KEYS.CONNECT_PROGRESS]: null
    });
  };

  try {
    let { [STORAGE_KEYS.PROXIES]: proxies } = await storageGet(STORAGE_KEYS.PROXIES);
    if (!proxies || proxies.length === 0) {
      log('Список пуст — обновляю перед подключением');
      try {
        await refreshList();
      } catch (err) {
        return { ok: false, error: 'Не удалось получить список прокси: ' + err.message };
      }
      ({ [STORAGE_KEYS.PROXIES]: proxies } = await storageGet(STORAGE_KEYS.PROXIES));
      if (!proxies || proxies.length === 0) {
        return { ok: false, error: 'Список прокси пуст' };
      }
    }

    const { [STORAGE_KEYS.LIST_SOURCE]: source } = await storageGet(STORAGE_KEYS.LIST_SOURCE);
    const settings = await getSettings();
    const stats = await getStats();
    const excluded = new Set();
    const maxTries = CONNECT_TRIES[source] || CONNECT_TRIES.direct;

    for (let i = 0; i < maxTries; i++) {
      if (await isCancelled()) {
        await chrome.proxy.settings.clear({ scope: 'regular' });
        return { ok: false, error: 'Отменено', cancelled: true };
      }

      const candidate = pickBestProxy(proxies, countryCode, excluded, stats, settings.allowHttpOnly);
      if (!candidate) break;
      excluded.add(candidate.p);

      await storageSet({
        [STORAGE_KEYS.CONNECT_PROGRESS]: { i: i + 1, total: maxTries, current: candidate.p }
      });

      // --- ФАЗА 1: ПРОВЕРКА. Через прокси идёт только зонд. ---
      let probe;
      try {
        await applyProxyConfig(candidate.p, 'trial', settings.failSafe);
        probe = await probeCurrentProxy(settings.testTimeoutMs);
      } catch (err) {
        log('Не удалось применить trial-конфигурацию', candidate.p, err.message);
        await recordStat(candidate.p, false);
        continue;
      }

      if (!probe.ok) {
        log('Кандидат не прошёл проверку:', candidate.p, probe.error);
        await recordStat(candidate.p, false);
        continue;
      }

      if (await isCancelled()) {
        await chrome.proxy.settings.clear({ scope: 'regular' });
        return { ok: false, error: 'Отменено', cancelled: true };
      }

      // --- ФАЗА 2: ВКЛЮЧЕНИЕ. Прокси заработал — ставим глобально. ---
      let meta = {
        ...candidate,
        l: probe.ms,
        exitIp: probe.ip,
        exitCountry: probe.country || candidate.c,
        exitCountryName: probe.countryName || candidate.n,
        connectedAt: new Date().toISOString()
      };

      try {
        await applyProxyConfig(candidate.p, 'active', settings.failSafe);
        await enableWebRTCGuard();
      } catch (err) {
        log('Не удалось включить прокси глобально:', candidate.p, err.message);
        await clearProxy();
        return { ok: false, error: 'Не удалось включить прокси: ' + err.message };
      }

      // Запоминаем реальный IP: по нему потом поймаем fallback на DIRECT.
      if (settings.failSafe) {
        const baseIp = await probeDirectViaPacBypass();
        if (baseIp) await storageSet({ [STORAGE_KEYS.BASE_IP]: baseIp });
      }

      await storageSet({
        [STORAGE_KEYS.ENABLED]: true,
        [STORAGE_KEYS.ACTIVE_META]: meta,
        [STORAGE_KEYS.CONSEC_FAILS]: 0,
        [STORAGE_KEYS.SELECTED_COUNTRY]: countryCode || null
      });
      await recordStat(candidate.p, true);
      await updateMeasuredLatency(candidate.p, probe.ms);
      await updateBadge(true, false);
      log('Подключено:', meta.p, probe.ip, `${probe.ms} мс`);
      return { ok: true, meta };
    }

    await clearProxy();
    return {
      ok: false,
      error: 'Ни один прокси не прошёл проверку. Сеть не пострадала — попробуйте ещё раз или обновите список.'
    };
  } catch (err) {
    log('connect error:', err);
    await clearProxy();
    return { ok: false, error: err.message };
  } finally {
    await finish();
  }
}

/**
 * Замеряет реальный IP в обход прокси. Нужен, чтобы в режиме failSafe
 * отличать «прокси жив» от «Chrome откатился на DIRECT».
 */
async function probeDirectViaPacBypass() {
  const { [STORAGE_KEYS.BASE_IP]: known } = await storageGet(STORAGE_KEYS.BASE_IP);
  if (known) return known;
  try {
    await chrome.proxy.settings.clear({ scope: 'regular' });
    const ip = await probeDirect();
    return ip;
  } catch {
    return null;
  } finally {
    const { [STORAGE_KEYS.APPLIED]: applied } = await storageGet(STORAGE_KEYS.APPLIED);
    if (applied) {
      try {
        await applyProxyConfig(applied.proxyUrl, applied.mode, applied.failSafe);
      } catch { /* вернёмся в active на следующем запросе */ }
    }
  }
}

/** Подключение к КОНКРЕТНОМУ прокси (вкладка «Серверы»). */
async function connectTo(proxyUrl) {
  const { [STORAGE_KEYS.CONNECTING]: already } = await storageGet(STORAGE_KEYS.CONNECTING);
  if (already) return { ok: false, error: 'Подключение уже выполняется' };

  await storageSet({
    [STORAGE_KEYS.CONNECTING]: true,
    [STORAGE_KEYS.CANCEL]: false,
    [STORAGE_KEYS.CONNECT_PROGRESS]: { i: 1, total: 1, current: proxyUrl }
  });
  await updateBadge(false, true);

  try {
    if (!parseProxyUrl(proxyUrl)) {
      return { ok: false, error: 'Неверный формат прокси: ' + proxyUrl };
    }
    const { [STORAGE_KEYS.PROXIES]: proxies } = await storageGet(STORAGE_KEYS.PROXIES);
    const entry = (proxies || []).find((e) => e.p === proxyUrl);
    const settings = await getSettings();

    // Пробуем сначала: если прокси мёртв, сеть пользователя не пострадает.
    let probe;
    try {
      await applyProxyConfig(proxyUrl, 'trial', settings.failSafe);
      probe = await probeCurrentProxy(settings.testTimeoutMs);
    } catch (err) {
      await clearProxy();
      return { ok: false, error: 'Не удалось применить прокси: ' + err.message };
    }

    if (!probe.ok) {
      await clearProxy();
      await recordStat(proxyUrl, false);
      const hint = probe.error && /certificate|SSL/i.test(probe.error)
        ? ' Прокси подменяет сертификат — браузер бы показал ошибку сертификата.'
        : '';
      return { ok: false, error: 'Прокси не отвечает: ' + (probe.error || 'таймаут') + hint };
    }

    try {
      await applyProxyConfig(proxyUrl, 'active', settings.failSafe);
      await enableWebRTCGuard();
    } catch (err) {
      await clearProxy();
      return { ok: false, error: 'Не удалось включить прокси: ' + err.message };
    }

    if (settings.failSafe) {
      const baseIp = await probeDirectViaPacBypass();
      if (baseIp) await storageSet({ [STORAGE_KEYS.BASE_IP]: baseIp });
    }

    const meta = {
      ...(entry || { p: proxyUrl }),
      p: proxyUrl,
      l: probe.ms,
      exitIp: probe.ip,
      exitCountry: probe.country || (entry && entry.c) || '',
      exitCountryName: probe.countryName || (entry && entry.n) || '',
      connectedAt: new Date().toISOString()
    };
    await storageSet({
      [STORAGE_KEYS.ENABLED]: true,
      [STORAGE_KEYS.ACTIVE_META]: meta,
      [STORAGE_KEYS.CONSEC_FAILS]: 0
    });
    await recordStat(proxyUrl, true);
    await updateMeasuredLatency(proxyUrl, probe.ms);
    await updateBadge(true, false);
    log('Подключено вручную:', meta.p, probe.ip, `${probe.ms} мс`);
    return { ok: true, meta };
  } catch (err) {
    log('connectTo error:', err);
    await clearProxy();
    return { ok: false, error: err.message };
  } finally {
    await storageSet({
      [STORAGE_KEYS.CONNECTING]: false,
      [STORAGE_KEYS.CONNECT_PROGRESS]: null
    });
  }
}

async function disconnect() {
  await clearProxy();
  log('Отключено');
  return { ok: true };
}

// ============ ЗАЩИТА ОТ ПОТЕРИ СЕТИ ============

/**
 * Обработчик ошибок прокси от самого Chrome.
 * Если браузер не смог достучаться до прокси — считаем это провалом
 * и либо переключаемся, либо снимаем прокси.
 */
chrome.proxy.onProxyError.addListener((details) => {
  log('chrome.proxy.onProxyError:', details && details.error, details && details.host);
  (async () => {
    const { [STORAGE_KEYS.ENABLED]: enabled } = await storageGet(STORAGE_KEYS.ENABLED);
    const { [STORAGE_KEYS.CONNECTING]: connecting } = await storageGet(STORAGE_KEYS.CONNECTING);
    const { [STORAGE_KEYS.ACTIVE_META]: meta } = await storageGet(STORAGE_KEYS.ACTIVE_META);
    if (meta && meta.p) await recordStat(meta.p, false);
    // Во время подключения ошибка — просто сигнал, что кандидат плохой.
    if (connecting || !enabled || !meta) return;
    await handleProxyFailure(meta);
  })();
});

/** Реакция на подтверждённую смерть активного прокси. */
async function handleProxyFailure(meta) {
  const { [STORAGE_KEYS.CONSEC_FAILS]: prev } = await storageGet(STORAGE_KEYS.CONSEC_FAILS);
  const fails = (prev || 0) + 1;
  await storageSet({ [STORAGE_KEYS.CONSEC_FAILS]: fails });

  if (fails < FAIL_THRESHOLD) return;

  const { [STORAGE_KEYS.SELECTED_COUNTRY]: country } = await storageGet(STORAGE_KEYS.SELECTED_COUNTRY);
  log(`Активный прокси не отвечает (${fails}) — переподключаюсь`);
  await clearProxy();
  const res = await connect(country || null);
  if (!res.ok) log('Автопереподключение не удалось:', res.error);
  return res;
}

/** Периодическая проверка активного прокси. */
async function healthCheck() {
  const { [STORAGE_KEYS.ENABLED]: enabled } = await storageGet(STORAGE_KEYS.ENABLED);
  if (!enabled) return;
  const { [STORAGE_KEYS.CONNECTING]: connecting } = await storageGet(STORAGE_KEYS.CONNECTING);
  if (connecting) return;

  const { [STORAGE_KEYS.ACTIVE_META]: meta } = await storageGet(STORAGE_KEYS.ACTIVE_META);
  if (!meta) return;

  const settings = await getSettings();
  const probe = await probeCurrentProxy(settings.testTimeoutMs);

  if (probe.ok) {
    // Ловим откат на DIRECT в режиме failSafe: если «выходной» IP совпал
    // с реальным — прокси мёртв, а браузер тихо вернулся к вашему адресу.
    const { [STORAGE_KEYS.BASE_IP]: baseIp } = await storageGet(STORAGE_KEYS.BASE_IP);
    const fellBack = settings.failSafe && baseIp && probe.ip === baseIp;

    if (!fellBack) {
      await storageSet({
        [STORAGE_KEYS.ACTIVE_META]: { ...meta, l: probe.ms, exitIp: probe.ip },
        [STORAGE_KEYS.CONSEC_FAILS]: 0
      });
      await recordStat(meta.p, true);
      await updateMeasuredLatency(meta.p, probe.ms);
      log('Проверка живости: ок', probe.ms, 'мс');
      return;
    }
    log('Проверка живости: браузер откатился на прямое соединение');
    await handleProxyFailure(meta);
    return;
  }

  log('Проверка живости: провал —', probe.error);
  await handleProxyFailure(meta);
}

// ============ ФОНОВЫЕ ЗАДАЧИ ============

chrome.alarms.create(ALARM_REFRESH, { periodInMinutes: 360 });
chrome.alarms.create(ALARM_HEALTH, { periodInMinutes: 1 });
chrome.alarms.create(ALARM_WATCHDOG, { periodInMinutes: 5 });

chrome.alarms.onAlarm.addListener(async (alarm) => {
  try {
    if (alarm.name === ALARM_REFRESH) {
      log('Плановое обновление списка');
      await reconcileProxyState('перед обновлением списка');
      await refreshList();
    } else if (alarm.name === ALARM_HEALTH) {
      await healthCheck();
    } else if (alarm.name === ALARM_WATCHDOG) {
      // Страховка: если что-то пошло не так (worker был убит, вкладка
      // закрылась во время подключения) — приводим браузер в порядок.
      await reconcileProxyState('watchdog');
    }
  } catch (err) {
    log('alarm error:', err.message);
  }
});

// ============ СТАРТОВАЯ ИНИЦИАЛИЗАЦИЯ ============

// Выполняется при каждом запуске service worker'а, в т.ч. после того,
// как Chrome его «усыпил». Самое важное место для починки «осиротевшего» прокси.
(async () => {
  try {
    await reconcileProxyState('старт worker');
  } catch (err) {
    log('Сверка на старте не удалась:', err.message);
  }
  try {
    const { [STORAGE_KEYS.SETTINGS]: hasSettings } = await storageGet(STORAGE_KEYS.SETTINGS);
    if (!hasSettings) await storageSet({ [STORAGE_KEYS.SETTINGS]: DEFAULT_SETTINGS });
  } catch { /* не критично */ }
})();

chrome.runtime.onInstalled.addListener(async (details) => {
  log('Установлено/обновлено:', details.reason);
  const settings = await getSettings();
  await storageSet({
    [STORAGE_KEYS.SETTINGS]: settings,
    [STORAGE_KEYS.CONNECTING]: false,
    [STORAGE_KEYS.CANCEL]: false
  });
  // При обновлении расширения подхватываем свежий встроенный список:
  // пользователь нажал «Обновить» — и получил спарсенные им прокси.
  if (details.reason === 'update' || details.reason === 'install') {
    try {
      await fetchBundledList();
      return;
    } catch (err) {
      log('Встроенный список недоступен:', err.message);
    }
  }
  try {
    await refreshList();
  } catch (err) {
    log('Первичная загрузка списка не удалась:', err.message);
  }
});

chrome.runtime.onStartup.addListener(async () => {
  // chrome.proxy-настройки переживают перезапуск браузера: сначала сверяемся.
  await reconcileProxyState('запуск браузера');

  const { [STORAGE_KEYS.ENABLED]: enabled } = await storageGet(STORAGE_KEYS.ENABLED);
  await updateBadge(!!enabled, false);

  const { [STORAGE_KEYS.PROXIES]: proxies } = await storageGet(STORAGE_KEYS.PROXIES);
  if (!proxies || proxies.length === 0) {
    try {
      await refreshList();
    } catch (err) {
      log('Загрузка при старте не удалась:', err.message);
    }
  }
});

// ============ СООБЩЕНИЯ ОТ POPUP / OPTIONS ============

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      switch (msg && msg.action) {
        case 'getState': {
          const state = await storageGet([
            STORAGE_KEYS.PROXIES,
            STORAGE_KEYS.ACTIVE_META,
            STORAGE_KEYS.ENABLED,
            STORAGE_KEYS.CONNECTING,
            STORAGE_KEYS.CONNECT_PROGRESS,
            STORAGE_KEYS.LAST_UPDATE,
            STORAGE_KEYS.LIST_SOURCE,
            STORAGE_KEYS.SELECTED_COUNTRY
          ]);
          const settings = await getSettings();
          const license = await getLicense();
          const proxies = state[STORAGE_KEYS.PROXIES] || [];
          const byLatency = proxies
            .filter((e) => Number.isFinite(e.l) && e.l > 0)
            .sort((a, b) => a.l - b.l)
            .slice(0, 300);
          sendResponse({
            ok: true,
            enabled: !!state[STORAGE_KEYS.ENABLED],
            connecting: !!state[STORAGE_KEYS.CONNECTING],
            progress: state[STORAGE_KEYS.CONNECT_PROGRESS] || null,
            active: state[STORAGE_KEYS.ACTIVE_META] || null,
            totalProxies: proxies.length,
            measuredProxies: byLatency,
            countries: getCountryStats(proxies),
            selectedCountry: state[STORAGE_KEYS.SELECTED_COUNTRY] || null,
            lastUpdate: state[STORAGE_KEYS.LAST_UPDATE] || null,
            listSource: state[STORAGE_KEYS.LIST_SOURCE] || null,
            settings,
            license
          });
          break;
        }

        case 'connect': {
          sendResponse(await connect(msg.country || null));
          break;
        }

        case 'connectTo': {
          if (!msg.proxy || typeof msg.proxy !== 'string') {
            sendResponse({ ok: false, error: 'Не указан прокси' });
            break;
          }
          sendResponse(await connectTo(msg.proxy));
          break;
        }

        case 'cancelConnect': {
          await storageSet({ [STORAGE_KEYS.CANCEL]: true });
          sendResponse({ ok: true });
          break;
        }

        case 'disconnect': {
          sendResponse(await disconnect());
          break;
        }

        // Аварийная кнопка: снимает прокси в браузере, что бы ни было
        // в нашем хранилище. Спасает, когда сеть уже легла.
        case 'emergencyReset': {
          sendResponse(await emergencyReset());
          break;
        }

        case 'reconcile': {
          sendResponse(await reconcileProxyState('ручная проверка'));
          break;
        }

        case 'toggle': {
          const { [STORAGE_KEYS.ENABLED]: enabled } = await storageGet(STORAGE_KEYS.ENABLED);
          if (enabled) {
            sendResponse(await disconnect());
          } else {
            const { [STORAGE_KEYS.SELECTED_COUNTRY]: country } =
              await storageGet(STORAGE_KEYS.SELECTED_COUNTRY);
            sendResponse(await connect(msg.country || country || null));
          }
          break;
        }

        case 'switchCountry': {
          const country = msg.country || null;
          await storageSet({ [STORAGE_KEYS.SELECTED_COUNTRY]: country });
          const { [STORAGE_KEYS.ENABLED]: enabled } = await storageGet(STORAGE_KEYS.ENABLED);
          if (enabled) {
            sendResponse(await connect(country));
          } else {
            sendResponse({ ok: true });
          }
          break;
        }

        case 'refresh': {
          try {
            const count = await refreshList();
            sendResponse({ ok: true, count });
          } catch (err) {
            sendResponse({ ok: false, error: err.message });
          }
          break;
        }

        // Явная загрузка встроенного списка из пакета расширения.
        case 'loadBundled': {
          try {
            const { count } = await fetchBundledList();
            sendResponse({ ok: true, count });
          } catch (err) {
            sendResponse({ ok: false, error: err.message });
          }
          break;
        }

        // Узнать страну конкретного прокси — по кнопке «📍» в списке серверов.
        // Гео делается по адресу самого прокси, БЕЗ подключения к нему:
        // это не занимает прокси-слот и не требует ждать ответа сервера.
        case 'locate': {
          const entries = Array.isArray(msg.proxies)
            ? msg.proxies.slice(0, 50)
            : (msg.proxy ? [msg.proxy] : []);
          if (entries.length === 0) {
            sendResponse({ ok: false, error: 'Не указан прокси' });
            break;
          }

          const { [STORAGE_KEYS.PROXIES]: proxies } = await storageGet(STORAGE_KEYS.PROXIES);
          const list = proxies || [];
          const found = [];
          const failed = [];

          for (const url of entries) {
            const parsed = parseProxyUrl(url);
            if (!parsed) {
              failed.push({ p: url, error: 'неверный формат' });
              continue;
            }
            try {
              const geo = await lookupGeo(parsed.host, 6000);
              found.push({ p: url, ...geo });
            } catch (err) {
              failed.push({ p: url, error: err.message });
            }
          }

          // Записываем страну в список — она сохранится и переживёт перезапуск.
          if (found.length) {
            const byUrl = new Map(found.map((g) => [g.p, g]));
            const updated = list.map((e) => {
              const g = byUrl.get(e.p);
              if (!g) return e;
              return { ...e, c: g.country || e.c, n: g.countryName || e.n, i: g.isp || e.i };
            });
            await storageSet({ [STORAGE_KEYS.PROXIES]: updated });
          }

          log(`Гео по запросу: ${found.length} определено, ${failed.length} нет`);
          sendResponse({ ok: found.length > 0, found, failed, ...(found.length ? {} : { error: 'не удалось определить страну' }) });
          break;
        }

        case 'checkNow': {
          const { [STORAGE_KEYS.ENABLED]: enabled } = await storageGet(STORAGE_KEYS.ENABLED);
          if (!enabled) {
            sendResponse({ ok: false, error: 'Прокси не подключён' });
            break;
          }
          await healthCheck();
          const { [STORAGE_KEYS.ACTIVE_META]: meta } = await storageGet(STORAGE_KEYS.ACTIVE_META);
          const { [STORAGE_KEYS.CONSEC_FAILS]: fails } = await storageGet(STORAGE_KEYS.CONSEC_FAILS);
          sendResponse({
            ok: !fails,
            ip: meta && meta.exitIp,
            ms: meta && meta.l,
            error: fails ? 'Прокси не отвечает, выполняется переподключение' : null
          });
          break;
        }

        case 'import': {
          const data = msg.data;
          let entries = [];
          if (typeof data === 'string') {
            entries = toCompactEntries(parseProxyText(data), {});
          } else if (Array.isArray(data)) {
            entries = sanitizeEntries(data);
          } else if (data && Array.isArray(data.proxies)) {
            entries = sanitizeEntries(data.proxies);
          }
          entries = sanitizeEntries(entries);
          if (entries.length === 0) {
            sendResponse({ ok: false, error: 'В файле не найдено валидных прокси' });
            break;
          }
          await storageSet({
            [STORAGE_KEYS.PROXIES]: entries,
            [STORAGE_KEYS.LAST_UPDATE]: new Date().toISOString(),
            [STORAGE_KEYS.LIST_SOURCE]: 'import'
          });
          log(`Импортировано ${entries.length} прокси`);
          sendResponse({ ok: true, count: entries.length });
          break;
        }

        case 'getSettings': {
          sendResponse({ ok: true, settings: await getSettings(), license: await getLicense() });
          break;
        }

        case 'setSettings': {
          const cur = await getSettings();
          const next = {
            ...cur,
            ...pick(msg.settings, ['listUrl', 'mode', 'testTimeoutMs', 'failSafe', 'allowHttpOnly'])
          };
          if (typeof next.listUrl !== 'string') next.listUrl = '';
          next.listUrl = next.listUrl.trim();
          if (next.listUrl && !/^https?:\/\//i.test(next.listUrl)) {
            sendResponse({ ok: false, error: 'URL должен начинаться с http:// или https://' });
            break;
          }
          if (!['auto', 'bundled', 'remote', 'direct'].includes(next.mode)) next.mode = 'auto';
          next.testTimeoutMs = Math.min(20000, Math.max(3000, Number(next.testTimeoutMs) || 10000));
          next.failSafe = next.failSafe !== false;
          next.allowHttpOnly = !!next.allowHttpOnly;
          await storageSet({ [STORAGE_KEYS.SETTINGS]: next });
          // Переприменяем PAC с новыми настройками, если прокси включён.
          const { [STORAGE_KEYS.ENABLED]: enabled } = await storageGet(STORAGE_KEYS.ENABLED);
          const { [STORAGE_KEYS.APPLIED]: applied } = await storageGet(STORAGE_KEYS.APPLIED);
          if (enabled && applied) {
            try {
              await applyProxyConfig(applied.proxyUrl, applied.mode, next.failSafe);
            } catch (err) {
              log('Не удалось переприменить прокси после смены настроек:', err.message);
            }
          }
          sendResponse({ ok: true, settings: next });
          break;
        }

        case 'activateLicense': {
          const key = String(msg.key || '').trim();
          if (isValidLicenseKey(key)) {
            const updated = { key: key.toUpperCase(), valid: true, activatedAt: new Date().toISOString() };
            await storageSet({ [STORAGE_KEYS.LICENSE]: updated });
            sendResponse({ ok: true, license: updated });
          } else {
            const license = await getLicense();
            const updated = { ...license, valid: false };
            await storageSet({ [STORAGE_KEYS.LICENSE]: updated });
            sendResponse({ ok: false, error: 'Неверный формат ключа (SWIP-XXXX-XXXX-XXXX)' });
          }
          break;
        }

        default:
          sendResponse({ ok: false, error: 'Неизвестное действие' });
      }
    } catch (err) {
      console.error('[SwapIP] handler:', err);
      sendResponse({ ok: false, error: err.message });
    }
  })();
  return true; // асинхронный sendResponse
});

function pick(obj, keys) {
  const out = {};
  if (!obj) return out;
  for (const k of keys) {
    if (k in obj) out[k] = obj[k];
  }
  return out;
}
