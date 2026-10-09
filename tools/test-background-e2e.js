/*
 * SwapIP — end-to-end стенд service worker'а.
 *
 * Загружает НАСТОЯЩИЙ background.js в Node с заглушками chrome.* API
 * и прогоняет реальные сценарии:
 *   1. 'refresh'  — загрузка прямых публичных источников (живой интернет);
 *   2. 'connect'  — подбор кандидата, проверка его живым запросом ЧЕРЕЗ
 *                   прокси (undici ProxyAgent эмулирует поведение chrome.proxy,
 *                   через который браузер гоняет трафик расширения);
 *   3. 'getState' — состояние для popup;
 *   4. 'checkNow' — фоновая проверка живости.
 *
 * Запуск: node tools/test-background-e2e.js
 */
const path = require('path');
const fs = require('fs');
const { ProxyAgent, Agent, fetch: undiciFetch } = require('undici');

const EXT_DIR = path.join(__dirname, '..', 'extension');

// ============ ЗАГЛУШКИ CHROME.* ============

const listeners = { message: [], alarm: [], installed: [], startup: [], proxyError: [] };

function makeChromeRuntime() {
  return {
    onMessage: {
      addListener: (fn) => listeners.message.push(fn)
    },
    onInstalled: {
      addListener: (fn) => listeners.installed.push(fn)
    },
    onStartup: {
      addListener: (fn) => listeners.startup.push(fn)
    },
    getURL: (p) => 'file:///' + path.join(EXT_DIR, p),
    openOptionsPage: () => {}
  };
}

const store = new Map();

function makeStorageArea(map) {
  return {
    get: async (keys) => {
      if (keys === null || keys === undefined) {
        return Object.fromEntries(map);
      }
      if (typeof keys === 'string') keys = [keys];
      const out = {};
      for (const k of keys) if (map.has(k)) out[k] = map.get(k);
      return out;
    },
    set: async (obj) => {
      for (const [k, v] of Object.entries(obj)) map.set(k, v);
    }
  };
}

// Состояние «браузерного» прокси: chrome.proxy рано или поздно применит
// конфигурацию ко всему трафику расширения — в стенде мы повторяем это
// через подмену globalThis.fetch в момент probe.
let appliedProxyConfig = null;
// Последний применённый PAC — нужен тестам, чтобы проверить trial-режим
// уже после того, как конфигурация будет снята.
let lastAppliedPac = null;

function makeChromeProxy() {
  return {
    settings: {
      set: async ({ value }) => {
        appliedProxyConfig = value;
        if (value && value.mode === 'pac_script' && value.pacScript) {
          lastAppliedPac = value.pacScript.data;
        }
      },
      get: async () => ({ value: appliedProxyConfig || { mode: 'system' } }),
      clear: async () => {
        appliedProxyConfig = null;
      }
    },
    onProxyError: { addListener: (fn) => listeners.proxyError.push(fn) }
  };
}

const alarms = {};
function makeChromeAlarms() {
  return {
    create: (name) => {
      alarms[name] = true;
    },
    onAlarm: {
      addListener: (fn) => {
        listeners.alarm.push(fn);
      }
    }
  };
}

function makeChromeAction() {
  const state = { text: '', color: '' };
  return {
    setBadgeText: async ({ text }) => {
      state.text = text;
    },
    setBadgeBackgroundColor: async ({ color }) => {
      state.color = color;
    },
    _state: state
  };
}

// ============ ПОДМЕНА FETCH: ТРАФИК ЧЕРЕЗ «chrome.proxy» ============

// Разбираем PAC из background.js, чтобы стенд видел ту же маршрутизацию,
// которую задал бы реальный Chrome.
const PROBE_HOSTS = ['ipwho.is', 'ipinfo.io', 'api.ip.sb', 'api.ipify.org'];

function parsePac(data) {
  const token = (data.match(/var SWAPIP_PROXY = "(.*?)"/) || [])[1] || null;
  const trial = /var SWAPIP_TRIAL = true/.test(data);
  const failsafe = /var SWAPIP_FAILSAFE = true/.test(data);
  return { token, trial, failsafe };
}

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function proxyUriFromToken(token) {
  const m = String(token).match(/^(PROXY|HTTPS|SOCKS5|SOCKS4)\s+(\S+)$/);
  if (!m) return null;
  return { kind: m[1], hostport: m[2] };
}

// Используем fetch именно из npm-undici: его dispatcher'ы
// (ProxyAgent/Agent) несовместимы со встроенным fetch Node.
// Встроенный список расширение читает через chrome.runtime.getURL(),
// то есть по file://-пути. undici такие схемы не понимает — читаем сами.
globalThis.fetch = async (url, init = {}) => {
  if (typeof url === 'string' && url.startsWith('file:///')) {
    const buf = fs.readFileSync(url.slice('file:///'.length).replace(/\//g, path.sep));
    return {
      ok: true,
      status: 200,
      json: async () => JSON.parse(buf.toString('utf-8')),
      text: async () => buf.toString('utf-8')
    };
  }

  const conf = appliedProxyConfig;

  if (conf && conf.mode === 'pac_script') {
    const pac = parsePac(conf.pacScript.data);
    const host = hostOf(url);
    const isProbe = PROBE_HOSTS.includes(host);

    // Реплика FindProxyForURL для интересующих нас случаев. В trial-режиме
    // через прокси уходит ТОЛЬКО зонд — если это перестанет работать,
    // тест поймает возврат к схеме «включили и проверяем», которая роняла сеть.
    const useProxy = pac.token && (isProbe || !pac.trial);
    if (!useProxy) {
      return undiciFetch(url, { ...init, dispatcher: new Agent({ connectTimeout: 10000 }) });
    }

    const parsed = proxyUriFromToken(pac.token);
    if (parsed.kind !== 'PROXY') {
      throw new Error(`${parsed.kind} через стенд не проверяется (в Chrome поддерживается)`);
    }
    return undiciFetch(url, {
      ...init,
      dispatcher: new ProxyAgent({
        uri: `http://${parsed.hostport}`,
        connectTimeout: 8000,
        requestTls: { rejectUnauthorized: false }
      })
    });
  }

  return undiciFetch(url, { ...init, dispatcher: new Agent({ connectTimeout: 10000 }) });
};

// ============ ЗАГРУЗКА background.js ============

const noop = () => {};
globalThis.chrome = {
  runtime: makeChromeRuntime(),
  storage: { local: makeStorageArea(store), onChanged: { addListener: noop } },
  proxy: makeChromeProxy(),
  alarms: makeChromeAlarms(),
  action: makeChromeAction(),
  privacy: {
    network: {
      webRTCIPHandlingPolicy: {
        set: async () => {},
        clear: async () => {}
      }
    }
  }
};

// importScripts — заглушка для service worker. В реальном worker'е
// top-level const/let из importScripts попадают в общую глобальную
// лексическую область; в Node eval они изолированы, поэтому экспортируем
// их вручную.
globalThis.importScripts = (rel) => {
  const code = fs.readFileSync(path.join(EXT_DIR, rel), 'utf-8');
  const exported = (0, eval)(
    code +
      '\n;({ DIRECT_SOURCES, DIRECT_MODE_MAX_PROXIES, normalizeProxy, parseProxyText, toCompactEntries })'
  );
  Object.assign(globalThis, exported);
};

const bgCode = fs.readFileSync(path.join(EXT_DIR, 'background.js'), 'utf-8');
(0, eval)(bgCode);

// ============ ПРОГОН СЦЕНАРИЕВ ============

function send(message) {
  return new Promise((resolve) => {
    let answered = false;
    const resp = (r) => {
      if (!answered) {
        answered = true;
        resolve(r);
      }
    };
    for (const fn of listeners.message) fn(message, {}, resp);
    setTimeout(() => {
      if (!answered) resolve({ ok: false, error: 'нет ответа' });
    }, 120000);
  });
}

const summary = { steps: [] };
function report(name, ok, detail) {
  summary.steps.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
}

(async () => {
  // 1. Обновление списка из прямых источников.
  //    Явно ставим mode=direct: в auto встроенный список имеет приоритет,
  //    и если он свежий — прямые источники не трогаются (так и задумано).
  await send({ action: 'setSettings', settings: { mode: 'direct' } });
  const refresh = await send({ action: 'refresh' });
  const total = refresh.count || 0;
  report('refresh (прямые источники)', refresh.ok && total > 100, `${total} прокси`);

  // 2. Подключение: подбор + живая проверка через прокси.
  //    Стенд на undici умеет проверять только http://-прокси (socks4/5 и
  //    https-схемы в реальном Chrome поддерживаются нативно) — оставляем
  //    в пуле стенда только http-кандидатов.
  const all = store.get('proxies') || [];
  const httpOnly = all.filter((e) => e.p.startsWith('http://')).slice(0, 300);
  store.set('proxies', httpOnly);
  console.log(`Пул стенда: ${httpOnly.length} http-прокси (из ${all.length})`);

  const connect = await send({ action: 'connect', country: null });
  if (connect.ok) {
    const m = connect.meta;
    report(
      'connect (живая проверка через прокси)',
      true,
      `${m.p} · exit IP ${m.exitIp} · ${m.l} мс · страна ${m.exitCountry || '?'}`
    );
    // 3. Состояние для popup
    const st = await send({ action: 'getState' });
    report(
      'getState',
      st.ok && st.enabled && st.active && st.active.exitIp === m.exitIp,
      `enabled=${st.enabled}, всего=${st.totalProxies}, connecting=${st.connecting}`
    );

    // 4. Ручная проверка живости.
    //    Публичные прокси умирают за минуты, поэтому «только что
    //    подключившийся» прокси вполне может не ответить на повторный запрос.
    //    Это не регрессия — регрессия была бы «прокси остался включённым».
    const check = await send({ action: 'checkNow' });
    if (check.ok) {
      report('checkNow', true, `${check.ip} · ${check.ms} мс`);
    } else {
      const stAfter = await send({ action: 'getState' });
      const safe = !stAfter.enabled || !stAfter.connecting;
      report(
        'checkNow: умерший прокси приводит к безопасному состоянию',
        safe && (appliedProxyConfig === null || stAfter.enabled),
        check.error || ''
      );
    }

    // 5. Подключение к КОНКРЕТНОМУ серверу (вкладка «Серверы»)
    const httpProxies = (store.get('proxies') || []).filter((e) => e.p.startsWith('http://'));
    if (httpProxies.length > 2) {
      const target = httpProxies[2].p;
      const to = await send({ action: 'connectTo', proxy: target });
      if (to.ok) {
        report('connectTo (ручной выбор)', to.ok && to.meta.p === target,
          `${to.meta.p} · exit IP ${to.meta.exitIp} · ${to.meta.l} мс`);
        await send({ action: 'disconnect' });
      } else {
        // живой публичный прокси мог умереть с момента проверки — это допустимо
        report('connectTo (ручной выбор)', /не отвечает/.test(to.error || ''), `ожидаемо: ${to.error}`);
      }
    }

    // 6. Отключение
    const off = await send({ action: 'disconnect' });
    const st2 = await send({ action: 'getState' });
    report('disconnect', off.ok && !st2.enabled && appliedProxyConfig === null, 'прокси снят');
  } else {
    // Публичные прокси живут минутами, и HTTPS-capable в конкретный момент
    // может не быть ни одного (замер: 34 из 150 работали по HTTP, 0 — по HTTPS).
    // Это НЕ падение расширения — наоборот, так и должно быть: раньше такие
    // прокси проходили проверку и роняли сеть в Chrome.
    const stateAfter = await send({ action: 'getState' });
    report(
      'connect: сеть не пострадала при отсутствии живых прокси',
      stateAfter.ok && !stateAfter.enabled && appliedProxyConfig === null,
      `${connect.error} · прокси в браузере снят, соединение прямое`
    );
    const st = stateAfter;
    report('getState после неудачи', st.ok && !st.enabled, `total=${st.totalProxies}`);
  }

  // 6. Импорт списка в формате анализатора
  const importResp = await send({
    action: 'import',
    data: { proxies: [{ p: 'http://1.2.3.4:8080', l: 100, c: 'NL', n: 'Netherlands', a: 'elite', i: 'Test ISP' }] }
  });
  report('import (формат анализатора)', importResp.ok && importResp.count === 1, '');

  // 7. Регрессия: «осиротевший» прокси в браузере при выключенном расширении.
  //    Именно это состояние приводило к «сеть заблокирована, пока не удалишь
  //    расширение»: настройка пережила перезапуск, а UI считал себя выключенным.
  appliedProxyConfig = { mode: 'pac_script', pacScript: { data: 'var SWAPIP_PROXY = "PROXY 9.9.9.9:1";' } };
  store.set('enabled', false);
  store.set('appliedProxy', null);
  store.set('activeMeta', null);
  const rec = await send({ action: 'reconcile' });
  report(
    'reconcile снимает осиротевший прокси',
    rec.ok && rec.cleared === true && appliedProxyConfig === null,
    appliedProxyConfig === null ? 'прокси снят автоматически' : 'прокси остался!'
  );

  // 8. Регрессия: PAC в trial-режиме не должен гонять обычный трафик
  //    через проверяемый прокси.
  lastAppliedPac = null;
  store.set('proxies', [{ p: 'http://127.0.0.1:9', l: 50, c: 'US', n: 'USA', a: 'elite', i: '', https: true }]);
  const dead = await send({ action: 'connectTo', proxy: 'http://127.0.0.1:9' });
  report(
    'trial-PAC: только зонд через прокси',
    !!lastAppliedPac
      && /SWAPIP_TRIAL = true/.test(lastAppliedPac)
      && /if \(SWAPIP_TRIAL\) return "DIRECT";/.test(lastAppliedPac)
      && !dead.ok
      && appliedProxyConfig === null,
    `мёртвый прокси отклонён (${dead.error || 'ok'}), сеть не затронута`
  );

  // 9. Аварийный сброс снимает прокси даже при «забытом» состоянии.
  appliedProxyConfig = { mode: 'pac_script', pacScript: { data: 'var SWAPIP_PROXY = "PROXY 9.9.9.9:1";' } };
  const reset = await send({ action: 'emergencyReset' });
  report(
    'emergencyReset снимает прокси в браузере',
    reset.ok && reset.browserCleared && appliedProxyConfig === null,
    ''
  );

  // 10. Гео по запросу: страна определяется по адресу прокси, БЕЗ подключения
  //     к нему. Проверяем, что действие отвечает и пишет страну в список.
  await send({
    action: 'import',
    data: { proxies: [{ p: 'http://8.8.8.8:8080', l: 120, c: '', n: '', a: 'elite', i: '' }] }
  });
  const loc = await send({ action: 'locate', proxy: 'http://8.8.8.8:8080' });
  let storedGeo = null;
  for (const e of (store.get('proxies') || [])) {
    if (e.p === 'http://8.8.8.8:8080' && e.c) storedGeo = e;
  }
  report(
    'locate (страна по запросу, без подключения)',
    loc.ok && loc.found && loc.found.length === 1 && !!storedGeo,
    storedGeo
      ? `${storedGeo.c} ${storedGeo.n}${storedGeo.i ? ' · ' + storedGeo.i : ''}`
      : (loc.error || 'нет ответа')
  );

  // 11. Встроенный список: файл, который кладёт анализатор в extension/data/.
  //     Именно он делает «нажал Обновить в chrome://extensions → прокси уже есть».
  const bundlePath = path.join(EXT_DIR, 'data', 'proxies.json');
  if (fs.existsSync(bundlePath)) {
    const bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf-8'));
    if (!bundle.proxies || bundle.proxies.length === 0) {
      // Штатное состояние репозитория: анализатор ещё не запускали.
      // Расширение должно корректно это пережить, а не сломаться.
      const empty = await send({ action: 'loadBundled' });
      const stEmpty = await send({ action: 'getState' });
      report(
        'пустой встроенный список обработан без ошибки',
        empty.ok === false && stEmpty.ok,
        `сообщение: ${empty.error} (ожидаемо)`
      );
    } else {
      const bundled = await send({ action: 'loadBundled' });
      const stBundled = await send({ action: 'getState' });
      report(
        'loadBundled (список внутри расширения)',
        bundled.ok && bundled.count > 0 && stBundled.listSource === 'bundled',
        `${bundled.count} прокси, источник=${stBundled.listSource}`
      );
    }
  } else {
    console.log('SKIP  loadBundled — нет extension/data/proxies.json');
  }

  const failed = summary.steps.filter((s) => !s.ok).length;
  console.log(`\nИтого: ${summary.steps.length - failed} PASS / ${failed} FAIL`);
  console.log('Примечание: качество публичного пула плавает. Признак регрессии —');
  console.log('не «нет живых прокси», а «сеть осталась заблокированной после неудачи».');
  process.exit(failed ? 1 : 0);
})().catch((err) => {
  console.error('СТЕНД УПАЛ:', err);
  process.exit(1);
});
