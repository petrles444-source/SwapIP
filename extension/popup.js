// ============ СОСТОЯНИЕ ============
let state = {
  enabled: false,
  connecting: false,
  progress: null,
  active: null,
  totalProxies: 0,
  measuredProxies: [],   // топ-300 по скорости {p,l,c,n,a,i}
  countries: [],
  selectedCountry: null,
  lastUpdate: null,
  listSource: null
};

let activeTab = 'main';
let pollTimer = null;
let errorTimer = null;
let serverFilter = 'all';
let serverSort = 'ping';
let countrySort = 'ping';

// ============ ИНИЦИАЛИЗАЦИЯ ============
document.addEventListener('DOMContentLoaded', async () => {
  document.getElementById('connectBtn').addEventListener('click', toggleConnection);
  document.getElementById('checkBtn').addEventListener('click', checkNow);
  document.getElementById('settingsBtn').addEventListener('click', () => chrome.runtime.openOptionsPage());
  document.getElementById('refreshBtn').addEventListener('click', refreshList);
  document.getElementById('bundledBtn').addEventListener('click', loadBundledList);
  document.getElementById('emergencyBtn').addEventListener('click', emergencyReset);
  document.getElementById('importFile').addEventListener('change', handleImport);
  document.getElementById('serverFilter').addEventListener('change', (e) => { serverFilter = e.target.value; renderServers(); });
  document.getElementById('serverSort').addEventListener('change', (e) => { serverSort = e.target.value; renderServers(); });
  document.getElementById('countrySort').addEventListener('change', (e) => { countrySort = e.target.value; renderCountries(); });

  // Переключение вкладок
  for (const tab of document.querySelectorAll('.tab')) {
    tab.addEventListener('click', () => {
      activeTab = tab.dataset.tab;
      document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t === tab));
      document.querySelectorAll('.tab-page').forEach((p) => p.classList.toggle('active', p.id === 'page-' + activeTab));
      render();
    });
  }

  // Живое обновление состояния из background
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local') loadState();
  });

  await loadState();
});

// ============ ОБЩЕНИЕ С BACKGROUND ============
function sendMessage(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (resp) => resolve(resp || { ok: false, error: 'нет ответа' }));
  });
}

async function loadState() {
  const resp = await sendMessage({ action: 'getState' });
  if (resp && resp.ok) {
    state = resp;
    render();
  }
  schedulePolling();
}

function schedulePolling() {
  // Опрос идёт всегда, пока popup открыт: прогресс подбора и обновления
  // состояния должны быть видны без перезагрузки окна.
  if (!pollTimer) {
    pollTimer = setInterval(loadState, state.connecting ? 700 : 5000);
  } else if (state.connecting) {
    clearInterval(pollTimer);
    pollTimer = setInterval(loadState, 700);
  }
}

// ============ УТИЛИТЫ ОТРИСОВКИ ============
function getFlagEmoji(code) {
  if (!code || code.length !== 2) return '🌍';
  return String.fromCodePoint(
    ...code.toUpperCase().split('').map((ch) => 0x1F1E6 + ch.charCodeAt(0) - 65)
  );
}

function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = String(s);
  return div.innerHTML;
}

function pingClass(ms) {
  if (ms < 300) return 'fast';
  if (ms < 1000) return 'mid';
  return 'slow';
}

function showError(message) {
  const sub = document.getElementById('statusSub');
  sub.textContent = `⚠ ${message}`;
  sub.style.color = '#f87171';
  clearTimeout(errorTimer);
  errorTimer = setTimeout(() => {
    sub.style.color = '';
    loadState();
  }, 4000);
}

/** Короткое подтверждение успеха — чтобы действие не выглядело «ничего не сделал». */
function showNotice(message, ok) {
  const sub = document.getElementById('statusSub');
  sub.textContent = message;
  sub.style.color = ok ? '#22c55e' : '#f87171';
  clearTimeout(errorTimer);
  errorTimer = setTimeout(() => {
    sub.style.color = '';
    loadState();
  }, 4000);
}

// ============ ГЛАВНАЯ ОТРИСОВКА ============
function render() {
  const indicator = document.getElementById('statusIndicator');
  const title = document.getElementById('statusTitle');
  const sub = document.getElementById('statusSub');

  if (state.connecting) {
    indicator.className = 'status-indicator connecting';
    title.textContent = 'Подключение…';
    sub.textContent = 'Ищем и проверяем быстрый прокси';
    sub.style.color = '';
  } else if (state.enabled && state.active) {
    indicator.className = 'status-indicator active';
    title.textContent = 'Подключено';
    sub.textContent = state.active.p.replace(/^\w+:\/\//, '');
    sub.style.color = '';
  } else {
    indicator.className = 'status-indicator';
    title.textContent = 'Отключено';
    sub.textContent = 'Прямое соединение — локация не изменена';
    sub.style.color = '';
  }

  renderProgress();

  // Во время подключения кнопка не блокируется — нажатие отменяет попытку.
  // Иначе пользователь остаётся с зависшим окном без единого способа выйти.
  const btn = document.getElementById('connectBtn');
  const btnText = document.getElementById('btnText');
  btn.disabled = false;
  btn.classList.toggle('connecting', !!state.connecting);
  if (state.connecting) {
    btn.classList.remove('active');
    btnText.textContent = 'Отмена';
  } else if (state.enabled) {
    btn.classList.add('active');
    btnText.textContent = 'Отключиться';
  } else {
    btn.classList.remove('active');
    btnText.textContent = 'Подключиться';
  }

  document.getElementById('checkBtn').disabled = !state.enabled;
  renderLocation();
  renderStats();

  if (activeTab === 'servers') renderServers();
  if (activeTab === 'countries') renderCountries();
}

/** Полоса прогресса подбора + понятный текст вместо «висит». */
function renderProgress() {
  const box = document.getElementById('connectProgress');
  const bar = document.getElementById('progressBar');
  const text = document.getElementById('progressText');
  if (!state.connecting) {
    box.hidden = true;
    return;
  }
  box.hidden = false;
  const p = state.progress;
  const i = p && p.i ? p.i : 0;
  const total = p && p.total ? p.total : 0;
  const percent = total ? Math.round((i / total) * 100) : 20;
  bar.style.width = `${Math.max(8, Math.min(100, percent))}%`;
  const host = p && p.current ? p.current.replace(/^\w+:\/\//, '') : '';
  text.textContent = total
    ? `Проверяем прокси ${i} из ${total}${host ? ' · ' + host : ''}`
    : 'Проверяем прокси…';
}

/** Карточка «откуда идёт соединение». */
function renderLocation() {
  const flag = document.getElementById('locFlag');
  const label = document.getElementById('locLabel');
  const value = document.getElementById('locValue');
  const meta = document.getElementById('locMeta');

  if (state.enabled && state.active && state.active.exitIp) {
    const code = state.active.exitCountry || '';
    flag.textContent = getFlagEmoji(code);
    label.textContent = 'Соединение идёт через';
    value.className = 'location-value active';
    const name = state.active.exitCountryName || state.active.n || code || 'Неизвестная страна';
    value.textContent = name;
    const parts = [`IP: ${state.active.exitIp}`, `пинг: ${state.active.l} мс`];
    if (state.active.i) parts.push(state.active.i);
    meta.textContent = parts.join(' · ');
  } else {
    flag.textContent = '🌍';
    label.textContent = 'Ваша локация';
    value.className = 'location-value';
    value.textContent = 'Прямое соединение — реальный IP';
    meta.textContent = 'Нажмите «Подключиться» или выберите страну';
  }
}

function renderStats() {
  const el = document.getElementById('stats');
  const parts = [];
  if (state.totalProxies > 0) parts.push(`Прокси: ${state.totalProxies}`);
  const sourceLabels = {
    bundled: 'встроенный список',
    remote: 'кураторский список',
    direct: 'публичные источники',
    import: 'импорт'
  };
  if (state.listSource) parts.push(sourceLabels[state.listSource] || state.listSource);
  if (state.lastUpdate) {
    const d = new Date(state.lastUpdate);
    parts.push(`обновлён: ${d.toLocaleDateString('ru-RU')} ${d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })}`);
  }
  el.textContent = parts.length ? parts.join(' · ') : 'Список пуст — вкладка «Страны» → ⟳';
}

// ============ ВКЛАДКА «СЕРВЕРЫ» ============
function renderServers() {
  const list = document.getElementById('serverList');
  const hint = document.getElementById('serversHint');
  list.innerHTML = '';

  let servers = (state.measuredProxies || []).slice();

  // Прокси без измеренного пинга (прямые списки) показываем «как есть» в конце.
  if (servers.length === 0 && state.totalProxies > 0) {
    hint.textContent = 'Пинг ещё не измерен — он появится после первого подключения.';
    const note = document.createElement('div');
    note.className = 'empty-note';
    note.textContent = 'Нет измеренных серверов. Подключитесь один раз — расширение замерит пинг лучших, или импортируйте кураторский список из анализатора (кнопка «Импорт»).';
    list.appendChild(note);
    return;
  }

  if (serverFilter !== 'all') {
    servers = servers.filter((e) => e.p.startsWith(serverFilter + '://'));
  }

  if (serverSort === 'ping') {
    servers.sort((a, b) => (a.l || 99999) - (b.l || 99999));
  } else {
    servers.sort((a, b) => (a.n || a.c || 'zz').localeCompare(b.n || b.c || 'zz') || (a.l || 99999) - (b.l || 99999));
  }

  hint.textContent = `Показано: ${servers.length} из ${state.measuredProxies.length} измеренных (лучший пинг: ${servers.length ? servers[0].l : '—'} мс)`;

  const activeUrl = state.active && state.active.p;
  for (const s of servers.slice(0, 200)) {
    const item = document.createElement('div');
    item.className = 'server-item' + (activeUrl === s.p ? ' selected' : '');
    const proto = s.p.split('://')[0];
    const addr = s.p.replace(/^\w+:\/\//, '');
    const country = s.n || s.c || 'Страна неизвестна';
    const ping = s.l
      ? `<div class="ping-badge ${pingClass(s.l)}">${s.l} мс</div>`
      : '<div class="ping-badge">— мс</div>';

    // Кнопка «📍» — узнать страну именно этого прокси.
    // Гео делается по адресу прокси, без подключения к нему, поэтому
    // ответ приходит за ~200 мс и чужие страницы не грузятся.
    // Клик по строке (кроме кнопки) — подключиться.
    const geoBtn = s.c
      ? `<div class="geo-tag known" title="${escapeHtml(country)}">📍</div>`
      : '<div class="geo-tag" title="Узнать страну этого прокси">📍</div>';

    item.innerHTML = `
      <div class="server-flag">${getFlagEmoji(s.c)}</div>
      <div class="server-info">
        <div class="server-addr">${escapeHtml(addr)}</div>
        <div class="server-meta">${escapeHtml(country)}${s.i ? ' · ' + escapeHtml(s.i) : ''}</div>
      </div>
      <div class="proto-tag">${proto}</div>
      ${geoBtn}
      ${ping}
    `;

    item.addEventListener('click', (ev) => {
      if (ev.target.closest('.geo-tag')) return;
      connectToProxy(s.p);
    });
    item.title = 'Подключиться к этому серверу';

    const geo = item.querySelector('.geo-tag');
    geo.addEventListener('click', (ev) => {
      ev.stopPropagation();
      locateProxy(s.p, geo);
    });

    list.appendChild(item);
  }

  if (servers.length === 0) {
    const note = document.createElement('div');
    note.className = 'empty-note';
    note.textContent = 'Нет серверов под этот фильтр.';
    list.appendChild(note);
  }
}

/**
 * Узнаёт страну одного прокси по кнопке «📍».
 * Гео сохраняется в список, поэтому страна остаётся после перезапуска
 * и попадает в подсчётку на вкладке «Страны».
 */
async function locateProxy(proxyUrl, btn) {
  btn.classList.add('loading');
  btn.title = 'Определяем страну…';
  const resp = await sendMessage({ action: 'locate', proxy: proxyUrl });
  btn.classList.remove('loading');

  if (resp.ok && resp.found && resp.found.length) {
    const g = resp.found[0];
    btn.classList.add('known');
    btn.title = g.countryName || g.country;
    await loadState();
  } else {
    btn.title = (resp.error || 'не удалось определить') + ' — попробуй ещё раз';
    showError('Не удалось определить страну: ' + (resp.error || 'нет ответа'));
  }
}

// ============ ВКЛАДКА «СТРАНЫ» ============
function renderCountries() {
  const container = document.getElementById('countries');
  container.innerHTML = '';

  if (state.countries.length === 0) {
    const note = document.createElement('div');
    note.className = 'empty-note';
    note.innerHTML = state.totalProxies === 0
      ? 'Список пуст. Нажмите ⟳, чтобы загрузить прокси из публичных источников.'
      : 'Страны появятся сами — их не нужно определять заранее.<br><br>'
        + '<b>Подключись</b> к любому прокси: страна определится по фактическому выходу.<br>'
        + 'Или на вкладке «📡 Серверы» нажми <b>📍</b> у нужного прокси.<br><br>'
        + 'Так быстрее: определять страны для всех сразу долго и обычно не нужно.';
    container.appendChild(note);
    return;
  }

  let countries = state.countries.slice();
  if (countrySort === 'ping') {
    countries.sort((a, b) => (a.bestLatency ?? 99999) - (b.bestLatency ?? 99999));
  } else if (countrySort === 'count') {
    countries.sort((a, b) => b.count - a.count);
  } else {
    countries.sort((a, b) => (a.name || a.code).localeCompare(b.name || b.code));
  }

  // Строка «Авто»
  const auto = document.createElement('div');
  auto.className = 'country-item' + (state.selectedCountry ? '' : ' selected');
  const total = countries.reduce((sum, c) => sum + c.count, 0);
  auto.innerHTML = `
    <div class="country-flag">🌐</div>
    <div class="country-info">
      <div class="country-name">Авто — быстрейший сервер</div>
      <div class="country-meta">${total} прокси во всех странах</div>
    </div>
    <div class="country-latency">auto</div>
  `;
  auto.addEventListener('click', () => selectCountry(null));
  container.appendChild(auto);

  const activeCode = state.active && state.active.exitCountry;
  for (const c of countries) {
    const item = document.createElement('div');
    item.className = 'country-item' + (state.selectedCountry === c.code ? ' selected' : '');
    const latency = c.bestLatency
      ? `<div class="country-latency${c.bestLatency < 500 ? ' fast' : ''}">${c.bestLatency} мс</div>`
      : '';
    item.innerHTML = `
      <div class="country-flag">${getFlagEmoji(c.code)}</div>
      <div class="country-info">
        <div class="country-name">${escapeHtml(c.name || c.code)}</div>
        <div class="country-meta">${c.count} прокси</div>
      </div>
      ${latency}
    `;
    item.title = 'Подключиться к быстрейшему серверу этой страны';
    item.addEventListener('click', () => selectCountry(c.code));
    container.appendChild(item);
  }
}

// ============ ДЕЙСТВИЯ ============

/**
 * Главная кнопка: подключиться / отключиться / отменить подключение.
 * Во время подбора прокси нажатие = отмена, а не блокировка кнопки.
 */
async function toggleConnection() {
  if (state.connecting) {
    const btn = document.getElementById('btnText');
    btn.textContent = 'Отменяем…';
    await sendMessage({ action: 'cancelConnect' });
    await loadState();
    return;
  }
  const resp = await sendMessage({ action: 'toggle' });
  if (!resp.ok && resp.error) showError(resp.error);
  await loadState();
}

async function selectCountry(code) {
  const resp = await sendMessage({ action: 'switchCountry', country: code });
  if (resp.ok) {
    // switchCountry при выключенном прокси только запоминает выбор —
    // подключим сразу, чтобы выбор страны сразу давал эффект.
    const st = await sendMessage({ action: 'getState' });
    if (st.ok && !st.enabled) {
      await sendMessage({ action: 'connect', country: code });
    }
  } else if (resp.error) {
    showError(resp.error);
  }
  await loadState();
}

async function connectToProxy(proxyUrl) {
  const resp = await sendMessage({ action: 'connectTo', proxy: proxyUrl });
  if (!resp.ok && resp.error) showError(resp.error);
  await loadState();
}

async function refreshList() {
  const btn = document.getElementById('refreshBtn');
  btn.classList.add('spinning');
  const resp = await sendMessage({ action: 'refresh' });
  btn.classList.remove('spinning');
  if (resp.ok) {
    await loadState();
  } else {
    showError(resp.error || 'Не удалось обновить список');
  }
}

/** Загрузка списка, встроенного в пакет расширения (подготовлен анализатором). */
async function loadBundledList() {
  const btn = document.getElementById('bundledBtn');
  const prev = btn.textContent;
  btn.textContent = 'Загружаем…';
  const resp = await sendMessage({ action: 'loadBundled' });
  btn.textContent = prev;
  if (resp.ok) {
    await loadState();
  } else {
    showError('Встроенный список недоступен: ' + resp.error);
  }
}

/**
 * Аварийный сброс. Нужен, когда прокси уже включён, сеть не работает
 * и обычный «Отключиться» не помогает: снимаем настройку напрямую
 * в браузере, игнорируя наше собственное состояние.
 */
async function emergencyReset() {
  const hint = document.getElementById('emergencyHint');
  const btn = document.getElementById('emergencyBtn');
  btn.disabled = true;
  hint.style.color = '';
  hint.textContent = 'Сбрасываем…';
  const resp = await sendMessage({ action: 'emergencyReset' });
  btn.disabled = false;
  if (resp && resp.ok) {
    hint.style.color = '#22c55e';
    hint.textContent = resp.browserCleared
      ? '✓ Прокси снят, сеть восстановлена'
      : '✓ Состояние сброшено';
    setTimeout(() => { hint.textContent = ''; }, 5000);
  } else {
    hint.style.color = '#f87171';
    hint.textContent = 'Не удалось: ' + ((resp && resp.error) || 'нет ответа');
  }
  await loadState();
}

async function checkNow() {
  const btn = document.getElementById('checkBtn');
  btn.disabled = true;
  const resp = await sendMessage({ action: 'checkNow' });
  if (resp.ok) {
    await loadState();
  } else {
    showError(resp.error || 'Прокси не отвечает');
    await loadState();
  }
}
function handleImport(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = async (e) => {
    const text = String(e.target.result || '');
    let payload = text;
    try {
      payload = JSON.parse(text);
    } catch {
      // не JSON — сырой текст с ip:port по строке
    }
    const resp = await sendMessage({ action: 'import', data: payload });
    if (resp.ok) {
      await loadState();
      // Раньше импорт проходил молча — было непонятно, сработал он или нет.
      showNotice(`✓ Импортировано прокси: ${resp.count}`, true);
    } else {
      showError(resp.error || 'Ошибка импорта');
    }
  };
  reader.readAsText(file);
  event.target.value = '';
}
