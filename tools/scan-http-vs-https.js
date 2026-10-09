/*
 * Сравнение: сколько прокси работает по HTTP и сколько по HTTPS (CONNECT).
 *
 * Разница и есть та самая причина ошибок в Chrome:
 * прокси, которые отвечают на HTTP, но не умеют CONNECT, ломают любой
 * защищённый сайт (ERR_CONNECTION_CLOSED), и именно они раньше доходили
 * до пользователя как «рабочие».
 *
 * Запуск: node tools/scan-http-vs-https.js [сколько]
 */
const { ProxyAgent, Agent, fetch: uf } = require('./node_modules/undici');

const LIMIT = Number(process.argv[2] || 120);

const SOURCES = [
  'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
  'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt'
];

function withTimeout(ms) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  return { signal: c.signal, done: () => clearTimeout(t) };
}

async function testHttp(p) {
  const { signal, done } = withTimeout(9000);
  const t = Date.now();
  try {
    const r = await uf('http://api.ipify.org/?format=json', {
      dispatcher: new ProxyAgent({ uri: p, connectTimeout: 9000 }), signal
    });
    const body = await r.text();
    return { ok: r.ok, ms: Date.now() - t, ip: body.trim() };
  } catch (e) {
    return { ok: false, ms: Date.now() - t, err: e.message };
  } finally { done(); }
}

async function testHttps(p) {
  const { signal, done } = withTimeout(9000);
  const t = Date.now();
  try {
    const r = await uf('https://api.ipify.org/?format=json', {
      dispatcher: new ProxyAgent({
        uri: p, connectTimeout: 9000, requestTls: { rejectUnauthorized: false }
      }), signal
    });
    const body = await r.text();
    return { ok: r.ok, ms: Date.now() - t, ip: body.trim() };
  } catch (e) {
    return { ok: false, ms: Date.now() - t, err: e.message };
  } finally { done(); }
}

(async () => {
  const pool = new Set();
  for (const url of SOURCES) {
    try {
      const r = await uf(url);
      for (const line of (await r.text()).split(/\r?\n/)) {
        const m = line.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/);
        if (m) pool.add(`http://${m[1]}:${m[2]}`);
      }
    } catch (e) { console.error('источник недоступен:', e.message); }
  }

  const all = [...pool];
  const step = Math.max(1, Math.floor(all.length / LIMIT));
  const list = all.filter((_, i) => i % step === 0).slice(0, LIMIT);
  console.log(`Проверяем ${list.length} прокси из ${all.length}\n`);

  const httpOnly = [];
  let httpOk = 0;
  let httpsOk = 0;

  await Promise.all(list.map(async (p) => {
    const [h, s] = await Promise.all([testHttp(p), testHttps(p)]);
    if (h.ok) {
      httpOk++;
      if (s.ok) httpsOk++; else httpOnly.push({ p, ms: h.ms });
    }
  }));

  console.log(`Работают по HTTP:        ${httpOk} из ${list.length}`);
  console.log(`Работают по HTTPS:       ${httpsOk} из ${list.length}`);
  console.log(`Только HTTP (ломают Chrome): ${httpOnly.length}\n`);

  if (httpOnly.length) {
    console.log('Примеры HTTP-без-HTTPS (именно они дают ERR_CONNECTION_CLOSED):');
    for (const x of httpOnly.slice(0, 10)) console.log(`  ${x.p}  ${x.ms}ms`);
  }

  console.log('\nВывод: проверять нужно по HTTPS. Иначе в расширение попадают');
  console.log('прокси, которые ломают сеть на любом https:// сайте.');
})();
