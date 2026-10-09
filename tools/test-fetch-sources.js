/*
 * Интеграционный тест: скачивает публичные списки так же, как это делает
 * service worker в гибридном режиме, и проверяет, что парсер извлекает
 * прокси. Запуск: node tools/test-fetch-sources.js
 */
const path = require('path');
const { DIRECT_SOURCES, parseProxyText } = require(
  path.join(__dirname, '..', 'extension', 'lib', 'sources.js')
);

(async () => {
  const seen = new Set();
  for (const src of DIRECT_SOURCES) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 15000);
    try {
      const resp = await fetch(src.url, { signal: ctrl.signal });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const text = await resp.text();
      const set = parseProxyText(text, src.defaultProtocol);
      for (const u of set) seen.add(u);
      console.log(`OK   ${src.name}: ${set.size} прокси`);
    } catch (err) {
      console.log(`FAIL ${src.name}: ${err.message}`);
    } finally {
      clearTimeout(timer);
    }
  }
  console.log(`\nИтого уникальных прокси из прямых источников: ${seen.size}`);
  const sample = [...seen].slice(0, 5);
  console.log('Примеры:', sample.join(', '));
  process.exit(seen.size > 100 ? 0 : 1);
})();
