/*
 * SwapIP — unit-тесты чистой логики lib/sources.js (запуск: node tools/test-sources.js).
 * Проверяют нормализацию всех входных форматов и парсинг текстовых списков.
 */
const path = require('path');
const {
  DIRECT_SOURCES,
  normalizeProxy,
  parseProxyText,
  toCompactEntries,
  isValidIpv4,
  isValidPort
} = require(path.join(__dirname, '..', 'extension', 'lib', 'sources.js'));

let passed = 0;
let failed = 0;

function assertEq(actual, expected, label) {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a === b) {
    passed++;
  } else {
    failed++;
    console.error(`FAIL ${label}\n  expected: ${b}\n  actual:   ${a}`);
  }
}

// --- isValidIpv4 / isValidPort ---
assertEq(isValidIpv4('192.168.1.1'), true, 'ipv4 ok');
assertEq(isValidIpv4('256.1.1.1'), false, 'ipv4 octet >255');
assertEq(isValidIpv4('1.2.3'), false, 'ipv4 short');
assertEq(isValidIpv4('a.b.c.d'), false, 'ipv4 letters');
assertEq(isValidPort('8080'), true, 'port ok');
assertEq(isValidPort('0'), false, 'port 0');
assertEq(isValidPort('70000'), false, 'port >65535');

// --- normalizeProxy: поддерживаемые форматы ---
assertEq(normalizeProxy('1.2.3.4:8080'), 'http://1.2.3.4:8080', 'ip:port');
assertEq(normalizeProxy('http://1.2.3.4:8080'), 'http://1.2.3.4:8080', 'http://ip:port');
assertEq(normalizeProxy('SOCKS5://5.6.7.8:1080'), 'socks5://5.6.7.8:1080', 'socks5 upper');
assertEq(normalizeProxy('socks4://5.6.7.8:1080'), 'socks4://5.6.7.8:1080', 'socks4');
assertEq(
  normalizeProxy('http://user:pass@1.2.3.4:3128'),
  'http://user:pass@1.2.3.4:3128',
  'user:pass@'
);
assertEq(
  normalizeProxy('1.2.3.4:3128:myuser:mypass'),
  'http://myuser:mypass@1.2.3.4:3128',
  'ip:port:user:pass'
);
assertEq(normalizeProxy('1.2.3.4:8080 http'), 'http://1.2.3.4:8080', 'trailing protocol');
assertEq(normalizeProxy('socks5 9.9.9.9 1080'), 'socks5://9.9.9.9:1080', 'spaced protocol');
assertEq(normalizeProxy('"1.2.3.4:80"'), 'http://1.2.3.4:80', 'quoted');
assertEq(normalizeProxy('proxy.example.com:8080'), null, 'hostname not supported');
assertEq(normalizeProxy('999.1.1.1:80'), null, 'bad ip rejected');
assertEq(normalizeProxy('1.2.3.4:0'), null, 'bad port rejected');
assertEq(normalizeProxy(''), null, 'empty');
assertEq(normalizeProxy('# comment'), null, 'comment');
assertEq(normalizeProxy('ftp://1.2.3.4:21'), null, 'unsupported protocol');

// --- parseProxyText ---
const sample = [
  '# список',
  '1.2.3.4:8080',
  'socks5://5.6.7.8:1080',
  '1.2.3.4:8080',            // дубликат — должен схлопнуться
  'garbage line',
  'http://user:pass@10.0.0.1:3128'
].join('\n');
const parsed = parseProxyText(sample);
assertEq(parsed.size, 3, 'parse dedupes');
assertEq(parsed.has('http://1.2.3.4:8080'), true, 'parse has http');
assertEq(parsed.has('socks5://5.6.7.8:1080'), true, 'parse has socks5');
assertEq(parsed.has('http://user:pass@10.0.0.1:3128'), true, 'parse has auth');

// --- toCompactEntries ---
const entries = toCompactEntries(parsed, {});
assertEq(entries.length, 3, 'entries count');
assertEq(entries.every((e) => e.l === null && e.c === '' && e.a === 'unknown'), true, 'entries defaults');

// --- DIRECT_SOURCES sanity ---
assertEq(DIRECT_SOURCES.length >= 5, true, 'enough direct sources');
assertEq(DIRECT_SOURCES.every((s) => s.url.startsWith('https://')), true, 'sources https');

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
