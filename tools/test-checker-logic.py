# -*- coding: utf-8 -*-
"""
Детерминированный тест логики analyzer/checker.py на ЛОКАЛЬНЫХ прокси.

Публичные пулы живут минутами, поэтому на них нельзя проверить правильность
логики — только факт «жив/мёртв». Здесь мы поднимаем три настоящих прокси
на localhost и проверяем, что checker ведёт себя правильно:

  1. HTTP-only прокси (понимает только абсолютные GET, без CONNECT)
     → должен быть ОТКЛОНЁН (именно он ломает Chrome: ERR_CONNECTION_CLOSED)
  2. MITM-прокси (делает CONNECT, но подсовывает свой сертификат)
     → должен быть ОТКЛОНЁН (NETERR_CERT_AUTHORITY_INVALID)
  3. Корректный CONNECT-прокси (пробрасывает TLS как есть)
     → должен быть ПРИНЯТ

Никакого интернета: цель — проверить решения, а не доступность пула.

Запуск: python tools/test-checker-logic.py
"""
import asyncio
import os
import socket
import ssl
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

import aiohttp

from checker import check_proxy

CONNECTED = threading.Event()
MITM_REQUESTS = []


def _recv_headers(sock):
    data = b''
    sock.settimeout(10)
    while b'\r\n\r\n' not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode('latin-1', errors='replace')


# ---------- 1. HTTP-only прокси ----------
def http_only_proxy(port_holder):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 0))
    srv.listen(64)
    port_holder.append(srv.getsockname()[1])
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=_handle_http_only, args=(conn,), daemon=True).start()


def _handle_http_only(conn):
    try:
        head = _recv_headers(conn)
        if not head:
            return
        method = head.split(' ')[0].upper()
        # CONNECT не поддерживаем — закрываем соединение.
        # Именно так ведёт себя большинство бесплатных HTTP-прокси.
        if method == 'CONNECT':
            conn.close()
            return
        # Абсолютный GET — отвечаем «как прокси» (в реальности тут MITM/подмена).
        body = b'{"ip":"1.2.3.4"}'
        conn.sendall(
            b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '
            + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body
        )
        conn.close()
    except Exception:
        pass


# ---------- 2. MITM-прокси: CONNECT есть, но сертификат свой ----------
def mitm_proxy(port_holder):
    # Генерируем самоподписанный сертификат для ipwho.is / api.ipify.org
    certfile, keyfile = _make_selfsigned()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 0))
    srv.listen(64)
    port_holder.append(srv.getsockname()[1])
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=_handle_mitm, args=(conn, ctx), daemon=True).start()


def _handle_mitm(conn, ctx):
    try:
        head = _recv_headers(conn)
        if not head.upper().startswith('CONNECT'):
            conn.close()
            return
        hostport = head.split(' ')[1]
        host, _, port = hostport.partition(':')
        conn.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
        # Отвечаем СВОИМ сертификатом — так и работает MITM-прокси.
        tls = ctx.wrap_socket(conn, server_side=True)
        try:
            tls.recv(4096)
            MITM_REQUESTS.append(host)
            body = b'{"ip":"9.9.9.9"}'
            tls.sendall(
                b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '
                + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body
            )
        finally:
            tls.close()
    except Exception:
        pass


def _make_selfsigned():
    """Самоподписанный сертификат для CN=ipwho.is (openssl на Windows может отсутствовать)."""
    import datetime
    d = os.path.join(os.environ.get('TEMP', '.'), 'swapip_mitm')
    os.makedirs(d, exist_ok=True)
    certfile = os.path.join(d, 'cert.pem')
    keyfile = os.path.join(d, 'key.pem')
    if os.path.exists(certfile) and os.path.exists(keyfile):
        return certfile, keyfile

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'ipwho.is'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'SwapIP MITM Test'),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u'ipwho.is'),
                                         x509.DNSName(u'api.ipify.org')]),
            critical=False,
        )
        # самоподписанный: CA=True, но цепочку доверия браузер не построит
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with open(certfile, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(keyfile, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    return certfile, keyfile


# ---------- 3. Корректный CONNECT-прокси ----------
def good_connect_proxy(port_holder):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 0))
    srv.listen(64)
    port_holder.append(srv.getsockname()[1])
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=_handle_good_connect, args=(conn,), daemon=True).start()


def _handle_good_connect(conn):
    try:
        head = _recv_headers(conn)
        if not head.upper().startswith('CONNECT'):
            conn.close()
            return
        hostport = head.split(' ')[1]
        host, _, port = hostport.partition(':')
        upstream = socket.create_connection((host, int(port)), timeout=10)
        conn.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
        # Пробрасываем байты в обе стороны как есть — TLS не трогаем.
        def pump(a, b):
            try:
                while True:
                    data = a.recv(8192)
                    if not data:
                        break
                    b.sendall(data)
            except Exception:
                pass
            finally:
                for s in (a, b):
                    try:
                        s.close()
                    except Exception:
                        pass
        t1 = threading.Thread(target=pump, args=(conn, upstream), daemon=True)
        t2 = threading.Thread(target=pump, args=(upstream, conn), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()
    except Exception:
        pass


async def main():
    ports = {}
    for name, fn in (('http', http_only_proxy), ('mitm', mitm_proxy), ('good', good_connect_proxy)):
        holder = []
        t = threading.Thread(target=fn, args=(holder,), daemon=True)
        t.start()
        for _ in range(100):
            if holder:
                break
            await asyncio.sleep(0.05)
        ports[name] = holder[0]
        print(f"  прокси '{name}' на 127.0.0.1:{ports[name]}")

    # Контрольный замер: убеждаемся, что MITM-прокси ДЕЙСТВИТЕЛЬНО перехватывает
    # соединение. Если и с отключённой проверкой сертификата он не отвечает,
    # его отклонение ничего не доказывает.
    print('\nКонтроль MITM (проверка сертификата ОТКЛЮЧЕНА):')
    mitm_url = f'http://127.0.0.1:{ports["mitm"]}'
    mitm_works = False
    try:
        conn = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=conn) as s:
            async with s.get('https://api.ipify.org/?format=json', proxy=mitm_url,
                             timeout=aiohttp.ClientTimeout(total=12)) as r:
                body = await r.text()
        mitm_works = True
        print(f"  MITM отвечает (сертификат не проверяем): {body[:60]}")
    except Exception as exc:  # noqa: BLE001
        print(f"  MITM не ответил даже без проверки: {type(exc).__name__}: {exc}")

    if not mitm_works:
        print('\n✗ Тест некорректен: MITM-прокси не перехватывает, отклонение ничего не доказывает.')
        sys.exit(1)

    print()
    results = {}
    async with aiohttp.ClientSession() as s:
        for name, port in ports.items():
            url = f'http://127.0.0.1:{port}'
            t0 = asyncio.get_event_loop().time()
            r = await check_proxy(s, url, timeout=12)
            dt = (asyncio.get_event_loop().time() - t0) * 1000
            results[name] = r
            status = 'ПРИНЯТ' if r else 'отклонён'
            print(f"{name:<10} {url:<26} {status:<10} {dt:>6.0f} мс")

    print()
    ok = True

    r = results['http']
    if r is not None:
        print('✗ FAIL: HTTP-only прокси принят — Chrome упал бы с ERR_CONNECTION_CLOSED')
        ok = False
    else:
        print('✓ PASS: HTTP-only прокси (без CONNECT) отклонён')

    r = results['mitm']
    if r is not None:
        print('✗ FAIL: MITM-прокси принят — Chrome показал бы NETERR_CERT_AUTHORITY_INVALID')
        ok = False
    else:
        print(f'✓ PASS: MITM-прокси отклонён (CONNECT был: {bool(MITM_REQUESTS)})')
        print(f'   MITM-сервер видел запросы к: {MITM_REQUESTS[:3] or "—"}')
        if not MITM_REQUESTS:
            print('   (отсеян на этапе CONNECT/handshake — тоже верно:')
            print('    Chrome показал бы ту же ошибку сертификата)')

    r = results['good']
    if r is None:
        print('✗ FAIL: корректный CONNECT-прокси отклонён (слишком строгий фильтр!)')
        ok = False
    else:
        print(f"✓ PASS: корректный CONNECT-прокси принят (exit={r['external_ip']})")

    print()
    if MITM_REQUESTS:
        print(f"MITM-прокси получил реальные CONNECT-запросы к: {MITM_REQUESTS[:3]}")
        print("Значит фильтр отбрасывает его именно за подмену сертификата, а не за «недоступен».")

    print('\nИТОГ:', 'все проверки пройдены' if ok else 'есть провалы')
    sys.exit(0 if ok else 1)


asyncio.run(main())
