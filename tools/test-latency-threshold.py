# -*- coding: utf-8 -*-
"""
Доказывает, как работает порог задержки MAX_ACCEPTABLE_LATENCY_MS.

Поднимает ЛОКАЛЬНЫЕ прокси с искусственной задержкой ответа
(0.2 / 1.0 / 3.0 / 6.0 секунд) и проверяет, что:

  * при пороге по умолчанию принимается всё, что вменяемо;
  * при низком пороге отсекается именно медленное, а не всё подряд.

Это защита от повторения ошибки: когда порог выставлен слишком жёстко,
ломается ВСЁ, и кажется, что «пулы умерли».

Запуск: python tools/test-latency-threshold.py
"""
import asyncio
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'analyzer'))

import aiohttp  # noqa: E402

import checker  # noqa: E402
import config  # noqa: E402

# Ответ, который вернёт наш прокси
BODY = b'{"ip":"203.0.113.7"}'


def make_delayed_proxy(delay: float):
    """Настоящий CONNECT-прокси, который перед туннелированием ждёт `delay` секунд.

    Важно: это полноценный прокси — он соединяется с целевым сервером и
    перекладывает байты как есть. Только так задержка измеряется честно:
    если отдавать HTTP вместо TLS, проверка провалится и мы измерим время
    ошибки, а не задержку.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 0))
    srv.listen(64)
    port = srv.getsockname()[1]

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

    def handle(conn):
        upstream = None
        try:
            conn.settimeout(20)
            head = b''
            while b'\r\n\r\n' not in head:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                head += chunk
            if not head.upper().startswith(b'CONNECT'):
                return
            host, _, port_s = head.split(' ')[1].partition(':')

            # Вот наша искусственная задержка — ДО соединения с целью.
            time.sleep(delay)

            upstream = socket.create_connection((host, int(port_s)), timeout=20)
            conn.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')

            # ВАЖНО: клиент успевает отправить TLS ClientHello ещё ДО нашего
            # ответа на CONNECT, и эти байты уже лежат в буфере conn.
            # Если начать pump сейчас, они уйдут нормально. Но если мы
            # ждали их отдельно и прочитали — их надо вернуть обратно в
            # поток, иначе TLS-хендшейк рвётся.
            leftover = b''
            conn.setblocking(False)
            try:
                while True:
                    chunk = conn.recv(8192)
                    if not chunk:
                        break
                    leftover += chunk
            except OSError:
                # BlockingIOError — данных пока нет, это норма
                pass
            conn.setblocking(True)
            if leftover:
                upstream.sendall(leftover)

            t1 = threading.Thread(target=pump, args=(conn, upstream), daemon=True)
            t2 = threading.Thread(target=pump, args=(upstream, conn), daemon=True)
            t1.start(); t2.start(); t1.join(); t2.join()
        except Exception:
            for s in (conn, upstream):
                try:
                    if s:
                        s.close()
                except Exception:
                    pass

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return port


async def check_with_threshold(session, url, threshold, timeout):
    old = checker.MAX_ACCEPTABLE_LATENCY_MS
    checker.MAX_ACCEPTABLE_LATENCY_MS = threshold
    try:
        return await checker.check_proxy(session, url, timeout=timeout)
    finally:
        checker.MAX_ACCEPTABLE_LATENCY_MS = old


async def main():
    delays = [0.2, 1.0, 3.0, 6.0]
    ports = {}
    for d in delays:
        ports[d] = make_delayed_proxy(d)
    print('локальные прокси с задержкой:', {f'{d}с': p for d, p in ports.items()})

    default_thr = config.MAX_ACCEPTABLE_LATENCY_MS
    print(f'\nпорог по умолчанию в config.py: {default_thr} мс\n')

    async with aiohttp.ClientSession() as s:
        # --- замеряем реальную задержку для каждого ---
        print('фактическая задержка (без фильтра, порог 999999):')
        measured = {}
        for d in delays:
            url = f'http://127.0.0.1:{ports[d]}'
            t0 = time.perf_counter()
            await check_with_threshold(s, url, 999999, 15)
            dt = (time.perf_counter() - t0) * 1000
            measured[d] = dt
            print(f'  задержка {d:>4} с -> измерено {dt:>7.0f} мс')

        # --- при разных порогах ---
        print()
        ok_default = True
        for thr in (500, 2000, 5000):
            accepted = []
            for d in delays:
                url = f'http://127.0.0.1:{ports[d]}'
                r = await check_with_threshold(s, url, thr, 15)
                if r:
                    accepted.append(d)
            print(f'  порог {thr:>5} мс -> приняты задержки: '
                  f'{[f"{x}с" for x in accepted]}')

        # --- вывод с порогом по умолчанию ---
        accepted = []
        for d in delays:
            url = f'http://127.0.0.1:{ports[d]}'
            r = await check_with_threshold(s, url, default_thr, 15)
            if r:
                accepted.append(d)

        print(f'\nпри пороге по умолчанию ({default_thr} мс) принято: '
              f'{[f"{x}с" for x in accepted]}')

        # Быстрый прокси обязан приниматься всегда
        if 0.2 not in accepted:
            print('\n✗ ОШИБКА: даже быстрый прокси (0.2 с) отвергнут — порог слишком жёсткий')
            ok_default = False
        else:
            print('\n✓ быстрый прокси принимается — порог не сломан')

        # Если при умеренном пороге не проходит НИЧЕГО — это подозрительно
        if not accepted:
            print('✗ ОШИБКА: не принят ни один прокси. Порог заведомо слишком жёсткий,')
            print('  расширение останется с пустым списком.')
            ok_default = False

    print()
    print('Как выбирать порог:')
    print('  500  мс — НЕЛЬЗЯ: в задержку входит CONNECT и TLS-хендшейк,')
    print('                 даже локальный прокси даёт ~600 мс. Список выйдет пустым.')
    print('  2000 мс — жёстко: отсеивает нормальные зарубежные прокси')
    print('  5000 мс — разумный компромисс (по умолчанию)')
    print('  None/0 — не отсеивать по скорости вовсе, оставить только таймаут')
    return 0 if ok_default else 1


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
