function sendMessage(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (resp) => resolve(resp || { ok: false, error: 'нет ответа' }));
  });
}

function setStatus(el, text, ok) {
  el.textContent = text;
  el.className = 'status-line ' + (ok ? 'ok' : 'err');
}

document.addEventListener('DOMContentLoaded', async () => {
  const resp = await sendMessage({ action: 'getSettings' });
  if (resp.ok) {
    document.getElementById('listUrl').value = resp.settings.listUrl || '';
    document.getElementById('mode').value = resp.settings.mode || 'auto';
    document.getElementById('timeout').value = resp.settings.testTimeoutMs || 10000;
    document.getElementById('failSafe').checked = resp.settings.failSafe !== false;
    document.getElementById('allowHttpOnly').checked = !!resp.settings.allowHttpOnly;
    if (resp.license && resp.license.key) {
      document.getElementById('licenseKey').value = resp.license.key;
    }
    renderProStatus(resp.license);
  }

  document.getElementById('saveBtn').addEventListener('click', async () => {
    const settings = {
      listUrl: document.getElementById('listUrl').value.trim(),
      mode: document.getElementById('mode').value,
      testTimeoutMs: Number(document.getElementById('timeout').value) || 10000,
      failSafe: document.getElementById('failSafe').checked,
      allowHttpOnly: document.getElementById('allowHttpOnly').checked
    };
    const saveResp = await sendMessage({ action: 'setSettings', settings });
    const el = document.getElementById('saveStatus');
    if (saveResp.ok) {
      setStatus(el, '✓ Настройки сохранены', true);
    } else {
      setStatus(el, saveResp.error || 'Ошибка сохранения', false);
    }
  });

  document.getElementById('resetBtn').addEventListener('click', async () => {
    const el = document.getElementById('diagStatus');
    setStatus(el, 'Сбрасываем…', true);
    const r = await sendMessage({ action: 'emergencyReset' });
    if (r.ok) {
      setStatus(el, r.browserCleared ? '✓ Прокси снят, сеть восстановлена' : '✓ Состояние сброшено', true);
    } else {
      setStatus(el, r.error || 'Не удалось сбросить', false);
    }
  });

  document.getElementById('reconcileBtn').addEventListener('click', async () => {
    const el = document.getElementById('diagStatus');
    const r = await sendMessage({ action: 'reconcile' });
    if (!r.ok) {
      setStatus(el, r.error || 'Ошибка проверки', false);
    } else if (r.cleared) {
      setStatus(el, '⚠ Найден прокси, оставшийся в браузере — снят автоматически', true);
    } else {
      setStatus(el, '✓ Всё сходится: состояние расширения и браузера совпадает', true);
    }
  });

  document.getElementById('activateBtn').addEventListener('click', async () => {
    const key = document.getElementById('licenseKey').value.trim();
    const el = document.getElementById('licenseStatus');
    if (!key) {
      setStatus(el, 'Введите ключ', false);
      return;
    }
    const resp2 = await sendMessage({ action: 'activateLicense', key });
    if (resp2.ok) {
      setStatus(el, '✓ PRO активирован', true);
    } else {
      setStatus(el, resp2.error || 'Ошибка активации', false);
    }
    renderProStatus(resp2.license);
  });
});

function renderProStatus(license) {
  const el = document.getElementById('proStatus');
  if (license && license.valid) {
    el.textContent = '✓ PRO активирован. После запуска платных серверов вы автоматически получите доступ к быстрым приватным прокси.';
    el.style.color = '#22c55e';
  } else {
    el.textContent = 'PRO-версия откроет доступ к быстрым приватным серверам (планируется). Ключ можно будет приобрести после запуска.';
    el.style.color = '';
  }
}
