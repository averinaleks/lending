(function () {
  'use strict';

  var key = 'okoroleva.analytics.excluded.v1';
  var status = document.getElementById('analytics-status');
  var notice = document.getElementById('analytics-notice');
  var exclude = document.getElementById('analytics-exclude');
  var include = document.getElementById('analytics-include');
  if (!status || !notice || !exclude || !include) return;

  function showState(excluded) {
    status.dataset.state = excluded ? 'excluded' : 'included';
    status.textContent = excluded
      ? 'Посещения из этого браузера не учитываются.'
      : 'Посещения из этого браузера учитываются.';
    exclude.disabled = excluded;
    include.disabled = !excluded;
  }

  function showError() {
    status.dataset.state = 'error';
    status.textContent = 'Не удалось подтвердить настройку браузера.';
    notice.textContent = 'Хранилище браузера недоступно или не сохранило изменение. Разрешите хранение данных для этого сайта и повторите действие.';
    exclude.disabled = false;
    include.disabled = false;
  }

  function save(excluded) {
    try {
      if (excluded) window.localStorage.setItem(key, '1');
      else window.localStorage.removeItem(key);
      if ((window.localStorage.getItem(key) === '1') !== excluded) throw new Error('Preference not saved');
      showState(excluded);
      notice.textContent = 'Сохранено. Перезагрузите уже открытые страницы сайта, чтобы применить настройку.';
    } catch (error) {
      showError();
    }
  }

  exclude.addEventListener('click', function () { save(true); });
  include.addEventListener('click', function () { save(false); });
  try {
    showState(window.localStorage.getItem(key) === '1');
  } catch (error) {
    showError();
  }
}());
