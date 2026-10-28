/* 登录页交互：以 JSON 提交凭据，成功后跳转管理界面 */
(function () {
  'use strict';

  var form = document.getElementById('loginForm');
  var userEl = document.getElementById('username');
  var passEl = document.getElementById('password');
  var errEl = document.getElementById('loginError');
  var btn = document.getElementById('submitBtn');

  function showError(message) {
    errEl.textContent = message;
    errEl.hidden = false;
    btn.disabled = false;
    btn.textContent = '登 录';
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    errEl.hidden = true;
    btn.disabled = true;
    btn.textContent = '登录中...';

    fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: userEl.value, password: passEl.value })
    }).then(function (resp) {
      return resp.json().then(function (data) {
        return { status: resp.status, data: data };
      });
    }).then(function (result) {
      var ok = result.status >= 200 && result.status < 300 && result.data && result.data.ok;
      if (!ok) {
        showError((result.data && result.data.error) || '登录失败');
        passEl.value = '';
        passEl.focus();
        return;
      }
      window.location.replace((result.data && result.data.redirect) || '/');
    }).catch(function () {
      showError('网络错误，请稍后重试');
    });
  });
})();
