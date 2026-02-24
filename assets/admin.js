(function () {
  'use strict';

  if (typeof AuthForgeLoginSecurity === 'undefined') {
    return;
  }

  const modal = document.getElementById('authforge-login-security-modal');
  if (!modal) {
    return;
  }

  const openBtn = document.getElementById('authforge-login-security-open-setup');
  const closeBtn = document.getElementById('authforge-login-security-close');
  const setupStep = document.getElementById('authforge-login-security-setup-step');
  const backupStep = document.getElementById('authforge-login-security-backup-step');
  const verifyBtn = document.getElementById('authforge-login-security-verify');
  const otpInput = document.getElementById('authforge-login-security-otp');
  const qrBox = document.getElementById('authforge-login-security-qr');
  const secretText = document.getElementById('authforge-login-security-secret');
  const message = document.getElementById('authforge-login-security-message');
  const backupList = document.getElementById('authforge-login-security-backup-list');
  const copyBtn = document.getElementById('authforge-login-security-copy-backups');
  const regenBtn = document.getElementById('authforge-login-security-regen-backups');
  const disableBtn = document.getElementById('authforge-login-security-disable');
  const statusText = document.getElementById('authforge-login-security-status-text');
  const backupCount = document.getElementById('authforge-login-security-backup-count');

  function setMessage(text, isError) {
    message.textContent = text || '';
    message.classList.toggle('is-error', !!isError);
  }

  function openModal() {
    modal.hidden = false;
  }

  function closeModal() {
    modal.hidden = true;
    setMessage('');
  }

  function resetModalForSetup() {
    setupStep.hidden = false;
    backupStep.hidden = true;
    backupList.innerHTML = '';
    otpInput.value = '';
    setMessage(AuthForgeLoginSecurity.i18n.loading);
    qrBox.innerHTML = '';
    secretText.textContent = '';
  }

  function showBackups(codes, successText) {
    setupStep.hidden = true;
    backupStep.hidden = false;
    backupList.innerHTML = '';

    codes.forEach(function (code) {
      const li = document.createElement('li');
      li.textContent = code;
      backupList.appendChild(li);
    });

    setMessage(successText || '');
  }

  async function post(action, payload) {
    const body = new URLSearchParams();
    body.set('action', action);
    body.set('user_id', AuthForgeLoginSecurity.userId);
    body.set('nonce', AuthForgeLoginSecurity.nonce);

    Object.keys(payload || {}).forEach(function (key) {
      body.set(key, payload[key]);
    });

    const res = await fetch(AuthForgeLoginSecurity.ajaxUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
      body: body.toString()
    });

    const data = await res.json();
    if (!data || !data.success) {
      throw new Error((data && data.data && data.data.message) || AuthForgeLoginSecurity.i18n.error);
    }

    return data.data;
  }

  async function startSetup() {
    openModal();
    resetModalForSetup();

    try {
      const data = await post(AuthForgeLoginSecurity.actions.startSetup, {});
      qrBox.innerHTML = '';
      if (window.jQuery && typeof window.jQuery.fn.qrcode === 'function') {
        window.jQuery(qrBox).qrcode({
          width: 200,
          height: 200,
          text: data.otpauthUri
        });
      }
      secretText.textContent = data.secret;
      setMessage('');
      otpInput.focus();
    } catch (err) {
      setMessage(err.message, true);
    }
  }

  async function verifySetup() {
    const otp = (otpInput.value || '').trim();
    if (!/^\d{6}$/.test(otp)) {
      setMessage(AuthForgeLoginSecurity.i18n.otpPlaceholder, true);
      return;
    }

    setMessage(AuthForgeLoginSecurity.i18n.loading);

    try {
      const data = await post(AuthForgeLoginSecurity.actions.confirmSetup, { otp: otp });
      showBackups(data.backupCodes || [], AuthForgeLoginSecurity.i18n.setupSuccess);
      statusText.textContent = AuthForgeLoginSecurity.i18n.enabledText || 'Enabled';
      backupCount.textContent = String(data.backupCount || 0);
      regenBtn.disabled = false;
      disableBtn.disabled = false;
    } catch (err) {
      setMessage(err.message, true);
    }
  }

  async function regenerateBackups() {
    openModal();
    setupStep.hidden = true;
    backupStep.hidden = true;
    setMessage(AuthForgeLoginSecurity.i18n.loading);

    try {
      const data = await post(AuthForgeLoginSecurity.actions.regenerateBackup, {});
      showBackups(data.backupCodes || [], AuthForgeLoginSecurity.i18n.regenSuccess);
      backupCount.textContent = String(data.backupCount || 0);
    } catch (err) {
      setMessage(err.message, true);
    }
  }

  async function disableTwoFA() {
    if (!window.confirm(AuthForgeLoginSecurity.i18n.disableConfirm)) {
      return;
    }

    try {
      const data = await post(AuthForgeLoginSecurity.actions.disableTwoFa, {});
      statusText.textContent = AuthForgeLoginSecurity.i18n.disabledText || 'Disabled';
      backupCount.textContent = String(data.backupCount || 0);
      regenBtn.disabled = true;
      disableBtn.disabled = true;
      setMessage('');
      closeModal();
    } catch (err) {
      window.alert(err.message);
    }
  }

  async function copyBackupCodes() {
    const items = Array.prototype.slice.call(backupList.querySelectorAll('li'));
    if (!items.length) {
      return;
    }

    const text = items.map(function (item) {
      return item.textContent || '';
    }).join('\n');

    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const temp = document.createElement('textarea');
        temp.value = text;
        temp.setAttribute('readonly', 'readonly');
        temp.style.position = 'fixed';
        temp.style.opacity = '0';
        document.body.appendChild(temp);
        temp.focus();
        temp.select();
        document.execCommand('copy');
        document.body.removeChild(temp);
      }
      setMessage(AuthForgeLoginSecurity.i18n.copySuccess || 'Copied.');
    } catch (err) {
      setMessage(AuthForgeLoginSecurity.i18n.copyError || 'Copy failed.', true);
    }
  }

  openBtn.addEventListener('click', startSetup);
  verifyBtn.addEventListener('click', verifySetup);
  regenBtn.addEventListener('click', regenerateBackups);
  disableBtn.addEventListener('click', disableTwoFA);
  copyBtn.addEventListener('click', copyBackupCodes);
  closeBtn.addEventListener('click', closeModal);

  modal.addEventListener('click', function (e) {
    if (e.target && e.target.getAttribute('data-close') === '1') {
      closeModal();
    }
  });
})();
