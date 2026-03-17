// ==UserScript==
// @name         New API 渠道迁移（导出/导入）
// @namespace    https://github.com/
// @version      0.1.0
// @description  在 /console/channel 页面导出/导入渠道配置（支持可选导出 key，可能需要 2FA/安全验证）
// @match        *://*/console/channel*
// @run-at       document-start
// @grant        GM_addStyle
// @grant        GM_registerMenuCommand
// ==/UserScript==

(function () {
  'use strict';

  const APP = Object.freeze({
    NAME: 'New API 渠道迁移',
    VERSION: '0.3.4',
  });

  const UI = Object.freeze({
    PANEL_ID: 'newApiChannelMigratorPanel',
    MODAL_ID: 'newApiChannelMigratorModal',
    TOAST_ID: 'newApiChannelMigratorToast',
    Z_INDEX: 2147483647,
  });

  const API = Object.freeze({
    CHANNEL_LIST: '/api/channel/',
    CHANNEL_ONE: (id) => `/api/channel/${encodeURIComponent(String(id))}`,
    CREATE_CANDIDATES: ['/api/channel/', '/api/channel'],
  });

  const EXPORT = Object.freeze({
    FORMAT: 'new-api-channel-migrator',
    FORMAT_VERSION: 1,
    PAGE_SIZE: 100,
  });

  const TWOFA = Object.freeze({
    // TOTP usually changes every 30s.
    TOTP_STEP_MS: 30 * 1000,
  });

  const VERIFY = Object.freeze({
    VERIFY_PATH: '/api/verify',
    METHOD: '2fa',
    // If server does not return expires_at, use a safe short fallback.
    FALLBACK_SESSION_MS: 5 * 60 * 1000,
  });

  const DROP_FIELDS_DEFAULT = new Set([
    // Server/runtime fields - usually not needed for migration.
    'id',
    'created_time',
    'test_time',
    'response_time',
    'used_quota',
    'balance',
    'balance_updated_time',
  ]);

  const CREATE_WHITELIST = new Set([
    // Minimal required fields
    'type',
    'name',
    'key',
    // Common optional fields
    'openai_organization',
    'base_url',
    'other',
    'models',
    'max_input_tokens',
    'group',
    'groups',
    'model_mapping',
    'status_code_mapping',
    'priority',
    'weight',
    'status',
    'auto_ban',
    'multi_key_mode',
    'other_info',
    'tag',
    'settings',
    'setting',
    'test_model',
    'param_override',
    'header_override',
    'remark',
  ]);

  const state = {
    authHeaders: {},
    twofa: {
      code: '',
      expiresAt: 0,
    },
    verifySession: {
      // Server-side "security verify" window (to view key). Epoch ms.
      expiresAt: 0,
      // When /api/verify returns 429, avoid retry storm.
      rateLimitedUntil: 0,
    },
    // Small in-memory cache to avoid repeated key calls.
    keyCacheByChannelId: new Map(),
    uiReady: false,
  };

  // ----------------------------
  // Small helpers
  // ----------------------------

  function safeJsonParse(text, fallback) {
    try {
      return JSON.parse(text);
    } catch {
      return fallback;
    }
  }

  function nowIso() {
    return new Date().toISOString();
  }

  function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
  }

  function clamp(n, min, max) {
    return Math.max(min, Math.min(max, n));
  }

  function makeDraggable(targetEl, handleEl) {
    if (!targetEl || !handleEl) return;
    try {
      handleEl.style.cursor = 'move';
    } catch {
      // ignore
    }

    let dragging = false;
    let startX = 0;
    let startY = 0;
    let startLeft = 0;
    let startTop = 0;
    let boxW = 0;
    let boxH = 0;

    const onPointerDown = (e) => {
      try {
        if (e.button != null && e.button !== 0) return;
        if (e.target && e.target.closest && e.target.closest('button')) return;
        e.preventDefault();

        const rect = targetEl.getBoundingClientRect();
        startX = e.clientX;
        startY = e.clientY;
        startLeft = rect.left;
        startTop = rect.top;
        boxW = rect.width;
        boxH = rect.height;

        targetEl.style.position = 'fixed';
        targetEl.style.left = `${startLeft}px`;
        targetEl.style.top = `${startTop}px`;
        targetEl.style.right = 'auto';
        targetEl.style.bottom = 'auto';
        targetEl.style.transform = 'none';

        dragging = true;
        if (handleEl.setPointerCapture) handleEl.setPointerCapture(e.pointerId);
        document.documentElement.style.userSelect = 'none';
      } catch {
        // ignore
      }
    };

    const onPointerMove = (e) => {
      if (!dragging) return;
      try {
        const dx = e.clientX - startX;
        const dy = e.clientY - startY;

        const padding = 8;
        const left = clamp(startLeft + dx, padding, Math.max(padding, window.innerWidth - boxW - padding));
        const top = clamp(startTop + dy, padding, Math.max(padding, window.innerHeight - boxH - padding));

        targetEl.style.left = `${left}px`;
        targetEl.style.top = `${top}px`;
      } catch {
        // ignore
      }
    };

    const stop = () => {
      dragging = false;
      document.documentElement.style.userSelect = '';
    };

    handleEl.addEventListener('pointerdown', onPointerDown);
    handleEl.addEventListener('pointermove', onPointerMove);
    handleEl.addEventListener('pointerup', stop);
    handleEl.addEventListener('pointercancel', stop);
  }

  function toFileSafe(s) {
    return String(s).replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 80);
  }

  function h(tag, attrs, children) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v == null) continue;
        if (k === 'class') el.className = v;
        else if (k === 'style') el.setAttribute('style', v);
        else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, String(v));
      }
    }
    const list = Array.isArray(children) ? children : children == null ? [] : [children];
    for (const child of list) {
      if (child == null) continue;
      el.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
    }
    return el;
  }

  function toast(message, level) {
    try {
      const existing = document.getElementById(UI.TOAST_ID);
      if (existing) existing.remove();
      const el = h(
        'div',
        {
          id: UI.TOAST_ID,
          style: [
            'position:fixed',
            'right:16px',
            'bottom:16px',
            `z-index:${UI.Z_INDEX}`,
            'max-width:360px',
            'padding:10px 12px',
            'border-radius:10px',
            'font-size:13px',
            'line-height:1.4',
            'box-shadow:0 10px 30px rgba(0,0,0,.18)',
            `background:${level === 'error' ? '#fee2e2' : level === 'warn' ? '#fef3c7' : '#dcfce7'}`,
            'color:#111827',
          ].join(';'),
        },
        message
      );
      document.documentElement.appendChild(el);
      window.setTimeout(() => el.remove(), 3500);
    } catch {
      // ignore
    }
  }

  // ----------------------------
  // Auth headers capture (fetch/XHR)
  // ----------------------------

  function normalizeHeaderKey(k) {
    return String(k).toLowerCase();
  }

  function captureAuthHeadersFromObject(headersObj) {
    if (!headersObj) return;
    const next = { ...state.authHeaders };
    for (const [k, v] of Object.entries(headersObj)) {
      if (v == null) continue;
      const lk = normalizeHeaderKey(k).replace(/_/g, '-');
      if (lk === 'authorization') next.Authorization = String(v);
      if (lk === 'new-api-user') next['New-API-User'] = String(v);
    }
    state.authHeaders = next;
  }

  function captureAuthHeadersFromHeaders(headers) {
    if (!headers) return;
    const next = { ...state.authHeaders };
    try {
      const auth = headers.get ? headers.get('Authorization') : null;
      if (auth) next.Authorization = auth;
    } catch {
      // ignore
    }
    try {
      const user = headers.get ? headers.get('New-API-User') : null;
      if (user) next['New-API-User'] = user;
    } catch {
      // ignore
    }
    state.authHeaders = next;
  }

  function tryGetUserIdFromStorage() {
    // Page usually stores user info in localStorage.user
    const raw = localStorage.getItem('user');
    if (!raw) return null;
    const u = safeJsonParse(raw, null);
    if (!u || typeof u !== 'object') return null;
    if (u.id == null) return null;
    const n = Number(u.id);
    if (!Number.isFinite(n)) return null;
    return String(n);
  }

  function ensureNewApiUserHeader(headers) {
    const next = { ...headers };
    if (next['New-API-User']) return next;
    const id = tryGetUserIdFromStorage();
    if (id) next['New-API-User'] = id;
    return next;
  }

  function hookFetch() {
    if (typeof window.fetch !== 'function') return;
    const original = window.fetch.bind(window);
    window.fetch = async function (input, init) {
      try {
        const url = typeof input === 'string' ? input : input && input.url ? input.url : '';
        const headers = (init && init.headers) || (input && input.headers) || null;

        if (headers) {
          if (headers instanceof Headers) captureAuthHeadersFromHeaders(headers);
          else if (Array.isArray(headers)) captureAuthHeadersFromObject(Object.fromEntries(headers));
          else if (typeof headers === 'object') captureAuthHeadersFromObject(headers);
        }
      } catch {
        // ignore
      }
      return original(input, init);
    };
  }

  function hookXHR() {
    if (typeof window.XMLHttpRequest !== 'function') return;
    const proto = window.XMLHttpRequest.prototype;
    if (!proto) return;

    const originalOpen = proto.open;
    const originalSetRequestHeader = proto.setRequestHeader;
    const originalSend = proto.send;

    proto.open = function (method, url, ...rest) {
      try {
        this.__newApiMigratorMethod = String(method || 'GET').toUpperCase();
        this.__newApiMigratorUrl = String(url || '');
        this.__newApiMigratorHeaders = this.__newApiMigratorHeaders && typeof this.__newApiMigratorHeaders === 'object' ? this.__newApiMigratorHeaders : {};
      } catch {
        // ignore
      }
      return originalOpen.call(this, method, url, ...rest);
    };

    proto.setRequestHeader = function (k, v) {
      try {
        this.__newApiMigratorHeaders = this.__newApiMigratorHeaders && typeof this.__newApiMigratorHeaders === 'object' ? this.__newApiMigratorHeaders : {};
        this.__newApiMigratorHeaders[String(k)] = String(v);
        captureAuthHeadersFromObject(this.__newApiMigratorHeaders);
      } catch {
        // ignore
      }
      return originalSetRequestHeader.call(this, k, v);
    };

    proto.send = function (body) {
      return originalSend.call(this, body);
    };
  }

  hookFetch();
  hookXHR();

  // ----------------------------
  // API request helper
  // ----------------------------

  function buildAuthHeaders() {
    const base = {};
    if (state.authHeaders.Authorization) base.Authorization = state.authHeaders.Authorization;
    if (state.authHeaders['New-API-User']) base['New-API-User'] = state.authHeaders['New-API-User'];
    return ensureNewApiUserHeader(base);
  }

  async function apiCall(pathOrUrl, options) {
    const opts = options || {};
    const method = (opts.method || 'GET').toUpperCase();
    const url = (() => {
      try {
        return new URL(pathOrUrl, location.origin).toString();
      } catch {
        return String(pathOrUrl);
      }
    })();

    const headers = {
      Accept: 'application/json, text/plain, */*',
      ...buildAuthHeaders(),
      ...(opts.headers || {}),
    };

    const hasBody = opts.body != null && method !== 'GET' && method !== 'HEAD';
    let body = undefined;
    if (hasBody) {
      headers['Content-Type'] = headers['Content-Type'] || 'application/json';
      body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);
    }

    const resp = await fetch(url, {
      method,
      headers,
      body,
      credentials: 'include',
      cache: 'no-store',
    });

    const retryAfterSec = (() => {
      try {
        const raw = resp.headers && resp.headers.get ? resp.headers.get('Retry-After') : null;
        if (!raw) return 0;
        const n = Number(String(raw).trim());
        if (!Number.isFinite(n) || n <= 0) return 0;
        return n;
      } catch {
        return 0;
      }
    })();

    const text = await resp.text();
    const json = safeJsonParse(text, null);
    const parsed = parseNewApiResponse(json);
    const message = (() => {
      const m = String(parsed.message || '').trim();
      if (m) return m;
      const t = String(text || '').trim();
      if (!t) return '';
      // Keep it short to avoid spamming UI.
      if (t.length <= 240) return t;
      return t.slice(0, 240);
    })();
    return {
      ok: resp.ok && (parsed.success !== false),
      status: resp.status,
      retryAfterSec,
      url,
      rawText: text,
      json,
      success: parsed.success,
      data: parsed.data,
      message,
    };
  }

  function parseNewApiResponse(json) {
    // Common shapes:
    // 1) { success:boolean, data:any, message:string }
    // 2) { message:string, ... }
    // 3) { error:{ message:string } } or { error:string }
    if (json == null) return { success: null, data: null, message: '' };
    if (typeof json === 'string') return { success: null, data: null, message: json };
    if (typeof json !== 'object') return { success: null, data: json, message: '' };

    const message =
      typeof json.message === 'string'
        ? json.message
        : typeof json.msg === 'string'
          ? json.msg
          : typeof json.detail === 'string'
            ? json.detail
            : typeof json.error === 'string'
              ? json.error
              : json.error && typeof json.error === 'object' && typeof json.error.message === 'string'
                ? json.error.message
                : json.error && typeof json.error === 'object' && typeof json.error.detail === 'string'
                  ? json.error.detail
                  : '';

    const success = (() => {
      if ('success' in json) return json.success === true || json.success === 1 || json.success === 'true';
      if ('ok' in json) return json.ok === true || json.ok === 1 || json.ok === 'true';
      if ('error' in json && json.error) return false;
      return null;
    })();

    const data = 'data' in json ? json.data ?? null : json;
    return { success, data, message: String(message || '') };
  }

  function isLikelyNeed2fa(message) {
    const m = String(message || '').toLowerCase();
    return (
      m.includes('二步') ||
      m.includes('2fa') ||
      m.includes('验证码') ||
      m.includes('totp') ||
      m.includes('mfa') ||
      m.includes('安全验证') ||
      (m.includes('安全') && m.includes('验证')) ||
      m.includes('/verify') ||
      (m.includes('verify') && m.includes('code'))
    );
  }

  function isLikelyTwofaCodeInvalid(message) {
    const m = String(message || '').toLowerCase();
    return (
      (m.includes('验证码') || m.includes('code') || m.includes('totp') || m.includes('otp')) &&
      (m.includes('过期') || m.includes('invalid') || m.includes('无效') || m.includes('错误') || m.includes('失败'))
    );
  }

  function computeTotpExpiresAt(nowMs) {
    const step = TWOFA.TOTP_STEP_MS;
    const base = Math.floor(nowMs / step) * step;
    return base + step;
  }

  function getCachedTwofaCode() {
    const code = state.twofa && state.twofa.code ? String(state.twofa.code).trim() : '';
    const expiresAt = state.twofa && state.twofa.expiresAt ? Number(state.twofa.expiresAt) : 0;
    if (!code || !expiresAt) return null;
    if (Date.now() >= expiresAt) return null;
    return code;
  }

  function saveTwofaCode(code) {
    state.twofa.code = String(code || '').trim();
    state.twofa.expiresAt = computeTotpExpiresAt(Date.now());
  }

  function clearTwofaCode() {
    state.twofa.code = '';
    state.twofa.expiresAt = 0;
  }

  function getTwofaCode(promptTitle, forcePrompt) {
    const cached = getCachedTwofaCode();
    if (cached && !forcePrompt) return cached;
    const defaultValue = state.twofa && state.twofa.code ? String(state.twofa.code) : '';
    const input = window.prompt(`${promptTitle || '需要 2FA'}：请输入验证码（一般 6 位）`, defaultValue);
    if (!input) return null;
    const clean = String(input).trim();
    if (!clean) return null;
    saveTwofaCode(clean);
    return clean;
  }

  function buildTwofaHeaders(code) {
    return { 'X-2FA-Code': String(code || '').trim() };
  }

  function isVerifySessionValid() {
    const exp = state.verifySession && state.verifySession.expiresAt ? Number(state.verifySession.expiresAt) : 0;
    return Boolean(exp && Date.now() < exp);
  }

  function setVerifySessionExpiresAt(expiresAtMs) {
    const n = Number(expiresAtMs || 0);
    state.verifySession.expiresAt = Number.isFinite(n) && n > 0 ? n : 0;
  }

  function parseExpiresAtToMs(value) {
    if (value == null) return 0;
    if (typeof value === 'number' && Number.isFinite(value)) {
      // seconds or ms
      if (value > 1e12) return Math.floor(value);
      if (value > 1e9) return Math.floor(value * 1000);
      // small numbers: treat as "seconds from now"
      if (value > 0 && value < 60 * 60 * 24) return Date.now() + Math.floor(value * 1000);
      return 0;
    }
    if (typeof value === 'string') {
      const s = value.trim();
      if (!s) return 0;
      const asNum = Number(s);
      if (Number.isFinite(asNum)) return parseExpiresAtToMs(asNum);
      const t = Date.parse(s);
      if (Number.isFinite(t)) return t;
    }
    return 0;
  }

  function extractVerifyStatusInfo(res) {
    const data = res && res.data != null ? res.data : res && res.json != null ? res.json : null;
    if (data == null) return { verified: null, expiresAtMs: 0 };
    if (typeof data === 'boolean') return { verified: data, expiresAtMs: 0 };
    if (typeof data !== 'object') return { verified: null, expiresAtMs: 0 };

    const verified =
      'verified' in data ? Boolean(data.verified) : 'ok' in data ? Boolean(data.ok) : 'status' in data ? Boolean(data.status) : null;

    const expiresRaw =
      data.expires_at ?? data.expire_at ?? data.expired_at ?? data.expiresAt ?? data.expireAt ?? data.expiredAt ?? data.expire_time ?? null;
    const expiresAtMs = parseExpiresAtToMs(expiresRaw);
    return { verified, expiresAtMs };
  }

  async function doVerifyWithCodeBestEffort(code) {
    const clean = String(code || '').trim();
    if (!clean) return { ok: false, message: '你没填验证码' };

    // Primary: new-api uses POST /api/verify { method: "2fa", code: "xxxxxx" }
    const primaryBody = { method: VERIFY.METHOD, code: clean };
    const primary = await apiCall(VERIFY.VERIFY_PATH, { method: 'POST', body: primaryBody, headers: buildTwofaHeaders(clean) });

    if (primary.ok) {
      const info = extractVerifyStatusInfo(primary);
      setVerifySessionExpiresAt(info.expiresAtMs || Date.now() + VERIFY.FALLBACK_SESSION_MS);
      return { ok: true, message: primary.message || '验证成功' };
    }

    if (primary.status === 429) {
      const retryMs = Math.max(15 * 1000, Number(primary.retryAfterSec || 0) * 1000);
      state.verifySession.rateLimitedUntil = Date.now() + retryMs;
      return { ok: false, rateLimited: true, message: primary.message || '太快了，请稍后再试' };
    }
    if (isLikelyTwofaCodeInvalid(primary.message)) return { ok: false, invalidCode: true, message: primary.message || '验证码不对/过期' };

    const msgLower = String(primary.message || '').toLowerCase();
    const primaryUnsupported = primary.status === 404 || msgLower.includes('invalid url');
    if (primaryUnsupported) return { ok: false, unsupported: true, message: primary.message || '验证失败（接口不支持）' };
    return { ok: false, message: primary.message || `验证失败：${primary.status}` };
  }

  async function ensureVerifiedSessionForKey() {
    if (isVerifySessionValid()) return { ok: true, source: 'cache' };
    const rl = Number(state.verifySession.rateLimitedUntil || 0);
    if (rl && Date.now() < rl) {
      const waitSec = Math.max(1, Math.ceil((rl - Date.now()) / 1000));
      return { ok: false, rateLimited: true, message: `太快了，等 ${waitSec} 秒再试` };
    }

    const code = getTwofaCode('查看 key 需要验证码', false);
    if (!code) return { ok: false, message: '你没填验证码' };

    const first = await doVerifyWithCodeBestEffort(code);
    if (first.ok) return { ok: true, source: 'verify' };
    if (first.rateLimited) return first;
    if (first.invalidCode) {
      clearTwofaCode();
      const code2 = getTwofaCode('验证码可能过期了，再输一次', true);
      if (!code2) return { ok: false, message: '你没填验证码' };
      const second = await doVerifyWithCodeBestEffort(code2);
      if (!second.ok) return second;
      return { ok: true, source: 'verify' };
    }
    return first;
  }

  // ----------------------------
  // Channel list / detail
  // ----------------------------

  async function fetchAllChannels() {
    const all = [];
    let page = 1;
    for (;;) {
      const url = new URL(API.CHANNEL_LIST, location.origin);
      url.searchParams.set('p', String(page));
      url.searchParams.set('page_size', String(EXPORT.PAGE_SIZE));
      url.searchParams.set('id_sort', 'false');
      url.searchParams.set('tag_mode', 'false');

      const res = await apiCall(url.toString(), { method: 'GET' });
      if (!res.ok) {
        throw new Error(res.message || `拉渠道失败：${res.status}`);
      }
      const data = res.data || {};
      const items = Array.isArray(data.items) ? data.items : [];
      all.push(...items);
      const total = Number(data.total || 0);
      const pageSize = Number(data.page_size || EXPORT.PAGE_SIZE);
      if (!items.length) break;
      if (total && all.length >= total) break;
      if (items.length < pageSize) break;
      page += 1;
      if (page > 200) break; // safety
    }
    return all;
  }

  async function fetchChannelDetail(id) {
    const res = await apiCall(API.CHANNEL_ONE(id), { method: 'GET' });
    if (!res.ok) throw new Error(res.message || `拉渠道详情失败：${id}`);
    return res.data || null;
  }

  function pickExportFields(channel, mode) {
    if (!channel || typeof channel !== 'object') return null;
    if (mode === 'all') return { ...channel };
    // mode: config only
    const out = {};
    for (const [k, v] of Object.entries(channel)) {
      if (DROP_FIELDS_DEFAULT.has(k)) continue;
      out[k] = v;
    }
    return out;
  }

  // ----------------------------
  // Key export (fixed endpoints)
  // ----------------------------

  class RateLimitedError extends Error {
    constructor(message) {
      super(message);
      this.name = 'RateLimitedError';
    }
  }

  function buildChannelKeyPath(id) {
    return `/api/channel/${encodeURIComponent(String(id))}/key`;
  }

  async function requestChannelKeyOnce(id, extraHeaders) {
    const res = await apiCall(buildChannelKeyPath(id), { method: 'POST', body: null, headers: extraHeaders || null });
    const key = extractKeyFromResponse(res);
    if (res.ok && key) return { ok: true, key, res };
    return { ok: false, key: key || '', res };
  }

  function extractKeyFromResponse(res) {
    if (!res) return null;
    const data = res.data;
    if (typeof data === 'string' && data.trim()) return data.trim();
    if (data && typeof data === 'object') {
      if (typeof data.key === 'string' && data.key.trim()) return data.key.trim();
      if (typeof data.api_key === 'string' && data.api_key.trim()) return data.api_key.trim();
      if (typeof data.secret === 'string' && data.secret.trim()) return data.secret.trim();
    }
    const json = res.json;
    if (json && typeof json === 'object') {
      // Sometimes key is at top-level.
      if (typeof json.key === 'string' && json.key.trim()) return json.key.trim();
    }
    return null;
  }

  async function getChannelKey(id) {
    const cached = state.keyCacheByChannelId.get(String(id));
    if (cached) return cached;

    const first = await requestChannelKeyOnce(id, null);
    if (first.ok) {
      state.keyCacheByChannelId.set(String(id), first.key);
      return first.key;
    }

    // Need login / permission.
    if (first.res.status === 401) throw new Error(first.res.message || '没登录或没权限');

    const looksNeedVerify = first.res.status === 403 || isLikelyNeed2fa(first.res.message);
    if (!looksNeedVerify) throw new Error(first.res.message || '拿 key 失败');

    const verified = await ensureVerifiedSessionForKey();
    if (!verified.ok) {
      if (verified.rateLimited) throw new RateLimitedError(verified.message || '太快了，请稍后再试');

      // Older versions might not have /api/verify. Try per-request code.
      if (verified.unsupported) {
        const code = getTwofaCode('拿 key 需要验证码', false);
        if (!code) throw new Error('你没填验证码');
        const byCode = await requestChannelKeyOnce(id, buildTwofaHeaders(code));
        if (byCode.ok) {
          state.keyCacheByChannelId.set(String(id), byCode.key);
          return byCode.key;
        }
        throw new Error(byCode.res.message || '拿 key 失败');
      }
      throw new Error(verified.message || '安全验证失败');
    }

    const afterVerify = await requestChannelKeyOnce(id, null);
    if (afterVerify.ok) {
      state.keyCacheByChannelId.set(String(id), afterVerify.key);
      return afterVerify.key;
    }

    // Some versions still require X-2FA-Code on the key request.
    const stillNeedTwofa = afterVerify.res.status === 403 || isLikelyNeed2fa(afterVerify.res.message);
    if (stillNeedTwofa) {
      const cachedCode = getCachedTwofaCode();
      const code = cachedCode || getTwofaCode('拿 key 需要验证码', false);
      if (!code) throw new Error('你没填验证码');
      const byCode = await requestChannelKeyOnce(id, buildTwofaHeaders(code));
      if (byCode.ok) {
        state.keyCacheByChannelId.set(String(id), byCode.key);
        return byCode.key;
      }

      if (isLikelyTwofaCodeInvalid(byCode.res.message)) {
        clearTwofaCode();
        const code2 = getTwofaCode('验证码可能过期了，再输一次', true);
        if (!code2) throw new Error('你没填验证码');
        const byCode2 = await requestChannelKeyOnce(id, buildTwofaHeaders(code2));
        if (byCode2.ok) {
          state.keyCacheByChannelId.set(String(id), byCode2.key);
          return byCode2.key;
        }
        throw new Error(byCode2.res.message || '拿 key 失败');
      }

      throw new Error(byCode.res.message || '拿 key 失败');
    }

    throw new Error(afterVerify.res.message || '拿 key 失败');
  }

  // ----------------------------
  // Export / Download
  // ----------------------------

  function downloadJson(filename, obj) {
    const text = JSON.stringify(obj, null, 2);
    const blob = new Blob([text], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = h('a', { href: url, download: filename }, []);
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  async function doExportFlow() {
    toast('正在拉渠道列表…');
    const list = await fetchAllChannels();
    if (!list.length) {
      toast('没找到渠道', 'warn');
      return;
    }
    openExportModal(list);
  }

  // ----------------------------
  // Import / Create
  // ----------------------------

  function buildCreatePayload(ch) {
    const payload = {};
    for (const [k, v] of Object.entries(ch || {})) {
      if (!CREATE_WHITELIST.has(k)) continue;
      payload[k] = v;
    }
    payload.key = String(payload.key ?? '');
    return payload;
  }

  async function createChannel(payload) {
    let lastErr = null;
    const body = { mode: 'single', channel: payload };
    for (const path of API.CREATE_CANDIDATES) {
      const res = await apiCall(path, { method: 'POST', body });
      if (res.ok) return res.data;
      lastErr = new Error(res.message || `创建失败：${res.status}`);
      // If endpoint not found/invalid url, try next.
      if (res.status === 404) continue;
      if (res.message && String(res.message).toLowerCase().includes('invalid url')) continue;
      // For auth errors, stop early.
      if (res.status === 401 || res.status === 403) throw lastErr;
    }
    throw lastErr || new Error('创建失败');
  }

  async function doImportFlow() {
    openImportModal();
  }

  // ----------------------------
  // UI (Panel + Modal)
  // ----------------------------

  function ensureStyle() {
    const css = `
      #${UI.PANEL_ID} {
        position: fixed;
        right: 16px;
        top: 120px;
        z-index: ${UI.Z_INDEX};
        background: rgba(17, 24, 39, 0.92);
        color: #fff;
        border-radius: 12px;
        padding: 10px;
        width: 150px;
        font-size: 13px;
        box-shadow: 0 12px 30px rgba(0,0,0,.25);
      }
      #${UI.PANEL_ID} .panel-header{
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        margin-bottom: 6px;
      }
      #${UI.PANEL_ID} .panel-title{
        font-weight: 700;
        line-height: 1.2;
      }
      #${UI.PANEL_ID} .panel-close{
        width: 24px;
        height: 24px;
        border: 0;
        border-radius: 8px;
        background: rgba(255,255,255,.12);
        color: #fff;
        cursor: pointer;
        line-height: 24px;
        font-size: 16px;
      }
      #${UI.PANEL_ID} .panel-close:hover{ background: rgba(255,255,255,.18); }
      #${UI.PANEL_ID} .btn {
        width: 100%;
        margin: 6px 0;
        padding: 8px 10px;
        border: 0;
        border-radius: 10px;
        cursor: pointer;
        font-size: 13px;
      }
      #${UI.PANEL_ID} .btn-primary { background: #3b82f6; color: #fff; }
      #${UI.PANEL_ID} .btn-secondary { background: #10b981; color: #fff; }
      #${UI.PANEL_ID} .btn-ghost { background: rgba(255,255,255,.12); color: #fff; }
      #${UI.PANEL_ID} .muted { opacity: .85; font-size: 12px; line-height: 1.3; }

      #${UI.MODAL_ID} {
        position: fixed;
        inset: 0;
        z-index: ${UI.Z_INDEX};
        background: rgba(0,0,0,.45);
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 24px;
      }
      #${UI.MODAL_ID} .dialog {
        width: min(920px, 96vw);
        max-height: 86vh;
        overflow: auto;
        background: #fff;
        border-radius: 14px;
        box-shadow: 0 20px 60px rgba(0,0,0,.25);
        color: #111827;
      }
      #${UI.MODAL_ID} .header {
        padding: 14px 16px;
        border-bottom: 1px solid #e5e7eb;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
      }
      #${UI.MODAL_ID} .title { font-size: 15px; font-weight: 700; }
      #${UI.MODAL_ID} .close {
        border: 0;
        background: transparent;
        font-size: 18px;
        cursor: pointer;
        padding: 6px 8px;
      }
      #${UI.MODAL_ID} .body { padding: 16px; }
      #${UI.MODAL_ID} .footer {
        padding: 12px 16px;
        border-top: 1px solid #e5e7eb;
        display: flex;
        justify-content: flex-end;
        gap: 10px;
        flex-wrap: wrap;
      }
      #${UI.MODAL_ID} .action {
        border: 0;
        border-radius: 10px;
        padding: 8px 12px;
        cursor: pointer;
        font-size: 13px;
      }
      #${UI.MODAL_ID} .action.primary { background: #2563eb; color: #fff; }
      #${UI.MODAL_ID} .action.gray { background: #e5e7eb; color: #111827; }
      #${UI.MODAL_ID} .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
      #${UI.MODAL_ID} .card {
        border: 1px solid #e5e7eb;
        border-radius: 12px;
        padding: 12px;
        margin-top: 12px;
      }
      #${UI.MODAL_ID} .table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 8px;
        font-size: 13px;
      }
      #${UI.MODAL_ID} .table th, #${UI.MODAL_ID} .table td {
        border-bottom: 1px solid #f1f5f9;
        padding: 8px 6px;
        text-align: left;
        vertical-align: top;
      }
      #${UI.MODAL_ID} .badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 999px;
        background: #f1f5f9;
        font-size: 12px;
        color: #0f172a;
      }
      #${UI.MODAL_ID} input[type="text"]{
        padding: 6px 8px;
        border: 1px solid #e5e7eb;
        border-radius: 10px;
        min-width: 260px;
      }
      #${UI.MODAL_ID} .warn { color: #b45309; }
      #${UI.MODAL_ID} .error { color: #b91c1c; }
    `;
    if (typeof GM_addStyle === 'function') GM_addStyle(css);
    else {
      const style = h('style', {}, css);
      document.documentElement.appendChild(style);
    }
  }

  function closeModal() {
    const el = document.getElementById(UI.MODAL_ID);
    if (el) el.remove();
  }

  function showModal(title, bodyNode, actions) {
    closeModal();
    const header = h('div', { class: 'header' }, [
      h('div', { class: 'title' }, `${title}`),
      h('button', { class: 'close', onclick: closeModal, title: 'Close' }, '×'),
    ]);
    const dialog = h('div', { class: 'dialog' }, [
      header,
      h('div', { class: 'body' }, bodyNode),
      h('div', { class: 'footer' }, actions || []),
    ]);
    const modal = h('div', { id: UI.MODAL_ID }, [dialog]);
    document.documentElement.appendChild(modal);
    makeDraggable(dialog, header);
  }

  function ensurePanel() {
    if (state.uiReady) return;
    state.uiReady = true;
    ensureStyle();

    const existing = document.getElementById(UI.PANEL_ID);
    if (existing) return;

    const panel = h('div', { id: UI.PANEL_ID }, []);
    const header = h('div', { class: 'panel-header' }, [
      h('div', { class: 'panel-title' }, APP.NAME),
      h('button', { class: 'panel-close', title: 'Close', onclick: () => panel.remove() }, '×'),
    ]);

    panel.appendChild(header);
    panel.appendChild(h('div', { class: 'muted' }, `v${APP.VERSION}`));
    panel.appendChild(
      h(
        'button',
        {
          class: 'btn btn-primary',
          onclick: () => {
            doExportFlow().catch((e) => toast(String(e.message || e), 'error'));
          },
        },
        '导出 JSON'
      )
    );
    panel.appendChild(
      h(
        'button',
        {
          class: 'btn btn-secondary',
          onclick: () => {
            doImportFlow();
          },
        },
        '导入 JSON'
      )
    );
    panel.appendChild(
      h(
        'button',
        {
          class: 'btn btn-ghost',
          onclick: () => {
            openHelpModal();
          },
        },
        '说明'
      )
    );
    document.documentElement.appendChild(panel);
    makeDraggable(panel, header);
  }

  function openHelpModal() {
    const lines = [
      `当前站点：${location.origin}`,
      '学习接口：已关闭（只走固定 API）',
      `鉴权头：Authorization ${state.authHeaders.Authorization ? '有' : '无'}，New-API-User ${state.authHeaders['New-API-User'] ? '有' : '无'}`,
      '',
      '提示：',
      '1）导出“含 key”会做一次“安全验证”（可能要 2FA 验证码）',
      '   - 验证码只会缓存到它过期（一般 30 秒）',
      '   - 安全验证会在服务端记一会儿（看接口返回的 expires_at）',
      '2）导入默认“允许重复”，会直接新增渠道',
      '3）如果你退出登录/刷新，可能要重新登录',
    ];
    showModal(
      '说明',
      h('div', {}, [
        h('div', { class: 'card' }, [h('pre', { style: 'white-space:pre-wrap;margin:0;font-size:13px;' }, lines.join('\n'))]),
      ]),
      [h('button', { class: 'action gray', onclick: closeModal }, '关闭')]
    );
  }

  function openExportModal(channelList) {
    const rows = channelList.map((c) => {
      const id = c && c.id != null ? String(c.id) : '';
      const name = c && c.name != null ? String(c.name) : '';
      const group = c && c.group != null ? String(c.group) : '';
      const type = c && c.type != null ? String(c.type) : '';
      return { id, name, group, type };
    });

    const selected = new Set(rows.map((r) => r.id));
    let includeKey = false;
    let mode = 'config';
    const checkboxById = new Map();

    const table = h('table', { class: 'table' }, [
      h('thead', {}, [
        h('tr', {}, [
          h('th', {}, ''),
          h('th', {}, 'ID'),
          h('th', {}, '名称'),
          h('th', {}, '分组'),
          h('th', {}, '类型'),
        ]),
      ]),
      h(
        'tbody',
        {},
        rows.map((r) => {
          const checkbox = h('input', {
            type: 'checkbox',
            checked: true,
            onchange: (e) => {
              if (e.target.checked) selected.add(r.id);
              else selected.delete(r.id);
            },
          });
          checkboxById.set(r.id, checkbox);
          return h('tr', {}, [
            h('td', {}, [checkbox]),
            h('td', {}, r.id),
            h('td', {}, r.name),
            h('td', {}, r.group || '-'),
            h('td', {}, r.type || '-'),
          ]);
        })
      ),
    ]);

    const body = h('div', {}, [
      h('div', { class: 'row' }, [
        h(
          'button',
          {
            class: 'action gray',
            onclick: () => {
              selected.clear();
              for (const [id, box] of checkboxById.entries()) {
                box.checked = true;
                selected.add(id);
              }
            },
          },
          '全选'
        ),
        h(
          'button',
          {
            class: 'action gray',
            onclick: () => {
              selected.clear();
              for (const box of checkboxById.values()) box.checked = false;
            },
          },
          '全不选'
        ),
        h('span', { class: 'badge' }, `共 ${rows.length} 条`),
      ]),
      h('div', { class: 'card' }, [
        h('div', { class: 'row' }, [
          h('label', {}, [
            h('input', {
              type: 'checkbox',
              onchange: (e) => {
                includeKey = Boolean(e.target.checked);
              },
            }),
            ' 导出 key（可能需要验证码）',
          ]),
        ]),
        h('div', { style: 'margin-top:10px' }, [
          h('div', { style: 'font-weight:700;margin-bottom:6px' }, '导出内容'),
          h('label', { style: 'margin-right:14px' }, [
            h('input', {
              type: 'radio',
              name: 'exportMode',
              checked: true,
              onchange: () => {
                mode = 'config';
              },
            }),
            ' 只要配置（推荐）',
          ]),
          h('label', {}, [
            h('input', {
              type: 'radio',
              name: 'exportMode',
              onchange: () => {
                mode = 'all';
              },
            }),
            ' 全部字段',
          ]),
        ]),
        h('div', { class: 'muted', style: 'margin-top:8px' }, '提示：默认会自动去掉 id / 用量 / 余额 这些“搬家没用”的字段。'),
      ]),
      h('div', { class: 'card' }, [h('div', { style: 'font-weight:700' }, '选择要导出的渠道'), table]),
    ]);

    const actions = [
      h('button', { class: 'action gray', onclick: closeModal }, '取消'),
      h(
        'button',
        {
          class: 'action primary',
          onclick: async () => {
            try {
              const ids = Array.from(selected).filter(Boolean);
              if (!ids.length) {
                toast('你没选任何渠道', 'warn');
                return;
              }
              await exportSelected(ids, { includeKey, mode });
              closeModal();
            } catch (e) {
              toast(String(e.message || e), 'error');
            }
          },
        },
        '开始导出'
      ),
    ];

    showModal('导出渠道', body, actions);
  }

  async function exportSelected(ids, opts) {
    const includeKey = Boolean(opts && opts.includeKey);
    const mode = opts && opts.mode === 'all' ? 'all' : 'config';

    toast('正在拉渠道详情…');
    const channels = [];
    for (let i = 0; i < ids.length; i += 1) {
      const id = ids[i];
      const detail = await fetchChannelDetail(id);
      const picked = pickExportFields(detail, mode);
      if (!picked) continue;
      picked.__export_meta = { source_id: id };
      channels.push(picked);
      await sleep(30);
    }

    if (includeKey) {
      toast('正在拉 key…', 'warn');
      for (const ch of channels) {
        const id = ch && ch.__export_meta ? ch.__export_meta.source_id : null;
        if (!id) continue;
        try {
          const key = await getChannelKey(id);
          ch.key = key;
        } catch (e) {
          if (e && String(e.name || '') === 'RateLimitedError') throw e;
          // Keep empty key, but show warning.
          ch.key = ch.key || '';
          toast(`渠道 ${id} 的 key 失败：${String(e.message || e)}`, 'warn');
        }
        await sleep(60);
      }
    } else {
      // Ensure key exists as field (optional).
      for (const ch of channels) {
        if (!('key' in ch)) ch.key = '';
      }
    }

    const out = {
      format: EXPORT.FORMAT,
      format_version: EXPORT.FORMAT_VERSION,
      exported_at: nowIso(),
      source: { origin: location.origin, page: location.pathname },
      options: { include_key: includeKey, mode },
      channels,
    };
    const host = toFileSafe(location.host);
    const ts = toFileSafe(nowIso().replace(/[:.]/g, '-'));
    const filename = `channels_${host}_${ts}.json`;
    downloadJson(filename, out);
    toast('导出完成', 'ok');
  }

  function openImportModal() {
    const fileInput = h('input', {
      type: 'file',
      accept: 'application/json',
      onchange: async (e) => {
        const file = e.target.files && e.target.files[0] ? e.target.files[0] : null;
        if (!file) return;
        const text = await file.text();
        const json = safeJsonParse(text, null);
        const validated = validateImportJson(json);
        if (!validated.ok) {
          toast(validated.message, 'error');
          return;
        }
        const parsed = validated.data;
        const selected = new Set(parsed.channels.map((_, idx) => String(idx)));
        toast('文件读取成功');
        // Re-open modal to render table.
        closeModal();
        openImportModalWithData(parsed, selected);
      },
    });

    const body = h('div', {}, [
      h('div', { class: 'card' }, [
        h('div', { style: 'font-weight:700;margin-bottom:8px' }, '第 1 步：选择 JSON 文件'),
        fileInput,
        h('div', { class: 'muted', style: 'margin-top:8px' }, '提示：只支持本脚本导出的 JSON。'),
      ]),
    ]);

    showModal('导入渠道', body, [h('button', { class: 'action gray', onclick: closeModal }, '关闭')]);
  }

  function openImportModalWithData(parsed, selected) {
    const channels = parsed.channels || [];

    const countMissingKey = () =>
      channels
        .map((c, idx) => ({ c, idx }))
        .filter(({ c, idx }) => selected.has(String(idx)) && !String(c.key || '').trim()).length;

    const table = h('table', { class: 'table' }, [
      h('thead', {}, [
        h('tr', {}, [
          h('th', {}, ''),
          h('th', {}, '名称'),
          h('th', {}, '分组'),
          h('th', {}, '类型'),
          h('th', {}, 'key'),
        ]),
      ]),
      h(
        'tbody',
        {},
        channels.map((c, idx) => {
          const name = String(c.name || '');
          const hasKey = String(c.key || '').trim().length > 0;
          return h('tr', {}, [
            h('td', {}, [
              h('input', {
                type: 'checkbox',
                checked: true,
                onchange: (e) => {
                  if (e.target.checked) selected.add(String(idx));
                  else selected.delete(String(idx));
                },
              }),
            ]),
            h('td', {}, name || '-'),
            h('td', {}, String(c.group || '-') || '-'),
            h('td', {}, String(c.type || '-') || '-'),
            h('td', {}, hasKey ? '有' : h('span', { class: 'warn' }, '无')),
          ]);
        })
      ),
    ]);

    const body = h('div', {}, [
      h('div', { class: 'card' }, [
        h('div', { style: 'font-weight:700;margin-bottom:8px' }, '导入选项'),
        h('div', { class: 'row' }, [h('span', { class: 'badge' }, '允许重复：开（直接新增）')]),
        h('div', { class: 'muted', style: 'margin-top:8px' }, '提示：如果文件里没 key，就会按“空 key”去导入。'),
      ]),
      h('div', { class: 'card' }, [h('div', { style: 'font-weight:700' }, '选择要导入的渠道'), table]),
      h('div', { class: 'muted', style: 'margin-top:10px' }, `来源：${parsed.source && parsed.source.origin ? parsed.source.origin : '-'}`),
    ]);

    const actions = [
      h('button', { class: 'action gray', onclick: closeModal }, '取消'),
      h(
        'button',
        {
          class: 'action primary',
          onclick: async () => {
            const missing = countMissingKey();
            if (missing) toast(`有 ${missing} 条没 key，会按空 key 导入`, 'warn');
            const toImport = channels.map((c, idx) => ({ c, idx })).filter(({ idx }) => selected.has(String(idx))).map(({ c }) => c);
            if (!toImport.length) {
              toast('你没选任何渠道', 'warn');
              return;
            }
            const result = await importSelected(toImport);
            closeModal();
            const okCount = result && typeof result.okCount === 'number' ? result.okCount : 0;
            const failCount = result && typeof result.failCount === 'number' ? result.failCount : 0;
            const level = failCount ? 'warn' : 'ok';
            toast(`导入结束：成功 ${okCount}，失败 ${failCount}，马上刷新…`, level);
            window.setTimeout(() => location.reload(), 900);
          },
        },
        '开始导入'
      ),
    ];

    showModal('导入渠道（已读到文件）', body, actions);
  }

  function validateImportJson(json) {
    if (!json || typeof json !== 'object') return { ok: false, message: 'JSON 不是对象' };
    if (json.format !== EXPORT.FORMAT) return { ok: false, message: '不是本脚本导出的文件（format 不对）' };
    if (!Array.isArray(json.channels)) return { ok: false, message: 'channels 字段不对' };
    // Normalize data.
    const channels = json.channels
      .map((c) => (c && typeof c === 'object' ? c : null))
      .filter(Boolean)
      .map((c) => ({ ...c }));
    return {
      ok: true,
      data: {
        ...json,
        channels,
      },
    };
  }

  async function importSelected(channels) {
    toast('开始导入…', 'warn');

    let okCount = 0;
    let failCount = 0;
    for (let i = 0; i < channels.length; i += 1) {
      const ch = channels[i];
      const name = String(ch.name || '');
      try {
        const payload = buildCreatePayload(ch);
        if (!payload.name) throw new Error('缺 name');
        await createChannel(payload);
        okCount += 1;
        toast(`成功：${name}`);
      } catch (e) {
        failCount += 1;
        toast(`失败：${name}：${String(e.message || e)}`, 'error');
      }
      await sleep(120);
    }
    return { okCount, failCount };
  }

  // ----------------------------
  // Menu commands (optional)
  // ----------------------------

  function registerMenu() {
    if (typeof GM_registerMenuCommand !== 'function') return;
    try {
      GM_registerMenuCommand('导出渠道 JSON', () => doExportFlow().catch((e) => toast(String(e.message || e), 'error')));
      GM_registerMenuCommand('导入渠道 JSON', () => doImportFlow());
      GM_registerMenuCommand('说明', () => openHelpModal());
    } catch {
      // ignore
    }
  }

  // ----------------------------
  // Bootstrap UI at DOM ready
  // ----------------------------

  registerMenu();

  function onReady(fn) {
    if (document.readyState === 'complete' || document.readyState === 'interactive') fn();
    else document.addEventListener('DOMContentLoaded', fn, { once: true });
  }
  onReady(() => {
    // Only show UI on console/channel page (avoid match edge cases).
    if (!location.pathname.startsWith('/console/channel')) return;
    ensurePanel();
  });
})();
