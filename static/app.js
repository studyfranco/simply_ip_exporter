'use strict';

// ── Pure-JS SHA-256 / HMAC-SHA256 fallback ──────────────────────────────────
// `crypto.subtle` is only available in a secure context (HTTPS or localhost). Plain-HTTP LAN
// deployments (a pfSense box talking to this dashboard over the local network) are a documented
// use case, so signing must not simply fail there. This is a small, self-contained FIPS 180-4 /
// RFC 2104 implementation used only when `crypto.subtle` is unavailable.
const PureCrypto = (() => {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));

  function sha256(bytes) {
    let h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const bitLen = bytes.length * 8;
    const padded = bytes.slice();
    padded.push(0x80);
    while (padded.length % 64 !== 56) padded.push(0);
    for (let i = 7; i >= 0; i--) padded.push((bitLen / Math.pow(2, i * 8)) & 0xff);

    const w = new Array(64);
    for (let chunk = 0; chunk < padded.length; chunk += 64) {
      for (let i = 0; i < 16; i++) {
        w[i] = (padded[chunk + i * 4] << 24) | (padded[chunk + i * 4 + 1] << 16) |
               (padded[chunk + i * 4 + 2] << 8) | padded[chunk + i * 4 + 3];
      }
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (hh + S1 + ch + K[i] + w[i]) | 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h = [h[0] + a, h[1] + b, h[2] + c, h[3] + d, h[4] + e, h[5] + f, h[6] + g, h[7] + hh].map((x) => x | 0);
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      out[i * 4] = (h[i] >>> 24) & 0xff;
      out[i * 4 + 1] = (h[i] >>> 16) & 0xff;
      out[i * 4 + 2] = (h[i] >>> 8) & 0xff;
      out[i * 4 + 3] = h[i] & 0xff;
    }
    return out;
  }

  function hmacSha256(keyBytes, messageBytes) {
    const blockSize = 64;
    let key = keyBytes;
    if (key.length > blockSize) key = sha256(Array.from(key));
    const padded = new Uint8Array(blockSize);
    padded.set(key);
    const ipad = new Uint8Array(blockSize);
    const opad = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
      ipad[i] = padded[i] ^ 0x36;
      opad[i] = padded[i] ^ 0x5c;
    }
    const inner = sha256(Array.from(ipad).concat(Array.from(messageBytes)));
    return sha256(Array.from(opad).concat(Array.from(inner)));
  }

  return { sha256, hmacSha256 };
})();

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function textToBytes(str) {
  return new TextEncoder().encode(str);
}

async function hmacSign(secret, method, target, timestamp, body) {
  const message = `${method}\n${target}\n${timestamp}\n${body}`;
  const secretBytes = textToBytes(secret);
  const messageBytes = textToBytes(message);

  if (window.isSecureContext && window.crypto && window.crypto.subtle) {
    const key = await crypto.subtle.importKey(
      'raw', secretBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, messageBytes);
    return 'sha256=' + toHex(new Uint8Array(signature));
  }
  return 'sha256=' + toHex(PureCrypto.hmacSha256(secretBytes, messageBytes));
}

// ── Session & API client ────────────────────────────────────────────────────
const Session = {
  get apiKey() { return sessionStorage.getItem('sie_api_key') || ''; },
  get signingSecret() { return sessionStorage.getItem('sie_signing_secret') || ''; },
  set(apiKey, signingSecret) {
    sessionStorage.setItem('sie_api_key', apiKey);
    sessionStorage.setItem('sie_signing_secret', signingSecret);
  },
  clear() {
    sessionStorage.removeItem('sie_api_key');
    sessionStorage.removeItem('sie_signing_secret');
  },
  isSet() { return !!this.apiKey && !!this.signingSecret; },
};

async function apiCall(method, path, bodyObj) {
  const body = bodyObj !== undefined ? JSON.stringify(bodyObj) : '';
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const signature = await hmacSign(Session.signingSecret, method, path, timestamp, body);

  const response = await fetch(path, {
    method,
    headers: {
      'X-API-Key': Session.apiKey,
      'X-Timestamp': timestamp,
      'X-Signature-256': signature,
      'Content-Type': 'application/json',
    },
    body: bodyObj !== undefined ? body : undefined,
  });

  if (response.status === 204) return null;
  const text = await response.text();
  const json = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error((json && json.error) || `HTTP ${response.status}`);
  }
  return json;
}

// ── UI ───────────────────────────────────────────────────────────────────────
const el = (id) => document.getElementById(id);

function showError(id, message) {
  const box = el(id);
  box.textContent = message;
  box.classList.remove('hidden');
}
function hideError(id) {
  el(id).classList.add('hidden');
}

let me = null;

async function tryLogin(apiKey, signingSecret) {
  Session.set(apiKey, signingSecret);
  try {
    me = await apiCall('GET', '/api/auth/me');
    el('login-screen').classList.add('hidden');
    el('dashboard').classList.remove('hidden');
    el('header-actions').classList.remove('hidden');
    renderIdentity();
    await Promise.all([
      loadEndpoints(),
      me.is_master ? loadKeys() : Promise.resolve(),
      me.is_master ? loadAuditLogs() : Promise.resolve(),
    ]);
    if (me.is_master) {
      el('keys-card').classList.remove('hidden');
      el('audit-card').classList.remove('hidden');
    }
  } catch (e) {
    Session.clear();
    showError('login-error', 'Authentication failed: ' + e.message);
  }
}

function renderIdentity() {
  el('identity-name').textContent = me.name;
  el('identity-prefix').textContent = me.prefix;
  const badge = el('identity-badge');
  badge.textContent = me.is_master ? 'MASTER' : 'DAUGHTER';
  badge.className = 'badge ' + (me.is_master ? 'master' : 'daughter');
}

function logout() {
  Session.clear();
  me = null;
  el('dashboard').classList.add('hidden');
  el('header-actions').classList.add('hidden');
  el('login-screen').classList.remove('hidden');
}

// ── Endpoints ────────────────────────────────────────────────────────────────
async function loadEndpoints() {
  const endpoints = await apiCall('GET', '/api/endpoints');
  const tbody = el('endpoints-body');
  tbody.innerHTML = '';
  for (const ep of endpoints) {
    const tr = document.createElement('tr');
    const feedUrl = window.location.origin + ep.feed_path;
    tr.innerHTML = `
      <td>${escapeHtml(ep.name)}<div class="dim">${escapeHtml(ep.vault_groups)}</div></td>
      <td class="mono">${escapeHtml(feedUrl)}</td>
      <td>${ep.ttl_seconds}s</td>
      <td>${[ep.filter_rfc1918 && 'RFC1918', ep.filter_bogons && 'Bogons', ep.filter_loopback && 'Loopback'].filter(Boolean).join(', ') || '—'}</td>
      <td>${ep.last_synced_at || 'never'}</td>
      <td class="row">
        <button class="small secondary" data-copy="${escapeHtml(feedUrl)}">Copy URL</button>
        <button class="small danger" data-delete-endpoint="${ep.id}">Delete</button>
      </td>`;
    tbody.appendChild(tr);
  }
  tbody.querySelectorAll('[data-copy]').forEach((btn) => {
    btn.addEventListener('click', () => navigator.clipboard.writeText(btn.dataset.copy));
  });
  tbody.querySelectorAll('[data-delete-endpoint]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!confirm('Delete this endpoint?')) return;
      await apiCall('DELETE', `/api/endpoints/${btn.dataset.deleteEndpoint}`);
      await loadEndpoints();
    });
  });
}

async function createEndpoint(event) {
  event.preventDefault();
  hideError('endpoint-error');
  try {
    await apiCall('POST', '/api/endpoints', {
      name: el('ep-name').value,
      description: el('ep-description').value || null,
      vault_groups: el('ep-groups').value,
      ttl_seconds: parseInt(el('ep-ttl').value, 10) || 3600,
      bound_ips: el('ep-bound-ips').value || null,
      filter_rfc1918: el('ep-filter-rfc1918').checked,
      filter_bogons: el('ep-filter-bogons').checked,
      filter_loopback: el('ep-filter-loopback').checked,
    });
    event.target.reset();
    await loadEndpoints();
  } catch (e) {
    showError('endpoint-error', e.message);
  }
}

// ── Keys (Master only) ──────────────────────────────────────────────────────
async function loadKeys() {
  const keys = await apiCall('GET', '/api/keys');
  const tbody = el('keys-body');
  tbody.innerHTML = '';
  for (const k of keys) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(k.name)}<div class="dim mono">${escapeHtml(k.prefix)}…</div></td>
      <td><span class="badge ${k.is_master ? 'master' : 'daughter'}">${k.is_master ? 'MASTER' : 'DAUGHTER'}</span></td>
      <td>${k.can_manage_keys ? 'Yes' : 'No'}</td>
      <td class="row">
        ${k.is_master ? '' : `<button class="small secondary" data-rotate-key="${k.id}">Rotate</button>
        <button class="small danger" data-delete-key="${k.id}">Delete</button>`}
      </td>`;
    tbody.appendChild(tr);
  }
  tbody.querySelectorAll('[data-delete-key]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!confirm('Delete this key?')) return;
      await apiCall('DELETE', `/api/keys/${btn.dataset.deleteKey}`);
      await loadKeys();
    });
  });
  tbody.querySelectorAll('[data-rotate-key]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!confirm('Rotate this key? Its previous secret stops working immediately.')) return;
      const minted = await apiCall('POST', `/api/keys/${btn.dataset.rotateKey}/rotate`);
      showMintedKey(minted);
      await loadKeys();
    });
  });
}

function showMintedKey(minted) {
  el('minted-key-box').classList.remove('hidden');
  el('minted-api-key').textContent = minted.api_key;
  el('minted-signing-secret').textContent = minted.signing_secret;
}

async function createKey(event) {
  event.preventDefault();
  hideError('key-error');
  try {
    const minted = await apiCall('POST', '/api/keys', {
      name: el('key-name').value,
      bound_ips: el('key-bound-ips').value || null,
      can_manage_keys: el('key-can-manage-keys').checked,
    });
    event.target.reset();
    showMintedKey(minted);
    await loadKeys();
  } catch (e) {
    showError('key-error', e.message);
  }
}

// ── Audit Logs (Master only) ────────────────────────────────────────────────
async function loadAuditLogs() {
  hideError('audit-error');
  try {
    const action = el('audit-action-filter').value.trim();
    const path = '/api/audit-logs' + (action ? `?action=${encodeURIComponent(action)}` : '');
    const logs = await apiCall('GET', path);
    const tbody = el('audit-body');
    tbody.innerHTML = '';
    for (const entry of logs) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="dim">${escapeHtml(entry.timestamp)}</td>
        <td><span class="mono">${escapeHtml(entry.action)}</span></td>
        <td>${escapeHtml(entry.target_resource || '—')}</td>
        <td>${escapeHtml(entry.api_key_name)}<div class="dim mono">${escapeHtml(entry.api_key_prefix)}…</div></td>
        <td class="mono">${escapeHtml(entry.client_ip)}</td>
        <td class="dim">${escapeHtml(entry.details || '—')}</td>`;
      tbody.appendChild(tr);
    }
  } catch (e) {
    showError('audit-error', e.message);
  }
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : String(str);
  return div.innerHTML;
}

// ── Wiring ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  el('login-form').addEventListener('submit', (event) => {
    event.preventDefault();
    hideError('login-error');
    tryLogin(el('login-api-key').value.trim(), el('login-signing-secret').value.trim());
  });
  el('logout-btn').addEventListener('click', logout);
  el('endpoint-form').addEventListener('submit', createEndpoint);
  el('key-form').addEventListener('submit', createKey);
  el('minted-key-dismiss').addEventListener('click', () => el('minted-key-box').classList.add('hidden'));
  el('audit-refresh-btn').addEventListener('click', loadAuditLogs);
  el('audit-action-filter').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      loadAuditLogs();
    }
  });

  if (Session.isSet()) {
    tryLogin(Session.apiKey, Session.signingSecret);
  }
});
