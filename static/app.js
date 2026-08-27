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

// ── Proxy-aware base paths ──────────────────────────────────────────────────
// Two distinct bases, because behind a reverse proxy they are genuinely different paths:
//
//   REQUEST_BASE — where to SEND. Derived from the directory this page is served from, so a
//                  dashboard mounted at /ip_exporter/ fetches /ip_exporter/api/... with no
//                  configuration. Computed once at load: the page's own location never changes
//                  under it.
//   apiBaseOverride — what to SIGN in front of `path`. The prefix this process itself sees after
//                  the proxy is done rewriting, which no amount of introspection in the browser
//                  can discover — hence the override field on the login form. Defaults to '' (sign
//                  `path` exactly as called), which is correct for both a direct deployment and
//                  the common reverse-proxy case where the proxy strips its own prefix before
//                  forwarding here.
//
// Signing the browser's own request URL instead would break the moment a stripping proxy is in
// front: this service would verify '/api/auth/me' against a signature computed over
// '/ip_exporter/api/auth/me'.

/** Trims a user-typed override, guarantees exactly one leading slash and no trailing one, and
 * collapses a blank entry to '' (meaning "sign `path` unchanged"). Idempotent. */
function normalizeBasePath(raw) {
  const trimmed = (raw || '').trim();
  if (!trimmed) return '';
  return '/' + trimmed.replace(/^\/+/, '').replace(/\/+$/, '');
}

/** The directory this page was served from: '/ip_exporter/index.html' → '/ip_exporter', '/' → ''. */
function deriveRequestBase() {
  const path = window.location.pathname;
  const dir = path.slice(0, path.lastIndexOf('/') + 1) || '/';
  return dir.replace(/\/+$/, '');
}

const REQUEST_BASE = deriveRequestBase();

// ── Session & API client ────────────────────────────────────────────────────
const Session = {
  get apiKey() { return sessionStorage.getItem('sie_api_key') || ''; },
  get signingSecret() { return sessionStorage.getItem('sie_signing_secret') || ''; },
  get apiBaseOverride() { return sessionStorage.getItem('sie_api_base') || ''; },
  set(apiKey, signingSecret) {
    sessionStorage.setItem('sie_api_key', apiKey);
    sessionStorage.setItem('sie_signing_secret', signingSecret);
  },
  // Kept separate from set()/clear(): the override describes the deployment, not the credential,
  // so it survives a logout instead of forcing the operator to retype it on every session.
  setApiBaseOverride(raw) {
    const normalized = normalizeBasePath(raw);
    if (normalized) sessionStorage.setItem('sie_api_base', normalized);
    else sessionStorage.removeItem('sie_api_base');
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
  const signTarget = `${Session.apiBaseOverride}${path}`;
  const signature = await hmacSign(Session.signingSecret, method, signTarget, timestamp, body);
  const requestUrl = `${REQUEST_BASE}${path}`.replace(/\/{2,}/g, '/');

  const response = await fetch(requestUrl, {
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
    const err = new Error((json && json.error) || `HTTP ${response.status}`);
    // Most callers only ever read `.message` (unchanged behavior). A caller that needs to react to
    // *which* error this was — e.g. the key-deletion flow distinguishing a 409's structured
    // `owned_endpoints` inventory from every other failure — reads `.status`/`.body` instead of
    // parsing the message string back apart.
    err.status = response.status;
    err.body = json;
    throw err;
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

// Transient, non-blocking notification — used where a raw `alert()` would otherwise interrupt an
// error the user can act on elsewhere (e.g. deleteKey's non-409 failures). Falls back to `alert`
// if the container isn't in the DOM (defensive only; index.html always defines it).
function showToast(message, kind) {
  const container = el('toast-container');
  if (!container) {
    window.alert(message);
    return;
  }
  const toast = document.createElement('div');
  toast.className = `toast toast-${kind || 'error'}`;
  toast.textContent = message;
  container.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('visible'));
  setTimeout(() => {
    toast.classList.remove('visible');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
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
      el('keys-tab-btn').classList.remove('hidden');
      el('audit-tab-btn').classList.remove('hidden');
    }
  } catch (e) {
    Session.clear();
    showError('login-error', 'Authentication failed: ' + e.message);
  }
}

// Strict parity with example/simply_ip_vault's own header (the user's explicit instruction): a
// role badge only, no key name or prefix — those identify the *credential*, not something vault's
// header shows either.
function renderIdentity() {
  const badge = el('identity-badge');
  badge.textContent = me.is_master ? 'MASTER' : 'DAUGHTER';
  badge.className = 'badge badge-tier ' + (me.is_master ? 'badge-tier-master' : 'badge-tier-daughter');
}

// Reloads whichever tab is currently active, without a full page reload (so scroll position, the
// other tabs' already-fetched data, and the session all survive) and without re-authenticating —
// tryLogin() is only ever called once at login/session-restore. Each tab's own load*() function is
// already idempotent (called once at login, and again on every tab switch's worth of manual data
// staleness this button exists to fix), so this just re-invokes the same one.
async function refreshActiveTab() {
  const active = document.querySelector('.tab-panel.active');
  if (!active) return;
  const tab = active.id.replace('tab-', '');
  if (tab === 'endpoints') await loadEndpoints();
  else if (tab === 'keys' && me && me.is_master) await loadKeys();
  else if (tab === 'audit' && me && me.is_master) await loadAuditLogs();
}

// Switches the active tab: one .tab-btn/.tab-panel pair gains `.active`, every other pair loses
// it. Panels not currently active are `display: none` entirely (see .tab-panel in style.css) —
// each tab's own load*() call already ran once at login (tryLogin's Promise.all), so switching
// tabs is a pure display change, no re-fetch.
function activateTab(tabName) {
  document.querySelectorAll('.tab-btn').forEach((b) => {
    b.classList.remove('active');
    b.setAttribute('aria-selected', 'false');
  });
  document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));

  const btn = document.querySelector(`.tab-btn[data-tab="${tabName}"]`);
  btn.classList.add('active');
  btn.setAttribute('aria-selected', 'true');
  el(`tab-${tabName}`).classList.add('active');
}

function logout() {
  Session.clear();
  me = null;
  el('dashboard').classList.add('hidden');
  el('header-actions').classList.add('hidden');
  el('login-screen').classList.remove('hidden');
  el('keys-tab-btn').classList.add('hidden');
  el('audit-tab-btn').classList.add('hidden');
  activateTab('endpoints');
}

// ── Endpoints ────────────────────────────────────────────────────────────────
async function loadEndpoints() {
  const endpoints = await apiCall('GET', '/api/endpoints');
  const tbody = el('endpoints-body');
  tbody.innerHTML = '';
  if (endpoints.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="table-empty">No endpoints yet — create one below.</td></tr>';
  }
  for (const ep of endpoints) {
    const tr = document.createElement('tr');
    const feedUrl = window.location.origin + REQUEST_BASE + ep.feed_path;
    tr.innerHTML = `
      <td>${escapeHtml(ep.name)}<div class="text-muted text-sm">${escapeHtml(ep.vault_groups)}</div></td>
      <td class="font-mono break-all">${escapeHtml(feedUrl)}</td>
      <td>${ep.ttl_seconds}s</td>
      <td>${formatMaxAge(ep.max_age_seconds)}</td>
      <td>${[ep.filter_rfc1918 && 'RFC1918', ep.filter_bogons && 'Bogons', ep.filter_loopback && 'Loopback'].filter(Boolean).join(', ') || '—'}</td>
      <td class="font-mono text-sm">${ep.bound_ips ? escapeHtml(ep.bound_ips) : '<span class="text-muted">Unrestricted</span>'}</td>
      <td>${ep.last_synced_at || 'never'}</td>
      <td class="row">
        <button class="btn btn-secondary btn-sm" data-edit-endpoint="${ep.id}">Edit</button>
        <button class="btn btn-secondary btn-sm" data-copy="${escapeHtml(feedUrl)}">Copy URL</button>
        <button class="btn btn-danger btn-sm" data-delete-endpoint="${ep.id}">Delete</button>
      </td>`;
    tbody.appendChild(tr);
  }
  tbody.querySelectorAll('[data-copy]').forEach((btn) => {
    btn.addEventListener('click', () => navigator.clipboard.writeText(btn.dataset.copy));
  });
  tbody.querySelectorAll('[data-edit-endpoint]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = endpoints.find((ep) => ep.id === btn.dataset.editEndpoint);
      if (target) openEditEndpointModal(target);
    });
  });
  tbody.querySelectorAll('[data-delete-endpoint]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!confirm('Delete this endpoint?')) return;
      await apiCall('DELETE', `/api/endpoints/${btn.dataset.deleteEndpoint}`);
      await loadEndpoints();
    });
  });
}

// Populates a Vault-group checkbox grid (WEB UI => ENDPOINT GROUP LIST EXPORTER => ENDPOINT GROUP
// LIST VAULT, per the user's own framing) for the create/edit endpoint modals' `vault_groups`
// field, pre-checking whichever names `selectedRaw` (the endpoint's current comma-separated
// vault_groups string) already names.
//
// Master sees every group Vault has (GET /api/vault-groups). A Daughter cannot call that
// Master-only endpoint, and has no use for it anyway — "master can see all groups" (AGENT.MD), so
// a Daughter's picker is populated from its OWN granted groups only (GET /api/keys/{id}/groups):
// this is the "hide" half of "disable/hide ungranted groups", and avoids exposing Vault's full
// group list to a key with no rights over any group it doesn't already hold.
async function loadGroupPicker(listElId, hintElId, errorElId, selectedRaw) {
  const list = el(listElId);
  const hintEl = el(hintElId);
  const selected = new Set((selectedRaw || '').split(',').map((s) => s.trim()).filter(Boolean));
  list.innerHTML = '<span class="text-muted text-sm">Loading…</span>';
  hintEl.textContent = '';
  hideError(errorElId);

  let groups;
  try {
    groups = me.is_master
      ? await apiCall('GET', '/api/vault-groups')
      : (await apiCall('GET', `/api/keys/${me.id}/groups`)).map((g) => ({ id: g.vault_group_id, name: g.vault_group_name }));
  } catch (e) {
    list.innerHTML = '';
    showError(errorElId, e.message);
    return;
  }

  if (groups.length === 0) {
    list.innerHTML = '';
    hintEl.textContent = me.is_master
      ? 'Vault has no groups.'
      : 'You have not been granted read access to any Vault group yet — ask the Master.';
    return;
  }

  list.innerHTML = groups
    .map((g) => `
      <label class="checkbox-container">
        <input type="checkbox" value="${escapeHtml(g.name)}" ${selected.has(g.name) ? 'checked' : ''} />
        <span class="checkmark"></span>
        ${escapeHtml(g.name)} <span class="text-muted text-sm">(${g.id})</span>
      </label>`)
    .join('');
}

/** Reads a group picker's checked boxes back into the comma-separated `vault_groups` string the
 * API expects. */
function readGroupPicker(listElId) {
  return Array.from(document.querySelectorAll(`#${listElId} input[type="checkbox"]:checked`))
    .map((cb) => cb.value)
    .join(',');
}

// Opens/closes the "New Endpoint" modal — matches example/simply_ip_vault's own
// "+ Add IP / Grant Access" → #manage-ip-modal pattern: the creation form isn't permanently
// inline, it's revealed by the toolbar button and dismissed the same way every other modal here
// is (×, Cancel, backdrop click, or Escape).
function openCreateEndpointModal() {
  hideError('endpoint-error');
  loadGroupPicker('ep-groups-list', 'ep-groups-hint', 'ep-groups-error', '');
  el('create-endpoint-modal').classList.remove('hidden');
}

function closeCreateEndpointModal() {
  el('create-endpoint-modal').classList.add('hidden');
}

async function createEndpoint(event) {
  event.preventDefault();
  hideError('endpoint-error');
  try {
    await apiCall('POST', '/api/endpoints', {
      name: el('ep-name').value,
      description: el('ep-description').value || null,
      vault_groups: readGroupPicker('ep-groups-list'),
      ttl_seconds: parseInt(el('ep-ttl').value, 10) || 3600,
      max_age_seconds: parseInt(el('ep-max-age').value, 10) || 0,
      bound_ips: el('ep-bound-ips').value || null,
      filter_rfc1918: el('ep-filter-rfc1918').checked,
      filter_bogons: el('ep-filter-bogons').checked,
      filter_loopback: el('ep-filter-loopback').checked,
    });
    event.target.reset();
    closeCreateEndpointModal();
    await loadEndpoints();
  } catch (e) {
    showError('endpoint-error', e.message);
  }
}

// Opens the Edit Endpoint modal, pre-filled from the already-fetched endpoint list (no extra
// round-trip) — same fields as creation, including Bound IPs: every endpoint is IP-unrestricted
// by default (bound_ips absent), and this is where that can be changed after the fact, not just
// at creation time.
function openEditEndpointModal(target) {
  hideError('edit-endpoint-error');
  el('edit-ep-id').value = target.id;
  el('edit-ep-name').value = target.name;
  el('edit-ep-description').value = target.description || '';
  el('edit-ep-ttl').value = target.ttl_seconds;
  el('edit-ep-max-age').value = target.max_age_seconds;
  el('edit-ep-bound-ips').value = target.bound_ips || '';
  el('edit-ep-filter-rfc1918').checked = target.filter_rfc1918;
  el('edit-ep-filter-bogons').checked = target.filter_bogons;
  el('edit-ep-filter-loopback').checked = target.filter_loopback;
  loadGroupPicker('edit-ep-groups-list', 'edit-ep-groups-hint', 'edit-ep-groups-error', target.vault_groups);
  el('edit-endpoint-modal').classList.remove('hidden');
}

function closeEditEndpointModal() {
  el('edit-endpoint-modal').classList.add('hidden');
}

async function submitEditEndpoint(event) {
  event.preventDefault();
  hideError('edit-endpoint-error');
  const id = el('edit-ep-id').value;
  try {
    await apiCall('PUT', `/api/endpoints/${id}`, {
      name: el('edit-ep-name').value,
      // description/bound_ips are sent as-is, NOT `value || null`: PUT /api/endpoints/{id}
      // treats a present-but-empty string as "clear this field" and an absent (null) field as
      // "leave it unchanged" (src/api/endpoints.rs::update_endpoint). Coalescing an emptied
      // field to null here would make clearing Bound IPs — the one way to lift an endpoint back
      // to unrestricted after it was set — silently do nothing.
      description: el('edit-ep-description').value,
      vault_groups: readGroupPicker('edit-ep-groups-list'),
      ttl_seconds: parseInt(el('edit-ep-ttl').value, 10) || 3600,
      max_age_seconds: parseInt(el('edit-ep-max-age').value, 10) || 0,
      bound_ips: el('edit-ep-bound-ips').value,
      filter_rfc1918: el('edit-ep-filter-rfc1918').checked,
      filter_bogons: el('edit-ep-filter-bogons').checked,
      filter_loopback: el('edit-ep-filter-loopback').checked,
    });
    closeEditEndpointModal();
    showToast('Endpoint updated', 'success');
    await loadEndpoints();
  } catch (e) {
    showError('edit-endpoint-error', e.message);
  }
}

// ── Keys (Master only) ──────────────────────────────────────────────────────

// Row ids currently checked in the keys table, persisted across re-renders (loadKeys() rebuilds
// the tbody on every call — see wireRowSelection's own comment for why the Set survives that).
const selectedKeyIds = new Set();

// Wires a table's "select all" header checkbox and its `.row-select` body checkboxes to a shared
// Set of selected row ids, keeping the header checkbox's checked/indeterminate state and the
// batch-delete button's enabled state + label in sync. Ported from example/simply_ip_vault's
// FirewallClient.wireRowSelection. Call after every full tbody.innerHTML replace — row checkboxes
// are recreated each time, so they need fresh listeners; the header checkbox and delete button are
// static elements outside the tbody, so their handlers are (re)assigned via .onchange/.onclick
// rather than addEventListener, to avoid stacking duplicate handlers across renders.
function wireRowSelection({ tbodyId, selectAllId, deleteBtnId, selectedSet, onDeleteSelected }) {
  const selectAllEl = el(selectAllId);
  const deleteBtn = el(deleteBtnId);
  const rowCheckboxes = () => Array.from(document.querySelectorAll(`#${tbodyId} .row-select`));

  const updateControls = () => {
    const boxes = rowCheckboxes();
    const checkedCount = boxes.filter((cb) => cb.checked).length;
    selectAllEl.checked = boxes.length > 0 && checkedCount === boxes.length;
    selectAllEl.indeterminate = checkedCount > 0 && checkedCount < boxes.length;
    const nothingSelected = selectedSet.size === 0;
    deleteBtn.closest('.batch-actions')?.classList.toggle('hidden', nothingSelected);
    deleteBtn.disabled = nothingSelected;
    deleteBtn.textContent = nothingSelected ? 'Delete Selected' : `Delete Selected (${selectedSet.size})`;
  };

  rowCheckboxes().forEach((cb) => {
    cb.checked = selectedSet.has(cb.dataset.id);
    cb.addEventListener('change', () => {
      if (cb.checked) selectedSet.add(cb.dataset.id);
      else selectedSet.delete(cb.dataset.id);
      updateControls();
    });
  });

  selectAllEl.onchange = () => {
    rowCheckboxes().forEach((cb) => {
      cb.checked = selectAllEl.checked;
      if (cb.checked) selectedSet.add(cb.dataset.id);
      else selectedSet.delete(cb.dataset.id);
    });
    updateControls();
  };

  deleteBtn.onclick = () => onDeleteSelected();

  updateControls();
}

async function loadKeys() {
  const keys = await apiCall('GET', '/api/keys');

  // Drop selections for keys that no longer exist (deleted elsewhere, or by a previous batch).
  const currentIds = new Set(keys.map((k) => k.id));
  for (const id of [...selectedKeyIds]) {
    if (!currentIds.has(id)) selectedKeyIds.delete(id);
  }

  // One badge-scope pill per granted Vault group, fetched per Daughter key (Master bypasses group
  // enforcement entirely — "master can see all groups" — so there is nothing to fetch or show for
  // it). Read-only by design (AGENT.MD: this crate never writes to Vault, so a grant's mere
  // existence *is* the permission — there is no separate "R"/"RW" distinction to render).
  const daughterKeys = keys.filter((k) => !k.is_master);
  const grantsByKeyId = new Map();
  await Promise.all(
    daughterKeys.map(async (k) => {
      try {
        grantsByKeyId.set(k.id, await apiCall('GET', `/api/keys/${k.id}/groups`));
      } catch (e) {
        grantsByKeyId.set(k.id, []);
      }
    })
  );

  const tbody = el('keys-body');
  tbody.innerHTML = '';
  if (keys.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="table-empty">No keys yet.</td></tr>';
  }
  for (const k of keys) {
    const tr = document.createElement('tr');
    const tierClass = k.is_master ? 'badge-tier-master' : 'badge-tier-daughter';
    const scopeBadges = [`<span class="badge badge-tier ${tierClass}">${k.is_master ? 'MASTER' : 'DAUGHTER'}</span>`];
    if (k.can_manage_keys) scopeBadges.push('<span class="badge badge-scope">MANAGE KEYS</span>');
    for (const grant of grantsByKeyId.get(k.id) || []) {
      scopeBadges.push(`<span class="badge badge-scope">${escapeHtml(grant.vault_group_name)}: R</span>`);
    }
    tr.innerHTML = `
      <td>${k.is_master ? '' : `<input type="checkbox" class="row-select" data-id="${k.id}" />`}</td>
      <td>${escapeHtml(k.name)}<div class="text-muted font-mono text-sm">${escapeHtml(k.prefix)}…</div></td>
      <td class="row">${scopeBadges.join('')}</td>
      <td class="row">
        <button class="btn btn-secondary btn-sm" data-edit-key="${k.id}">Edit</button>
        ${k.is_master ? '' : `<button class="btn btn-secondary btn-sm" data-regenerate-key="${k.id}" title="Replace BOTH the API key and its signing secret">Regenerate</button>
        <button class="btn btn-secondary btn-sm" data-rotate-secret-key="${k.id}" title="Replace only the signing secret; the API key stays the same">Rotate Secret</button>
        <button class="btn btn-danger btn-sm" data-delete-key="${k.id}">Delete</button>`}
      </td>`;
    tbody.appendChild(tr);
  }
  tbody.querySelectorAll('[data-delete-key]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!confirm('Delete this key?')) return;
      await deleteKey(btn.dataset.deleteKey, keys);
    });
  });
  tbody.querySelectorAll('[data-edit-key]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = keys.find((k) => k.id === btn.dataset.editKey);
      if (target) openEditKeyModal(target);
    });
  });
  // "Regenerate": replaces BOTH the API key and its signing secret (POST .../rotate) — the
  // original, wider rotation this crate already had, renamed to match example/simply_ip_vault's
  // own terminology for the same operation.
  tbody.querySelectorAll('[data-regenerate-key]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!confirm('Regenerate this key? Both the API key and its signing secret change — the previous credentials stop working immediately.')) {
        return;
      }
      const minted = await apiCall('POST', `/api/keys/${btn.dataset.regenerateKey}/rotate`);
      showMintedKey(minted);
      await loadKeys();
    });
  });
  // "Rotate Secret": replaces ONLY the signing secret (POST .../rotate-secret) — the API key,
  // name, and can_manage_keys are left untouched. Narrower and lower-blast-radius than Regenerate.
  tbody.querySelectorAll('[data-rotate-secret-key]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!confirm('Rotate this key\'s signing secret? The API key and its permissions stay the same, but the current signing secret stops working immediately.')) {
        return;
      }
      const rotated = await apiCall('POST', `/api/keys/${btn.dataset.rotateSecretKey}/rotate-secret`);
      showMintedKey({ signing_secret: rotated.signing_secret });
      await loadKeys();
    });
  });

  wireRowSelection({
    tbodyId: 'keys-body',
    selectAllId: 'select-all-keys',
    deleteBtnId: 'delete-selected-keys',
    selectedSet: selectedKeyIds,
    onDeleteSelected: () => batchDeleteKeys(),
  });
}

// Deletes every selected key with one DELETE per id (the API has no bulk endpoint). Any single
// failure — including the 409 "still owns endpoints" conflict batchDeleteKeys does not attempt to
// resolve automatically — just counts toward the failure tally; the operator can delete that one
// key individually afterward to get the proper reassignment prompt. Mirrors
// example/simply_ip_vault's own batchDeleteKeys, which resolves conflicts the same way.
async function batchDeleteKeys() {
  const count = selectedKeyIds.size;
  if (count === 0) return;
  if (!confirm(`Delete ${count} selected key${count === 1 ? '' : 's'}? This immediately revokes their access and cannot be undone.`)) {
    return;
  }

  const ids = [...selectedKeyIds];
  const results = await Promise.allSettled(ids.map((id) => apiCall('DELETE', `/api/keys/${id}`)));
  const failed = results.filter((r) => r.status === 'rejected').length;
  selectedKeyIds.clear();

  showToast(
    failed === 0
      ? `${count} key${count === 1 ? '' : 's'} deleted`
      : `${count - failed} of ${count} deleted; ${failed} failed (still owns endpoints? delete it individually to reassign them)`,
    failed === 0 ? 'success' : 'error'
  );
  await loadKeys();
  await loadEndpoints();
}

// Deletes a key, handling the 409 "still owns endpoints" case by opening the reassignment dialog
// rather than failing silently or dumping a raw error string on the caller. `allKeys` is the
// already-fetched key list `loadKeys` just rendered, reused as the reassignment dropdown's
// candidate set so opening the dialog needs no extra round-trip.
async function deleteKey(keyId, allKeys) {
  try {
    await apiCall('DELETE', `/api/keys/${keyId}`);
    await loadKeys();
    await loadEndpoints();
  } catch (e) {
    if (e.status === 409 && e.body && Array.isArray(e.body.owned_endpoints)) {
      openReassignDialog(keyId, e.body.owned_endpoints, allKeys);
    } else {
      showToast(e.message, 'error');
    }
  }
}

// Opens/closes the reassignment modal — a plain `.modal-overlay` div toggled via the `hidden`
// class (example/simply_ip_vault's own modal mechanism), not a native <dialog>. See
// AGENT_NOTES.MD for why: this crate briefly used a native <dialog> here, restyled to match
// vault's visual language, and hit a real centering bug that vault's own div-based modals never
// could (the universal `* { margin: 0 }` reset silently defeats native <dialog> centering, which
// depends on the UA stylesheet's `margin: auto` — see the fix commit for the full story). Copying
// vault's actual mechanism rather than re-styling a different one avoids that whole class of bug.
function closeReassignDialog() {
  el('reassign-dialog').classList.add('hidden');
}

// Lists the endpoints blocking a key's deletion and lets the operator pick another key to receive
// them before retrying the delete with ?reassign_to=<id> — the reassignment and the delete happen
// together, atomically, on the server (api::keys::delete_api_key).
function openReassignDialog(keyId, ownedEndpoints, allKeys) {
  const modal = el('reassign-dialog');
  el('reassign-summary').textContent =
    `This key still owns ${ownedEndpoints.length} endpoint(s). Choose another key to take ownership, ` +
    'or cancel and reassign/delete them individually first.';

  el('reassign-endpoint-list').innerHTML =
    ownedEndpoints.map((ep) => `<li>${escapeHtml(ep.name)}</li>`).join('');

  const select = el('reassign-target');
  const candidates = allKeys.filter((k) => k.id !== keyId);
  select.innerHTML = candidates
    .map((k) => `<option value="${k.id}">${escapeHtml(k.name)}${k.is_master ? ' (Master)' : ''}</option>`)
    .join('');

  hideError('reassign-error');

  // Assigned (not addEventListener'd) so a second delete attempt replaces the previous attempt's
  // closure over `keyId`/`allKeys` rather than stacking a second listener beside it.
  el('reassign-cancel-btn').onclick = () => closeReassignDialog();
  el('reassign-modal-close').onclick = () => closeReassignDialog();
  el('reassign-confirm-btn').onclick = async () => {
    hideError('reassign-error');
    if (!select.value) {
      showError('reassign-error', 'No other key exists to receive these endpoints.');
      return;
    }
    try {
      await apiCall('DELETE', `/api/keys/${keyId}?reassign_to=${encodeURIComponent(select.value)}`);
      closeReassignDialog();
      await loadKeys();
      await loadEndpoints();
    } catch (e) {
      showError('reassign-error', e.message);
    }
  };

  modal.classList.remove('hidden');
}

// `minted.api_key` is present for a create/regenerate (both credential halves are new) and
// absent for a secret-only rotation — the "API Key" row is hidden in the latter case rather than
// shown empty, since there's nothing new there to copy.
function showMintedKey(minted) {
  const apiKeyRow = el('minted-api-key-row');
  if (minted.api_key) {
    apiKeyRow.classList.remove('hidden');
    el('minted-api-key').textContent = minted.api_key;
  } else {
    apiKeyRow.classList.add('hidden');
  }
  el('minted-signing-secret').textContent = minted.signing_secret;
  el('minted-key-box').classList.remove('hidden');
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

// Opens the Edit Key modal, pre-filled from the already-fetched key list (no extra round-trip).
// On the Master key, name and can_manage_keys are disabled and a note explains why — AGENT.MD:
// the Master key is immutable through the API except for its own bound_ips — rather than hiding
// those fields, so the operator can see they exist without being offered a change that would 403.
function openEditKeyModal(target) {
  hideError('edit-key-error');
  el('edit-key-id').value = target.id;
  el('edit-key-name').value = target.name;
  el('edit-key-bound-ips').value = target.bound_ips || '';
  el('edit-key-can-manage-keys').checked = target.can_manage_keys;

  el('edit-key-name').disabled = target.is_master;
  el('edit-key-can-manage-keys').disabled = target.is_master;
  el('edit-key-master-note').classList.toggle('hidden', !target.is_master);

  loadKeyGroupAccess(target);
  el('edit-key-modal').classList.remove('hidden');
}

// Populates the Edit Key modal's "Vault Group Access" section: one checkbox per group Vault
// currently has (fetched live), pre-checked against this key's current grants. Hidden entirely
// for the Master key — it bypasses group enforcement, so there is nothing to assign
// ("master can see all groups" — the user's own framing). Each checkbox grants/revokes
// immediately on toggle (POST/DELETE /api/keys/{id}/groups), independent of the modal's own
// Save Changes button, which only ever touches name/bound_ips/can_manage_keys.
async function loadKeyGroupAccess(target) {
  const section = el('edit-key-groups-section');
  if (target.is_master) {
    section.classList.add('hidden');
    return;
  }
  section.classList.remove('hidden');
  const list = el('edit-key-groups-list');
  list.innerHTML = '<span class="text-muted text-sm">Loading…</span>';
  hideError('edit-key-groups-error');

  let allGroups;
  let grants;
  try {
    [allGroups, grants] = await Promise.all([
      apiCall('GET', '/api/vault-groups'),
      apiCall('GET', `/api/keys/${target.id}/groups`),
    ]);
  } catch (e) {
    list.innerHTML = '';
    showError('edit-key-groups-error', e.message);
    return;
  }

  if (allGroups.length === 0) {
    list.innerHTML = '<span class="text-muted text-sm">Vault has no groups.</span>';
    return;
  }

  const permissionIdByGroupId = new Map(grants.map((g) => [g.vault_group_id, g.id]));
  list.innerHTML = allGroups
    .map((g) => `
      <label class="checkbox-container">
        <input type="checkbox" data-group-id="${g.id}" data-group-name="${escapeHtml(g.name)}" ${permissionIdByGroupId.has(g.id) ? 'checked' : ''} />
        <span class="checkmark"></span>
        ${escapeHtml(g.name)} <span class="text-muted text-sm">(${g.id})</span>
      </label>`)
    .join('');

  list.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
    cb.addEventListener('change', async () => {
      cb.disabled = true;
      hideError('edit-key-groups-error');
      try {
        if (cb.checked) {
          await apiCall('POST', `/api/keys/${target.id}/groups`, { vault_group_id: cb.dataset.groupId });
          showToast(`Granted read access to ${cb.dataset.groupName}`, 'success');
        } else {
          const permissionId = permissionIdByGroupId.get(cb.dataset.groupId);
          await apiCall('DELETE', `/api/keys/${target.id}/groups/${permissionId}`);
          showToast(`Revoked read access to ${cb.dataset.groupName}`, 'success');
        }
        await loadKeyGroupAccess(target);
      } catch (e) {
        cb.checked = !cb.checked;
        cb.disabled = false;
        showError('edit-key-groups-error', e.message);
      }
    });
  });
}

function closeEditKeyModal() {
  el('edit-key-modal').classList.add('hidden');
}

async function submitEditKey(event) {
  event.preventDefault();
  hideError('edit-key-error');
  const id = el('edit-key-id').value;
  const isMaster = el('edit-key-name').disabled;
  try {
    // On the Master key, name/can_manage_keys are omitted entirely (not sent as unchanged
    // values) — guard_master_update refuses the update if either field is merely *present* in
    // the payload, even carrying the key's own current value, so a no-op resubmission of those
    // fields would still 403.
    //
    // bound_ips is sent as-is, NOT `value || null`: PUT /api/keys/{id} treats a present-but-empty
    // string as "clear this field" and an absent (null) field as "leave it unchanged"
    // (src/api/keys.rs::update_api_key) — coalescing an emptied field to null would make clearing
    // Bound IPs silently do nothing.
    const payload = { bound_ips: el('edit-key-bound-ips').value };
    if (!isMaster) {
      payload.name = el('edit-key-name').value;
      payload.can_manage_keys = el('edit-key-can-manage-keys').checked;
    }
    await apiCall('PUT', `/api/keys/${id}`, payload);
    closeEditKeyModal();
    showToast('Key updated', 'success');
    await loadKeys();
  } catch (e) {
    showError('edit-key-error', e.message);
  }
}

// ── Audit Logs (Master only) ────────────────────────────────────────────────
// Straightforward offset pagination against GET /api/audit-logs?limit=&offset= (src/api/audit.rs
// already supports both) — no PagedCache/local-chunk layer like example/simply_ip_vault's own
// audit tab, since this crate has no total-count endpoint to page a local cache against. A page
// that comes back full-length is the only signal "there might be a next page" has to go on.
const AUDIT_PAGE_SIZE = 50;
let auditOffset = 0;
let auditHasMore = false;

function updateAuditPaginationUI() {
  el('audit-btn-prev').disabled = auditOffset === 0;
  el('audit-btn-next').disabled = !auditHasMore;
  el('audit-page-indicator').textContent = `Page ${Math.floor(auditOffset / AUDIT_PAGE_SIZE) + 1}`;
}

async function loadAuditLogs() {
  hideError('audit-error');
  try {
    const action = el('audit-action-filter').value.trim();
    const params = new URLSearchParams({ limit: String(AUDIT_PAGE_SIZE), offset: String(auditOffset) });
    if (action) params.set('action', action);
    const logs = await apiCall('GET', `/api/audit-logs?${params.toString()}`);
    auditHasMore = logs.length === AUDIT_PAGE_SIZE;
    updateAuditPaginationUI();

    const tbody = el('audit-body');
    tbody.innerHTML = '';
    if (logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="table-empty">No audit log entries match.</td></tr>';
    }
    for (const entry of logs) {
      const tr = document.createElement('tr');
      const actor = `${entry.api_key_name} (${entry.api_key_prefix}...)`;
      const target = entry.target_resource || '-';
      const details = entry.details || '-';
      tr.innerHTML = `
        <td class="text-muted text-sm" title="${escapeHtml(entry.timestamp)}">${escapeHtml(formatTimestamp(entry.timestamp))}</td>
        <td class="text-sm" title="${escapeHtml(actor)}">${escapeHtml(entry.api_key_name)} <span class="text-muted text-sm">(${escapeHtml(entry.api_key_prefix)}...)</span></td>
        <td class="font-mono text-sm">${escapeHtml(entry.client_ip)}</td>
        <td><span class="badge badge-scope">${escapeHtml(entry.action)}</span></td>
        <td class="font-mono text-sm" title="${escapeHtml(target)}">${escapeHtml(target)}</td>
        <td class="text-sm" title="${escapeHtml(details)}">${escapeHtml(details)}</td>`;
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

// Renders a server timestamp (chrono::NaiveDateTime, no timezone marker — always UTC in this
// crate) in the viewer's own timezone, formatted as DD/MM/YYYY, HH:MM:SS. The timezone-inference
// rule (append 'Z' only if nothing already marks one) and the raw-string fallback for anything
// that doesn't parse as a date at all are ported from example/simply_ip_vault's own
// formatTimestamp; the format itself deliberately does NOT use vault's bare toLocaleString() (its
// output is locale-dependent — e.g. M/D/YYYY in a US-locale browser — so copying that call would
// not actually reproduce a stable DD/MM/YYYY, HH:MM:SS display). 'en-GB' is what produces that
// exact format regardless of the viewer's own locale.
function formatTimestamp(raw) {
  if (!raw) return '—';
  const hasTimezone = /[zZ]|[+-]\d{2}:?\d{2}$/.test(raw);
  const date = new Date(hasTimezone ? raw : `${raw}Z`);
  if (Number.isNaN(date.getTime())) return raw;
  return date.toLocaleString('en-GB');
}

// Renders an endpoint's retention window for the endpoints table. 0 is the documented spelling of
// "unlimited" (no age cutoff), not "zero seconds" — showing a bare "0s" would read as the opposite
// of what it means. Anything else is shown both raw and in the largest whole unit that divides it
// evenly, so "3600s / 1h" stays scannable without hiding the exact configured value.
function formatMaxAge(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value <= 0) return '<span class="text-muted">Unlimited</span>';
  const units = [['d', 86400], ['h', 3600], ['m', 60]];
  for (const [suffix, size] of units) {
    if (value % size === 0) return `${value}s <span class="text-muted">/ ${value / size}${suffix}</span>`;
  }
  return `${value}s`;
}

// ── Wiring ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Prefill from storage so a proxied deployment doesn't ask for the override again on every
  // logout — only the credentials themselves are cleared by Session.clear().
  el('login-api-base').value = Session.apiBaseOverride;
  el('login-form').addEventListener('submit', (event) => {
    event.preventDefault();
    hideError('login-error');
    // Applied before tryLogin(), since its very first request (GET /api/auth/me) is already signed.
    Session.setApiBaseOverride(el('login-api-base').value);
    tryLogin(el('login-api-key').value.trim(), el('login-signing-secret').value.trim());
  });
  el('btn-logout').addEventListener('click', logout);
  el('btn-refresh').addEventListener('click', () => refreshActiveTab());
  el('endpoint-form').addEventListener('submit', createEndpoint);
  el('key-form').addEventListener('submit', createKey);

  // Create Endpoint modal: open from the toolbar button, close on the × button, Cancel, a
  // backdrop click, or Escape — same conventions as the reassignment modal below.
  el('open-create-endpoint').addEventListener('click', openCreateEndpointModal);
  el('create-endpoint-close').addEventListener('click', closeCreateEndpointModal);
  el('create-endpoint-cancel').addEventListener('click', closeCreateEndpointModal);
  el('create-endpoint-modal').addEventListener('click', (event) => {
    if (event.target.id === 'create-endpoint-modal') closeCreateEndpointModal();
  });
  el('minted-key-dismiss').addEventListener('click', () => el('minted-key-box').classList.add('hidden'));

  // Edit Endpoint modal: same four close conventions as every other modal here.
  el('edit-endpoint-form').addEventListener('submit', submitEditEndpoint);
  el('edit-endpoint-close').addEventListener('click', closeEditEndpointModal);
  el('edit-endpoint-cancel').addEventListener('click', closeEditEndpointModal);
  el('edit-endpoint-modal').addEventListener('click', (event) => {
    if (event.target.id === 'edit-endpoint-modal') closeEditEndpointModal();
  });

  // Edit Key modal: same four close conventions as every other modal here.
  el('edit-key-form').addEventListener('submit', submitEditKey);
  el('edit-key-close').addEventListener('click', closeEditKeyModal);
  el('edit-key-cancel').addEventListener('click', closeEditKeyModal);
  el('edit-key-modal').addEventListener('click', (event) => {
    if (event.target.id === 'edit-key-modal') closeEditKeyModal();
  });

  el('audit-refresh-btn').addEventListener('click', () => {
    auditOffset = 0;
    loadAuditLogs();
  });
  el('audit-action-filter').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      auditOffset = 0;
      loadAuditLogs();
    }
  });
  el('audit-btn-prev').addEventListener('click', () => {
    auditOffset = Math.max(0, auditOffset - AUDIT_PAGE_SIZE);
    loadAuditLogs();
  });
  el('audit-btn-next').addEventListener('click', () => {
    if (!auditHasMore) return;
    auditOffset += AUDIT_PAGE_SIZE;
    loadAuditLogs();
  });

  // Tabs — each panel's data was already loaded once at login (tryLogin's Promise.all), so
  // switching is a pure display change; see activateTab()'s own comment.
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => activateTab(btn.dataset.tab));
  });

  // Reassignment modal: close on the × button, Cancel (wired per-open in openReassignDialog()),
  // a backdrop click, or Escape — matching example/simply_ip_vault's own modal-close conventions.
  el('reassign-dialog').addEventListener('click', (event) => {
    // Only a click on the overlay itself — a click that merely bubbled up from the card would
    // close the dialog while the operator is still using the reassignment dropdown.
    if (event.target.id === 'reassign-dialog') closeReassignDialog();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    if (!el('reassign-dialog').classList.contains('hidden')) closeReassignDialog();
    if (!el('create-endpoint-modal').classList.contains('hidden')) closeCreateEndpointModal();
    if (!el('edit-key-modal').classList.contains('hidden')) closeEditKeyModal();
    if (!el('edit-endpoint-modal').classList.contains('hidden')) closeEditEndpointModal();
  });

  if (Session.isSet()) {
    tryLogin(Session.apiKey, Session.signingSecret);
  }
});
