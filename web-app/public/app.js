/* Proxy Circuit — Control Plane SPA
 * All DOM mutations use textContent / createElement to prevent XSS.
 */
'use strict';

// ── State ────────────────────────────────────────────────────────────────────
let token    = sessionStorage.getItem('token') || null;
let userRole = sessionStorage.getItem('role')  || null;
let userName = sessionStorage.getItem('username') || null;
let walletAddr = null;

// ── Helpers ──────────────────────────────────────────────────────────────────
function esc(v) { return String(v ?? ''); }   // safe text; never inserted as HTML

function el(tag, attrs = {}, text) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  if (text !== undefined) e.textContent = text;
  return e;
}

async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  if (body)  opts.body = JSON.stringify(body);
  const res = await fetch('/api' + path, opts);
  const data = res.ok ? await res.json().catch(() => null) : null;
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw Object.assign(new Error(err.error || res.statusText), { status: res.status });
  }
  return data;
}

function showAlert(containerId, msg, type = 'info') {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.className = 'alert ' + type;
  el.textContent = msg;
  setTimeout(() => { if (el) el.textContent = ''; }, 4000);
}

function setAuth(data) {
  token    = data.token;
  userRole = data.role;
  userName = data.username || data.role;
  sessionStorage.setItem('token',    token);
  sessionStorage.setItem('role',     userRole);
  sessionStorage.setItem('username', userName);
}

function clearAuth() {
  token = userRole = userName = null;
  sessionStorage.clear();
}

// ── Auth tabs ─────────────────────────────────────────────────────────────────
document.querySelectorAll('.auth-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.auth-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    const id = 'tab-' + tab.dataset.tab;
    document.getElementById(id)?.classList.add('active');
  });
});

// ── Password login ────────────────────────────────────────────────────────────
document.getElementById('btn-login-pw').addEventListener('click', async () => {
  const username = document.getElementById('pw-username').value.trim();
  const password = document.getElementById('pw-password').value;
  document.getElementById('err-pw').textContent = '';
  try {
    const data = await api('POST', '/auth/login', { username, password });
    setAuth(data);
    showApp();
  } catch (e) {
    document.getElementById('err-pw').textContent = e.message;
  }
});

// ── SHA-256 key login ─────────────────────────────────────────────────────────
document.getElementById('btn-login-sha').addEventListener('click', async () => {
  const username = document.getElementById('sha-username').value.trim();
  const key      = document.getElementById('sha-key').value;
  document.getElementById('err-sha').textContent = '';
  if (!username || !key) {
    document.getElementById('err-sha').textContent = 'Username and key are required';
    return;
  }
  // Hash the key client-side using Web Crypto (SHA-256)
  let keyHex = key;
  if (!/^[0-9a-f]{64}$/i.test(key)) {
    const buf  = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key));
    keyHex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
  }
  try {
    const data = await api('POST', '/auth/login/sha256', { username, key: keyHex });
    setAuth(data);
    showApp();
  } catch (e) {
    document.getElementById('err-sha').textContent = e.message;
  }
});

// ── Wallet login ──────────────────────────────────────────────────────────────
const walletDot   = document.getElementById('wallet-dot');
const walletLabel = document.getElementById('wallet-addr-label');

document.getElementById('btn-connect-wallet').addEventListener('click', async () => {
  document.getElementById('err-wallet').textContent = '';
  if (!window.ethereum) {
    document.getElementById('err-wallet').textContent = 'No Web3 wallet detected. Install MetaMask.';
    return;
  }
  try {
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    walletAddr = accounts[0];
    walletDot.classList.add('connected');
    walletLabel.textContent = walletAddr.slice(0,6) + '…' + walletAddr.slice(-4);
    document.getElementById('wallet-sign-section').style.display = '';
    document.getElementById('btn-login-wallet').style.display = '';
  } catch (e) {
    document.getElementById('err-wallet').textContent = e.message;
  }
});

document.getElementById('btn-login-wallet').addEventListener('click', async () => {
  document.getElementById('err-wallet').textContent = '';
  try {
    // 1. Get challenge from server
    const { challenge } = await api('GET', '/auth/wallet/challenge?address=' + walletAddr);
    // 2. Sign with wallet
    const signature = await window.ethereum.request({
      method: 'personal_sign',
      params: [challenge, walletAddr],
    });
    // 3. Verify on server
    const data = await api('POST', '/auth/wallet/verify', { address: walletAddr, signature });
    setAuth(data);
    showApp();
  } catch (e) {
    document.getElementById('err-wallet').textContent = e.message;
  }
});

// ── Guest login ───────────────────────────────────────────────────────────────
document.getElementById('btn-login-guest').addEventListener('click', async () => {
  document.getElementById('err-guest').textContent = '';
  try {
    const data = await api('POST', '/auth/guest', {});
    setAuth(data);
    showApp();
  } catch (e) {
    document.getElementById('err-guest').textContent = e.message;
  }
});

// ── Enter key on password fields ──────────────────────────────────────────────
['pw-username','pw-password'].forEach(id =>
  document.getElementById(id).addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('btn-login-pw').click();
  })
);

// ── App init ──────────────────────────────────────────────────────────────────
function showApp() {
  document.getElementById('auth-screen').style.display = 'none';
  document.getElementById('app').style.display = 'block';

  const hdrUser = document.getElementById('hdr-username');
  const hdrRole = document.getElementById('hdr-role');
  hdrUser.textContent = userName || 'user';
  hdrRole.textContent = userRole || 'viewer';
  hdrRole.className   = 'role-chip ' + (userRole || 'viewer');

  loadDashboard();
}

if (token) showApp();

// ── Logout ────────────────────────────────────────────────────────────────────
document.getElementById('btn-logout').addEventListener('click', () => {
  clearAuth();
  document.getElementById('app').style.display = 'none';
  document.getElementById('auth-screen').style.display = 'flex';
});

// ── Navigation ────────────────────────────────────────────────────────────────
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    item.classList.add('active');
    const page = document.getElementById('page-' + item.dataset.page);
    if (page) page.classList.add('active');
    // Lazy load
    if (item.dataset.page === 'nodes')    loadNodes();
    if (item.dataset.page === 'sessions') loadSessions();
    if (item.dataset.page === 'policies') loadPolicies();
    if (item.dataset.page === 'audit')    loadAudit();
  });
});

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const [nodes, sessions, policies, audit] = await Promise.all([
      api('GET', '/nodes'),
      api('GET', '/sessions'),
      api('GET', '/policies'),
      api('GET', '/audit').catch(() => []),
    ]);
    document.getElementById('stat-nodes').textContent    = nodes.length;
    document.getElementById('stat-sessions').textContent = sessions.filter(s => s.status === 'active').length;
    document.getElementById('stat-policies').textContent = policies.length;
    document.getElementById('stat-audit').textContent    = audit.length;

    const tbody = document.querySelector('#recent-nodes tbody');
    tbody.textContent = '';
    nodes.slice(0, 8).forEach(n => {
      const tr = el('tr');
      [n.host, n.role, n.region || 'default', n.status].forEach((v, i) => {
        const td = el('td');
        if (i === 1 || i === 3) {
          const b = el('span', { class: 'badge ' + esc(v) }, v);
          td.appendChild(b);
        } else {
          td.textContent = esc(v);
        }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  } catch (e) {
    showAlert('dash-alert', 'Failed to load dashboard: ' + e.message, 'error');
  }
}

// ── Nodes ─────────────────────────────────────────────────────────────────────
async function loadNodes() {
  try {
    const nodes = await api('GET', '/nodes');
    const tbody = document.getElementById('nodes-body');
    tbody.textContent = '';
    nodes.forEach(n => {
      const tr = el('tr');
      [n.host, n.port, n.role, n.region, n.status, (n.created_at || '').slice(0,10)].forEach((v, i) => {
        const td = el('td');
        if (i === 2 || i === 4) {
          td.appendChild(el('span', { class: 'badge ' + esc(v) }, esc(v)));
        } else {
          td.textContent = esc(v);
        }
        tr.appendChild(td);
      });
      const actTd = el('td');
      if (['admin','operator'].includes(userRole)) {
        const btn = el('button', { class: 'btn-del', 'data-id': n.id }, '✕ Delete');
        btn.addEventListener('click', () => deleteNode(n.id));
        actTd.appendChild(btn);
      }
      tr.appendChild(actTd);
      tbody.appendChild(tr);
    });
  } catch (e) {
    showAlert('nodes-alert', 'Error: ' + e.message, 'error');
  }
}

async function deleteNode(id) {
  if (!confirm('Delete this node?')) return;
  try {
    await api('DELETE', '/nodes/' + id);
    loadNodes();
  } catch (e) {
    showAlert('nodes-alert', 'Delete failed: ' + e.message, 'error');
  }
}

// Node modal
document.getElementById('btn-add-node').addEventListener('click', () =>
  document.getElementById('modal-node').classList.add('open'));
document.getElementById('btn-node-cancel').addEventListener('click', () =>
  document.getElementById('modal-node').classList.remove('open'));
document.getElementById('btn-refresh-nodes').addEventListener('click', loadNodes);
document.getElementById('btn-node-save').addEventListener('click', async () => {
  const host   = document.getElementById('n-host').value.trim();
  const port   = parseInt(document.getElementById('n-port').value, 10);
  const role   = document.getElementById('n-role').value;
  const region = document.getElementById('n-region').value.trim() || 'default';
  try {
    await api('POST', '/nodes', { host, port, role, region });
    document.getElementById('modal-node').classList.remove('open');
    showAlert('nodes-alert', 'Node added', 'success');
    loadNodes();
  } catch (e) {
    showAlert('nodes-alert', 'Error: ' + e.message, 'error');
  }
});

// ── Sessions ──────────────────────────────────────────────────────────────────
async function loadSessions() {
  try {
    const sessions = await api('GET', '/sessions');
    const tbody = document.getElementById('sessions-body');
    tbody.textContent = '';
    sessions.forEach(s => {
      const tr = el('tr');
      [s.id.slice(0,8)+'…', s.client_ip || '—', s.destination || '—', s.status,
       (s.started_at || '').slice(0,16)].forEach((v, i) => {
        const td = el('td');
        if (i === 3) {
          td.appendChild(el('span', { class: 'badge ' + esc(v) }, esc(v)));
        } else {
          td.textContent = esc(v);
        }
        tr.appendChild(td);
      });
      const actTd = el('td');
      if (['admin'].includes(userRole) && s.status === 'active') {
        const btn = el('button', { class: 'btn-del', 'data-id': s.id }, '✕ Kill');
        btn.addEventListener('click', async () => {
          await api('DELETE', '/sessions/' + s.id).catch(() => {});
          loadSessions();
        });
        actTd.appendChild(btn);
      }
      tr.appendChild(actTd);
      tbody.appendChild(tr);
    });
  } catch (e) { /* guest may not have access */ }
}

// ── Policies ──────────────────────────────────────────────────────────────────
async function loadPolicies() {
  try {
    const policies = await api('GET', '/policies');
    const tbody = document.getElementById('policies-body');
    tbody.textContent = '';
    policies.forEach(p => {
      const tr = el('tr');
      [p.name, p.action, p.priority, p.src_cidr || '*', p.dst_host || '*', p.enabled ? '✓' : '✗'].forEach((v, i) => {
        const td = el('td');
        if (i === 1) {
          td.appendChild(el('span', { class: 'badge ' + esc(v) }, esc(v)));
        } else {
          td.textContent = esc(v);
        }
        tr.appendChild(td);
      });
      const actTd = el('td');
      if (['admin','operator'].includes(userRole)) {
        const btn = el('button', { class: 'btn-del', 'data-id': p.id }, '✕');
        btn.addEventListener('click', async () => {
          await api('DELETE', '/policies/' + p.id).catch(() => {});
          loadPolicies();
        });
        actTd.appendChild(btn);
      }
      tr.appendChild(actTd);
      tbody.appendChild(tr);
    });
  } catch (e) { /* silent for guests */ }
}

document.getElementById('btn-add-policy').addEventListener('click', () =>
  document.getElementById('modal-policy').classList.add('open'));
document.getElementById('btn-policy-cancel').addEventListener('click', () =>
  document.getElementById('modal-policy').classList.remove('open'));
document.getElementById('btn-policy-save').addEventListener('click', async () => {
  const name     = document.getElementById('p-name').value.trim();
  const action   = document.getElementById('p-action').value;
  const priority = parseInt(document.getElementById('p-priority').value || '0', 10);
  const src_cidr = document.getElementById('p-src').value.trim() || null;
  const dst_host = document.getElementById('p-dst').value.trim() || null;
  const dst_ports= document.getElementById('p-ports').value.trim() || null;
  try {
    await api('POST', '/policies', { name, action, priority, src_cidr, dst_host, dst_ports });
    document.getElementById('modal-policy').classList.remove('open');
    showAlert('policies-alert', 'Policy created', 'success');
    loadPolicies();
  } catch (e) {
    showAlert('policies-alert', 'Error: ' + e.message, 'error');
  }
});

// ── JWT Creator ────────────────────────────────────────────────────────────────

/** Pure-JS base64url encode (no dependency). */
function b64url(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

/** HMAC-SHA256 using Web Crypto API. Returns hex string. */
async function hmacSha256(secret, data) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return b64url(String.fromCharCode(...new Uint8Array(sig)));
}

document.getElementById('btn-jwt-create').addEventListener('click', async () => {
  const secret  = document.getElementById('jwt-secret').value;
  const sub     = document.getElementById('jwt-sub').value.trim();
  const aud     = document.getElementById('jwt-aud').value.trim();
  const expSecs = parseInt(document.getElementById('jwt-exp').value, 10);
  let extra = {};
  try {
    const raw = document.getElementById('jwt-extra').value.trim();
    if (raw) extra = JSON.parse(raw);
  } catch {
    showAlert('jwt-create-alert', 'Extra claims is not valid JSON', 'error');
    return;
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = { iat: now, ...extra };
  if (sub) payload.sub = sub;
  if (aud) payload.aud = aud;
  if (expSecs > 0) payload.exp = now + expSecs;

  const header  = { alg: 'HS256', typ: 'JWT' };
  const hB64    = b64url(JSON.stringify(header));
  const pB64    = b64url(JSON.stringify(payload));
  const signing = hB64 + '.' + pB64;
  const sigB64  = await hmacSha256(secret, signing);
  const jwt     = signing + '.' + sigB64;

  // Render colour-coded output (safe — using textContent per span)
  const out = document.getElementById('jwt-output');
  out.textContent = '';
  const parts = jwt.split('.');
  parts.forEach((part, i) => {
    const s = document.createElement('span');
    s.className = ['jwt-part-header','jwt-part-payload','jwt-part-sig'][i] || '';
    s.textContent = part + (i < 2 ? '.' : '');
    out.appendChild(s);
  });

  // Copy button
  const copyBtn = document.getElementById('btn-jwt-copy');
  copyBtn.onclick = () => { navigator.clipboard.writeText(jwt); copyBtn.textContent = 'Copied!'; setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500); };

  document.getElementById('jwt-decoded').textContent = JSON.stringify({ header, payload }, null, 2);
});

document.getElementById('btn-jwt-decode').addEventListener('click', async () => {
  const raw    = document.getElementById('jwt-decode-input').value.trim();
  const secret = document.getElementById('jwt-decode-secret').value;
  const out    = document.getElementById('jwt-decode-result');
  try {
    const [hPart, pPart, sPart] = raw.split('.');
    const header  = JSON.parse(b64urlDecode(hPart));
    const payload = JSON.parse(b64urlDecode(pPart));
    let verified  = 'not verified (no secret provided)';
    if (secret) {
      const expected = await hmacSha256(secret, hPart + '.' + pPart);
      verified = (expected === sPart) ? '✅ Signature valid' : '❌ Signature INVALID';
    }
    out.textContent = JSON.stringify({ header, payload, verified }, null, 2);
  } catch {
    out.textContent = '⚠️ Could not decode token — check format';
  }
});

// ── Audit log ─────────────────────────────────────────────────────────────────
async function loadAudit() {
  try {
    const rows  = await api('GET', '/audit?limit=200');
    const tbody = document.getElementById('audit-body');
    tbody.textContent = '';
    rows.forEach(r => {
      const isSuccess = (r.result || '').startsWith('success');
      const tr = el('tr', { class: 'audit-row ' + (isSuccess ? 'success' : 'failure') });
      [(r.ts || '').slice(0,16), r.event, r.actor, r.target || '—', r.result].forEach(v => {
        tr.appendChild(el('td', {}, esc(v)));
      });
      tbody.appendChild(tr);
    });
  } catch (e) { /* may be viewer-only restricted */ }
}
document.getElementById('btn-refresh-audit').addEventListener('click', loadAudit);
