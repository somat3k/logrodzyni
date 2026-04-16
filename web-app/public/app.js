/* logrodzyni — Control Plane SPA  |  v2.1  |  All DOM mutations use textContent/createElement (XSS-safe) */
'use strict';

// ── State (localStorage → persists across browser restarts) ───────────────────
let token    = localStorage.getItem('jwt')  || null;
let userRole = localStorage.getItem('role') || null;
let userName = localStorage.getItem('user') || null;
let walletAddr = null;

// ── Helpers ───────────────────────────────────────────────────────────────────
const esc = v => String(v ?? '');

function el(tag, attrs = {}, text) {
  const e = document.createElement(tag);
  Object.entries(attrs).forEach(([k, v]) => e.setAttribute(k, v));
  if (text !== undefined) e.textContent = text;
  return e;
}

async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  if (body)  opts.body = JSON.stringify(body);
  const configuredBase = window.__API_BASE__;
  const normalizedPath = String(path || '').replace(/^\/+/, '');
  const endpointPath = configuredBase && /\/api\/?$/.test(configuredBase)
    ? normalizedPath
    : `api/${normalizedPath}`;
  const base = (configuredBase || window.location.origin).replace(/\/+$/, '') + '/';
  const url = new URL(endpointPath, base);
  const res = await fetch(url.toString(), opts);
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    // Auto-logout when a stored token is rejected by a non-auth endpoint (expired / revoked).
    // Mark the error as sessionExpired so callers can skip their generic error UI and avoid
    // showing a duplicate/conflicting message alongside the "Session expired" toast.
    if (res.status === 401 && token && !path.startsWith('/auth/')) {
      clearAuth();
      const app     = document.getElementById('app');
      const fab     = document.getElementById('fab');
      const landing = document.getElementById('landing');
      if (app)     { app.classList.remove('open'); app.style.display = 'none'; }
      if (fab)     fab.style.display = 'none';
      if (landing) landing.style.display = '';
      toast('Session expired — please sign in again', 'err');
      throw Object.assign(new Error('Session expired'), { status: 401, sessionExpired: true });
    }
    throw Object.assign(new Error(data.error || res.statusText), { status: res.status });
  }
  return data;
}

function setAuth(data) {
  token    = data.token;
  userRole = data.role;
  userName = data.username || data.role;
  localStorage.setItem('jwt',  token);
  localStorage.setItem('role', userRole);
  localStorage.setItem('user', userName);
}

function clearAuth() {
  token = userRole = userName = null;
  localStorage.clear();
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const root = document.getElementById('toasts');
  const t = el('div', { class: `toast toast-${type}` }, msg);
  root.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

// ── Canvas particle hero ──────────────────────────────────────────────────────
(function initCanvas() {
  const canvas = document.getElementById('hero-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const particles = [];
  const N = 70;

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  for (let i = 0; i < N; i++) {
    particles.push({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      r: Math.random() * 1.5 + 0.4,
      vx: (Math.random() - .5) * .35,
      vy: (Math.random() - .5) * .35,
      a: Math.random(),
    });
  }

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    // connections
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const d  = Math.sqrt(dx*dx + dy*dy);
        if (d < 130) {
          ctx.beginPath();
          ctx.strokeStyle = `rgba(34,197,94,${(1 - d/130) * 0.22})`;
          ctx.lineWidth = 0.6;
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }
    // dots
    particles.forEach(p => {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > canvas.width)  p.vx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.vy *= -1;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(34,197,94,${p.a * 0.7})`;
      ctx.fill();
    });
    requestAnimationFrame(draw);
  }
  draw();
})();

// ── Landing nav scroll effect ─────────────────────────────────────────────────
window.addEventListener('scroll', () => {
  const nav = document.getElementById('lnav');
  if (nav) nav.classList.toggle('scrolled', window.scrollY > 30);
});

// ── Auth overlay ──────────────────────────────────────────────────────────────
function openAuth(mode = 'login') {
  const overlay = document.getElementById('auth-overlay');
  const title   = document.getElementById('auth-title');
  const sub     = document.getElementById('auth-sub');
  if (mode === 'register') {
    title.textContent = 'Create your account';
    sub.textContent   = 'Join logrodzyni — free & open';
    switchAuthTab('reg');
  } else {
    title.textContent = 'Welcome back';
    sub.textContent   = 'Sign in to your control plane';
    switchAuthTab('pw');
  }
  overlay.classList.add('open');
  // Auto-focus first text input in the active panel
  setTimeout(() => {
    const panel = overlay.querySelector('.auth-panel.active');
    const first = panel?.querySelector('input[type="text"], input[type="password"]');
    if (first) first.focus();
  }, 60);
}
function closeAuth() {
  document.getElementById('auth-overlay').classList.remove('open');
}

function switchAuthTab(tabId) {
  document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.auth-panel').forEach(p => p.classList.remove('active'));
  const tab = document.querySelector(`.auth-tab[data-tab="${tabId}"]`);
  if (tab) tab.classList.add('active');
  document.getElementById('tab-' + tabId)?.classList.add('active');
  const title = document.getElementById('auth-title');
  const sub   = document.getElementById('auth-sub');
  if (tabId === 'reg')  { if (title) title.textContent = 'Create your account'; if (sub) sub.textContent = 'Join logrodzyni — free & open'; }
  if (tabId === 'pw')   { if (title) title.textContent = 'Welcome back';         if (sub) sub.textContent = 'Sign in to your control plane'; }
  // Auto-focus first input in the newly active panel
  setTimeout(() => {
    const panel = document.getElementById('tab-' + tabId);
    const first = panel?.querySelector('input[type="text"], input[type="password"]');
    if (first) first.focus();
  }, 40);
}

// Helper — set button loading state
function btnLoading(btn, loading, originalText) {
  if (loading) {
    btn.disabled = true;
    btn.dataset.originalText = btn.textContent;
    btn.classList.add('btn-loading');
    btn.textContent = originalText || btn.textContent;
  } else {
    btn.disabled = false;
    btn.classList.remove('btn-loading');
    btn.textContent = btn.dataset.originalText || btn.textContent;
  }
}

// Helper — show auth error with shake
function showAuthError(errEl, msg) {
  errEl.textContent = msg;
  errEl.classList.remove('shaking');
  void errEl.offsetWidth; // reflow
  errEl.classList.add('shaking');
  setTimeout(() => errEl.classList.remove('shaking'), 400);
}

// Helper — validate required fields, mark them red, return true if all ok
function requireFields(pairs) {
  let ok = true;
  pairs.forEach(([id, label]) => {
    const inp = document.getElementById(id);
    if (!inp) return;
    const wrap = inp.closest('.field') || inp.parentElement;
    if (!inp.value.trim()) {
      wrap.classList.add('field-err');
      ok = false;
    } else {
      wrap.classList.remove('field-err');
    }
  });
  return ok;
}

// Landing CTAs
document.getElementById('nav-signin')?.addEventListener('click', () => openAuth('login'));
document.getElementById('nav-register')?.addEventListener('click', () => openAuth('register'));
document.getElementById('hero-start')?.addEventListener('click', () => openAuth('register'));
document.getElementById('hero-signin')?.addEventListener('click', () => openAuth('login'));
document.getElementById('cta-start')?.addEventListener('click', () => openAuth('register'));
document.getElementById('auth-close')?.addEventListener('click', closeAuth);
document.getElementById('auth-overlay')?.addEventListener('click', e => {
  if (e.target === document.getElementById('auth-overlay')) closeAuth();
});
document.getElementById('nav-docs')?.addEventListener('click', e => {
  e.preventDefault();
  if (token) { showApp(); navigate('docs'); }
  else openAuth('login');
});

// Service card launches
document.querySelectorAll('.svc-card[data-launch]').forEach(card => {
  card.addEventListener('click', () => {
    const pg = card.dataset.launch;
    if (token) { showApp(); navigate(pg); }
    else openAuth('login');
  });
});

// Auth tabs — use shared switchAuthTab helper
document.querySelectorAll('.auth-tab').forEach(tab => {
  tab.addEventListener('click', () => switchAuthTab(tab.dataset.tab));
});

// Auth panel cross-links (Register ↔ Sign In)
document.querySelectorAll('.auth-link[data-switch-tab]').forEach(link => {
  link.addEventListener('click', () => switchAuthTab(link.dataset.switchTab));
});

// ── Password login ────────────────────────────────────────────────────────────
document.getElementById('pw-btn')?.addEventListener('click', async () => {
  const btn      = document.getElementById('pw-btn');
  const errEl    = document.getElementById('pw-err');
  errEl.textContent = '';
  // Remove field-err highlights on a new attempt
  ['pw-user','pw-pass'].forEach(id => document.getElementById(id)?.closest('.field')?.classList.remove('field-err'));
  if (!requireFields([['pw-user','Username'],['pw-pass','Password']])) {
    showAuthError(errEl, 'Please enter your username and password.');
    return;
  }
  const username = document.getElementById('pw-user').value.trim();
  const password = document.getElementById('pw-pass').value;
  btnLoading(btn, true);
  try {
    const data = await api('POST', '/auth/login', { username, password });
    setAuth(data); closeAuth(); showApp();
  } catch (e) {
    btnLoading(btn, false);
    showAuthError(errEl, e.message || 'Sign in failed. Check your credentials.');
  }
});
['pw-user','pw-pass'].forEach(id =>
  document.getElementById(id)?.addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('pw-btn')?.click(); })
);

// ── SHA-256 login ─────────────────────────────────────────────────────────────
document.getElementById('sha-btn')?.addEventListener('click', async () => {
  const btn      = document.getElementById('sha-btn');
  const username = document.getElementById('sha-user').value.trim();
  const key      = document.getElementById('sha-key').value;
  const errEl    = document.getElementById('sha-err');
  errEl.textContent = '';
  if (!username || !key) { showAuthError(errEl, 'Username and key are required'); return; }
  let keyHex = key;
  if (!/^[0-9a-f]{64}$/i.test(key)) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key));
    keyHex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
  }
  btnLoading(btn, true);
  try {
    const data = await api('POST', '/auth/login/sha256', { username, key: keyHex });
    setAuth(data); closeAuth(); showApp();
  } catch (e) {
    btnLoading(btn, false);
    showAuthError(errEl, e.message || 'SHA-256 sign in failed.');
  }
});

// ── Wallet login ──────────────────────────────────────────────────────────────
const walletDot   = document.getElementById('w-dot');
const walletLabel = document.getElementById('w-label');

document.getElementById('w-connect-btn')?.addEventListener('click', async () => {
  const errEl = document.getElementById('wallet-err');
  errEl.textContent = '';
  if (!window.ethereum) { errEl.textContent = 'No Web3 wallet detected. Install MetaMask.'; return; }
  try {
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    walletAddr = accounts[0];
    walletDot?.classList.add('on');
    if (walletLabel) walletLabel.textContent = walletAddr.slice(0,6) + '…' + walletAddr.slice(-4);
    document.getElementById('w-sign-btn').style.display = '';
  } catch (e) { errEl.textContent = e.message; }
});

document.getElementById('w-sign-btn')?.addEventListener('click', async () => {
  const errEl = document.getElementById('wallet-err');
  errEl.textContent = '';
  try {
    const { challenge } = await api('GET', '/auth/wallet/challenge?address=' + walletAddr);
    const signature     = await window.ethereum.request({ method: 'personal_sign', params: [challenge, walletAddr] });
    const data          = await api('POST', '/auth/wallet/verify', { address: walletAddr, signature });
    setAuth(data); closeAuth(); showApp();
  } catch (e) { errEl.textContent = e.message; }
});

// ── Guest login ───────────────────────────────────────────────────────────────
document.getElementById('guest-btn')?.addEventListener('click', async () => {
  const btn   = document.getElementById('guest-btn');
  const errEl = document.getElementById('guest-err');
  errEl.textContent = '';
  btnLoading(btn, true);
  try {
    const data = await api('POST', '/auth/guest', {});
    setAuth(data); closeAuth(); showApp();
  } catch (e) {
    btnLoading(btn, false);
    showAuthError(errEl, e.message || 'Guest access failed.');
  }
});

// ── Register ──────────────────────────────────────────────────────────────────
document.getElementById('reg-btn')?.addEventListener('click', async () => {
  const btn          = document.getElementById('reg-btn');
  const username     = document.getElementById('reg-user').value.trim();
  const display_name = document.getElementById('reg-name').value.trim();
  const password     = document.getElementById('reg-pass').value;
  const confirm      = document.getElementById('reg-confirm').value;
  const errEl        = document.getElementById('reg-err');
  errEl.textContent  = '';
  ['reg-user','reg-pass','reg-confirm'].forEach(id => document.getElementById(id)?.closest('.field')?.classList.remove('field-err'));
  if (!requireFields([['reg-user','Username'],['reg-pass','Password'],['reg-confirm','Confirm']])) {
    showAuthError(errEl, 'Username and password are required.'); return;
  }
  if (password !== confirm)   { showAuthError(errEl, 'Passwords do not match.'); document.getElementById('reg-confirm')?.closest('.field')?.classList.add('field-err'); return; }
  if (password.length < 8)    { showAuthError(errEl, 'Password must be at least 8 characters.'); document.getElementById('reg-pass')?.closest('.field')?.classList.add('field-err'); return; }
  btnLoading(btn, true);
  try {
    const data = await api('POST', '/auth/register', { username, password, display_name });
    setAuth(data); closeAuth(); showApp();
    toast('Account created! Welcome, ' + userName, 'ok');
  } catch (e) {
    btnLoading(btn, false);
    showAuthError(errEl, e.message || 'Registration failed. Try a different username.');
  }
});
['reg-user','reg-pass','reg-confirm'].forEach(id =>
  document.getElementById(id)?.addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('reg-btn')?.click(); })
);

// ── App init ──────────────────────────────────────────────────────────────────
function showApp() {
  document.getElementById('landing').style.display = 'none';
  const app = document.getElementById('app');
  app.style.display = '';
  app.classList.add('open');
  document.getElementById('fab').style.display = '';

  const initials = (userName || 'U').slice(0,2).toUpperCase();
  const hdAv     = document.getElementById('hd-av');
  if (hdAv) hdAv.textContent = initials[0];
  const hdUser   = document.getElementById('hd-user-lbl');
  if (hdUser) hdUser.textContent = esc(userName || 'user');
  const hdRole   = document.getElementById('hd-role');
  if (hdRole) { hdRole.textContent = esc(userRole || 'viewer'); hdRole.className = 'role-chip ' + (userRole || 'viewer'); }

  navigate('dashboard');
}

if (token) {
  document.getElementById('landing').style.display = 'none';
  showApp();
}

// ── Logout ────────────────────────────────────────────────────────────────────
document.getElementById('app-logout')?.addEventListener('click', () => {
  clearAuth();
  document.getElementById('app').classList.remove('open');
  document.getElementById('app').style.display = 'none';
  document.getElementById('fab').style.display = 'none';
  document.getElementById('landing').style.display = '';
});

// ── Navigation ────────────────────────────────────────────────────────────────
function navigate(page) {
  document.querySelectorAll('.sb-item').forEach(item => {
    item.classList.toggle('active', item.dataset.page === page);
  });
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const pg = document.getElementById('page-' + page);
  if (pg) pg.classList.add('active');

  // lazy load
  if (page === 'dashboard')  loadDashboard();
  if (page === 'proxy')      loadNodes().then(ns => { if (ns) renderProxyNodes(ns); });
  if (page === 'nodes')      loadNodes().then(ns => { if (ns) renderNodes(ns); });
  if (page === 'sessions')   loadSessions();
  if (page === 'policies')   loadPolicies();
  if (page === 'audit')      loadAudit();
  if (page === 'account')    loadAccount();
  if (page === 'docs')       renderDoc('intro');
}

document.querySelectorAll('.sb-item').forEach(item => {
  item.addEventListener('click', () => navigate(item.dataset.page));
});

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const [nodes, sessions, policies, audit] = await Promise.all([
      api('GET', '/nodes'),
      api('GET', '/sessions'),
      api('GET', '/policies'),
      api('GET', '/audit?limit=50').catch(() => []),
    ]);
    document.getElementById('s-nodes').textContent    = nodes.length;
    document.getElementById('s-sessions').textContent = sessions.filter(s => s.status === 'active').length;
    document.getElementById('s-policies').textContent = policies.length;
    document.getElementById('s-audit').textContent    = audit.length;
    document.getElementById('badge-nodes').textContent = nodes.length;
    document.getElementById('proxy-routes-stat') && (document.getElementById('proxy-routes-stat').textContent = nodes.length);

    const tbody = document.getElementById('dash-nodes-tbody');
    if (!tbody) return;
    tbody.textContent = '';
    nodes.slice(0, 8).forEach(n => {
      const tr = el('tr');
      [n.host, n.role, n.region || 'default', n.status].forEach((v, i) => {
        const td = el('td');
        if (i === 1 || i === 3) td.appendChild(el('span', { class: 'tag ' + statusTag(esc(v)) }, esc(v)));
        else td.textContent = esc(v);
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  } catch (e) {
    if (e.sessionExpired) return; // toast already shown by api()
    const a = document.getElementById('dash-alert');
    if (a) { a.className = 'alert alert-err'; a.textContent = 'Failed to load dashboard: ' + e.message; }
  }
}

document.getElementById('dash-refresh')?.addEventListener('click', loadDashboard);

function statusTag(v) {
  const m = { active:'tag-ok', pending:'tag-warn', terminated:'tag-err', offline:'tag-err',
               ingress:'tag-accent', relay:'tag-blue', egress:'tag-purple',
               allow:'tag-ok', deny:'tag-err', 'rate-limit':'tag-warn' };
  return m[v] || 'tag-muted';
}

// ── Nodes ─────────────────────────────────────────────────────────────────────
async function loadNodes() {
  try {
    return await api('GET', '/nodes');
  } catch (e) {
    if (e.sessionExpired) return null;
    showPageAlert('nodes-alert', 'Error: ' + e.message, 'err');
    return null;
  }
}

function renderNodes(nodes) {
  const tbody = document.getElementById('nodes-tbody');
  if (!tbody) return;
  tbody.textContent = '';
  nodes.forEach(n => {
    const tr = el('tr');
    [n.host, n.port, n.role, n.region || 'default', n.status, (n.created_at||'').slice(0,10)].forEach((v, i) => {
      const td = el('td');
      if (i === 2 || i === 4) td.appendChild(el('span', { class: 'tag ' + statusTag(esc(v)) }, esc(v)));
      else td.textContent = esc(v);
      tr.appendChild(td);
    });
    const actTd = el('td');
    if (['admin','operator'].includes(userRole)) {
      const btn = el('button', { class: 'btn-del' }, '✕ Delete');
      btn.addEventListener('click', () => deleteNode(n.id));
      actTd.appendChild(btn);
    }
    tr.appendChild(actTd);
    tbody.appendChild(tr);
  });
}

function renderProxyNodes(nodes) {
  const tbody = document.getElementById('proxy-nodes-tbody');
  if (!tbody) return;
  tbody.textContent = '';
  nodes.forEach(n => {
    const tr = el('tr');
    [n.host, n.port, n.role, n.region||'default', n.status, (n.created_at||'').slice(0,10)].forEach((v, i) => {
      const td = el('td');
      if (i === 2 || i === 4) td.appendChild(el('span', { class: 'tag ' + statusTag(esc(v)) }, esc(v)));
      else td.textContent = esc(v);
      tr.appendChild(td);
    });
    const actTd = el('td');
    if (['admin','operator'].includes(userRole)) {
      const btn = el('button', { class: 'btn-del' }, '✕');
      btn.addEventListener('click', () => deleteNode(n.id, loadProxyPage));
      actTd.appendChild(btn);
    }
    tr.appendChild(actTd);
    tbody.appendChild(tr);
  });
}

async function loadProxyPage() {
  const ns = await loadNodes();
  if (ns) renderProxyNodes(ns);
}

async function deleteNode(id, cb) {
  if (!confirm('Delete this node?')) return;
  try {
    await api('DELETE', '/nodes/' + id);
    const ns = await loadNodes();
    if (ns) { renderNodes(ns); if (cb) cb(); }
    toast('Node deleted', 'ok');
  } catch (e) {
    if (e.sessionExpired) return;
    showPageAlert('nodes-alert', 'Delete failed: ' + e.message, 'err');
  }
}

function showPageAlert(id, msg, type) {
  const el2 = document.getElementById(id);
  if (!el2) return;
  el2.className = 'alert alert-' + type;
  el2.textContent = msg;
  setTimeout(() => { if (el2) el2.textContent = ''; }, 4000);
}

// Node modal wiring
document.getElementById('add-node-btn')?.addEventListener('click', () => openModal('modal-node'));
document.getElementById('add-node-btn2')?.addEventListener('click', () => openModal('modal-node'));
document.getElementById('refresh-nodes-btn')?.addEventListener('click', async () => {
  const ns = await loadNodes(); if (ns) renderNodes(ns);
});
document.getElementById('n-save-btn')?.addEventListener('click', async () => {
  const host   = document.getElementById('n-host').value.trim();
  const port   = parseInt(document.getElementById('n-port').value, 10);
  const role   = document.getElementById('n-role').value;
  const region = document.getElementById('n-region').value.trim() || 'default';
  try {
    await api('POST', '/nodes', { host, port, role, region });
    closeModal('modal-node');
    toast('Node registered', 'ok');
    const ns = await loadNodes();
    if (ns) { renderNodes(ns); renderProxyNodes(ns); }
  } catch (e) { if (!e.sessionExpired) toast('Error: ' + e.message, 'err'); }
});

// ── Sessions ──────────────────────────────────────────────────────────────────
async function loadSessions() {
  try {
    const sessions = await api('GET', '/sessions');
    const tbody    = document.getElementById('sessions-tbody');
    if (!tbody) return;
    tbody.textContent = '';
    sessions.forEach(s => {
      const tr = el('tr');
      [s.id.slice(0,8)+'…', s.client_ip||'—', s.destination||'—', s.status, (s.started_at||'').slice(0,16)].forEach((v, i) => {
        const td = el('td');
        if (i === 3) td.appendChild(el('span', { class: 'tag ' + statusTag(esc(v)) }, esc(v)));
        else td.textContent = esc(v);
        tr.appendChild(td);
      });
      const actTd = el('td');
      if (userRole === 'admin' && s.status === 'active') {
        const btn = el('button', { class: 'btn-del' }, '✕ Kill');
        btn.addEventListener('click', async () => { await api('DELETE','/sessions/'+s.id).catch(()=>{}); loadSessions(); });
        actTd.appendChild(btn);
      }
      tr.appendChild(actTd);
      tbody.appendChild(tr);
    });
  } catch (_) { /* guest may be restricted */ }
}

// ── Policies ──────────────────────────────────────────────────────────────────
async function loadPolicies() {
  try {
    const policies = await api('GET', '/policies');
    const tbody    = document.getElementById('policies-tbody');
    if (!tbody) return;
    tbody.textContent = '';
    policies.forEach(p => {
      const tr = el('tr');
      [p.name, p.action, p.priority, p.src_cidr||'*', p.dst_host||'*', p.enabled?'✓':'✗'].forEach((v, i) => {
        const td = el('td');
        if (i === 1) td.appendChild(el('span', { class: 'tag ' + statusTag(esc(v)) }, esc(v)));
        else td.textContent = esc(v);
        tr.appendChild(td);
      });
      const actTd = el('td');
      if (['admin','operator'].includes(userRole)) {
        const btn = el('button', { class: 'btn-del' }, '✕');
        btn.addEventListener('click', async () => { await api('DELETE','/policies/'+p.id).catch(()=>{}); loadPolicies(); toast('Policy deleted','ok'); });
        actTd.appendChild(btn);
      }
      tr.appendChild(actTd);
      tbody.appendChild(tr);
    });
  } catch (_) {}
}

document.getElementById('add-policy-btn')?.addEventListener('click', () => openModal('modal-policy'));
document.getElementById('p-save-btn')?.addEventListener('click', async () => {
  const name     = document.getElementById('p-name').value.trim();
  const action   = document.getElementById('p-action').value;
  const priority = parseInt(document.getElementById('p-priority').value||'0',10);
  const src_cidr = document.getElementById('p-src').value.trim()||null;
  const dst_host = document.getElementById('p-dst').value.trim()||null;
  const dst_ports= document.getElementById('p-ports').value.trim()||null;
  try {
    await api('POST', '/policies', { name, action, priority, src_cidr, dst_host, dst_ports });
    closeModal('modal-policy');
    toast('Policy created', 'ok');
    loadPolicies();
  } catch (e) { if (!e.sessionExpired) toast('Error: ' + e.message, 'err'); }
});

// ── Audit ─────────────────────────────────────────────────────────────────────
async function loadAudit() {
  try {
    const rows  = await api('GET', '/audit?limit=200');
    const tbody = document.getElementById('audit-tbody');
    if (!tbody) return;
    tbody.textContent = '';
    rows.forEach(r => {
      const ok = (r.result||'').startsWith('success');
      const tr = el('tr');
      [(r.ts||'').slice(0,16), r.event, r.actor, r.target||'—', r.result].forEach(v => tr.appendChild(el('td',{},esc(v))));
      if (!ok) tr.style.color = 'var(--err)';
      tbody.appendChild(tr);
    });
  } catch (_) {}
}
document.getElementById('audit-refresh-btn')?.addEventListener('click', loadAudit);

// ── JWT Creator ────────────────────────────────────────────────────────────────
/** Base64url-encode a UTF-8 string safely (handles non-Latin1 / unicode input). */
function b64url(str) {
  const bytes = new TextEncoder().encode(str);
  const binary = Array.from(bytes, b => String.fromCharCode(b)).join('');
  return btoa(binary).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function b64dec(str) { str=str.replace(/-/g,'+').replace(/_/g,'/'); while(str.length%4)str+='='; return atob(str); }
async function hmacSha256(secret, data) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  const sig  = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return b64url(String.fromCharCode(...new Uint8Array(sig)));
}

document.getElementById('jwt-gen-btn')?.addEventListener('click', async () => {
  const secret  = document.getElementById('jwt-secret').value;
  const sub     = document.getElementById('jwt-sub').value.trim();
  const aud     = document.getElementById('jwt-aud').value.trim();
  const expSecs = parseInt(document.getElementById('jwt-exp').value, 10);
  const alertEl = document.getElementById('jwt-alert');
  let extra = {};
  try {
    const raw = document.getElementById('jwt-extra').value.trim();
    if (raw) extra = JSON.parse(raw);
  } catch { if(alertEl){alertEl.className='alert alert-err';alertEl.textContent='Extra claims: invalid JSON';} return; }

  const now = Math.floor(Date.now()/1000);
  const payload = { iat: now, ...extra };
  if (sub) payload.sub = sub;
  if (aud) payload.aud = aud;
  if (expSecs > 0) payload.exp = now + expSecs;
  const header = { alg:'HS256', typ:'JWT' };

  const hB64 = b64url(JSON.stringify(header));
  const pB64 = b64url(JSON.stringify(payload));
  const sig  = await hmacSha256(secret, hB64+'.'+pB64);
  const jwt  = hB64+'.'+pB64+'.'+sig;

  const out = document.getElementById('jwt-output');
  out.textContent = '';
  const parts = jwt.split('.');
  const classes = ['jwt-part-h','jwt-part-p','jwt-part-s'];
  parts.forEach((part, i) => {
    if (i > 0) { const dot = el('span',{class:'jwt-dot'},'.'); out.appendChild(dot); }
    out.appendChild(el('span',{class:classes[i]},part));
  });
  const cpBtn = document.getElementById('jwt-copy-btn');
  if (cpBtn) cpBtn.onclick = () => { navigator.clipboard.writeText(jwt); cpBtn.textContent='Copied!'; setTimeout(()=>{cpBtn.textContent='Copy';},1500); };

  document.getElementById('jwt-decoded').textContent = JSON.stringify({header,payload},null,2);
  if(alertEl) alertEl.textContent='';
});

document.getElementById('jwt-decode-btn')?.addEventListener('click', async () => {
  const raw    = document.getElementById('jwt-decode-in').value.trim();
  const secret = document.getElementById('jwt-decode-sec').value;
  const out    = document.getElementById('jwt-decode-out');
  try {
    const [hP,pP,sP] = raw.split('.');
    const header  = JSON.parse(b64dec(hP));
    const payload = JSON.parse(b64dec(pP));
    let verified  = 'not verified (no secret)';
    if (secret) {
      const expected = await hmacSha256(secret, hP+'.'+pP);
      verified = expected === sP ? '✅ Signature VALID' : '❌ Signature INVALID';
    }
    out.textContent = JSON.stringify({header,payload,verified},null,2);
  } catch { out.textContent = '⚠️ Could not decode token — check format'; }
});

// ── Account ───────────────────────────────────────────────────────────────────
async function loadAccount() {
  try {
    const u = await api('GET', '/account');
    const n = u.display_name || u.username;
    const av = document.getElementById('acc-avatar');
    if (av) av.textContent = (n||'U')[0].toUpperCase();
    const nl = document.getElementById('acc-name-lbl');     if(nl) nl.textContent = esc(n);
    const ul = document.getElementById('acc-user-lbl');     if(ul) ul.textContent = '@' + esc(u.username);
    const rl = document.getElementById('acc-role-lbl');     if(rl) rl.textContent = esc(u.role) + ' · ' + esc(u.auth_type);
    const di = document.getElementById('acc-display');      if(di) di.value = esc(u.display_name || '');
    const si = document.getElementById('acc-since');        if(si) si.value = (u.created_at||'').slice(0,10);
    // SHA-256 token section: only relevant for SHA-256 accounts
    const shaSection = document.getElementById('acc-sha-section');
    if (shaSection) shaSection.style.display = u.auth_type === 'sha256_key' ? '' : 'none';
  } catch (e) { if (!e.sessionExpired) toast('Failed to load account: ' + e.message, 'err'); }
}

document.getElementById('acc-save-btn')?.addEventListener('click', async () => {
  const display_name = document.getElementById('acc-display').value.trim();
  const msgEl = document.getElementById('acc-save-msg');
  try {
    await api('PATCH', '/account', { display_name });
    if(msgEl) { msgEl.textContent='Saved!'; setTimeout(()=>{msgEl.textContent='';},2500); }
    toast('Profile updated', 'ok');
    loadAccount();
  } catch (e) { if (!e.sessionExpired) toast('Error: ' + e.message, 'err'); }
});

document.getElementById('acc-pw-btn')?.addEventListener('click', async () => {
  const current_password = document.getElementById('acc-cur-pw').value;
  const new_password     = document.getElementById('acc-new-pw').value;
  const confirm          = document.getElementById('acc-conf-pw').value;
  const errEl            = document.getElementById('acc-pw-err');
  const msgEl            = document.getElementById('acc-pw-msg');
  errEl.textContent      = '';
  if (new_password !== confirm) { errEl.textContent='Passwords do not match'; return; }
  if (new_password.length < 8)  { errEl.textContent='Minimum 8 characters'; return; }
  try {
    await api('PATCH', '/account', { current_password, new_password });
    if(msgEl) { msgEl.textContent='Updated!'; setTimeout(()=>{msgEl.textContent='';},2500); }
    toast('Password changed', 'ok');
    ['acc-cur-pw','acc-new-pw','acc-conf-pw'].forEach(id => { const el2=document.getElementById(id); if(el2)el2.value=''; });
  } catch (e) { if (!e.sessionExpired) errEl.textContent = e.message; }
});

document.getElementById('acc-copy-sha')?.addEventListener('click', () => {
  const val = document.getElementById('acc-sha-token')?.textContent || '';
  navigator.clipboard.writeText(val).then(() => toast('Copied', 'ok'));
});

// Account sub-tabs
document.querySelectorAll('.acc-nav-item').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.acc-nav-item').forEach(i => i.classList.remove('active'));
    document.querySelectorAll('.acc-panel').forEach(p => p.classList.remove('active'));
    item.classList.add('active');
    document.getElementById('stab-' + item.dataset.stab)?.classList.add('active');
  });
});

// ── Modals ────────────────────────────────────────────────────────────────────
function openModal(id)  { document.getElementById(id)?.classList.add('open'); }
function closeModal(id) { document.getElementById(id)?.classList.remove('open'); }

document.querySelectorAll('.modal-x, [data-modal]').forEach(btn => {
  btn.addEventListener('click', () => closeModal(btn.dataset.modal || btn.closest('.modal-overlay')?.id));
});
document.querySelectorAll('.modal-overlay').forEach(ov => {
  ov.addEventListener('click', e => { if (e.target === ov) closeModal(ov.id); });
});

// ── Docs ──────────────────────────────────────────────────────────────────────
/**
 * Build a sanitized DOM fragment from an HTML string.
 * Only an allowlist of tags is passed through; all other elements are unwrapped
 * (their children are preserved but the element itself is dropped).
 * Attributes are stripped except href/target on <a> elements, with protocol filtering.
 */
function buildSafeDocFragment(html) {
  const parser  = new DOMParser();
  const parsed  = parser.parseFromString(String(html ?? ''), 'text/html');
  const fragment = document.createDocumentFragment();
  const allowedTags = new Set([
    'H3','H4','P','UL','OL','LI','PRE','CODE','STRONG','EM','A','BR','SPAN',
  ]);
  const allowedLinkProtocols = new Set(['http:','https:','mailto:','tel:']);

  function sanitizeNode(node) {
    if (node.nodeType === Node.TEXT_NODE)
      return document.createTextNode(node.textContent || '');
    if (node.nodeType !== Node.ELEMENT_NODE) return null;

    if (!allowedTags.has(node.tagName)) {
      // Unwrap: keep children, drop the tag itself
      const frag = document.createDocumentFragment();
      node.childNodes.forEach(child => {
        const safe = sanitizeNode(child);
        if (safe) frag.appendChild(safe);
      });
      return frag;
    }

    const safeEl = document.createElement(node.tagName.toLowerCase());

    if (node.tagName === 'A') {
      const href = node.getAttribute('href');
      if (href) {
        try {
          const url = new URL(href, window.location.origin);
          if (allowedLinkProtocols.has(url.protocol)) safeEl.setAttribute('href', href);
        } catch (_) { /* drop invalid URL */ }
      }
      if (node.getAttribute('target') === '_blank') {
        safeEl.setAttribute('target', '_blank');
        safeEl.setAttribute('rel', 'noopener noreferrer');
      }
    }

    node.childNodes.forEach(child => {
      const safe = sanitizeNode(child);
      if (safe) safeEl.appendChild(safe);
    });
    return safeEl;
  }

  parsed.body.childNodes.forEach(node => {
    const safe = sanitizeNode(node);
    if (safe) fragment.appendChild(safe);
  });
  return fragment;
}

function renderDoc(key) {
  const data = DOCS[key];
  const body = document.getElementById('doc-body');
  if (!body || !data) return;
  body.textContent = '';
  body.appendChild(buildSafeDocFragment(data.body));
  document.querySelectorAll('.docs-nav-item').forEach(item => {
    item.classList.toggle('active', item.dataset.doc === key);
  });
}

const DOCS = {
  intro: {
    title: 'Introduction',
    body: `<h3>What is logrodzyni?</h3>
<p>logrodzyni is a <strong>universal-purpose acceleration platform</strong> — an integrated system delivering a high-performance proxy engine, a distributed shard framework, an experimental programming language (HoloLang), and an intelligent operating canvas, all governed from one interface.</p>
<h4>The Four Pillars</h4>
<ul>
  <li><strong>Proxy Effective Engine (logrodzyni)</strong> — L4/L7 traffic routing with mTLS, real-time ACL enforcement, and dynamic upstream cluster management. The core relay powering every hop.</li>
  <li><strong>Shard Framework — All-Round</strong> — Distributed data partitioning using tensor objects, graph-collected data, and encrypted block records. Tensors carry data; shards coordinate the network-regulated exchange.</li>
  <li><strong>HoloLang</strong> — An experimental programming language for processing pipelines and device-level programming. Ships with its own native compiler. Methodology-first, kaizen-inspired, macro-mapping aware.</li>
  <li><strong>Canvas IDE / Operating Systems</strong> — Collects all pillars. Machine Learning and Neural Networks built into a Domain Specific Language, C Preprocessor integration, and Proto-based extensibility.</li>
</ul>
<h4>Architecture</h4>
<p>logrodzyni uses a layered circuit model: <code>Ingress Gateway → Relay Nodes → Egress Node → Policy Engine</code>. All inter-service communication is protected by mTLS with short-lived leaf certificates issued by the shared-security CA.</p>
<h4>Status</h4>
<p>The project is currently in active development and has not yet been publicly released. Documentation is being filled in progressively as features stabilise. <em>Watch this space for updates.</em></p>`
  },
  quickstart: {
    title: 'Quickstart',
    body: `<h3>Get Started in Minutes</h3>
<h4>1. Create your account</h4>
<p>Click <strong>Get Started</strong> on the landing page or <strong>Register</strong> in the sign-in panel. Choose a username (3–32 chars) and a password (minimum 8 characters). No admin approval required — your account is ready immediately with <code>viewer</code> role. An admin can elevate your role to <code>operator</code> or <code>admin</code>.</p>
<h4>2. Register your first node</h4>
<pre>POST /api/nodes
{
  "host": "10.0.0.1",
  "port": 1080,
  "role": "relay",
  "region": "us-east-1"
}</pre>
<h4>3. Configure a policy</h4>
<pre>POST /api/policies
{
  "name": "allow-all",
  "action": "allow",
  "priority": 10
}</pre>
<h4>4. Obtain a JWT</h4>
<p>Use the built-in <strong>JWT Creator</strong> page to mint and sign tokens, or call <code>POST /api/auth/login</code> directly.</p>`
  },
  'auth-doc': {
    title: 'Authentication',
    body: `<h3>Authentication Methods</h3>
<h4>Password</h4>
<p>Standard username + bcrypt password authentication. Credentials are never stored in plain text.</p>
<pre>POST /api/auth/login
{ "username": "admin", "password": "secret" }</pre>
<h4>SHA-256 Key</h4>
<p>Authenticate with a 64-char hex SHA-256 key. The key is hashed client-side via Web Crypto before transmission.</p>
<pre>POST /api/auth/login/sha256
{ "username": "operator", "key": "&lt;hex&gt;" }</pre>
<h4>MetaMask / Wallet</h4>
<p>EIP-191 challenge-response authentication. Request a challenge, sign with <code>personal_sign</code>, submit the signature. No gas or transaction required.</p>
<h4>Guest</h4>
<p>Ephemeral read-only viewer token. Expires in 2 hours. No credentials required. No account created.</p>
<h4>Session Persistence</h4>
<p>Your session token is stored in <code>localStorage</code> and survives browser restarts. Sign out explicitly to clear it.</p>`
  },
  'register-doc': {
    title: 'Account Registration',
    body: `<h3>Creating an Account</h3>
<p>Self-registration is open to anyone. <strong>No admin approval required.</strong> New accounts receive the <code>viewer</code> role by default.</p>
<h4>Requirements</h4>
<ul>
  <li>Username: 3–32 characters, alphanumeric, hyphens, underscores</li>
  <li>Password: minimum 8 characters</li>
  <li>Display name: optional, 1–64 characters</li>
  <li>Reserved usernames (e.g. <code>guest</code>) are not available for self-registration</li>
</ul>
<h4>API</h4>
<pre>POST /api/auth/register
{
  "username": "alice",
  "password": "secure-pass",
  "display_name": "Alice"
}</pre>
<p>Returns a JWT with <code>role: "viewer"</code> on success. An administrator can promote the account to <code>operator</code> or <code>admin</code>.</p>
<h4>Philosophy</h4>
<p>Every repository owner controls their own infrastructure. Open registry — free for all. No centralised gating.</p>`
  },
  'proxy-doc': {
    title: 'Proxy Layer',
    body: `<h3>Proxy Effective Engine — logrodzyni</h3>
<p>The proxy layer is the core relay of logrodzyni. It handles all incoming traffic, applies ACL policies, performs TLS termination, and load-balances across registered upstream nodes.</p>
<h4>Node Roles</h4>
<ul>
  <li><code>ingress</code> — Public-facing entry point, handles TLS + client auth.</li>
  <li><code>relay</code> — Internal hop node, forwards traffic between ingress and egress.</li>
  <li><code>egress</code> — Connects to the final upstream destination.</li>
</ul>
<h4>Protocols</h4>
<p>SOCKS5 (RFC 1928) and HTTP CONNECT on configurable ports. Bidirectional async relay using Boost.Asio epoll I/O. Up to 10,000 concurrent sessions per relay node.</p>
<h4>Performance</h4>
<p>Target: &lt;5ms P99 overhead per hop; &lt;50ms end-to-end for a 3-hop circuit; 1 Gbps+ aggregate throughput.</p>`
  },
  'shards-doc': {
    title: 'Shard Framework',
    body: `<h3>Shard Framework — All-Round</h3>
<p>The Shard Framework is the distributed data backbone of logrodzyni. It provides automatic data partitioning using consistent hashing and introduces a <strong>tensor-based object model</strong> for data exchange across the network.</p>
<h4>Data Model</h4>
<ul>
  <li><strong>Tensor objects</strong> — A tensor is an object with assigned data. When two tensors exist in the same environment, they share the same underlying data. Think of it like assigning an object reference — same environment, same data.</li>
  <li><strong>Graph-collected data</strong> — Tensors collect data from graphs. Graph nodes represent data relationships; edges encode the flow between tensors.</li>
  <li><strong>Blocks</strong> — A block registers graph and shard data, then persistently saves it in <code>[~]</code> encrypted form — safe for public distribution under kaizen/lean principles.</li>
  <li><strong>Attribute-driven discovery</strong> — Tensors carry attributes that define what data they hold. When tensors with matching attributes find each other across the network, they exchange data via a network-regulated method. Open registry — no centralised coordinator.</li>
</ul>
<h4>Key Features</h4>
<ul>
  <li>Consistent hashing ring with virtual nodes</li>
  <li>Zero-downtime rebalancing triggered by node join/leave</li>
  <li>Cross-shard query routing at the gateway layer</li>
  <li>Hot-shard detection and automatic split</li>
  <li>Macro and algorithm mappings for record persistence</li>
  <li>Encrypted block storage — <code>[~]</code> format</li>
</ul>
<p><em>📋 Full tensor specification and block format — coming soon when the project is publicly released.</em></p>`
  },
  'holo-doc': {
    title: 'Holography',
    body: `<h3>Holography</h3>
<p>Multi-region state replication with causal consistency guarantees. Holographic projections allow you to inspect a live snapshot of any region's data topology without disrupting production traffic.</p>
<h4>Consistency Modes</h4>
<ul>
  <li><code>causal</code> — Reads always reflect causally prior writes. Default for user-state projections.</li>
  <li><code>eventual</code> — Best-effort propagation. Suitable for policy mirrors and configuration data.</li>
  <li><code>strong</code> — Linearizable reads. Use for financial or critical coordination data.</li>
</ul>
<h4>Relationship to HoloLang</h4>
<p>HoloLang, the experimental processing language, takes its name and some of its tensor-sharing semantics from this holographic replication model. See the <strong>HoloLang</strong> section for details on the language itself.</p>`
  },
  'hololang-doc': {
    title: 'HoloLang',
    body: `<h3>HoloLang — Experimental Language</h3>
<p>HoloLang is an experimental programming language purpose-built for <strong>processing pipelines</strong> and <strong>device-level programming</strong>. It ships with its own native compiler and follows a deliberate, methodology-first approach to language and system design.</p>
<h4>Design Philosophy</h4>
<ul>
  <li>Kaizen-inspired incremental design — every construct has a minimal, deliberate purpose.</li>
  <li>Lean programming model — no waste; every token serves the pipeline.</li>
  <li>Macro and algorithm mappings baked into the language grammar.</li>
  <li>First-class support for tensor-like data objects with graph-aware attributes.</li>
  <li>Open registry semantics — free for all, no admin gating.</li>
</ul>
<h4>Core Concepts</h4>
<ul>
  <li><strong>Tensors as objects</strong> — Assign data to a tensor; sharing the same environment means sharing the same data.</li>
  <li><strong>Attribute-driven networking</strong> — Tensors discover peers by matching attributes and exchange data via network-regulated channels.</li>
  <li><strong>Encrypted records</strong> — All shard/tensor data is persisted in <code>[~]</code> encrypted form for safe public distribution.</li>
  <li><strong>Macro mappings</strong> — Algorithmic patterns encoded as macros enable safe, repeatable transformations across devices.</li>
</ul>
<h4>Compiler</h4>
<p>The HoloLang compiler is a native toolchain purpose-built for the language, targeting processing units and device-level execution environments. The compiler is currently in active development.</p>
<p><em>📋 Full language specification, grammar, and compiler binaries — coming soon when the project is publicly released.</em></p>`
  },
  'os-doc': {
    title: 'Canvas IDE & Oper. Systems',
    body: `<h3>Canvas IDE — Operating Systems</h3>
<p>The Operating Systems pillar collects all four logrodzyni components and delivers them through <strong>Canvas IDE</strong> — an integrated development environment with Machine Learning and Neural Networks built directly into its Domain Specific Language.</p>
<h4>Canvas IDE</h4>
<ul>
  <li><strong>Domain Specific Language (DSL)</strong> — Purpose-built for expressing proxy routing, shard topology, holographic projections, and ML pipeline configuration in one unified grammar.</li>
  <li><strong>Machine Learning built-in</strong> — Training, inference, and anomaly detection are first-class language constructs, not bolted-on libraries.</li>
  <li><strong>Neural Network primitives</strong> — Graph-based NN definitions directly in the IDE grammar, compatible with the Shard tensor model.</li>
  <li><strong>C Preprocessor integration</strong> — Macro expansion and conditional compilation at the IDE level for zero-overhead abstractions.</li>
  <li><strong>Proto extensibility</strong> — Protocol Buffer definitions for inter-service communication schemas, enabling typed cross-component contracts.</li>
</ul>
<h4>Current Capabilities</h4>
<ul>
  <li>Real-time process orchestration and resource scheduling</li>
  <li>CPU/memory threshold alerting with ML anomaly baseline</li>
  <li>Automated runbook execution on alert trigger</li>
  <li>Cron-style job scheduling with distributed locking</li>
</ul>
<p><em>📋 Canvas IDE full specification, language grammar, and IDE release — coming soon when the project is publicly released.</em></p>`
  },
  'api-auth': {
    title: 'Auth API Reference',
    body: `<h3>Auth Endpoints</h3>
<pre>POST /api/auth/register      — Create account (open, no approval required)
POST /api/auth/login         — Password login
POST /api/auth/login/sha256  — SHA-256 key login
GET  /api/auth/wallet/challenge — Request wallet challenge nonce
POST /api/auth/wallet/verify — Verify wallet signature (EIP-191)
POST /api/auth/guest         — Guest token (read-only, 2h TTL)
POST /api/auth/logout        — Logout (client discards token)
GET  /api/account            — Get profile (auth required, not guest)
PATCH /api/account           — Update profile / change password</pre>
<h4>Response</h4>
<p>All auth endpoints return <code>{ token, role, username, expiresIn }</code> on success. Include the token as <code>Authorization: Bearer &lt;token&gt;</code> in subsequent requests.</p>
<h4>Roles</h4>
<pre>viewer   — read-only access (default for new accounts and guests)
operator — read/write nodes, sessions, policies
admin    — full CRUD including user management</pre>`
  },
  'api-nodes': {
    title: 'Nodes API',
    body: `<h3>Nodes API</h3>
<pre>GET    /api/nodes        — List all nodes (viewer+)
POST   /api/nodes        — Register node (operator+)
GET    /api/nodes/:id    — Get node (viewer+)
PUT    /api/nodes/:id    — Update node (operator+)
DELETE /api/nodes/:id    — Delete node (admin)</pre>
<h4>Node Object</h4>
<pre>{
  "id": "uuid",
  "host": "10.0.0.1",
  "port": 1080,
  "role": "relay",
  "region": "us-east-1",
  "status": "active",
  "created_at": "2026-01-01T00:00:00Z"
}</pre>`
  },
  'api-jwt': {
    title: 'JWT Guide',
    body: `<h3>JWT Security Guide</h3>
<h4>Best Practices</h4>
<ul>
  <li>Always set an <code>exp</code> claim. Short-lived tokens (≤8h) reduce blast radius on theft.</li>
  <li>Store tokens in <code>httpOnly</code> cookies or memory — never <code>localStorage</code> in untrusted environments. logrodzyni uses <code>localStorage</code> for convenience; evaluate your own threat model.</li>
  <li>Always verify the <code>alg</code> header server-side and reject <code>alg:none</code>.</li>
  <li>Rotate signing secrets regularly. Keep an old-key grace period for in-flight tokens.</li>
  <li>Never embed sensitive PII in the payload — it's only base64, not encrypted.</li>
  <li>Use short claim names (<code>sub</code>, <code>iss</code>, <code>aud</code>) per RFC 7519.</li>
</ul>
<h4>logrodzyni JWT Structure</h4>
<pre>Header: { "alg": "HS256", "typ": "JWT" }
Payload: { "id", "username", "role", "authType", "iat", "exp" }</pre>`
  },
};

document.querySelectorAll('.docs-nav-item').forEach(item => {
  item.addEventListener('click', () => renderDoc(item.dataset.doc));
});

// ── Global escape key ─────────────────────────────────────────────────────────
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    closeAuth();
    document.querySelectorAll('.modal-overlay.open').forEach(m => closeModal(m.id));
  }
});

// ── Auto-restore ──────────────────────────────────────────────────────────────
// (handled above via `if (token) showApp()` at init)
