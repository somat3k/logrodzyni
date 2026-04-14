'use strict';

// ── State ─────────────────────────────────────────────────────────────────────
let token = sessionStorage.getItem('token') || null;
let userRole = sessionStorage.getItem('role') || null;

// ── Helpers ───────────────────────────────────────────────────────────────────

async function api(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  if (body)  opts.body = JSON.stringify(body);
  const res = await fetch('/api' + path, opts);
  if (res.status === 204) return null;
  return res.json();
}

function showAlert(containerId, msg, type = 'success') {
  const el = document.getElementById(containerId);
  el.innerHTML = `<div class="alert ${type}">${msg}</div>`;
  setTimeout(() => { el.innerHTML = ''; }, 4000);
}

function badge(text, cls) {
  return `<span class="badge ${cls}">${text}</span>`;
}

// ── Auth ──────────────────────────────────────────────────────────────────────

document.getElementById('login-btn').addEventListener('click', async () => {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  const err = document.getElementById('login-error');
  err.textContent = '';

  try {
    const data = await api('POST', '/auth/login', { username, password });
    if (data.error) { err.textContent = data.error; return; }
    token    = data.token;
    userRole = data.role;
    sessionStorage.setItem('token', token);
    sessionStorage.setItem('role', userRole);
    showDashboard(username);
  } catch (e) {
    err.textContent = 'Login failed: ' + e.message;
  }
});

document.getElementById('password').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('login-btn').click();
});

document.getElementById('logout-btn').addEventListener('click', () => {
  token    = null;
  userRole = null;
  sessionStorage.clear();
  document.getElementById('dashboard').style.display   = 'none';
  document.getElementById('login-screen').style.display = 'flex';
});

// ── Navigation ────────────────────────────────────────────────────────────────

document.querySelectorAll('nav button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('page-' + btn.dataset.page).classList.add('active');
    if (btn.dataset.page === 'nodes')    loadNodes();
    if (btn.dataset.page === 'sessions') loadSessions();
    if (btn.dataset.page === 'policies') loadPolicies();
    if (btn.dataset.page === 'overview') loadOverview();
  });
});

// ── Dashboard bootstrap ───────────────────────────────────────────────────────

function showDashboard(username) {
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('dashboard').style.display    = 'block';
  document.getElementById('user-info').textContent      = `${username} (${userRole})`;
  loadOverview();
}

// ── Overview ──────────────────────────────────────────────────────────────────

async function loadOverview() {
  const [nodes, sessions, policies] = await Promise.all([
    api('GET', '/nodes'),
    api('GET', '/sessions'),
    api('GET', '/policies'),
  ]);
  document.getElementById('stat-nodes').textContent    = Array.isArray(nodes)    ? nodes.length    : '—';
  document.getElementById('stat-sessions').textContent = Array.isArray(sessions) ? sessions.length : '—';
  document.getElementById('stat-policies').textContent = Array.isArray(policies) ? policies.length : '—';

  const tbody = document.querySelector('#tbl-nodes-overview tbody');
  tbody.innerHTML = '';
  (nodes || []).forEach(n => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${n.host}</td><td>${n.port}</td><td>${badge(n.role, n.role)}</td><td>${badge(n.status, n.status)}</td><td>${n.region || '—'}</td>`;
    tbody.appendChild(tr);
  });
}

// ── Nodes ─────────────────────────────────────────────────────────────────────

async function loadNodes() {
  const nodes = await api('GET', '/nodes');
  const tbody = document.querySelector('#tbl-nodes tbody');
  tbody.innerHTML = '';
  (nodes || []).forEach(n => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="font-size:.75rem;color:var(--muted)">${n.id.slice(0,8)}…</td>
      <td>${n.host}</td><td>${n.port}</td>
      <td>${badge(n.role, n.role)}</td>
      <td>${badge(n.status || 'registered', n.status || 'active')}</td>
      <td>${n.region || '—'}</td>
      <td><button onclick="deleteNode('${n.id}')" style="background:var(--err);border:none;color:#fff;padding:.25rem .6rem;border-radius:4px;cursor:pointer;font-size:.8rem">Delete</button></td>`;
    tbody.appendChild(tr);
  });
}

async function deleteNode(id) {
  if (!confirm('Delete this node?')) return;
  await api('DELETE', '/nodes/' + id);
  loadNodes();
}

document.getElementById('form-add-node').addEventListener('submit', async e => {
  e.preventDefault();
  const fd   = new FormData(e.target);
  const body = {
    host:   fd.get('host'),
    port:   parseInt(fd.get('port'), 10),
    role:   fd.get('role'),
    region: fd.get('region') || null,
  };
  const res = await api('POST', '/nodes', body);
  if (res && res.error) {
    showAlert('node-alert', res.error, 'error');
  } else {
    showAlert('node-alert', 'Node registered successfully', 'success');
    e.target.reset();
    loadNodes();
  }
});

// ── Sessions ──────────────────────────────────────────────────────────────────

async function loadSessions() {
  const sessions = await api('GET', '/sessions');
  const filter   = document.getElementById('session-filter').value.toLowerCase();
  const tbody    = document.querySelector('#tbl-sessions tbody');
  tbody.innerHTML = '';
  (sessions || [])
    .filter(s => !filter || (s.dstHost || '').toLowerCase().includes(filter))
    .forEach(s => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-size:.75rem;color:var(--muted)">${s.id.slice(0,8)}…</td>
        <td>${s.srcIp}</td><td>${s.dstHost}</td><td>${s.dstPort}</td>
        <td>${s.bytesSent}</td><td>${s.bytesRecv}</td>
        <td>${badge(s.status, s.status)}</td>
        <td><button onclick="terminateSession('${s.id}')" style="background:var(--warn);border:none;color:#000;padding:.25rem .6rem;border-radius:4px;cursor:pointer;font-size:.8rem">Terminate</button></td>`;
      tbody.appendChild(tr);
    });
}

async function terminateSession(id) {
  await api('DELETE', '/sessions/' + id);
  loadSessions();
}

document.getElementById('refresh-sessions').addEventListener('click', loadSessions);
document.getElementById('session-filter').addEventListener('input', loadSessions);

// ── Policies ──────────────────────────────────────────────────────────────────

async function loadPolicies() {
  const policies = await api('GET', '/policies');
  const tbody    = document.querySelector('#tbl-policies tbody');
  tbody.innerHTML = '';
  (policies || []).forEach(p => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${p.priority}</td>
      <td>${p.srcIpPrefix || '—'}</td>
      <td>${p.dstHostGlob || '—'}</td>
      <td>${(p.dstPorts || []).join(', ') || '—'}</td>
      <td>${badge(p.verdict, p.verdict === 'allow' ? 'active' : 'terminated')}</td>
      <td style="font-size:.8rem;color:var(--muted)">${p.description || '—'}</td>
      <td><button onclick="deletePolicy('${p.id}')" style="background:var(--err);border:none;color:#fff;padding:.25rem .6rem;border-radius:4px;cursor:pointer;font-size:.8rem">Delete</button></td>`;
    tbody.appendChild(tr);
  });
}

async function deletePolicy(id) {
  if (!confirm('Delete this policy?')) return;
  await api('DELETE', '/policies/' + id);
  loadPolicies();
}

document.getElementById('form-add-policy').addEventListener('submit', async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const portsRaw = fd.get('dstPorts');
  const dstPorts = portsRaw
    ? portsRaw.split(',').map(p => parseInt(p.trim(), 10)).filter(Boolean)
    : [];

  const body = {
    priority:    parseInt(fd.get('priority'), 10),
    srcIpPrefix: fd.get('srcIpPrefix') || null,
    dstHostGlob: fd.get('dstHostGlob') || null,
    dstPorts,
    verdict:     fd.get('verdict'),
    description: fd.get('description') || '',
  };
  const res = await api('POST', '/policies', body);
  if (res && res.error) {
    showAlert('policy-alert', res.error, 'error');
  } else {
    showAlert('policy-alert', 'Policy rule added', 'success');
    e.target.reset();
    loadPolicies();
  }
});

// ── Auto-login if token present ───────────────────────────────────────────────

if (token) {
  const stored = sessionStorage.getItem('username') || 'user';
  showDashboard(stored);
}
