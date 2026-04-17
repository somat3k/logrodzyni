'use strict';

const qs = id => document.getElementById(id);

const AUDIT_LIMIT_MIN = 1;
const AUDIT_LIMIT_MAX = 1000;
const AUDIT_LIMIT_DEFAULT = 200;
const NODE_PORT_MIN = 1;
const NODE_PORT_MAX = 65535;

function toast(message, type = '') {
  const root = qs('toasts');
  const node = document.createElement('div');
  node.className = `toast ${type}`.trim();
  node.textContent = message;
  root.appendChild(node);
  setTimeout(() => node.remove(), 3500);
}

async function api(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body) opts.body = JSON.stringify(body);

  const res = await fetch(`/api${path}`, opts);
  if (res.status === 204) return null;
  const payload = await res.json().catch(() => ({ error: res.statusText || 'Request failed' }));
  if (!res.ok) throw new Error(payload.error || `Request failed: ${res.status}`);
  return payload;
}

function setLastRefresh() {
  qs('last-refresh').textContent = new Date().toLocaleString();
}

function switchPage(page) {
  document.querySelectorAll('.tab[data-page]').forEach(tab => {
    tab.classList.toggle('active', tab.dataset.page === page);
  });
  document.querySelectorAll('.page').forEach(node => {
    node.classList.toggle('active', node.id === `page-${page}`);
  });
}

function rowActionButton(label, cls, onClick) {
  const btn = document.createElement('button');
  btn.textContent = label;
  if (cls) btn.classList.add(cls);
  btn.addEventListener('click', onClick);
  return btn;
}

function appendCell(tr, value = '') {
  const td = document.createElement('td');
  td.textContent = String(value ?? '');
  tr.appendChild(td);
  return td;
}

async function loadOverview() {
  const [nodes, sessions, policies, audit] = await Promise.all([
    api('GET', '/nodes'),
    api('GET', '/sessions'),
    api('GET', '/policies'),
    api('GET', '/audit?limit=200').catch(() => []),
  ]);

  qs('stat-nodes').textContent = nodes.length;
  qs('stat-sessions').textContent = sessions.filter(s => s.status === 'active').length;
  qs('stat-policies').textContent = policies.length;
  qs('stat-audit').textContent = audit.length;
}

async function loadNodes() {
  const nodes = await api('GET', '/nodes');
  const tbody = qs('nodes-tbody');
  tbody.textContent = '';

  nodes.forEach(node => {
    const tr = document.createElement('tr');
    appendCell(tr, node.host);
    appendCell(tr, node.port);
    appendCell(tr, node.role);
    appendCell(tr, node.region);
    appendCell(tr, node.status);
    const controls = appendCell(tr);

    controls.appendChild(rowActionButton('Delete', 'danger', async () => {
      try {
        await api('DELETE', `/nodes/${node.id}`);
        await refreshAll();
        toast('Node deleted');
      } catch (err) {
        toast(err.message, 'err');
      }
    }));

    tbody.appendChild(tr);
  });
}

async function loadSessions() {
  const sessions = await api('GET', '/sessions');
  const tbody = qs('sessions-tbody');
  tbody.textContent = '';

  sessions.forEach(session => {
    const tr = document.createElement('tr');
    appendCell(tr, session.id);
    appendCell(tr, session.client_ip);
    appendCell(tr, session.destination);
    appendCell(tr, session.status);
    const controls = appendCell(tr);

    if (session.status === 'active') {
      controls.appendChild(rowActionButton('Terminate', 'danger', async () => {
        try {
          await api('DELETE', `/sessions/${session.id}`);
          await refreshAll();
          toast('Session terminated');
        } catch (err) {
          toast(err.message, 'err');
        }
      }));
    }

    tbody.appendChild(tr);
  });
}

async function loadPolicies() {
  const policies = await api('GET', '/policies');
  const tbody = qs('policies-tbody');
  tbody.textContent = '';

  policies.forEach(policy => {
    const tr = document.createElement('tr');
    appendCell(tr, policy.name);
    appendCell(tr, policy.action);
    appendCell(tr, policy.priority);
    appendCell(tr, policy.src_cidr);
    appendCell(tr, `${policy.dst_host || ''}${policy.dst_ports ? `:${policy.dst_ports}` : ''}`);
    const controls = appendCell(tr);

    controls.appendChild(rowActionButton('Delete', 'danger', async () => {
      try {
        await api('DELETE', `/policies/${policy.id}`);
        await refreshAll();
        toast('Policy deleted');
      } catch (err) {
        toast(err.message, 'err');
      }
    }));

    tbody.appendChild(tr);
  });
}

async function loadAudit() {
  const rawLimit = Number(qs('audit-limit').value);
  const limit = Number.isFinite(rawLimit)
    ? Math.min(Math.max(rawLimit, AUDIT_LIMIT_MIN), AUDIT_LIMIT_MAX)
    : AUDIT_LIMIT_DEFAULT;
  const audit = await api('GET', `/audit?limit=${limit}`);
  const tbody = qs('audit-tbody');
  tbody.textContent = '';

  audit.forEach(item => {
    const tr = document.createElement('tr');
    appendCell(tr, item.ts);
    appendCell(tr, item.event);
    appendCell(tr, item.actor);
    appendCell(tr, item.result);
    appendCell(tr, item.target);
    tbody.appendChild(tr);
  });
}

async function createNode() {
  const host = qs('node-host').value.trim();
  const port = Number(qs('node-port').value);
  if (!host) throw new Error('Host is required');
  if (!Number.isInteger(port) || port < NODE_PORT_MIN || port > NODE_PORT_MAX) {
    throw new Error(`Port must be an integer between ${NODE_PORT_MIN} and ${NODE_PORT_MAX}`);
  }

  const body = {
    host,
    port,
    role: qs('node-role').value,
    region: qs('node-region').value.trim() || 'default',
    status: qs('node-status').value.trim() || 'pending',
  };
  await api('POST', '/nodes', body);
  qs('node-host').value = '';
  qs('node-port').value = '';
  toast('Node created');
  await refreshAll();
}

async function createSession() {
  const body = {
    client_ip: qs('session-client-ip').value.trim() || undefined,
    destination: qs('session-destination').value.trim() || '',
    node_id: qs('session-node-id').value.trim() || null,
  };
  await api('POST', '/sessions', body);
  qs('session-client-ip').value = '';
  qs('session-destination').value = '';
  qs('session-node-id').value = '';
  toast('Session created');
  await refreshAll();
}

async function createPolicy() {
  const priorityRaw = Number(qs('policy-priority').value || 0);
  if (!Number.isFinite(priorityRaw)) throw new Error('Policy priority must be numeric');

  const body = {
    name: qs('policy-name').value.trim(),
    action: qs('policy-action').value,
    priority: priorityRaw,
    src_cidr: qs('policy-src').value.trim() || null,
    dst_host: qs('policy-dst-host').value.trim() || null,
    dst_ports: qs('policy-dst-ports').value.trim() || null,
  };
  await api('POST', '/policies', body);
  qs('policy-name').value = '';
  qs('policy-src').value = '';
  qs('policy-dst-host').value = '';
  qs('policy-dst-ports').value = '';
  toast('Policy created');
  await refreshAll();
}

async function refreshAll() {
  try {
    await Promise.all([loadOverview(), loadNodes(), loadSessions(), loadPolicies(), loadAudit()]);
    setLastRefresh();
  } catch (err) {
    toast(err.message, 'err');
  }
}

function bindEvents() {
  document.querySelectorAll('.tab[data-page]').forEach(tab => {
    tab.addEventListener('click', () => switchPage(tab.dataset.page));
  });

  qs('refresh-all').addEventListener('click', refreshAll);
  qs('audit-refresh').addEventListener('click', async () => {
    try {
      await loadAudit();
      setLastRefresh();
    } catch (err) {
      toast(err.message, 'err');
    }
  });

  qs('node-create').addEventListener('click', async () => {
    try { await createNode(); } catch (err) { toast(err.message, 'err'); }
  });
  qs('session-create').addEventListener('click', async () => {
    try { await createSession(); } catch (err) { toast(err.message, 'err'); }
  });
  qs('policy-create').addEventListener('click', async () => {
    try { await createPolicy(); } catch (err) { toast(err.message, 'err'); }
  });
}

bindEvents();
refreshAll();
