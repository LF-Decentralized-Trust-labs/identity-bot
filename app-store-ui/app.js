const API = '/api';
let currentSection = 'apps';

async function api(path, opts = {}) {
  const res = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json', ...opts.headers },
    ...opts,
  });
  if (res.status === 204) return null;
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `Request failed: ${res.status}`);
  return data;
}

function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = `toast show ${type}`;
  setTimeout(() => t.className = 'toast', 3000);
}

function navigate(section) {
  currentSection = section;
  document.querySelectorAll('.nav-item').forEach(n =>
    n.classList.toggle('active', n.dataset.section === section)
  );
  document.querySelectorAll('.section').forEach(s =>
    s.classList.toggle('section-hidden', s.id !== `section-${section}`)
  );
  if (section === 'apps') loadApps();
  else if (section === 'policies') loadPolicies();
  else if (section === 'audit') loadAuditLog();
}

async function loadStats() {
  try {
    const [appsData, policiesData, auditData] = await Promise.all([
      api('/apps'),
      api('/policies'),
      api('/audit-log?limit=1000'),
    ]);
    const apps = appsData.apps || [];
    const running = apps.filter(a => a.status === 'running').length;
    document.getElementById('stat-total').textContent = apps.length;
    document.getElementById('stat-running').textContent = running;
    document.getElementById('stat-policies').textContent = (policiesData.policies || []).length;
    document.getElementById('stat-events').textContent = (auditData.entries || []).length;
  } catch (e) {
    console.error('Failed to load stats:', e);
  }
}

async function loadApps() {
  loadStats();
  try {
    const data = await api('/apps');
    const apps = data.apps || [];
    const policies = (await api('/policies')).policies || [];
    const grid = document.getElementById('apps-grid');

    if (apps.length === 0) {
      grid.innerHTML = `
        <div class="empty-state" style="grid-column: 1 / -1;">
          <div class="icon">&#128230;</div>
          <h3>No Apps Registered</h3>
          <p>Register your first app to start monitoring its behavior in the sandbox.</p>
        </div>`;
      return;
    }

    grid.innerHTML = apps.map(app => {
      const policy = policies.find(p => p.id === app.policy_id);
      return `
      <div class="card app-card">
        <div class="app-card-header">
          <h3>${esc(app.name)}</h3>
          <span class="status-badge status-${app.status}">
            <span class="status-dot"></span>${app.status}
          </span>
        </div>
        <div class="app-meta">
          <span>&#128196; ${esc(app.language)}</span>
          <span>&#128197; ${formatDate(app.registered_at)}</span>
        </div>
        <div class="app-desc">${esc(app.description || 'No description')}</div>
        <div class="app-meta">
          ${policy ? `<span>Policy: <strong>${esc(policy.name)}</strong></span>` : '<span style="color:var(--warning)">No policy assigned</span>'}
        </div>
        <div class="app-actions">
          ${app.status === 'stopped'
            ? `<button class="btn btn-primary btn-sm" onclick="launchApp('${app.id}')">&#9654; Launch</button>`
            : `<button class="btn btn-secondary btn-sm" onclick="stopApp('${app.id}')">&#9724; Stop</button>`}
          <button class="btn btn-secondary btn-sm" onclick="showAssignPolicy('${app.id}')">&#128274; Policy</button>
          <button class="btn btn-danger btn-sm" onclick="deleteApp('${app.id}','${esc(app.name)}')">&#128465; Remove</button>
        </div>
      </div>`;
    }).join('');
  } catch (e) {
    showToast(e.message, 'error');
  }
}

async function launchApp(id) {
  try {
    await api(`/apps/${id}/launch`, { method: 'POST' });
    showToast('App launch command issued (stubbed)');
    loadApps();
  } catch (e) { showToast(e.message, 'error'); }
}

async function stopApp(id) {
  try {
    await api(`/apps/${id}/stop`, { method: 'POST' });
    showToast('App stopped');
    loadApps();
  } catch (e) { showToast(e.message, 'error'); }
}

async function deleteApp(id, name) {
  if (!confirm(`Remove "${name}"? This cannot be undone.`)) return;
  try {
    await api(`/apps/${id}`, { method: 'DELETE' });
    showToast(`"${name}" removed`);
    loadApps();
  } catch (e) { showToast(e.message, 'error'); }
}

function showModal(id) {
  document.getElementById(id).classList.add('active');
}

function hideModal(id) {
  document.getElementById(id).classList.remove('active');
}

async function submitRegisterApp(e) {
  e.preventDefault();
  const form = e.target;
  try {
    await api('/apps', {
      method: 'POST',
      body: JSON.stringify({
        name: form.name.value,
        description: form.description.value,
        language: form.language.value,
        entry_point: form.entry_point.value,
      }),
    });
    showToast('App registered');
    hideModal('modal-register-app');
    form.reset();
    loadApps();
  } catch (e) { showToast(e.message, 'error'); }
}

async function showAssignPolicy(appId) {
  const policies = (await api('/policies')).policies || [];
  const sel = document.getElementById('assign-policy-select');
  sel.innerHTML = '<option value="">-- No Policy --</option>' +
    policies.map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join('');
  document.getElementById('assign-policy-app-id').value = appId;
  showModal('modal-assign-policy');
}

async function submitAssignPolicy(e) {
  e.preventDefault();
  const appId = document.getElementById('assign-policy-app-id').value;
  const policyId = document.getElementById('assign-policy-select').value;
  try {
    await api(`/apps/${appId}/policy`, {
      method: 'PUT',
      body: JSON.stringify({ policy_id: policyId }),
    });
    showToast('Policy assigned');
    hideModal('modal-assign-policy');
    loadApps();
  } catch (e) { showToast(e.message, 'error'); }
}

async function loadPolicies() {
  try {
    const data = await api('/policies');
    const policies = data.policies || [];
    const list = document.getElementById('policies-list');

    if (policies.length === 0) {
      list.innerHTML = `
        <div class="empty-state">
          <div class="icon">&#128274;</div>
          <h3>No Policies Defined</h3>
          <p>Create a governance policy to control what sandboxed apps can do.</p>
        </div>`;
      return;
    }

    list.innerHTML = policies.map(p => `
      <div class="card policy-card">
        <div class="policy-info">
          <h4>${esc(p.name)}</h4>
          <p>${esc(p.description || 'No description')}</p>
          <div class="policy-rules">
            <span class="policy-tag">${p.allow_net_access ? '&#127760; Network: Allow' : '&#128683; Network: Deny'}</span>
            <span class="policy-tag">${p.allow_file_write ? '&#128196; File Write: Allow' : '&#128683; File Write: Deny'}</span>
            <span class="policy-tag">&#128176; Max Spend: $${p.max_spend.toFixed(2)}</span>
            ${(p.allowed_domains || []).length > 0 ? `<span class="policy-tag">&#9989; ${p.allowed_domains.length} allowed domain(s)</span>` : ''}
            ${(p.blocked_domains || []).length > 0 ? `<span class="policy-tag">&#128683; ${p.blocked_domains.length} blocked domain(s)</span>` : ''}
          </div>
        </div>
        <button class="btn btn-danger btn-sm" onclick="deletePolicy('${p.id}','${esc(p.name)}')">&#128465;</button>
      </div>
    `).join('');
  } catch (e) { showToast(e.message, 'error'); }
}

async function deletePolicy(id, name) {
  if (!confirm(`Delete policy "${name}"?`)) return;
  try {
    await api(`/policies/${id}`, { method: 'DELETE' });
    showToast(`Policy "${name}" deleted`);
    loadPolicies();
  } catch (e) { showToast(e.message, 'error'); }
}

async function submitCreatePolicy(e) {
  e.preventDefault();
  const form = e.target;
  const allowed = form.allowed_domains.value.split(',').map(s => s.trim()).filter(Boolean);
  const blocked = form.blocked_domains.value.split(',').map(s => s.trim()).filter(Boolean);
  try {
    await api('/policies', {
      method: 'POST',
      body: JSON.stringify({
        name: form.name.value,
        description: form.description.value,
        allowed_domains: allowed,
        blocked_domains: blocked,
        max_spend: parseFloat(form.max_spend.value) || 0,
        allow_file_write: document.getElementById('toggle-file-write').classList.contains('active'),
        allow_net_access: document.getElementById('toggle-net-access').classList.contains('active'),
      }),
    });
    showToast('Policy created');
    hideModal('modal-create-policy');
    form.reset();
    loadPolicies();
  } catch (e) { showToast(e.message, 'error'); }
}

async function loadAuditLog() {
  try {
    const data = await api('/audit-log?limit=200');
    const entries = data.entries || [];
    const tbody = document.getElementById('audit-tbody');

    if (entries.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:2rem;color:var(--text-muted);">
        No audit events yet. Events will appear here when apps are launched and monitored.</td></tr>`;
      return;
    }

    tbody.innerHTML = entries.map(e => `
      <tr>
        <td style="color:var(--text-muted);font-size:0.75rem;">${formatTime(e.timestamp)}</td>
        <td>${esc(e.app_name || e.app_id)}</td>
        <td><span class="audit-type audit-type-${e.event_type}">${e.event_type}</span></td>
        <td>${esc(e.target)}</td>
        <td>${esc(e.details)}</td>
        <td><span class="audit-action-${e.action}">${e.action}</span></td>
      </tr>
    `).join('');
  } catch (e) { showToast(e.message, 'error'); }
}

function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function formatDate(iso) {
  if (!iso) return 'N/A';
  return new Date(iso).toLocaleDateString();
}

function formatTime(iso) {
  if (!iso) return 'N/A';
  const d = new Date(iso);
  return d.toLocaleString();
}

function toggleSwitch(id) {
  document.getElementById(id).classList.toggle('active');
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-item').forEach(n => {
    n.addEventListener('click', () => navigate(n.dataset.section));
  });

  document.getElementById('form-register-app').addEventListener('submit', submitRegisterApp);
  document.getElementById('form-create-policy').addEventListener('submit', submitCreatePolicy);
  document.getElementById('form-assign-policy').addEventListener('submit', submitAssignPolicy);

  navigate('apps');
});
