const csrf = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
const tokenInput = document.getElementById('admin-token');
const tokenModal = document.getElementById('token-modal');
const modalTokenStatus = document.getElementById('modal-token-status');

// Set initial token value
tokenInput.value = sessionStorage.getItem('admin_token') || '';
updateTokenUIState();

// Save Token Handler
document.getElementById('token-form').addEventListener('submit', (e) => {
  e.preventDefault();
  sessionStorage.setItem('admin_token', tokenInput.value);
  updateTokenUIState();
  tokenModal.close();
  showToast('Admin authorization token updated');
  // Reload current active tab
  const activeBtn = document.querySelector('.nav-btn.active');
  if (activeBtn) activeBtn.click();
});

// Show Modal trigger
document.getElementById('btn-show-token-modal').addEventListener('click', () => {
  tokenInput.value = sessionStorage.getItem('admin_token') || '';
  updateTokenUIState();
  tokenModal.showModal();
});

function updateTokenUIState() {
  const val = sessionStorage.getItem('admin_token') || '';
  const solid = document.getElementById('auth-ping-solid');
  const glowing = document.getElementById('auth-ping-glowing');
  const title = document.getElementById('auth-status-title');
  const desc = document.getElementById('auth-status-desc');

  if (val) {
    solid.className = 'relative inline-flex rounded-full h-2 w-2 bg-indigo-500';
    glowing.className = 'animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 bg-indigo-400';
    title.textContent = 'Bearer Auth';
    desc.textContent = 'Token is set';
    modalTokenStatus.innerHTML = '<span class="text-indigo-600 dark:text-indigo-400 font-semibold">Active: Bearer mode</span>';
  } else {
    solid.className = 'relative inline-flex rounded-full h-2 w-2 bg-emerald-500';
    glowing.className = 'animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 bg-emerald-400';
    title.textContent = 'Anonymous';
    desc.textContent = 'No token (Local Dev)';
    modalTokenStatus.innerHTML = '<span class="text-emerald-600 dark:text-emerald-400 font-semibold">Active: Anonymous mode</span>';
  }
}

export function adminToken() {
  return sessionStorage.getItem('admin_token') || '';
}

// --- Dynamic Toast System ---
export function showToast(message, type = 'success') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full px-4';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  const bgClass = type === 'error' 
    ? 'bg-red-600 dark:bg-red-900/90 text-white border-red-500/20' 
    : 'bg-indigo-600 dark:bg-indigo-900/90 text-white border-indigo-500/20';
  const icon = type === 'error' ? 'alert-triangle' : 'check-circle';
  toast.className = `flex items-center gap-3 p-4 rounded-xl shadow-lg border backdrop-blur-md ${bgClass} transition-all duration-300 transform translate-y-2 opacity-0`;
  toast.innerHTML = `<i data-lucide="${icon}" class="w-5 h-5 shrink-0"></i>
                     <span class="text-sm font-semibold">${esc(message)}</span>`;
  container.appendChild(toast);
  lucide.createIcons();

  // Animate in
  setTimeout(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  }, 10);

  // Animate out and remove
  setTimeout(() => {
    toast.classList.add('translate-y-2', 'opacity-0');
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// --- API Wrapper ---
export async function call(method, path, body) {
  const headers = {'X-CSRF-Token': csrf};
  const tok = adminToken();
  if (tok) headers['Authorization'] = 'Bearer ' + tok;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  
  try {
    const resp = await fetch(path, {method, headers, body: body !== undefined ? JSON.stringify(body) : undefined});
    if (resp.status === 401) {
      sessionStorage.removeItem('admin_token');
      updateTokenUIState();
      throw new Error('401 Unauthorized — check your admin token');
    }
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`${method} ${path} → ${resp.status} ${text}`);
    }
    if (resp.status === 204) return null;
    return await resp.json();
  } catch(e) {
    console.error(e);
    throw e;
  }
}

export function esc(s) {
  return s === null || s === undefined 
    ? '' 
    : String(s).replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'})[c]);
}

// --- Theme Toggle ---
const html = document.documentElement;
const themeToggle = document.getElementById('theme-toggle');

if (localStorage.getItem('theme') === 'light') {
  html.classList.remove('dark');
} else {
  html.classList.add('dark');
  localStorage.setItem('theme', 'dark');
}

themeToggle.addEventListener('click', () => {
  if (html.classList.contains('dark')) {
    html.classList.remove('dark');
    localStorage.setItem('theme', 'light');
  } else {
    html.classList.add('dark');
    localStorage.setItem('theme', 'dark');
  }
});

// --- Tab Routing Registry ---
const routingRegistry = {
  'dashboard': () => import('./components/dashboard.js').then(m => m.showDashboard()),
  'clients': () => import('./components/clients.js').then(m => m.showClients()),
  'scopes': () => import('./components/scopes.js').then(m => m.showScopes()),
  'users': () => import('./components/users.js').then(m => m.showUsers()),
  'roles': () => import('./components/roles.js').then(m => m.showRoles()),
  'sessions': () => import('./components/sessions.js').then(m => m.showSessions()),
  'refresh-tokens': () => import('./components/tokens.js').then(m => m.showTokens()),
  'keys': () => import('./components/keys.js').then(m => m.showKeys()),
  'audit': () => import('./components/audit.js').then(m => m.showAudit()),
};

document.querySelectorAll('nav button').forEach(btn => {
  btn.addEventListener('click', async () => {
    const tab = btn.getAttribute('data-tab');
    const out = document.getElementById('content');
    
    // Update sidebar active styling
    document.querySelectorAll('.nav-btn').forEach(b => {
      b.className = 'nav-btn w-full flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100 hover:bg-zinc-100 dark:hover:bg-zinc-800';
    });
    btn.className = 'nav-btn w-full flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-bold bg-indigo-600 text-white shadow-md shadow-indigo-500/10 transition-all duration-200';
    btn.classList.add('active');

    // Update page title
    document.getElementById('current-tab-title').textContent = btn.textContent.trim();

    // Route execution
    const loader = routingRegistry[tab];
    if (loader) {
      try {
        await loader();
      } catch (err) {
        out.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 rounded-xl p-4 text-sm font-semibold">${esc(err.message)}</div>`;
      }
    }
  });
});

// Boot Default Tab
document.querySelector('[data-tab=dashboard]').click();
