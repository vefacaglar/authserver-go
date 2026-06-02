import { call, esc, showToast } from '../app.js';

function renderScopes(items) {
  let h = `
    <div class="flex items-center justify-between">
      <h3 class="text-lg font-bold tracking-tight">OIDC Scopes</h3>
      <button id="btn-new-scope" class="flex items-center justify-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-semibold shadow-md shadow-indigo-500/10 transition-colors">
        <i data-lucide="plus-circle" class="w-4 h-4"></i> New Scope
      </button>
    </div>
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mt-4">
  `;

  h += items.map(s => `
    <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-5 rounded-2xl flex flex-col justify-between shadow-sm relative overflow-hidden">
      ${s.required ? '<div class="absolute top-0 right-0 px-2 py-0.5 rounded-bl bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 text-[10px] font-bold uppercase tracking-wider">Required</div>' : ''}
      <div class="space-y-2">
        <code class="text-sm font-bold text-indigo-600 dark:text-indigo-400">${esc(s.name)}</code>
        <h4 class="font-bold text-base leading-tight">${esc(s.display_name || s.name)}</h4>
        <p class="text-xs text-zinc-500 dark:text-zinc-400 leading-relaxed">${esc(s.description || 'No description provided')}</p>
      </div>
      <div class="flex items-center justify-between border-t border-zinc-100 dark:border-zinc-800/80 pt-3 mt-4">
        <span class="text-[10px] text-zinc-400 font-semibold uppercase tracking-wider">OIDC Scope</span>
        <div class="flex gap-2">
          <button class="btn-edit-scope text-xs font-semibold text-zinc-600 hover:text-zinc-500 dark:text-zinc-400 dark:hover:text-zinc-300 inline-flex items-center gap-1" data-name="${esc(s.name)}">
            <i data-lucide="edit-3" class="w-3 h-3"></i> Edit
          </button>
          ${(s.name !== 'openid' && s.name !== 'profile' && s.name !== 'email' && s.name !== 'offline_access') ? `
            <button class="btn-del-scope text-xs font-semibold text-red-600 hover:text-red-500 inline-flex items-center gap-1" data-name="${esc(s.name)}">
              <i data-lucide="trash" class="w-3 h-3"></i> Delete
            </button>
          ` : '<span class="text-[10px] text-zinc-400">Core Protected</span>'}
        </div>
      </div>
    </div>
  `).join('');

  h += '</div>';
  return h;
}

function scopeForm(s = {}, isEdit = false) {
  return `
    <div class="flex items-center justify-between">
      <h3 class="text-lg font-bold tracking-tight">${isEdit ? 'Edit OIDC Scope' : 'Create OIDC Scope'}</h3>
      <button id="btn-back-scopes" class="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-xs font-semibold transition-colors">
        <i data-lucide="arrow-left" class="w-3.5 h-3.5"></i> Back to Scopes
      </button>
    </div>
    <form id="scope-form" class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-2xl p-6 md:p-8 shadow-sm space-y-5 max-w-xl mt-4">
      <div class="space-y-1">
        <label for="f-scope-name" class="text-xs font-semibold text-zinc-400 uppercase tracking-wider block">Scope Key *</label>
        <input id="f-scope-name" required placeholder="e.g. read_profile" value="${esc(s.name || '')}" ${isEdit ? 'readonly class="w-full px-3 py-2 bg-zinc-100 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm text-zinc-400 focus:outline-none"' : 'class="w-full px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white"'}>
      </div>
      <div class="space-y-1">
        <label for="f-scope-display" class="text-xs font-semibold text-zinc-400 uppercase tracking-wider block">Display Name</label>
        <input id="f-scope-display" placeholder="e.g. Read Profile Details" value="${esc(s.display_name || '')}" class="w-full px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white">
      </div>
      <div class="space-y-1">
        <label for="f-scope-desc" class="text-xs font-semibold text-zinc-400 uppercase tracking-wider block">Description</label>
        <input id="f-scope-desc" placeholder="Allows the OIDC client to read profile metadata" value="${esc(s.description || '')}" class="w-full px-3 py-2 bg-white dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:text-white">
      </div>
      <div class="flex items-center gap-3 pt-2">
        <label class="flex items-center gap-2 text-sm cursor-pointer">
          <input id="f-scope-req" type="checkbox" class="rounded border-zinc-300 dark:border-zinc-700 text-indigo-600 focus:ring-indigo-500" ${s.required ? 'checked' : ''}>
          <span>Required (Consent screen cannot skip this)</span>
        </label>
      </div>
      <div class="flex items-center justify-between pt-4 border-t border-zinc-100 dark:border-zinc-800 mt-4">
        <div>
          ${(isEdit && s.name !== 'openid' && s.name !== 'profile' && s.name !== 'email' && s.name !== 'offline_access') ? `
            <button type="button" id="btn-delete-scope" class="px-4 py-2 border border-red-200 dark:border-red-900/30 text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20 rounded-lg text-sm font-semibold transition-colors flex items-center gap-1.5">
              <i data-lucide="trash-2" class="w-4 h-4"></i> Delete Scope
            </button>
          ` : ''}
        </div>
        <div class="flex items-center gap-3">
          <button type="button" id="btn-cancel-scope" class="px-4 py-2 border border-zinc-200 dark:border-zinc-800 rounded-lg text-sm font-semibold hover:bg-zinc-50 dark:hover:bg-zinc-800 transition-colors">Cancel</button>
          <button type="submit" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-semibold shadow-md shadow-indigo-500/10 transition-colors">
            ${isEdit ? 'Save Changes' : 'Create Scope'}
          </button>
        </div>
      </div>
      <div id="form-error"></div>
    </form>
  `;
}

export async function showScopes() {
  const out = document.getElementById('content');
  out.innerHTML = '<p class="text-zinc-400">loading scopes…</p>';
  try {
    const r = await call('GET', '/admin/api/scopes');
    out.innerHTML = renderScopes(r.items || []);
    lucide.createIcons();

    const goBack = () => showScopes();

    document.getElementById('btn-new-scope').addEventListener('click', () => {
      out.innerHTML = scopeForm();
      lucide.createIcons();
      
      document.getElementById('btn-back-scopes').addEventListener('click', goBack);
      document.getElementById('btn-cancel-scope').addEventListener('click', goBack);

      document.getElementById('scope-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const errDiv = document.getElementById('form-error');
        errDiv.textContent = '';
        try {
          await call('POST', '/admin/api/scopes', {
            name: document.getElementById('f-scope-name').value.trim(),
            display_name: document.getElementById('f-scope-display').value.trim(),
            description: document.getElementById('f-scope-desc').value.trim(),
            required: document.getElementById('f-scope-req').checked
          });
          showToast('OIDC Scope registered successfully');
          showScopes();
        } catch(err) {
          errDiv.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 p-3 rounded-lg text-xs mt-3">${esc(err.message)}</div>`;
        }
      });
    });

    out.querySelectorAll('.btn-edit-scope').forEach(btn => {
      btn.addEventListener('click', () => {
        const name = btn.getAttribute('data-name');
        const s = (r.items || []).find(item => item.name === name);
        if (!s) return;
        
        out.innerHTML = scopeForm(s, true);
        lucide.createIcons();
        
        document.getElementById('btn-back-scopes').addEventListener('click', goBack);
        document.getElementById('btn-cancel-scope').addEventListener('click', goBack);

        const deleteBtn = document.getElementById('btn-delete-scope');
        if (deleteBtn) {
          deleteBtn.addEventListener('click', async () => {
            if (!confirm(`Are you sure you want to delete scope "${name}"?`)) return;
            try {
              await call('DELETE', '/admin/api/scopes/' + encodeURIComponent(name));
              showToast(`Scope "${name}" deleted successfully`);
              showScopes();
            } catch(e) {
              document.getElementById('form-error').innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 p-3 rounded-lg text-xs mt-3">${esc(e.message)}</div>`;
            }
          });
        }

        document.getElementById('scope-form').addEventListener('submit', async (e) => {
          e.preventDefault();
          const errDiv = document.getElementById('form-error');
          errDiv.textContent = '';
          try {
            await call('PUT', '/admin/api/scopes/' + encodeURIComponent(name), {
              name: name,
              display_name: document.getElementById('f-scope-display').value.trim(),
              description: document.getElementById('f-scope-desc').value.trim(),
              required: document.getElementById('f-scope-req').checked
            });
            showToast('OIDC Scope updated successfully');
            showScopes();
          } catch(err) {
            errDiv.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 p-3 rounded-lg text-xs mt-3">${esc(err.message)}</div>`;
          }
        });
      });
    });

    out.querySelectorAll('.btn-del-scope').forEach(btn => {
      btn.addEventListener('click', async () => {
        const name = btn.getAttribute('data-name');
        if (!confirm(`Are you sure you want to delete scope "${name}"?`)) return;
        try {
          await call('DELETE', '/admin/api/scopes/' + encodeURIComponent(name));
          showToast(`Scope "${name}" deleted successfully`);
          showScopes();
        } catch(e) {
          showToast(e.message, 'error');
        }
      });
    });
  } catch(e) {
    out.innerHTML = `<div class="bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 rounded-xl p-4 text-sm font-semibold">${esc(e.message)}</div>`;
  }
}
