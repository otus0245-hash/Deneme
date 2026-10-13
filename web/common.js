// Ortak yardımcılar: api(), el(), toast(), layout()
async function api(path, opts) {
  const r = await fetch(path, opts);
  if (r.status === 401 && location.pathname !== '/login') { location.href = '/login'; }
  if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
  const ct = r.headers.get('content-type') || '';
  return ct.includes('json') ? r.json() : r.text();
}

// Giriş yapan kullanıcı ve yetkileri (login sayfası hariç)
let ME = null;
const meReady = location.pathname === '/login' ? Promise.resolve(null)
  : api('/api/me').then(m => (ME = m));
const can = p => !!(ME && ME.perms.includes(p));

function qs(k) { return new URLSearchParams(location.search).get(k); }

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const k in (attrs || {})) {
    const v = attrs[k];
    if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'class') e.className = v;
    else e.setAttribute(k, v);
  }
  kids.flat().forEach(c => { if (c != null) e.append(c); });
  return e;
}

function toast(msg, bad) {
  let box = document.getElementById('toast');
  if (!box) { box = el('div', { id: 'toast' }); document.body.append(box); }
  const t = el('div', { class: bad ? 'bad' : '' }, msg);
  box.append(t);
  setTimeout(() => t.remove(), 4000);
}

function fmtUp(s) {
  const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60;
  return (h ? h + 's ' : '') + (h || m ? m + 'dk ' : '') + x + 'sn';
}

function fmtMem(kb) { return kb ? (kb / 1024).toFixed(1) + ' MB' : '-'; }

function fmtSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}

function passwordDialog() {
  const old = el('input', { type: 'password', autocomplete: 'current-password' });
  const nw = el('input', { type: 'password', autocomplete: 'new-password' });
  const dlg = el('dialog', {},
    el('h3', {}, 'Şifre değiştir'),
    el('label', {}, 'Mevcut şifre'), old,
    el('label', {}, 'Yeni şifre (en az 8 karakter)'), nw,
    el('div', { class: 'foot' },
      el('button', { class: 'b-ghost', onclick: () => dlg.close() }, 'Vazgeç'),
      el('button', { onclick: async () => {
        try {
          await api('/api/me/password', { method: 'POST', body: JSON.stringify({ old: old.value, new: nw.value }) });
          toast('Şifre değiştirildi'); dlg.close();
        } catch (e) { toast(e.message, true); }
      } }, 'Kaydet')));
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
}

async function logout() {
  try { await api('/api/logout', { method: 'POST' }); } catch (e) {}
  location.href = '/login';
}

// Üst bar + sol menü. active: 'bots' | 'console' | 'files' | 'db' | 'users'
function layout(active) {
  const id = qs('id');
  const top = document.getElementById('top');
  const nav = document.getElementById('nav');
  top.append(el('a', { class: 'brand', href: '/' }, 'Bot Panel'));

  const link = (text, href, key) =>
    el('a', { href, class: key === active ? 'active' : '' }, text);
  const q = '?id=' + encodeURIComponent(id || '');

  if (id) {
    top.append(el('span', { class: 'crumb' }, '/'));
    top.append(el('span', { id: 'crumb' }, ''));
    top.append(el('span', { class: 'dot', id: 'dot' }));
    const refresh = () => api('/api/bot/info' + q).then(i => {
      document.getElementById('crumb').textContent = i.name;
      document.getElementById('dot').className = 'dot' + (i.running ? ' on' : '');
      document.title = i.name + ' - Bot Panel';
    }).catch(e => {
      document.getElementById('crumb').textContent = e.message;
    });
    meReady.then(() => { refresh(); setInterval(refresh, 3000); });
  }

  meReady.then(() => {
    if (!ME) return;
    if (id) {
      if (can('bots.view')) nav.append(link('Konsol', '/console' + q, 'console'));
      if (can('files.view')) nav.append(link('Dosyalar', '/files' + q, 'files'));
      if (can('db.view')) nav.append(link('Veritabanı', '/db' + q, 'db'));
      nav.append(el('hr'), link('Tüm botlar', '/', ''));
    } else {
      nav.append(link('Botlar', '/', 'bots'));
    }
    if (ME.manage) nav.append(link('Hesaplar', '/users', 'users'));
    if (ME.admin) nav.append(link('Günlük', '/audit', 'audit'));

    top.append(el('span', { style: 'flex:1' }),
      el('span', { class: 'crumb' }, ME.name + (ME.admin ? ' (admin)' : '')),
      el('button', { class: 'sm b-ghost', onclick: passwordDialog }, 'Şifre'),
      el('button', { class: 'sm b-ghost', onclick: logout }, 'Çıkış'));
  });
}
