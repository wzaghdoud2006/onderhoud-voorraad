const { esc } = require('./helpers');

const CSS = `
  :root{--bg:#f6f7fb;--surface:#fff;--fg:#1a1f2e;--muted:#6b7280;--border:#e5e7eb;--primary:#4f46e5;--primary-fg:#fff;
        --ok:#059669;--warn:#d97706;--danger:#dc2626;--info:#2563eb;}
  *{box-sizing:border-box} html,body{margin:0}
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);font-size:14px;line-height:1.5}
  a{color:var(--primary);text-decoration:none} a:hover{text-decoration:underline}
  header.top{background:var(--surface);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:10}
  .bar{max-width:1100px;margin:0 auto;display:flex;align-items:center;gap:18px;padding:0 18px;height:56px}
  .brand{font-weight:800;letter-spacing:-.3px}
  nav.main{display:flex;gap:4px;flex:1;flex-wrap:wrap}
  nav.main a{color:var(--muted);font-weight:600;padding:8px 12px;border-radius:8px}
  nav.main a.on{color:var(--primary);background:#eef2ff}
  .who{display:flex;align-items:center;gap:10px;font-size:13px;color:var(--muted)}
  .wrap{max-width:1100px;margin:0 auto;padding:22px 18px}
  h1{font-size:22px;margin:0 0 4px} h2{font-size:17px;margin:22px 0 10px}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:14px}
  .card .bd{padding:16px}
  .card .card-head{padding:13px 16px;border-bottom:1px solid var(--border);font-weight:700}
  .grid{display:grid;gap:14px}
  .kpis{grid-template-columns:repeat(2,1fr)} @media(min-width:760px){.kpis{grid-template-columns:repeat(4,1fr)}}
  .kpi .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:700}
  .kpi .val{font-size:26px;font-weight:800;margin-top:6px}
  table{width:100%;border-collapse:collapse}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border)}
  th{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
  tr:last-child td{border-bottom:0}
  .mono{font-family:ui-monospace,Menlo,Consolas,monospace}
  .muted{color:var(--muted)} .right{text-align:right} .nowrap{white-space:nowrap}
  .badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:700}
  .b-ok{background:#dcfce7;color:#166534}.b-warn{background:#fef3c7;color:#92400e}.b-info{background:#dbeafe;color:#1e40af}
  .b-danger{background:#fee2e2;color:#991b1b}.b-neutral{background:#f3f4f6;color:#374151}
  input,select,textarea{width:100%;padding:9px 11px;border:1px solid var(--border);border-radius:9px;background:#fff;font:inherit;color:inherit}
  input:focus,select:focus,textarea:focus{outline:none;border-color:var(--primary)}
  label{display:block;font-size:12px;font-weight:700;color:var(--muted);margin-bottom:5px}
  .btn{display:inline-flex;align-items:center;gap:6px;padding:9px 15px;border-radius:9px;border:1px solid var(--border);
       background:#fff;font:inherit;font-weight:700;cursor:pointer;color:var(--fg)}
  .btn:hover{background:var(--bg);text-decoration:none}
  .btn-p{background:var(--primary);border-color:var(--primary);color:#fff}
  .btn-d{border-color:var(--danger);color:var(--danger)} .btn-d:hover{background:var(--danger);color:#fff}
  .btn-sm{padding:5px 10px;font-size:12px}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .between{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
  .field{margin-bottom:12px}
  .flash{padding:11px 15px;border-radius:10px;margin-bottom:14px;font-weight:600}
  .flash.ok{background:#dcfce7;color:#166534}.flash.err{background:#fee2e2;color:#991b1b}
  .chips{display:flex;gap:6px;flex-wrap:wrap}
  .chip{padding:6px 12px;border-radius:8px;border:1px solid var(--border);font-size:12px;font-weight:700;color:var(--fg)}
  .chip.on{background:var(--primary);border-color:var(--primary);color:#fff}
  details.modal{margin:0}
  details.modal>summary{list-style:none;display:inline-flex}
  details.modal>summary::-webkit-details-marker{display:none}
  .sheet{position:fixed;inset:0;background:rgba(15,23,42,.45);display:flex;align-items:flex-start;justify-content:center;padding:40px 16px;z-index:50;overflow:auto}
  .sheet .box{background:#fff;border-radius:16px;max-width:520px;width:100%;border:1px solid var(--border)}
  .sheet .hd{padding:15px 18px;border-bottom:1px solid var(--border);font-weight:700;display:flex;justify-content:space-between;align-items:center}
  .sheet .bd{padding:18px}
  .cols2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .login{max-width:400px;margin:8vh auto}
`;

function layoutHead(user, active, title) {
  const company = user ? esc(user.company_name) : '';
  return `<!doctype html>
<html lang="nl"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Onderhoud &amp; Voorraad${company ? ' — ' + company : ''}</title>
<style>${CSS}</style>
</head><body>
${user ? navBar(user, active) : ''}
<div class="${user ? 'wrap' : ''}">`;
}

function navBar(user, active) {
  const on = (k) => (active === k ? 'on' : '');
  return `<header class="top"><div class="bar">
  <span class="brand">🛠️ Onderhoud &amp; Voorraad</span>
  <nav class="main">
    <a href="/dashboard" class="${on('dashboard')}">Overzicht</a>
    <a href="/maintenance" class="${['maintenance', 'issue'].includes(active) ? 'on' : ''}">Onderhoud</a>
    <a href="/inventory" class="${['inventory', 'inventory_settings', 'history', 'orders'].includes(active) ? 'on' : ''}">Voorraad</a>
    ${user.role === 'admin' || user.is_super ? `<a href="/users" class="${on('users')}">Gebruikers</a>` : ''}
    ${user.is_super ? `<a href="/companies" class="${on('companies')}">Bedrijven</a>` : ''}
  </nav>
  <div class="who">
    <span><strong>${esc(user.name)}</strong> · ${esc(user.company_name)} · ${esc(require('./helpers').ROLES[user.role] || user.role)}${user.is_super ? ' <span class="badge b-info">super-admin</span>' : ''}</span>
    <form method="post" action="/logout" style="margin:0"><input type="hidden" name="csrf" value="${esc(user.csrf)}"><button class="btn btn-sm">Uitloggen</button></form>
  </div>
</div></header>`;
}

function flashHtml(flashes) {
  return (flashes || []).map(([type, msg]) => `<div class="flash ${esc(type)}">${esc(msg)}</div>`).join('');
}

function actingBanner(user) {
  if (!user || !user.actingOther) return '';
  return `<div class="flash" style="background:#e0e7ff;color:#3730a3;display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap">
    <span>👁️ Je bekijkt nu <strong>${esc(user.company_name)}</strong> als super-admin.</span>
    <form method="post" action="/companies/stop-switch" style="margin:0"><input type="hidden" name="csrf" value="${esc(user.csrf)}"><button class="btn btn-sm">Terug naar mijn bedrijf</button></form>
  </div>`;
}

function layoutFoot() {
  return `<script>document.addEventListener("click",function(ev){
    var opened=ev.target.closest("details.modal");
    document.querySelectorAll("details.modal[open]").forEach(function(el){if(el!==opened)el.open=false;});
    if(ev.target.classList.contains("sheet")){var d=ev.target.closest("details.modal");if(d)d.open=false;}
  });</script></div></body></html>`;
}

function csrfField(token) {
  return `<input type="hidden" name="csrf" value="${esc(token)}">`;
}

function modal(btnClass, btnLabel, title, innerHtml) {
  return `<details class="modal"><summary class="btn ${btnClass}">${esc(btnLabel)}</summary>
    <div class="sheet"><div class="box">
      <div class="hd">${esc(title)}<button type="button" class="btn btn-sm" onclick="this.closest('details').open=false">✕</button></div>
      ${innerHtml}
    </div></div></details>`;
}
function modalFoot(csrf, submitBtn) {
  return `<div style="padding:13px 18px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:8px">
    <button type="button" class="btn" onclick="this.closest('details').open=false">Annuleren</button>${submitBtn}
  </div>`;
}
function field(label, inner) {
  return `<label>${esc(label)}${inner}</label>`;
}

module.exports = { layoutHead, layoutFoot, flashHtml, actingBanner, csrfField, modal, modalFoot, field, navBar };
