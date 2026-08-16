require('dotenv').config();
const express = require('express');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const { pool, q, migrate, seedIfEmpty, ensureSuperAdmin } = require('./db');
const {
  esc, money, fmtDate, fmtDt, PRIORITIES, STATUSES, MOVE_TYPES, ROLES, isOverdue, applyMovement, can,
} = require('./helpers');
const { layoutHead, layoutFoot, flashHtml, actingBanner, csrfField, modal, modalFoot, field } = require('./views');

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(
  cookieSession({
    name: 'sess',
    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    maxAge: 30 * 24 * 60 * 60 * 1000,
    sameSite: 'lax',
  })
);

// ---------------------------------------------------------------- helpers
function ensureCsrf(req) {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(16).toString('hex');
  return req.session.csrf;
}
function csrfOk(req) {
  return req.body.csrf && req.session.csrf && req.body.csrf === req.session.csrf;
}
function flash(req, msg, type = 'ok') {
  req.session.flash = req.session.flash || [];
  req.session.flash.push([type, msg]);
}
function takeFlash(req) {
  const f = req.session.flash || [];
  req.session.flash = [];
  return f;
}
function nn(v) {
  const s = String(v ?? '').trim();
  return s === '' ? null : s;
}

// ---------------------------------------------------------------- auth middleware
async function loadUser(req, res, next) {
  ensureCsrf(req);
  if (!req.session.uid) { req.user = null; return next(); }
  const { rows } = await q(
    `SELECT u.*, c.name AS company_name FROM users u JOIN companies c ON c.id = u.company_id
     WHERE u.id = $1 AND u.active = true`,
    [req.session.uid]
  );
  if (!rows[0]) { req.user = null; return next(); }
  const user = rows[0];
  user.csrf = req.session.csrf;

  // Super-admin acting-as-another-company.
  const homeCid = user.company_id;
  let cid = homeCid;
  if (user.is_super && req.session.actingCompanyId) {
    const ac = await q('SELECT name FROM companies WHERE id = $1', [req.session.actingCompanyId]);
    if (ac.rows[0]) { cid = req.session.actingCompanyId; user.company_name = ac.rows[0].name; }
    else { delete req.session.actingCompanyId; }
  }
  user.homeCompanyId = homeCid;
  user.effectiveCompanyId = cid;
  user.actingOther = cid !== homeCid;
  req.user = user;
  next();
}
app.use(loadUser);

function requireAuth(req, res, next) {
  if (!req.user) return res.redirect('/login');
  next();
}
function requireCsrf(req, res, next) {
  if (!csrfOk(req)) return res.status(400).send('Ongeldige sessie (CSRF-token). Ga terug en probeer opnieuw.');
  next();
}
function requireCap(cap) {
  return (req, res, next) => {
    if (!can(req.user, cap)) { flash(req, 'Geen rechten.', 'err'); return res.redirect('back'); }
    next();
  };
}

// ---------------------------------------------------------------- badge helpers
const prioBadge = (p) => ({ laag: 'b-neutral', middel: 'b-info', hoog: 'b-warn', kritiek: 'b-danger' }[p] || 'b-neutral');
const statusBadge = (s) => ({ open: 'b-warn', in_behandeling: 'b-info', on_hold: 'b-neutral', opgelost: 'b-ok', gesloten: 'b-neutral' }[s] || 'b-neutral');
const moveBadge = (t) => ({ levering: 'b-ok', afschrijving: 'b-danger', telling: 'b-info', correctie: 'b-warn' }[t] || 'b-neutral');

function page(req, active, bodyHtml) {
  return layoutHead(req.user, active) + flashHtml(takeFlash(req)) + actingBanner(req.user) + bodyHtml + layoutFoot();
}

// ================================================================== AUTH
app.get('/login', (req, res) => {
  if (req.user) return res.redirect('/dashboard');
  res.send(`${layoutHead(null, 'login')}${flashHtml(takeFlash(req))}
    <div class="login">
      <div style="text-align:center;margin-bottom:18px"><div style="font-size:34px">🛠️</div><h1>Onderhoud &amp; Voorraad</h1><p class="muted">Log in om verder te gaan</p></div>
      <div class="card"><div class="bd">
        <form method="post" action="/login">
          ${csrfField(ensureCsrf(req))}
          <div class="field"><label>E-mail</label><input name="email" type="email" required autofocus placeholder="admin@demo.local"></div>
          <div class="field"><label>Wachtwoord</label><input name="password" type="password" required placeholder="Demo1234!"></div>
          <button class="btn btn-p" style="width:100%">Inloggen</button>
        </form>
      </div></div>
      <p class="muted" style="text-align:center;margin-top:14px">Nieuw bedrijf? <a href="/register">Maak een account aan →</a></p>
      <p class="muted" style="text-align:center;font-size:12px">Demo: <span class="mono">admin@demo.local</span> / <span class="mono">Demo1234!</span></p>
    </div>${layoutFoot()}`);
});

app.post('/login', async (req, res) => {
  if (!csrfOk(req)) return res.status(400).send('Ongeldige sessie.');
  const email = String(req.body.email || '').trim().toLowerCase();
  const { rows } = await q('SELECT * FROM users WHERE email = $1 AND active = true', [email]);
  const u = rows[0];
  if (u && (await bcrypt.compare(String(req.body.password || ''), u.password_hash))) {
    req.session.uid = u.id;
    return res.redirect('/dashboard');
  }
  flash(req, 'Onjuiste inloggegevens.', 'err');
  res.redirect('/login');
});

app.get('/register', (req, res) => {
  if (req.user) return res.redirect('/dashboard');
  res.send(`${layoutHead(null, 'register')}${flashHtml(takeFlash(req))}
    <div class="login">
      <div style="text-align:center;margin-bottom:18px"><h1>Nieuw bedrijf</h1><p class="muted">Maak een bedrijf + beheerdersaccount aan</p></div>
      <div class="card"><div class="bd">
        <form method="post" action="/register">
          ${csrfField(ensureCsrf(req))}
          <div class="field"><label>Bedrijfsnaam</label><input name="company" required></div>
          <div class="field"><label>Jouw naam</label><input name="name" required></div>
          <div class="field"><label>E-mail</label><input name="email" type="email" required></div>
          <div class="field"><label>Wachtwoord (min. 6 tekens)</label><input name="password" type="password" required></div>
          <button class="btn btn-p" style="width:100%">Bedrijf aanmaken</button>
        </form>
      </div></div>
      <p class="muted" style="text-align:center;margin-top:14px"><a href="/login">← Terug naar inloggen</a></p>
    </div>${layoutFoot()}`);
});

app.post('/register', async (req, res) => {
  if (!csrfOk(req)) return res.status(400).send('Ongeldige sessie.');
  const company = String(req.body.company || '').trim();
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const pw = String(req.body.password || '');
  if (!company || !name || !email || pw.length < 6) {
    flash(req, 'Vul alle velden in (wachtwoord min. 6 tekens).', 'err');
    return res.redirect('/register');
  }
  const exists = await q('SELECT 1 FROM users WHERE email = $1', [email]);
  if (exists.rows[0]) {
    flash(req, 'Dit e-mailadres is al in gebruik.', 'err');
    return res.redirect('/register');
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const co = await client.query('INSERT INTO companies (name) VALUES ($1) RETURNING id', [company]);
    const cid = co.rows[0].id;
    const hash = await bcrypt.hash(pw, 10);
    const u = await client.query(
      'INSERT INTO users (company_id,name,email,password_hash,role) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [cid, name, email, hash, 'admin']
    );
    await client.query('COMMIT');
    req.session.uid = u.rows[0].id;
    flash(req, `Welkom! Bedrijf "${company}" is aangemaakt.`);
    res.redirect('/dashboard');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
});

app.post('/logout', (req, res) => {
  if (!csrfOk(req)) return res.status(400).send('Ongeldige sessie.');
  req.session = null;
  res.redirect('/login');
});

app.get('/', (req, res) => res.redirect(req.user ? '/dashboard' : '/login'));

// ================================================================== DASHBOARD
app.get('/dashboard', requireAuth, async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  const [openIssues, critical, products, low, value, recentIssues, lowList] = await Promise.all([
    q(`SELECT COUNT(*)::int c FROM issues WHERE company_id=$1 AND status IN ('open','in_behandeling','on_hold')`, [cid]),
    q(`SELECT COUNT(*)::int c FROM issues WHERE company_id=$1 AND priority='kritiek' AND status IN ('open','in_behandeling','on_hold')`, [cid]),
    q(`SELECT COUNT(*)::int c FROM products WHERE company_id=$1 AND active=true`, [cid]),
    q(`SELECT COUNT(*)::int c FROM products WHERE company_id=$1 AND active=true AND stock<=min_stock`, [cid]),
    q(`SELECT COALESCE(SUM(price*stock),0)::float v FROM products WHERE company_id=$1 AND active=true`, [cid]),
    q(`SELECT * FROM issues WHERE company_id=$1 ORDER BY created_at DESC LIMIT 5`, [cid]),
    q(`SELECT * FROM products WHERE company_id=$1 AND active=true AND stock<=min_stock ORDER BY (stock-min_stock) LIMIT 5`, [cid]),
  ]);

  const kpis = [
    ['Open storingen', openIssues.rows[0].c], ['Kritiek', critical.rows[0].c],
    ['Producten onder min.', low.rows[0].c], ['Voorraadwaarde', money(value.rows[0].v)],
  ];
  let html = `<h1>Overzicht</h1><p class="muted">Welkom, ${esc(req.user.name)}.</p>`;
  html += `<div class="grid kpis" style="margin-top:14px">${kpis.map(([l, v]) => `<div class="card kpi"><div class="bd"><div class="lbl">${esc(l)}</div><div class="val">${esc(v)}</div></div></div>`).join('')}</div>`;
  html += `<div class="grid" style="grid-template-columns:1fr;margin-top:6px">`;
  html += `<div class="card"><div class="bd"><div class="between"><h2 style="margin:0">Recente storingen</h2><a href="/maintenance">Alle →</a></div></div><table><tbody>`;
  html += recentIssues.rows.length ? recentIssues.rows.map((i) => `<tr><td><a href="/maintenance/${i.id}">${esc(i.title)}</a></td><td><span class="badge ${prioBadge(i.priority)}">${esc(PRIORITIES[i.priority])}</span></td><td><span class="badge ${statusBadge(i.status)}">${esc(STATUSES[i.status])}</span></td></tr>`).join('') : `<tr><td class="muted" style="padding:16px">Nog geen storingen.</td></tr>`;
  html += `</tbody></table></div>`;
  html += `<div class="card"><div class="bd"><div class="between"><h2 style="margin:0">Lage voorraad</h2><a href="/inventory/orders">Bestellijst →</a></div></div><table><tbody>`;
  html += lowList.rows.length ? lowList.rows.map((p) => `<tr><td>${esc(p.name)}</td><td class="right mono">${p.stock} / ${p.min_stock}</td></tr>`).join('') : `<tr><td class="muted" style="padding:16px">Niets onder het minimum. ✓</td></tr>`;
  html += `</tbody></table></div></div>`;
  res.send(page(req, 'dashboard', html));
});

// ================================================================== MAINTENANCE
app.get('/maintenance', requireAuth, async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  const fs = req.query.status || '';
  const fp = req.query.priority || '';
  let sql = 'SELECT * FROM issues WHERE company_id=$1';
  const params = [cid];
  if (STATUSES[fs]) { params.push(fs); sql += ` AND status=$${params.length}`; }
  if (PRIORITIES[fp]) { params.push(fp); sql += ` AND priority=$${params.length}`; }
  sql += ` ORDER BY CASE priority WHEN 'kritiek' THEN 0 WHEN 'hoog' THEN 1 WHEN 'middel' THEN 2 ELSE 3 END, created_at DESC`;
  const { rows: issues } = await q(sql, params);
  const { rows: allIssues } = await q('SELECT priority,status,due_date FROM issues WHERE company_id=$1', [cid]);

  let kOpen = 0, kProg = 0, kCrit = 0, kOver = 0;
  for (const i of allIssues) {
    const open = ['open', 'in_behandeling', 'on_hold'].includes(i.status);
    if (open) kOpen++;
    if (i.status === 'in_behandeling') kProg++;
    if (i.priority === 'kritiek' && open) kCrit++;
    if (isOverdue(i.due_date, i.status)) kOver++;
  }
  const { rows: team } = await q('SELECT name FROM users WHERE company_id=$1 ORDER BY name', [cid]);

  let html = `<div class="between"><h1>Onderhoud</h1>`;
  if (can(req.user, 'maintenance.create')) html += newIssueModal(req, team);
  html += `</div>`;
  html += `<div class="grid kpis" style="margin:14px 0">${[['Open storingen', kOpen], ['In behandeling', kProg], ['Kritiek', kCrit], ['Over tijd', kOver]].map(([l, v]) => `<div class="card kpi"><div class="bd"><div class="lbl">${esc(l)}</div><div class="val">${v}</div></div></div>`).join('')}</div>`;
  html += `<div class="chips" style="margin-bottom:14px">`;
  html += filterChip('Alle', '/maintenance', !fs && !fp);
  for (const [k, v] of Object.entries(STATUSES)) html += filterChip(v, `/maintenance?status=${k}`, fs === k);
  html += `<span style="width:1px;background:var(--border);margin:0 4px"></span>`;
  for (const [k, v] of Object.entries(PRIORITIES)) html += filterChip(v, `/maintenance?priority=${k}`, fp === k);
  html += `</div>`;
  html += `<div class="card"><table><thead><tr><th>Titel</th><th>Prioriteit</th><th>Status</th><th>Toegewezen</th><th>Streefdatum</th></tr></thead><tbody>`;
  html += issues.length ? issues.map((i) => {
    const ov = isOverdue(i.due_date, i.status);
    return `<tr><td><a href="/maintenance/${i.id}">${esc(i.title)}</a></td><td><span class="badge ${prioBadge(i.priority)}">${esc(PRIORITIES[i.priority])}</span></td><td><span class="badge ${statusBadge(i.status)}">${esc(STATUSES[i.status])}</span></td><td class="muted">${esc(i.assignee || 'Niet toegewezen')}</td><td class="${ov ? '' : 'muted'}" ${ov ? 'style="color:var(--danger);font-weight:700"' : ''}>${fmtDate(i.due_date)}${ov ? ' · over tijd' : ''}</td></tr>`;
  }).join('') : `<tr><td colspan="5" class="muted" style="padding:26px;text-align:center">Geen storingen gevonden.</td></tr>`;
  html += `</tbody></table></div>`;
  res.send(page(req, 'maintenance', html));
});

function filterChip(label, href, active) {
  return `<a class="chip ${active ? 'on' : ''}" href="${esc(href)}">${esc(label)}</a>`;
}
function newIssueModal(req, team) {
  const opts = team.map((t) => `<option value="${esc(t.name)}">${esc(t.name)}</option>`).join('');
  const inner = `<div class="bd"><form method="post" action="/maintenance">
    ${csrfField(req.user.csrf)}
    <div class="field"><label>Titel</label><input name="title" required></div>
    <div class="field"><label>Omschrijving</label><textarea name="description" rows="3"></textarea></div>
    <div class="cols2"><div class="field"><label>Prioriteit</label><select name="priority">${Object.entries(PRIORITIES).map(([k, v]) => `<option value="${k}" ${k === 'middel' ? 'selected' : ''}>${esc(v)}</option>`).join('')}</select></div>
    <div class="field"><label>Streefdatum</label><input name="due_date" type="date"></div></div>
    <div class="field"><label>Toegewezen aan</label><select name="assignee"><option value="">Niet toegewezen</option>${opts}</select></div>
    <button class="btn btn-p">Melden</button></form></div>`;
  return modal('btn-p', '+ Storing melden', 'Storing melden', inner);
}

app.post('/maintenance', requireAuth, requireCsrf, requireCap('maintenance.create'), async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  if (!req.body.title) { flash(req, 'Titel is verplicht.', 'err'); return res.redirect('/maintenance'); }
  const prio = PRIORITIES[req.body.priority] ? req.body.priority : 'middel';
  await q(
    `INSERT INTO issues (company_id,title,description,priority,status,assignee,reported_by,due_date)
     VALUES ($1,$2,$3,$4,'open',$5,$6,$7)`,
    [cid, req.body.title, nn(req.body.description), prio, nn(req.body.assignee), req.user.name, nn(req.body.due_date)]
  );
  flash(req, 'Storing gemeld.');
  res.redirect('/maintenance');
});

app.get('/maintenance/:id', requireAuth, async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  const id = Number(req.params.id);
  const { rows } = await q('SELECT * FROM issues WHERE id=$1 AND company_id=$2', [id, cid]);
  const issue = rows[0];
  if (!issue) return res.send(page(req, 'maintenance', `<p>Storing niet gevonden. <a href="/maintenance">Terug</a></p>`));
  const { rows: comments } = await q('SELECT * FROM issue_comments WHERE issue_id=$1 ORDER BY created_at DESC', [id]);
  const { rows: team } = await q('SELECT name FROM users WHERE company_id=$1 ORDER BY name', [cid]);

  let html = `<p><a href="/maintenance">← Terug naar storingen</a></p>`;
  html += `<div class="between"><div>`;
  html += `<div class="row" style="margin-bottom:6px"><span class="badge ${prioBadge(issue.priority)}">${esc(PRIORITIES[issue.priority])}</span><span class="badge ${statusBadge(issue.status)}">${esc(STATUSES[issue.status])}</span></div>`;
  html += `<h1>${esc(issue.title)}</h1><p class="muted">Gemeld door ${esc(issue.reported_by)} · ${fmtDt(issue.created_at)}</p></div>`;
  html += `<div class="row">`;
  if (can(req.user, 'maintenance.update')) html += editIssueModal(req, issue, team);
  if (can(req.user, 'maintenance.manage')) html += `<form method="post" action="/maintenance/${id}/delete" onsubmit="return confirm('Storing verwijderen?')">${csrfField(req.user.csrf)}<button class="btn btn-d">Verwijderen</button></form>`;
  html += `</div></div>`;

  html += `<div class="grid" style="grid-template-columns:1fr;margin-top:16px;gap:16px"><div class="grid" style="grid-template-columns:1fr;gap:16px">`;
  html += `<div class="card"><div class="bd"><h2 style="margin-top:0">Details</h2><p style="white-space:pre-line">${esc(issue.description || '—')}</p>
    <div class="cols2"><div><label>Toegewezen aan</label>${esc(issue.assignee || 'Niet toegewezen')}</div><div><label>Streefdatum</label>${fmtDate(issue.due_date)}</div></div></div></div>`;

  if (can(req.user, 'maintenance.update')) {
    html += `<div class="card"><div class="bd"><h2 style="margin-top:0">Status &amp; prioriteit</h2><div class="cols2">
      <form method="post" action="/maintenance/${id}/status">${csrfField(req.user.csrf)}<label>Status</label><select name="status" onchange="this.form.submit()">${Object.entries(STATUSES).map(([k, v]) => `<option value="${k}" ${issue.status === k ? 'selected' : ''}>${esc(v)}</option>`).join('')}</select></form>
      <form method="post" action="/maintenance/${id}/priority">${csrfField(req.user.csrf)}<label>Prioriteit</label><select name="priority" onchange="this.form.submit()">${Object.entries(PRIORITIES).map(([k, v]) => `<option value="${k}" ${issue.priority === k ? 'selected' : ''}>${esc(v)}</option>`).join('')}</select></form>
      </div></div></div>`;
  }

  html += `<div class="card"><div class="bd"><h2 style="margin-top:0">Opmerkingen</h2>`;
  if (can(req.user, 'maintenance.update')) html += `<form method="post" action="/maintenance/${id}/comment" class="row" style="margin-bottom:12px">${csrfField(req.user.csrf)}<input name="body" placeholder="Opmerking toevoegen…" required style="flex:1"><button class="btn btn-p">Plaatsen</button></form>`;
  html += comments.length ? comments.map((c) => `<div style="border:1px solid var(--border);border-radius:10px;padding:10px;margin-bottom:8px">${esc(c.body).replace(/\n/g, '<br>')}<div class="muted" style="font-size:12px;margin-top:4px">${esc(c.author)} · ${fmtDt(c.created_at)}</div></div>`).join('') : `<p class="muted">Nog geen opmerkingen.</p>`;
  html += `</div></div></div></div>`;
  res.send(page(req, 'issue', html));
});

function editIssueModal(req, issue, team) {
  const opts = team.map((t) => `<option value="${esc(t.name)}" ${issue.assignee === t.name ? 'selected' : ''}>${esc(t.name)}</option>`).join('');
  const inner = `<div class="bd"><form method="post" action="/maintenance/${issue.id}/update">
    ${csrfField(req.user.csrf)}
    <div class="field"><label>Titel</label><input name="title" required value="${esc(issue.title)}"></div>
    <div class="field"><label>Omschrijving</label><textarea name="description" rows="3">${esc(issue.description)}</textarea></div>
    <div class="cols2"><div class="field"><label>Prioriteit</label><select name="priority">${Object.entries(PRIORITIES).map(([k, v]) => `<option value="${k}" ${issue.priority === k ? 'selected' : ''}>${esc(v)}</option>`).join('')}</select></div>
    <div class="field"><label>Streefdatum</label><input name="due_date" type="date" value="${issue.due_date ? new Date(issue.due_date).toISOString().slice(0, 10) : ''}"></div></div>
    <div class="field"><label>Toegewezen aan</label><select name="assignee"><option value="">Niet toegewezen</option>${opts}</select></div>
    <button class="btn btn-p">Opslaan</button></form></div>`;
  return modal('btn-sm', 'Bewerken', 'Storing bewerken', inner);
}

app.post('/maintenance/:id/update', requireAuth, requireCsrf, requireCap('maintenance.update'), async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  const id = Number(req.params.id);
  const prio = PRIORITIES[req.body.priority] ? req.body.priority : 'middel';
  await q(
    `UPDATE issues SET title=$1,description=$2,priority=$3,assignee=$4,due_date=$5 WHERE id=$6 AND company_id=$7`,
    [req.body.title, nn(req.body.description), prio, nn(req.body.assignee), nn(req.body.due_date), id, cid]
  );
  flash(req, 'Storing bijgewerkt.');
  res.redirect(`/maintenance/${id}`);
});
app.post('/maintenance/:id/status', requireAuth, requireCsrf, requireCap('maintenance.update'), async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  const id = Number(req.params.id);
  const status = STATUSES[req.body.status] ? req.body.status : 'open';
  const resolved = ['opgelost', 'gesloten'].includes(status) ? new Date() : null;
  await q('UPDATE issues SET status=$1, resolved_at=$2 WHERE id=$3 AND company_id=$4', [status, resolved, id, cid]);
  flash(req, 'Status bijgewerkt.');
  res.redirect(`/maintenance/${id}`);
});
app.post('/maintenance/:id/priority', requireAuth, requireCsrf, requireCap('maintenance.update'), async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  const id = Number(req.params.id);
  const prio = PRIORITIES[req.body.priority] ? req.body.priority : 'middel';
  await q('UPDATE issues SET priority=$1 WHERE id=$2 AND company_id=$3', [prio, id, cid]);
  res.redirect(`/maintenance/${id}`);
});
app.post('/maintenance/:id/comment', requireAuth, requireCsrf, requireCap('maintenance.update'), async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  const id = Number(req.params.id);
  const own = await q('SELECT 1 FROM issues WHERE id=$1 AND company_id=$2', [id, cid]);
  if (own.rows[0] && req.body.body) {
    await q('INSERT INTO issue_comments (issue_id,body,author) VALUES ($1,$2,$3)', [id, req.body.body, req.user.name]);
  }
  res.redirect(`/maintenance/${id}`);
});
app.post('/maintenance/:id/delete', requireAuth, requireCsrf, requireCap('maintenance.manage'), async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  const id = Number(req.params.id);
  await q('DELETE FROM issues WHERE id=$1 AND company_id=$2', [id, cid]);
  flash(req, 'Storing verwijderd.');
  res.redirect('/maintenance');
});

// ================================================================== INVENTORY
app.get('/inventory', requireAuth, async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  const search = req.query.q || '';
  const fcat = req.query.cat || '';
  const low = req.query.low === '1';

  let sql = `SELECT p.*, c.name cat, s.name sup, l.name loc FROM products p
             LEFT JOIN categories c ON c.id=p.category_id
             LEFT JOIN suppliers s ON s.id=p.supplier_id
             LEFT JOIN locations l ON l.id=p.location_id
             WHERE p.company_id=$1 AND p.active=true`;
  const params = [cid];
  if (search) { params.push(`%${search}%`); sql += ` AND (p.name ILIKE $${params.length} OR p.sku ILIKE $${params.length} OR p.barcode ILIKE $${params.length})`; }
  if (fcat) { params.push(Number(fcat)); sql += ` AND p.category_id=$${params.length}`; }
  sql += ' ORDER BY p.name';
  let { rows: prods } = await q(sql, params);
  if (low) prods = prods.filter((p) => p.stock <= p.min_stock);

  const { rows: all } = await q('SELECT price,stock,min_stock FROM products WHERE company_id=$1 AND active=true', [cid]);
  const tItems = all.length;
  const tStock = all.reduce((a, p) => a + p.stock, 0);
  const tLow = all.filter((p) => p.stock <= p.min_stock).length;
  const tVal = all.reduce((a, p) => a + Number(p.price) * p.stock, 0);
  const { rows: cats } = await q('SELECT * FROM categories WHERE company_id=$1 ORDER BY name', [cid]);
  const { rows: sups } = await q('SELECT * FROM suppliers WHERE company_id=$1 ORDER BY name', [cid]);
  const { rows: locs } = await q('SELECT * FROM locations WHERE company_id=$1 ORDER BY name', [cid]);

  let html = `<div class="between"><h1>Voorraad</h1><div class="row">`;
  html += `<a class="btn" href="/inventory/history">Historie</a><a class="btn" href="/inventory/orders">Bestellijst</a>`;
  if (can(req.user, 'inventory.manage')) html += `<a class="btn" href="/inventory/settings">Instellingen</a>`;
  if (can(req.user, 'reports.view')) html += `<a class="btn" href="/inventory/export.csv">Export CSV</a>`;
  if (can(req.user, 'inventory.manage')) html += productModal(req, null, cats, sups, locs);
  html += `</div></div>`;
  html += `<div class="grid kpis" style="margin:14px 0">${[['Artikelen', tItems], ['Totale voorraad', tStock], ['Onder minimum', tLow], ['Voorraadwaarde', money(tVal)]].map(([l, v]) => `<div class="card kpi"><div class="bd"><div class="lbl">${esc(l)}</div><div class="val">${esc(v)}</div></div></div>`).join('')}</div>`;

  html += `<form method="get" action="/inventory" class="row" style="margin-bottom:14px">
    <input name="q" value="${esc(search)}" placeholder="Zoek op naam, SKU of barcode…" style="flex:1;min-width:180px">
    <select name="cat" onchange="this.form.submit()"><option value="">Alle categorieën</option>${cats.map((c) => `<option value="${c.id}" ${fcat == String(c.id) ? 'selected' : ''}>${esc(c.name)}</option>`).join('')}</select>
    <label class="chip ${low ? 'on' : ''}" style="cursor:pointer"><input type="checkbox" name="low" value="1" ${low ? 'checked' : ''} onchange="this.form.submit()" style="width:auto;margin-right:6px">Alleen lage voorraad</label>
    <button class="btn">Zoeken</button></form>`;

  html += `<div class="card" style="overflow-x:auto"><table><thead><tr><th>Product</th><th>SKU</th><th>Categorie</th><th>Locatie</th><th>Leverancier</th><th class="right">Prijs</th><th class="right">Voorraad</th><th>Status</th>${can(req.user, 'inventory.move') || can(req.user, 'inventory.manage') ? '<th></th>' : ''}</tr></thead><tbody>`;
  html += prods.length ? prods.map((p) => {
    const lw = p.stock <= p.min_stock;
    let row = `<tr><td><strong>${esc(p.name)}</strong></td><td class="mono muted">${esc(p.sku)}</td><td class="muted">${esc(p.cat || '—')}</td><td class="muted">${esc(p.loc || '—')}</td><td class="muted">${esc(p.sup || '—')}</td><td class="right mono">${money(p.price)}</td><td class="right mono">${p.stock} <span class="muted">/ ${p.min_stock}</span></td><td><span class="badge ${lw ? 'b-danger' : 'b-ok'}">${lw ? 'Laag' : 'OK'}</span></td>`;
    if (can(req.user, 'inventory.move') || can(req.user, 'inventory.manage')) {
      row += '<td class="nowrap right">';
      if (can(req.user, 'inventory.move')) row += moveModal(req, p);
      if (can(req.user, 'inventory.manage')) row += ' ' + productModal(req, p, cats, sups, locs) + ` <form method="post" action="/inventory/${p.id}/delete" style="display:inline" onsubmit="return confirm('Verwijderen?')">${csrfField(req.user.csrf)}<button class="btn btn-sm btn-d">✕</button></form>`;
      row += '</td>';
    }
    row += '</tr>';
    return row;
  }).join('') : `<tr><td colspan="9" class="muted" style="padding:26px;text-align:center">Geen producten gevonden.</td></tr>`;
  html += `</tbody></table></div>`;
  res.send(page(req, 'inventory', html));
});

function opts(rows, selected, placeholder) {
  let h = `<option value="">${esc(placeholder)}</option>`;
  for (const r of rows) h += `<option value="${r.id}" ${String(selected) === String(r.id) ? 'selected' : ''}>${esc(r.name)}</option>`;
  return h;
}
function productModal(req, p, cats, sups, locs) {
  const isEdit = !!p;
  p = p || {};
  const inner = `<div class="bd"><form method="post" action="${isEdit ? `/inventory/${p.id}/update` : '/inventory'}">
    ${csrfField(req.user.csrf)}
    <div class="field"><label>Naam</label><input name="name" required value="${esc(p.name || '')}"></div>
    <div class="cols2"><div class="field"><label>SKU</label><input name="sku" required value="${esc(p.sku || '')}"></div><div class="field"><label>Barcode</label><input name="barcode" value="${esc(p.barcode || '')}"></div></div>
    <div class="cols2"><div class="field"><label>Prijs (€)</label><input name="price" value="${p.price != null ? String(p.price).replace('.', ',') : '0'}"></div><div class="field"><label>Min. voorraad</label><input name="min_stock" type="number" min="0" value="${p.min_stock || 0}"></div></div>
    ${isEdit ? '' : `<div class="cols2"><div class="field"><label>Beginvoorraad</label><input name="stock" type="number" min="0" value="0"></div><div class="field"><label>Eenheid</label><input name="unit" value="stuk"></div></div>`}
    ${isEdit ? `<div class="field"><label>Eenheid</label><input name="unit" value="${esc(p.unit)}"></div>` : ''}
    <div class="cols2"><div class="field"><label>Categorie</label><select name="category_id">${opts(cats, p.category_id || '', '—')}</select></div><div class="field"><label>Locatie</label><select name="location_id">${opts(locs, p.location_id || '', '—')}</select></div></div>
    <div class="field"><label>Leverancier</label><select name="supplier_id">${opts(sups, p.supplier_id || '', '—')}</select></div>
    <button class="btn btn-p">${isEdit ? 'Opslaan' : 'Toevoegen'}</button></form></div>`;
  return modal(isEdit ? 'btn-sm' : 'btn-p', isEdit ? 'Bewerk' : '+ Product toevoegen', isEdit ? 'Product bewerken' : 'Nieuw product', inner);
}
function moveModal(req, p) {
  const inner = `<div class="bd"><form method="post" action="/inventory/${p.id}/move">
    ${csrfField(req.user.csrf)}
    <p class="muted">Huidige voorraad: <strong>${p.stock} ${esc(p.unit)}</strong></p>
    <div class="field"><label>Type mutatie</label><select name="type">${Object.entries(MOVE_TYPES).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join('')}</select></div>
    <div class="field"><label>Aantal (bij correctie mag negatief; bij telling = nieuwe stand)</label><input name="qty" type="number" value="0" required></div>
    <div class="field"><label>Notitie</label><input name="note"></div>
    <button class="btn btn-p">Verwerken</button></form></div>`;
  return modal('btn-sm', 'Voorraad', `Voorraadmutatie · ${p.name}`, inner);
}

app.post('/inventory', requireAuth, requireCsrf, requireCap('inventory.manage'), async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  if (!req.body.name || !req.body.sku) { flash(req, 'Naam en SKU zijn verplicht.', 'err'); return res.redirect('/inventory'); }
  const price = parseFloat(String(req.body.price || '0').replace(',', '.')) || 0;
  const stock = parseInt(req.body.stock, 10) || 0;
  const { rows } = await q(
    `INSERT INTO products (company_id,name,sku,barcode,unit,price,min_stock,category_id,supplier_id,location_id,stock)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
    [cid, req.body.name, req.body.sku, nn(req.body.barcode), req.body.unit || 'stuk', price, parseInt(req.body.min_stock, 10) || 0,
      nn(req.body.category_id), nn(req.body.supplier_id), nn(req.body.location_id), stock]
  );
  if (stock > 0) {
    await q('INSERT INTO stock_movements (company_id,product_id,type,qty,note,user_name) VALUES ($1,$2,$3,$4,$5,$6)',
      [cid, rows[0].id, 'levering', stock, 'Beginvoorraad', req.user.name]);
  }
  flash(req, 'Product toegevoegd.');
  res.redirect('/inventory');
});
app.post('/inventory/:id/update', requireAuth, requireCsrf, requireCap('inventory.manage'), async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  const id = Number(req.params.id);
  const price = parseFloat(String(req.body.price || '0').replace(',', '.')) || 0;
  await q(
    `UPDATE products SET name=$1,sku=$2,barcode=$3,unit=$4,price=$5,min_stock=$6,category_id=$7,supplier_id=$8,location_id=$9 WHERE id=$10 AND company_id=$11`,
    [req.body.name, req.body.sku, nn(req.body.barcode), req.body.unit || 'stuk', price, parseInt(req.body.min_stock, 10) || 0,
      nn(req.body.category_id), nn(req.body.supplier_id), nn(req.body.location_id), id, cid]
  );
  flash(req, 'Product bijgewerkt.');
  res.redirect('/inventory');
});
app.post('/inventory/:id/delete', requireAuth, requireCsrf, requireCap('inventory.manage'), async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  await q('DELETE FROM products WHERE id=$1 AND company_id=$2', [Number(req.params.id), cid]);
  flash(req, 'Product verwijderd.');
  res.redirect('/inventory');
});
app.post('/inventory/:id/move', requireAuth, requireCsrf, requireCap('inventory.move'), async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  const id = Number(req.params.id);
  const { rows } = await q('SELECT * FROM products WHERE id=$1 AND company_id=$2', [id, cid]);
  const prod = rows[0];
  if (prod) {
    const type = MOVE_TYPES[req.body.type] ? req.body.type : 'correctie';
    const r = applyMovement(prod.stock, type, parseInt(req.body.qty, 10) || 0);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('UPDATE products SET stock=$1 WHERE id=$2', [r.new, prod.id]);
      await client.query('INSERT INTO stock_movements (company_id,product_id,type,qty,note,user_name) VALUES ($1,$2,$3,$4,$5,$6)',
        [cid, prod.id, type, r.delta, nn(req.body.note), req.user.name]);
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
    flash(req, `Voorraad bijgewerkt: ${prod.name} → ${r.new} ${prod.unit}.`);
  }
  res.redirect('/inventory');
});

app.get('/inventory/history', requireAuth, async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  const { rows: moves } = await q(
    `SELECT m.*, p.name pname, p.sku FROM stock_movements m JOIN products p ON p.id=m.product_id WHERE m.company_id=$1 ORDER BY m.created_at DESC LIMIT 300`,
    [cid]
  );
  let html = `<div class="between"><h1>Voorraadhistorie</h1><a class="btn" href="/inventory">← Voorraad</a></div>`;
  html += `<div class="card" style="margin-top:14px;overflow-x:auto"><table><thead><tr><th>Datum</th><th>Product</th><th>Type</th><th class="right">Wijziging</th><th>Door</th><th>Notitie</th></tr></thead><tbody>`;
  html += moves.length ? moves.map((m) => `<tr><td class="nowrap">${fmtDt(m.created_at)}</td><td><strong>${esc(m.pname)}</strong> <span class="mono muted">${esc(m.sku)}</span></td><td><span class="badge ${moveBadge(m.type)}">${esc(MOVE_TYPES[m.type] || m.type)}</span></td><td class="right mono" style="color:${m.qty >= 0 ? 'var(--ok)' : 'var(--danger)'}">${m.qty >= 0 ? '+' : ''}${m.qty}</td><td class="muted">${esc(m.user_name)}</td><td class="muted">${esc(m.note)}</td></tr>`).join('') : `<tr><td colspan="6" class="muted" style="padding:26px;text-align:center">Nog geen mutaties.</td></tr>`;
  html += `</tbody></table></div>`;
  res.send(page(req, 'history', html));
});

app.get('/inventory/orders', requireAuth, async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  const { rows } = await q(
    `SELECT p.*, s.name sup FROM products p LEFT JOIN suppliers s ON s.id=p.supplier_id WHERE p.company_id=$1 AND p.active=true AND p.stock<=p.min_stock ORDER BY s.name, p.name`,
    [cid]
  );
  let html = `<div class="between"><h1>Bestellijst (lage voorraad)</h1><a class="btn" href="/inventory">← Voorraad</a></div>`;
  if (!rows.length) {
    html += `<div class="card" style="margin-top:14px"><div class="bd muted">Geen artikelen onder het minimum. ✓</div></div>`;
    return res.send(page(req, 'orders', html));
  }
  const groups = {};
  for (const r of rows) { const key = r.sup || 'Zonder leverancier'; (groups[key] = groups[key] || []).push(r); }
  for (const [sup, items] of Object.entries(groups)) {
    html += `<h2>${esc(sup)}</h2><div class="card" style="overflow-x:auto"><table><thead><tr><th>Product</th><th>SKU</th><th class="right">Voorraad</th><th class="right">Min.</th><th class="right">Bestellen</th></tr></thead><tbody>`;
    html += items.map((p) => {
      const need = Math.max(p.min_stock * 2 - p.stock, p.min_stock);
      return `<tr><td>${esc(p.name)}</td><td class="mono muted">${esc(p.sku)}</td><td class="right mono">${p.stock}</td><td class="right mono">${p.min_stock}</td><td class="right mono" style="font-weight:800;color:var(--primary)">${need}</td></tr>`;
    }).join('');
    html += `</tbody></table></div>`;
  }
  res.send(page(req, 'orders', html));
});

app.get('/inventory/settings', requireAuth, requireCap('inventory.manage'), async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  const { rows: cats } = await q(`SELECT c.*, (SELECT COUNT(*)::int FROM products p WHERE p.category_id=c.id) n FROM categories c WHERE c.company_id=$1 ORDER BY name`, [cid]);
  const { rows: sups } = await q('SELECT * FROM suppliers WHERE company_id=$1 ORDER BY name', [cid]);
  const { rows: locs } = await q(`SELECT l.*, (SELECT COUNT(*)::int FROM products p WHERE p.location_id=l.id) n FROM locations l WHERE l.company_id=$1 ORDER BY name`, [cid]);

  let html = `<div class="between"><h1>Voorraad-instellingen</h1><a class="btn" href="/inventory">← Voorraad</a></div>`;
  html += `<div class="grid" style="grid-template-columns:1fr;margin-top:14px;gap:16px">`;
  html += `<div class="card"><div class="bd"><h2 style="margin-top:0">Categorieën</h2>
    <form method="post" action="/inventory/settings/categories" class="row" style="margin-bottom:12px">${csrfField(req.user.csrf)}<input name="name" placeholder="Nieuwe categorie" required style="flex:1"><button class="btn btn-p">Toevoegen</button></form>
    ${cats.map((c) => settingsRow(req, c.name, `${c.n} producten`, `/inventory/settings/categories/${c.id}/delete`)).join('')}
    </div></div>`;
  html += `<div class="card"><div class="bd"><h2 style="margin-top:0">Leveranciers</h2>
    <form method="post" action="/inventory/settings/suppliers" class="row" style="margin-bottom:12px">${csrfField(req.user.csrf)}<input name="name" placeholder="Naam" required style="flex:1"><input name="email" placeholder="E-mail (optioneel)" style="flex:1"><input name="phone" placeholder="Tel (optioneel)" style="width:120px"><button class="btn btn-p">Toevoegen</button></form>
    ${sups.map((s) => settingsRow(req, s.name, [s.email, s.phone].filter(Boolean).join(' ') || '—', `/inventory/settings/suppliers/${s.id}/delete`)).join('')}
    </div></div>`;
  html += `<div class="card"><div class="bd"><h2 style="margin-top:0">Locaties</h2>
    <form method="post" action="/inventory/settings/locations" class="row" style="margin-bottom:12px">${csrfField(req.user.csrf)}<input name="name" placeholder="Nieuwe locatie" required style="flex:1"><button class="btn btn-p">Toevoegen</button></form>
    ${locs.map((l) => settingsRow(req, l.name, `${l.n} producten`, `/inventory/settings/locations/${l.id}/delete`)).join('')}
    </div></div>`;
  html += `</div>`;
  res.send(page(req, 'inventory_settings', html));
});
function settingsRow(req, name, sub, delAction) {
  return `<div class="between" style="padding:9px 0;border-bottom:1px solid var(--border)"><div><div style="font-weight:600">${esc(name)}</div><div class="muted" style="font-size:12px">${esc(sub)}</div></div>
    <form method="post" action="${esc(delAction)}" onsubmit="return confirm('Verwijderen?')">${csrfField(req.user.csrf)}<button class="btn btn-sm btn-d">✕</button></form></div>`;
}
for (const [seg, tbl] of [['categories', 'categories'], ['suppliers', 'suppliers'], ['locations', 'locations']]) {
  app.post(`/inventory/settings/${seg}`, requireAuth, requireCsrf, requireCap('inventory.manage'), async (req, res) => {
    const cid = req.user.effectiveCompanyId;
    if (req.body.name) {
      if (tbl === 'suppliers') await q('INSERT INTO suppliers (company_id,name,email,phone) VALUES ($1,$2,$3,$4)', [cid, req.body.name, nn(req.body.email), nn(req.body.phone)]);
      else await q(`INSERT INTO ${tbl} (company_id,name) VALUES ($1,$2)`, [cid, req.body.name]);
      flash(req, 'Toegevoegd.');
    }
    res.redirect('/inventory/settings');
  });
  app.post(`/inventory/settings/${seg}/:id/delete`, requireAuth, requireCsrf, requireCap('inventory.manage'), async (req, res) => {
    const cid = req.user.effectiveCompanyId;
    await q(`DELETE FROM ${tbl} WHERE id=$1 AND company_id=$2`, [Number(req.params.id), cid]);
    flash(req, 'Verwijderd.');
    res.redirect('/inventory/settings');
  });
}

app.get('/inventory/export.csv', requireAuth, requireCap('reports.view'), async (req, res) => {
  const cid = req.user.effectiveCompanyId;
  const { rows } = await q(
    `SELECT p.*, c.name cat, s.name sup FROM products p LEFT JOIN categories c ON c.id=p.category_id LEFT JOIN suppliers s ON s.id=p.supplier_id WHERE p.company_id=$1 AND p.active=true ORDER BY p.name`,
    [cid]
  );
  const cell = (v) => { const s = String(v ?? ''); return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  const header = ['Naam', 'SKU', 'Barcode', 'Categorie', 'Leverancier', 'Eenheid', 'Prijs', 'Voorraad', 'MinVoorraad', 'Waarde'];
  const lines = [header.join(';')];
  for (const p of rows) {
    lines.push([p.name, p.sku, p.barcode, p.cat, p.sup, p.unit, Number(p.price).toFixed(2), p.stock, p.min_stock, (Number(p.price) * p.stock).toFixed(2)].map(cell).join(';'));
  }
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="voorraad-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.send('\uFEFF' + lines.join('\n'));
});

// ================================================================== USERS
app.get('/users', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin' && !req.user.is_super) return res.redirect('/dashboard');
  const cid = req.user.effectiveCompanyId;
  const { rows: users } = await q('SELECT * FROM users WHERE company_id=$1 ORDER BY name', [cid]);
  let html = `<h1>Gebruikers</h1><p class="muted">Voeg collega's toe tot <strong>${esc(req.user.company_name)}</strong> en geef ze een rol.</p>`;
  html += `<div class="grid" style="grid-template-columns:1fr;margin-top:14px;gap:16px">`;
  html += `<div class="card"><div class="bd"><h2 style="margin-top:0">Nieuwe gebruiker</h2>
    <form method="post" action="/users"><div class="cols2">${csrfField(req.user.csrf)}
      <div class="field"><label>Naam</label><input name="name" required></div>
      <div class="field"><label>E-mail</label><input name="email" type="email" required></div>
      <div class="field"><label>Wachtwoord (min. 6)</label><input name="password" type="password" required></div>
      <div class="field"><label>Rol</label><select name="role">${Object.entries(ROLES).map(([k, v]) => `<option value="${k}" ${k === 'technicus' ? 'selected' : ''}>${esc(v)}</option>`).join('')}</select></div>
    </div><button class="btn btn-p">Gebruiker toevoegen</button></form></div></div>`;
  html += `<div class="card" style="overflow-x:auto"><table><thead><tr><th>Naam</th><th>E-mail</th><th>Rol</th><th></th></tr></thead><tbody>`;
  html += users.map((u) => `<tr><td><strong>${esc(u.name)}</strong>${u.id === req.user.id ? ' <span class="badge b-info">jij</span>' : ''}</td><td class="mono muted">${esc(u.email)}</td><td><span class="badge b-neutral">${esc(ROLES[u.role] || u.role)}</span></td><td class="right">${u.id === req.user.id ? '' : `<form method="post" action="/users/${u.id}/delete" onsubmit="return confirm('Gebruiker verwijderen?')">${csrfField(req.user.csrf)}<button class="btn btn-sm btn-d">Verwijderen</button></form>`}</td></tr>`).join('');
  html += `</tbody></table></div></div>`;
  res.send(page(req, 'users', html));
});
app.post('/users', requireAuth, requireCsrf, async (req, res) => {
  if (req.user.role !== 'admin' && !req.user.is_super) { flash(req, 'Geen rechten.', 'err'); return res.redirect('/users'); }
  const cid = req.user.effectiveCompanyId;
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!req.body.name || !email || String(req.body.password || '').length < 6) {
    flash(req, 'Vul naam, e-mail en wachtwoord (min. 6 tekens) in.', 'err');
    return res.redirect('/users');
  }
  const exists = await q('SELECT 1 FROM users WHERE email=$1', [email]);
  if (exists.rows[0]) { flash(req, 'E-mailadres bestaat al.', 'err'); return res.redirect('/users'); }
  const role = ROLES[req.body.role] ? req.body.role : 'technicus';
  const hash = await bcrypt.hash(req.body.password, 10);
  await q('INSERT INTO users (company_id,name,email,password_hash,role) VALUES ($1,$2,$3,$4,$5)', [cid, req.body.name, email, hash, role]);
  flash(req, 'Gebruiker toegevoegd.');
  res.redirect('/users');
});
app.post('/users/:id/delete', requireAuth, requireCsrf, async (req, res) => {
  if (req.user.role !== 'admin' && !req.user.is_super) { flash(req, 'Geen rechten.', 'err'); return res.redirect('/users'); }
  const cid = req.user.effectiveCompanyId;
  const id = Number(req.params.id);
  if (id === req.user.id) { flash(req, 'Je kunt jezelf niet verwijderen.', 'err'); return res.redirect('/users'); }
  await q('DELETE FROM users WHERE id=$1 AND company_id=$2', [id, cid]);
  flash(req, 'Gebruiker verwijderd.');
  res.redirect('/users');
});

// ================================================================== COMPANIES (super-admin)
app.get('/companies', requireAuth, async (req, res) => {
  if (!req.user.is_super) return res.redirect('/dashboard');
  const { rows: companies } = await q(`
    SELECT c.*,
      (SELECT COUNT(*)::int FROM users u WHERE u.company_id=c.id) nusers,
      (SELECT COUNT(*)::int FROM products p WHERE p.company_id=c.id AND p.active=true) nprods,
      (SELECT COUNT(*)::int FROM issues i WHERE i.company_id=c.id AND i.status IN ('open','in_behandeling','on_hold')) nopen
    FROM companies c ORDER BY c.name`);
  let html = `<div class="between"><div><h1>Bedrijven</h1><p class="muted">Beheer alle bedrijven op dit platform en schakel ertussen.</p></div>${addCompanyModal(req)}</div>`;
  html += `<div class="card" style="margin-top:14px;overflow-x:auto"><table><thead><tr><th>Bedrijf</th><th class="right">Gebruikers</th><th class="right">Producten</th><th class="right">Open storingen</th><th></th></tr></thead><tbody>`;
  for (const c of companies) {
    const isHome = c.id === req.user.homeCompanyId;
    const isActive = req.user.effectiveCompanyId === c.id;
    html += `<tr><td><strong>${esc(c.name)}</strong>${isHome ? ' <span class="badge b-neutral">jouw bedrijf</span>' : ''}${isActive && !isHome ? ' <span class="badge b-info">actief</span>' : ''}<div class="muted" style="font-size:12px">Aangemaakt ${fmtDate(c.created_at)}</div></td>`;
    html += `<td class="right mono">${c.nusers}</td><td class="right mono">${c.nprods}</td><td class="right mono">${c.nopen}</td><td class="right nowrap">`;
    html += isActive ? `<a class="btn btn-sm" href="/dashboard">Bekijken</a> ` : `<form method="post" action="/companies/${c.id}/switch" style="display:inline">${csrfField(req.user.csrf)}<button class="btn btn-sm btn-p">Openen</button></form> `;
    if (!isHome) html += `<form method="post" action="/companies/${c.id}/delete" style="display:inline" onsubmit="return confirm('Bedrijf én alle data verwijderen?')">${csrfField(req.user.csrf)}<button class="btn btn-sm btn-d">✕</button></form>`;
    html += `</td></tr>`;
  }
  html += `</tbody></table></div><p class="muted" style="font-size:13px;margin-top:12px">Tip: klik <strong>Openen</strong> om als super-admin in een bedrijf te werken. Je ziet dan een balk bovenaan om terug te keren.</p>`;
  res.send(page(req, 'companies', html));
});
function addCompanyModal(req) {
  const inner = `<div class="bd"><form method="post" action="/companies">
    ${csrfField(req.user.csrf)}
    <div class="field"><label>Bedrijfsnaam</label><input name="company" required></div>
    <p class="muted" style="font-size:12px;margin:0 0 10px">Optioneel meteen een beheerder aanmaken:</p>
    <div class="field"><label>Naam beheerder</label><input name="admin_name"></div>
    <div class="cols2"><div class="field"><label>E-mail</label><input name="admin_email" type="email"></div><div class="field"><label>Wachtwoord (min. 6)</label><input name="admin_password" type="password"></div></div>
    <button class="btn btn-p">Bedrijf aanmaken</button></form></div>`;
  return modal('btn-p', '+ Nieuw bedrijf', 'Nieuw bedrijf', inner);
}
app.post('/companies', requireAuth, requireCsrf, async (req, res) => {
  if (!req.user.is_super) { flash(req, 'Geen rechten.', 'err'); return res.redirect('/companies'); }
  if (!req.body.company) return res.redirect('/companies');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const co = await client.query('INSERT INTO companies (name) VALUES ($1) RETURNING id', [req.body.company]);
    const newCid = co.rows[0].id;
    if (req.body.admin_name && req.body.admin_email && String(req.body.admin_password || '').length >= 6) {
      const em = String(req.body.admin_email).trim().toLowerCase();
      const exists = await client.query('SELECT 1 FROM users WHERE email=$1', [em]);
      if (!exists.rows[0]) {
        const hash = await bcrypt.hash(req.body.admin_password, 10);
        await client.query('INSERT INTO users (company_id,name,email,password_hash,role) VALUES ($1,$2,$3,$4,$5)', [newCid, req.body.admin_name, em, hash, 'admin']);
      }
    }
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  flash(req, `Bedrijf "${req.body.company}" aangemaakt.`);
  res.redirect('/companies');
});
app.post('/companies/:id/switch', requireAuth, requireCsrf, async (req, res) => {
  if (!req.user.is_super) { flash(req, 'Geen rechten.', 'err'); return res.redirect('/dashboard'); }
  const id = Number(req.params.id);
  const exists = await q('SELECT 1 FROM companies WHERE id=$1', [id]);
  if (exists.rows[0]) { req.session.actingCompanyId = id; flash(req, 'Je werkt nu in een ander bedrijf.'); }
  res.redirect('/dashboard');
});
app.post('/companies/stop-switch', requireAuth, requireCsrf, (req, res) => {
  delete req.session.actingCompanyId;
  flash(req, 'Terug naar je eigen bedrijf.');
  res.redirect('/companies');
});
app.post('/companies/:id/delete', requireAuth, requireCsrf, async (req, res) => {
  if (!req.user.is_super) { flash(req, 'Geen rechten.', 'err'); return res.redirect('/companies'); }
  const id = Number(req.params.id);
  if (id === req.user.homeCompanyId) { flash(req, 'Je kunt je eigen bedrijf niet verwijderen.', 'err'); return res.redirect('/companies'); }
  await q('DELETE FROM companies WHERE id=$1', [id]);
  if (req.session.actingCompanyId === id) delete req.session.actingCompanyId;
  flash(req, 'Bedrijf verwijderd.');
  res.redirect('/companies');
});

// ================================================================== health + boot
app.get('/healthz', async (req, res) => {
  try { await q('SELECT 1'); res.status(200).send('ok'); }
  catch (e) { res.status(500).send('db error: ' + e.message); }
});

const PORT = process.env.PORT || 3000;
async function boot() {
  await migrate();
  await seedIfEmpty();
  await ensureSuperAdmin();
  app.listen(PORT, () => console.log(`Onderhoud & Voorraad draait op poort ${PORT}`));
}
boot().catch((e) => { console.error('Opstarten mislukt:', e); process.exit(1); });

module.exports = app;
