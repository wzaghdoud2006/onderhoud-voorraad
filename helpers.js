function esc(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function money(v) {
  const n = Number(v || 0);
  return '€ ' + n.toLocaleString('nl-NL', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
function fmtDate(s) {
  if (!s) return '—';
  const d = new Date(s);
  return d.toLocaleDateString('nl-NL', { day: '2-digit', month: '2-digit', year: 'numeric' });
}
function fmtDt(s) {
  if (!s) return '—';
  const d = new Date(s);
  return d.toLocaleDateString('nl-NL', { day: '2-digit', month: '2-digit', year: 'numeric' }) + ' ' +
    d.toLocaleTimeString('nl-NL', { hour: '2-digit', minute: '2-digit' });
}

const MOVE_TYPES = { levering: 'Levering', afschrijving: 'Afschrijving', telling: 'Telling', correctie: 'Correctie' };

// Every permission a role can be granted, grouped for the role editor UI.
const PERMISSION_GROUPS = [
  {
    label: 'Voorraad',
    perms: [
      ['inventory.view', 'Voorraad bekijken'],
      ['inventory.create', 'Producten toevoegen'],
      ['inventory.update', 'Producten bewerken'],
      ['inventory.delete', 'Producten verwijderen'],
      ['inventory.move', 'Voorraadmutaties verwerken'],
    ],
  },
  {
    label: 'Rapportages',
    perms: [['reports.view', 'Rapportages / CSV-export']],
  },
  {
    label: 'Beheer',
    perms: [
      ['users.manage', 'Gebruikers beheren'],
      ['roles.manage', 'Rollen beheren'],
      ['settings.manage', 'Bedrijfsinstellingen beheren'],
    ],
  },
];
const ALL_PERMISSIONS = PERMISSION_GROUPS.flatMap((g) => g.perms.map(([k]) => k));

function applyMovement(current, type, qty) {
  let n;
  if (type === 'levering') n = current + Math.abs(qty);
  else if (type === 'afschrijving') n = Math.max(0, current - Math.abs(qty));
  else if (type === 'telling') n = Math.max(0, Math.round(qty));
  else n = Math.max(0, current + qty); // correctie
  return { new: n, delta: n - current };
}

/** Permission check against the user's resolved permissions array (from their role). */
function can(user, cap) {
  if (!user) return false;
  if (user.is_super) return true; // platform super-admin always has full access
  const perms = user.permissions || [];
  if (perms.includes('*')) return true;
  if (perms.includes(cap)) return true;
  const mod = cap.split('.')[0];
  if (perms.includes(`${mod}.*`)) return true;
  return false;
}

/**
 * Minimal dependency-free CSV parser. Auto-detects ',' vs ';' as delimiter
 * (Sligro/Excel exports commonly use ';'), strips a UTF-8 BOM, and handles
 * quoted fields (including embedded delimiters/newlines and "" escaping).
 * Returns { headers: string[], rows: string[][] }.
 */
function parseCsv(text) {
  text = String(text || '').replace(/^\uFEFF/, '');
  const firstLine = text.split(/\r?\n/, 1)[0] || '';
  const delim = (firstLine.match(/;/g) || []).length >= (firstLine.match(/,/g) || []).length ? ';' : ',';

  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else field += c;
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === delim) {
      row.push(field); field = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.some((f) => f !== '')) rows.push(row);
      row = [];
    } else {
      field += c;
    }
  }
  if (field !== '' || row.length) { row.push(field); if (row.some((f) => f !== '')) rows.push(row); }

  const headers = (rows.shift() || []).map((h) => h.trim().toLowerCase());
  return { headers, rows };
}

/** Find the index of the first header matching any of the given candidate names. */
function findCol(headers, candidates) {
  for (const cand of candidates) {
    const i = headers.indexOf(cand);
    if (i >= 0) return i;
  }
  return -1;
}

module.exports = {
  esc, money, fmtDate, fmtDt, MOVE_TYPES, applyMovement, can,
  PERMISSION_GROUPS, ALL_PERMISSIONS, parseCsv, findCol,
};
