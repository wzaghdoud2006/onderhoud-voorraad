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

module.exports = {
  esc, money, fmtDate, fmtDt, MOVE_TYPES, applyMovement, can,
  PERMISSION_GROUPS, ALL_PERMISSIONS,
};
