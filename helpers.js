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

const PRIORITIES = { laag: 'Laag', middel: 'Middel', hoog: 'Hoog', kritiek: 'Kritiek' };
const STATUSES = { open: 'Open', in_behandeling: 'In behandeling', on_hold: 'On hold', opgelost: 'Opgelost', gesloten: 'Gesloten' };
const MOVE_TYPES = { levering: 'Levering', afschrijving: 'Afschrijving', telling: 'Telling', correctie: 'Correctie' };
const ROLES = { admin: 'Beheerder', manager: 'Manager', technicus: 'Technicus' };

function isOverdue(due, status) {
  if (!due) return false;
  const open = ['open', 'in_behandeling', 'on_hold'].includes(status);
  return open && new Date(due) < new Date(new Date().toDateString());
}

function applyMovement(current, type, qty) {
  let n;
  if (type === 'levering') n = current + Math.abs(qty);
  else if (type === 'afschrijving') n = Math.max(0, current - Math.abs(qty));
  else if (type === 'telling') n = Math.max(0, Math.round(qty));
  else n = Math.max(0, current + qty); // correctie
  return { new: n, delta: n - current };
}

/** Role-based capability check, mirrors the PHP app's can(). */
function can(user, cap) {
  if (!user) return false;
  if (user.role === 'admin') return true;
  const map = {
    manager: ['inventory.manage', 'inventory.move', 'maintenance.manage', 'maintenance.update', 'reports.view'],
    technicus: ['inventory.move', 'inventory.view', 'maintenance.update', 'maintenance.create'],
  };
  if (['inventory.view', 'maintenance.view', 'reports.view'].includes(cap)) return true;
  return (map[user.role] || []).includes(cap);
}

module.exports = { esc, money, fmtDate, fmtDt, PRIORITIES, STATUSES, MOVE_TYPES, ROLES, isOverdue, applyMovement, can };
