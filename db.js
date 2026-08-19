// ---------------------------------------------------------------------------
// Database: connection pool + migrations (idempotent) + demo seed.
// ---------------------------------------------------------------------------
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : (process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : false),
});

async function q(text, params) {
  return pool.query(text, params);
}

// Default role templates seeded for every company. 'admin' always gets the
// wildcard so there is always at least one fully-privileged role per company.
const DEFAULT_ROLES = [
  { key: 'admin', name: 'Beheerder', permissions: ['*'] },
  { key: 'manager', name: 'Manager', permissions: ['inventory.*', 'reports.view', 'users.manage'] },
  { key: 'medewerker', name: 'Medewerker', permissions: ['inventory.view', 'inventory.move'] },
];

async function migrate() {
  await q(`
    CREATE TABLE IF NOT EXISTS companies (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS roles (
      id SERIAL PRIMARY KEY,
      company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      key TEXT NOT NULL,
      name TEXT NOT NULL,
      permissions TEXT[] NOT NULL DEFAULT '{}',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, key)
    );
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'medewerker',
      role_id INTEGER REFERENCES roles(id) ON DELETE SET NULL,
      is_super BOOLEAN NOT NULL DEFAULT false,
      active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS categories (
      id SERIAL PRIMARY KEY,
      company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS suppliers (
      id SERIAL PRIMARY KEY,
      company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      email TEXT, phone TEXT
    );
    CREATE TABLE IF NOT EXISTS locations (
      id SERIAL PRIMARY KEY,
      company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
      supplier_id INTEGER REFERENCES suppliers(id) ON DELETE SET NULL,
      location_id INTEGER REFERENCES locations(id) ON DELETE SET NULL,
      name TEXT NOT NULL,
      sku TEXT NOT NULL,
      barcode TEXT,
      unit TEXT NOT NULL DEFAULT 'stuk',
      price NUMERIC NOT NULL DEFAULT 0,
      stock INTEGER NOT NULL DEFAULT 0,
      min_stock INTEGER NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS stock_movements (
      id SERIAL PRIMARY KEY,
      company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      qty INTEGER NOT NULL,
      note TEXT,
      user_name TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_products_company ON products(company_id);
    CREATE INDEX IF NOT EXISTS idx_movements_company ON stock_movements(company_id);
    CREATE INDEX IF NOT EXISTS idx_users_company ON users(company_id);
    CREATE INDEX IF NOT EXISTS idx_roles_company ON roles(company_id);
    CREATE TABLE IF NOT EXISTS audit_log (
      id SERIAL PRIMARY KEY,
      company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,
      user_name TEXT NOT NULL,
      action TEXT NOT NULL,
      details TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_audit_company ON audit_log(company_id, created_at DESC);
  `);
  // Safe to run on every boot even against a pre-existing (older) database.
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role_id INTEGER REFERENCES roles(id) ON DELETE SET NULL;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar BYTEA;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_mime TEXT;`);
  await q(`ALTER TABLE companies ADD COLUMN IF NOT EXISTS logo BYTEA;`);
  await q(`ALTER TABLE companies ADD COLUMN IF NOT EXISTS logo_mime TEXT;`);
}

/** Write one row to the activity log. Never throws — logging failures must not break the request. */
async function writeAudit(companyId, userName, action, details) {
  try { await q('INSERT INTO audit_log (company_id,user_name,action,details) VALUES ($1,$2,$3,$4)', [companyId, userName, action, details || null]); }
  catch (e) { console.error('audit log write failed:', e.message); }
}

/** Insert the three default roles for a company; returns { admin, manager, medewerker } role rows. */
async function seedDefaultRoles(client, companyId) {
  const out = {};
  for (const r of DEFAULT_ROLES) {
    const { rows } = await client.query(
      `INSERT INTO roles (company_id,key,name,permissions) VALUES ($1,$2,$3,$4)
       ON CONFLICT (company_id,key) DO UPDATE SET name = EXCLUDED.name
       RETURNING id, key, name, permissions`,
      [companyId, r.key, r.name, r.permissions]
    );
    out[r.key] = rows[0];
  }
  return out;
}

/** For every company without any roles yet, seed the default set. */
async function backfillRoles() {
  const { rows: companies } = await q(
    `SELECT c.id FROM companies c WHERE NOT EXISTS (SELECT 1 FROM roles r WHERE r.company_id = c.id)`
  );
  for (const c of companies) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await seedDefaultRoles(client, c.id);
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  }
}

/** Assign every user without a role_id to the role matching their legacy `role` text column. */
async function backfillUserRoles() {
  const { rows: users } = await q(`SELECT id, company_id, role FROM users WHERE role_id IS NULL`);
  for (const u of users) {
    const key = ['admin', 'manager', 'medewerker'].includes(u.role) ? u.role : 'medewerker';
    const { rows } = await q(`SELECT id FROM roles WHERE company_id=$1 AND key=$2`, [u.company_id, key]);
    const roleId = rows[0] ? rows[0].id : null;
    if (roleId) await q(`UPDATE users SET role_id=$1 WHERE id=$2`, [roleId, u.id]);
  }
}

async function seedIfEmpty() {
  const { rows } = await q('SELECT COUNT(*)::int AS c FROM users');
  if (rows[0].c > 0) return;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const co = await client.query('INSERT INTO companies (name) VALUES ($1) RETURNING id', ['Demo Speelparadijs']);
    const cid = co.rows[0].id;
    const roles = await seedDefaultRoles(client, cid);
    const hash = await bcrypt.hash('Demo1234!', 10);
    await client.query(
      'INSERT INTO users (company_id,name,email,password_hash,role,role_id,is_super) VALUES ($1,$2,$3,$4,$5,$6,true)',
      [cid, 'Beheerder', 'admin@demo.local', hash, 'admin', roles.admin.id]
    );
    await client.query(
      'INSERT INTO users (company_id,name,email,password_hash,role,role_id) VALUES ($1,$2,$3,$4,$5,$6)',
      [cid, 'Youssef (Medewerker)', 'tech@demo.local', hash, 'medewerker', roles.medewerker.id]
    );
    const catIds = [];
    for (const n of ['Horeca', 'Games', 'Onderhoud']) {
      const r = await client.query('INSERT INTO categories (company_id,name) VALUES ($1,$2) RETURNING id', [cid, n]);
      catIds.push(r.rows[0].id);
    }
    const supIds = [];
    for (const n of ['Lumex BV', 'GreenTech Parts', 'Cleanline']) {
      const r = await client.query('INSERT INTO suppliers (company_id,name) VALUES ($1,$2) RETURNING id', [cid, n]);
      supIds.push(r.rows[0].id);
    }
    const locIds = [];
    for (const n of ['Magazijn', 'Bar', 'Werkplaats']) {
      const r = await client.query('INSERT INTO locations (company_id,name) VALUES ($1,$2) RETURNING id', [cid, n]);
      locIds.push(r.rows[0].id);
    }
    const demoProducts = [
      ['Cola 0,33L', 'DR-COLA', '8710000111', 'stuk', 1.5, 120, 48],
      ['Water 0,5L', 'DR-WATER', '8710000112', 'stuk', 1.2, 20, 40],
      ['Chips zak', 'SN-CHIPS', '8710000113', 'stuk', 2.0, 8, 24],
      ['Arcade tokens (100)', 'AR-TOKEN', '8710000114', 'set', 10.0, 300, 100],
      ['Poetsdoek microvezel', 'ON-DOEK', '8710000115', 'stuk', 3.5, 12, 20],
      ['Smeerolie 1L', 'ON-OLIE', '8710000116', 'fles', 7.5, 6, 10],
    ];
    for (let i = 0; i < demoProducts.length; i++) {
      const [name, sku, barcode, unit, price, stock, minStock] = demoProducts[i];
      await client.query(
        `INSERT INTO products (company_id,category_id,supplier_id,location_id,name,sku,barcode,unit,price,stock,min_stock)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [cid, catIds[i % catIds.length], supIds[i % supIds.length], locIds[i % locIds.length], name, sku, barcode, unit, price, stock, minStock]
      );
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

/** Ensure there is at least one platform super-admin (backfill for older data). */
async function ensureSuperAdmin() {
  const { rows } = await q('SELECT COUNT(*)::int AS c FROM users WHERE is_super = true');
  if (rows[0].c > 0) return;
  const first = await q("SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1");
  if (first.rows[0]) await q('UPDATE users SET is_super = true WHERE id = $1', [first.rows[0].id]);
}

module.exports = {
  pool, q, migrate, seedIfEmpty, ensureSuperAdmin,
  seedDefaultRoles, backfillRoles, backfillUserRoles, DEFAULT_ROLES, writeAudit,
};
