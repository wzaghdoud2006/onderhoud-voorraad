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

async function migrate() {
  await q(`
    CREATE TABLE IF NOT EXISTS companies (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'technicus',
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
      email TEXT,
      phone TEXT
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
    CREATE TABLE IF NOT EXISTS issues (
      id SERIAL PRIMARY KEY,
      company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      description TEXT,
      priority TEXT NOT NULL DEFAULT 'middel',
      status TEXT NOT NULL DEFAULT 'open',
      assignee TEXT,
      reported_by TEXT NOT NULL,
      due_date DATE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      resolved_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS issue_comments (
      id SERIAL PRIMARY KEY,
      issue_id INTEGER NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
      body TEXT NOT NULL,
      author TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_products_company ON products(company_id);
    CREATE INDEX IF NOT EXISTS idx_issues_company ON issues(company_id);
    CREATE INDEX IF NOT EXISTS idx_movements_company ON stock_movements(company_id);
    CREATE INDEX IF NOT EXISTS idx_users_company ON users(company_id);
  `);
}

async function seedIfEmpty() {
  const { rows } = await q('SELECT COUNT(*)::int AS c FROM users');
  if (rows[0].c > 0) return;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const co = await client.query('INSERT INTO companies (name) VALUES ($1) RETURNING id', ['Demo Speelparadijs']);
    const cid = co.rows[0].id;
    const hash = await bcrypt.hash('Demo1234!', 10);
    await client.query(
      'INSERT INTO users (company_id,name,email,password_hash,role,is_super) VALUES ($1,$2,$3,$4,$5,true)',
      [cid, 'Beheerder', 'admin@demo.local', hash, 'admin']
    );
    await client.query(
      'INSERT INTO users (company_id,name,email,password_hash,role) VALUES ($1,$2,$3,$4,$5)',
      [cid, 'Youssef (Technicus)', 'tech@demo.local', hash, 'technicus']
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
    await client.query(
      `INSERT INTO issues (company_id,title,description,priority,status,assignee,reported_by,due_date)
       VALUES ($1,$2,$3,$4,$5,$6,$7, CURRENT_DATE - INTERVAL '2 days')`,
      [cid, 'Kartbaan lamp defect', 'Lamp boven bocht 3 flikkert.', 'hoog', 'open', 'Youssef (Technicus)', 'Beheerder']
    );
    await client.query(
      `INSERT INTO issues (company_id,title,description,priority,status,assignee,reported_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [cid, 'Airhockey vertoont ruis', 'Compressor maakt piepend geluid.', 'middel', 'in_behandeling', 'Youssef (Technicus)', 'Beheerder']
    );
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

module.exports = { pool, q, migrate, seedIfEmpty, ensureSuperAdmin };
