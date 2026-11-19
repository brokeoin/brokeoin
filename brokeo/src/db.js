import pg from 'pg';

// bigint columns (timestamps) come back as strings by default; the app wants numbers
pg.types.setTypeParser(20, v => Number(v));

const url = process.env.DATABASE_URL || process.env.POSTGRES_URL;
if (!url) throw new Error('DATABASE_URL is not set. Add your Postgres connection string to the environment variables.');

// Small pool: every serverless instance keeps its own connections. Use the *pooled* connection string if your host offers one.
export const pool = new pg.Pool({ connectionString: url, max: 3, idleTimeoutMillis: 10_000, connectionTimeoutMillis: 10_000 });
pool.on('error', e => console.error('pg pool error', e.message));

export const q = async (text, params = []) => (await pool.query(text, params)).rows;
export const one = async (text, params = []) => (await pool.query(text, params)).rows[0] || null;
export const scalar = async (text, params = []) => { const r = (await pool.query({ text, values: params, rowMode: 'array' })).rows[0]; return r ? r[0] : null; };

/** Runs fn(client) inside a transaction. */
export async function tx(fn) {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const out = await fn(c);
    await c.query('COMMIT');
    return out;
  } catch (e) {
    await c.query('ROLLBACK').catch(() => {});
    throw e;
  } finally { c.release(); }
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS owners (
  phone TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
  phone TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'new',   -- new | pending_docs | pending_inspection | approved | rejected
  name TEXT, email TEXT, agency TEXT, city TEXT,
  pan TEXT, aadhaar_masked TEXT,         -- the full Aadhaar number is never stored
  has_rera BOOLEAN NOT NULL DEFAULT FALSE,
  rera_no TEXT, rera_state TEXT,
  office_name TEXT, office_address TEXT, office_lat DOUBLE PRECISION, office_lng DOUBLE PRECISION,
  insp_date TEXT, insp_slot TEXT,
  pan_doc TEXT, aadhaar_doc TEXT, rera_doc TEXT, office_photo TEXT,   -- ids in the files table
  note TEXT NOT NULL DEFAULT '',
  submitted_at BIGINT, approved_at BIGINT,
  created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS properties (
  id TEXT PRIMARY KEY,
  owner_phone TEXT NOT NULL REFERENCES owners(phone),
  status TEXT NOT NULL DEFAULT 'active',  -- active | sold
  title TEXT NOT NULL, type TEXT NOT NULL, bhk TEXT, area DOUBLE PRECISION NOT NULL, extra TEXT, description TEXT,
  price DOUBLE PRECISION NOT NULL, nego TEXT NOT NULL,
  comm_type TEXT NOT NULL, comm_value DOUBLE PRECISION NOT NULL,
  address TEXT NOT NULL, locality TEXT NOT NULL, city TEXT NOT NULL, pincode TEXT NOT NULL,
  lat DOUBLE PRECISION NOT NULL, lng DOUBLE PRECISION NOT NULL,
  contact_name TEXT NOT NULL, contact_phone TEXT NOT NULL, contact_alt TEXT, contact_email TEXT, contact_time TEXT,
  photos TEXT NOT NULL DEFAULT '[]',      -- JSON array of ids in the files table
  created_at BIGINT NOT NULL, updated_at BIGINT,
  sold_at BIGINT, sold_to TEXT, sold_commission DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_prop_owner ON properties(owner_phone);
CREATE INDEX IF NOT EXISTS idx_prop_status ON properties(status, created_at);

CREATE TABLE IF NOT EXISTS leads (
  id TEXT PRIMARY KEY,
  property_id TEXT NOT NULL,              -- no FK: leads are kept (status 'removed') when a listing is deleted
  agent_phone TEXT NOT NULL REFERENCES agents(phone),
  owner_phone TEXT NOT NULL,
  note TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'interested',  -- interested | closed | lost | removed
  created_at BIGINT NOT NULL,
  UNIQUE (property_id, agent_phone)
);
CREATE INDEX IF NOT EXISTS idx_leads_owner ON leads(owner_phone);
CREATE INDEX IF NOT EXISTS idx_leads_agent ON leads(agent_phone);

CREATE TABLE IF NOT EXISTS otps (
  phone TEXT NOT NULL, role TEXT NOT NULL,
  code_hash TEXT NOT NULL, expires_at BIGINT NOT NULL,
  tries INTEGER NOT NULL DEFAULT 0, sent_at BIGINT NOT NULL,
  PRIMARY KEY (phone, role)
);

-- Uploaded images. kind 'photo' = listing photo (public by unguessable id), 'kyc' = agent document (admin only).
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  mime TEXT NOT NULL,
  data BYTEA NOT NULL,
  created_at BIGINT NOT NULL
);
`;

let ready = null;
/** Creates the tables on first use (safe to run repeatedly). */
export const ensureSchema = () => (ready ??= pool.query(SCHEMA).catch(e => { ready = null; throw e; }));
