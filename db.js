const { Pool } = require("pg");
const fs = require("fs");
const path = require("path");

const DB_HOST = process.env.DB_HOST || "localhost";
const DB_PORT = parseInt(process.env.DB_PORT || "5432", 10);
const DB_USER = process.env.DB_USER || "postgres";
const DB_PASS = process.env.DB_PASS || "";
const DB_NAME = process.env.DB_NAME || "certificate_app";

const DATA_DIR = process.env.DATA_DIR || __dirname;

const pool = new Pool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASS,
  database: DB_NAME,
  max: 10,
  idleTimeoutMillis: 30000,
});

const SCHEMA = `
CREATE TABLE IF NOT EXISTS certificates (
  hash VARCHAR(255) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  "rollNumber" VARCHAR(100) DEFAULT '',
  course VARCHAR(255) DEFAULT '',
  department VARCHAR(255) DEFAULT '',
  year VARCHAR(50) DEFAULT '',
  email VARCHAR(255) DEFAULT '',
  "ipfsHash" VARCHAR(255) DEFAULT '',
  "txHash" VARCHAR(255) DEFAULT '',
  timestamp TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS activity (
  id BIGSERIAL PRIMARY KEY,
  type VARCHAR(100) NOT NULL,
  details TEXT NULL,
  timestamp TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS brand (
  id INT PRIMARY KEY DEFAULT 1,
  name VARCHAR(255) NOT NULL DEFAULT 'XYZ University',
  "shortName" VARCHAR(50) DEFAULT 'XYZ',
  logo TEXT NULL
);

CREATE TABLE IF NOT EXISTS users (
  username VARCHAR(100) PRIMARY KEY,
  password VARCHAR(64) NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'admin',
  "createdAt" TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS results (
  id VARCHAR(64) PRIMARY KEY,
  "rollNumber" VARCHAR(100) NOT NULL,
  name VARCHAR(255) DEFAULT '',
  department VARCHAR(255) DEFAULT '',
  semester VARCHAR(100) DEFAULT '',
  subjects JSONB NULL,
  timestamp TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS departments (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS issues (
  id BIGSERIAL PRIMARY KEY,
  "rollNumber" VARCHAR(100) DEFAULT '',
  semester VARCHAR(100) DEFAULT '',
  message TEXT NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'open',
  timestamp TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS app_sessions (
  token VARCHAR(64) PRIMARY KEY,
  username VARCHAR(100) NOT NULL,
  expires BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
  key VARCHAR(100) PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS monitor_apps (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  app_key VARCHAR(100) UNIQUE NOT NULL,
  url TEXT NOT NULL,
  type VARCHAR(50) DEFAULT 'web',
  department VARCHAR(255) DEFAULT '',
  notes TEXT DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  ropa_status VARCHAR(20) NOT NULL DEFAULT 'not_started',
  ropa_owner VARCHAR(100) DEFAULT '',
  ropa_notes TEXT DEFAULT '',
  ropa_updated_at TIMESTAMPTZ NULL,
  dpia_status VARCHAR(20) NOT NULL DEFAULT 'not_started',
  dpia_owner VARCHAR(100) DEFAULT '',
  dpia_notes TEXT DEFAULT '',
  dpia_updated_at TIMESTAMPTZ NULL,
  dpdp_status VARCHAR(20) NOT NULL DEFAULT 'not_started',
  dpdp_owner VARCHAR(100) DEFAULT '',
  dpdp_notes TEXT DEFAULT '',
  dpdp_updated_at TIMESTAMPTZ NULL,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS monitor_checks (
  id BIGSERIAL PRIMARY KEY,
  app_id BIGINT NOT NULL REFERENCES monitor_apps(id) ON DELETE CASCADE,
  status_code INT,
  latency_ms INT,
  online BOOLEAN NOT NULL DEFAULT FALSE,
  checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_checks_app_time ON monitor_checks(app_id, checked_at DESC);

CREATE TABLE IF NOT EXISTS monitor_events (
  id BIGSERIAL PRIMARY KEY,
  app_id BIGINT REFERENCES monitor_apps(id) ON DELETE SET NULL,
  app_key VARCHAR(100) DEFAULT '',
  type VARCHAR(100) NOT NULL,
  severity VARCHAR(20) NOT NULL DEFAULT 'info',
  message TEXT NOT NULL,
  username VARCHAR(255) DEFAULT '',
  ip VARCHAR(64) DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_events_time ON monitor_events(created_at DESC);

CREATE TABLE IF NOT EXISTS dpia_assessments (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  description TEXT DEFAULT '',
  business_unit VARCHAR(255) DEFAULT '',
  status VARCHAR(30) NOT NULL DEFAULT 'draft',
  risk_level VARCHAR(20) NOT NULL DEFAULT 'medium',
  data_categories JSONB NOT NULL DEFAULT '[]',
  third_party BOOLEAN NOT NULL DEFAULT false,
  third_party_name VARCHAR(255) DEFAULT '',
  start_date TIMESTAMPTZ NULL,
  due_date TIMESTAMPTZ NULL,
  completed_at TIMESTAMPTZ NULL,
  risks JSONB NOT NULL DEFAULT '[]',
  "createdAt" TIMESTAMPTZ NULL,
  "updatedAt" TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS dpia_risks (
  id BIGSERIAL PRIMARY KEY,
  assessment_id BIGINT NOT NULL REFERENCES dpia_assessments(id) ON DELETE CASCADE,
  description TEXT NOT NULL,
  likelihood VARCHAR(20) NOT NULL DEFAULT 'medium',
  impact VARCHAR(20) NOT NULL DEFAULT 'medium',
  risk_level VARCHAR(20) NOT NULL DEFAULT 'medium',
  status VARCHAR(30) NOT NULL DEFAULT 'open',
  remediation TEXT DEFAULT '',
  due_date TIMESTAMPTZ NULL,
  resolved_at TIMESTAMPTZ NULL,
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_dpia_risks_assessment ON dpia_risks(assessment_id);

CREATE TABLE IF NOT EXISTS dpia_workflow_config (
  id INT PRIMARY KEY DEFAULT 1,
  stages JSONB NOT NULL DEFAULT '[]',
  transitions JSONB NOT NULL DEFAULT '[]',
  "updatedAt" TIMESTAMPTZ NULL,
  "updatedBy" VARCHAR(100) DEFAULT ''
);

CREATE TABLE IF NOT EXISTS dpia_audit_log (
  id BIGSERIAL PRIMARY KEY,
  assessment_id BIGINT NOT NULL REFERENCES dpia_assessments(id) ON DELETE CASCADE,
  action VARCHAR(50) NOT NULL,
  from_stage VARCHAR(50) DEFAULT '',
  to_stage VARCHAR(50) DEFAULT '',
  username VARCHAR(100) DEFAULT '',
  comment TEXT DEFAULT '',
  meta JSONB NOT NULL DEFAULT '{}',
  "createdAt" TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_dpia_audit_assessment ON dpia_audit_log(assessment_id, id);
`;

async function ensureDatabase() {
  const adminPool = new Pool({
    host: DB_HOST,
    port: DB_PORT,
    user: DB_USER,
    password: DB_PASS,
    database: "postgres",
    max: 1,
  });
  try {
    const { rows } = await adminPool.query("SELECT 1 FROM pg_database WHERE datname = $1", [DB_NAME]);
    if (rows.length === 0) {
      await adminPool.query(`CREATE DATABASE ${DB_NAME}`);
      console.log(`Database '${DB_NAME}' created`);
    }
  } finally {
    await adminPool.end();
  }
  await pool.query(SCHEMA);
  await pool.query(
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '[]'::jsonb`
  );
  await pool.query(
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS departments JSONB NOT NULL DEFAULT '[]'::jsonb`
  );
  await pool.query(`ALTER TABLE users ALTER COLUMN password TYPE TEXT`);
  await pool.query(`ALTER TABLE results ADD COLUMN IF NOT EXISTS aadhaar VARCHAR(12) DEFAULT ''`);
  await pool.query(`ALTER TABLE results ADD COLUMN IF NOT EXISTS mobile VARCHAR(15) DEFAULT ''`);
  await pool.query(`ALTER TABLE monitor_apps ADD COLUMN IF NOT EXISTS ropa_status VARCHAR(20) NOT NULL DEFAULT 'not_started'`);
  await pool.query(`ALTER TABLE monitor_apps ADD COLUMN IF NOT EXISTS ropa_owner VARCHAR(100) DEFAULT ''`);
  await pool.query(`ALTER TABLE monitor_apps ADD COLUMN IF NOT EXISTS ropa_notes TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE monitor_apps ADD COLUMN IF NOT EXISTS ropa_updated_at TIMESTAMPTZ NULL`);
  await pool.query(`ALTER TABLE monitor_apps ADD COLUMN IF NOT EXISTS dpia_status VARCHAR(20) NOT NULL DEFAULT 'not_started'`);
  await pool.query(`ALTER TABLE monitor_apps ADD COLUMN IF NOT EXISTS dpia_owner VARCHAR(100) DEFAULT ''`);
  await pool.query(`ALTER TABLE monitor_apps ADD COLUMN IF NOT EXISTS dpia_notes TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE monitor_apps ADD COLUMN IF NOT EXISTS dpia_updated_at TIMESTAMPTZ NULL`);
  await pool.query(`ALTER TABLE monitor_apps ADD COLUMN IF NOT EXISTS dpdp_status VARCHAR(20) NOT NULL DEFAULT 'not_started'`);
  await pool.query(`ALTER TABLE monitor_apps ADD COLUMN IF NOT EXISTS dpdp_owner VARCHAR(100) DEFAULT ''`);
  await pool.query(`ALTER TABLE monitor_apps ADD COLUMN IF NOT EXISTS dpdp_notes TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE monitor_apps ADD COLUMN IF NOT EXISTS dpdp_updated_at TIMESTAMPTZ NULL`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_monitor_apps_ropa ON monitor_apps(ropa_status)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_monitor_apps_dpia ON monitor_apps(dpia_status)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_monitor_apps_dpdp ON monitor_apps(dpdp_status)`);
  await pool.query(`ALTER TABLE dpia_assessments ADD COLUMN IF NOT EXISTS stage VARCHAR(50) NOT NULL DEFAULT 'draft'`);
  await pool.query(
    `UPDATE dpia_assessments
        SET stage = CASE
              WHEN status = 'completed'  THEN 'active'
              WHEN status = 'in_progress' THEN 'assessment'
              WHEN status = 'on_hold'     THEN 'review'
              ELSE 'draft'
            END
      WHERE status != 'draft' AND status != '' AND stage = 'draft'`
  );
}

function toDate(v) {
  if (!v) return null;
  const d = new Date(v);
  return isNaN(d.getTime()) ? null : d;
}

async function migrateFromJson() {
  const read = (file, fallback) => {
    try {
      const p = path.join(DATA_DIR, file);
      if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf8"));
    } catch (e) {
      console.error(`Error reading ${file}:`, e.message);
    }
    return fallback;
  };

  const { rows: [{ c }] } = await pool.query("SELECT COUNT(*)::int AS c FROM certificates");
  if (c === 0) {
    const certs = read("certificates.json", {});
    for (const [hash, d] of Object.entries(certs)) {
      await pool.query(
        `INSERT INTO certificates (hash, name, "rollNumber", course, department, year, email, "ipfsHash", "txHash", timestamp)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (hash) DO NOTHING`,
        [hash, d.name, d.rollNumber || "", d.course || "", d.department || "", d.year || "", d.email || "", d.ipfsHash, d.txHash || "", toDate(d.timestamp)]
      );
    }
    if (Object.keys(certs).length) console.log(`Migrated ${Object.keys(certs).length} certificates`);
  }

  const { rows: [{ c: ac }] } = await pool.query("SELECT COUNT(*)::int AS c FROM activity");
  if (ac === 0) {
    const log = read("activity.json", []);
    for (const e of log) {
      await pool.query(
        "INSERT INTO activity (type, details, timestamp) VALUES ($1, $2, $3)",
        [e.type, JSON.stringify(e.details || {}), toDate(e.timestamp)]
      );
    }
    if (log.length) console.log(`Migrated ${log.length} activity entries`);
  }

  const { rows: [{ c: bc }] } = await pool.query("SELECT COUNT(*)::int AS c FROM brand");
  if (bc === 0) {
    const brand = read("brand.json", {});
    await pool.query(
      `INSERT INTO brand (id, name, "shortName", logo) VALUES (1, $1, $2, $3)
       ON CONFLICT (id) DO UPDATE SET id = 1`,
      [brand.name || "XYZ University", brand.shortName || "XYZ", brand.logo || null]
    );
  }

  const { rows: [{ c: uc }] } = await pool.query("SELECT COUNT(*)::int AS c FROM users");
  if (uc === 0) {
    const users = read("users.json", {});
    for (const [username, u] of Object.entries(users)) {
      await pool.query(
        `INSERT INTO users (username, password, role, "createdAt") VALUES ($1, $2, $3, $4)
         ON CONFLICT (username) DO NOTHING`,
        [username, u.password, u.role || "admin", toDate(u.createdAt)]
      );
    }
    if (Object.keys(users).length) console.log(`Migrated ${Object.keys(users).length} users`);
  }

  const { rows: [{ c: rc }] } = await pool.query("SELECT COUNT(*)::int AS c FROM results");
  if (rc === 0) {
    const results = read("results.json", []);
    for (const r of results) {
      await pool.query(
        `INSERT INTO results (id, "rollNumber", name, department, semester, subjects, timestamp) VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (id) DO NOTHING`,
        [r.id, r.rollNumber, r.name, r.department, r.semester, JSON.stringify(r.subjects || []), toDate(r.timestamp)]
      );
    }
    if (results.length) console.log(`Migrated ${results.length} results`);
  }

  const { rows: [{ c: dc }] } = await pool.query("SELECT COUNT(*)::int AS c FROM departments");
  if (dc === 0) {
    const deps = read("departments.json", []);
    for (const name of deps) {
      await pool.query("INSERT INTO departments (name) VALUES ($1) ON CONFLICT (name) DO NOTHING", [name]);
    }
    if (deps.length) console.log(`Migrated ${deps.length} departments`);
  }
}

async function init() {
  await ensureDatabase();
  await migrateFromJson();
}

module.exports = { pool, init };
