const express = require("express");
const multer = require("multer");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const XLSX = require("xlsx");
const { ethers } = require("ethers");
const { pool, init } = require("./db");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));
const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || "0.0.0.0";
const upload = multer({ storage: multer.memoryStorage() });

const MONITOR_AGENT_TOKEN = process.env.MONITOR_AGENT_TOKEN || "";
const MONITOR_APP_KEY = process.env.MONITOR_APP_KEY || "certificate-portal";
const MONITOR_POLL_INTERVAL = parseInt(process.env.MONITOR_POLL_INTERVAL || "30", 10) * 1000;
const MONITOR_CHECK_TIMEOUT = parseInt(process.env.MONITOR_CHECK_TIMEOUT || "5000", 10);

async function insertMonitorEvent({ appKey, type, severity, message, username, ip }) {
  let appId = null;
  if (appKey) {
    const { rows } = await pool.query("SELECT id, name FROM monitor_apps WHERE app_key = $1", [appKey]).catch(() => ({ rows: [] }));
    appId = rows.length ? rows[0].id : null;
  }
  const allowedSev = ["info", "low", "medium", "high", "critical"];
  const sev = allowedSev.includes(severity) ? severity : "info";
  try {
    await pool.query(
      `INSERT INTO monitor_events (app_id, app_key, type, severity, message, username, ip)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [appId, String(appKey || "").slice(0, 100), String(type || "security").slice(0, 100), sev,
       String(message || "").slice(0, 1000), String(username || "").slice(0, 255), String(ip || "").slice(0, 64)]
    );
  } catch (e) {
    console.error("Monitor event insert failed:", e.message);
  }
}

function reportEvent(type, severity, message, username, ip) {
  insertMonitorEvent({ appKey: MONITOR_APP_KEY, type, severity, message, username, ip });
}

const MONITOR_SEVERITY = {
  CERTIFICATE_DELETED: "medium",
  RESULT_DELETED: "medium",
  USER_DELETED: "high",
  USER_UPDATED: "medium",
  USER_CREATED: "low",
  BRAND_UPDATED: "low",
  ISSUE_DELETED: "medium",
  DPIA_APPROVED: "high",
  DPIA_REJECTED: "high",
  DPIA_CREATED: "low",
  DPIA_UPDATED: "low",
  DPIA_DELETED: "high",
  DPIA_STAGE_CHANGED: "medium",
  DPIA_RISK_UPDATED: "medium",
};

const PINATA_JWT = process.env.PINATA_JWT || "";

const SEPOLIA_RPC = process.env.SEPOLIA_RPC_URL;
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;
const ADMIN_KEY = process.env.ADMIN_PRIVATE_KEY;

const provider = new ethers.JsonRpcProvider(SEPOLIA_RPC);
const wallet = new ethers.Wallet(ADMIN_KEY, provider);

const contractABI = [
  {
    inputs: [
      { name: "_hash", type: "string" },
      { name: "_name", type: "string" },
      { name: "_ipfs", type: "string" }
    ],
    name: "addCertificate",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function"
  }
];
const contract = new ethers.Contract(CONTRACT_ADDRESS, contractABI, wallet);

const ADMIN_USER = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASS = process.env.ADMIN_PASSWORD || "admin123";

const DEFAULT_BRAND = {
  name: "XYZ University",
  shortName: "XYZ",
  logo: null
};

const CERT_COLS = `hash, name, "rollNumber", course, department, year, email, "ipfsHash", "txHash", timestamp`;

function hashPass(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(String(pw), salt, 64).toString("hex");
  return `scrypt$${salt}$${hash}`;
}

function verifyPass(stored, pw) {
  if (typeof stored === "string" && stored.startsWith("scrypt$")) {
    const [, salt, hash] = stored.split("$");
    if (!salt || !hash) return false;
    const candidate = crypto.scryptSync(String(pw), salt, 64);
    const expected = Buffer.from(hash, "hex");
    return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
  }
  const legacy = crypto.createHash("sha256").update(String(pw)).digest("hex");
  if (typeof stored !== "string" || stored.length !== legacy.length) return false;
  return crypto.timingSafeEqual(Buffer.from(legacy), Buffer.from(stored));
}

function parseJson(v, fallback) {
  if (v == null) return fallback;
  if (typeof v === "object") return v;
  try {
    return JSON.parse(v);
  } catch (e) {
    return fallback;
  }
}

function normalizeSemester(v) {
  const s = String(v || "").trim();
  if (!s) return s;
  const m = s.match(/(\d+)/);
  if (m) {
    const n = parseInt(m[1], 10);
    if (!/sem/i.test(s)) return `Sem ${n}`;
  }
  return s;
}

const ACTIVITY_SEVERITY = MONITOR_SEVERITY;

function summarizeAction(type, details) {
  const d = details || {};
  switch (type) {
    case "CERTIFICATE_ISSUED": return `Certificate issued for ${d.name || "?"} (${d.rollNumber || "no roll"})${d.onChain ? " · on-chain" : ""}`;
    case "CERTIFICATE_DELETED": return `Certificate deleted: ${d.name || d.hash}`;
    case "CERTIFICATE_BULK_ISSUED": return `Bulk issued ${d.count} certificate(s)`;
    case "RESULT_DELETED": return d.department ? `Results deleted for department ${d.department}` : `Result deleted for ${d.rollNumber || "?"} ${d.semester || ""}`;
    case "RESULT_BULK_ADDED": return `Bulk result upload: ${d.added} added, ${d.updated} updated`;
    case "RESULT_ADDED": return `Result added: ${d.rollNumber} ${d.semester || ""}`;
    case "RESULT_UPDATED": return `Result updated: ${d.rollNumber} ${d.semester || ""}`;
    case "RESULT_OTP_SENT": return `Result OTP sent to roll ${d.rollNumber}`;
    case "BRAND_UPDATED": return `University branding changed to "${d.name || "?"}"`;
    case "USER_CREATED": return `User created: ${d.user} (${d.role || "user"})`;
    case "USER_UPDATED": return `User modified: ${d.user}`;
    case "USER_DELETED": return `User deleted: ${d.user}`;
    case "ISSUE_RAISED": return `Issues raised for ${d.rollNumber || "?"} ${d.semester || ""}`;
    case "ISSUE_UPDATED": return `Issue #${d.id} marked ${d.status}`;
    case "ISSUE_DELETED": return `Issue #${d.id} deleted`;
    case "ADMIN_LOGIN": return `Admin login: ${d.user}`;
    case "DPIA_CREATED": return `DPIA created: ${d.title || "?"}`;
    case "DPIA_UPDATED": return `DPIA updated: ${d.title || "?"}`;
    case "DPIA_DELETED": return `DPIA deleted: ${d.title || "?"}`;
    case "DPIA_STAGE_CHANGED": return `DPIA "${d.title || "?"}" moved ${d.from || "?"} → ${d.to || "?"}`;
    case "DPIA_APPROVED": return `DPIA "${d.title || "?"}" approved (${d.to || "active"})`;
    case "DPIA_REJECTED": return `DPIA "${d.title || "?"}" rejected → ${d.to || "?"}`;
    case "DPIA_RISK_UPDATED": return `DPIA risk ${d.detail || "updated"} (${d.id || "?"})`;
    default: return `${type}${d.name ? ": " + d.name : ""}${d.user ? " · " + d.user : ""}`;
  }
}

async function logActivity(type, details) {
  const actor = (details && details.user) || "";
  reportEvent(type.toLowerCase().replace(/_/g, "_"), ACTIVITY_SEVERITY[type] || "info", summarizeAction(type, details), actor);
  await pool.query(
    "INSERT INTO activity (type, details, timestamp) VALUES ($1, $2, $3)",
    [type, JSON.stringify(details || {}), new Date()]
  );
}

const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

async function createSession(username) {
  const token = crypto.randomBytes(32).toString("hex");
  const expires = Date.now() + SESSION_TTL_MS;
  await pool.query("DELETE FROM app_sessions WHERE expires < $1", [Date.now()]);
  await pool.query("INSERT INTO app_sessions (token, username, expires) VALUES ($1, $2, $3)", [token, username, expires]);
  return token;
}

async function getUsernameFromReq(req) {
  const token = req.get("x-auth-token");
  if (!token) return null;
  const { rows } = await pool.query("SELECT username, expires FROM app_sessions WHERE token = $1", [token]);
  const s = rows[0];
  if (!s || s.expires < Date.now()) {
    await pool.query("DELETE FROM app_sessions WHERE token = $1", [token]).catch(() => {});
    return null;
  }
  const expires = Date.now() + SESSION_TTL_MS;
  await pool.query("UPDATE app_sessions SET expires = $1 WHERE token = $2", [expires, token]).catch(() => {});
  return s.username;
}

async function isAdminRequest(req) {
  const uname = await getUsernameFromReq(req);
  if (!uname) return false;
  const { rows } = await pool.query("SELECT * FROM users WHERE username = $1 AND role = 'admin'", [uname]);
  return rows.length > 0;
}

async function requireAdmin(req, res, next) {
  if (await isAdminRequest(req)) return next();
  return res.status(403).json({ error: "Admin access required" });
}

function parsePerms(v) {
  const arr = typeof v === "string" ? parseJson(v, []) : v;
  return Array.isArray(arr) ? arr.map(String) : [];
}

const parseDepts = parsePerms;

const ROLE_KEYS = ["admin", "user", "department-head", "privacy-manager", "cybersecurity", "hr", "legal"];

function normalizeRole(role) {
  if (role === "admin") return "admin";
  return ROLE_KEYS.includes(role) ? String(role) : "user";
}

async function hasPerm(req, perm) {
  const uname = await getUsernameFromReq(req);
  if (!uname) return false;
  const { rows } = await pool.query("SELECT role, permissions FROM users WHERE username = $1", [uname]);
  if (rows.length === 0) return false;
  if ((rows[0].role || "user") === "admin") return true;
  return parsePerms(rows[0].permissions).includes(perm);
}

const requirePerm = (perm) => async (req, res, next) => {
  if (await hasPerm(req, perm)) return next();
  return res.status(403).json({ error: "Permission denied" });
};

async function getDeptScope(req) {
  const uname = await getUsernameFromReq(req);
  if (!uname) return { restricted: true, depts: [] };
  const { rows } = await pool.query("SELECT role, departments FROM users WHERE username = $1", [uname]);
  if (rows.length === 0) return { restricted: true, depts: [] };
  if ((rows[0].role || "user") === "admin") return { restricted: false, depts: [] };
  const depts = parseDepts(rows[0].departments);
  return { restricted: depts.length > 0, depts };
}

function deptAllowed(scope, department) {
  return !scope.restricted || scope.depts.includes(department);
}

// ---------- Student result verification (Aadhaar + OTP) ----------
const OTP_TTL_MS = 5 * 60 * 1000;
const otpStore = new Map(); // rollKey -> { hash, expires, attempts, lastRequest }
const resultAccessTokens = new Map(); // token -> { rollKey, expires }
const RESULT_TOKEN_TTL_MS = 15 * 60 * 1000;

const digitsOnly = (v) => String(v || "").replace(/\D/g, "");
const maskMobile = (m) => (m && m.length >= 4 ? "XXXXXXX" + m.slice(-4) : "your registered mobile");

async function sendSms(mobile, message) {
  const cfg = await getSmsConfig();
  if (!cfg.provider || cfg.provider === "none" || !cfg.apiKey || !mobile) return { demo: true };
  try {
    let ok = false;
    if (cfg.provider === "fast2sms") {
      const res = await fetch("https://www.fast2sms.com/dev/bulkV2", {
        method: "POST",
        headers: { authorization: cfg.apiKey, "Content-Type": "application/json" },
        body: JSON.stringify({ route: "otp", variables_values: message, numbers: mobile })
      });
      const data = await res.json();
      ok = data.return === true;
      if (!ok) console.error("Fast2SMS error:", JSON.stringify(data).slice(0, 200));
    } else if (cfg.provider === "msg91") {
      const params = new URLSearchParams({ mobile: `91${mobile}`, template_id: cfg.templateId || "", OTP: message });
      const res = await fetch(`https://control.msg91.com/api/v5/flow/?${params.toString()}`, {
        method: "POST",
        headers: { authkey: cfg.apiKey }
      });
      const data = await res.json();
      ok = data.type === "success";
      if (!ok) console.error("MSG91 error:", JSON.stringify(data).slice(0, 200));
    } else if (cfg.provider === "textlocal") {
      const params = new URLSearchParams({
        apikey: cfg.apiKey, numbers: mobile, message,
        sender: cfg.senderId || "TXTLCL"
      });
      const res = await fetch("https://api.textlocal.in/send/", { method: "POST", body: params });
      const data = await res.json();
      ok = data.status === "success";
      if (!ok) console.error("TextLocal error:", JSON.stringify(data).slice(0, 200));
    } else if (cfg.provider === "android") {
      const base = (cfg.baseUrl || "").trim();
      if (!base || !cfg.apiKey) {
        console.error("Android gateway not fully configured (need base URL + password)");
      } else {
        const username = cfg.senderId || "admin";
        const auth = Buffer.from(`${username}:${cfg.apiKey}`).toString("base64");
        const phone = mobile.length === 10 ? `+91${mobile}` : `+${mobile}`;
        const res = await fetch(`${base}/message`, {
          method: "POST",
          headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/json" },
          body: JSON.stringify({ textMessage: { text: message }, phoneNumbers: [phone] })
        });
        ok = res.status === 200 || res.status === 201;
        if (!ok) console.error("Android gateway error:", res.status, (await res.text()).slice(0, 150));
      }
    }
    return { demo: false, ok };
  } catch (e) {
    console.error("SMS send failed:", e.message);
    return { demo: false, ok: false };
  }
}

async function getSmsConfig() {
  try {
    const { rows } = await pool.query("SELECT key, value FROM app_settings WHERE key LIKE 'sms_%'");
    const map = Object.fromEntries(rows.map(r => [r.key, r.value]));
    return {
      provider: map.sms_provider || (process.env.SMS_PROVIDER || ""),
      apiKey: map.sms_api_key || process.env.SMS_API_KEY || "",
      senderId: map.sms_sender_id || "",
      templateId: map.sms_template_id || "",
      baseUrl: map.sms_base_url || process.env.SMS_BASE_URL || ""
    };
  } catch {
    return { provider: "", apiKey: process.env.SMS_API_KEY || "", senderId: "", templateId: "", baseUrl: "" };
  }
}

app.get("/api/settings/sms", requireAdmin, async (req, res) => {
  const cfg = await getSmsConfig();
  res.json({
    provider: cfg.provider || "none",
    keyMasked: cfg.apiKey ? cfg.apiKey.slice(0, 4) + "*".repeat(Math.max(4, cfg.apiKey.length - 8)) + cfg.apiKey.slice(-4) : "",
    configured: !!cfg.apiKey && cfg.provider !== "none",
    senderId: cfg.senderId, templateId: cfg.templateId, baseUrl: cfg.baseUrl
  });
});

app.put("/api/settings/sms", requireAdmin, async (req, res) => {
  const { provider, apiKey, senderId, templateId, baseUrl } = req.body || {};
  const allowed = ["none", "fast2sms", "msg91", "textlocal", "android"];
  if (!allowed.includes(provider)) return res.status(400).json({ error: "Invalid provider" });
  const entries = [["sms_provider", provider], ["sms_sender_id", String(senderId || "").trim()], ["sms_template_id", String(templateId || "").trim()], ["sms_base_url", String(baseUrl || "").trim().replace(/\/+$/, "")]];
  if (apiKey && !apiKey.includes("*")) entries.push(["sms_api_key", String(apiKey).trim()]);
  for (const [key, value] of entries) {
    await pool.query("INSERT INTO app_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2", [key, value]);
  }
  res.json({ success: true });
});

app.post("/api/settings/sms/test", requireAdmin, async (req, res) => {
  const mobile = digitsOnly(req.body?.mobile);
  if (mobile.length < 10) return res.status(400).json({ error: "Enter a valid 10-digit mobile number" });
  const otp = String(crypto.randomInt(100000, 999999));
  const sent = await sendSms(mobile, otp);
  if (sent.demo) return res.json({ success: true, demo: true, demoOtp: otp, note: "No gateway configured — running in demo mode" });
  if (!sent.ok) return res.status(502).json({ error: "Gateway rejected the message. Check your API key / sender details." });
  res.json({ success: true, note: "Test SMS sent successfully" });
});

app.post("/api/results/otp/request", async (req, res) => {
  const { rollNumber, aadhaar } = req.body || {};
  const roll = String(rollNumber || "").trim().toLowerCase();
  const aad = digitsOnly(aadhaar);
  if (!roll) return res.status(400).json({ error: "Roll Number is required" });
  if (aad.length !== 12) return res.status(400).json({ error: "Enter a valid 12-digit Aadhaar number" });

  const now = Date.now();
  const prev = otpStore.get(roll);
  if (prev && now - prev.lastRequest < 30 * 1000) {
    return res.status(429).json({ error: "Please wait 30 seconds before requesting another OTP" });
  }

  const { rows } = await pool.query(
    'SELECT aadhaar, mobile FROM results WHERE LOWER("rollNumber") = $1 ORDER BY timestamp DESC LIMIT 1',
    [roll]
  );
  if (rows.length === 0) return res.status(404).json({ error: "No student found with this roll number" });
  const storedAad = digitsOnly(rows[0].aadhaar);
  if (!storedAad) return res.status(400).json({ error: "Aadhaar is not registered for this student. Contact the university office." });
  if (storedAad !== aad) return res.status(401).json({ error: "Aadhaar number does not match our records" });

  const otp = String(crypto.randomInt(100000, 999999));
  otpStore.set(roll, { hash: crypto.createHash("sha256").update(otp).digest("hex"), expires: now + OTP_TTL_MS, attempts: 0, lastRequest: now });

  const mobile = digitsOnly(rows[0].mobile);
  if (!mobile) return res.status(400).json({ error: "No mobile number is registered for this student. Contact the university office." });
  const sent = await sendSms(mobile, otp);
  if (!sent.demo && !sent.ok) {
    console.error(`SMS gateway failed for ${roll}; falling back to on-screen OTP`);
    logActivity("RESULT_OTP_SENT", { rollNumber: roll }).catch(() => {});
    return res.json({
      success: true,
      maskedMobile: maskMobile(mobile),
      demoOtp: otp,
      note: "SMS delivery is temporarily unavailable — OTP shown on screen instead."
    });
  }

  logActivity("RESULT_OTP_SENT", { rollNumber: roll }).catch(() => {});
  res.json({ success: true, maskedMobile: maskMobile(mobile), demoOtp: sent.demo ? otp : undefined });
});

app.post("/api/results/otp/verify", async (req, res) => {
  const { rollNumber, otp } = req.body || {};
  const roll = String(rollNumber || "").trim().toLowerCase();
  const rec = otpStore.get(roll);
  if (!rec) return res.status(400).json({ error: "Request an OTP first" });
  if (Date.now() > rec.expires) { otpStore.delete(roll); return res.status(401).json({ error: "OTP expired. Request a new one." }); }
  if (rec.attempts >= 5) { otpStore.delete(roll); return res.status(429).json({ error: "Too many wrong attempts. Request a new OTP." }); }
  const hash = crypto.createHash("sha256").update(String(otp || "").trim()).digest("hex");
  if (hash !== rec.hash) {
    rec.attempts += 1;
    return res.status(401).json({ error: `Incorrect OTP (${5 - rec.attempts} attempts left)` });
  }
  otpStore.delete(roll);
  const token = crypto.randomBytes(24).toString("hex");
  resultAccessTokens.set(token, { rollKey: roll, expires: Date.now() + RESULT_TOKEN_TTL_MS });
  res.json({ success: true, resultToken: token });
});

async function ensureDefaultAdmin() {
  const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [ADMIN_USER]);
  if (rows.length === 0) {
    await pool.query(
      `INSERT INTO users (username, password, role, "createdAt") VALUES ($1, $2, $3, $4)
       ON CONFLICT (username) DO NOTHING`,
      [ADMIN_USER, hashPass(ADMIN_PASS), "admin", new Date()]
    );
    console.log(`Default admin '${ADMIN_USER}' created`);
  }
}

async function listCertificates() {
  const { rows } = await pool.query(`SELECT ${CERT_COLS} FROM certificates ORDER BY timestamp DESC`);
  return rows;
}

app.post("/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).send("No file uploaded");
    const blob = new Blob([req.file.buffer], { type: req.file.mimetype });
    const formData = new FormData();
    formData.append("file", blob, req.file.originalname);
    formData.append("network", "public");
    const response = await fetch("https://uploads.pinata.cloud/v3/files", {
      method: "POST",
      headers: { Authorization: `Bearer ${PINATA_JWT}` },
      body: formData,
    });
    const data = await response.json();
    console.log("Pinata response:", data);
    res.json(data);
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).send("Upload failed");
  }
});

app.post("/api/certificates", async (req, res) => {
  const { hash, name, rollNumber, course, department, year, email, ipfsHash, txHash } = req.body;
  if (!hash || !name || !ipfsHash) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  await pool.query(
    `INSERT INTO certificates (${CERT_COLS})
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
     ON CONFLICT (hash) DO UPDATE SET
       name = EXCLUDED.name, "rollNumber" = EXCLUDED."rollNumber", course = EXCLUDED.course,
       department = EXCLUDED.department, year = EXCLUDED.year, email = EXCLUDED.email,
       "ipfsHash" = EXCLUDED."ipfsHash", "txHash" = EXCLUDED."txHash"`,
    [hash, name, rollNumber || "", course || "", department || "", year || "", email || "", ipfsHash, txHash || "", new Date()]
  );
  console.log("Certificate stored:", hash);
  await logActivity("CERTIFICATE_ISSUED", { hash, name, rollNumber: rollNumber || "", course: course || "", email: email || "", onChain: !!txHash });
  res.json({ success: true });
});

app.get("/api/search", async (req, res) => {
  const q = (req.query.q || "").toLowerCase().trim();
  if (!q) return res.json([]);
  const like = `%${q}%`;
  const { rows } = await pool.query(
    `SELECT ${CERT_COLS} FROM certificates
     WHERE LOWER(hash) LIKE $1 OR LOWER(name) LIKE $2 OR LOWER("rollNumber") LIKE $3 OR LOWER(email) LIKE $4`,
    [like, like, like, like]
  );
  res.json(rows);
});

app.get("/api/verify/:hash", async (req, res) => {
  const hash = req.params.hash.toLowerCase();
  const { rows } = await pool.query('SELECT hash, "ipfsHash" FROM certificates WHERE LOWER(hash) = $1', [hash]);
  res.json(rows.length ? { valid: true, hash, ipfsHash: rows[0].ipfsHash || "" } : { valid: false });
});

app.get("/api/certificates", async (req, res) => {
  res.json(await listCertificates());
});

app.delete("/api/certificates/:hash", requireAdmin, async (req, res) => {
  const hash = req.params.hash.toLowerCase();
  const { rows } = await pool.query("SELECT * FROM certificates WHERE LOWER(hash) = $1", [hash]);
  const existing = rows[0];
  if (!existing) {
    return res.status(404).json({ error: "Certificate not found" });
  }
  await pool.query("DELETE FROM certificates WHERE LOWER(hash) = $1", [hash]);
  console.log("Certificate deleted:", hash);
  await logActivity("CERTIFICATE_DELETED", { hash, name: existing.name || "", rollNumber: existing.rollNumber || "" });
  res.json({ success: true });
});

app.delete("/api/activity", requireAdmin, async (req, res) => {
  await pool.query("DELETE FROM activity");
  console.log("Activity log cleared");
  res.json({ success: true });
});

app.get("/api/certificates/download", async (req, res) => {
  const certs = await listCertificates();
  const data = certs.map(d => ({
    Name: d.name,
    "Roll Number": d.rollNumber || "",
    Course: d.course || "",
    Department: d.department || "",
    Year: d.year || "",
    Email: d.email || "",
    Hash: d.hash,
    "IPFS CID": d.ipfsHash,
    "Transaction Hash": d.txHash || "",
    Timestamp: d.timestamp ? new Date(d.timestamp).toISOString() : ""
  }));
  if (req.query.format === "xlsx") {
    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.json_to_sheet(data);
    XLSX.utils.book_append_sheet(wb, ws, "Certificates");
    const buf = XLSX.write(wb, { type: "buffer", bookType: "xlsx" });
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.setHeader("Content-Disposition", "attachment; filename=certificates.xlsx");
    res.send(buf);
  } else {
    const header = "Name,Roll Number,Course,Department,Year,Email,Hash,IPFS CID,Transaction Hash,Timestamp\n";
    const rows = data.map(d =>
      `"${d.Name}","${d["Roll Number"]}","${d.Course}","${d.Department}","${d.Year}","${d.Email}","${d.Hash}","${d["IPFS CID"]}","${d["Transaction Hash"]}","${d.Timestamp}"`
    ).join("\n");
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", "attachment; filename=certificates.csv");
    res.send(header + rows);
  }
});

app.get("/api/dashboard/stats", async (req, res) => {
  const [{ total }] = (await pool.query("SELECT COUNT(*)::int AS total FROM certificates")).rows;
  const [{ today }] = (await pool.query("SELECT COUNT(*)::int AS today FROM certificates WHERE timestamp::date = CURRENT_DATE")).rows;
  const { rows: recent } = await pool.query(`SELECT ${CERT_COLS} FROM certificates ORDER BY timestamp DESC LIMIT 5`);
  res.json({ total, today, recent });
});

app.get("/api/dashboard/analytics", async (req, res) => {
  const [{ totalDepartments }] = (await pool.query("SELECT COUNT(*)::int AS \"totalDepartments\" FROM departments")).rows;
  const [{ totalResults }] = (await pool.query("SELECT COUNT(*)::int AS \"totalResults\" FROM results")).rows;
  const { rows: byDepartment } = await pool.query(
    "SELECT COALESCE(NULLIF(department, ''), 'Unknown') AS department, COUNT(*)::int AS count FROM results GROUP BY department ORDER BY count DESC"
  );
  const { rows: rawBySemester } = await pool.query(
    "SELECT semester FROM results"
  );
  const semCounts = {};
  rawBySemester.forEach(r => {
    const s = normalizeSemester(r.semester);
    semCounts[s || "Unknown"] = (semCounts[s || "Unknown"] || 0) + 1;
  });
  const bySemester = Object.entries(semCounts).map(([semester, count]) => ({ semester, count })).sort((a, b) => a.semester.localeCompare(b.semester, undefined, { numeric: true }));
  const semMap = Object.fromEntries(bySemester.map(r => [r.semester, r.count]));
  const bySemesterFull = Array.from({ length: 10 }, (_, i) => {
    const label = `Sem ${i + 1}`;
    return { semester: label, count: semMap[label] || 0 };
  });
  const { rows: departments } = await pool.query("SELECT name FROM departments ORDER BY name");
  const { rows: byDay } = await pool.query(
    "SELECT to_char(date_trunc('day', COALESCE(timestamp, now())), 'YYYY-MM-DD') AS day, COUNT(*)::int AS count FROM certificates GROUP BY day ORDER BY day DESC LIMIT 7"
  );
  const byDayAsc = byDay.reverse();
  const { rows: issueCounts } = await pool.query("SELECT status, COUNT(*)::int AS count FROM issues GROUP BY status");
  const issues = { open: 0, resolved: 0, rejected: 0 };
  issueCounts.forEach(r => { if (issues[r.status] != null) issues[r.status] = r.count; });
  issues.total = issueCounts.reduce((a, r) => a + r.count, 0);
  res.json({ totalDepartments, totalResults, byDepartment, bySemester: bySemesterFull, byDay: byDayAsc, departments: departments.map(d => d.name), issues });
});

app.post("/api/certificates/bulk-upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    const ext = path.extname(req.file.originalname).toLowerCase();
    let rows = [];
    if (ext === ".csv") {
      const text = req.file.buffer.toString("utf8");
      const lines = text.split(/\r?\n/).filter(l => l.trim());
      if (lines.length < 2) return res.status(400).json({ error: "CSV must have header + data rows" });
      const headers = lines[0].split(",").map(h => h.replace(/^"|"$/g, "").trim().toLowerCase());
      for (let i = 1; i < lines.length; i++) {
        const vals = lines[i].split(",").map(v => v.replace(/^"|"$/g, "").trim());
        const row = {};
        headers.forEach((h, j) => row[h] = vals[j] || "");
        const rollKey = headers.find(h => h === "rollnumber" || h === "roll number" || h === "roll" || h === "rollno");
        if (rollKey) row.rollNumber = row[rollKey];
        rows.push(row);
      }
    } else if (ext === ".xlsx") {
      const wb = XLSX.read(req.file.buffer);
      const ws = wb.Sheets[wb.SheetNames[0]];
      rows = XLSX.utils.sheet_to_json(ws, { defval: "" }).map(raw => {
        const row = {};
        Object.keys(raw).forEach(k => {
          const key = String(k).toLowerCase().replace(/\s+/g, "");
          row[key] = raw[k];
        });
        const rollKey = Object.keys(row).find(h => h === "rollnumber" || h === "roll" || h === "rollno");
        if (rollKey) row.rollNumber = row[rollKey];
        if (!row.name) row.name = row.fullname || row.studentname || row["nameofthestudent"];
        return row;
      });
    } else {
      return res.status(400).json({ error: "Unsupported format. Use CSV or XLSX." });
    }
    if (rows.length === 0) return res.status(400).json({ error: "No valid rows found" });
    res.json({ count: rows.length, rows });
  } catch (err) {
    console.error("Bulk upload error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/certificates/bulk-save", async (req, res) => {
  const { certificates } = req.body;
  if (!Array.isArray(certificates) || certificates.length === 0) {
    return res.status(400).json({ error: "No certificates to save" });
  }
  let saved = 0;
  const hashes = [];
  for (const c of certificates) {
    if (!c.hash || !c.name) continue;
    await pool.query(
      `INSERT INTO certificates (${CERT_COLS})
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (hash) DO UPDATE SET
         name = EXCLUDED.name, "rollNumber" = EXCLUDED."rollNumber", course = EXCLUDED.course,
         department = EXCLUDED.department, year = EXCLUDED.year, email = EXCLUDED.email,
         "ipfsHash" = EXCLUDED."ipfsHash", "txHash" = EXCLUDED."txHash"`,
      [c.hash, c.name, c.rollNumber || "", c.course || "", c.department || "", c.year || "", c.email || "", c.ipfsHash || "", c.txHash || "", new Date()]
    );
    saved++;
    hashes.push(c.hash);
  }
  await logActivity("CERTIFICATE_BULK_ISSUED", { count: saved, hashes });
  res.json({ success: true, saved });
});

app.get("/api/departments", async (req, res) => {
  const { rows } = await pool.query("SELECT name FROM departments ORDER BY name");
  res.json(rows.map(r => r.name));
});

app.post("/api/departments", requireAdmin, async (req, res) => {
  const { name } = req.body || {};
  const trimmed = String(name || "").trim();
  if (!trimmed) return res.status(400).json({ error: "Department name is required" });
  const { rows: existing } = await pool.query("SELECT * FROM departments WHERE name = $1", [trimmed]);
  if (existing.length) return res.status(400).json({ error: "Department already exists" });
  await pool.query("INSERT INTO departments (name) VALUES ($1)", [trimmed]);
  const { rows } = await pool.query("SELECT name FROM departments ORDER BY name");
  res.json({ success: true, departments: rows.map(r => r.name) });
});

app.delete("/api/departments/:name", requireAdmin, async (req, res) => {
  const target = decodeURIComponent(req.params.name);
  const { rows: existing } = await pool.query("SELECT * FROM departments WHERE name = $1", [target]);
  if (!existing.length) return res.status(404).json({ error: "Department not found" });
  await pool.query("DELETE FROM departments WHERE name = $1", [target]);
  const delRes = await pool.query("DELETE FROM results WHERE department = $1", [target]);
  const removedResults = delRes.rowCount;
  if (removedResults > 0) {
    await logActivity("RESULT_DELETED", { department: target, count: removedResults });
  }
  const { rows } = await pool.query("SELECT name FROM departments ORDER BY name");
  res.json({ success: true, departments: rows.map(r => r.name), removedResults });
});

app.post("/api/results/bulk-upload", upload.single("file"), requirePerm("results"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    const ext = path.extname(req.file.originalname).toLowerCase();
    let rows = [];
    if (ext === ".csv") {
      const text = req.file.buffer.toString("utf8");
      const lines = text.split(/\r?\n/).filter(l => l.trim());
      if (lines.length < 2) return res.status(400).json({ error: "CSV must have header + data rows" });
      const headers = lines[0].split(",").map(h => h.replace(/^"|"$/g, "").trim().toLowerCase().replace(/\s+/g, ""));
      for (let i = 1; i < lines.length; i++) {
        const vals = lines[i].split(",").map(v => v.replace(/^"|"$/g, "").trim());
        const row = {};
        headers.forEach((h, j) => row[h] = vals[j] || "");
        rows.push(row);
      }
    } else if (ext === ".xlsx") {
      const wb = XLSX.read(req.file.buffer);
      const ws = wb.Sheets[wb.SheetNames[0]];
      rows = XLSX.utils.sheet_to_json(ws, { defval: "" }).map(raw => {
        const row = {};
        Object.keys(raw).forEach(k => {
          const key = String(k).toLowerCase().replace(/\s+/g, "");
          row[key] = raw[k];
        });
        return row;
      });
    } else {
      return res.status(400).json({ error: "Unsupported format. Use CSV or XLSX." });
    }

    const norm = (hits) => {
      for (const h of hits) {
        const key = Object.keys(rows[0] || {}).find(k => k === h);
        if (key) return key;
      }
      return null;
    };

    const rollKey = norm(["rollnumber", "rollno", "roll"]);
    const nameKey = norm(["name", "studentname", "student", "fullname"]);
    const deptKey = norm(["department", "dept"]);
    const semKey = norm(["semester", "sem"]);
    const subjectKey = norm(["subject", "subjectname", "course", "subjectcode"]);
    const marksKey = norm(["marks", "marksobtained", "obtained", "score"]);
    const maxKey = norm(["maxmarks", "totalmarks", "max", "maxm", "maximum"]);
    const gradeKey = norm(["grade", "gradepoint", "result"]);
    const aadhaarKey = norm(["aadhaar", "aadhar", "aadhaarno", "aadharNo".toLowerCase(), "uid", "adharnumber"]);
    const mobileKey = norm(["mobile", "mobileno", "mobileNumber".toLowerCase(), "phone", "phoneno", "contact"]);

    const validRows = [];
    for (const raw of rows) {
      const r = {
        rollNumber: (rollKey ? raw[rollKey] : "") || "",
        name: (nameKey ? raw[nameKey] : "") || "",
        department: (deptKey ? raw[deptKey] : "") || "",
        semester: (semKey ? raw[semKey] : "") || "",
        subject: (subjectKey ? raw[subjectKey] : "") || "",
        marks: (marksKey ? raw[marksKey] : "") || "",
        maxMarks: (maxKey ? raw[maxKey] : "") || "",
        grade: (gradeKey ? raw[gradeKey] : "") || "",
        aadhaar: (aadhaarKey ? String(raw[aadhaarKey] ?? "").replace(/\D/g, "") : ""),
        mobile: (mobileKey ? String(raw[mobileKey] ?? "").replace(/\D/g, "") : ""),
      };
      if (r.rollNumber && r.subject) validRows.push(r);
    }
    if (validRows.length === 0) {
      return res.status(400).json({ error: "No valid rows found. Ensure each row has Roll Number and Subject." });
    }

    const scope = await getDeptScope(req);
    if (scope.restricted) {
      const bad = validRows.find(r => !deptAllowed(scope, String(r.department || "").trim()));
      if (bad) {
        return res.status(403).json({ error: `You do not have access to department "${bad.department || "(empty)"}"` });
      }
    }

    res.json({ count: validRows.length, rows: validRows });
  } catch (err) {
    console.error("Results bulk upload error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/results/bulk-save", requirePerm("results"), async (req, res) => {
  const { rows } = req.body;
  if (!Array.isArray(rows) || rows.length === 0) {
    return res.status(400).json({ error: "No rows to save" });
  }
  const scope = await getDeptScope(req);
  if (scope.restricted) {
    const bad = rows.find(r => !deptAllowed(scope, String((r && r.department) || "").trim()));
    if (bad) {
      return res.status(403).json({ error: `You do not have access to department "${(bad && bad.department) || "(empty)"}"` });
    }
  }
  const { rows: deptRows } = await pool.query("SELECT name FROM departments");
  const deps = new Set(deptRows.map(r => r.name));
  const groups = {};
  for (const row of rows) {
    if (!row.rollNumber || !row.subject) continue;
    const sem = normalizeSemester(row.semester || "Sem 1");
    const key = `${row.rollNumber.trim().toLowerCase()}__${sem.toLowerCase()}`;
    if (!groups[key]) {
      groups[key] = {
        rollNumber: row.rollNumber.trim(),
        name: row.name || row.rollNumber.trim(),
        department: row.department || "",
        semester: sem,
        aadhaar: digitsOnly(row.aadhaar).slice(0, 12),
        mobile: digitsOnly(row.mobile).slice(0, 15),
        subjects: [],
      };
    }
    if (!groups[key].aadhaar && row.aadhaar) groups[key].aadhaar = digitsOnly(row.aadhaar).slice(0, 12);
    if (!groups[key].mobile && row.mobile) groups[key].mobile = digitsOnly(row.mobile).slice(0, 15);
    groups[key].subjects.push({
      subject: String(row.subject).trim(),
      marks: row.marks === "" || row.marks == null ? null : Number(row.marks),
      maxMarks: row.maxMarks === "" || row.maxMarks == null ? null : Number(row.maxMarks),
      grade: String(row.grade || "").trim()
    });
    if (row.department && !deps.has(row.department.trim())) deps.add(row.department.trim());
  }

  let added = 0;
  let updated = 0;
  const now = new Date();
  for (const key of Object.keys(groups)) {
    const g = groups[key];
    const { rows: existing } = await pool.query(
      "SELECT * FROM results WHERE LOWER(\"rollNumber\") = $1 AND LOWER(semester) = $2",
      [g.rollNumber.toLowerCase(), g.semester.toLowerCase()]
    );
    if (existing.length) {
      const subjects = parseJson(existing[0].subjects, []);
      subjects.push(...g.subjects);
      await pool.query(
        "UPDATE results SET subjects = $1, name = $2, department = $3, aadhaar = $4, mobile = $5 WHERE id = $6",
        [JSON.stringify(subjects), g.name || existing[0].name, g.department || existing[0].department,
         g.aadhaar || existing[0].aadhaar || "", g.mobile || existing[0].mobile || "", existing[0].id]
      );
      updated++;
    } else {
      await pool.query(
        `INSERT INTO results (id, "rollNumber", name, department, semester, aadhaar, mobile, subjects, timestamp) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [crypto.randomBytes(8).toString("hex"), g.rollNumber, g.name, g.department, g.semester, g.aadhaar, g.mobile, JSON.stringify(g.subjects), now]
      );
      added++;
    }
  }
  for (const d of deps) {
    await pool.query("INSERT INTO departments (name) VALUES ($1) ON CONFLICT (name) DO NOTHING", [d]);
  }
  await logActivity("RESULT_BULK_ADDED", { added, updated });
  res.json({ success: true, added, updated, totalStudents: Object.keys(groups).length });
});

app.get("/api/results/verify", async (req, res) => {
  const rollNumber = (req.query.rollNumber || "").trim();
  const semester = (req.query.semester || "").trim();
  if (!rollNumber) return res.status(400).json({ error: "Roll Number is required" });
  const isAdmin = await isAdminRequest(req);
  if (!isAdmin) {
    const rTok = (req.get("x-result-token") || "").trim();
    const rec = resultAccessTokens.get(rTok);
    if (!rec || rec.expires < Date.now()) {
      return res.status(401).json({ error: "Verification required. Please login with Aadhaar and OTP." });
    }
    if (rec.rollKey !== rollNumber.toLowerCase()) {
      return res.status(403).json({ error: "This access code is for a different roll number" });
    }
  }
  for (const [t, v] of resultAccessTokens) if (v.expires < Date.now()) resultAccessTokens.delete(t);
  const sql = "SELECT * FROM results WHERE LOWER(\"rollNumber\") = $1"
    + (semester
      ? " AND COALESCE(NULLIF(regexp_replace(semester, '\\D', '', 'g'), ''), '0') = COALESCE(NULLIF(regexp_replace($2, '\\D', '', 'g'), ''), '0')"
      : "")
    + " ORDER BY timestamp DESC";
  const params = [rollNumber.toLowerCase()];
  if (semester) params.push(semester);
  const { rows } = await pool.query(sql, params);
  res.json(rows.map(r => ({ id: r.id, rollNumber: r.rollNumber, name: r.name, department: r.department, semester: r.semester, subjects: parseJson(r.subjects, []) })));
});

app.get("/api/results", async (req, res) => {
  const uname = await getUsernameFromReq(req);
  if (!uname) return res.status(401).json({ error: "Login required" });
  const scope = await getDeptScope(req);
  const q = (req.query.q || "").toLowerCase().trim();
  const department = (req.query.department || "").trim();
  const semester = (req.query.semester || "").trim();
  if (department && !deptAllowed(scope, department)) {
    return res.status(403).json({ error: "You do not have access to this department" });
  }
  const where = [];
  const params = [];
  if (q) {
    where.push("(LOWER(name) LIKE $1 OR LOWER(\"rollNumber\") LIKE $2)");
    params.push(`%${q}%`, `%${q}%`);
  }
  if (department) {
    where.push(`department = $${params.length + 1}`);
    params.push(department);
  } else if (scope.restricted) {
    where.push(`department = ANY($${params.length + 1})`);
    params.push(scope.depts);
  }
  if (semester) {
    where.push(`COALESCE(NULLIF(regexp_replace(semester, '\\D', '', 'g'), ''), '0') = COALESCE(NULLIF(regexp_replace($${params.length + 1}, '\\D', '', 'g'), ''), '0')`);
    params.push(semester);
  }
  const sql = "SELECT * FROM results" + (where.length ? " WHERE " + where.join(" AND ") : "") + " ORDER BY timestamp DESC";
  const { rows } = await pool.query(sql, params);
  res.json(rows.map(r => ({ ...r, subjects: parseJson(r.subjects, []) })));
});

app.post("/api/results", requirePerm("results"), async (req, res) => {
  const { rollNumber, name, department, semester, aadhaar, mobile, subjects } = req.body || {};
  const sem = normalizeSemester(semester || "");
  if (!rollNumber || !String(rollNumber).trim()) return res.status(400).json({ error: "Roll Number is required" });
  if (!name || !String(name).trim()) return res.status(400).json({ error: "Student name is required" });
  if (!department || !String(department).trim()) return res.status(400).json({ error: "Department is required" });
  if (!sem) return res.status(400).json({ error: "Semester is required" });
  const scope = await getDeptScope(req);
  if (!deptAllowed(scope, String(department).trim())) {
    return res.status(403).json({ error: `You do not have access to department "${department}"` });
  }
  const { rows: duplicate } = await pool.query(
    "SELECT * FROM results WHERE LOWER(\"rollNumber\") = $1 AND LOWER(semester) = $2",
    [String(rollNumber).trim().toLowerCase(), sem.toLowerCase()]
  );
  if (duplicate.length) return res.status(400).json({ error: `Result already exists for ${rollNumber} in ${sem}` });
  const entry = {
    id: crypto.randomBytes(8).toString("hex"),
    rollNumber: String(rollNumber).trim(),
    name: String(name).trim(),
    department: String(department).trim(),
    semester: sem,
    aadhaar: digitsOnly(aadhaar).slice(0, 12),
    mobile: digitsOnly(mobile).slice(0, 15),
    subjects: Array.isArray(subjects) ? subjects.map(s => ({
      subject: String(s.subject || "").trim(),
      marks: s.marks === "" || s.marks == null ? null : Number(s.marks),
      maxMarks: s.maxMarks === "" || s.maxMarks == null ? null : Number(s.maxMarks),
      grade: String(s.grade || "").trim()
    })).filter(s => s.subject) : [],
    timestamp: new Date().toISOString()
  };
  await pool.query(
    `INSERT INTO results (id, "rollNumber", name, department, semester, aadhaar, mobile, subjects, timestamp) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [entry.id, entry.rollNumber, entry.name, entry.department, entry.semester, entry.aadhaar, entry.mobile, JSON.stringify(entry.subjects), new Date()]
  );
  await logActivity("RESULT_ADDED", { rollNumber: entry.rollNumber, name: entry.name, semester: entry.semester });
  res.json({ success: true, result: entry });
});

app.put("/api/results/:id", requirePerm("results"), async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM results WHERE id = $1", [req.params.id]);
  if (rows.length === 0) return res.status(404).json({ error: "Result not found" });
  const existing = rows[0];
  const { rollNumber, name, department, semester, aadhaar, mobile, subjects } = req.body || {};
  const scope = await getDeptScope(req);
  if (!deptAllowed(scope, existing.department)) {
    return res.status(403).json({ error: "You do not have access to this department" });
  }
  if (department && String(department).trim() && !deptAllowed(scope, String(department).trim())) {
    return res.status(403).json({ error: `You do not have access to department "${department}"` });
  }
  const updated = {
    rollNumber: rollNumber ? String(rollNumber).trim() : existing.rollNumber,
    name: name ? String(name).trim() : existing.name,
    department: department ? String(department).trim() : existing.department,
    semester: semester ? normalizeSemester(semester) : existing.semester,
    aadhaar: aadhaar !== undefined ? digitsOnly(aadhaar).slice(0, 12) : (existing.aadhaar || ""),
    mobile: mobile !== undefined ? digitsOnly(mobile).slice(0, 15) : (existing.mobile || ""),
    subjects: Array.isArray(subjects)
      ? subjects.map(s => ({
          subject: String(s.subject || "").trim(),
          marks: s.marks === "" || s.marks == null ? null : Number(s.marks),
          maxMarks: s.maxMarks === "" || s.maxMarks == null ? null : Number(s.maxMarks),
          grade: String(s.grade || "").trim()
        })).filter(s => s.subject)
      : parseJson(existing.subjects, [])
  };
  await pool.query(
    `UPDATE results SET "rollNumber" = $1, name = $2, department = $3, semester = $4, aadhaar = $5, mobile = $6, subjects = $7 WHERE id = $8`,
    [updated.rollNumber, updated.name, updated.department, updated.semester, updated.aadhaar, updated.mobile, JSON.stringify(updated.subjects), existing.id]
  );
  await logActivity("RESULT_UPDATED", { rollNumber: updated.rollNumber, semester: updated.semester });
  res.json({ success: true, result: { id: existing.id, ...updated, timestamp: existing.timestamp } });
});

app.delete("/api/results/:id", requirePerm("results"), async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM results WHERE id = $1", [req.params.id]);
  if (rows.length === 0) return res.status(404).json({ error: "Result not found" });
  const scope = await getDeptScope(req);
  if (!deptAllowed(scope, rows[0].department)) {
    return res.status(403).json({ error: "You do not have access to this department" });
  }
  const removed = rows[0];
  await pool.query("DELETE FROM results WHERE id = $1", [req.params.id]);
  await logActivity("RESULT_DELETED", { rollNumber: removed.rollNumber, name: removed.name, semester: removed.semester });
  res.json({ success: true });
});

app.post("/api/issues", async (req, res) => {
  const { rollNumber, semester, message } = req.body || {};
  if (!message || !String(message).trim()) return res.status(400).json({ error: "Issue description is required" });
  if (rollNumber && !String(rollNumber).trim()) return res.status(400).json({ error: "Roll Number is required" });
  const { rows } = await pool.query(
    'INSERT INTO issues ("rollNumber", semester, message, status, timestamp) VALUES ($1, $2, $3, $4, $5) RETURNING id',
    [String(rollNumber || "").trim(), String(semester || "").trim(), String(message).trim(), "open", new Date()]
  );
  await logActivity("ISSUE_RAISED", { rollNumber: String(rollNumber || "").trim(), semester: String(semester || "").trim(), message: String(message).trim() });
  res.json({ success: true, id: rows[0].id });
});

app.get("/api/issues", requirePerm("issues"), async (req, res) => {
  const q = (req.query.q || "").toLowerCase().trim();
  const rows = q
    ? (await pool.query(
        "SELECT * FROM issues WHERE LOWER(message) LIKE $1 OR LOWER(\"rollNumber\") LIKE $2 ORDER BY timestamp DESC",
        [`%${q}%`, `%${q}%`]
      )).rows
    : (await pool.query("SELECT * FROM issues ORDER BY timestamp DESC")).rows;
  res.json(rows.map(r => ({
    id: r.id, rollNumber: r.rollNumber, semester: r.semester,
    message: r.message, status: r.status, timestamp: r.timestamp
  })));
});

app.patch("/api/issues/:id", requirePerm("issues"), async (req, res) => {
  const status = req.body && req.body.status;
  if (!status || !["open", "resolved", "rejected"].includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }
  const { rows } = await pool.query("UPDATE issues SET status = $1 WHERE id = $2 RETURNING id", [status, req.params.id]);
  if (rows.length === 0) return res.status(404).json({ error: "Issue not found" });
  await logActivity("ISSUE_UPDATED", { id: req.params.id, status });
  res.json({ success: true });
});

app.delete("/api/issues/:id", requirePerm("issues"), async (req, res) => {
  const { rows } = await pool.query("DELETE FROM issues WHERE id = $1 RETURNING id", [req.params.id]);
  if (rows.length === 0) return res.status(404).json({ error: "Issue not found" });
  await logActivity("ISSUE_DELETED", { id: req.params.id });
  res.json({ success: true });
});

app.get("/api/activity", async (req, res) => {
  const q = (req.query.q || "").toLowerCase().trim();
  const rows = q
    ? (await pool.query(
        "SELECT * FROM activity WHERE LOWER(type) LIKE $1 OR LOWER(details) LIKE $2 ORDER BY timestamp DESC",
        [`%${q}%`, `%${q}%`]
      )).rows
    : (await pool.query("SELECT * FROM activity ORDER BY timestamp DESC")).rows;
  res.json(rows.map(r => ({ type: r.type, details: parseJson(r.details, {}), timestamp: r.timestamp })));
});

app.get("/api/brand", async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM brand WHERE id = 1");
  if (rows.length === 0) return res.json({ ...DEFAULT_BRAND });
  res.json({ name: rows[0].name, shortName: rows[0].shortName, logo: rows[0].logo });
});

app.put("/api/brand", async (req, res) => {
  const { name, shortName, logo } = req.body || {};
  const { rows } = await pool.query("SELECT * FROM brand WHERE id = 1");
  const brand = rows.length ? rows[0] : { ...DEFAULT_BRAND };
  if (typeof name === "string" && name.trim()) brand.name = name.trim().slice(0, 120);
  if (typeof shortName === "string") brand.shortName = shortName.trim().slice(0, 20) || brand.shortName;
  brand.logo = typeof logo === "string" && logo ? logo : null;
  await pool.query(
    `INSERT INTO brand (id, name, "shortName", logo) VALUES (1, $1, $2, $3)
     ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, "shortName" = EXCLUDED."shortName", logo = EXCLUDED.logo`,
    [brand.name, brand.shortName, brand.logo]
  );
  await logActivity("BRAND_UPDATED", { name: brand.name });
  res.json({ success: true, brand: { name: brand.name, shortName: brand.shortName, logo: brand.logo } });
});

const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 10;
const loginAttempts = new Map();

app.post("/api/admin/login", async (req, res) => {
  const key = req.ip || "unknown";
  const now = Date.now();
  const rec = loginAttempts.get(key);
  if (rec && rec.count >= LOGIN_MAX_ATTEMPTS && now - rec.first < LOGIN_WINDOW_MS) {
    reportEvent("login_rate_limit", "critical", "Login rate limit hit — account/IP temporarily locked", username, key);
    return res.status(429).json({ success: false, error: "Too many login attempts. Try again in 15 minutes." });
  }
  const { username, password } = req.body || {};
  const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [username || ""]);
  const u = rows[0];
  if (u && verifyPass(u.password, password)) {
    if (!String(u.password).startsWith("scrypt$")) {
      await pool.query("UPDATE users SET password = $1 WHERE username = $2", [hashPass(password), username]);
    }
    loginAttempts.delete(key);
    const token = await createSession(username);
    await logActivity("ADMIN_LOGIN", { user: username });
    reportEvent("login", "info", `Successful ${u.role} login`, username, key);
    res.json({ success: true, token, user: username, role: u.role, permissions: parsePerms(u.permissions), departments: parseDepts(u.departments) });
  } else {
    reportEvent("failed_login", "high", "Invalid admin credentials", username, key);
    if (!rec || now - rec.first >= LOGIN_WINDOW_MS) {
      loginAttempts.set(key, { first: now, count: 1 });
    } else {
      rec.count += 1;
    }
    res.status(401).json({ success: false, error: "Invalid credentials" });
  }
});

app.get("/api/users", requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT username, role, permissions, departments, "createdAt" FROM users');
  res.json(rows.map(u => ({ username: u.username, role: u.role || "admin", permissions: parsePerms(u.permissions), departments: parseDepts(u.departments), createdAt: u.createdAt })));
});

app.post("/api/users", requireAdmin, async (req, res) => {
  const { username, password, role, permissions, departments } = req.body || {};
  if (!username || !String(username).trim()) return res.status(400).json({ error: "Username is required" });
  if (!password || String(password).length < 4) return res.status(400).json({ error: "Password must be at least 4 characters" });
  const uname = String(username).trim();
  const { rows: existing } = await pool.query("SELECT * FROM users WHERE username = $1", [uname]);
  if (existing.length) return res.status(400).json({ error: "User already exists" });
  const userRole = normalizeRole(role);
  const perms = userRole === "admin" ? [] : parsePerms(permissions);
  const depts = userRole === "admin" ? [] : parseDepts(departments);
  await pool.query(
    `INSERT INTO users (username, password, role, permissions, departments, "createdAt") VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6)`,
    [uname, hashPass(password), userRole, JSON.stringify(perms), JSON.stringify(depts), new Date()]
  );
  await logActivity("USER_CREATED", { user: uname, role: userRole });
  res.json({ success: true });
});

app.put("/api/users/:username", requireAdmin, async (req, res) => {
  const uname = req.params.username;
  const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [uname]);
  if (rows.length === 0) return res.status(404).json({ error: "User not found" });
  const { password, role, permissions, departments } = req.body || {};
  if (password && String(password).length < 4) return res.status(400).json({ error: "Password must be at least 4 characters" });
  if (role) {
    const newRole = normalizeRole(role);
    if (newRole !== "admin" && (rows[0].role || "admin") === "admin") {
      if (uname === ADMIN_USER) return res.status(400).json({ error: "Cannot demote the primary admin account" });
      const { rows: adminRows } = await pool.query("SELECT COUNT(*)::int AS c FROM users WHERE role = 'admin'");
      if (adminRows[0].c <= 1) return res.status(400).json({ error: "At least one admin must remain" });
    }
    await pool.query("UPDATE users SET role = $1 WHERE username = $2", [newRole, uname]);
  }
  const targetRole = role ? normalizeRole(role) : (rows[0].role || "user");
  if (Array.isArray(permissions)) {
    await pool.query("UPDATE users SET permissions = $1::jsonb WHERE username = $2", [JSON.stringify(targetRole === "admin" ? [] : parsePerms(permissions)), uname]);
  }
  if (Array.isArray(departments)) {
    await pool.query("UPDATE users SET departments = $1::jsonb WHERE username = $2", [JSON.stringify(targetRole === "admin" ? [] : parseDepts(departments)), uname]);
  }
  if (password) await pool.query("UPDATE users SET password = $1 WHERE username = $2", [hashPass(password), uname]);
  await logActivity("USER_UPDATED", { user: uname });
  res.json({ success: true });
});

app.delete("/api/users/:username", requireAdmin, async (req, res) => {
  const uname = req.params.username;
  const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [uname]);
  if (rows.length === 0) return res.status(404).json({ error: "User not found" });
  const { rows: adminRows } = await pool.query("SELECT COUNT(*)::int AS activeAdmins FROM users WHERE role = 'admin'");
  const activeAdmins = adminRows[0].activeAdmins;
  if (uname === ADMIN_USER) return res.status(400).json({ error: "Cannot delete the primary admin account" });
  if ((rows[0].role || "admin") === "admin" && activeAdmins <= 1) {
    return res.status(400).json({ error: "At least one admin must remain" });
  }
  await pool.query("DELETE FROM users WHERE username = $1", [uname]);
  await logActivity("USER_DELETED", { user: uname });
  res.json({ success: true });
});

app.post("/api/certificates/blockchain", async (req, res) => {
  try {
    const { hash, name, ipfsHash } = req.body;
    if (!hash || !name || !ipfsHash) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    console.log(`Sending tx: addCertificate("${hash}", "${name}", "${ipfsHash}")`);
    const tx = await contract.addCertificate(hash, name, ipfsHash);
    console.log(`Waiting for confirmation... TxHash: ${tx.hash}`);
    const receipt = await tx.wait();
    console.log(`Tx confirmed in block ${receipt.blockNumber}`);
    res.json({ success: true, txHash: tx.hash, blockNumber: receipt.blockNumber });
  } catch (err) {
    console.error("Blockchain tx failed:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Campus Monitor: agent endpoint (called by other campus apps) ----------
app.post("/api/agent/event", async (req, res) => {
  const provided = (req.headers["x-monitor-token"] || "").trim();
  if (!MONITOR_AGENT_TOKEN || provided !== MONITOR_AGENT_TOKEN) {
    return res.status(403).json({ error: "Invalid agent token" });
  }
  const { appKey, type, severity, message, username, ip } = req.body || {};
  if (!appKey || !message) return res.status(400).json({ error: "appKey and message are required" });
  const { rows } = await pool.query("SELECT id, name FROM monitor_apps WHERE enabled AND app_key = $1", [appKey]);
  if (rows.length === 0) return res.status(404).json({ error: "Unknown app_key (register it first)" });
  await insertMonitorEvent({ appKey, type, severity, message, username, ip });
  res.status(201).json({ success: true, app: rows[0].name });
});

// ---------- Campus Monitor: admin API ----------
app.get("/api/monitor/stats", requirePerm("monitor"), async (req, res) => {
  const apps = await pool.query("SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE enabled)::int AS enabled FROM monitor_apps");
  const online = await pool.query(`
    SELECT COUNT(*)::int AS c FROM monitor_apps m
    WHERE m.enabled AND (SELECT c.online FROM monitor_checks c WHERE c.app_id = m.id ORDER BY c.id DESC LIMIT 1)
  `);
  const events = await pool.query("SELECT COUNT(*)::int AS total FROM monitor_events");
  const critical = await pool.query("SELECT COUNT(*)::int AS c FROM monitor_events WHERE severity IN ('high','critical') AND created_at > now() - interval '24 hours'");
  const ropaDone = await pool.query("SELECT COUNT(*)::int AS c FROM monitor_apps WHERE enabled AND ropa_status = 'completed'");
  const dpiaDone = await pool.query("SELECT COUNT(*)::int AS c FROM monitor_apps WHERE enabled AND dpia_status = 'completed'");
  const dpdpDone = await pool.query("SELECT COUNT(*)::int AS c FROM monitor_apps WHERE enabled AND dpdp_status = 'completed'");
  const recent = await pool.query(`
    SELECT e.id, e.type, e.severity, e.message, e.username, e.ip, e.created_at, m.name AS app_name
    FROM monitor_events e LEFT JOIN monitor_apps m ON m.id = e.app_id
    ORDER BY e.id DESC LIMIT 20
  `);
  res.json({
    totalApps: apps.rows[0].total,
    enabledApps: apps.rows[0].enabled,
    onlineApps: online.rows[0].c,
    totalEvents: events.rows[0].total,
    critical24h: critical.rows[0].c,
    ropaCompleted: ropaDone.rows[0].c,
    dpiaCompleted: dpiaDone.rows[0].c,
    dpdpCompleted: dpdpDone.rows[0].c,
    recent: recent.rows,
  });
});

app.get("/api/monitor/apps", requirePerm("monitor"), async (req, res) => {
  const { rows } = await pool.query(`
    SELECT m.id, m.name, m.app_key, m.url, m.type, m.department, m.notes, m.enabled, m."createdAt",
      m.ropa_status, m.ropa_owner, m.ropa_notes, m.ropa_updated_at,
      m.dpia_status, m.dpia_owner, m.dpia_notes, m.dpia_updated_at,
      m.dpdp_status, m.dpdp_owner, m.dpdp_notes, m.dpdp_updated_at,
      (SELECT c.online FROM monitor_checks c WHERE c.app_id = m.id ORDER BY c.id DESC LIMIT 1) AS last_online,
      (SELECT c.status_code FROM monitor_checks c WHERE c.app_id = m.id ORDER BY c.id DESC LIMIT 1) AS last_status,
      (SELECT c.latency_ms FROM monitor_checks c WHERE c.app_id = m.id ORDER BY c.id DESC LIMIT 1) AS last_latency,
      (SELECT c.checked_at FROM monitor_checks c WHERE c.app_id = m.id ORDER BY c.id DESC LIMIT 1) AS last_checked,
      (SELECT COUNT(*) FILTER (WHERE c.online) * 100.0 / NULLIF(COUNT(*), 0)
         FROM monitor_checks c WHERE c.app_id = m.id AND c.checked_at > now() - interval '24 hours') AS uptime_24h
    FROM monitor_apps m ORDER BY m.name
  `);
  res.json(rows);
});

app.post("/api/monitor/apps", requireAdmin, async (req, res) => {
  const { name, app_key: appKey, url, type, department, notes, enabled,
          ropa_status, ropa_owner, ropa_notes, dpia_status, dpia_owner, dpia_notes,
          dpdp_status, dpdp_owner, dpdp_notes } = req.body || {};
  if (!name || !url) return res.status(400).json({ error: "name and url are required" });
  try {
    new URL(url);
  } catch {
    return res.status(400).json({ error: "Invalid URL" });
  }
  const key = (appKey || String(name).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || crypto.randomBytes(4).toString("hex"));
  const rStatus = ["not_started", "in_progress", "completed"].includes(ropa_status) ? ropa_status : "not_started";
  const dStatus = ["not_started", "in_progress", "completed"].includes(dpia_status) ? dpia_status : "not_started";
  const pStatus = ["not_started", "in_progress", "completed"].includes(dpdp_status) ? dpdp_status : "not_started";
  const now = rStatus === "completed" || rStatus === "in_progress" ? new Date() : null;
  const dnow = dStatus === "completed" || dStatus === "in_progress" ? new Date() : null;
  const pnow = pStatus === "completed" || pStatus === "in_progress" ? new Date() : null;
  try {
    const { rows } = await pool.query(
      `INSERT INTO monitor_apps (name, app_key, url, type, department, notes, enabled,
         ropa_status, ropa_owner, ropa_notes, ropa_updated_at, dpia_status, dpia_owner, dpia_notes, dpia_updated_at,
         dpdp_status, dpdp_owner, dpdp_notes, dpdp_updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, TRUE), $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19) RETURNING *`,
      [name, key, url, type || "web", department || "", notes || "", enabled,
       rStatus, String(ropa_owner || "").slice(0, 100), ropa_notes || "", now,
       dStatus, String(dpia_owner || "").slice(0, 100), dpia_notes || "", dnow,
       pStatus, String(dpdp_owner || "").slice(0, 100), dpdp_notes || "", pnow]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    if (e.code === "23505") return res.status(400).json({ error: "app key already in use" });
    throw e;
  }
});

app.put("/api/monitor/apps/:id", requirePerm("monitor"), async (req, res) => {
  const { name, url, type, department, notes, enabled,
          ropa_status, ropa_owner, ropa_notes, dpia_status, dpia_owner, dpia_notes,
          dpdp_status, dpdp_owner, dpdp_notes } = req.body || {};
  if (url) {
    try {
      new URL(url);
    } catch {
      return res.status(400).json({ error: "Invalid URL" });
    }
  }
  const rStatus = ropa_status === undefined ? undefined : (["not_started", "in_progress", "completed"].includes(ropa_status) ? ropa_status : undefined);
  const dStatus = dpia_status === undefined ? undefined : (["not_started", "in_progress", "completed"].includes(dpia_status) ? dpia_status : undefined);
  const pStatus = dpdp_status === undefined ? undefined : (["not_started", "in_progress", "completed"].includes(dpdp_status) ? dpdp_status : undefined);
  const ropaUpdatedAt = ropa_status === undefined ? undefined : (rStatus === "completed" || rStatus === "in_progress" ? new Date() : null);
  const dpiaUpdatedAt = dpia_status === undefined ? undefined : (dStatus === "completed" || dStatus === "in_progress" ? new Date() : null);
  const dpdpUpdatedAt = dpdp_status === undefined ? undefined : (pStatus === "completed" || pStatus === "in_progress" ? new Date() : null);
  const { rows } = await pool.query(
    `UPDATE monitor_apps SET name = COALESCE($2, name), url = COALESCE($3, url), type = COALESCE($4, type),
         department = COALESCE($5, department), notes = COALESCE($6, notes), enabled = COALESCE($7, enabled),
         ropa_status = COALESCE($8, ropa_status), ropa_owner = COALESCE($9, ropa_owner),
         ropa_notes = COALESCE($10, ropa_notes), ropa_updated_at = $11,
         dpia_status = COALESCE($12, dpia_status), dpia_owner = COALESCE($13, dpia_owner),
         dpia_notes = COALESCE($14, dpia_notes), dpia_updated_at = $15,
         dpdp_status = COALESCE($16, dpdp_status), dpdp_owner = COALESCE($17, dpdp_owner),
         dpdp_notes = COALESCE($18, dpdp_notes), dpdp_updated_at = $19
     WHERE id = $1 RETURNING *`,
    [req.params.id, name, url, type, department, notes, enabled,
     rStatus, ropa_owner === undefined ? undefined : String(ropa_owner).slice(0, 100), ropa_notes,
     ropaUpdatedAt, dStatus, dpia_owner === undefined ? undefined : String(dpia_owner).slice(0, 100), dpia_notes,
     dpiaUpdatedAt, pStatus, dpdp_owner === undefined ? undefined : String(dpdp_owner).slice(0, 100), dpdp_notes,
     dpdpUpdatedAt]
  );
  if (rows.length === 0) return res.status(404).json({ error: "App not found" });
  res.json(rows[0]);
});

app.delete("/api/monitor/apps/:id", requireAdmin, async (req, res) => {
  const { rows } = await pool.query("DELETE FROM monitor_apps WHERE id = $1 RETURNING id", [req.params.id]);
  if (rows.length === 0) return res.status(404).json({ error: "App not found" });
  res.json({ success: true });
});

app.get("/api/monitor/apps/:id/checks", requireAdmin, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "200", 10), 2000);
  const { rows } = await pool.query(
    "SELECT status_code, latency_ms, online, checked_at FROM monitor_checks WHERE app_id = $1 ORDER BY id DESC LIMIT $2",
    [req.params.id, limit]
  );
  res.json(rows.reverse());
});

// ---------- Campus Monitor: background poller ----------
async function pruneChecks(appId) {
  await pool.query(
    `DELETE FROM monitor_checks
     WHERE app_id = $1 AND id < (SELECT id FROM monitor_checks c2 WHERE c2.app_id = $1 ORDER BY c2.id DESC LIMIT 1 OFFSET 1000)`,
    [appId]
  );
}

async function checkMonitoredApp(a) {
  const started = Date.now();
  let status_code = 0;
  let online = false;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), MONITOR_CHECK_TIMEOUT);
  try {
    const response = await fetch(a.url, { method: "GET", redirect: "manual", signal: controller.signal });
    status_code = response.status;
    online = status_code >= 200 && status_code < 500;
  } catch (e) {
    online = false;
  } finally {
    clearTimeout(timer);
  }
  const latency = Date.now() - started;
  try {
    await pool.query(
      "INSERT INTO monitor_checks (app_id, status_code, latency_ms, online) VALUES ($1, $2, $3, $4)",
      [a.id, status_code, latency, online]
    );
  } catch (e) {
    console.error("Check insert failed:", e.message);
  }
  await pruneChecks(a.id).catch(() => {});
  if (!online) {
    await insertMonitorEvent({
      appKey: a.app_key,
      type: "app_down",
      severity: "critical",
      message: `App "${a.name}" is DOWN (HTTP ${status_code})`,
      ip: "",
    });
  }
}

async function pollMonitoredApps() {
  let apps = [];
  try {
    const { rows } = await pool.query("SELECT * FROM monitor_apps WHERE enabled ORDER BY id");
    apps = rows;
  } catch (e) {
    console.error("Poll query failed (tables not ready yet):", e.message);
    return;
  }
  await Promise.all(apps.map(checkMonitoredApp));
  console.log(`[monitor] checked ${apps.length} app(s)`);
}

async function seedMonitorApps() {
  try {
    const { rows } = await pool.query("SELECT COUNT(*)::int AS c FROM monitor_apps");
    if (rows[0].c > 0) return;
    const selfUrl = `http://localhost:${PORT}`;
    await pool.query(
      `INSERT INTO monitor_apps (name, app_key, url, type, department, notes)
       VALUES ($1, $2, $3, 'web', 'Records Office', 'Self-monitored campus app') ON CONFLICT (app_key) DO NOTHING`,
      ["Certificate Portal", "certificate-portal", selfUrl]
    );
    console.log("[monitor] seeded default app: Certificate Portal");
  } catch (e) {
    console.error("[monitor] seed failed:", e.message);
  }
}

// ---------- DPIA Reporting & Dashboard ----------
const DPIA_STATUSES = ["draft", "in_progress", "completed", "on_hold"];
const DPIA_RISK_LEVELS = ["low", "medium", "high", "critical"];
const DPIA_CATEGORIES = [
  "Student Records", "Academic Results", "Aadhaar Data", "Mobile Numbers",
  "Biometric Data", "Health Records", "Financial Data", "HR Employee Data",
  "CCTV / Surveillance", "IoT / Sensors", "Campus Access", "Online Services"
];
const DPIA_LIKELIHOOD = ["rare", "unlikely", "possible", "likely", "almost_certain"];
const DPIA_IMPACT = ["negligible", "minor", "moderate", "major", "severe"];

function dpiaRiskLevel(likelihood, impact) {
  const li = DPIA_LIKELIHOOD.indexOf(likelihood);
  const im = DPIA_IMPACT.indexOf(impact);
  const score = (Math.max(0, li) + 1) * (Math.max(0, im) + 1);
  if (score >= 20) return "critical";
  if (score >= 12) return "high";
  if (score >= 6) return "medium";
  return "low";
}

function parseJsonArr(v) {
  if (Array.isArray(v)) return v;
  if (typeof v === "string") { try { return JSON.parse(v); } catch { return []; } }
  return [];
}

const DPIA_ASSESSMENT_COLS = `id, title, description, business_unit AS "businessUnit", status, stage,
  risk_level AS "riskLevel", data_categories AS "dataCategories", third_party AS "thirdParty",
  third_party_name AS "thirdPartyName", start_date AS "startDate", due_date AS "dueDate",
  completed_at AS "completedAt", risks, "createdAt" AS "createdAt", "updatedAt" AS "updatedAt"`;

// ---------- DPIA Approval Workflow ----------
const DPIA_DEFAULT_STAGES = [
  { id: "draft", label: "Draft", color: "#64748b" },
  { id: "assessment", label: "Assessment", color: "#3b82f6" },
  { id: "review", label: "Review", color: "#8b5cf6" },
  { id: "risk_treatment", label: "Risk Treatment", color: "#f59e0b" },
  { id: "privacy_review", label: "Privacy Review", color: "#ec4899" },
  { id: "approval", label: "Approval", color: "#f97316" },
  { id: "active", label: "Active", color: "#22c55e" },
  { id: "periodic_review", label: "Periodic Review", color: "#06b6d4" },
];

const DPIA_DEFAULT_TRANSITIONS = [
  { from: "draft", to: "assessment", label: "Start Assessment", requireComment: false, requireAdmin: false },
  { from: "assessment", to: "draft", label: "Send Back to Draft", requireComment: true, requireAdmin: false },
  { from: "assessment", to: "review", label: "Submit for Review", requireComment: false, requireAdmin: false },
  { from: "review", to: "assessment", label: "Request Changes", requireComment: true, requireAdmin: false },
  { from: "review", to: "risk_treatment", label: "Approve Review", requireComment: false, requireAdmin: false },
  { from: "risk_treatment", to: "review", label: "Request Changes", requireComment: true, requireAdmin: false },
  { from: "risk_treatment", to: "privacy_review", label: "Complete Risk Treatment", requireComment: false, requireAdmin: false },
  { from: "privacy_review", to: "risk_treatment", label: "Request Changes", requireComment: true, requireAdmin: false },
  { from: "privacy_review", to: "approval", label: "Submit for Approval", requireComment: false, requireAdmin: false },
  { from: "approval", to: "privacy_review", label: "Reject — Return for Revisions", requireComment: true, requireAdmin: true },
  { from: "approval", to: "active", label: "Approve & Activate", requireComment: true, requireAdmin: true },
  { from: "active", to: "periodic_review", label: "Start Periodic Review", requireComment: false, requireAdmin: false },
  { from: "periodic_review", to: "active", label: "Re-confirm & Reactivate", requireComment: true, requireAdmin: true },
  { from: "periodic_review", to: "assessment", label: "Trigger Re-assessment", requireComment: true, requireAdmin: false },
];

async function getDpiaWorkflow() {
  const { rows } = await pool.query("SELECT stages, transitions FROM dpia_workflow_config WHERE id = 1");
  if (rows.length) {
    const stages = parseJsonArr(rows[0].stages);
    const transitions = parseJsonArr(rows[0].transitions);
    if (stages.length && transitions.length) {
      return { stages, transitions };
    }
  }
  const defaults = { stages: DPIA_DEFAULT_STAGES, transitions: DPIA_DEFAULT_TRANSITIONS };
  await pool.query(
    `INSERT INTO dpia_workflow_config (id, stages, transitions, "updatedAt", "updatedBy")
     VALUES (1, $1, $2, now(), 'system')
     ON CONFLICT (id) DO NOTHING`,
    [JSON.stringify(defaults.stages), JSON.stringify(defaults.transitions)]
  ).catch(() => {});
  return defaults;
}

function dpiaStageMeta(stage, stages) {
  const s = stages.find(x => x.id === stage);
  return { id: stage, label: s ? s.label : stage.replace(/_/g, " "), color: s ? s.color : "#64748b" };
}

function dpiaStageToStatus(stage) {
  if (stage === "active" || stage === "periodic_review") return "completed";
  if (stage === "draft") return "draft";
  return "in_progress";
}

async function dpiaAudit(assessmentId, action, fromStage, toStage, username, comment, meta) {
  await pool.query(
    `INSERT INTO dpia_audit_log (assessment_id, action, from_stage, to_stage, username, comment, meta, "createdAt")
     VALUES ($1, $2, $3, $4, $5, $6, $7, now())`,
    [assessmentId, action, fromStage || "", toStage || "", username || "", comment || "",
     JSON.stringify(meta || {})]
  );
}

app.get("/api/dpia/workflow", requirePerm("dpia"), async (req, res) => {
  try {
    res.json(await getDpiaWorkflow());
  } catch (e) {
    console.error("DPIA workflow config error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.put("/api/dpia/workflow", requireAdmin, async (req, res) => {
  try {
    const { stages, transitions } = req.body || {};
    const cleanStages = (parseJsonArr(stages) || []).filter(s => s && s.id).map(s => ({
      id: String(s.id).trim(), label: String(s.label || s.id).slice(0, 60), color: String(s.color || "#64748b")
    }));
    const stageIds = new Set(cleanStages.map(s => s.id));
    const cleanTransitions = (parseJsonArr(transitions) || []).filter(t => t && stageIds.has(t.from) && stageIds.has(t.to)).map(t => ({
      from: t.from, to: t.to,
      label: String(t.label || `${t.from} → ${t.to}`).slice(0, 80),
      requireComment: !!t.requireComment, requireAdmin: !!t.requireAdmin
    }));
    const uname = (await getUsernameFromReq(req)) || "";
    await pool.query(
      `INSERT INTO dpia_workflow_config (id, stages, transitions, "updatedAt", "updatedBy")
       VALUES (1, $1, $2, now(), $3)
       ON CONFLICT (id) DO UPDATE SET stages = $1, transitions = $2, "updatedAt" = now(), "updatedBy" = $3`,
      [JSON.stringify(cleanStages), JSON.stringify(cleanTransitions), uname]
    );
    res.json({ success: true, stages: cleanStages, transitions: cleanTransitions });
  } catch (e) {
    console.error("DPIA workflow config save error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/dpia/dashboard", requireAdmin, async (req, res) => {
  try {
    const [{ total }] = (await pool.query("SELECT COUNT(*)::int AS total FROM dpia_assessments")).rows;
    const { rows: byStatus } = await pool.query("SELECT status, COUNT(*)::int AS count FROM dpia_assessments GROUP BY status");
    const statusMap = Object.fromEntries(byStatus.map(r => [r.status, r.count]));
    const open = (statusMap.draft || 0) + (statusMap.in_progress || 0) + (statusMap.on_hold || 0);
    const completed = statusMap.completed || 0;

    const { rows: highRiskRows } = await pool.query(
      "SELECT id FROM dpia_assessments WHERE risk_level = 'high' OR risk_level = 'critical'"
    );
    const { rows: riskRows } = await pool.query(
      `SELECT r.assessment_id, r.status, r.due_date, r.risk_level
         FROM dpia_risks r JOIN dpia_assessments a ON a.id = r.assessment_id`
    );

    const openRisks = riskRows.filter(r => r.status !== "resolved");
    const highRisks = riskRows.filter(r => ["high", "critical"].includes(r.risk_level));
    const overdueNow = riskRows.filter(r => r.status !== "resolved" && r.due_date && new Date(r.due_date) < new Date());

    // Overdue remediation = unresolved risks past due date OR pending assessments past due
    const { rows: overdueAssess } = await pool.query(
      "SELECT COUNT(*)::int AS c FROM dpia_assessments WHERE status != 'completed' AND due_date IS NOT NULL AND due_date < now()"
    );

    const [{ c: thirdPartyCount }] = (await pool.query("SELECT COUNT(*)::int AS c FROM dpia_assessments WHERE third_party")).rows;
    const { rows: byCategory } = await pool.query("SELECT data_categories FROM dpia_assessments");
    const catCounts = {};
    byCategory.forEach(r => {
      parseJsonArr(r.data_categories).forEach(c => { catCounts[c] = (catCounts[c] || 0) + 1; });
    });
    const dataCategories = Object.entries(catCounts).map(([category, count]) => ({ category, count })).sort((a, b) => b.count - a.count);

    const { rows: byUnit } = await pool.query(
      "SELECT COALESCE(NULLIF(business_unit, ''), 'Not Assigned') AS unit, status, COUNT(*)::int AS count FROM dpia_assessments GROUP BY unit, status ORDER BY unit"
    );

    const { rows: byStageRows } = await pool.query(
      "SELECT stage, COUNT(*)::int AS count FROM dpia_assessments GROUP BY stage"
    );
    const workflow = await getDpiaWorkflow();
    const byStage = workflow.stages.map(s => {
      const r = byStageRows.find(x => x.stage === s.id);
      return { stage: s.id, label: s.label, color: s.color, count: r ? r.count : 0 };
    });
    // any stages present in data but not in configured workflow
    byStageRows.forEach(r => {
      if (!workflow.stages.some(s => s.id === r.stage)) {
        byStage.push({ stage: r.stage, label: r.stage.replace(/_/g, " "), color: "#64748b", count: r.count });
      }
    });

    res.json({
      totalDpias: total,
      open, completed,
      highRiskProcessing: highRiskRows.length,
      openPrivacyRisks: openRisks.length,
      overdueRemediation: overdueNow.length + overdueAssess.c,
      thirdPartyProcessing: thirdPartyCount,
      dataCategories,
      byUnit: byUnit.map(r => ({ unit: r.unit, status: r.status, count: r.count })),
      riskBreakdown: {
        open: openRisks.length,
        resolved: riskRows.length - openRisks.length,
        high: highRisks.length
      },
      byStatus: byStatus.map(r => ({ status: r.status, count: r.count })),
      byStage,
      workflow: { stages: workflow.stages, transitions: workflow.transitions }
    });
  } catch (e) {
    console.error("DPIA dashboard error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/dpia", requirePerm("dpia"), async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT ${DPIA_ASSESSMENT_COLS} FROM dpia_assessments ORDER BY "createdAt" DESC`
    );
    res.json(rows);
  } catch (e) {
    console.error("DPIA list error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/dpia/report", requireAdmin, async (req, res) => {
  try {
    const [{ total }] = (await pool.query("SELECT COUNT(*)::int AS total FROM dpia_assessments")).rows;
    const [{ completed }] = (await pool.query("SELECT COUNT(*)::int AS completed FROM dpia_assessments WHERE status = 'completed'")).rows;
    const [{ highRisk }] = (await pool.query("SELECT COUNT(*)::int AS \"highRisk\" FROM dpia_assessments WHERE risk_level IN ('high','critical')")).rows;
    const [{ openRisks }] = (await pool.query("SELECT COUNT(*)::int AS \"openRisks\" FROM dpia_risks WHERE status != 'resolved'")).rows;
    const [{ overdue }] = (await pool.query("SELECT COUNT(*)::int AS \"overdue\" FROM dpia_risks WHERE status != 'resolved' AND due_date IS NOT NULL AND due_date < now()")).rows;
    const [{ thirdParty }] = (await pool.query("SELECT COUNT(*)::int AS \"thirdParty\" FROM dpia_assessments WHERE third_party")).rows;

    const { rows: byUnit } = await pool.query(
      "SELECT COALESCE(NULLIF(business_unit,''),'Not Assigned') AS unit, status, COUNT(*)::int AS count FROM dpia_assessments GROUP BY unit, status ORDER BY unit"
    );
    const { rows: topRisks } = await pool.query(
      `SELECT r.description, r.risk_level AS "riskLevel", r.status, a.business_unit AS "businessUnit", a.title AS assessment
         FROM dpia_risks r JOIN dpia_assessments a ON a.id = r.assessment_id
        WHERE r.risk_level IN ('high','critical')
        ORDER BY CASE r.risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END LIMIT 10`
    );

    const { rows: byStageRows } = await pool.query(
      "SELECT stage, COUNT(*)::int AS count FROM dpia_assessments GROUP BY stage ORDER BY stage"
    );
    const workflow = await getDpiaWorkflow();
    const stageOrder = Object.fromEntries(workflow.stages.map((s, i) => [s.id, i]));
    const stageLines = byStageRows
      .sort((a, b) => (stageOrder[a.stage] ?? 99) - (stageOrder[b.stage] ?? 99))
      .map(r => `  ${r.stage.replace(/_/g, " ")}: ${r.count}`);

    const lines = [
      "EXECUTIVE DPIA REPORT",
      `Generated: ${new Date().toISOString().slice(0, 10)}`,
      "=".repeat(48),
      "",
      `Total DPIAs: ${total}`,
      `Completed: ${completed}  |  Open: ${total - completed}`,
      `High-risk processing activities: ${highRisk}`,
      `Open privacy risks: ${openRisks}`,
      `Overdue remediation items: ${overdue}`,
      `Third-party processing activities: ${thirdParty}`,
      "",
      "WORKFLOW PIPELINE",
      "-".repeat(48),
      ...(stageLines.length ? stageLines : ["  None"]),
      "",
      "DPIA STATUS BY BUSINESS UNIT",
      "-".repeat(48),
      ...byUnit.map(r => `  ${r.unit}: ${r.status} = ${r.count}`),
      "",
      "TOP OPEN HIGH/CRITICAL RISKS",
      "-".repeat(48),
      ...(topRisks.length ? topRisks.map((r, i) => `  ${i + 1}. [${r.riskLevel.toUpperCase()}] ${r.description} (${r.assessment} · ${r.businessUnit})`) : ["  None"]),
      "",
      "Recommendation: Prioritize remediation of overdue high/critical risks and close residual DPIAs to meet privacy compliance obligations.",
      "=".repeat(48),
    ];

    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.send(lines.join("\n"));
  } catch (e) {
    console.error("DPIA report error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/dpia/:id", requirePerm("dpia"), async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT ${DPIA_ASSESSMENT_COLS} FROM dpia_assessments WHERE id = $1`,
      [req.params.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Not found" });
    const { rows: risks } = await pool.query(
      `SELECT id, description, likelihood, impact, risk_level AS "riskLevel", status, remediation,
              due_date AS "dueDate", resolved_at AS "resolvedAt", "createdAt" AS "createdAt"
         FROM dpia_risks WHERE assessment_id = $1 ORDER BY id`,
      [req.params.id]
    );
    const { rows: audit } = await pool.query(
      `SELECT id, action, from_stage AS "fromStage", to_stage AS "toStage", username, comment,
              meta, "createdAt" AS "createdAt"
         FROM dpia_audit_log WHERE assessment_id = $1 ORDER BY id DESC`,
      [req.params.id]
    );
    res.json({ ...rows[0], risks, audit });
  } catch (e) {
    console.error("DPIA detail error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/dpia", requirePerm("dpia"), async (req, res) => {
  try {
    const { title, description, businessUnit, status, stage, riskLevel, dataCategories, thirdParty, thirdPartyName, startDate, dueDate, completedAt, risks } = req.body || {};
    if (!title || !String(title).trim()) return res.status(400).json({ error: "Title is required" });
    const workflow = await getDpiaWorkflow();
    const stages = workflow.stages.map(s => s.id);
    const rowStage = stages.includes(stage) ? stage : (DPIA_STATUSES.includes(status) ? (status === "completed" ? "active" : status === "on_hold" ? "review" : "draft") : "draft");
    const rowStatus = dpiaStageToStatus(rowStage);
    const rowRisk = DPIA_RISK_LEVELS.includes(riskLevel) ? riskLevel : "medium";
    const cats = parseJsonArr(dataCategories).map(String).filter(Boolean);
    const { rows } = await pool.query(
      `INSERT INTO dpia_assessments (title, description, business_unit, status, stage, risk_level, data_categories, third_party, third_party_name, start_date, due_date, completed_at, "createdAt", "updatedAt")
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now(), now())
       RETURNING id`,
      [String(title).trim(), description || "", businessUnit || "", rowStatus, rowStage, rowRisk,
       JSON.stringify(cats), !!thirdParty, thirdPartyName || "",
       startDate || null, dueDate || null, completedAt || null]
    );
    const id = rows[0].id;
    const uname = (await getUsernameFromReq(req)) || "";
    await dpiaAudit(id, "created", "", rowStage, uname, "DPIA created", { title: title.trim() });
    for (const r of parseJsonArr(risks)) {
      if (!r || !r.description) continue;
      const level = DPIA_RISK_LEVELS.includes(r.riskLevel) ? r.riskLevel : dpiaRiskLevel(r.likelihood, r.impact);
      await pool.query(
        `INSERT INTO dpia_risks (assessment_id, description, likelihood, impact, risk_level, status, remediation, due_date)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [id, r.description, r.likelihood || "possible", r.impact || "moderate", level,
         r.status || "open", r.remediation || "", r.dueDate || null]
      );
    }
    if (parseJsonArr(risks).some(r => r && r.description)) {
      await dpiaAudit(id, "risk_added", rowStage, rowStage, uname, "Initial risks recorded", { count: parseJsonArr(risks).filter(r => r && r.description).length });
    }
    await logActivity("DPIA_CREATED", { user: uname, title: title.trim(), id });
    res.status(201).json({ success: true, id, stage: rowStage });
  } catch (e) {
    console.error("DPIA create error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.put("/api/dpia/:id", requirePerm("dpia"), async (req, res) => {
  try {
    const { title, description, businessUnit, status, stage, riskLevel, dataCategories, thirdParty, thirdPartyName, startDate, dueDate, completedAt, risks } = req.body || {};
    if (!title || !String(title).trim()) return res.status(400).json({ error: "Title is required" });
    const { rows: existingRows } = await pool.query("SELECT id, title, stage, status FROM dpia_assessments WHERE id = $1", [req.params.id]);
    if (existingRows.length === 0) return res.status(404).json({ error: "Not found" });
    const workflow = await getDpiaWorkflow();
    const stages = workflow.stages.map(s => s.id);
    const prev = existingRows[0];
    const rowStage = stages.includes(stage) ? stage : (DPIA_STATUSES.includes(status) ? (status === "completed" ? "active" : status === "on_hold" ? "review" : "draft") : prev.stage || "draft");
    const rowStatus = dpiaStageToStatus(rowStage);
    const rowRisk = DPIA_RISK_LEVELS.includes(riskLevel) ? riskLevel : "medium";
    const cats = parseJsonArr(dataCategories).map(String).filter(Boolean);
    await pool.query(
      `UPDATE dpia_assessments SET title = $2, description = $3, business_unit = $4, status = $5, stage = $6,
         risk_level = $7, data_categories = $8, third_party = $9, third_party_name = $10,
         start_date = $11, due_date = $12, completed_at = $13, "updatedAt" = now()
       WHERE id = $1`,
      [req.params.id, String(title).trim(), description || "", businessUnit || "", rowStatus, rowStage, rowRisk,
       JSON.stringify(cats), !!thirdParty, thirdPartyName || "", startDate || null, dueDate || null, completedAt || null]
    );
    const uname = (await getUsernameFromReq(req)) || "";
    await dpiaAudit(req.params.id, "updated", prev.stage || "draft", rowStage, uname, "Assessment details updated", {
      titleChanged: prev.title !== title.trim(), stageChanged: prev.stage !== rowStage
    });
    if (Array.isArray(risks)) {
      await pool.query("DELETE FROM dpia_risks WHERE assessment_id = $1", [req.params.id]);
      let count = 0;
      for (const r of risks) {
        if (!r || !r.description) continue;
        count++;
        const level = DPIA_RISK_LEVELS.includes(r.riskLevel) ? r.riskLevel : dpiaRiskLevel(r.likelihood, r.impact);
        await pool.query(
          `INSERT INTO dpia_risks (assessment_id, description, likelihood, impact, risk_level, status, remediation, due_date)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [req.params.id, r.description, r.likelihood || "possible", r.impact || "moderate", level,
           r.status || "open", r.remediation || "", r.dueDate || null]
        );
      }
      if (count > 0) await dpiaAudit(req.params.id, "risk_updated", rowStage, rowStage, uname, `Risk register revised (${count} risk(s))`, { count });
    }
    if (prev.stage !== rowStage) {
      await dpiaAudit(req.params.id, rowStage === "active" ? "approved" : "stage_changed", prev.stage || "draft", rowStage, uname, `Moved to ${rowStage}`, {});
      await logActivity("DPIA_STAGE_CHANGED", { user: uname, title: title.trim(), id: req.params.id, from: prev.stage, to: rowStage });
    }
    await logActivity("DPIA_UPDATED", { user: uname, title: title.trim(), id: req.params.id });
    res.json({ success: true });
  } catch (e) {
    console.error("DPIA update error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/dpia/:id/risk", requirePerm("dpia"), async (req, res) => {
  try {
    const { description, likelihood, impact, status, remediation, dueDate } = req.body || {};
    if (!description) return res.status(400).json({ error: "Description required" });
    const level = dpiaRiskLevel(likelihood, impact);
    const { rows: cur } = await pool.query("SELECT stage FROM dpia_assessments WHERE id = $1", [req.params.id]);
    const rowStage = cur.length ? cur[0].stage : "draft";
    const uname = (await getUsernameFromReq(req)) || "";
    await pool.query(
      `INSERT INTO dpia_risks (assessment_id, description, likelihood, impact, risk_level, status, remediation, due_date)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [req.params.id, description, likelihood || "possible", impact || "moderate", level, status || "open", remediation || "", dueDate || null]
    );
    await dpiaAudit(req.params.id, "risk_added", rowStage, rowStage, uname, "Risk added: " + description, { riskLevel: level });
    await logActivity("DPIA_RISK_UPDATED", { user: uname, id: req.params.id, detail: "Risk added" });
    res.status(201).json({ success: true, riskLevel: level });
  } catch (e) {
    console.error("DPIA risk create error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.put("/api/dpia/risk/:riskId", requirePerm("dpia"), async (req, res) => {
  try {
    const { status, remediation, dueDate, resolvedAt } = req.body || {};
    if (!DPIA_RISK_LEVELS.length) { /* noop */ }
    const { rows: cur } = await pool.query(
      "SELECT a.stage, a.id AS assessment_id FROM dpia_risks r JOIN dpia_assessments a ON a.id = r.assessment_id WHERE r.id = $1",
      [req.params.riskId]
    );
    const rowStage = cur.length ? cur[0].stage : "draft";
    const uname = (await getUsernameFromReq(req)) || "";
    await pool.query(
      `UPDATE dpia_risks SET status = $2, remediation = COALESCE($3, remediation),
         due_date = COALESCE($4, due_date), resolved_at = COALESCE($5, resolved_at)
       WHERE id = $1`,
      [req.params.riskId, status || "open", remediation ?? null, dueDate ?? null, resolvedAt ?? null]
    );
    await dpiaAudit(cur.length ? cur[0].assessment_id : null, "risk_updated", rowStage, rowStage, uname,
      `Risk updated (status: ${status || "open"})${remediation ? " — remediation added" : ""}`, { status: status || "open" });
    await logActivity("DPIA_RISK_UPDATED", { user: uname, id: req.params.riskId, detail: "Risk updated" });
    res.json({ success: true });
  } catch (e) {
    console.error("DPIA risk update error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/dpia/:id/transition", requirePerm("dpia"), async (req, res) => {
  try {
    const { to, comment } = req.body || {};
    if (!to) return res.status(400).json({ error: "Target stage is required" });
    const { rows: cur } = await pool.query(
      "SELECT id, title, stage, status FROM dpia_assessments WHERE id = $1",
      [req.params.id]
    );
    if (cur.length === 0) return res.status(404).json({ error: "Not found" });
    const workflow = await getDpiaWorkflow();
    const from = cur[0].stage || "draft";
    const txn = workflow.transitions.find(t => t.from === from && t.to === to);
    if (!txn) return res.status(400).json({ error: `No allowed transition from "${from}" to "${to}"` });
    if (txn.requireAdmin && !(await isAdminRequest(req))) {
      return res.status(403).json({ error: "This transition requires an administrator" });
    }
    if (txn.requireComment && !String(comment || "").trim()) {
      return res.status(400).json({ error: "A comment is required for this transition" });
    }
    const uname = (await getUsernameFromReq(req)) || "";
    const nextStatus = dpiaStageToStatus(to);
    const action = to === "active" ? "approved" : (from === "approval" ? "rejected" : "stage_changed");
    await pool.query(
      "UPDATE dpia_assessments SET stage = $2, status = $3, \"updatedAt\" = now() WHERE id = $1",
      [req.params.id, to, nextStatus]
    );
    await dpiaAudit(req.params.id, action, from, to, uname, comment || "", { via: txn.label });
    await logActivity(
      action === "approved" ? "DPIA_APPROVED" : action === "rejected" ? "DPIA_REJECTED" : "DPIA_STAGE_CHANGED",
      { user: uname, title: cur[0].title, id: req.params.id, from, to }
    );
    res.json({ success: true, stage: to, status: nextStatus, action, from, via: txn.label });
  } catch (e) {
    console.error("DPIA transition error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/dpia/:id", requirePerm("dpia"), async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT title, stage FROM dpia_assessments WHERE id = $1", [req.params.id]);
    const uname = (await getUsernameFromReq(req)) || "";
    const title = rows.length ? rows[0].title : "?";
    if (rows.length) {
      await dpiaAudit(req.params.id, "deleted", rows[0].stage || "draft", "", uname, "DPIA deleted", {});
    }
    await pool.query("DELETE FROM dpia_assessments WHERE id = $1", [req.params.id]);
    await logActivity("DPIA_DELETED", { user: uname, title, id: req.params.id });
    res.json({ success: true });
  } catch (e) {
    console.error("DPIA delete error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

const buildPath = path.join(__dirname, "build");
if (fs.existsSync(buildPath)) {
  app.use(express.static(buildPath));
  app.use((req, res) => {
    if (req.path.startsWith("/api/")) return res.status(404).json({ error: "Not found" });
    res.sendFile(path.join(buildPath, "index.html"));
  });
  console.log("Serving React build from:", buildPath);
} else {
  console.log("No build/ directory found. Run 'npm run build' first.");
}

async function start() {
  await init();
  await seedMonitorApps();
  await ensureDefaultAdmin();
  const server = app.listen(PORT, HOST, () => {
    console.log(`Server running at http://${HOST}:${PORT}`);
  });
  server.on("error", (err) => {
    console.error("Server error:", err);
  });
  await pollMonitoredApps().catch((e) => console.error("[monitor] initial poll failed:", e.message));
  setInterval(() => pollMonitoredApps().catch(() => {}), MONITOR_POLL_INTERVAL);
}

if (require.main === module) {
  start().catch((err) => {
    console.error("Failed to start server:", err.message);
    console.error("Is PostgreSQL running? Check DB_HOST/DB_PORT/DB_USER/DB_PASS/DB_NAME in .env");
    process.exit(1);
  });
}

module.exports = { hashPass, verifyPass, parseJson, CERT_COLS, DEFAULT_BRAND };
