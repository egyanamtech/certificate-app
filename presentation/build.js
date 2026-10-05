const fs = require("fs");
const path = require("path");

const SRC_DIR = path.join(__dirname, "screenshots");
const OUT = path.join(__dirname, "certificate-app-presentation.html");

const slides = [
  ["01-home.png", "Public Landing Page", "Branded landing page with university logo, name, tagline, How It Works explainer (Issue → Store → Verify), trust band and dark/light theme toggle."],
  ["02-verify-certificate.png", "Verify Certificate (Public)", "Anyone can verify a certificate by entering its hash. The backend returns only validity — no student personal data is exposed."],
  ["03-check-result.png", "Check Result (Public)", "Students can look up semester-wise results by roll number, and raise issues against them without any login."],
  ["04-admin-login.png", "Admin Portal — Login", "Secure login with scrypt-hashed passwords, rate-limited attempts, and 64-char session tokens stored server-side."],
  ["05-dashboard.png", "Dashboard", "Live statistics: total certificates, issued today, departments, results and issue counts, plus 7-day / department-wise / semester-wise charts."],
  ["06-campus-monitor.png", "Campus Monitor", "Public-facing monitors ships with live certificate issuance feed and uptime/health status."],
  ["07-issue-certificate.png", "Issue Certificate", "Issue a single certificate with name, roll, course, department, year and email; generated SHA-256 hash with optional IPFS and on-chain (Sepolia) anchoring."],
  ["08-bulk-upload.png", "Bulk Upload", "Upload certificates or results as CSV/XLSX with header detection and a mismatch report; processing is gated until the data is complete."],
  ["09-verify-admin.png", "Verify (Admin)", "Admin-facing verification for certificates and results, with immediate pass/fail feedback."],
  ["10-certificates.png", "Certificates Registry", "Searchable registry by hash / name / roll / email, on-chain status badges, and CSV / XLSX export."],
  ["11-results.png", "Results", "Semester-wise student results with multiple subjects per record; unique roll + semester constraint prevents duplicates."],
  ["12-analytics.png", "Analytics", "Insights into certificates and results across semesters, departments and board state."],
  ["13-issues.png", "Issues", "Students' raised issues with open / resolved / rejected triage workflow for staff."],
  ["14-activity.png", "Activity Log", "Full audit trail of every key action (logins, issuances, deletions, user and brand changes) with search."],
  ["15-users.png", "User Management", "Role-based accounts: Admin, Normal User, Department Head, Privacy Manager, Cyber Security, HR and Legal — with per-user section permissions and department scoping."],
  ["16-settings.png", "Settings", "University branding (name, short name, logo) and self-service password change."],
  ["17-downloads.png", "Downloads", "One-stop export hub for the certificate registry and results as CSV or Excel."],
];

const roles = [
  ["Admin", "Full access to every section and all departments."],
  ["Normal User", "Section-based access; page permissions controlled per user."],
  ["Department Head", "Certificates, Results, Verify, Analytics, Issues, Activity (department-scoped)."],
  ["Privacy Manager", "Verify, Issues, Activity, Downloads (audit & privacy oversight)."],
  ["Cyber Security", "Campus Monitor, Verify, Issues, Activity."],
  ["HR", "Certificates, Results, Verify, Downloads, Activity."],
  ["Legal", "Verify, Issues, Activity, Downloads."],
];

const features = [
  ["SHA-256 Tamper-Proof Certificates", "Every certificate gets a unique cryptographic hash; optional anchoring to the Sepolia testnet blockchain and IPFS."],
  ["Role & Department Scoping", "Seven roles with fine-grained section permissions; normal users can be restricted to specific departments and cannot bypass the filter."],
  ["Bulk Upload With Mismatch Reports", "CSV / XLSX uploads for certificates and results with header detection and a full mismatch report before committing."],
  ["Public Verification, Privacy First", "Anyone can verify a hash; the API never exposes student personal data to the public."],
  ["Complete Audit Trail", "Every administrative action is logged with search; session tokens survive restarts and auto-rotate on idle."],
  ["Python-Fast Production Readiness", "Express + PostgreSQL JSONB backend, React SPA frontend, PM2 process management and Docker Compose deployment."],
];

const tech = [
  ["Frontend", "React (Create React App), custom CSS with light/dark themes"],
  ["Backend", "Node.js + Express REST API"],
  ["Database", "PostgreSQL 16 (JSONB for subjects, permissions & departments)"],
  ["Blockchain", "Optional Sepolia testnet anchoring of certificate hashes"],
  ["Files", "XLSX parsing, CSV export"],
  ["Ops", "PM2 process manager, Docker Compose"],
];

function slideHtml([file, title, desc]) {
  const b64 = fs.readFileSync(path.join(SRC_DIR, file)).toString("base64");
  return `
  <section class="slide">
    <div class="slide-head">
      <span class="slide-num"></span>
      <h2>${title}</h2>
      <p>${desc}</p>
    </div>
    <div class="slide-shot">
      <a href="screenshots/${file}" target="_blank"><img src="data:image/png;base64,${b64}" alt="${title}" loading="lazy"></a>
    </div>
  </section>`;
}

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Certificate &amp; Results Management System — Presentation</title>
<style>
  :root { --ink:#0f172a; --mut:#475569; --acc:#2563eb; --line:#e2e8f0; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; color: var(--ink); background:#f1f5f9; }
  .cover { background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 55%, #2563eb 100%); color:#fff; padding:80px 32px 56px; text-align:center; }
  .cover h1 { font-size:44px; margin:0 0 8px; letter-spacing:.5px; }
  .cover .sub { font-size:20px; opacity:.9; margin:0 0 26px; }
  .cover .tags span { display:inline-block; background:rgba(255,255,255,.14); border:1px solid rgba(255,255,255,.25); border-radius:20px; padding:6px 14px; margin:4px; font-size:13px; }
  .wrap { max-width:1080px; margin:0 auto; padding:32px 24px 64px; }
  section.slide { background:#fff; border:1px solid var(--line); border-radius:16px; margin:0 0 32px; overflow:hidden; box-shadow:0 6px 24px rgba(15,23,42,.06); }
  .slide-head { padding:22px 26px 12px; border-bottom:1px solid var(--line); }
  .slide-head h2 { margin:0 0 6px; font-size:26px; color:var(--ink); }
  .slide-head p { margin:0; color:var(--mut); font-size:15px; line-height:1.55; }
  .slide-shot { padding:18px; }
  .slide-shot img { display:block; width:100%; height:auto; border:1px solid var(--line); border-radius:10px; box-shadow:0 2px 10px rgba(15,23,42,.08); }
  .grid2 { display:grid; grid-template-columns:1fr 1fr; gap:24px; }
  @media (max-width:860px){ .grid2{grid-template-columns:1fr;} }
  .card { background:#fff; border:1px solid var(--line); border-radius:14px; padding:22px; }
  .card h3 { margin:0 0 10px; font-size:18px; color:var(--acc); }
  .card ul { margin:0; padding:0 0 0 18px; color:#334155; line-height:1.65; }
  .card table { width:100%; border-collapse:collapse; font-size:14px; }
  .card td, .card th { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  .card th { color:var(--mut); font-size:12px; text-transform:uppercase; letter-spacing:.5px; }
  .chip { display:inline-block; background:#eef2ff; color:#4338ca; border-radius:6px; padding:1px 8px; font-weight:600; font-size:12px; }
  footer { text-align:center; color:var(--mut); font-size:13px; padding:8px 0 40px; }
  .toc ul { columns:2; column-gap:28px; list-style:none; padding:0; }
  .toc li { break-inside:avoid; padding:6px 0; border-bottom:1px dashed var(--line); color:#334155; }
</style>
</head>
<body>

<div class="cover">
  <div style="font-size:60px;margin-bottom:10px;">🎓</div>
  <h1>Certificate &amp; Results Management System</h1>
  <p class="sub">Tamper-proof certificates · semester-wise results · public verification · role-based admin portal</p>
  <div class="tags">
    <span>🔐 Role-Based Access</span><span>⛓️ Blockchain Anchoring</span><span>⚡ Bulk Upload</span>
    <span>🕒 Audit Trail</span><span>🌙 Dark / Light Themes</span><span>🐳 Docker + PM2</span>
  </div>
</div>

<div class="wrap">

  <section class="card toc">
    <h3>📖 Contents</h3>
    <ul>
      <li>1 — Overview &amp; Key Features</li>
      <li>2 — Roles &amp; Permissions</li>
      <li>3 — Technology Stack</li>
      <li>4 — Public Website (4 screens)</li>
      <li>5 — Admin Portal (12 screens)</li>
      <li>6 — Access Details</li>
    </ul>
  </section>

  <section class="card">
    <h3>🚀 Overview</h3>
    <p style="color:#334155;line-height:1.7;margin:0 0 16px;">
      A full-stack university platform that lets the records office issue cryptographically tamper-proof certificates,
      manage semester-wise student results, and let the public verify credentials — all behind a secure,
      role-based admin portal with a complete audit trail.
    </p>
    <div class="grid2" style="margin-top:14px;">
      <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:12px;padding:14px;">
        <strong style="color:#1d4ed8;">🔓 Public</strong>
        <p style="margin:6px 0 0;font-size:14px;color:#374151;">Verify a certificate by hash · check a student result · raise an issue — no login required, no PII leaked.</p>
      </div>
      <div style="background:#ecfdf5;border:1px solid #a7f3d0;border-radius:12px;padding:14px;">
        <strong style="color:#047857;">🔐 Admin Portal</strong>
        <p style="margin:6px 0 0;font-size:14px;color:#374151;">Dashboard, certificates, results, analytics, issues, audit log, user management, branding and downloads — with 7 roles.</p>
      </div>
    </div>
  </section>

  <section class="card">
    <h3>✨ Key Features</h3>
    <div class="grid2">
      ${features.map(([t, d]) => `<div style="border:1px solid var(--line);border-radius:12px;padding:14px;"><strong>${t}</strong><p style="margin:6px 0 0;font-size:14px;color:#475569;">${d}</p></div>`).join("")}
    </div>
  </section>

  <section class="card">
    <h3>👥 Roles &amp; Permissions</h3>
    <table>
      <thead><tr><th>Role</th><th>Default Access</th></tr></thead>
      <tbody>
        ${roles.map(([r, d]) => `<tr><td><span class="chip">${r}</span></td><td>${d}</td></tr>`).join("")}
      </tbody>
    </table>
    <p style="font-size:13px;color:var(--mut);margin:12px 0 0;">Normal users can be limited to specific departments at the API level (403 enforced) — empty department selection means all departments.</p>
  </section>

  <section class="card">
    <h3>🛠 Technology Stack</h3>
    <table>
      <tbody>
        ${tech.map(([t, v]) => `<tr><th style="width:160px;">${t}</th><td>${v}</td></tr>`).join("")}
      </tbody>
    </table>
  </section>

  <h2 style="margin:40px 0 14px;font-size:30px;">📸 Application Screens</h2>
  ${slides.map(slideHtml).join("")}

  <section class="card">
    <h3>🔑 Access Details</h3>
    <table>
      <thead><tr><th>User</th><th>Role</th><th>Password</th></tr></thead>
      <tbody>
        <tr><td><strong>admin</strong></td><td>Admin</td><td><code>admin123</code></td></tr>
        <tr><td>normal_user</td><td>Normal User</td><td><code>staff123</code></td></tr>
        <tr><td>dept_head</td><td>Department Head</td><td><code>staff123</code></td></tr>
        <tr><td>privacy_mgr</td><td>Privacy Manager</td><td><code>staff123</code></td></tr>
        <tr><td>cybersec</td><td>Cyber Security</td><td><code>staff123</code></td></tr>
        <tr><td>hr_office</td><td>HR</td><td><code>staff123</code></td></tr>
        <tr><td>legal_team</td><td>Legal</td><td><code>staff123</code></td></tr>
      </tbody>
    </table>
  </section>

  <footer>Certificate &amp; Results Management System · Presentation generated ${new Date().toLocaleDateString("en-GB")}</footer>

</div>
</body>
</html>`;

fs.writeFileSync(OUT, html);
console.log(`Wrote ${OUT} (${Math.round(fs.statSync(OUT).size / 1024)} KB)`);