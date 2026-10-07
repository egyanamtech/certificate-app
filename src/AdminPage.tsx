import React, { useState, useEffect, useCallback } from "react";
import { useTheme, useBrand, Logo } from "./App";

const API_BASE = process.env.NODE_ENV === 'development'
  ? `http://${window.location.hostname}:5000`
  : '';

const BAR_COLORS = ["#38bdf8", "#34d399", "#fbbf24", "#f472b6", "#a78bfa", "#fb923c", "#4ade80", "#60a5fa", "#f87171", "#c084fc"];

const ACCESS_OPTIONS = [
  { id: "issue", label: "Issue Certificate" },
  { id: "bulk", label: "Bulk Upload" },
  { id: "verify", label: "Verify" },
  { id: "list", label: "Certificates" },
  { id: "results", label: "Results" },
  { id: "analytics", label: "Analytics" },
  { id: "monitor", label: "Campus Monitor" },
  { id: "issues", label: "Issues" },
  { id: "activity", label: "Activity" },
  { id: "downloads", label: "Downloads" },
];

const DEFAULT_ACCESS = ["issue", "bulk", "verify", "list", "activity", "downloads"];

const ROLE_OPTIONS = [
  { id: "user", label: "Normal User", permissions: DEFAULT_ACCESS },
  { id: "department-head", label: "Department Head", permissions: ["list", "results", "verify", "analytics", "issues", "activity"] },
  { id: "privacy-manager", label: "Privacy Manager", permissions: ["verify", "issues", "activity", "downloads", "dpia"] },
  { id: "cybersecurity", label: "Cyber Security", permissions: ["monitor", "verify", "issues", "activity"] },
  { id: "hr", label: "HR", permissions: ["list", "results", "verify", "downloads", "activity"] },
  { id: "legal", label: "Legal", permissions: ["verify", "issues", "activity", "downloads"] },
  { id: "admin", label: "Admin", permissions: [] },
];

const roleLabel = (id: any) => {
  const r = ROLE_OPTIONS.find(o => o.id === id);
  return r ? r.label : "User";
};

const roleDefaults = (id: any) => {
  const r = ROLE_OPTIONS.find(o => o.id === id);
  return r && Array.isArray(r.permissions) ? [...r.permissions] : [];
};

function BarChart({ data, height = 180 }: { data?: any[] | null; height?: number }) {
  const max = Math.max(1, ...(data || []).map(d => d.value));
  return (
    <div className="bar-chart" style={{ height }}>
      {(data || []).map((d, i) => (
        <div key={i} className="bar-col" title={`${d.label}: ${d.value}`}>
          <span className="bar-value">{d.value}</span>
          <div className="bar" style={{ height: `${Math.max(4, (d.value / max) * 100)}%`, background: BAR_COLORS[i % BAR_COLORS.length] }} />
          <span className="bar-label">{d.label}</span>
        </div>
      ))}
    </div>
  );
}

const authHeaders = () => ({
  "x-admin-user": localStorage.getItem("admin_user") || "",
  "x-auth-token": localStorage.getItem("admin_token") || "",
});

let _watchingAuth = false;
function watchSessionExpiry() {
  if (_watchingAuth || typeof window === "undefined" || !window.fetch) return;
  _watchingAuth = true;
  const orig = window.fetch.bind(window);
  window.fetch = async (...args) => {
    const res = await orig(...args);
    const url = typeof args[0] === "string" ? args[0] : (args[0] as any)?.url || "";
    const hasToken = !!localStorage.getItem("admin_token");
    if (hasToken && url.includes("/api/") && (res.status === 401 || res.status === 403)) {
      try {
        const data = await res.clone().json();
        if (data && (data.error === "Admin access required" || /session|token/i.test(data.error || ""))) {
          ["admin_token", "admin_user", "admin_role", "admin_perms", "admin_depts", "admin_last_active"].forEach(k => localStorage.removeItem(k));
          window.location.hash = "#admin";
          window.location.reload();
        }
      } catch {}
    }
    return res;
  };
}
watchSessionExpiry();

const IDLE_TIMEOUT_MS = 10 * 60 * 1000;

function sha256(data: any) {
  const chars = "0123456789abcdef";
  const K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data);
  const len = bytes.length * 8;
  const ml = 64 + ((len + 64 >>> 9 << 4) + 1) * 64;
  const m = new Uint8Array(ml);
  m.set(bytes);
  m[bytes.length] = 0x80;
  new DataView(m.buffer).setUint32(ml - 4, len >>> 32, false);
  new DataView(m.buffer).setUint32(ml - 8, len & 0xffffffff, false);
  let H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  for (let i = 0; i < m.length; i += 64) {
    const W: any[] = []; let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    const dv = new DataView(m.buffer, i, 64);
    for (let t = 0; t < 16; t++) W[t] = dv.getUint32(t * 4, false);
    for (let t = 16; t < 64; t++) {
      const s0 = ((W[t-15]>>>7)|(W[t-15]<<25)) ^ ((W[t-15]>>>18)|(W[t-15]<<14)) ^ (W[t-15]>>>3);
      const s1 = ((W[t-2]>>>17)|(W[t-2]<<15)) ^ ((W[t-2]>>>19)|(W[t-2]<<13)) ^ (W[t-2]>>>10);
      W[t] = (W[t-16] + s0 + W[t-7] + s1) | 0;
    }
    for (let t = 0; t < 64; t++) {
      const S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
      const ch = (e & f) ^ ((~e) & g);
      const temp1 = (h + S1 + ch + K[t] + W[t]) | 0;
      const S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      h = g; g = f; f = e; e = (d + temp1) | 0; d = c; c = b; b = a; a = (temp1 + S0 + maj) | 0;
    }
    H = H.map((v, j) => (v + [a,b,c,d,e,f,g,h][j]) | 0);
  }
  return H.map(v => chars[(v>>>28)&15]+chars[(v>>>24)&15]+chars[(v>>>20)&15]+chars[(v>>>16)&15]+chars[(v>>>12)&15]+chars[(v>>>8)&15]+chars[(v>>>4)&15]+chars[v&15]).join("");
}

export default function AdminPage({ onBack }: { onBack: () => void }) {
  const [loggedIn, setLoggedIn] = useState(false);
  const [checkingAuth, setCheckingAuth] = useState(true);
  const [loginUser, setLoginUser] = useState("");
  const [loginPass, setLoginPass] = useState("");
  const [loginError, setLoginError] = useState("");
  const [activeTab, setActiveTab] = useState("dashboard");
  const [stats, setStats] = useState<any>(null);
  const [analytics, setAnalytics] = useState<any>(null);
  const { theme, toggleTheme } = useTheme();
  const { brand } = useBrand();
  const [isAdmin, setIsAdmin] = useState(localStorage.getItem("admin_role") === "admin");
  const [currentUser, setCurrentUser] = useState(localStorage.getItem("admin_user") || "admin");
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    if (localStorage.getItem("admin_token")) {
      setLoggedIn(true);
    }
    setCheckingAuth(false);
  }, []);

  useEffect(() => {
    if (!loggedIn) return;
    const updateLastActive = () => {
      localStorage.setItem("admin_last_active", String(Date.now()));
    };
    const checkIdle = () => {
      const last = Number(localStorage.getItem("admin_last_active") || 0);
      if (Date.now() - last >= IDLE_TIMEOUT_MS) {
        localStorage.removeItem("admin_token");
        localStorage.removeItem("admin_user");
        localStorage.removeItem("admin_role");
        localStorage.removeItem("admin_perms");
        localStorage.removeItem("admin_depts");
        localStorage.removeItem("admin_last_active");
        setLoggedIn(false);
        setLoginError("Logged out due to inactivity (10 minutes). Please log in again.");
      }
    };
    const events = ["mousemove", "mousedown", "keydown", "touchstart", "scroll"];
    updateLastActive();
    events.forEach((e) => window.addEventListener(e, updateLastActive));
    const interval = setInterval(checkIdle, 15000);
    return () => {
      events.forEach((e) => window.removeEventListener(e, updateLastActive));
      clearInterval(interval);
    };
  }, [loggedIn]);

  const fetchStats = () => {
    fetch(`${API_BASE}/api/dashboard/stats`)
      .then(r => r.json())
      .then(d => setStats(d))
      .catch(() => {});
    fetch(`${API_BASE}/api/dashboard/analytics`)
      .then(r => r.json())
      .then(d => setAnalytics(d))
      .catch(() => {});
  };

  useEffect(() => {
    if (loggedIn && activeTab === "dashboard") {
      setStats(null);
      setAnalytics(null);
      fetchStats();
    }
  }, [loggedIn, activeTab]);

  const handleLogin = async () => {
    setLoginError("");
    try {
      const res = await fetch(`${API_BASE}/api/admin/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: loginUser, password: loginPass }),
      });
      const data = await res.json();
      if (data.success) {
        setLoggedIn(true);
        localStorage.setItem("admin_token", data.token || "1");
        localStorage.setItem("admin_user", data.user || loginUser);
        localStorage.setItem("admin_role", data.role || "admin");
        localStorage.setItem("admin_perms", JSON.stringify(data.permissions || []));
        localStorage.setItem("admin_depts", JSON.stringify(data.departments || []));
        localStorage.setItem("admin_last_active", String(Date.now()));
        setIsAdmin((data.role || "admin") === "admin");
        setCurrentUser(data.user || loginUser);
      } else {
        setLoginError("Invalid username or password");
      }
    } catch {
      setLoginError("Login failed. Is the server running?");
    }
  };

  if (checkingAuth) return null;

  if (!loggedIn) {
    return (
      <div className="page">
        <div className="card login-form">
          <button className="btn-back" onClick={onBack}>Back</button>
          <div style={{ textAlign: "center", fontSize: "48px", margin: "16px 0 8px" }}>🔐</div>
          <h1>Admin Login</h1>
          <p style={{ textAlign: "center", color: "#64748b", fontSize: "14px", marginBottom: "24px" }}>
            Enter admin credentials to access the portal
          </p>
          <div className="input-group">
            <label>Username</label>
            <input type="text" placeholder="Enter username" value={loginUser}
              onChange={(e) => setLoginUser(e.target.value)} />
          </div>
          <div className="input-group">
            <label>Password</label>
            <input type="password" placeholder="Enter password" value={loginPass}
              onChange={(e) => setLoginPass(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleLogin()} />
          </div>
          <button className="btn-primary" onClick={handleLogin} style={{ marginTop: "8px" }}>
            Login
          </button>
          {loginError && <p style={{ color: "#fca5a5", fontSize: "14px", textAlign: "center", marginTop: "12px" }}>{loginError}</p>}
        </div>
      </div>
    );
  }

  const userPerms = JSON.parse(localStorage.getItem("admin_perms") || "[]");
  let userDepts = [];
  try { userDepts = JSON.parse(localStorage.getItem("admin_depts") || "[]"); } catch { userDepts = []; }
  const can = (id: any) =>
    isAdmin ||
    userPerms.includes(id) ||
    (userPerms.length === 0 && !isAdmin && DEFAULT_ACCESS.includes(id));

  const navItems = [
    { id: "dashboard", label: "Dashboard", icon: "📊", show: true },
    { id: "monitor", label: "Campus Monitor", icon: "🛡️", show: can("monitor") },
    { id: "issue", label: "Issue Certificate", icon: "📜", show: can("issue") },
    { id: "bulk", label: "Bulk Upload", icon: "📦", show: can("bulk") },
    { id: "verify", label: "Verify", icon: "✅", show: can("verify") },
    { id: "list", label: "Certificates", icon: "🏆", show: can("list") },
    { id: "results", label: "Results", icon: "🎯", show: can("results") },
    { id: "analytics", label: "Analytics", icon: "📈", show: can("analytics") },
    { id: "issues", label: "Issues", icon: "🚩", show: can("issues") },
    { id: "dpia", label: "DPIA", icon: "🛡️", show: isAdmin || can("dpia") },
    { id: "activity", label: "Activity", icon: "🕒", show: true },
    { id: "users", label: "Users", icon: "👥", show: isAdmin },
    { id: "settings", label: "Settings", icon: "⚙️", show: isAdmin },
    { id: "downloads", label: "Downloads", icon: "⬇️", show: can("downloads") },
  ].filter(n => n.show);

  const currentLabel = navItems.find(n => n.id === activeTab)?.label || "Dashboard";

  return (
    <div className="admin-shell">
      <aside className={`admin-sidebar ${sidebarOpen ? "open" : ""}`}>
        <div className="admin-sidebar-brand">
          <Logo size={40} />
          <div className="admin-sidebar-name">
            <span className="admin-sidebar-title">{brand.name || "University"}</span>
            <span className="admin-sidebar-sub">Admin Portal</span>
          </div>
        </div>
        <nav className="admin-nav">
          {navItems.map(item => (
            <button
              key={item.id}
              className={`admin-nav-item ${activeTab === item.id ? "active" : ""}`}
              onClick={() => { setActiveTab(item.id); setSidebarOpen(false); }}
            >
              <span className="admin-nav-icon">{item.icon}</span>
              <span>{item.label}</span>
            </button>
          ))}
        </nav>
        <div className="admin-sidebar-foot">
          <span className="badge user-role" style={{ alignSelf: "flex-start" }}>
            {isAdmin ? `👑 ${currentUser} (Admin)` : `👤 ${currentUser} (${roleLabel(localStorage.getItem("admin_role"))})`}
          </span>
          {!isAdmin && (
            <div style={{ alignSelf: "flex-start", marginTop: "6px", display: "flex", flexWrap: "wrap", gap: "4px", alignItems: "center" }}>
              <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Departments:</span>
              {(userDepts || []).length === 0 ? (
                <span className="badge connected">All</span>
              ) : (
                userDepts.map((d: any, i: any) => (
                  <span key={i} className="badge" style={{ fontSize: "10px", maxWidth: "100%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={d}>
                    {d}
                  </span>
                ))
              )}
            </div>
          )}
        </div>
      </aside>
      {sidebarOpen && <div className="admin-overlay" onClick={() => setSidebarOpen(false)} />}

      <div className="admin-main">
        <header className="admin-topbar">
          <button className="btn-back admin-hamburger" onClick={() => setSidebarOpen(true)}>☰</button>
          <div className="admin-topbar-title">
            <span className="admin-crumb">Admin</span>
            <span className="admin-crumb-sep">/</span>
            <strong>{currentLabel}</strong>
          </div>
          <div className="admin-topbar-actions">
            <button className="btn-theme" onClick={toggleTheme}>{theme === "dark" ? "☀️" : "🌙"}</button>
            <span className={`badge ${isAdmin ? "connected" : "user-role"}`}>{isAdmin ? "Admin" : `${roleLabel(localStorage.getItem("admin_role"))}: ${currentUser}`}</span>
            <button className="btn-logout" onClick={() => {
              if (window.confirm("Logout and go back to home page?")) {
                localStorage.removeItem("admin_token");
                localStorage.removeItem("admin_role");
                localStorage.removeItem("admin_perms");
                localStorage.removeItem("admin_depts");
                localStorage.removeItem("admin_last_active");
                onBack();
              }
            }}>Logout</button>
          </div>
        </header>

        <main className="admin-content">
          {activeTab === "dashboard" && <Dashboard stats={stats} analytics={analytics} onRefresh={fetchStats} />}
          {activeTab === "monitor" && can("monitor") && <MonitorSection />}
          {activeTab === "issue" && can("issue") && <IssueCertificate />}
          {activeTab === "bulk" && can("bulk") && <BulkUpload />}
          {activeTab === "verify" && can("verify") && <VerifySection />}
          {activeTab === "list" && can("list") && <CertificatesList />}
          {activeTab === "results" && can("results") && <ResultsSection />}
          {activeTab === "analytics" && can("analytics") && <AnalyticsSection />}
          {activeTab === "issues" && can("issues") && <IssuesSection />}
          {activeTab === "dpia" && (isAdmin || can("dpia")) && <DPIASection />}
          {activeTab === "activity" && <ActivityLog />}
          {activeTab === "users" && isAdmin && <UsersSection />}
          {activeTab === "settings" && isAdmin && <SettingsSection />}
          {activeTab === "downloads" && can("downloads") && <DownloadsSection />}
        </main>
      </div>
    </div>
  );
}

function Dashboard({ stats, analytics, onRefresh }: { stats: any; analytics: any; onRefresh: () => void }) {
  if (!stats) {
    return <div className="section"><p style={{ color: "#64748b" }}>Loading stats...</p></div>;
  }
  return (
    <div className="section">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
        <h2 style={{ margin: 0, border: "none", padding: 0 }}>Dashboard</h2>
        <button className="btn-secondary" onClick={onRefresh} style={{ padding: "6px 12px", fontSize: "12px" }}>Refresh</button>
      </div>
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">📜</div>
          <div className="stat-value">{stats.total}</div>
          <div className="stat-label">Total Certificates</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">📅</div>
          <div className="stat-value">{stats.today}</div>
          <div className="stat-label">Issued Today</div>
        </div>
        {analytics && <>
          <div className="stat-card">
            <div className="stat-icon">🏛️</div>
            <div className="stat-value">{analytics.totalDepartments}</div>
            <div className="stat-label">Total Departments</div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">🎯</div>
            <div className="stat-value">{analytics.totalResults}</div>
            <div className="stat-label">Total Results</div>
          </div>
          {analytics.issues && <>
            <div className="stat-card">
              <div className="stat-icon">🚩</div>
              <div className="stat-value" style={{ color: "#fbbf24" }}>{analytics.issues.open}</div>
              <div className="stat-label">Open Issues</div>
            </div>
            <div className="stat-card">
              <div className="stat-icon">✅</div>
              <div className="stat-value" style={{ color: "#22c55e" }}>{analytics.issues.resolved}</div>
              <div className="stat-label">Resolved Issues</div>
            </div>
            <div className="stat-card">
              <div className="stat-icon">⛔</div>
              <div className="stat-value" style={{ color: "#ef4444" }}>{analytics.issues.rejected}</div>
              <div className="stat-label">Rejected Issues</div>
            </div>
          </>}
        </>}
      </div>

      {analytics && (
        <>
          <div className="chart-panel" style={{ marginTop: "20px" }}>
            <h3>Certificates Issued (Last 7 Days)</h3>
            <BarChart height={240} data={(analytics.byDay || []).map((d: any) => ({ label: d.day.slice(5), value: d.count }))} />
          </div>

          <div style={{ display: "flex", gap: "20px", flexWrap: "wrap", marginTop: "20px" }}>
            <div className="chart-panel" style={{ flex: "1", minWidth: "300px" }}>
              <h3>Department-wise Results</h3>
              <BarChart height={220} data={(analytics.byDepartment || []).map((d: any) => ({ label: d.department, value: d.count }))} />
            </div>

            <div className="chart-panel" style={{ flex: "1", minWidth: "300px" }}>
              <h3>Semester-wise Results</h3>
              <BarChart height={220} data={(analytics.bySemester || []).map((s: any) => ({ label: s.semester, value: s.count }))} />
            </div>

            {analytics.issues && (
              <div className="chart-panel" style={{ flex: "1", minWidth: "300px" }}>
                <h3>Issues</h3>
                <BarChart height={220} data={[
                  { label: "Open", value: analytics.issues.open },
                  { label: "Resolved", value: analytics.issues.resolved },
                  { label: "Rejected", value: analytics.issues.rejected },
                ]} />
              </div>
            )}
          </div>
        </>
      )}

      </div>
  );
}

function IssueCertificate() {
  const [file, setFile] = useState<any>(null);
  const [hash, setHash] = useState("");
  const [ipfsHash, setIpfsHash] = useState("");
  const [status, setStatus] = useState("");
  const [name, setName] = useState("");
  const [rollNumber, setRollNumber] = useState("");
  const [course, setCourse] = useState("");
  const [department, setDepartment] = useState("");
  const [year, setYear] = useState("");
  const [email, setEmail] = useState("");
  const [successPopup, setSuccessPopup] = useState<any>(null);

  const autoProcessFile = async (selectedFile: any) => {
    setFile(selectedFile);
    if (!selectedFile) return;
    setStatus("Hashing file...");
    const buffer = new Uint8Array(await selectedFile.arrayBuffer());
    const hex = sha256(buffer);
    setHash(hex);
    setStatus("Uploading to IPFS...");
    try {
      const formData = new FormData();
      formData.append("file", selectedFile);
      const res = await fetch(`${API_BASE}/upload`, { method: "POST", body: formData });
      const data = await res.json();
      if (!data.data.cid) { setStatus("IPFS upload failed"); return; }
      setIpfsHash(data.data.cid);
      setStatus("Ready to store on blockchain");
    } catch {
      setStatus("IPFS upload error");
    }
  };

  const addCertificate = async () => {
    try {
      if (!name) return alert("Student name is required");
      if (!rollNumber) return alert("Roll number is required");
      if (!file || !hash || !ipfsHash) return alert("Please select and upload a certificate file");
      setStatus("Sending to blockchain...");
      const res = await fetch(`${API_BASE}/api/certificates/blockchain`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hash, name, ipfsHash }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setStatus("Stored on Blockchain");
      await fetch(`${API_BASE}/api/certificates`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hash, name, rollNumber, course, department, year, email, ipfsHash, txHash: data.txHash }),
      });
      setSuccessPopup({ name, hash, rollNumber, txHash: data.txHash });
    } catch (err: any) {
      setStatus(`Transaction failed: ${err.message}`);
    }
  };

  return (
    <div className="section">
      <h2>Issue Certificate</h2>
      <div className="form-grid">
        <div className="input-group">
          <label>Student Name <span className="required">*</span></label>
          <input type="text" placeholder="e.g. John Doe" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="input-group">
          <label>Roll Number <span className="required">*</span></label>
          <input type="text" placeholder="e.g. 2021001" value={rollNumber} onChange={(e) => setRollNumber(e.target.value)} />
        </div>
        <div className="input-group">
          <label>Course</label>
          <input type="text" placeholder="e.g. B.Tech" value={course} onChange={(e) => setCourse(e.target.value)} />
        </div>
        <div className="input-group">
          <label>Department</label>
          <input type="text" placeholder="e.g. Computer Science" value={department} onChange={(e) => setDepartment(e.target.value)} />
        </div>
        <div className="input-group">
          <label>Year</label>
          <input type="text" placeholder="e.g. 2024" value={year} onChange={(e) => setYear(e.target.value)} />
        </div>
        <div className="input-group">
          <label>Email</label>
          <input type="email" placeholder="e.g. student@xyz.edu" value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
      </div>

      <div className="input-group">
        <label>Certificate File (PDF/Image)</label>
        <div className="file-input-wrapper">
          <input type="file" onChange={(e) => autoProcessFile(e.target.files?.[0])} />
        </div>
        {file && <p style={{ fontSize: "12px", color: "#64748b", marginTop: "4px" }}>Selected: {file.name}</p>}
      </div>

      {hash && (
        <div style={{ marginTop: "8px", fontSize: "12px", color: "#64748b" }}>
          <div>Hash: <span className="hash-text">{hash}</span></div>
        </div>
      )}
      {ipfsHash && (
        <div style={{ marginTop: "4px", fontSize: "12px", color: "#64748b" }}>
          <div>IPFS: <span className="hash-text">{ipfsHash}</span></div>
          <a className="link" href={`https://ipfs.io/ipfs/${ipfsHash}`} target="_blank" rel="noreferrer">View on IPFS</a>
        </div>
      )}

      <button className="btn-success" onClick={addCertificate}
        disabled={!name || !rollNumber || !ipfsHash}
        style={{ marginTop: "16px", width: "100%", ...(!name || !rollNumber || !ipfsHash ? { opacity: 0.5, cursor: "not-allowed" } : {}) }}>
        Add Certificate to Blockchain
      </button>

      {status && <div className="status">{status}</div>}

      {successPopup && (
        <div style={{
          position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
          background: "rgba(0,0,0,0.6)", display: "flex",
          alignItems: "center", justifyContent: "center", zIndex: 1000,
        }} onClick={() => setSuccessPopup(null)}>
          <div style={{
            background: "var(--card-bg)", border: "1px solid rgba(34,197,94,0.4)",
            borderRadius: "16px", padding: "28px", maxWidth: "440px",
            width: "90%", boxShadow: "0 20px 60px rgba(0,0,0,0.5)"
          }} onClick={(e) => e.stopPropagation()}>
            <div style={{ textAlign: "center", fontSize: "48px", marginBottom: "8px" }}>✅</div>
            <h2 style={{ textAlign: "center", color: "#86efac", border: "none", marginBottom: "16px" }}>
              Certificate Issued!
            </h2>
            <p style={{ fontSize: "14px", color: "var(--text-secondary)", textAlign: "center", marginBottom: "16px" }}>
              <strong style={{ color: "var(--text-primary)" }}>{successPopup.name}</strong> has been added to the blockchain.
            </p>
            <div style={{ background: "rgba(0,0,0,0.3)", borderRadius: "10px", padding: "14px", marginBottom: "16px" }}>
              <p style={{ fontSize: "13px", color: "#fbbf24", fontWeight: 600, marginBottom: "8px" }}>
                Save this hash to verify the certificate later:
              </p>
              <div className="hash-text" style={{ fontSize: "13px", userSelect: "all" }}>
                {successPopup.hash}
              </div>
              <button onClick={() => { navigator.clipboard.writeText(successPopup.hash); }}
                style={{ background: "none", border: "1px solid rgba(148,163,184,0.2)", color: "var(--text-secondary)", borderRadius: "6px", padding: "4px 10px", cursor: "pointer", fontSize: "12px", marginTop: "8px" }}>
                Copy Hash
              </button>
            </div>
            <button className="btn-primary" onClick={() => setSuccessPopup(null)}>
              Got it
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function BulkUpload() {
  const [csvFile, setCsvFile] = useState<any>(null);
  const [parsedRows, setParsedRows] = useState<any[]>([]);
  const [certFiles, setCertFiles] = useState<any[]>([]);
  const [bulkStatus, setBulkStatus] = useState("");
  const [bulkResults, setBulkResults] = useState<any[]>([]);
  const [bulkPopup, setBulkPopup] = useState<any>(null);

  const handleCsvFile = async (e: any) => {
    const f = e.target.files[0];
    if (!f) return;
    setCsvFile(f);
    setBulkResults([]);
    setBulkStatus("");
    try {
      const formData = new FormData();
      formData.append("file", f);
      const res = await fetch(`${API_BASE}/api/certificates/bulk-upload`, {
        method: "POST", body: formData,
      });
      const data = await res.json();
      if (data.rows) {
        setParsedRows(data.rows);
        setBulkStatus(`Parsed ${data.count} records`);
      } else {
        setBulkStatus("Error: " + (data.error || "Parse failed"));
      }
    } catch (err: any) {
      setBulkStatus("Upload error: " + err.message);
    }
  };

  const handleCertFiles = (e: any) => {
    const files = Array.from(e.target.files || []);
    setCertFiles(files);
  };

  const matchFileForRow = (row: any) => {
    const roll = (row.rollNumber || "").toString().toLowerCase().trim();
    const name = (row.name || "").toString().toLowerCase().trim();
    for (const f of certFiles) {
      const fname = f.name.replace(/\.[^/.]+$/, "").toLowerCase();
      if (roll && fname.includes(roll)) return f;
      if (name && fname.includes(name)) return f;
    }
    return null;
  };

  const unmatchedFiles = certFiles.filter(f => {
    const fname = f.name.replace(/\.[^/.]+$/, "").toLowerCase();
    return !parsedRows.some(row => {
      const roll = (row.rollNumber || "").toString().toLowerCase().trim();
      const name = (row.name || "").toString().toLowerCase().trim();
      return (roll && fname.includes(roll)) || (name && fname.includes(name));
    });
  });

  const rowsWithoutFile = parsedRows.filter(row => !matchFileForRow(row));

  const incompleteRows = parsedRows.filter(row => !row.name || !row.rollNumber);

  const allRowsComplete = parsedRows.length > 0 && incompleteRows.length === 0 && certFiles.length > 0;

  const processAll = async () => {
    if (!allRowsComplete) return;
    setBulkResults([]);
    setBulkStatus(`Processing ${parsedRows.length} certificates...`);

    const certs = [];
    for (let i = 0; i < parsedRows.length; i++) {
      const row = parsedRows[i];
      try {
        const matchedFile = matchFileForRow(row);
        let hash, ipfsHash;

        if (matchedFile) {
          setBulkStatus(`[${i + 1}/${parsedRows.length}] ${row.name} - uploading certificate file to IPFS...`);
          const buffer = new Uint8Array(await matchedFile.arrayBuffer());
          hash = sha256(buffer);
          const formData = new FormData();
          formData.append("file", matchedFile);
          const uploadRes = await fetch(`${API_BASE}/upload`, { method: "POST", body: formData });
          const uploadData = await uploadRes.json();
          ipfsHash = uploadData.data ? uploadData.data.cid : "";
        } else {
          const hashInput = `${row.name}-${row.rollNumber}-${i}`;
          hash = sha256(hashInput);
          setBulkStatus(`[${i + 1}/${parsedRows.length}] ${row.name} - uploading metadata to IPFS...`);
          const meta = { name: row.name, rollNumber: row.rollNumber, course: row.course, department: row.department, year: row.year, email: row.email, hash };
          const metaBlob = new Blob([JSON.stringify(meta, null, 2)], { type: "application/json" });
          const metaFile = new File([metaBlob], `${row.rollNumber || row.name}.json`, { type: "application/json" });
          const formData = new FormData();
          formData.append("file", metaFile);
          const uploadRes = await fetch(`${API_BASE}/upload`, { method: "POST", body: formData });
          const uploadData = await uploadRes.json();
          ipfsHash = uploadData.data ? uploadData.data.cid : "";
        }

        setBulkStatus(`[${i + 1}/${parsedRows.length}] ${row.name} - sending to blockchain...`);
        const bcRes = await fetch(`${API_BASE}/api/certificates/blockchain`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ hash, name: row.name, ipfsHash }),
        });
        const bcData = await bcRes.json();
        if (!bcRes.ok) throw new Error(bcData.error);

        certs.push({ hash, name: row.name, rollNumber: row.rollNumber || "", course: row.course || "", department: row.department || "", year: row.year || "", email: row.email || "", ipfsHash, txHash: bcData.txHash });
        setBulkStatus(`[${i + 1}/${parsedRows.length}] ${row.name} - done`);
        if (i < parsedRows.length - 1) await new Promise(r => setTimeout(r, 1500));
      } catch (err: any) {
        setBulkStatus(`[${i + 1}/${parsedRows.length}] ${row.name} - failed: ${err.message}`);
        return;
      }
    }

    try {
      const res = await fetch(`${API_BASE}/api/certificates/bulk-save`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ certificates: certs }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Save failed");
      setBulkResults(certs);
      setBulkStatus(`All ${data.saved} certificates processed!`);
      setBulkPopup(certs);
    } catch (err: any) {
      setBulkStatus(`Save failed: ${err.message}`);
    }
  };

  return (
    <div className="section">
        <h2>Bulk Upload (CSV / Excel)</h2>
        {bulkPopup && (
          <div style={{
            position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
            background: "rgba(0,0,0,0.6)", display: "flex",
            alignItems: "center", justifyContent: "center", zIndex: 1000,
          }} onClick={() => setBulkPopup(null)}>
            <div style={{
              background: "var(--card-bg)", border: "1px solid rgba(34,197,94,0.4)",
              borderRadius: "16px", padding: "28px", maxWidth: "480px",
              width: "90%", boxShadow: "0 20px 60px rgba(0,0,0,0.5)",
              maxHeight: "80vh", overflow: "auto"
            }} onClick={(e) => e.stopPropagation()}>
              <div style={{ textAlign: "center", fontSize: "48px", marginBottom: "8px" }}>✅</div>
              <h2 style={{ textAlign: "center", color: "#86efac", border: "none", marginBottom: "16px" }}>
                {bulkPopup.length} Certificates Issued!
              </h2>
              <div className="results-list">
                {bulkPopup.map((c: any, i: any) => (
                  <div key={i} className="result-item" style={{ marginBottom: "6px", padding: "10px" }}>
                    <p style={{ fontSize: "13px" }}><strong>#{i + 1} {c.name}</strong> {c.rollNumber && `(${c.rollNumber})`}</p>
                    <div className="hash-text" style={{ fontSize: "11px" }}>{c.hash}</div>
                  </div>
                ))}
              </div>
              <button className="btn-primary" onClick={() => setBulkPopup(null)} style={{ marginTop: "16px" }}>
                Done
              </button>
            </div>
          </div>
        )}

      <div className="demo-format">
        <p style={{ fontSize: "13px", fontWeight: 600, marginBottom: "8px" }}>Expected format (<strong>Name</strong> &amp; <strong>Roll Number</strong> required):</p>
        <div className="hash-text" style={{ fontSize: "12px", overflowX: "auto", whiteSpace: "nowrap" }}>
          Name,Roll Number,Course,Department,Year,Email<br />
          John Doe,2024001,B.Tech,Computer Science,2024,john@xyz.edu<br />
          Jane Smith,2024002,B.Tech,Information Technology,2024,jane@xyz.edu
        </div>
        <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "6px" }}>
          <strong>Name</strong> and <strong>Roll Number</strong> are required. Other columns are optional.<br />
          <a className="link" href="#" onClick={(e) => {
            e.preventDefault();
            const csv = "Name,Roll Number,Course,Department,Year,Email\nJohn Doe,2024001,B.Tech,Computer Science,2024,john@xyz.edu\nJane Smith,2024002,B.Tech,Information Technology,2024,jane@xyz.edu\nAlice Lee,2024003,M.Sc,Mathematics,2024,alice@xyz.edu";
            const blob = new Blob([csv], { type: "text/csv" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a"); a.href = url; a.download = "demo-certificates.csv"; a.click();
            URL.revokeObjectURL(url);
          }}>Download demo CSV</a>
        </p>
      </div>

      <div className="file-input-wrapper">
        <input type="file" accept=".csv,.xlsx" onChange={handleCsvFile} />
      </div>

      <div className="input-group">
        <label>Step 2 — Certificate Files (PDF/Image) <span style={{ fontWeight: 400, color: "var(--text-muted)" }}>(optional)</span></label>
        <div className="file-input-wrapper">
          <input type="file" multiple accept=".pdf,.png,.jpg,.jpeg" onChange={handleCertFiles} />
        </div>
        {certFiles.length > 0 && (
          <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "4px" }}>
            {certFiles.length} certificate file(s) selected.
          </p>
        )}
        <p style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "4px" }}>
          Name your files with the student's <strong>Roll Number</strong> or <strong>Name</strong> (e.g. <code>2024001.pdf</code> or <code>John_Doe.png</code>) so they match each student. If no file matches, a metadata record is used instead.
        </p>
      </div>

      {parsedRows.length > 0 && (
        <div style={{ marginTop: "16px" }}>
          <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "8px" }}>
            Preview ({parsedRows.length} records):
          </p>
          <div className="csv-preview">
            <table>
              <thead>
                <tr>
                  {Object.keys(parsedRows[0]).map((k, i) => <th key={i}>{k}</th>)}
                  <th>File</th>
                </tr>
              </thead>
              <tbody>
                {parsedRows.slice(0, 5).map((row, i) => {
                  const m = matchFileForRow(row);
                  const missing = (!row.name || !row.rollNumber);
                  return (
                    <tr key={i} style={missing ? { background: "rgba(239,68,68,0.12)" } : undefined}>
                      {Object.values(row as any).map((v: any, j: any) => <td key={j} style={missing ? { color: "#f87171" } : undefined}>{v || <em style={{ opacity: 0.5 }}>—</em>}</td>)}
                      <td style={{ color: m ? "#86efac" : "#fbbf24" }}>{m ? "✅ " + m.name : "⚠️ No file"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {parsedRows.length > 5 && <p style={{ fontSize: "12px", color: "#64748b", marginTop: "4px" }}>...and {parsedRows.length - 5} more</p>}
          </div>

          {certFiles.length > 0 && (unmatchedFiles.length > 0 || rowsWithoutFile.length > 0) && (
            <div className="mismatch-report">
              <div className="mismatch-title">
                ⚠️ <strong>File Mismatch Review</strong>
                <span className="mismatch-count">{(unmatchedFiles.length > 0 || rowsWithoutFile.length > 0) ? "Resolve before processing" : ""}</span>
              </div>

              {unmatchedFiles.length > 0 && (
                <div className="mismatch-block">
                  <p className="mismatch-head"><strong>{unmatchedFiles.length} certificate file(s)</strong> don't match any student in the CSV. They will be <em>ignored</em>.</p>
                  <div className="mismatch-files">
                    {unmatchedFiles.map((f, i) => <span key={i} className="mismatch-file">{f.name}</span>)}
                  </div>
                  <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "6px 0 0" }}>
                    Tip: rename the file with the student's Roll Number or Name (e.g. <code>2024001.pdf</code>) so it auto-matches.
                  </p>
                </div>
              )}

              {rowsWithoutFile.length > 0 && (
                <div className="mismatch-block">
                  <p style={{ margin: 0 }}>
                    <strong>{rowsWithoutFile.length} student(s)</strong> have <strong>no matching certificate file</strong>. A metadata record will be uploaded for them instead.
                  </p>
                  <div className="mismatch-files">
                    {rowsWithoutFile.map((r, i) => <span key={i} className="mismatch-file">{r.name} {r.rollNumber ? `(${r.rollNumber})` : ""}</span>)}
                  </div>
                </div>
              )}
            </div>
          )}
          {parsedRows.length > 0 && !allRowsComplete && (
            <div className="mismatch-report" style={{ borderColor: "var(--danger, #ef4444)" }}>
              <div className="mismatch-title" style={{ color: "var(--danger, #ef4444)" }}>
                ⚠️ <strong>Cannot Process</strong>
                <span className="mismatch-count">
                  {certFiles.length === 0
                    ? "No certificate files selected"
                    : `${incompleteRows.length} row(s) missing required fields`}
                </span>
              </div>
              {certFiles.length === 0 ? (
                <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: 0 }}>
                  Select certificate files in <strong>Step 2</strong> before processing. Name them with the student's Roll Number or Name.
                </p>
              ) : (
                <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: 0 }}>
                  Each row needs <strong>Name</strong> and <strong>Roll Number</strong>. Fill them in and re-upload the CSV to enable "Process All".
                </p>
              )}
            </div>
          )}
          <button
            className="btn-success"
            onClick={processAll}
            disabled={!allRowsComplete}
            style={{ marginTop: "12px", width: "100%", opacity: allRowsComplete ? 1 : 0.5, cursor: allRowsComplete ? "pointer" : "not-allowed" }}
          >
            {allRowsComplete ? `Process All (${parsedRows.length})` : certFiles.length === 0 ? "Process All (disabled — select certificate files)" : "Process All (disabled — complete required fields)"}
          </button>
        </div>
      )}
      {bulkStatus && <div className="status">{bulkStatus}</div>}
      {bulkResults.length > 0 && (
        <div style={{ marginTop: "16px" }}>
          <h3>Results</h3>
          <div className="results-list">
            {bulkResults.map((r, i) => (
              <div className="result-item" key={i}>
                <p><strong>#{i + 1} {r.name}</strong> {r.rollNumber && `(${r.rollNumber})`}</p>
                <div className="hash-text">Hash: {r.hash}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ActivityLog() {
  const [entries, setEntries] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");
  const canAdmin = localStorage.getItem("admin_role") === "admin";

  const load = useCallback(() => {
    setLoading(true);
    fetch(`${API_BASE}/api/activity`)
      .then(r => r.json())
      .then(d => { setEntries(d); setLoading(false); })
      .catch(() => { setLoading(false); });
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleClear = async () => {
    if (!window.confirm("Clear the entire activity log?")) return;
    try {
      await fetch(`${API_BASE}/api/activity`, { method: "DELETE", headers: authHeaders() });
      setEntries([]);
    } catch { alert("Clear failed"); }
  };

  const q = filter.toLowerCase().trim();
  const filtered = entries.filter(e => JSON.stringify(e).toLowerCase().includes(q));

  const infos = {
    CERTIFICATE_ISSUED: { icon: "🟢", label: "Certificate Issued" },
    CERTIFICATE_BULK_ISSUED: { icon: "📦", label: "Bulk Issued" },
    CERTIFICATE_DELETED: { icon: "🔴", label: "Certificate Deleted" },
    ADMIN_LOGIN: { icon: "🔐", label: "Admin Login" },
    USER_CREATED: { icon: "➕", label: "User Created" },
    USER_UPDATED: { icon: "✏️", label: "User Updated" },
    USER_DELETED: { icon: "🗑️", label: "User Deleted" },
    BRAND_UPDATED: { icon: "🏷️", label: "Branding Updated" },
  };

  const infoOf = (t: any) => (infos as any)[t] || { icon: "•", label: t || "Event" };

  return (
    <div className="section">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
        <h2 style={{ margin: 0, border: "none", padding: 0 }}>Activity Log</h2>
        {canAdmin && <div style={{ display: "flex", gap: "8px" }}>
          <button className="btn-secondary" onClick={load} style={{ padding: "6px 12px", fontSize: "12px" }}>Refresh</button>
          <button className="btn-del" onClick={handleClear}>Clear Log</button>
        </div>}
      </div>

      <input type="text" placeholder="Filter by name, hash, type..." value={filter}
        onChange={(e) => setFilter(e.target.value)} style={{ marginBottom: "16px" }} />

      {loading ? (
        <p style={{ color: "var(--text-secondary)" }}>Loading...</p>
      ) : filtered.length === 0 ? (
        <p style={{ color: "var(--text-secondary)" }}>No activity recorded yet.</p>
      ) : (
        <div className="activity-list">
          {filtered.map((e, i) => {
            const info = infoOf(e.type);
            const d = e.details || {};
            const when = new Date(e.timestamp);
            return (
              <div key={i} className="activity-item">
                <span className="activity-badge-pill" style={{ color: e.type === "CERTIFICATE_ISSUED" ? "#22c55e" : e.type === "CERTIFICATE_DELETED" || e.type === "USER_DELETED" ? "#ef4444" : "var(--accent)" }}>{e.type}</span>
                <div className="activity-body">
                  <div className="activity-title">{info.label}
                    {e.type === "ADMIN_LOGIN" && d.user && <span className="activity-name"> — <strong>{d.user}</strong> logged in</span>}
                    {e.type.startsWith("USER") && d.user && <span className="activity-name"> — <strong>{d.user}</strong>{d.role ? ` (${d.role})` : ""}</span>}
                    {e.type === "CERTIFICATE_ISSUED" && d.name && <span className="activity-name"> — <strong>{d.name}</strong>{d.rollNumber ? ` (${d.rollNumber})` : ""}</span>}
                    {e.type === "CERTIFICATE_ISSUED" && (d.onChain ? <span className="activity-badge onchain">On-chain</span> : <span className="activity-badge">Local only</span>)}
                    {e.type === "CERTIFICATE_DELETED" && d.name && <span className="activity-name"> — <strong>{d.name}</strong>{d.rollNumber ? ` (${d.rollNumber})` : ""}</span>}
                    {e.type === "CERTIFICATE_BULK_ISSUED" && d.count != null && <span className="activity-name"> — <strong>{d.count}</strong> {d.count === 1 ? "certificate" : "certificates"}</span>}
                    {e.type === "BRAND_UPDATED" && d.name && <span className="activity-name"> — <strong>{d.name}</strong></span>}
                    {e.type === "CERTIFICATE_DELETED" && !d.name && d.hash && <span className="activity-name"> — no data</span>}
                  </div>
                  <div className="activity-meta">
                    {when.toLocaleDateString()} {when.toLocaleTimeString()}
                    {d.hash && <span className="activity-hash" title={d.hash}>{d.hash}</span>}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
      <p style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "8px" }}>
        Showing {filtered.length} of {entries.length} events
      </p>
    </div>
  );
}

const EyeIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
    <circle cx="12" cy="12" r="3" />
  </svg>
);

const EyeOffIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
    <line x1="1" y1="1" x2="23" y2="23" />
  </svg>
);

function PwInput({ value, onChange, placeholder, style }: { value: any; onChange: (e: any) => void; placeholder: string; style?: any }) {
  const [show, setShow] = useState(false);
  return (
    <span className="pw-field" style={style}>
      <input type={show ? "text" : "password"} placeholder={placeholder} value={value} onChange={onChange}
        autoComplete="new-password" />
      <button type="button" className="pw-eye" onClick={() => setShow(v => !v)}
        title={show ? "Hide password" : "Show password"}
        aria-label={show ? "Hide password" : "Show password"}>
        {show ? <EyeOffIcon /> : <EyeIcon />}
      </button>
    </span>
  );
}

function UsersSection() {
  const [users, setUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [nUsername, setNUsername] = useState("");
  const [nPassword, setNPassword] = useState("");
  const [nRole, setNRole] = useState("user");
  const [nPerms, setNPerms] = useState(DEFAULT_ACCESS);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [resetFor, setResetFor] = useState("");
  const [resetPass, setResetPass] = useState("");
  const [editAccessFor, setEditAccessFor] = useState("");
  const [editPerms, setEditPerms] = useState<any[]>([]);
  const [nDepts, setNDepts] = useState<any[]>([]);
  const [allDepts, setAllDepts] = useState<any[]>([]);
  const [editDepts, setEditDepts] = useState<any[]>([]);
  const [filter, setFilter] = useState("");

  const me = localStorage.getItem("admin_user") || "";

const togglePerm = (list: any, id: any, setter: any) =>
    setter(list.includes(id) ? list.filter((p: any) => p !== id) : [...list, id]);

const handleRoleSelect = (e: any) => {
    const id = e.target.value;
    setNRole(id);
    if (id === "admin") {
      setNPerms([]);
      setNDepts([]);
    } else {
      setNPerms(roleDefaults(id));
      setNDepts([]);
    }
  };

  const load = useCallback(() => {
    setLoading(true);
    fetch(`${API_BASE}/api/users`, { headers: authHeaders() })
      .then(r => r.json())
      .then(d => { setUsers(Array.isArray(d) ? d : []); setLoading(false); })
      .catch(() => { setLoading(false); });
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    fetch(`${API_BASE}/api/departments`)
      .then(r => r.json())
      .then(d => {
        const names = Array.isArray(d)
          ? d.map(x => (typeof x === "string" ? x : x.name)).filter(Boolean)
          : d.departments || [];
        setAllDepts(names);
      })
      .catch(() => {});
  }, []);

  const handleCreate = async (e: any) => {
    e.preventDefault();
    setMsg(""); setErr("");
    if (!nUsername.trim()) return setErr("Username is required");
    if (nPassword.length < 4) return setErr("Password must be at least 4 characters");
    try {
      const res = await fetch(`${API_BASE}/api/users`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ username: nUsername.trim(), password: nPassword, role: nRole, permissions: nRole === "admin" ? [] : nPerms, departments: nRole === "admin" ? [] : nDepts })
      });
      const data = await res.json();
      if (data.success) {
        setMsg(`User "${nUsername.trim()}" created`);
        setNUsername(""); setNPassword(""); setNRole("user"); setNPerms(DEFAULT_ACCESS); setNDepts([]);
        load();
      } else {
        setErr(data.error || "Create failed");
      }
    } catch { setErr("Create failed"); }
  };

  const handleSaveAccess = async (username: any) => {
    setErr(""); setMsg("");
    try {
      const res = await fetch(`${API_BASE}/api/users/${username}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ permissions: editPerms, departments: editDepts })
      });
      const data = await res.json();
      if (data.success) {
        setMsg(`Access updated for "${username}"`);
        setEditAccessFor("");
        load();
      } else {
        setErr(data.error || "Update failed");
      }
    } catch { setErr("Update failed"); }
  };

  const handleRoleChange = async (u: any, newRole: any) => {
    if (newRole === u.role) return;
    const toAdmin = newRole === "admin";
    if (!window.confirm(`Change "${u.username}" role to "${roleLabel(newRole)}"?${toAdmin ? " (full access)" : ""}`)) return;
    setErr(""); setMsg("");
    try {
      const res = await fetch(`${API_BASE}/api/users/${u.username}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ role: newRole, permissions: toAdmin ? [] : roleDefaults(newRole) })
      });
      const data = await res.json();
      if (data.success) {
        if (toAdmin) {
          setEditAccessFor("");
          setResetFor("");
        }
        setMsg(`"${u.username}" is now ${roleLabel(newRole)}`);
        load();
      } else {
        setErr(data.error || "Role change failed");
      }
    } catch { setErr("Role change failed"); }
  };

  const handleReset = async (username: any) => {
    if (!resetPass || resetPass.length < 4) return setErr("New password must be at least 4 characters");
    setErr(""); setMsg("");
    try {
      const res = await fetch(`${API_BASE}/api/users/${username}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ password: resetPass })
      });
      const data = await res.json();
      if (data.success) {
        setMsg(`Password updated for "${username}"`);
        setResetFor(""); setResetPass("");
      } else {
        setErr(data.error || "Update failed");
      }
    } catch { setErr("Update failed"); }
  };

  const handleDeleteUser = async (username: any) => {
    if (!window.confirm(`Delete user "${username}"?`)) return;
    setErr(""); setMsg("");
    const res = await fetch(`${API_BASE}/api/users/${username}`, { method: "DELETE", headers: authHeaders() });
    const data = await res.json();
    if (data.success) {
      setMsg(`User "${username}" deleted`);
      load();
    } else {
      setErr(data.error || "Delete failed");
    }
  };

  const q = filter.toLowerCase().trim();
  const filteredUsers = users.filter(u =>
    !q ||
    u.username.toLowerCase().includes(q) ||
    (u.role || "").toLowerCase().includes(q) ||
    roleLabel(u.role).toLowerCase().includes(q) ||
    (u.permissions || []).some((p: any) => p.toLowerCase().includes(q)) ||
    (u.departments || []).some((d: any) => d.toLowerCase().includes(q))
  );

  return (
    <div className="section">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
        <h2 style={{ margin: 0, border: "none", padding: 0 }}>User Management</h2>
        <button className="btn-secondary" onClick={load} style={{ padding: "6px 12px", fontSize: "12px" }}>Refresh</button>
      </div>
      <p style={{ color: "var(--text-secondary)", fontSize: "13px", marginTop: "6px" }}>
        Create login accounts and manage passwords for university staff.
      </p>

      {err && <p className="form-error">{err}</p>}
      {msg && <p className="form-success">{msg}</p>}

      <div className="demo-format">
        <strong>Create New User</strong>
        <form className="user-create" onSubmit={handleCreate}>
          <input type="text" placeholder="Username" value={nUsername} onChange={(e) => setNUsername(e.target.value)} />
          <PwInput placeholder="Password (min 4 chars)" value={nPassword} onChange={(e) => setNPassword(e.target.value)} />
          <select value={nRole} onChange={handleRoleSelect}>
            {ROLE_OPTIONS.filter(o => o.id !== "admin").map(o => <option key={o.id} value={o.id}>{o.label}</option>)}
            <option value="admin">Admin</option>
          </select>
          <button className="btn-primary" type="submit" style={{ padding: "10px 16px" }}>Create User</button>
        </form>

        {nRole !== "admin" && (
          <div style={{ marginTop: "12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px", flexWrap: "wrap" }}>
              <span style={{ fontSize: "13px", fontWeight: 600 }}>Section Access:</span>
              <button type="button" className="btn-secondary" style={{ padding: "3px 10px", fontSize: "11px" }}
                onClick={() => setNPerms(ACCESS_OPTIONS.map(o => o.id))}>Select All</button>
              <button type="button" className="btn-secondary" style={{ padding: "3px 10px", fontSize: "11px" }}
                onClick={() => setNPerms([])}>Clear</button>
              <button type="button" className="btn-secondary" style={{ padding: "3px 10px", fontSize: "11px" }}
                onClick={() => setNPerms(DEFAULT_ACCESS)}>Default</button>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(170px, 1fr))", gap: "6px" }}>
              {ACCESS_OPTIONS.map(opt => (
                <label key={opt.id} style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", cursor: "pointer" }}>
                  <input type="checkbox" checked={nPerms.includes(opt.id)}
                    onChange={() => togglePerm(nPerms, opt.id, setNPerms)} />
                  {opt.label}
                </label>
              ))}
            </div>
          </div>
        )}
        {nRole !== "admin" && allDepts.length > 0 && (
          <div style={{ marginTop: "14px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px", flexWrap: "wrap" }}>
              <span style={{ fontSize: "13px", fontWeight: 600 }}>Department Access:</span>
              <button type="button" className="btn-secondary" style={{ padding: "3px 10px", fontSize: "11px" }}
                onClick={() => setNDepts(allDepts)}>Select All</button>
              <button type="button" className="btn-secondary" style={{ padding: "3px 10px", fontSize: "11px" }}
                onClick={() => setNDepts([])}>Clear</button>
              <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>Leave empty for all departments</span>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: "6px" }}>
              {allDepts.map(d => (
                <label key={d} style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "13px", cursor: "pointer" }}>
                  <input type="checkbox" checked={nDepts.includes(d)}
                    onChange={() => togglePerm(nDepts, d, setNDepts)} />
                  {d}
                </label>
              ))}
            </div>
          </div>
        )}
        {nRole === "admin" && (
          <p style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "8px" }}>
            Admins automatically get access to every section.
          </p>
        )}
      </div>

      {loading ? (
        <p style={{ color: "var(--text-secondary)" }}>Loading...</p>
      ) : users.length === 0 ? (
        <p style={{ color: "var(--text-secondary)" }}>No users yet.</p>
      ) : (
        <>
          <input type="text" placeholder="Search by username, role, access, or department..." value={filter}
            onChange={(e) => setFilter(e.target.value)} style={{ marginBottom: "16px" }} />
          <div className="list-table-wrap">
            <table className="certs-table">
              <thead><tr><th>Username</th><th>Role</th><th>Access</th><th>Created</th><th>Change Password</th><th>Action</th></tr></thead>
              <tbody>
                {filteredUsers.map(u => (
                  <tr key={u.username}>
                    <td><strong>{u.username}</strong>{u.username === me && <span style={{ fontSize: "11px", color: "var(--text-muted)" }}> (you)</span>}</td>
                    <td>
                      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "6px" }}>
                        <span className={`role-badge ${u.role === "admin" ? "admin" : "user"}`}>{roleLabel(u.role)}</span>
                        {!(u.username === me || u.username === "admin") && (
                          <select
                            value={u.role}
                            title="Change role"
                            onChange={(e) => handleRoleChange(u, e.target.value)}
                            style={{ padding: "2px 4px", fontSize: "11px", width: "150px", maxWidth: "100%", borderRadius: "6px", background: "var(--card-bg, #1e293b)", color: "var(--text-primary, #e2e8f0)", border: "1px solid var(--card-border, #334155)" }}
                          >
                            {ROLE_OPTIONS.map(o => (
                              <option key={o.id} value={o.id}>{o.label}</option>
                            ))}
                          </select>
                        )}
                      </div>
                    </td>
                  <td>
                    {editAccessFor === u.username && u.role !== "admin" ? (
                      <div style={{ minWidth: "220px" }}>
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "4px", marginBottom: "8px" }}>
                          {ACCESS_OPTIONS.map(opt => (
                            <label key={opt.id} style={{ display: "flex", alignItems: "center", gap: "5px", fontSize: "12px", cursor: "pointer" }}>
                              <input type="checkbox" checked={editPerms.includes(opt.id)}
                                onChange={() => togglePerm(editPerms, opt.id, setEditPerms)} />
                              {opt.label}
                            </label>
                          ))}
                        </div>
                        {u.role !== "admin" && allDepts.length > 0 && (
                          <div style={{ marginBottom: "8px" }}>
                            <p style={{ fontSize: "11px", fontWeight: 600, margin: "0 0 4px", opacity: 0.8 }}>
                              Departments:{" "}
                              <span style={{ fontWeight: 400, fontStyle: "italic", color: editDepts.length === 0 ? "var(--accent)" : "inherit", opacity: 0.85 }}>
                                {editDepts.length === 0 ? "none selected — user gets all departments" : `${editDepts.length} of ${allDepts.length} selected`}
                              </span>
                            </p>
                            <div style={{ maxHeight: "120px", overflowY: "auto" }}>
                              {allDepts.map(d => (
                                <label key={d} style={{ display: "flex", alignItems: "center", gap: "5px", fontSize: "12px", cursor: "pointer" }}>
                                  <input type="checkbox" checked={editDepts.includes(d)}
                                    onChange={() => togglePerm(editDepts, d, setEditDepts)} />
                                  {d}
                                </label>
                              ))}
                            </div>
                          </div>
                        )}
                        <div style={{ display: "flex", gap: "6px" }}>
                          <button className="btn-secondary" style={{ padding: "4px 10px", fontSize: "12px" }}
                            onClick={() => handleSaveAccess(u.username)}>Save Access</button>
                          <button className="btn-del" style={{ padding: "4px 10px", fontSize: "12px" }}
                            onClick={() => setEditAccessFor("")}>Cancel</button>
                        </div>
                      </div>
                    ) : u.role === "admin" ? (
                      <span className="badge connected">All sections</span>
                    ) : (
                      <span style={{ display: "flex", flexWrap: "wrap", gap: "4px", alignItems: "center" }}>
                        {(u.permissions || []).length === 0 && <em style={{ fontSize: "12px", opacity: 0.6 }}>No access</em>}
                        {(u.permissions || []).map((p: any) => {
                          const opt = ACCESS_OPTIONS.find(o => o.id === p);
                          return <span key={p} className="badge" style={{ fontSize: "11px" }}>{opt ? opt.label : p}</span>;
                        })}
                        <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                          Dept: {(u.departments || []).length === 0 ? "All" : u.departments.length}
                        </span>
                        <button className="btn-secondary reset" style={{ padding: "2px 8px", fontSize: "11px" }}
                          onClick={() => { setEditAccessFor(u.username); setEditPerms(u.permissions || []); setEditDepts(u.departments || []); }}>
                          Edit
                        </button>
                      </span>
                    )}
                  </td>
                  <td>{u.createdAt ? new Date(u.createdAt).toLocaleDateString() : "-"}</td>
                  <td>
                    {resetFor === u.username ? (
                      <span style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                        <PwInput placeholder="New password" value={resetPass} onChange={(e) => setResetPass(e.target.value)}
                          style={{ width: "160px", minWidth: "160px" }} />
                        <button className="btn-secondary" style={{ padding: "4px 10px", fontSize: "12px" }}
                          onClick={() => handleReset(u.username)}>Save</button>
                        <button className="btn-del" style={{ padding: "4px 10px", fontSize: "12px" }}
                          onClick={() => setResetFor("")}>X</button>
                      </span>
                    ) : (
                      <button className="btn-secondary reset" style={{ padding: "4px 10px", fontSize: "12px" }}
                        onClick={() => { setResetFor(u.username); setResetPass(""); }}>
                        Set Password
                      </button>
                    )}
                  </td>
                  <td>
                    <button className="btn-del" style={{ padding: "4px 10px", fontSize: "12px" }}
                      onClick={() => handleDeleteUser(u.username)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
          {filteredUsers.length === 0 && <p style={{ color: "var(--text-secondary)" }}>No users match "{filter}".</p>}
        </>
      )}
    </div>
  );
}

function SettingsSection() {
  const { brand, setBrand } = useBrand();
  const [name, setName] = useState(brand.name);
  const [shortName, setShortName] = useState(brand.shortName);
  const [logo, setLogo] = useState(brand.logo);
  const [preview, setPreview] = useState(brand.logo);
  const [saving, setSaving] = useState(false);
  const [savedMsg, setSavedMsg] = useState("");
  const [pwUser, setPwUser] = useState("");
  const [pwNew, setPwNew] = useState("");
  const [pwConfirm, setPwConfirm] = useState("");
  const [pwMsg, setPwMsg] = useState("");
  const [pwErr, setPwErr] = useState("");

  const currentUser = localStorage.getItem("admin_user") || "admin";

  const handlePassword = async () => {
    setPwErr(""); setPwMsg("");
    if (!pwUser.trim()) return setPwErr("Username is required");
    if (pwNew.length < 4) return setPwErr("New password must be at least 4 characters");
    if (pwNew !== pwConfirm) return setPwErr("Passwords do not match");
    try {
      const res = await fetch(`${API_BASE}/api/users/${encodeURIComponent(pwUser.trim())}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ password: pwNew })
      });
      const data = await res.json();
      if (data.success) {
        setPwMsg(`Password updated for "${pwUser.trim()}"`);
        setPwNew(""); setPwConfirm("");
      } else {
        setPwErr(data.error || "Update failed");
      }
    } catch { setPwErr("Update failed"); }
  };

  useEffect(() => {
    setName(brand.name);
    setShortName(brand.shortName);
    setLogo(brand.logo);
    setPreview(brand.logo);
  }, [brand]);

  const onPickLogo = (e: any) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    if (file.size > 800 * 1024) return alert("Logo must be under 800KB");
    const reader = new FileReader();
    reader.onload = () => {
      setLogo(typeof reader.result === "string" ? reader.result : null);
      setPreview(typeof reader.result === "string" ? reader.result : null);
    };
    reader.readAsDataURL(file);
  };

  const handleSave = async () => {
    if (!name.trim()) return alert("University name is required");
    setSaving(true);
    setSavedMsg("");
    try {
      const res = await fetch(`${API_BASE}/api/brand`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ name, shortName, logo })
      });
      const data = await res.json();
      if (data.success) {
        setBrand(data.brand);
        setSavedMsg("Saved! Branding updated across the app.");
      } else {
        alert("Save failed");
      }
    } catch {
      alert("Save failed");
    }
    setSaving(false);
  };

  return (
    <div className="section">
      <h2 style={{ margin: 0, border: "none", padding: 0 }}>University Branding</h2>
      <p style={{ color: "var(--text-secondary)", fontSize: "13px", marginTop: "6px" }}>
        Change the university name and logo shown on the public site.
      </p>

      <div className="brand-card">
        <div className="brand-preview">
          {preview ? (
            <img src={preview} alt="logo preview" className="brand-logo-preview" />
          ) : (
            <div className="brand-logo-placeholder">{(shortName || "U").toUpperCase()}</div>
          )}
          <span style={{ fontSize: "13px", color: "var(--text-muted)" }}>Preview</span>
        </div>

        <div className="brand-form">
          <label className="flabel">
            University Name <span className="required">*</span>
            <input type="text" value={name} onChange={(e) => setName(e.target.value)}
              placeholder="e.g. MIT University" />
          </label>
          <label className="flabel">
            Short Name (for default logo)
            <input type="text" value={shortName} onChange={(e) => setShortName(e.target.value)}
              placeholder="e.g. MIT" maxLength={6} />
          </label>
          <label className="flabel">
            Logo <span className="muted-sm">(PNG/JPG, under 800KB — used on landing page)</span>
            <input type="file" accept="image/png,image/jpeg,image/webp,image/svg+xml" onChange={onPickLogo} />
          </label>
          {logo && (
            <div style={{ display: "flex", gap: "8px" }}>
              <button className="btn-secondary" style={{ padding: "6px 12px", fontSize: "12px" }}
                onClick={() => { setLogo(null); setPreview(null); }}>Remove Logo</button>
            </div>
          )}
          <div style={{ display: "flex", alignItems: "center", gap: "12px", marginTop: "4px" }}>
            <button className="btn-primary" onClick={handleSave} disabled={saving}>
              {saving ? "Saving..." : "Save Branding"}
            </button>
            {savedMsg && <span style={{ color: "#22c55e", fontSize: "13px" }}>{savedMsg}</span>}
          </div>
        </div>
      </div>

      <h2 style={{ margin: "28px 0 0", border: "none", padding: 0 }}>Change Password</h2>
      <p style={{ color: "var(--text-secondary)", fontSize: "13px", marginTop: "6px" }}>
        Update the password for a user account.
      </p>
      <div className="brand-card" style={{ flexDirection: "column", alignItems: "stretch" }}>
        {pwErr && <p className="form-error">{pwErr}</p>}
        {pwMsg && <p className="form-success">{pwMsg}</p>}
        <label className="flabel">
          Username <span className="required">*</span>
          <input type="text" value={pwUser} onChange={(e) => setPwUser(e.target.value)}
            placeholder={currentUser} />
        </label>
        <label className="flabel">
          New Password <span className="required">*</span>
          <input type="password" value={pwNew} onChange={(e) => setPwNew(e.target.value)}
            placeholder="At least 4 characters" />
        </label>
        <label className="flabel">
          Confirm New Password <span className="required">*</span>
          <input type="password" value={pwConfirm} onChange={(e) => setPwConfirm(e.target.value)}
            placeholder="Repeat new password" />
        </label>
        <div>
          <button className="btn-primary" onClick={handlePassword}>Update Password</button>
        </div>
      </div>

      <SmsGatewayCard />
    </div>
  );
}

function SmsGatewayCard() {
  const [provider, setProvider] = useState("none");
  const [apiKey, setApiKey] = useState("");
  const [keyMasked, setKeyMasked] = useState("");
  const [senderId, setSenderId] = useState("");
  const [templateId, setTemplateId] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [testMobile, setTestMobile] = useState("");
  const [msg, setMsg] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [showKey, setShowKey] = useState(false);

  useEffect(() => {
    fetch(`${API_BASE}/api/settings/sms`, { headers: authHeaders() })
      .then(r => r.json())
      .then(d => {
        if (d.provider) setProvider(d.provider);
        setKeyMasked(d.keyMasked || "");
        setSenderId(d.senderId || "");
        setTemplateId(d.templateId || "");
        setBaseUrl(d.baseUrl || "");
      })
      .catch(() => {});
  }, []);

  const save = async () => {
    setBusy(true); setMsg(null);
    try {
      const res = await fetch(`${API_BASE}/api/settings/sms`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ provider, apiKey: apiKey || undefined, senderId, templateId, baseUrl })
      });
      const data = await res.json();
      setMsg(data.success ? { ok: true, text: "SMS settings saved." } : { ok: false, text: data.error || "Save failed" });
      if (data.success) { setApiKey(""); window.location.reload(); }
    } catch { setMsg({ ok: false, text: "Save failed" }); }
    setBusy(false);
  };

  const sendTest = async () => {
    setBusy(true); setMsg(null);
    try {
      const res = await fetch(`${API_BASE}/api/settings/sms/test`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ mobile: testMobile })
      });
      const data = await res.json();
      if (data.success && data.demo) setMsg({ ok: true, text: `Demo mode — OTP ${data.demoOtp} (configure a gateway to send real SMS)` });
      else if (data.success) setMsg({ ok: true, text: data.note || "Test SMS sent!" });
      else setMsg({ ok: false, text: data.error || "Test failed" });
    } catch { setMsg({ ok: false, text: "Test failed" }); }
    setBusy(false);
  };

  return (
    <>
      <h2 style={{ margin: "28px 0 0", border: "none", padding: 0 }}>SMS Gateway</h2>
      <p style={{ color: "var(--text-secondary)", fontSize: "13px", marginTop: "6px" }}>
        Configure the provider used to deliver result-verification OTPs. Without a gateway the system runs in demo mode.
      </p>
      <div className="brand-card" style={{ flexDirection: "column", alignItems: "stretch" }}>
        {msg && <p className={msg.ok ? "form-success" : "form-error"}>{msg.text}</p>}
        <label className="flabel">
          Provider
          <select value={provider} onChange={(e) => setProvider(e.target.value)}>
            <option value="none">Demo mode (OTP shown on screen)</option>
            <option value="android">Android Phone Gateway (free, self-hosted)</option>
            <option value="fast2sms">Fast2SMS</option>
            <option value="msg91">MSG91</option>
            <option value="textlocal">TextLocal</option>
          </select>
        </label>
        {provider === "android" && (
          <>
            <label className="flabel">
              Phone Gateway URL
              <input type="text" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="http://192.168.29.XXX:8080  (phone IP from the app)" />
            </label>
            <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "0 0 4px" }}>
              Install the "SMS Gateway" app on any Android phone with a SIM → enable the API server → copy its URL above → set an app password and enter it as the API key below.
            </p>
          </>
        )}
        <label className="flabel">
          {provider === "android" ? "Gateway App Password" : "API Key"}
          <span style={{ position: "relative", display: "block" }}>
            <input
              type={showKey ? "text" : "password"}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={keyMasked ? `Saved: ${keyMasked}` : "Paste your API key"}
              style={{ width: "100%", paddingRight: "38px" }}
            />
            <button type="button" className="pw-eye" onClick={() => setShowKey(v => !v)}
              aria-label={showKey ? "Hide key" : "Show key"} title={showKey ? "Hide key" : "Show key"}
              style={{ position: "absolute", right: "7px", top: "50%", transform: "translateY(-50%)" }}>
              {showKey ? (
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" /><line x1="1" y1="1" x2="23" y2="23" /></svg>
              ) : (
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" /></svg>
              )}
            </button>
          </span>
        </label>
        {provider === "msg91" && (
          <label className="flabel">
            DLT Template ID
            <input type="text" value={templateId} onChange={(e) => setTemplateId(e.target.value)} placeholder="MSG91 flow template id (uses {{OTP}} variable)" />
          </label>
        )}
        {(provider === "textlocal") && (
          <label className="flabel">
            Sender ID
            <input type="text" value={senderId} maxLength={6} onChange={(e) => setSenderId(e.target.value.toUpperCase())} placeholder="e.g. XYZUNI" />
          </label>
        )}
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" }}>
          <button className="btn-primary" onClick={save} disabled={busy}>
            {busy ? <><span className="spinner" /> Working</> : "Save Settings"}
          </button>
          <input type="text" placeholder="Send test SMS to..." inputMode="numeric"
            value={testMobile} onChange={(e) => setTestMobile(e.target.value.replace(/[^\d]/g, ""))}
            style={{ width: "180px" }} />
          <button className="btn-secondary" onClick={sendTest} disabled={busy || testMobile.length < 10}>Send Test</button>
        </div>
      </div>
    </>
  );
}

function CertificatesList() {
  const [certs, setCerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");
  const [courseFilter, setCourseFilter] = useState("");
  const [deleting, setDeleting] = useState("");
  const canAdmin = localStorage.getItem("admin_role") === "admin";

  const load = useCallback(() => {
    setLoading(true);
    fetch(`${API_BASE}/api/certificates`)
      .then(r => r.json())
      .then(d => { setCerts(d); setLoading(false); })
      .catch(() => { setLoading(false); });
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleDelete = async (hash: any, name: any) => {
    if (!window.confirm(`Delete certificate for ${name}?`)) return;
    setDeleting(hash);
    try {
      const res = await fetch(`${API_BASE}/api/certificates/${hash}`, { method: "DELETE", headers: authHeaders() });
      if (res.ok) {
        setCerts(prev => prev.filter(c => c.hash !== hash));
      } else {
        alert("Delete failed");
      }
    } catch {
      alert("Delete failed");
    }
    setDeleting("");
  };

  const q = filter.toLowerCase().trim();
  const filtered = certs.filter(c =>
    (q === "" || (c.name || "").toLowerCase().includes(q) || (c.rollNumber || "").toLowerCase().includes(q) || (c.email || "").toLowerCase().includes(q)) &&
    (courseFilter === "" || (c.course || "") === courseFilter)
  );

  const courses = [...new Set(certs.map(c => c.course).filter(Boolean))].sort();

  return (
    <div className="section">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
        <h2 style={{ margin: 0, border: "none", padding: 0 }}>All Certificates</h2>
        <button className="btn-secondary" onClick={load} style={{ padding: "6px 12px", fontSize: "12px" }}>Refresh</button>
      </div>

      <div className="list-filters">
        <input type="text" placeholder="Search by name, roll no, or email" value={filter}
          onChange={(e) => setFilter(e.target.value)} />
        <select value={courseFilter} onChange={(e) => setCourseFilter(e.target.value)}>
          <option value="">All Courses</option>
          {courses.map((c, i) => <option key={i} value={c}>{c}</option>)}
        </select>
      </div>

      {loading ? (
        <p style={{ color: "var(--text-secondary)" }}>Loading...</p>
      ) : filtered.length === 0 ? (
        <p style={{ color: "var(--text-secondary)" }}>No certificates found.</p>
      ) : (
        <div className="list-table-wrap">
          <table className="certs-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Name</th>
                <th>Roll No</th>
                <th>Course</th>
                <th>Department</th>
                <th>Year</th>
                <th>IPFS</th>
                {canAdmin && <th>Action</th>}
              </tr>
            </thead>
            <tbody>
              {filtered.map((c, i) => (
                <tr key={c.hash}>
                  <td>{i + 1}</td>
                  <td><strong>{c.name}</strong></td>
                  <td>{c.rollNumber || "-"}</td>
                  <td>{c.course || "-"}</td>
                  <td>{c.department || "-"}</td>
                  <td>{c.year || "-"}</td>
                  <td>
                    {c.ipfsHash ? (
                      <a className="link" href={`https://ipfs.io/ipfs/${c.ipfsHash}`} target="_blank" rel="noreferrer">View</a>
                    ) : "-"}
                  </td>
                  {canAdmin && (
                    <td>
                      <button className="btn-del" onClick={() => handleDelete(c.hash, c.name)} disabled={deleting === c.hash}>
                        {deleting === c.hash ? "..." : "Delete"}
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "8px" }}>
        Showing {filtered.length} of {certs.length} certificates
      </p>
    </div>
  );
}

function VerifySection() {
  const [verifyQuery, setVerifyQuery] = useState("");
  const [result, setResult] = useState<any>(null);
  const [results, setResults] = useState<any>(null);
  const [verifyStatus, setVerifyStatus] = useState("");

  const search = async () => {
    try {
      const q = verifyQuery.trim();
      if (!q) return alert("Enter a name, roll number, or hash");
      setResult(null);
      setResults(null);
      setVerifyStatus("Searching...");
      const res = await fetch(`${API_BASE}/api/search?q=${encodeURIComponent(q)}`);
      const data = await res.json();
      if (data.length === 1) {
        setResult(data[0]);
        setVerifyStatus("Certificate Found");
      } else if (data.length > 1) {
        setResults(data);
        setVerifyStatus(`${data.length} certificates found`);
      } else {
        setResult({ valid: false });
        setVerifyStatus("Certificate Not Found");
      }
    } catch {
      setVerifyStatus("Search failed");
    }
  };

  return (
    <div className="section">
      <h2>Verify Certificate</h2>
      <p style={{ fontSize: "14px", color: "var(--text-secondary)", marginBottom: "10px" }}>
        Search by student name, roll number, or certificate hash
      </p>
      <div style={{ display: "flex", gap: "8px" }}>
        <input type="text" placeholder="Name, Roll Number, or Hash" value={verifyQuery}
          onChange={(e) => setVerifyQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && search()} />
        <button className="btn-primary" onClick={search}
          style={{ width: "auto", padding: "10px 18px", whiteSpace: "nowrap" }}>
          Search
        </button>
      </div>
      {verifyStatus && <div className="status">{verifyStatus}</div>}
      {result && result.valid !== false && (
        <div className="result-card success">
          <p><strong style={{ color: "#86efac" }}>Certificate Verified</strong></p>
          <p><strong>Name:</strong> {result.name}</p>
          {result.rollNumber && <p><strong>Roll No:</strong> {result.rollNumber}</p>}
          {result.course && <p><strong>Course:</strong> {result.course}</p>}
          {result.department && <p><strong>Department:</strong> {result.department}</p>}
          {result.year && <p><strong>Year:</strong> {result.year}</p>}
          {result.email && <p><strong>Email:</strong> {result.email}</p>}
          <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "8px" }}>
            <strong>Hash:</strong> <span className="hash-text">{result.hash}</span>
          </p>
          {result.ipfsHash && (
            <a className="link" href={`https://ipfs.io/ipfs/${result.ipfsHash}`} target="_blank" rel="noreferrer">
              View Certificate on IPFS
            </a>
          )}
        </div>
      )}
      {result && result.valid === false && (
        <div className="result-card error">
          <p><strong style={{ color: "#fca5a5" }}>Certificate Not Found</strong></p>
          <p style={{ color: "#94a3b8", fontSize: "13px" }}>No certificate matches your search.</p>
        </div>
      )}
      {results && results.length > 0 && (
        <div className="result-card" style={{ marginTop: "16px" }}>
          <p><strong>Multiple certificates found:</strong></p>
          {results.map((r: any, i: any) => (
            <div key={i} style={{
              padding: "10px 0", borderBottom: i < results.length - 1 ? "1px solid rgba(148,163,184,0.15)" : "none",
              cursor: "pointer"
            }} onClick={() => { setResult(r); setResults(null); }}>
              <p><strong>{r.name}</strong> {r.rollNumber && <span style={{ color: "var(--text-secondary)" }}>({r.rollNumber})</span>}</p>
              <p style={{ fontSize: "12px", color: "var(--text-secondary)" }}>{r.course}{r.department && ` - ${r.department}`}{r.year && ` (${r.year})`}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function DownloadsSection() {
  return (
    <div className="section">
      <h2>Download Certificate List</h2>
      <div className="download-section">
        <a className="btn-download" href={`${API_BASE}/api/certificates/download`} target="_blank" rel="noreferrer">
          Download CSV
        </a>
        <a className="btn-download btn-download-green" href={`${API_BASE}/api/certificates/download?format=xlsx`} target="_blank" rel="noreferrer">
          Download Excel
        </a>
      </div>
    </div>
  );
}

function ResultsSection() {
  const [departments, setDepartments] = useState<any[]>([]);
  const [results, setResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState("");
  const [formError, setFormError] = useState("");

  const [newDept, setNewDept] = useState("");
  const [filters, setFilters] = useState({ q: "", department: "", semester: "" });

  const [form, setForm] = useState({
    rollNumber: "", name: "", department: "", semester: "",
    aadhaar: "", mobile: "",
    subjects: [{ subject: "", marks: "", maxMarks: "", grade: "" }]
  });
  const [editingId, setEditingId] = useState<any>(null);
  const [bulkRows, setBulkRows] = useState<any[]>([]);
  const [bulkFileName, setBulkFileName] = useState("");
  const [bulkStatus, setBulkStatus] = useState("");
  const [bulkError, setBulkError] = useState("");
  const [bulkSaving, setBulkSaving] = useState(false);

  const fetchDepartments = () => {
    fetch(`${API_BASE}/api/departments`)
      .then(r => r.json())
      .then(d => setDepartments(Array.isArray(d) ? d : []))
      .catch(() => setDepartments([]));
  };

  const isAdminUser = localStorage.getItem("admin_role") === "admin";
  let myDepts = [];
  try { myDepts = JSON.parse(localStorage.getItem("admin_depts") || "[]"); } catch { myDepts = []; }
  const deptRestricted = !isAdminUser && Array.isArray(myDepts) && myDepts.length > 0;
  const visibleDepartments = deptRestricted ? departments.filter(d => myDepts.includes(d)) : departments;

  const fetchResults = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams();
    if (filters.q) params.set("q", filters.q);
    if (filters.department) params.set("department", filters.department);
    if (filters.semester) params.set("semester", filters.semester);
    fetch(`${API_BASE}/api/results?${params.toString()}`, { headers: authHeaders() })
      .then(r => r.json())
      .then(d => {
        let rows = Array.isArray(d) ? d : [];
        if (deptRestricted) rows = rows.filter(r => myDepts.includes(r.department));
        setResults(rows); setLoading(false);
      })
      .catch(() => { setResults([]); setLoading(false); });
  }, [filters]);

  useEffect(() => {
    fetchDepartments();
  }, []);

  useEffect(() => {
    if (deptRestricted && !filters.department && visibleDepartments.length > 0) {
      setFilters(f => ({ ...f, department: myDepts.includes(f.department) ? f.department : visibleDepartments[0] }));
    }
  }, [deptRestricted, visibleDepartments]);

  useEffect(() => {
    fetchResults();
  }, [fetchResults]);

  const handleBulkFile = async (e: any) => {
    const f = e.target.files[0];
    if (!f) return;
    setBulkFileName(f.name);
    setBulkRows([]);
    setBulkStatus("");
    setBulkError("");
    try {
      const formData = new FormData();
      formData.append("file", f);
      const res = await fetch(`${API_BASE}/api/results/bulk-upload`, {
        method: "POST",
        headers: { ...authHeaders() },
        body: formData,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Parse failed");
      setBulkRows(data.rows || []);
      setBulkStatus(`Parsed ${data.count} subject rows`);
    } catch (err: any) {
      setBulkError(err.message);
    }
  };

  const saveBulk = async () => {
    if (bulkRows.length === 0) return;
    setBulkSaving(true);
    setBulkError("");
    setBulkStatus("Saving results...");
    try {
      const res = await fetch(`${API_BASE}/api/results/bulk-save`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ rows: bulkRows }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Save failed");
      setBulkStatus(`Saved! ${data.added} new, ${data.updated} updated, ${data.totalStudents} student(s) total`);
      setBulkRows([]);
      setBulkFileName("");
      fetchResults();
      fetchDepartments();
      setTimeout(() => setBulkStatus(""), 4000);
    } catch (err: any) {
      setBulkError(err.message);
    } finally {
      setBulkSaving(false);
    }
  };

  const setSubject = (i: any, key: any, value: any) => {
    const next = [...form.subjects];
    next[i] = { ...next[i], [key]: value };
    setForm({ ...form, subjects: next });
  };

  const addSubjectRow = () => {
    setForm({ ...form, subjects: [...form.subjects, { subject: "", marks: "", maxMarks: "", grade: "" }] });
  };

  const removeSubjectRow = (i: any) => {
    const next = form.subjects.filter((_, idx) => idx !== i);
    setForm({ ...form, subjects: next.length ? next : [{ subject: "", marks: "", maxMarks: "", grade: "" }] });
  };

  const resetForm = () => {
    setForm({ rollNumber: "", name: "", department: "", semester: "", aadhaar: "", mobile: "", subjects: [{ subject: "", marks: "", maxMarks: "", grade: "" }] });
    setEditingId(null);
    setFormError("");
  };

  const addDepartment = async () => {
    const name = newDept.trim();
    if (!name) return;
    setFormError("");
    try {
      const res = await fetch(`${API_BASE}/api/departments`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ name }),
      });
      const data = await res.json();
      if (!res.ok) { setFormError(data.error || "Failed to add department"); return; }
      setNewDept("");
      setDepartments(data.departments || []);
    } catch {
      setFormError("Failed to add department");
    }
  };

  const saveResult = async () => {
    setFormError("");
    if (!form.rollNumber.trim()) return setFormError("Roll Number is required");
    if (!form.name.trim()) return setFormError("Student name is required");
    if (!form.department.trim()) return setFormError("Department is required");
    if (!form.semester.trim()) return setFormError("Semester is required");
    const subjects = form.subjects.filter(s => s.subject.trim());
    if (subjects.length === 0) return setFormError("Add at least one subject");

    const body = {
      rollNumber: form.rollNumber, name: form.name, department: form.department,
      semester: form.semester, subjects,
      aadhaar: form.aadhaar.replace(/\D/g, ""), mobile: form.mobile.replace(/\D/g, ""),
    };
    try {
      const url = editingId ? `${API_BASE}/api/results/${editingId}` : `${API_BASE}/api/results`;
      const res = await fetch(url, {
        method: editingId ? "PUT" : "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) { setFormError(data.error || "Save failed"); return; }
      setStatus(editingId ? "Result updated" : "Result saved");
      resetForm();
      fetchResults();
      setTimeout(() => setStatus(""), 2500);
    } catch {
      setFormError("Save failed. Is the server running?");
    }
  };

  const deleteResult = async (id: any) => {
    if (!window.confirm("Delete this result?")) return;
    try {
      const res = await fetch(`${API_BASE}/api/results/${id}`, {
        method: "DELETE",
        headers: { ...authHeaders() },
      });
      if (!res.ok) return alert("Delete failed");
      fetchResults();
    } catch {
      alert("Delete failed");
    }
  };

  const deleteDepartment = async (name: any) => {
    const resultCount = results.filter(r => (r.department || "") === name).length;
    const msg = resultCount > 0
      ? `Remove department "${name}" and its ${resultCount} stored result(s)? This cannot be undone.`
      : `Remove department "${name}"?`;
    if (!window.confirm(msg)) return;
    try {
      const res = await fetch(`${API_BASE}/api/departments/${encodeURIComponent(name)}`, {
        method: "DELETE",
        headers: { ...authHeaders() },
      });
      const data = await res.json();
      if (!res.ok) return alert(data.error || "Delete failed");
      setDepartments(data.departments || []);
      if (data.removedResults > 0) {
        setStatus(`Department removed — ${data.removedResults} stored result(s) deleted`);
        fetchResults();
      }
    } catch {
      alert("Delete failed");
    }
  };

  const editResult = (r: any) => {
    setEditingId(r.id);
    setForm({
      rollNumber: r.rollNumber, name: r.name, department: r.department, semester: r.semester,
      aadhaar: r.aadhaar || "", mobile: r.mobile || "",
      subjects: r.subjects.length ? r.subjects.map((s: any) => ({
        subject: s.subject, marks: s.marks == null ? "" : s.marks,
        maxMarks: s.maxMarks == null ? "" : s.maxMarks, grade: s.grade || "",
      })) : [{ subject: "", marks: "", maxMarks: "", grade: "" }],
    });
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const semesters = ["Sem 1", "Sem 2", "Sem 3", "Sem 4", "Sem 5", "Sem 6", "Sem 7", "Sem 8", "Sem 9", "Sem 10"];

  return (
    <div className="section">
      <h2>Semester Results</h2>
      <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "12px" }}>
        Store and view student marks per semester, organized by department.
      </p>

      {status && <div className="form-success">{status}</div>}
      {formError && <div className="form-error">{formError}</div>}

      <div className="results-bulk">
        <h3 style={{ border: "none", padding: 0, marginBottom: "6px" }}>Bulk Upload Results</h3>
        <p style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "10px" }}>
          Upload a CSV / Excel with one row per subject. Columns: <code>Roll Number</code>, <code>Name</code>,
          <code> Department</code>, <code>Semester</code>, <code>Subject</code>, <code>Marks</code>,
          <code> Max Marks</code>, <code>Grade</code>. Rows with the same student + semester are grouped into one result.
        </p>
        <div className="demo-format" style={{ margin: "0 0 12px" }}>
          <p style={{ fontSize: "13px", fontWeight: 600, marginBottom: "8px" }}>
            Expected format (<strong>Roll Number</strong> &amp; <strong>Subject</strong> required):
          </p>
          <div className="hash-text" style={{ fontSize: "12px", overflowX: "auto", whiteSpace: "nowrap" }}>
            Roll Number,Name,Department,Semester,Subject,Marks,Max Marks,Grade<br />
            2024001,John Doe,Computer Science,Sem 1,Mathematics,85,100,A<br />
            2024001,John Doe,Computer Science,Sem 1,Physics,78,100,B<br />
            2024002,Jane Smith,Information Technology,Sem 2,Data Structures,72,100,B
          </div>
          <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "6px" }}>
            <a className="link" href="#" onClick={(e) => {
              e.preventDefault();
              const csv = "Roll Number,Name,Department,Semester,Subject,Marks,Max Marks,Grade\n2024001,John Doe,Computer Science,Sem 1,Mathematics,85,100,A\n2024001,John Doe,Computer Science,Sem 1,Physics,78,100,B\n2024002,Jane Smith,Information Technology,Sem 2,Data Structures,72,100,B\n2024003,Alice Lee,Mathematics,Sem 1,Linear Algebra,88,100,A+";
              const blob = new Blob([csv], { type: "text/csv" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a"); a.href = url; a.download = "demo-results.csv"; a.click();
              URL.revokeObjectURL(url);
            }}>Download demo CSV</a>
          </p>
        </div>
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" }}>
          <input type="file" accept=".csv,.xlsx" onChange={handleBulkFile} className="results-bulk-input" />
          <button className="btn-success" onClick={saveBulk} disabled={bulkRows.length === 0 || bulkSaving}
            style={{ opacity: bulkRows.length === 0 ? 0.5 : 1, cursor: bulkRows.length === 0 ? "not-allowed" : "pointer" }}>
            {bulkSaving ? "Saving..." : `Save Bulk (${bulkRows.length} rows)`}
          </button>
        </div>
        {bulkFileName && <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "8px" }}>📄 {bulkFileName}</p>}
        {bulkStatus && <div className="status" style={{ color: "var(--text-primary)" }}>{bulkStatus}</div>}
        {bulkError && <div className="form-error" style={{ margin: "10px 0 0" }}>{bulkError}</div>}

        {bulkRows.length > 0 && (
          <div className="csv-preview" style={{ marginTop: "12px" }}>
            <div style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "6px" }}>
              Preview — first 5 of {bulkRows.length} subject rows
            </div>
            <table>
              <thead>
                <tr><th>Roll No</th><th>Name</th><th>Dept</th><th>Sem</th><th>Subject</th><th>Marks</th><th>Max</th><th>Grade</th></tr>
              </thead>
              <tbody>
                {bulkRows.slice(0, 5).map((r, i) => (
                  <tr key={i}>
                    <td>{r.rollNumber}</td><td>{r.name}</td><td>{r.department}</td><td>{r.semester}</td>
                    <td>{r.subject}</td><td>{r.marks}</td><td>{r.maxMarks}</td><td>{r.grade}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="results-add">
        <h3 style={{ border: "none", padding: 0, marginBottom: "10px" }}>
          {editingId ? `Editing result — ${form.name || form.rollNumber}` : "Add Semester Result"}
        </h3>
        <div className="form-grid">
          <div className="input-group">
            <label>Student Name <span className="required">*</span></label>
            <input type="text" placeholder="e.g. John Doe" value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </div>
          <div className="input-group">
            <label>Roll Number <span className="required">*</span></label>
            <input type="text" placeholder="e.g. 2024001" value={form.rollNumber}
              onChange={(e) => setForm({ ...form, rollNumber: e.target.value })} />
          </div>
          <div className="input-group">
            <label>Aadhaar Number (for result login)</label>
            <input type="text" placeholder="12-digit Aadhaar (optional)" inputMode="numeric" maxLength={14}
              value={form.aadhaar}
              onChange={(e) => setForm({ ...form, aadhaar: e.target.value.replace(/[^\d\s]/g, "") })} />
          </div>
          <div className="input-group">
            <label>Registered Mobile (for OTP)</label>
            <input type="text" placeholder="10-digit mobile (optional)" inputMode="numeric" maxLength={13}
              value={form.mobile}
              onChange={(e) => setForm({ ...form, mobile: e.target.value.replace(/[^\d\s]/g, "") })} />
          </div>
          <div className="input-group">
            <label>Department <span className="required">*</span></label>
            <select value={form.department} onChange={(e) => setForm({ ...form, department: e.target.value })}>
              <option value="">Select department...</option>
              {visibleDepartments.map((d, i) => <option key={i} value={d}>{d}</option>)}
              {!deptRestricted && <option value="__other__">Other (type below)</option>}
            </select>
            {form.department === "__other__" && (
              <input type="text" placeholder="Type department name" style={{ marginTop: "8px" }}
                value={form.department === "__other__" ? "" : form.department}
                onChange={(e) => setForm({ ...form, department: e.target.value })} />
            )}
          </div>
          <div className="input-group">
            <label>Semester <span className="required">*</span></label>
            <select value={form.semester} onChange={(e) => setForm({ ...form, semester: e.target.value })}>
              <option value="">Select semester...</option>
              {semesters.map((s, i) => <option key={i} value={s}>{s}</option>)}
            </select>
          </div>
        </div>

        <div style={{ marginTop: "14px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
            <label style={{ fontSize: "13px", color: "var(--text-secondary)", fontWeight: 600 }}>Subjects &amp; Marks</label>
            <button className="btn-secondary" type="button" onClick={addSubjectRow} style={{ padding: "4px 10px", fontSize: "12px" }}>+ Add Subject</button>
          </div>
          <div className="subjects-table">
            <div className="subjects-row subjects-head">
              <span>Subject</span><span>Marks</span><span>Max Marks</span><span>Grade</span><span></span>
            </div>
            {form.subjects.map((s, i) => (
              <div className="subjects-row" key={i}>
                <input type="text" placeholder="Subject" value={s.subject}
                  onChange={(e) => setSubject(i, "subject", e.target.value)} />
                <input type="number" placeholder="Marks" value={s.marks}
                  onChange={(e) => setSubject(i, "marks", e.target.value)} />
                <input type="number" placeholder="Max" value={s.maxMarks}
                  onChange={(e) => setSubject(i, "maxMarks", e.target.value)} />
                <input type="text" placeholder="Grade" value={s.grade}
                  onChange={(e) => setSubject(i, "grade", e.target.value)} />
                <button className="btn-del" type="button" onClick={() => removeSubjectRow(i)} style={{ border: "none", padding: "4px 8px" }}>✕</button>
              </div>
            ))}
          </div>
        </div>

        <div style={{ display: "flex", gap: "10px", marginTop: "16px" }}>
          <button className="btn-success" onClick={saveResult} style={{ flex: 1 }}>
            {editingId ? "Update Result" : "Save Result"}
          </button>
          {editingId && <button className="btn-secondary" onClick={resetForm}>Cancel</button>}
        </div>
      </div>

      <div className="results-manage" style={{ marginTop: "28px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "8px", marginBottom: "8px" }}>
          <h3 style={{ border: "none", padding: 0 }}>Departments</h3>
          {isAdminUser && (
            <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", alignItems: "center" }}>
              <input type="text" placeholder="Add department" value={newDept} style={{ width: "180px" }}
                onChange={(e) => setNewDept(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addDepartment()} />
              <button className="btn-secondary" onClick={addDepartment} style={{ padding: "8px 12px" }}>Add</button>
            </div>
          )}
        </div>
        {!isAdminUser && (
          <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "0 0 8px" }}>
            Only admins can add or remove departments.
          </p>
        )}
        {departments.length > 0 ? (
          <div className="dept-chips">
            {departments.map((d, i) => (
              <span className="dept-chip" key={i}>
                {d}
                {isAdminUser && (
                  <button className="dept-chip-del" onClick={() => deleteDepartment(d)} title={`Remove ${d}`}>✕</button>
                )}
              </span>
            ))}
          </div>
        ) : (
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>No departments yet.</p>
        )}
      </div>

      <div style={{ marginTop: "28px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "8px", marginBottom: "12px" }}>
          <h3 style={{ border: "none", padding: 0 }}>Results ({results.length})</h3>
          <div className="list-filters" style={{ marginBottom: 0 }}>
            <input type="text" placeholder="Search name / roll no" value={filters.q}
              onChange={(e) => setFilters({ ...filters, q: e.target.value })} />
            <select value={filters.department} onChange={(e) => setFilters({ ...filters, department: e.target.value })}>
              {!deptRestricted && <option value="">All departments</option>}
              {visibleDepartments.map((d, i) => <option key={i} value={d}>{d}</option>)}
            </select>
            <select value={filters.semester} onChange={(e) => setFilters({ ...filters, semester: e.target.value })}>
              <option value="">All semesters</option>
              {semesters.map((s, i) => <option key={i} value={s}>{s}</option>)}
            </select>
          </div>
        </div>

        {loading ? (
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>Loading...</p>
        ) : results.length === 0 ? (
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>No results match your filters.</p>
        ) : (
          <div className="results-list">
            {results.map((r) => {
              const totalObtained = r.subjects.reduce((s: any, x: any) => s + (Number(x.marks) || 0), 0);
              const totalMax = r.subjects.reduce((s: any, x: any) => s + (Number(x.maxMarks) || 0), 0);
              const pct = totalMax ? Math.round((totalObtained / totalMax) * 100) : null;
              return (
                <div className="result-item" key={r.id}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "10px", flexWrap: "wrap" }}>
                    <div>
                      <strong style={{ fontSize: "15px" }}>{r.name}</strong>
                      <span style={{ color: "var(--text-secondary)", marginLeft: "8px", fontSize: "13px" }}>{r.rollNumber}</span>
                      <div className="activity-meta" style={{ marginTop: "4px" }}>
                        <span className="activity-badge-pill">{r.department}</span>
                        <span className="activity-badge-pill" style={{ color: "#60a5fa" }}>{r.semester}</span>
                        {pct !== null && <span className="activity-badge-pill" style={{ color: pct >= 40 ? "#86efac" : "#fca5a5" }}>{pct}%</span>}
                        <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                          {r.subjects.length} subject(s) · {new Date(r.timestamp).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                    <div style={{ display: "flex", gap: "6px" }}>
                      <button className="btn-secondary" onClick={() => editResult(r)} style={{ padding: "5px 12px", fontSize: "12px" }}>Edit</button>
                      <button className="btn-del" onClick={() => deleteResult(r.id)}>Delete</button>
                    </div>
                  </div>
                  <table className="subjects-detail" style={{ marginTop: "10px" }}>
                    <thead>
                      <tr><th>Subject</th><th>Marks</th><th>Max</th><th>Grade</th></tr>
                    </thead>
                    <tbody>
                      {r.subjects.map((s: any, i: any) => (
                        <tr key={i}>
                          <td>{s.subject}</td>
                          <td>{s.marks ?? "—"}</td>
                          <td>{s.maxMarks ?? "—"}</td>
                          <td>{s.grade || "—"}</td>
                        </tr>
                      ))}
                      <tr>
                        <td><strong>Total</strong></td>
                        <td><strong>{totalObtained}</strong></td>
                        <td><strong>{totalMax}</strong></td>
                        <td>{pct !== null ? `${pct}%` : "—"}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function IssuesSection() {
  const [issues, setIssues] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");

  const load = useCallback(() => {
    setLoading(true);
    fetch(`${API_BASE}/api/issues`, { headers: authHeaders() })
      .then(r => r.json())
      .then(d => { setIssues(d); setLoading(false); })
      .catch(() => { setLoading(false); });
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleStatus = async (id: any, status: any) => {
    try {
      await fetch(`${API_BASE}/api/issues/${id}`, { method: "PATCH", headers: { ...authHeaders(), "Content-Type": "application/json" }, body: JSON.stringify({ status }) });
      load();
    } catch { alert("Update failed"); }
  };

  const handleDelete = async (id: any) => {
    if (!window.confirm("Delete this issue?")) return;
    try {
      await fetch(`${API_BASE}/api/issues/${id}`, { method: "DELETE", headers: authHeaders() });
      load();
    } catch { alert("Delete failed"); }
  };

  const q = filter.toLowerCase().trim();
  const filtered = issues.filter(i => JSON.stringify(i).toLowerCase().includes(q));

  const statusColor = (s: any) => s === "open" ? "#f59e0b" : s === "resolved" ? "#22c55e" : "#ef4444";

  const counts = {
    open: issues.filter(i => i.status === "open").length,
    resolved: issues.filter(i => i.status === "resolved").length,
    rejected: issues.filter(i => i.status === "rejected").length,
  };

  const semCounts: Record<string, number> = {};
  issues.forEach(i => {
    const key = i.semester || "Unknown";
    semCounts[key] = (semCounts[key] || 0) + 1;
  });

  const dayCounts: Record<string, number> = {};
  for (let d = 6; d >= 0; d--) {
    const dt = new Date();
    dt.setDate(dt.getDate() - d);
    dayCounts[dt.toISOString().slice(0, 10)] = 0;
  }
  issues.forEach(i => {
    const key = new Date(i.timestamp).toISOString().slice(0, 10);
    if (key in dayCounts) dayCounts[key] += 1;
  });

  return (
    <div className="section">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
        <h2 style={{ margin: 0, border: "none", padding: 0 }}>Issue Dashboard</h2>
        <button className="btn-secondary" onClick={load} style={{ padding: "6px 12px", fontSize: "12px" }}>Refresh</button>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">🚩</div>
          <div className="stat-value">{issues.length}</div>
          <div className="stat-label">Total Issues</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🟠</div>
          <div className="stat-value" style={{ color: "#fbbf24" }}>{counts.open}</div>
          <div className="stat-label">Open</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">✅</div>
          <div className="stat-value" style={{ color: "#22c55e" }}>{counts.resolved}</div>
          <div className="stat-label">Resolved</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">⛔</div>
          <div className="stat-value" style={{ color: "#ef4444" }}>{counts.rejected}</div>
          <div className="stat-label">Rejected</div>
        </div>
      </div>

      <div style={{ display: "flex", gap: "20px", flexWrap: "wrap", marginTop: "20px", marginBottom: "16px" }}>
        <div className="chart-panel" style={{ flex: "1", minWidth: "260px" }}>
          <h3>Issues by Status</h3>
          <BarChart height={200} data={[
            { label: "Open", value: counts.open },
            { label: "Resolved", value: counts.resolved },
            { label: "Rejected", value: counts.rejected },
          ]} />
        </div>

        <div className="chart-panel" style={{ flex: "1", minWidth: "260px" }}>
          <h3>Issues by Semester</h3>
          <BarChart height={200} data={Object.entries(semCounts).map(([label, value]) => ({ label, value }))} />
        </div>

        <div className="chart-panel" style={{ flex: "1", minWidth: "260px" }}>
          <h3>Issues (Last 7 Days)</h3>
          <BarChart height={200} data={Object.entries(dayCounts).map(([day, value]) => ({ label: day.slice(5), value }))} />
        </div>
      </div>

      <input type="text" placeholder="Filter issues..." value={filter}
        onChange={(e) => setFilter(e.target.value)} style={{ marginBottom: "16px" }} />

      {loading ? (
        <p style={{ color: "var(--text-secondary)" }}>Loading...</p>
      ) : filtered.length === 0 ? (
        <p style={{ color: "var(--text-secondary)" }}>No issues reported.</p>
      ) : (
        <div className="activity-list">
          {filtered.map((i) => {
            const when = new Date(i.timestamp);
            return (
              <div key={i.id} className="activity-item">
                <span className="activity-badge-pill" style={{ color: statusColor(i.status) }}>{i.status.toUpperCase()}</span>
                <div className="activity-body">
                  <div className="activity-title">
                    Roll <strong>{i.rollNumber || "—"}</strong>
                    {i.semester ? ` · ${i.semester}` : ""}
                  </div>
                  <div className="activity-meta" style={{ color: "var(--text-secondary)", fontSize: "13px", marginTop: "4px" }}>
                    {i.message}
                  </div>
                  <div className="activity-meta">
                    {when.toLocaleDateString()} {when.toLocaleTimeString()}
                  </div>
                  <div style={{ display: "flex", gap: "8px", marginTop: "10px", flexWrap: "wrap" }}>
                    {i.status !== "open" && <button className="btn-secondary" onClick={() => handleStatus(i.id, "open")} style={{ padding: "5px 10px", fontSize: "12px" }}>Reopen</button>}
                    {i.status !== "resolved" && <button className="btn-secondary" onClick={() => handleStatus(i.id, "resolved")} style={{ padding: "5px 10px", fontSize: "12px" }}>Resolve</button>}
                    {i.status !== "rejected" && <button className="btn-secondary" onClick={() => handleStatus(i.id, "rejected")} style={{ padding: "5px 10px", fontSize: "12px" }}>Reject</button>}
                    <button className="btn-del" onClick={() => handleDelete(i.id)}>Delete</button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function AnalyticsSection() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    fetch(`${API_BASE}/api/dashboard/analytics`)
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => { setLoading(false); });
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) {
    return <div className="section"><p style={{ color: "var(--text-secondary)" }}>Loading...</p></div>;
  }

  return (
    <div className="section">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
        <h2 style={{ margin: 0, border: "none", padding: 0 }}>Analytics</h2>
        <button className="btn-secondary" onClick={load} style={{ padding: "6px 12px", fontSize: "12px" }}>Refresh</button>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">🏛️</div>
          <div className="stat-value">{data.totalDepartments}</div>
          <div className="stat-label">Total Departments</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🎯</div>
          <div className="stat-value">{data.totalResults}</div>
          <div className="stat-label">Total Results</div>
        </div>
      </div>

      <div style={{ display: "flex", gap: "20px", flexWrap: "wrap", marginTop: "20px" }}>
        <div className="chart-panel" style={{ flex: "1", minWidth: "300px" }}>
          <h3>Certificates Issued (Last 7 Days)</h3>
          <BarChart height={220} data={(data.byDay || []).map((d: any) => ({ label: d.day.slice(5), value: d.count }))} />
        </div>
        <div className="chart-panel" style={{ flex: "1", minWidth: "300px" }}>
          <h3>Department-wise Results</h3>
          <BarChart height={220} data={(data.byDepartment || []).map((d: any) => ({ label: d.department, value: d.count }))} />
        </div>
        <div className="chart-panel" style={{ flex: "1", minWidth: "300px" }}>
          <h3>Semester-wise Results</h3>
          <BarChart height={220} data={(data.bySemester || []).map((s: any) => ({ label: s.semester, value: s.count }))} />
        </div>
      </div>

      <h3 style={{ marginTop: "24px" }}>All Departments</h3>
      <div className="stat-card" style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
        {(data.departments || []).map((name: any, i: any) => (
          <span key={i} className="badge">{name}</span>
        ))}
        {(data.departments || []).length === 0 && <p style={{ color: "var(--text-secondary)" }}>No departments added yet.</p>}
      </div>
    </div>
  );
}

function MonitorSection() {
  const [data, setData] = useState<any>(null);
  const [apps, setApps] = useState<any[]>([]);
  const [form, setForm] = useState({ name: "", app_key: "", url: "", type: "web", department: "", notes: "" });
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const load = useCallback(() => {
    fetch(`${API_BASE}/api/monitor/stats`, { headers: authHeaders() })
      .then(r => r.json()).then(setData).catch(() => {});
    fetch(`${API_BASE}/api/monitor/apps`, { headers: authHeaders() })
      .then(r => r.json()).then(setApps).catch(() => {});
  }, []);

  useEffect(() => {
    load();
    const iv = setInterval(load, 15000);
    return () => clearInterval(iv);
  }, [load]);

  const onlineCount = apps.filter(a => a.last_online === true).length;
  const offlineCount = apps.filter(a => a.last_online !== true && a.last_checked).length;
  const downtime = offlineCount;

  const addApp = async (e: any) => {
    e.preventDefault();
    setMsg(""); setErr("");
    try {
      const res = await fetch(`${API_BASE}/api/monitor/apps`, {
        method: "POST",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const d = await res.json();
      if (!res.ok) throw new Error(d.error || "Failed to register app");
      setForm({ name: "", app_key: "", url: "", type: "web", department: "", notes: "" });
      setMsg(`Registered "${d.name}". It will be checked automatically.`);
      load();
    } catch (ex: any) { setErr(ex.message); }
  };

  const toggleApp = async (a: any) => {
    try {
      const res = await fetch(`${API_BASE}/api/monitor/apps/${a.id}`, {
        method: "PUT",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !a.enabled }),
      });
      if (!res.ok) throw new Error("Update failed");
      load();
    } catch (ex: any) { setErr(ex.message); }
  };

  const deleteApp = async (a: any) => {
    if (!window.confirm(`Remove "${a.name}" from monitoring? Its history will be deleted.`)) return;
    try {
      const res = await fetch(`${API_BASE}/api/monitor/apps/${a.id}`, { method: "DELETE", headers: authHeaders() });
      if (!res.ok) throw new Error("Delete failed");
      setMsg(`Removed "${a.name}" from monitoring.`);
      load();
    } catch (ex: any) { setErr(ex.message); }
  };

  const updateCompliance = async (a: any, field: any, value: any) => {
    const comp = field.endsWith("ropa") ? "ROPA" : field.endsWith("dpia") ? "DPIA" : "DPDP";
    const cur = field.endsWith("ropa") ? (a.ropa_status || "not_started")
      : field.endsWith("dpia") ? (a.dpia_status || "not_started")
      : (a.dpdp_status || "not_started");
    if (value === cur) return;
    setErr(""); setMsg("");
    try {
      const res = await fetch(`${API_BASE}/api/monitor/apps/${a.id}`, {
        method: "PUT",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ [field]: value }),
      });
      if (!res.ok) throw new Error("Update failed");
      setMsg(`${comp} for "${a.name}" set to ${value.replace(/_/g, " ")}.`);
      load();
    } catch (ex: any) { setErr(ex.message); }
  };

  const updateOwner = async (a: any, field: any, value: any) => {
    const comp = field.endsWith("ropa") ? "ROPA" : field.endsWith("dpia") ? "DPIA" : "DPDP";
    const cur = field.endsWith("ropa") ? (a.ropa_owner || "")
      : field.endsWith("dpia") ? (a.dpia_owner || "")
      : (a.dpdp_owner || "");
    if (value.trim() === cur.trim()) return;
    setErr(""); setMsg("");
    try {
      const res = await fetch(`${API_BASE}/api/monitor/apps/${a.id}`, {
        method: "PUT",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ [field]: value.trim() }),
      });
      if (!res.ok) throw new Error("Update failed");
      setMsg(`${comp} owner for "${a.name}" updated.`);
      load();
    } catch (ex: any) { setErr(ex.message); }
  };

  const compBadge = (s: any) => {
    const map = { completed: "connected", in_progress: "warn", not_started: "danger" };
    return `badge ${(map as any)[s] || "info"}`;
  };
  const compLabel = (s: any) => {
    const map = { completed: "Completed", in_progress: "In progress", not_started: "Not started" };
    return (map as any)[s] || "N/A";
  };

const sevBadge = (s: any) => {
  const map = { info: "info", low: "low", medium: "warn", high: "danger", critical: "critical" };
  return `badge ${(map as any)[s] || "info"}`;
};

const origin = window.location.origin;
const helpBlock = `POST ${origin}/api/agent/event
Headers: X-Monitor-Token: <token from server .env: MONITOR_AGENT_TOKEN>
         Content-Type:  application/json
Body:    { "appKey": "<this app_key>", "type": "failed_login",
          "message": "3 failed admins", "severity": "high", "username": "x" }`;
const curlExample = `curl -s -X POST ${origin}/api/agent/event -H "X-Monitor-Token: TOKEN" -H "Content-Type: application/json" -d '{"appKey":"admission-portal","type":"failed_login","message":"Test","severity":"info"}'`;

  return (
    <div className="section">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
        <h2 style={{ margin: 0, border: "none", padding: 0 }}>🛡️ Campus Monitor</h2>
        <button className="btn-secondary" onClick={load} style={{ padding: "6px 12px", fontSize: "12px" }}>Refresh</button>
      </div>
      <p style={{ color: "var(--text-secondary)", fontSize: "13px", marginBottom: "18px" }}>
        Uptime, health, security and <strong>data-protection compliance</strong> for all campus applications.
        Each app is checked automatically every 30 seconds; track whether each app has completed its
        <strong> ROPA</strong> (Record of Processing Activities), <strong>DPIA</strong> (Data Protection
        Impact Assessment) and <strong>DPDP</strong> (Digital Personal Data Protection Act) obligations.
      </p>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">📱</div>
          <div className="stat-value">{data ? data.enabledApps : "…"}</div>
          <div className="stat-label">Monitored Apps</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">✅</div>
          <div className="stat-value" style={{ color: "var(--ok)" }}>{onlineCount}</div>
          <div className="stat-label">Online</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">⛔</div>
          <div className="stat-value" style={{ color: downtime ? "var(--danger)" : "var(--ok)" }}>{downtime}</div>
          <div className="stat-label">Offline / Errors</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🚨</div>
          <div className="stat-value" style={{ color: (data && data.critical24h) ? "var(--danger)" : "var(--ok)" }}>{data ? data.critical24h : "…"}</div>
          <div className="stat-label">Security Events (24h)</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">📋</div>
          <div className="stat-value" style={{ color: (data && data.ropaCompleted) ? "var(--ok)" : "var(--text-muted)" }}>{data != null ? `${data.ropaCompleted}/${data.enabledApps}` : "…"}</div>
          <div className="stat-label">ROPA Completed</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🛡️</div>
          <div className="stat-value" style={{ color: (data && data.dpiaCompleted) ? "var(--ok)" : "var(--text-muted)" }}>{data != null ? `${data.dpiaCompleted}/${data.enabledApps}` : "…"}</div>
          <div className="stat-label">DPIA Completed</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🇮🇳</div>
          <div className="stat-value" style={{ color: (data && data.dpdpCompleted) ? "var(--ok)" : "var(--text-muted)" }}>{data != null ? `${data.dpdpCompleted}/${data.enabledApps}` : "…"}</div>
          <div className="stat-label">DPDP Completed</div>
        </div>
      </div>

      {msg && <div className="badge connected" style={{ marginBottom: "12px" }}>{msg}</div>}
      {err && <div style={{ color: "var(--danger)", fontSize: "13px", marginBottom: "12px" }}>{err}</div>}

      <div className="card" style={{ marginBottom: "18px", padding: "16px" }}>
        <h3 style={{ marginTop: 0 }}>Register a campus application</h3>
        <form onSubmit={addApp} style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "12px" }}>
          <input placeholder="App name *" value={form.name} required
            onChange={e => setForm({ ...form, name: e.target.value })} />
          <input placeholder="App key (unique slug)" value={form.app_key}
            onChange={e => setForm({ ...form, app_key: e.target.value })} />
          <input placeholder="https://app-url *" value={form.url} required
            onChange={e => setForm({ ...form, url: e.target.value })} />
          <select value={form.type} onChange={e => setForm({ ...form, type: e.target.value })}>
            <option value="web">Web app</option>
            <option value="api">API</option>
            <option value="database">Database</option>
            <option value="other">Other</option>
          </select>
          <input placeholder="Department" value={form.department}
            onChange={e => setForm({ ...form, department: e.target.value })} />
          <button className="btn-primary" type="submit">Register</button>
        </form>
      </div>

      <details className="card" style={{ marginBottom: "18px", padding: "14px 16px" }}>
        <summary style={{ cursor: "pointer", fontWeight: 600, color: "var(--text-secondary)" }}>💡 Agent integration for other campus apps</summary>
        <ol style={{ margin: "12px 0 8px", paddingLeft: "20px", fontSize: "13px", lineHeight: 1.7 }}>
          <li>Register the app above (the portal will also health-check its URL every 30&nbsp;s).</li>
          <li>Point the app's backend at the event endpoint to report security events:</li>
        </ol>
        <pre style={{ background: "var(--bg-secondary)", border: "1px solid var(--border)", borderRadius: "6px", padding: "10px", fontSize: "12px", overflowX: "auto" }}>{helpBlock}</pre>
        <p style={{ margin: "10px 0 0", fontSize: "12px", color: "var(--text-muted)" }}>
          Severities: <code>info</code>, <code>low</code>, <code>medium</code>, <code>high</code>, <code>critical</code>.
          Example: <code>{curlExample}</code>
        </p>
      </details>

      <div className="list-table-wrap">
        <table className="certs-table">
          <thead>
            <tr>
              <th>Status</th><th>Application</th><th>Type / Dept</th><th>URL</th>
              <th>Latency</th><th>Uptime 24h</th><th>ROPA</th><th>DPIA</th><th>DPDP</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {apps.map(a => {
              const on = a.last_online === true;
              const uptime = a.uptime_24h == null ? "—" : `${parseFloat(a.uptime_24h).toFixed(1)}%`;
              const ropa = a.ropa_status || "not_started";
              const dpia = a.dpia_status || "not_started";
              const dpdp = a.dpdp_status || "not_started";
              return (
                <tr key={a.id}>
                  <td>
                    <span style={{ color: on ? "var(--ok)" : "var(--danger)", fontSize: "13px" }}>
                      {on ? "● ONLINE" : (a.last_checked ? "● OFFLINE" : "● NEW")}
                    </span>
                  </td>
                  <td><strong>{a.name}</strong><br /><span style={{ color: "var(--text-muted)", fontSize: "12px" }}>{a.app_key}</span></td>
                  <td>{a.type}{a.department && <span style={{ color: "var(--text-muted)", fontSize: "12px" }}><br />{a.department}</span>}</td>
                  <td style={{ maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    <span style={{ color: "var(--text-muted)" }}>{a.url}</span>
                  </td>
                  <td>{a.last_latency != null ? `${a.last_latency} ms` : "—"}</td>
                  <td>{uptime}</td>
                  <td>
                    <span className={compBadge(ropa)} style={{ fontSize: "11px" }}>{compLabel(ropa)}</span>
                    {a.ropa_updated_at && <span className="activity-meta" style={{ display: "block", fontSize: "10px" }}>{new Date(a.ropa_updated_at).toLocaleDateString()}</span>}
                    <select value={ropa} onChange={e => updateCompliance(a, "ropa_status", e.target.value)}
                      className="comp-select" title="Update ROPA status"
                      style={{ marginTop: "4px", fontSize: "11px", padding: "2px 4px", display: "block", width: "100%" }}>
                      <option value="not_started">Not started</option>
                      <option value="in_progress">In progress</option>
                      <option value="completed">Completed</option>
                    </select>
                    <input
                      type="text"
                      placeholder="Owner…"
                      defaultValue={a.ropa_owner || ""}
                      onBlur={e => updateOwner(a, "ropa_owner", e.target.value)}
                      className="comp-select"
                      title="Who is responsible for this policy"
                      style={{ marginTop: "4px", fontSize: "11px", padding: "2px 6px", width: "100%", boxSizing: "border-box" }}
                    />
                  </td>
                  <td>
                    <span className={compBadge(dpia)} style={{ fontSize: "11px" }}>{compLabel(dpia)}</span>
                    {a.dpia_updated_at && <span className="activity-meta" style={{ display: "block", fontSize: "10px" }}>{new Date(a.dpia_updated_at).toLocaleDateString()}</span>}
                    <select value={dpia} onChange={e => updateCompliance(a, "dpia_status", e.target.value)}
                      className="comp-select" title="Update DPIA status"
                      style={{ marginTop: "4px", fontSize: "11px", padding: "2px 4px", display: "block", width: "100%" }}>
                      <option value="not_started">Not started</option>
                      <option value="in_progress">In progress</option>
                      <option value="completed">Completed</option>
                    </select>
                    <input
                      type="text"
                      placeholder="Owner…"
                      defaultValue={a.dpia_owner || ""}
                      onBlur={e => updateOwner(a, "dpia_owner", e.target.value)}
                      className="comp-select"
                      title="Who is responsible for this policy"
                      style={{ marginTop: "4px", fontSize: "11px", padding: "2px 6px", width: "100%", boxSizing: "border-box" }}
                    />
                  </td>
                  <td>
                    <span className={compBadge(dpdp)} style={{ fontSize: "11px" }}>{compLabel(dpdp)}</span>
                    {a.dpdp_updated_at && <span className="activity-meta" style={{ display: "block", fontSize: "10px" }}>{new Date(a.dpdp_updated_at).toLocaleDateString()}</span>}
                    <select value={dpdp} onChange={e => updateCompliance(a, "dpdp_status", e.target.value)}
                      className="comp-select" title="Update DPDP status"
                      style={{ marginTop: "4px", fontSize: "11px", padding: "2px 4px", display: "block", width: "100%" }}>
                      <option value="not_started">Not started</option>
                      <option value="in_progress">In progress</option>
                      <option value="completed">Completed</option>
                    </select>
                    <input
                      type="text"
                      placeholder="Owner…"
                      defaultValue={a.dpdp_owner || ""}
                      onBlur={e => updateOwner(a, "dpdp_owner", e.target.value)}
                      className="comp-select"
                      title="Who is responsible for this policy"
                      style={{ marginTop: "4px", fontSize: "11px", padding: "2px 6px", width: "100%", boxSizing: "border-box" }}
                    />
                  </td>
                  <td style={{ whiteSpace: "nowrap" }}>
                    <button className="btn-secondary" onClick={() => toggleApp(a)} style={{ padding: "4px 10px", fontSize: "12px", marginRight: "6px" }}>
                      {a.enabled ? "Pause" : "Resume"}
                    </button>
                    <button className="btn-del" onClick={() => deleteApp(a)}>Delete</button>
                  </td>
                </tr>
              );
            })}
            {apps.length === 0 && (
              <tr><td colSpan={10} style={{ textAlign: "center", color: "var(--text-muted)", padding: "24px" }}>No applications registered yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <details className="card" style={{ marginTop: "18px", padding: "14px 16px" }}>
        <summary style={{ cursor: "pointer", fontWeight: 600, color: "var(--text-secondary)" }}>📋 Data-protection compliance (ROPA, DPIA &amp; DPDP)</summary>
        <div style={{ marginTop: "10px", fontSize: "13px", lineHeight: 1.6 }}>
          <p style={{ margin: "0 0 8px" }}>
            <strong>ROPA — Record of Processing Activities:</strong> the GDPR Article 30 register that records what
            personal data each application processes, for what purpose, which categories of data subjects, retention
            periods, and any processors. An app should have a completed ROPA before it goes live.
          </p>
          <p style={{ margin: "0 0 8px" }}>
            <strong>DPIA — Data Protection Impact Assessment:</strong> the GDPR Article 35 risk assessment required
            when an application processes personal data in a way that is likely to result in a high risk to individuals
            (e.g. large-scale processing, special-category data, profiling, or cross-border transfers).
          </p>
          <p style={{ margin: "0 0 8px" }}>
            <strong>DPDP — Digital Personal Data Protection Act (India, 2023):</strong> India's data-protection law.
            Covered apps should confirm lawful processing under a notice and consent regime, implement reasonable
            security safeguards, notify breaches (Data Protection Board), honour data-principal rights (access,
            correction, erasure, grievance), apply storage limitation and manage children's-data requirements —
            track the status of each app's DPDP obligations here.
          </p>
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" }}>
            <span className="badge connected">Completed</span>
            <span className="badge warn">In progress</span>
            <span className="badge danger">Not started</span>
            <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
              — use the dropdown to update status and the <em>Owner</em> box to name who is responsible.
              The changed date is recorded automatically.
            </span>
          </div>
        </div>
      </details>

      <h3 style={{ marginTop: "24px" }}>Recent Security Events</h3>
      <div className="list-table-wrap">
        <table className="certs-table">
          <thead>
            <tr><th>Severity</th><th>Type</th><th>Message</th><th>Application</th><th>User</th><th>Time</th></tr>
          </thead>
          <tbody>
            {(data && data.recent && data.recent.length > 0 ? data.recent : []).map((ev: any) => (
              <tr key={ev.id}>
                <td><span className={sevBadge(ev.severity)}>{ev.severity}</span></td>
                <td>{ev.type}</td>
                <td>{ev.message}</td>
                <td>{ev.app_name || "—"}</td>
                <td>{ev.username || "—"}</td>
                <td style={{ whiteSpace: "nowrap" }}>{new Date(ev.created_at).toLocaleString()}</td>
              </tr>
            ))}
            {!(data && data.recent && data.recent.length) && (
              <tr><td colSpan={6} style={{ textAlign: "center", color: "var(--text-muted)", padding: "24px" }}>No security events yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const DPIA_RISK_SELECT = ["low", "medium", "high", "critical"];
const DPIA_CATEGORY_SELECT = [
  "Student Records", "Academic Results", "Aadhaar Data", "Mobile Numbers",
  "Biometric Data", "Health Records", "Financial Data", "HR Employee Data",
  "CCTV / Surveillance", "IoT / Sensors", "Campus Access", "Online Services"
];
const DPIA_LIKELIHOOD_SELECT = ["rare", "unlikely", "possible", "likely", "almost_certain"];
const DPIA_IMPACT_SELECT = ["negligible", "minor", "moderate", "major", "severe"];

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

function riskBadgeColor(level: any) {
  if (level === "critical") return "#ef4444";
  if (level === "high") return "#f97316";
  if (level === "medium") return "#eab308";
  return "#22c55e";
}

function statusColor(s: any) {
  if (s === "completed") return "#22c55e";
  if (s === "in_progress") return "#3b82f6";
  if (s === "on_hold") return "#f59e0b";
  return "#64748b";
}

function DPIASection() {
  const [dash, setDash] = useState<any>(null);
  const [items, setItems] = useState<any[]>([]);
  const [risks, setRisks] = useState<any>({});
  const [audits, setAudits] = useState<any>({});
  const [expanded, setExpanded] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editId, setEditId] = useState<any>(null);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [workflow, setWorkflow] = useState({ stages: DPIA_DEFAULT_STAGES, transitions: DPIA_DEFAULT_TRANSITIONS });
  const [showWorkflowCfg, setShowWorkflowCfg] = useState(false);
  const [wfErr, setWfErr] = useState("");

  const stageMeta = (stage: any) => {
    const s = (workflow.stages || []).find(x => x.id === stage);
    return { id: stage, label: s ? s.label : (stage || "?").replace(/_/g, " "), color: s ? s.color : "#64748b" };
  };

  const canTransition = (a: any) => {
    const isAdminUser = localStorage.getItem("admin_role") === "admin";
    return (workflow.transitions || []).filter(t =>
      t.from === (a.stage || "draft") && (!t.requireAdmin || isAdminUser)
    );
  };

  const progIndex = (stage: any) => {
    const i = (workflow.stages || []).findIndex(s => s.id === stage);
    return i;
  };

  const emptyForm = () => ({
    title: "", description: "", businessUnit: "", stage: "draft", riskLevel: "medium",
    dataCategories: [] as string[], thirdParty: false, thirdPartyName: "",
    startDate: "", dueDate: "",
    risks: [{ description: "", likelihood: "possible", impact: "moderate", status: "open", remediation: "", dueDate: "" }]
  });
  const [form, setForm] = useState(emptyForm());

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([
      fetch(`${API_BASE}/api/dpia/dashboard`, { headers: authHeaders() }).then(r => r.ok ? r.json() : null),
      fetch(`${API_BASE}/api/dpia`, { headers: authHeaders() }).then(r => r.ok ? r.json() : []),
      fetch(`${API_BASE}/api/dpia/workflow`, { headers: authHeaders() }).then(r => r.ok ? r.json() : null),
    ]).then(([d, list, wf]) => {
      if (wf && Array.isArray(wf.stages)) setWorkflow(wf);
      setDash(d); setItems(list || []); setLoading(false);
      (list || []).forEach((a: any) => {
        fetch(`${API_BASE}/api/dpia/${a.id}`, { headers: authHeaders() }).then(r => r.ok ? r.json() : null)
          .then(detail => {
            if (detail) {
              setRisks((p: any) => ({ ...p, [a.id]: detail.risks || [] }));
              setAudits((p: any) => ({ ...p, [a.id]: detail.audit || [] }));
            }
          })
          .catch(() => {});
      });
    }).catch(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  const toggleCategory = (c: any) => {
    setForm((f: any) => {
      const has = f.dataCategories.includes(c);
      return { ...f, dataCategories: has ? f.dataCategories.filter((x: any) => x !== c) : [...f.dataCategories, c] };
    });
  };

  const submit = async (e: any) => {
    e.preventDefault();
    setMsg(""); setErr("");
    if (!form.title.trim()) { setErr("DPIA title is required"); return; }
    const cleanRisks = form.risks.map(r => ({
      description: r.description.trim(), likelihood: r.likelihood, impact: r.impact,
      status: r.status, remediation: r.remediation.trim(), dueDate: r.dueDate || null
    })).filter(r => r.description);
    const payload = { ...form, risks: cleanRisks, dataCategories: form.dataCategories };
    try {
      const url = editId ? `${API_BASE}/api/dpia/${editId}` : `${API_BASE}/api/dpia`;
      const res = await fetch(url, {
        method: editId ? "PUT" : "POST",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const d = await res.json();
      if (!res.ok) throw new Error(d.error || "Save failed");
      setMsg(editId ? "DPIA updated." : "DPIA created.");
      setShowForm(false); setEditId(null); setForm(emptyForm());
      load();
    } catch (ex: any) { setErr(ex.message); }
  };

  const doTransition = async (a: any, to: any, requireComment: any) => {
    const comment = requireComment ? window.prompt(`Comment required to move "${a.title}" to next stage:`) : "";
    if (requireComment && !comment) return;
    try {
      const res = await fetch(`${API_BASE}/api/dpia/${a.id}/transition`, {
        method: "POST",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ to, comment }),
      });
      const d = await res.json();
      if (!res.ok) throw new Error(d.error || "Transition failed");
      setMsg(`Moved "${a.title}" → ${stageMeta(to).label}.`);
      load();
    } catch (ex: any) { setErr(ex.message); }
  };

  const saveWorkflowCfg = async () => {
    setWfErr("");
    try {
      const res = await fetch(`${API_BASE}/api/dpia/workflow`, {
        method: "PUT",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ stages: workflow.stages, transitions: workflow.transitions }),
      });
      const d = await res.json();
      if (!res.ok) throw new Error(d.error || "Save failed");
      setWorkflow({ stages: d.stages, transitions: d.transitions });
      setMsg("Workflow configuration saved.");
      setShowWorkflowCfg(false);
      load();
    } catch (ex: any) { setWfErr(ex.message); }
  };

  const del = async (a: any) => {
    if (!window.confirm(`Delete DPIA "${a.title}" and its risks?`)) return;
    try {
      const res = await fetch(`${API_BASE}/api/dpia/${a.id}`, { method: "DELETE", headers: authHeaders() });
      if (!res.ok) throw new Error("Delete failed");
      load();
    } catch (ex: any) { alert(ex.message); }
  };

  const edit = (a: any) => {
    setEditId(a.id);
    setForm({
      title: a.title, description: a.description || "", businessUnit: a.businessUnit || "",
      stage: a.stage || "draft", riskLevel: a.riskLevel || "medium",
      dataCategories: Array.isArray(a.dataCategories) ? a.dataCategories : [],
      thirdParty: !!a.thirdParty, thirdPartyName: a.thirdPartyName || "",
      startDate: a.startDate ? a.startDate.slice(0, 10) : "",
      dueDate: a.dueDate ? a.dueDate.slice(0, 10) : "",
      risks: (risks[a.id] || [{ description: "", likelihood: "possible", impact: "moderate", status: "open", remediation: "", dueDate: "" }])
        .map((r: any) => ({ description: r.description, likelihood: r.likelihood, impact: r.impact, status: r.status, remediation: r.remediation || "", dueDate: r.dueDate ? r.dueDate.slice(0, 10) : "" }))
    });
    setShowForm(true);
  };

  const newForm = () => { setEditId(null); setForm(emptyForm()); setShowForm(true); };

  const downloadReport = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/dpia/report`, { headers: authHeaders() });
      if (!res.ok) throw new Error("Report failed");
      const text = await res.text();
      const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `dpia-executive-report-${new Date().toISOString().slice(0, 10)}.txt`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (ex: any) { alert(ex.message); }
  };

  const viewReport = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/dpia/report`, { headers: authHeaders() });
      if (!res.ok) throw new Error("Report failed");
      const text = await res.text();
      const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      window.open(url, "_blank");
      setTimeout(() => URL.revokeObjectURL(url), 30000);
    } catch (ex: any) { alert(ex.message); }
  };

  if (loading) return <div className="section"><p style={{ color: "var(--text-secondary)" }}>Loading DPIA report...</p></div>;

  const byUnit: any = {};
  (dash?.byUnit || []).forEach((r: any) => { byUnit[r.unit] = byUnit[r.unit] || {}; byUnit[r.unit][r.status] = r.count; });

  return (
    <div className="section">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px", flexWrap: "wrap", gap: "8px" }}>
        <h2 style={{ margin: 0, border: "none", padding: "0" }}>DPIA Reporting & Dashboard</h2>
        <div style={{ display: "flex", gap: "8px" }}>
          <button className="btn-secondary" onClick={viewReport} style={{ padding: "6px 12px", fontSize: "12px" }}>📄 View Report</button>
          <button className="btn-secondary" onClick={downloadReport} style={{ padding: "6px 12px", fontSize: "12px" }}>⬇️ Export Report</button>
          <button className="btn-secondary" onClick={() => setShowWorkflowCfg(!showWorkflowCfg)} style={{ padding: "6px 12px", fontSize: "12px" }}>{showWorkflowCfg ? "✕ Close Workflow" : "⚙️ Workflow"}</button>
          <button className="btn-primary" onClick={newForm} style={{ padding: "6px 12px", fontSize: "12px" }}>+ New DPIA</button>
        </div>
      </div>

      {msg && <div className="notice success" style={{ marginBottom: "12px" }}>{msg}</div>}
      {err && <div className="notice error" style={{ marginBottom: "12px" }}>{err}</div>}

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">🛡️</div>
          <div className="stat-value">{dash?.totalDpias ?? 0}</div>
          <div className="stat-label">Total DPIAs</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">✅</div>
          <div className="stat-value">{dash?.completed ?? 0} / {dash?.open ?? 0}</div>
          <div className="stat-label">Completed / Open</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">⚠️</div>
          <div className="stat-value">{dash?.highRiskProcessing ?? 0}</div>
          <div className="stat-label">High-Risk Activities</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🔓</div>
          <div className="stat-value">{dash?.openPrivacyRisks ?? 0} / {dash?.overdueRemediation ?? 0}</div>
          <div className="stat-label">Open / Overdue Risks</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🤝</div>
          <div className="stat-value">{dash?.thirdPartyProcessing ?? 0}</div>
          <div className="stat-label">Third-Party Processing</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">📦</div>
          <div className="stat-value">{dash?.dataCategories?.length ?? 0}</div>
          <div className="stat-label">Data Categories</div>
        </div>
      </div>

      <div style={{ display: "flex", gap: "20px", flexWrap: "wrap", marginTop: "20px" }}>
        <div className="chart-panel" style={{ flex: "1", minWidth: "300px" }}>
          <h3>DPIA Status by Business Unit</h3>
          <table className="subjects-table" style={{ width: "100%", fontSize: "13px" }}>
            <thead>
              <tr><th>Business Unit</th><th>Draft</th><th>In Progress</th><th>Completed</th><th>On Hold</th></tr>
            </thead>
            <tbody>
              {Object.keys(byUnit).sort().map(u => (
                <tr key={u}>
                  <td>{u}</td>
                  <td>{byUnit[u].draft || 0}</td>
                  <td>{byUnit[u].in_progress || 0}</td>
                  <td>{byUnit[u].completed || 0}</td>
                  <td>{byUnit[u].on_hold || 0}</td>
                </tr>
              ))}
              {Object.keys(byUnit).length === 0 && <tr><td colSpan={5} style={{ textAlign: "center", color: "var(--text-muted)", padding: "16px" }}>No assessments yet.</td></tr>}
            </tbody>
          </table>
        </div>

        <div className="chart-panel" style={{ flex: "1", minWidth: "280px" }}>
          <h3>Data Categories Processed</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "260px", overflowY: "auto" }}>
            {(dash?.dataCategories || []).map((dc: any) => (
              <div key={dc.category} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ flex: 1, fontSize: "13px" }}>{dc.category}</span>
                <span className="badge connected">{dc.count}</span>
              </div>
            ))}
            {(dash?.dataCategories || []).length === 0 && <p style={{ color: "var(--text-muted)", fontSize: "13px" }}>None yet.</p>}
          </div>
        </div>

        <div className="chart-panel" style={{ flex: "1", minWidth: "260px" }}>
          <h3>Risk Breakdown</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "13px" }}>
              <span>Open risks</span><span className="badge">{dash?.riskBreakdown?.open ?? 0}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "13px" }}>
              <span>Resolved risks</span><span className="badge connected">{dash?.riskBreakdown?.resolved ?? 0}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "13px" }}>
              <span>High / Critical risks</span><span className="badge alert">{dash?.riskBreakdown?.high ?? 0}</span>
            </div>
          </div>
        </div>
      </div>

      {showWorkflowCfg && (
        <div className="chart-panel" style={{ marginTop: "24px" }}>
          <h3>⚙️ DPIA Approval Workflow Configuration</h3>
          {wfErr && <div className="notice error" style={{ marginBottom: "12px" }}>{wfErr}</div>}
          <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "12px" }}>
            Customize the pipeline stages and allow/block transitions. Transitions marked <strong>Admin only</strong>
            require an administrator to execute; transitions marked <strong>Comment</strong> require a comment.
          </p>

          <label style={{ fontWeight: 600, display: "block", margin: "16px 0 8px" }}>Stages (in pipeline order)</label>
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            {workflow.stages.map((s, i) => (
              <div key={s.id} style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12px" }}>
                <span className="badge" style={{ background: s.color, width: "150px" }}>{s.id}</span>
                <input value={s.label} onChange={e => {
                  const stages = [...workflow.stages];
                  stages[i] = { ...stages[i], label: e.target.value };
                  setWorkflow({ ...workflow, stages });
                }} style={{ flex: 1, padding: "4px 8px" }} />
                <input type="color" value={s.color} onChange={e => {
                  const stages = [...workflow.stages];
                  stages[i] = { ...stages[i], color: e.target.value };
                  setWorkflow({ ...workflow, stages });
                }} title="Stage color" />
                {i > 0 && <button className="btn-secondary" style={{ padding: "3px 8px", fontSize: "11px" }} onClick={() => {
                  const stages = [...workflow.stages];
                  [stages[i - 1], stages[i]] = [stages[i], stages[i - 1]];
                  setWorkflow({ ...workflow, stages });
                }}>↑</button>}
                {i < workflow.stages.length - 1 && <button className="btn-secondary" style={{ padding: "3px 8px", fontSize: "11px" }} onClick={() => {
                  const stages = [...workflow.stages];
                  [stages[i], stages[i + 1]] = [stages[i + 1], stages[i]];
                  setWorkflow({ ...workflow, stages });
                }}>↓</button>}
                <button className="btn-danger" style={{ padding: "3px 8px", fontSize: "11px" }} onClick={() => {
                  const id = s.id;
                  setWorkflow(w => ({
                    stages: w.stages.filter(x => x.id !== id),
                    transitions: w.transitions.filter(t => t.from !== id && t.to !== id),
                  }));
                }}>✕</button>
              </div>
            ))}
            <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
              <button className="btn-secondary" style={{ padding: "3px 8px", fontSize: "11px" }} onClick={() => {
                const nid = window.prompt("New stage id (e.g. 'consultation'):");
                const nlabel = window.prompt("Stage label:", nid || "");
                if (!nid) return;
                setWorkflow(w => ({ ...w, stages: [...w.stages, { id: nid, label: nlabel || nid, color: "#64748b" }] }));
              }}>+ Add Stage</button>
            </div>
          </div>

          <label style={{ fontWeight: 600, display: "block", margin: "20px 0 8px" }}>Transitions</label>
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            {workflow.transitions.map((t, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12px", flexWrap: "wrap" }}>
                <select value={t.from} onChange={e => {
                  const ts = [...workflow.transitions];
                  ts[i] = { ...ts[i], from: e.target.value };
                  setWorkflow({ ...workflow, transitions: ts });
                }} style={{ padding: "4px" }}>
                  {workflow.stages.map(s => <option key={s.id} value={s.id}>{s.id}</option>)}
                </select>
                <span>→</span>
                <select value={t.to} onChange={e => {
                  const ts = [...workflow.transitions];
                  ts[i] = { ...ts[i], to: e.target.value };
                  setWorkflow({ ...workflow, transitions: ts });
                }} style={{ padding: "4px" }}>
                  {workflow.stages.map(s => <option key={s.id} value={s.id}>{s.id}</option>)}
                </select>
                <input value={t.label} onChange={e => {
                  const ts = [...workflow.transitions];
                  ts[i] = { ...ts[i], label: e.target.value };
                  setWorkflow({ ...workflow, transitions: ts });
                }} placeholder="Action label" style={{ flex: 1, padding: "4px 8px" }} />
                <label style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "11px" }}>
                  <input type="checkbox" checked={!!t.requireComment} onChange={e => {
                    const ts = [...workflow.transitions];
                    ts[i] = { ...ts[i], requireComment: e.target.checked };
                    setWorkflow({ ...workflow, transitions: ts });
                  }} /> Comment
                </label>
                <label style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "11px" }}>
                  <input type="checkbox" checked={!!t.requireAdmin} onChange={e => {
                    const ts = [...workflow.transitions];
                    ts[i] = { ...ts[i], requireAdmin: e.target.checked };
                    setWorkflow({ ...workflow, transitions: ts });
                  }} /> Admin only
                </label>
                <button className="btn-danger" style={{ padding: "3px 8px", fontSize: "11px" }} onClick={() => {
                  setWorkflow(w => ({ ...w, transitions: w.transitions.filter((_, j) => j !== i) }));
                }}>✕</button>
              </div>
            ))}
            <div style={{ display: "flex", gap: "6px" }}>
              <button className="btn-secondary" style={{ padding: "3px 8px", fontSize: "11px" }} onClick={() => {
                setWorkflow(w => ({ ...w, transitions: [...w.transitions, { from: "draft", to: "assessment", label: "Next step", requireComment: false, requireAdmin: false }] }));
              }}>+ Add Transition</button>
              <button className="btn-secondary" style={{ padding: "3px 8px", fontSize: "11px" }} onClick={() => {
                setWorkflow({ stages: DPIA_DEFAULT_STAGES, transitions: DPIA_DEFAULT_TRANSITIONS });
                setWfErr("");
              }}>↺ Reset to Defaults</button>
            </div>
          </div>

          <div style={{ marginTop: "16px", display: "flex", gap: "8px" }}>
            <button className="btn-primary" onClick={saveWorkflowCfg} style={{ padding: "6px 14px", fontSize: "12px" }}>Save Workflow</button>
            <button className="btn-secondary" onClick={() => setShowWorkflowCfg(false)} style={{ padding: "6px 14px", fontSize: "12px" }}>Cancel</button>
          </div>
        </div>
      )}

      {showForm && (
        <div className="chart-panel" style={{ marginTop: "24px" }}>
          <h3>{editId ? "Edit DPIA" : "New DPIA Assessment"}</h3>
          <form onSubmit={submit} className="form-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
            <div className="input-group">
              <label>Title *</label>
              <input value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} placeholder="e.g. Student Result Portal" />
            </div>
            <div className="input-group">
              <label>Business Unit</label>
              <input value={form.businessUnit} onChange={e => setForm({ ...form, businessUnit: e.target.value })} placeholder="e.g. Records Office" />
            </div>
            <div className="input-group" style={{ gridColumn: "1 / -1" }}>
              <label>Description</label>
              <textarea value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} placeholder="Describe the processing activity..." rows={2} />
            </div>
            <div className="input-group">
              <label>Workflow Stage</label>
              <select value={form.stage} onChange={e => setForm({ ...form, stage: e.target.value })}>
                {(workflow.stages || []).map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
              </select>
            </div>
            <div className="input-group">
              <label>Overall Risk Level</label>
              <select value={form.riskLevel} onChange={e => setForm({ ...form, riskLevel: e.target.value })}>
                {DPIA_RISK_SELECT.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div className="input-group">
              <label>Start Date</label>
              <input type="date" value={form.startDate} onChange={e => setForm({ ...form, startDate: e.target.value })} />
            </div>
            <div className="input-group">
              <label>Due Date</label>
              <input type="date" value={form.dueDate} onChange={e => setForm({ ...form, dueDate: e.target.value })} />
            </div>
            <div className="input-group" style={{ gridColumn: "1 / -1" }}>
              <label>Data Categories</label>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                {DPIA_CATEGORY_SELECT.map((c: any) => (
                  <button key={c} type="button" onClick={() => toggleCategory(c)}
                    className={form.dataCategories.includes(c) ? "badge connected" : "badge"}
                    style={{ cursor: "pointer", border: "none", fontSize: "12px" }}>
                    {c}
                  </button>
                ))}
              </div>
            </div>
            <div className="input-group">
              <label style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <input type="checkbox" checked={form.thirdParty} onChange={e => setForm({ ...form, thirdParty: e.target.checked })} />
                Involves third-party processor
              </label>
              {form.thirdParty && <input value={form.thirdPartyName} onChange={e => setForm({ ...form, thirdPartyName: e.target.value })} placeholder="Third-party name" style={{ marginTop: "6px" }} />}
            </div>

            <div style={{ gridColumn: "1 / -1" }}>
              <label style={{ fontWeight: 600 }}>Privacy Risks</label>
              {form.risks.map((r, i) => (
                <div key={i} className="chart-panel" style={{ padding: "12px", marginTop: "8px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <strong style={{ fontSize: "13px" }}>Risk #{i + 1}</strong>
                    <button type="button" className="btn-secondary" style={{ padding: "2px 8px", fontSize: "11px" }}
                      onClick={() => setForm(f => ({ ...f, risks: f.risks.filter((_, j) => j !== i) }))}>Remove</button>
                  </div>
                  <div className="form-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginTop: "8px" }}>
                    <input style={{ gridColumn: "1 / -1" }} value={r.description} onChange={e => { const risks = [...form.risks]; risks[i] = { ...risks[i], description: e.target.value }; setForm({ ...form, risks }); }} placeholder="Describe the risk" />
                    <select value={r.likelihood} onChange={e => { const risks = [...form.risks]; risks[i] = { ...risks[i], likelihood: e.target.value }; setForm({ ...form, risks }); }}>
                      {DPIA_LIKELIHOOD_SELECT.map(o => <option key={o} value={o}>{o.replace(/_/g, " ")}</option>)}
                    </select>
                    <select value={r.impact} onChange={e => { const risks = [...form.risks]; risks[i] = { ...risks[i], impact: e.target.value }; setForm({ ...form, risks }); }}>
                      {DPIA_IMPACT_SELECT.map(o => <option key={o} value={o}>{o.replace(/_/g, " ")}</option>)}
                    </select>
                    <select value={r.status} onChange={e => { const risks = [...form.risks]; risks[i] = { ...risks[i], status: e.target.value }; setForm({ ...form, risks }); }}>
                      <option value="open">Open</option>
                      <option value="mitigating">Mitigating</option>
                      <option value="resolved">Resolved</option>
                    </select>
                    <input type="date" value={r.dueDate} onChange={e => { const risks = [...form.risks]; risks[i] = { ...risks[i], dueDate: e.target.value }; setForm({ ...form, risks }); }} />
                    <input style={{ gridColumn: "1 / -1" }} value={r.remediation} onChange={e => { const risks = [...form.risks]; risks[i] = { ...risks[i], remediation: e.target.value }; setForm({ ...form, risks }); }} placeholder="Remediation plan" />
                  </div>
                </div>
              ))}
              <button type="button" className="btn-secondary" style={{ marginTop: "8px", padding: "6px 12px", fontSize: "12px" }}
                onClick={() => setForm(f => ({ ...f, risks: [...f.risks, { description: "", likelihood: "possible", impact: "moderate", status: "open", remediation: "", dueDate: "" }] }))}>+ Add Risk</button>
            </div>

            <div style={{ gridColumn: "1 / -1", display: "flex", gap: "8px" }}>
              <button type="submit" className="btn-primary">{editId ? "Save Changes" : "Create DPIA"}</button>
              <button type="button" className="btn-secondary" onClick={() => { setShowForm(false); setEditId(null); }}>Cancel</button>
            </div>
          </form>
        </div>
      )}

      <h3 style={{ marginTop: "24px" }}>All DPIAs</h3>
      <div className="certs-table-wrap" style={{ overflowX: "auto" }}>
        <table className="certs-table">
          <thead>
            <tr>
              <th>Title</th><th>Business Unit</th><th>Stage</th><th>Risk</th><th>Sub-processes</th><th>Third-Party</th><th>Due</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map(a => {
              const subRisk = risks[a.id] || [];
              return (
                <tr key={a.id}>
                  <td style={{ fontWeight: 600, cursor: "pointer" }} onClick={() => setExpanded(expanded === a.id ? null : a.id)}>
                    {a.title} {subRisk.length > 0 && <span className="badge">{subRisk.length}</span>}
                  </td>
                  <td>{a.businessUnit || "—"}</td>
                  <td><span className="badge" style={{ background: stageMeta(a.stage).color }}>{stageMeta(a.stage).label}</span></td>
                  <td><span className="badge" style={{ background: riskBadgeColor(a.riskLevel) }}>{a.riskLevel}</span></td>
                  <td>{(a.dataCategories || []).slice(0, 2).join(", ")}{a.dataCategories?.length > 2 ? ` +${a.dataCategories.length - 2}` : ""}</td>
                  <td>{a.thirdParty ? (a.thirdPartyName || "Yes") : "—"}</td>
                  <td>{a.dueDate ? new Date(a.dueDate).toLocaleDateString() : "—"}</td>
                  <td>
                    <button className="btn-secondary" onClick={() => edit(a)} style={{ padding: "3px 8px", fontSize: "11px", marginRight: "4px" }}>✏️</button>
                    <button className="btn-danger" onClick={() => del(a)} style={{ padding: "3px 8px", fontSize: "11px" }}>🗑️</button>
                  </td>
                </tr>
              );
            })}
            {items.length === 0 && <tr><td colSpan={8} style={{ textAlign: "center", color: "var(--text-muted)", padding: "24px" }}>No DPIAs yet. Create your first assessment.</td></tr>}
          </tbody>
        </table>
      </div>

      {expanded && items.find(a => a.id === expanded) && (
        <div className="chart-panel" style={{ marginTop: "16px" }}>
          {(() => {
            const a = items.find(x => x.id === expanded);
            const meta = stageMeta(a.stage);
            const progs = progIndex(a.stage);
            const next = canTransition(a);
            const audit = audits[expanded] || [];
            return (
              <>
                <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: "8px", alignItems: "center" }}>
                  <h3 style={{ margin: 0, border: "none", padding: 0 }}>Workflow — {a.title}</h3>
                  <span className="badge" style={{ background: meta.color, fontSize: "12px" }}>Current: {meta.label}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "4px", flexWrap: "wrap", margin: "16px 0" }}>
                  {(workflow.stages || []).map((s, i) => (
                    <div key={s.id} style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                      <div style={{
                        display: "flex", alignItems: "center", gap: "6px", padding: "4px 10px",
                        borderRadius: "999px", background: i <= progs ? s.color : "var(--panel-bg)",
                        color: i <= progs ? "#fff" : "var(--text-muted)", border: `1px solid ${s.color}`,
                        fontSize: "12px", fontWeight: i === progs ? 700 : 400
                      }}>
                        {i < progs ? "✓" : i === progs ? "●" : `${i + 1}.`} {s.label}
                      </div>
                      {i < workflow.stages.length - 1 && <span style={{ color: "var(--text-muted)" }}>→</span>}
                    </div>
                  ))}
                </div>

                {next.length > 0 && (
                  <div style={{ marginBottom: "16px" }}>
                    <strong style={{ fontSize: "13px", display: "block", marginBottom: "6px" }}>Advance workflow:</strong>
                    <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                      {next.map(t => (
                        <button key={`${t.from}-${t.to}`} className="btn-primary" style={{ padding: "5px 12px", fontSize: "12px" }}
                          onClick={() => doTransition(a, t.to, t.requireComment)}>
                          {t.label} {t.requireComment ? " (comment)" : ""}
                          {t.requireAdmin ? " ⭐" : ""}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                <h3 style={{ margin: "0 0 8px", border: "none", padding: 0, fontSize: "16px" }}>Privacy Risks — {a.title}</h3>
                <table className="subjects-table" style={{ width: "100%", fontSize: "13px" }}>
                  <thead><tr><th>Risk</th><th>Likelihood</th><th>Impact</th><th>Level</th><th>Status</th><th>Due</th><th>Remediation</th></tr></thead>
                  <tbody>
                    {(risks[expanded] || []).map((r: any) => (
                      <tr key={r.id}>
                        <td>{r.description}</td>
                        <td>{r.likelihood}</td>
                        <td>{r.impact}</td>
                        <td><span className="badge" style={{ background: riskBadgeColor(r.riskLevel) }}>{r.riskLevel}</span></td>
                        <td><span className="badge" style={{ background: statusColor(r.status) }}>{r.status}</span></td>
                        <td>{r.dueDate ? new Date(r.dueDate).toLocaleDateString() : "—"}</td>
                        <td>{r.remediation || "—"}</td>
                      </tr>
                    ))}
                    {(risks[expanded] || []).length === 0 && <tr><td colSpan={7} style={{ textAlign: "center", color: "var(--text-muted)", padding: "12px" }}>No risks recorded.</td></tr>}
                  </tbody>
                </table>

                <h3 style={{ margin: "20px 0 8px", border: "none", padding: 0, fontSize: "16px" }}>Audit Trail</h3>
                <div style={{ display: "flex", flexDirection: "column", gap: "6px", maxHeight: "260px", overflowY: "auto" }}>
                  {audit.map((e: any, i: any) => (
                    <div key={e.id || i} style={{ fontSize: "12px", borderLeft: "3px solid var(--primary)", paddingLeft: "10px", background: "var(--panel-bg)" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: "6px" }}>
                        <strong>{e.action.replace(/_/g, " ")}</strong>
                        <span style={{ color: "var(--text-muted)" }}>{new Date(e.createdAt).toLocaleString()} — {e.username}</span>
                      </div>
                      {(e.fromStage || e.toStage) && (
                        <div style={{ color: "var(--text-secondary)", marginTop: "2px" }}>
                          {e.fromStage && <span style={{ color: stageMeta(e.fromStage).color }}>● {stageMeta(e.fromStage).label}</span>}
                          {e.fromStage && e.toStage && <span> → </span>}
                          {e.toStage && <span style={{ color: stageMeta(e.toStage).color }}>● {stageMeta(e.toStage).label}</span>}
                        </div>
                      )}
                      {e.comment && <div style={{ color: "var(--text-secondary)", marginTop: "2px", fontStyle: "italic" }}>"{e.comment}"</div>}
                    </div>
                  ))}
                  {audit.length === 0 && <p style={{ color: "var(--text-muted)", fontSize: "13px" }}>No audit entries yet.</p>}
                </div>
              </>
            );
          })()}
        </div>
      )}
    </div>
  );
}
