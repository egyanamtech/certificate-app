import React, { useState, createContext, useContext, useEffect } from "react";
import AdminPage from "./AdminPage";
import VerifyPage from "./VerifyPage";
import VerifyResult from "./VerifyResult";
import { UNIVERSITY, DEFAULT_LOGO_SVG } from "./config";
import "./App.css";

const ThemeContext = createContext();
const BrandContext = createContext();

export { ThemeContext, BrandContext };

export function useTheme() {
  return useContext(ThemeContext);
}

export function useBrand() {
  return useContext(BrandContext);
}

export { Logo };

function getPageFromHash() {
  const raw = window.location.hash.slice(1).replace(/^\//, "") || "";
  if (raw === "admin") return "admin";
  if (raw === "verify" || raw.startsWith("verify/")) return "verify";
  if (raw === "result" || raw.startsWith("result/")) return "result";
  return "home";
}

function getHashParam() {
  return window.location.hash.slice(1).replace(/^\//, "").split("/")[1] || "";
}

function Logo({ size = 80 }) {
  const { brand } = useBrand();
  if (brand.logo) {
    return <img src={brand.logo} alt={brand.name} style={{ width: size, height: size, borderRadius: "18px", objectFit: "cover" }} />;
  }
  const svg = DEFAULT_LOGO_SVG
    .replace('width="80" height="80"', `width="${size}" height="${size}"`)
    .replace(/>XYZ</, `>${brand.shortName || "U"}</`);
  return <div style={{ width: size, height: size }} dangerouslySetInnerHTML={{ __html: svg }} />;
}

export default function App() {
  const [page, setPage] = useState(getPageFromHash);
  const [theme, setTheme] = useState(() => localStorage.getItem("app_theme") || "dark");
  const [brand, setBrand] = useState(UNIVERSITY);

  useEffect(() => {
    fetch(`${window.location.origin.replace(/:\d+$/, "")}:5000/api/brand`)
      .then(r => r.json())
      .then(full => {
        if (full && full.name) setBrand(b => ({ ...b, ...full }));
      })
      .catch(() => {});
  }, []);

  const brandValue = { brand, setBrand };

  useEffect(() => {
    const base = brand.name || "University";
    const suffix = page === "admin" ? "Admin Portal" : page === "verify" ? "Verify Certificate" : page === "result" ? "Check Result" : "Certificate Portal";
    document.title = `${base} · ${suffix}`;
  }, [brand, page]);

  useEffect(() => {
    const cur = window.location.hash.slice(1).replace(/^\//, "");
    if (page === "home") {
      if (cur) window.location.hash = "";
    } else if (cur !== page && !cur.startsWith(page + "/")) {
      window.location.hash = page;
    }
  }, [page]);

  useEffect(() => {
    const onHashChange = () => setPage(getPageFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const toggleTheme = () => setTheme(t => {
    const next = t === "dark" ? "light" : "dark";
    localStorage.setItem("app_theme", next);
    return next;
  });

  document.body.className = theme;

  const goHome = () => {
    localStorage.removeItem("admin_token");
    setPage("home");
  };

  if (page === "admin") return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      <BrandContext.Provider value={brandValue}>
        <AdminPage onBack={goHome} />
      </BrandContext.Provider>
    </ThemeContext.Provider>
  );
  if (page === "verify") return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      <BrandContext.Provider value={brandValue}>
        <VerifyPage onBack={goHome} initialHash={getHashParam()} />
      </BrandContext.Provider>
    </ThemeContext.Provider>
  );
  if (page === "result") return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      <BrandContext.Provider value={brandValue}>
        <VerifyResult onBack={goHome} />
      </BrandContext.Provider>
    </ThemeContext.Provider>
  );

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      <BrandContext.Provider value={brandValue}>
        <div className="landing-page">
          <header className="landing-nav">
            <div className="landing-nav-brand">
              <Logo size={44} />
              <div className="landing-nav-name">
                <span className="landing-nav-title-text">{brand.name}</span>
                <span className="landing-nav-sub">{brand.shortName} · Certificate Verification</span>
              </div>
            </div>
            <button className="btn-theme" onClick={toggleTheme} aria-label="Toggle theme">
              {theme === "dark" ? "☀️" : "🌙"}
            </button>
          </header>

          <main className="landing-main">
            <div className="landing-hero">
              <span className="landing-eyebrow">ACADEMIC CREDENTIALS</span>
              <div className="landing-logo"><Logo size={96} /></div>
              <h1 className="landing-title">{brand.name}</h1>
              <p className="landing-tagline">{UNIVERSITY.tagline}</p>
              <p className="landing-desc">{UNIVERSITY.description}</p>

              <div className="landing-actions">
                <button className="btn-landing verify" onClick={() => setPage("verify")}>
                  <span className="btn-icon">🎓</span>
                  Verify a Certificate
                </button>
                <button className="btn-landing verify" onClick={() => setPage("result")} style={{ background: "#059669" }}>
                  <span className="btn-icon">📋</span>
                  Check Result
                </button>
                <button className="btn-landing admin" onClick={() => setPage("admin")}>
                  <span className="btn-icon">🔐</span>
                  Admin Portal
                </button>
              </div>
            </div>

            <div className="landing-features">
              <div className="feature-card">
                <span className="feature-icon">🛡️</span>
                <strong>Tamper-Proof</strong>
                <span>Cryptographically anchored to the blockchain</span>
              </div>
              <div className="feature-card">
                <span className="feature-icon">⚡</span>
                <strong>Instant Verify</strong>
                <span>Check authenticity by certificate hash</span>
              </div>
              <div className="feature-card">
                <span className="feature-icon">🌍</span>
                <strong>Globally Verifiable</strong>
                <span>Authenticated from anywhere, anytime</span>
              </div>
            </div>

            <section className="landing-section how-it-works">
              <h2 className="landing-section-title">How It Works</h2>
              <div className="how-steps">
                <div className="how-step">
                  <span className="how-step-num">1</span>
                  <span className="how-step-icon">📜</span>
                  <strong>Certificate is Issued</strong>
                  <span className="how-step-desc">The records office issues a certificate and its details are written to the blockchain.</span>
                </div>
                <div className="how-step">
                  <span className="how-step-num">2</span>
                  <span className="how-step-icon">🔗</span>
                  <strong>Stored Securely</strong>
                  <span className="how-step-desc">A unique fingerprint (hash) is permanently linked to the student record on-chain.</span>
                </div>
                <div className="how-step">
                  <span className="how-step-num">3</span>
                  <span className="how-step-icon">✅</span>
                  <strong>Verified Instantly</strong>
                  <span className="how-step-desc">Employers and students verify authenticity in seconds — no paper, no third party.</span>
                </div>
              </div>
            </section>

            <section className="landing-section trust-band">
              <span className="trust-quote">“</span>
              <blockquote className="trust-text">
                Every certificate issued through {brand.name} can be independently verified anywhere in the world —
                eliminating forged documents and manual verification delays.
              </blockquote>
              <span className="trust-by">— Official Records Office, {brand.name}</span>
            </section>
          </main>

          <footer className="landing-footer">
            <span>© {UNIVERSITY.established} {brand.name}</span>
            <span className="landing-footer-sep">·</span>
            <span>{UNIVERSITY.location}</span>
            <span className="landing-footer-sep">·</span>
            <span>Official Records Office</span>
          </footer>
        </div>
      </BrandContext.Provider>
    </ThemeContext.Provider>
  );
}
