import React, { useState, useCallback, useEffect } from "react";
import { QRCodeSVG } from "qrcode.react";
import { useTheme } from "./App";

const API_BASE = process.env.NODE_ENV === 'development'
  ? `http://${window.location.hostname}:5000`
  : '';

export default function VerifyPage({ onBack, initialHash = "" }) {
  const { theme, toggleTheme } = useTheme();
  const [hash, setHash] = useState(initialHash);
  const [result, setResult] = useState(null);
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);

  const verify = useCallback(async () => {
    try {
      const h = hash.trim();
      if (!h) return alert("Enter a certificate hash");
      setLoading(true);
      setStatus("Verifying...");
      setResult(null);

      const res = await fetch(`${API_BASE}/api/verify/${encodeURIComponent(h)}`);
      const data = await res.json();

      if (data.valid) {
        setResult(data);
        setStatus("Certificate Verified");
      } else {
        setResult({ valid: false });
        setStatus("Certificate Not Found");
      }
    } catch {
      setStatus("Verification failed");
    } finally {
      setLoading(false);
    }
  }, [hash]);

  useEffect(() => {
    if (initialHash.trim()) verify();
  }, []);

  return (
    <div className="page">
      <div className="card" style={{ maxWidth: "560px" }}>
        <div className="header">
          <button className="btn-back" onClick={onBack}>Back</button>
          <button className="btn-theme" onClick={toggleTheme}>{theme === "dark" ? "☀️" : "🌙"}</button>
        </div>
        <div style={{ textAlign: "center", fontSize: "48px", margin: "12px 0 8px" }}>🎓</div>
        <h1 style={{ textAlign: "center" }}>Verify Certificate</h1>
        <p style={{ textAlign: "center", color: "var(--text-secondary)", fontSize: "14px", marginBottom: "24px" }}>
          Enter the certificate hash to verify its authenticity
        </p>

        <div style={{ display: "flex", gap: "10px" }}>
          <input
            type="text"
            placeholder="Enter Certificate Hash"
            value={hash}
            onChange={(e) => setHash(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && verify()}
            style={{ flex: 1 }}
          />
          <button
            className="btn-primary"
            onClick={verify}
            disabled={loading}
            style={{ width: "auto", padding: "10px 20px", whiteSpace: "nowrap" }}
          >
            {loading ? <><span className="spinner" /> Verifying</> : "Verify"}
          </button>
        </div>

        {status && <div className="status">{status}</div>}

        {result && result.valid !== false && (
          <div className="result-card success">
            <p><strong style={{ color: "#86efac" }}>Certificate Verified</strong></p>
            <div className="verify-qr">
              <QRCodeSVG
                value={`${window.location.origin}/#/verify/${result.hash}`}
                size={140}
                bgColor="transparent"
                fgColor={theme === "dark" ? "#e2e8f0" : "#0f172a"}
              />
              <p style={{ fontSize: "12px", color: "var(--text-secondary)" }}>Scan to re-verify this certificate</p>
            </div>
            {result && result.ipfsHash && (
              <div style={{ marginTop: "14px", textAlign: "center" }}>
                <a
                  className="btn-primary"
                  href={`https://ipfs.io/ipfs/${result.ipfsHash}`}
                  target="_blank"
                  rel="noreferrer"
                  style={{ display: "inline-block", textDecoration: "none", padding: "10px 18px" }}
                >
                  ⬇️ Download Certificate
                </a>
              </div>
            )}
            <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "8px" }}>
              <strong>Hash:</strong> <span className="hash-text">{result.hash}</span>{" "}
              <button className="btn-copy" onClick={(e) => { e.stopPropagation(); navigator.clipboard.writeText(result.hash); e.target.textContent = "Copied!"; setTimeout(() => { e.target.textContent = "Copy"; }, 1500); }}>Copy</button>
            </p>
          </div>
        )}

        {result && result.valid === false && (
          <div className="result-card error">
            <p><strong style={{ color: "#fca5a5" }}>Certificate Not Found</strong></p>
            <p style={{ color: "#94a3b8", fontSize: "13px" }}>No certificate exists for this hash.</p>
          </div>
        )}
      </div>
    </div>
  );
}