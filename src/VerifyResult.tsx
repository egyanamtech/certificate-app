import React, { useState, useCallback } from "react";
import { useTheme } from "./App";
import type {
  SubjectEntry,
  SubjectStats,
  StudentResult,
  OtpRequestResponse,
  OtpVerifyResponse,
  IssueSubmitResponse,
} from "./types/results";

const API_BASE =
  process.env.NODE_ENV === "development"
    ? `http://${window.location.hostname}:5000`
    : "";

type ResultStep = "identify" | "otp" | "done";

interface VerifyResultProps {
  onBack: () => void;
}

export function computeStats(subjects: SubjectEntry[]): SubjectStats {
  let total = 0, max = 0, count = 0;
  for (const s of subjects) {
    if (s.marks != null && !isNaN(Number(s.marks))) {
      total += Number(s.marks);
      if (s.maxMarks != null && !isNaN(Number(s.maxMarks))) max += Number(s.maxMarks);
      count++;
    }
  }
  const pct = max > 0 ? Math.round((total / max) * 100) : 0;
  const allPassed = subjects.every(s => {
    if (s.marks == null) return true;
    const m = Number(s.marks);
    if (m === 0) return false;
    if (s.grade && String(s.grade).toUpperCase() === "F") return false;
    return true;
  });
  return { total, max, pct, count, allPassed };
}

export default function VerifyResult({ onBack }: VerifyResultProps) {
  const { theme, toggleTheme } = useTheme();
  const [step, setStep] = useState<ResultStep>("identify"); // identify -> otp -> done
  const [roll, setRoll] = useState("");
  const [sem, setSem] = useState("");
  const [aadhaar, setAadhaar] = useState("");
  const [otp, setOtp] = useState("");
  const [maskedMobile, setMaskedMobile] = useState("");
  const [demoOtp, setDemoOtp] = useState("");
  const [resultToken, setResultToken] = useState("");
  const [results, setResults] = useState<StudentResult[] | null>(null);
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);
  const [showIssue, setShowIssue] = useState(false);
  const [issueMsg, setIssueMsg] = useState("");
  const [issueStatus, setIssueStatus] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const requestOtp = useCallback(async () => {
    const r = roll.trim();
    const a = aadhaar.replace(/\D/g, "");
    if (!r) return setStatus("Enter the roll number");
    if (a.length !== 12) return setStatus("Enter a valid 12-digit Aadhaar number");
    setLoading(true);
    setStatus("Sending OTP...");
    try {
      const res = await fetch(`${API_BASE}/api/results/otp/request`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rollNumber: r, aadhaar: a })
      });
      const data = (await res.json()) as OtpRequestResponse;
      if (data.success) {
        setMaskedMobile(data.maskedMobile || "");
        setDemoOtp(data.demoOtp || "");
        setOtp("");
        setStep("otp");
        setStatus(`OTP sent to ${data.maskedMobile || "registered mobile"}`);
      } else {
        setStatus(data.error || "Failed to send OTP");
      }
    } catch {
      setStatus("Failed to send OTP. Please try again.");
    } finally {
      setLoading(false);
    }
  }, [roll, aadhaar]);

  const handleSearch = useCallback(async () => {
    const r = roll.trim();
    if (!r) return setStatus("Enter the roll number");
    setLoading(true);
    setStatus("Searching...");
    try {
      const params = new URLSearchParams({ rollNumber: r });
      if (sem.trim()) params.set("semester", sem.trim());
      const res = await fetch(`${API_BASE}/api/results/verify?${params.toString()}`);
      const data = (await res.json()) as StudentResult[] | { error?: string };
      if (Array.isArray(data)) {
        setResults(data);
        setStatus(data.length ? `${data.length} result${data.length > 1 ? "s" : ""} found` : "No Result Found");
      } else {
        setResults([]);
        setStatus(data.error || "No Result Found");
      }
    } catch {
      setResults([]);
      setStatus("No Result Found");
    } finally {
      setLoading(false);
    }
  }, [roll, sem]);

  const loadResults = useCallback(async (r: string, token: string) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ rollNumber: r });
      if (sem.trim()) params.set("semester", sem.trim());
      const res = await fetch(`${API_BASE}/api/results/verify?${params.toString()}`, {
        headers: { "x-result-token": token }
      });
      const data = (await res.json()) as StudentResult[] | { error?: string };
      if (Array.isArray(data)) {
        setResults(data);
        setStatus(data.length ? `${data.length} result${data.length > 1 ? "s" : ""} found` : "No result found for this roll number");
      } else {
        setResults([]);
        setStatus(data.error || "Could not load results");
      }
    } catch {
      setResults([]);
      setStatus("Could not load results");
    } finally {
      setLoading(false);
    }
  }, [sem]);

  const verifyOtp = useCallback(async () => {
    const o = otp.replace(/\D/g, "");
    if (o.length !== 6) return setStatus("Enter the 6-digit OTP");
    setLoading(true);
    setStatus("Verifying...");
    try {
      const res = await fetch(`${API_BASE}/api/results/otp/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rollNumber: roll.trim(), otp: o })
      });
      const data = (await res.json()) as OtpVerifyResponse;
      if (data.success && data.resultToken) {
        setResultToken(data.resultToken);
        setStep("done");
        await loadResults(roll.trim(), data.resultToken);
      } else {
        setStatus(data.error || "OTP verification failed");
      }
    } catch {
      setStatus("OTP verification failed");
    } finally {
      setLoading(false);
    }
  }, [otp, roll, loadResults]);

  const submitIssue = useCallback(async () => {
    const msg = issueMsg.trim();
    const rollNumber = roll.trim();
    if (!msg) return alert("Describe the issue first");
    if (!rollNumber) return alert("Enter a roll number first");
    setSubmitting(true);
    setIssueStatus("");
    try {
      const res = await fetch(`${API_BASE}/api/issues`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rollNumber, semester: sem.trim(), message: msg }),
      });
      const data = (await res.json()) as IssueSubmitResponse;
      if (data.success) {
        setIssueMsg("");
        setShowIssue(false);
        setIssueStatus("Issue submitted to the admin. Thank you!");
      } else {
        setIssueStatus(data.error || "Failed to submit issue");
      }
    } catch {
      setIssueStatus("Failed to submit issue");
    } finally {
      setSubmitting(false);
    }
  }, [issueMsg, roll, sem]);

  return (
    <div className="page">
      <div className="card" style={{ maxWidth: "640px" }}>
        <div className="header">
          <button className="btn-back" onClick={onBack}>Back</button>
          <button className="btn-theme" onClick={toggleTheme}>{theme === "dark" ? "☀️" : "🌙"}</button>
        </div>
        <div style={{ textAlign: "center", fontSize: "48px", margin: "12px 0 8px" }}>🔐</div>
        <h1 style={{ textAlign: "center" }}>Verify Result</h1>
        <p style={{ textAlign: "center", color: "var(--text-secondary)", fontSize: "14px", marginBottom: "24px" }}>
          Secure login with Aadhaar number — an OTP will be sent to your registered mobile
        </p>

        {step === "identify" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            <input
              type="text"
              placeholder="Roll Number (e.g. 2024001)"
              value={roll}
              onChange={(e) => setRoll(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            />
            <input
              type="text"
              placeholder="Semester (optional)"
              value={sem}
              onChange={(e) => setSem(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            />
            <input
              type="text"
              placeholder="Aadhaar Number (12 digits)"
              value={aadhaar}
              inputMode="numeric"
              maxLength={14}
              onChange={(e) => setAadhaar(e.target.value.replace(/[^\d\s]/g, ""))}
              onKeyDown={(e) => e.key === "Enter" && requestOtp()}
            />
            <div style={{ display: "flex", gap: "10px" }}>
              <button className="btn-primary" onClick={handleSearch} disabled={loading} style={{ flex: 1 }}>
                {loading ? <><span className="spinner" /> Searching</> : "Search"}
              </button>
              <button className="btn-secondary" onClick={requestOtp} disabled={loading} style={{ flex: 1 }}>
                {loading ? <><span className="spinner" /> Sending OTP</> : "Send OTP"}
              </button>
            </div>
          </div>
        )}

        {step === "otp" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            <p style={{ fontSize: "13px", color: "var(--text-secondary)", margin: 0 }}>
              Enter the OTP sent to <strong>{maskedMobile}</strong>
            </p>
            {demoOtp && (
              <p style={{ fontSize: "12px", color: "#fbbf24", background: "rgba(251,191,36,0.1)", border: "1px solid rgba(251,191,36,0.3)", borderRadius: "8px", padding: "8px 12px", margin: 0 }}>
                SMS gateway not configured — demo OTP: <strong>{demoOtp}</strong>
              </p>
            )}
            <input
              type="text"
              placeholder="6-digit OTP"
              value={otp}
              inputMode="numeric"
              maxLength={6}
              style={{ letterSpacing: "8px", textAlign: "center", fontSize: "18px" }}
              onChange={(e) => setOtp(e.target.value.replace(/\D/g, ""))}
              onKeyDown={(e) => e.key === "Enter" && verifyOtp()}
              autoFocus
            />
            <button className="btn-primary" onClick={verifyOtp} disabled={loading}>
              {loading ? <><span className="spinner" /> Verifying</> : "Verify & View Result"}
            </button>
            <button
              className="btn-secondary"
              style={{ padding: "8px 12px", fontSize: "12px" }}
              onClick={() => { setStep("identify"); setStatus(""); setDemoOtp(""); }}
            >
              ← Change roll number / Aadhaar
            </button>
          </div>
        )}

        {status && <div className="status">{status}</div>}

        {step === "identify" && (
          <div style={{ marginTop: "16px", textAlign: "center" }}>
            <button className="btn-secondary" onClick={() => { setShowIssue(true); setIssueStatus(""); }}>
              🚩 Raise Issue
            </button>
          </div>
        )}

        {results && results.length > 0 && results.map((r, idx) => {
          const stats = computeStats(r.subjects || []);
          return (
            <div key={r.id} className="result-card" style={{ marginTop: "16px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <p><strong>{r.name}</strong> <span style={{ color: "var(--text-secondary)" }}>({r.rollNumber})</span></p>
                  <p style={{ fontSize: "13px", color: "var(--text-secondary)" }}>
                    {r.department}{r.semester ? ` · ${r.semester}` : ""}
                  </p>
                </div>
                <div style={{ textAlign: "right" }}>
                  <span className={stats.allPassed ? "badge badge-pass" : "badge badge-fail"}>
                    {stats.allPassed ? "PASS" : "REVIEW"}
                  </span>
                </div>
              </div>

              {idx === 0 && (r.subjects || []).length > 0 && (
                <table className="subjects-table" style={{ marginTop: "12px" }}>
                  <thead>
                    <tr><th>Subject</th><th>Marks</th><th>Max</th><th>Grade</th></tr>
                  </thead>
                  <tbody>
                    {(r.subjects || []).map((s, i) => (
                      <tr key={i}>
                        <td>{s.subject}</td>
                        <td>{s.marks == null ? "–" : s.marks}</td>
                        <td>{s.maxMarks == null ? "–" : s.maxMarks}</td>
                        <td>{s.grade || "–"}</td>
                      </tr>
                    ))}
                  </tbody>
                  <tfoot>
                    <tr>
                      <td><strong>Total</strong></td>
                      <td><strong>{stats.total}</strong></td>
                      <td><strong>{stats.max}</strong></td>
                      <td><strong>{stats.pct}%</strong></td>
                    </tr>
                  </tfoot>
                </table>
              )}
              {idx > 0 && (
                <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "8px" }}>
                  {r.subjects ? r.subjects.length : 0} subjects across {r.semester} — total {stats.total}/{stats.max} ({stats.pct}%)
                </p>
              )}
            </div>
          );
        })}

        {results && results.length === 0 && status !== "No Result Found" && (
          <div className="result-card error">
            <p><strong style={{ color: "#fca5a5" }}>No Result Found</strong></p>
            <p style={{ color: "#94a3b8", fontSize: "13px" }}>No results match this roll number.</p>
          </div>
        )}

        {step === "done" && !showIssue && (
          <div style={{ marginTop: "16px", textAlign: "center" }}>
            <button className="btn-secondary" onClick={() => { setShowIssue(true); setIssueStatus(""); }}>
              🚩 Raise Issue
            </button>
          </div>
        )}

        {showIssue && (
          <div className="result-card" style={{ marginTop: "16px" }}>
            <p><strong>🚩 Raise an Issue</strong></p>
            <p style={{ fontSize: "13px", color: "var(--text-secondary)", margin: "4px 0 12px" }}>
              Report a problem with this result to the university admin
            </p>
            <textarea
              placeholder="Describe the issue (e.g. wrong marks, missing subject)..."
              value={issueMsg}
              onChange={(e) => setIssueMsg(e.target.value)}
              rows={4}
              style={{ width: "100%" }}
            />
            <div style={{ display: "flex", gap: "10px", marginTop: "10px", justifyContent: "flex-end" }}>
              <button className="btn-secondary" onClick={() => { setShowIssue(false); setIssueMsg(""); setIssueStatus(""); }}>
                Cancel
              </button>
              <button className="btn-primary" onClick={submitIssue} disabled={submitting}>
                {submitting ? <><span className="spinner" /> Submitting</> : "Submit Issue"}
              </button>
            </div>
          </div>
        )}

        {issueStatus && (
          <p style={{ fontSize: "13px", marginTop: "12px", textAlign: "center", color: issueStatus.includes("admin") ? "#86efac" : "#fca5a5" }}>{issueStatus}</p>
        )}
      </div>
    </div>
  );
}