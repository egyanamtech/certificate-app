# DPIA Module — Presentation Guide

**Certificate & Campus e-Governance Platform**
*Data Protection Impact Assessment (DPIA) — Configurable Approval Workflow*

---

## 1. What is the DPIA Module?

The DPIA module lets the institution identify, document, and manage the
privacy risks of any processing activity that handles personal / student data
before it goes live. It works inside the existing Admin Portal under the
**🛡️ DPIA** tab and follows the stage-gated, document-then-approve pattern
recommended by privacy frameworks (EU GDPR Art. 35 and equivalent India
DPDP Act principles).

**Key capability:** the approval pipeline is **not hard-coded** — it is fully
configurable by an administrator (rename stages, reorder, add/remove gates,
require comments, restrict steps to admins).

---

## 2. The Default Approval Workflow (8 Stages)

```
Draft → Assessment → Review → Risk Treatment → Privacy Review → Approval → Active → Periodic Review
```

| Stage | Purpose | Colour |
|-------|---------|--------|
| **Draft** | Initial document created, data categories & scope captured | Grey |
| **Assessment** | Processing identified, risks first recorded | Blue |
| **Review** | Independent review of the assessment | Purple |
| **Risk Treatment** | Mitigation plans assigned & tracked | Amber |
| **Privacy Review** | Data-protection officer sign-off on residual risk | Pink |
| **Approval** | Final administrative approval gate (admin-only, comment) | Orange |
| **Active** | Lives on — DPIA complete & processing operates | Green |
| **Periodic Review** | Scheduled re-check; re-confirm or trigger re-assessment | Cyan |

Every stage is colour-coded and shown as a **live stepper** in the UI so staff
always see exactly where a DPIA stands.

---

## 3. Example Transition (Advance / Return / Reject) Rules

Transitions are validated against the configured workflow — you **cannot jump
stages** that aren't permitted:

| From | To | Action label | Comment? | Admin? |
|------|-----|--------------|----------|--------|
| Draft | Assessment | Start Assessment | – | – |
| Assessment | Draft | Send Back to Draft | ✅ | – |
| Assessment | Review | Submit for Review | – | – |
| Review | Risk Treatment | Approve Review | – | – |
| Risk Treatment | Privacy Review | Complete Risk Treatment | – | – |
| Privacy Review | Approval | Submit for Approval | – | – |
| **Approval** | **Active** | **Approve & Activate** | ✅ | ✅ |
| **Approval** | **Privacy Review** | **Reject — Return for Revisions** | ✅ | ✅ |
| Active | Periodic Review | Start Periodic Review | – | – |
| **Periodic Review** | **Active** | **Re-confirm & Reactivate** | ✅ | ✅ |
| Periodic Review | Assessment | Trigger Re-assessment | ✅ | – |

Notable governance controls:
- **Approval → Active** is restricted to **administrators** and **requires a
  comment** (e.g. justification of approval).
- **Rejection returns the DPIA to Privacy Review** — it must pass through the
  pipeline again; there is no shortcut straight back to Active.
- **No route from Privacy Review to Active** — the Approval gate cannot be skipped.

---

## 4. Complete Audit Trail (Immutable Change Log)

Every action is written to a dedicated `dpia_audit_log` table and shown in the
DPIA detail panel. Each entry records:

- **Who** — username who performed the action
- **What** — action (`created`, `updated`, `stage_changed`, `approved`, `rejected`, `risk_added`, `risk_updated`, `deleted`)
- **Where in the pipeline** — `from_stage → to_stage` (colour-coded)
- **When** — timestamp (`createdAt`)
- **Why** — mandatory comment (for gated transitions)
- **Metadata** — e.g. the exact transition label used (`via`)

This gives assurance work: every approval, rejection, and stage move is
traceable — you can always reconstruct **who approved a DPIA and why**.

---

## 5. Admin Configurable Workflow (⚙️ Workflow editor)

Only administrators can modify the pipeline. The editor supports:

- **Re-order, add, or remove stages** (with live colour + label editing)
- **Define allowed transitions** between stages (`from` → `to`)
- Mark each transition as **Comment required** and/or **Admin only**
- **Reset to Defaults** to restore the standard 8-stage pipeline
- Changes persist immediately and drive the stepper, transitions, dashboard
  pipeline counts, and the executive report

The editor is protected by an `admin` permission so regular users cannot alter
governance rules.

---

## 6. Dashboard & Executive Report

**Admin Dashboard (DPIA tab)**
- **Total DPIAs**, **Completed / Open**, **High-risk activities**,
  **Open / Overdue risks**, **Third-party processing**, **Data categories**
- **Workflow Pipeline** — count of DPIAs in each stage (driven by workflow order)
- **DPIA status by business unit**, **data categories processed**, and **risk breakdown**

**Executive Report** (downloadable / openable):
- Total DPIAs, completed/open, high-risk, open risks, overdue items, third-party
- **WORKFLOW PIPELINE** section — DPIAs per stage in pipeline order
- Top open high/critical risks for follow-up

---

## 7. Privacy Risk Assessment (built into each DPIA)

When creating/editing a DPIA you can add multiple **privacy risks**, each with:

- Description
- Likelihood (rare → almost certain)
- Impact (negligible → severe)
- Computed **risk level** (low / medium / high / critical)
- Status (open / mitigating / resolved)
- Remediation plan + due date

Open / overdue risks surface on the dashboard so unresolved privacy risks
cannot be silently forgotten.

---

## 8. Data Captured per DPIA

- Title, description, business unit
- **Workflow stage** (not just a static status)
- Overall risk level
- **Data categories** (12 pre-defined: Student Records, Academic Results,
  Aadhaar Data, Mobile Numbers, Biometric Data, Health Records, Financial
  Data, HR Employee Data, CCTV/Surveillance, IoT/Sensors, Campus Access,
  Online Services)
- Third-party processor involvement
- Start / due dates
- Privacy risks (multiple) with remediation tracking

---

## 9. Technical Implementation (for the technical slide)

| Layer | Detail |
|-------|--------|
| **Database** | `dpia_assessments`, `dpia_risks`, `dpia_audit_log` (CASCADE on delete), `dpia_workflow_config` (JSONB stages + transitions) |
| **Backend API** | `/api/dpia` (CRUD), `/api/dpia/:id/transition`, `/api/dpia/workflow` (GET/PUT, admin), `/api/dpia/dashboard`, `/api/dpia/report`; permission-gated (`dpia`, `admin`) |
| **Frontend** | React admin section: stepper, transition buttons, audit trail, workflow config editor; everything matches server-side defaults |
| **Security** | Admin-only gates enforced on the **server**, not just hidden in the UI; comments validated server-side |
| **Config persistence** | Workflow stored in JSONB; invalid/removed transitions fall back to safe defaults |

---

## 10. Demo Script (2 minutes)

1. Open **Admin Portal → 🛡️ DPIA** (admin login).
2. Click **+ New DPIA**, fill title, pick data categories, add one risk, save.
3. Show the **stepper** — DPIA is in *Draft*.
4. Click **Start Assessment →  Submit for Review → Approve Review → Complete
   Risk Treatment → Submit for Approval**.
5. At **Approval**, demonstrate the gate: show the comment is **required**
   before **Approve & Activate** goes through.
6. Expand the DPIA — scroll the **Audit Trail**: every stage move,
   who did it, when, and the approval comment.
7. Open **⚙️ Workflow** — show stages are editable, then **Reset to Defaults**.
8. Click **View Report** — point to the **Workflow Pipeline** section.
9. (Optional) Reject a DPIA at Approval → show it returns to **Privacy Review**.

---

*Platform: Certificate & Campus e-Governance Portal — DPIA module*