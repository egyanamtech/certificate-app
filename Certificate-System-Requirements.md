# Certificate & Results Management System

## Software Requirements Document

**Version:** 2.1 | **Date:** 25 September 2026 | **Status:** Implemented

---

## 1. Introduction

### 1.1 Purpose
This document describes the functional and non-functional requirements of the Certificate & Results Management System for XYZ University. The system allows university staff to issue tamper-proof certificates, manage semester-wise student results, and verify documents publicly, with role-based access control.

### 1.2 Scope
- **Public website:** certificate verification by hash, university branding, dark/light theme.
- **Admin portal:** dashboard, certificates, results, analytics, issues, activity log, user management, settings, downloads.
- **Backend REST API** with PostgreSQL storage, session-based authentication, role/permission/department-level authorization.

### 1.3 Intended Audience
University administration (admins), staff users (department operators), developers, and QA.

---

## 2. System Overview

The application is a React single-page front end backed by a Node.js (Express) API and a PostgreSQL database. Certificates are stored with SHA-256 hashes; results are grouped per student per semester with multiple subjects. All administrative actions are recorded in an audit trail.

**Deployment:** PM2 process manager on two machines (local and LAN server), PostgreSQL shared schema, Docker Compose available.

---

## 3. Functional Requirements

### 3.1 Public / Landing
- **FR-P1 – Branded Landing Page:** University logo, name, tagline and description rendered from brand settings.
- **FR-P2 – How It Works:** Three-step explainer: Issue, Store, Verify.
- **FR-P3 – Verify Certificate (Hash-only):** Anyone can enter a certificate hash; backend returns only validity status — no student PII is exposed.
- **FR-P4 – Theme Toggle:** Persistent dark/light theme preference.

### 3.2 Authentication & Sessions
- **FR-A1 – Login:** Users log in with username/password. Passwords are hashed (scrypt). Invalid attempts are rate-limited (lockout window).
- **FR-A2 – Session Tokens:** Server issues random 64-char session tokens stored in PostgreSQL (`app_sessions`); sessions survive server restarts and expire after 12 hours of inactivity.
- **FR-A3 – Idle Timeout:** Front end auto-logs-out after 10 minutes of inactivity.
- **FR-A4 – Dead-Session Handling:** If the server rejects a session (401/403), the UI automatically clears credentials and returns to the login screen.

### 3.3 Roles & Permissions
- **FR-R1 – Roles:** Two roles: Admin (full access to everything) and Normal User (section-based permissions).
- **FR-R2 – Section Permissions:** Per-user checkboxes control access to: Issue Certificate, Bulk Upload, Verify, Certificates, Results, Analytics, Issues, Activity, Downloads.
- **FR-R3 – Role Toggle:** Admins can promote/demote accounts between Admin and User from the Users screen (confirmation required; cannot demote self or built-in admin).
- **FR-R4 – Admin Override:** Admins implicitly hold every permission and see all departments.

### 3.4 Department Restrictions
- **FR-D1 – Department Assignment:** Each normal user may be limited to specific departments. Empty selection = all departments.
- **FR-D2 – Results Scoping:** Restricted users see only results of their departments; requesting other departments via API returns 403 Forbidden.
- **FR-D3 – No Filter Bypass:** Restricted users cannot remove the department filter: the All Departments option is hidden and a default department is pre-selected.
- **FR-D4 – Write Protection:** Create/edit/delete/bulk operations on results outside a user's departments are rejected server-side (403).
- **FR-D5 – Department Management:** Only admins can add or remove departments. The remove action cascades to that department's results after confirmation. Non-admins see a read-only list.

### 3.5 Dashboard
- **FR-B1 – Statistics:** Total certificates, issued today, total departments, total results, open/resolved/rejected issues.
- **FR-B2 – Charts:** Certificates issued in last 7 days, department-wise results, semester-wise results.

### 3.6 Certificates
- **FR-C1 – Issue Certificate:** Single certificate issue with hash, name, roll number, course, department, year, email, optional IPFS link; optional blockchain anchoring on Sepolia.
- **FR-C2 – Bulk Upload:** CSV/XLSX upload with header detection and mismatch report; processing gated until data is complete.
- **FR-C3 – Search & Download:** Search by hash/name/roll/email; export registry as CSV or XLSX.
- **FR-C4 – Delete:** Remove a certificate (admin only).

### 3.7 Results
- **FR-S1 – CRUD:** Add/edit/delete semester-wise results per student (roll + semester unique). Multiple subjects per result with marks, max marks, grade.
- **FR-S2 – Bulk Upload:** One row per subject; rows grouped by roll + semester and merged into existing records.
- **FR-S3 – Filters:** Search by name/roll number; filter by department and semester (respecting restrictions).

### 3.8 Issues
- **FR-I1 – Raise Issue:** Students/public can raise issues against a roll number + semester.
- **FR-I2 – Triage:** Admin/staff can resolve or reject issues; counts shown on dashboard.

### 3.9 Activity Log
- **FR-L1 – Audit Trail:** All key actions logged (login, issue, delete, result changes, user changes, brand changes) with timestamp.
- **FR-L2 – Search:** Full-text search over activity entries; clear-log restricted to admins.

### 3.10 User Management
- **FR-U1 – Create User:** Username + password (min 4 chars) + role; section permissions and department access selectable when creating a Normal User.
- **FR-U2 – Edit Access:** Inline editor for section permissions and department access (normal users only).
- **FR-U3 – Change Password:** Admin can reset any user's password; show/hide password toggle provided.
- **FR-U4 – Delete:** Delete users with confirmation; at least one admin must always remain.
- **FR-U5 – Search:** User list searchable by username, role, access, or department.

### 3.11 Settings
- **FR-G1 – Branding:** University name, short name and logo editable; reflected across portal and public pages.
- **FR-G2 – Password Change:** Logged-in user can change their own password.

---

## 4. Security Requirements
- **NFR-SEC1 – Password Storage:** Passwords hashed with scrypt; legacy SHA-256 hashes upgraded transparently at login.
- **NFR-SEC2 – Authorization Layers:** Every admin API validates session token, then role/permission/department scope server-side. Client-side hiding is never the only guard.
- **NFR-SEC3 – PII Protection:** Public verification exposes only hash validity, never personal data.
- **NFR-SEC4 – Rate Limiting:** Login endpoint throttles repeated failures per IP.
- **NFR-SEC5 – Session Revocation:** Expired/invalid tokens are deleted server-side; UI auto-recovery prevents zombie sessions.

---

## 4.5 Digital Personal Data Protection (DPDP) Requirements

The system is a university-operated **data fiduciary** under the Digital Personal Data Protection Act, 2023 (India). It processes student **personal data** (name, roll number, email, mobile, course, department, semester, marks/grades — and where maintained, Aadhaar) for the specified purposes of issuing certificates, publishing semester-wise results, and public hash-only verification. The following obligations apply.

- **NFR-DP1 – Notice:** Data principals (students) are provided a privacy notice at data collection. The notice states what personal data is collected, the purposes of processing, and how rights are exercised. The notice is available on the public site and recalled at issue/bulk-upload time.
- **NFR-DP2 – Lawful Ground / Consent:** Processing is restricted to specified purposes. Where consent is the legal basis (e.g. publication of a student's marks), consent must be free, specific, informed, unconditional and verifiable, and revocable by the data principal at any time. Withdrawal must be honoured and processing ceased within the statutory window.
- **NFR-DP3 – Purpose & Storage Limitation:** Personal data is used only for the specified purposes; no repurposing without fresh consent. Data is retained only as long as necessary (tied to academic record retention policy) and securely deleted thereafter, in line with the retention register maintained in the Campus Monitor module.
- **NFR-DP4 – Reasonable Security Safeguards:** Postgres access is protected, sessions are revocable (12-h idle expiry), passwords use scrypt, and the monitoring module issues security events (failed logins, anomalies). Safeguards must be continuously reviewed for adequacy.
- **NFR-DP5 – Breach Notification:** A personal data breach must be notified to the Data Protection Board and each affected data principal in the prescribed form, without delay (morning/evening-of-discovery reporting discipline). The monitoring module's security-event feed is the trigger mechanism.
- **NFR-DP6 – Data Principal Rights:** Exercisable rights for students include access to personal data and a summary of processing (Rights of the Data Principal), correction/updating, erasure, and grievance redressal via the Issues module (`/issues`) and a named grievance officer. Requests must be acknowledged within the statutory timeline.
- **NFR-DP7 – Grievance Officer:** A designated grievance officer (and contact) is published; student issues raised against roll number + semester in the Issues module are routed to this officer for DPDP-related complaints.
- **NFR-DP8 – Children's Data:** If records of children (under 18) are processed, verifiable parental consent is obtained; no tracking or behavioural advertising is performed on children's data.
- **NFR-DP9 – Data Transfers:** Personal data is not transferred outside India except under an order/intimation of adequacy by the Central Government; no cross-border processing is performed by default.
- **NFR-DP10 – Consent Managers:** Should consent be adopted, it is obtained through a Department-approved consent manager; no part of the system interoperates as a consent manager by itself.
- **NFR-DP11 – Register of Processing Activities (ROPA):** The Campus Monitor module (admin-only) records each application's processing activities with status/owner for ROPA, DPIA and DPDP compliance, forming the DPDP evidence register.
- **NFR-DP12 – NFR/DPIA linkage:** Departures from the above require an updated Data Protection Impact Assessment recorded per application in the Campus Monitor module before deployment.

---

## 5. Non-Functional Requirements
- **NFR-1 – Performance:** Typical admin operations respond within 1 second on LAN.
- **NFR-2 – Availability:** Process managed by PM2 with automatic restart; deployments must not invalidate active logins.
- **NFR-3 – Data Integrity:** PostgreSQL primary keys/unique constraints prevent duplicate results per roll + semester.
- **NFR-4 – Browser Support:** Modern evergreen browsers (Chrome, Edge, Firefox).
- **NFR-5 – Testing:** Automated test suites for backend and frontend (`npm run test:all`).

---

## 6. Technology Stack

| Layer        | Technology                                        |
|--------------|---------------------------------------------------|
| Frontend     | React 18 (Create React App), custom CSS light/dark themes |
| Backend      | Node.js, Express                                  |
| Database     | PostgreSQL 16 (JSONB for subjects/permissions/departments) |
| Files        | XLSX parsing, CSV export                          |
| Blockchain   | Optional Sepolia test-net anchoring of certificate hashes |
| Process/Deploy | PM2, Docker Compose                               |

---

## 7. Acceptance Criteria (Key Flows)
1. An admin can create a restricted user who sees only their departments' results and cannot bypass the restriction via search, direct URL, or API call.
2. A normal user cannot add/remove departments under any circumstance (UI hidden + API 403).
3. A logged-in session remains valid across server restarts and expires only after 12 hours idle.
4. Public visitors can verify a certificate hash without accessing any student PII.
5. Bulk uploads merge subject rows into one result per student + semester without duplicates.
6. DPDP: a privacy notice and grievance-officer contact are published; student-rights requests (access/correction/erasure) are logged and acknowledged; each campus application's ROPA/DPIA/DPDP status is tracked in the Campus Monitor module.