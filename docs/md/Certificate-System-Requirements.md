# Certificate Management System — Requirements

**Document ref:** Certificate-System-Requirements
**Version:** 1.0 (TypeScript migration baseline)
**Status:** Draft

---

## 1. Overview

A web-based **Certificate Management System (DApp)** for a university / e-governance
environment. It issues student certificates, verifies them over OTP, audits access,
tracks **DPDP Act compliance** (data protection, DPIAs, ROPA, breach handling), and
monitors the uptime and security of connected campus applications.

Primary user flows:

1. **Admin** issues and revokes certificates and result cards.
2. **Students/public** verify a certificate or result using a unique **hash** plus a
   **one-time password (OTP)** delivered by SMS.
3. **Verifiers** confirm authenticity without revealing sensitive data.
4. **Privacy / compliance teams** run Data Protection Impact Assessments (DPIA),
   maintain Records of Processing Activities (ROPA), and manage data breaches.
5. **Operations / security** monitor application health and security events.

## 2. Technology Stack

| Layer      | Technology                                            |
|------------|-------------------------------------------------------|
| Language   | TypeScript (strict mode), Node.js (v26)               |
| Backend    | Express 5, Multer, CORS, dotenv                        |
| Database   | PostgreSQL (`pg`)                                     |
| Frontend   | React 19 (Create React App), QueryParam search, OTP flow |
| Blockchain | Ethereum contract (ethers), optional IPFS/Pinata      |
| SMS        | Gateway service (`sms-gateway.ts`)                    |
| Reports    | XLSX export / executive DPIA report                   |
| Tests      | Jest 29, ts-jest (backend), react-scripts (frontend)  |
| Process    | tsx runner, optional PM2 (see `setup.sh`)             |

## 3. User Roles & Permissions

| Role              | Capabilities                                                             |
|-------------------|--------------------------------------------------------------------------|
| `admin`           | Full access: users, certificates, results, brand, departments, monitor, DPIA, activity |
| `user`            | Base access per granted permissions / departments                        |
| `department-head` | Department-scoped access to results and certificates                     |
| `privacy-manager` | DPIA, ROPA, breaches, data-subject actions                               |
| `cybersecurity`   | Monitor apps, security events, risk levels                               |
| `hr`              | People-related certificate flows (scoped)                                |
| `legal`           | Compliance review, DPIA approval                                         |

Permission model: each non-admin user carries an **JSONB permission list** and an
**optional department list**. Department-scoped users only see data for their
department.

## 4. Functional Requirements

### 4.1 Authentication & Authorization
- Admin login via `/api/admin/login` (username + password, bcrypt-style hashed).
- Admin seeded by environment variables (`ADMIN_USERNAME`, `ADMIN_PASSWORD`).
- Role-based access control on every API route.
- Audit logging of every sensitive action (login, issue, revoke, delete).

### 4.2 Certificate & Result Management
- Upload certificates synchronously or in bulk (CSV + files).
  - `POST /api/certificates`
  - `POST /api/certificates/bulk-upload`, `POST /api/certificates/bulk-save`
  - `POST /api/results/bulk-upload`, `POST /api/results/bulk-save`
- Download generated certificates (`/api/certificates/download`).
- Blockchain anchoring (`/api/certificates/blockchain`) via Ethereum contract.

### 4.3 Public Verification (OTP Flow)
- `POST /api/results/otp/request` — student gives roll no + Aadhaar; system
  sends OTP to masked mobile.
- `POST /api/results/otp/verify` — validates OTP, returns a **one-time result
  token**.
- `GET /api/verify/:hash` and `POST /api/results/verify` — verifier checks the
  certificate hash; only masked/meta data is disclosed.

### 4.4 DPDP Compliance Module
- **DPIA** (Data Protection Impact Assessment):
  - CRUD `/api/dpia`, dashboard `/api/dpia/dashboard`, report
    `/api/dpia/report`.
  - Stage workflow `/api/dpia/workflow` with configurable transitions
    (draft → assessment → review → risk_treatment → privacy_review →
    approval → active → periodic_review).
  - Risk register per DPIA (`/api/dpia/:id/risk`).
- **ROPA** records, **data breaches** and consent handled via `/api/issues`.
- **Application monitoring** for DPDP compliance: `/api/monitor/apps`,
  health checks `/api/monitor/apps/:id/checks`, stats.

### 4.5 Dashboard & Analytics
- `/api/dashboard/stats`, `/api/dashboard/analytics`:
  - Certificates/results issued (last 7 days), department-wise, semester-wise
    counts; security/DPIA summaries rendered in `AdminPage`.

### 4.6 SMS Gateway
- `sms-gateway.ts`: batch SMS delivery to students (independent service,
  started separately via `npm run sms-gateway`).

## 5. Non-Functional Requirements

- **Strict typing**: full TypeScript strict-mode typecheck passes
  (`npm run typecheck`, 0 errors).
- **Security**: passwords hashed; secrets only via `.env` (never committed);
  CSRF/authorization enforced per route.
- **Reliability**: Postgres as source of truth; runtime JSON files are
  **not** persisted (see `.gitignore`).
- **Performance**: bulk uploads with file-matching by roll/name; analytics
  pre-aggregated server-side.
- **Auditability**: every mutation logged to `/api/activity` with actor and
  timestamp.

## 6. API Surface (summary)

| Method | Path                              | Purpose                          |
|--------|-----------------------------------|----------------------------------|
| POST   | `/api/admin/login`                | Admin login                      |
| POST   | `/api/certificates`               | Issue certificate                |
| GET    | `/api/certificates/:hash`         | Lookup by hash                   |
| GET    | `/api/verify/:hash`               | Public verify (no token needed)  |
| POST   | `/api/results/otp/request`        | Send OTP                         |
| POST   | `/api/results/otp/verify`         | Verify OTP → result token        |
| POST   | `/api/results/verify`             | Verify with token                |
| GET/POST| `/api/results` (+ `/bulk-*`)     | Manage result cards              |
| GET    | `/api/dashboard/stats`            | Dashboard stats                  |
| GET    | `/api/dashboard/analytics`        | Charts data                      |
| GET/POST/PUT| `/api/dpia…`              | DPIA + risk + workflow           |
| GET/POST/PUT| `/api/monitor/apps…`       | Compliance app monitoring        |
| GET/POST/PUT| `/api/users…`           | User administration              |
| GET    | `/api/activity`                   | Audit trail                      |

Full list lives in `src/server.ts` (search `"/api/..."`).

## 7. Operational Notes

- **Start server:** `npm run server` (runs `tsx src/server.ts`).
- **Start SMS gateway:** `npm run sms-gateway`.
- **Tests:** `npm run test:all` (backend ts-jest + frontend CRA).
- **Typecheck:** `npm run typecheck`.
- **Production deploy:** `setup.sh` builds the frontend and registers the app
  with PM2 (`pm2 start src/server.ts --node-args="--import tsx"`).
- Access: server binds `0.0.0.0:5000` and serves the React build directly.