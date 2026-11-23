# ILVORA Workforce — Cloudflare integration foundation

This package preserves the supplied ILVORA Workforce portal and extends its Cloudflare Worker + D1 foundation with operational record APIs and document generation. The GitHub deployment workflow is manual-dispatch only to prevent accidental live deployment when code is pushed.

## Included
- Original portal and 48 supplied service packages retained, plus a dedicated Attendance Marker capture page.
- Login connected to a Worker API; role is read from the authenticated account, never from a user-selected dropdown.
- Six fixed roles: Managing Director, Administrator, Head Office Admin, Branch Admin / HR, Employee, Attendance Marker.
- Server-side module access checks for every `/modules/...` request.
- MD-only module access for the signatory/payroll/experience-certificate configuration module.
- D1 schema for users, branches, sessions, role-module access, login attempts and audit events.
- Password hashing with PBKDF2-SHA-256; opaque HttpOnly, Secure, SameSite=Strict session cookies.
- First-use MD bootstrap protected by a one-time secret.
- User creation guardrails and branch assignment rules.
- GitHub Actions deployment workflow.

## Important status
This is an operational development build, **not yet a certified production HR/payroll system**. The shared workspace supersedes the legacy front-end-only module interiors so sample dashboards and inactive prototype controls are not presented as live functionality. It provides persisted records, role-checked approvals, roster overlap checks, leave overlap/approval checks, a 30-day payroll calculation from approved salary, roster, attendance and paid medical-leave records, branch GPS geofencing, notifications, live record summaries and immutable official-document snapshots. It is a unified operational base, not yet a full implementation of every specialist workflow or a certified production application. Do not enter real employee or payroll data until all module workflows, integrations and acceptance tests are complete and the system has passed security review.

The Attendance Marker role is restricted to its dedicated attendance-capture module. It can submit attendance captures but cannot list or edit existing attendance records and cannot access HR, payroll, leave or roster administration. All non-executive roles (Head Office Admin, Branch Admin/HR, Employee and Attendance Marker) must complete a GPS check-in before opening any dashboard module or desk API. Managing Director and Administrator are exempt. A configured branch geofence is enforced server-side; without a geofence, GPS is captured but is not represented as geofence-verified. Rotating QR, OTP and face-recognition verification remain inactive pending device/provider integration and testing. Branch creation is restricted to Managing Director and Administrator.

## Existing Cloudflare environment — do not recreate or modify during review

This project is configured for the existing ILVORA Worker and D1 database. Do not create a new Worker or database, do not rerun the original bootstrap, and do not run `npm run deploy` as part of reviewing this ZIP. The live Worker and database were intentionally left untouched during development. The operational routes require migrations `0002_workforce_operations.sql` and `0003_head_office_attendance_gate.sql`; applying either migration and deploying the new Worker are separate changes that must happen only after explicit approval. Migration 0003 keeps Head Office as the only active branch, moves existing non-executive accounts to Head Office, and preserves old branch rows as inactive for historical references.

## GitHub deployment — manual approval only

1. Push this project to the selected GitHub repository, with the project files at the repository root.
2. In GitHub repository Settings → Secrets and variables → Actions, add:
   - `CLOUDFLARE_API_TOKEN` (Workers Scripts: Edit; D1: Edit as needed for migrations)
   - `CLOUDFLARE_ACCOUNT_ID`
3. A push to `main` does **not** deploy. Deployment is available only through Actions → Deploy ILVORA Workforce to Cloudflare → Run workflow, and requires the exact confirmation text `DEPLOY`. Do not run it until you explicitly approve changing the live application.
4. Apply database migrations separately when a migration is added. Do not run migrations from the public application.

## Current API routes
- `GET /api/health` — database/API health.
- `POST /api/setup/bootstrap` — one-time MD account setup.
- `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`.
- `POST /api/auth/change-password`.
- `GET /api/users`, `POST /api/users`.
- `GET /api/branches`, `GET /api/audit`, `GET /api/permissions`.
- `GET /api/dashboard/summary`, `GET/POST /api/settings`.
- `GET/POST /api/branches/geofence` — role-restricted branch geofence configuration.
- `GET/POST /api/notifications`, `POST /api/notifications/{id}/read`.
- `POST /api/payroll/run` — calculates draft payroll for a month from approved salary, roster, attendance and leave records.

## Role rules encoded in this foundation
- No role can be selected by the user at login.
- Unauthenticated access to service modules is denied.
- Each role can open only the module folders granted in `role_module_access`.
- Branch Admin can create Employee and Attendance Marker accounts only within their own branch.
- Administrator cannot create an MD account and cannot access MD signatory settings.
- MD final resignation approval is enforced in the operational record API.
- Administrator advance approval is checked against the latest approved salary record; advances above 25% require MD approval.
- Branch Admin leave approval is limited to 5 calendar days; longer leave requires Head Office Admin approval.
- Attendance correction approval is restricted to Head Office Admin.
- MD signatory settings and assets are available only to the Managing Director role.
- Role permissions are not inherited automatically. Any new route must be explicitly authorised.

## Local development
- `npm install`
- `npm run db:migrate:local`
- `npm run dev`

For local bootstrap, set a local `BOOTSTRAP_SECRET` in a `.dev.vars` file (never commit it), then call the bootstrap endpoint.

## Added operational APIs in this upgrade

- `GET /api/workspace/{type}` — role/branch-filtered record list.
- `POST /api/workspace/{type}` — create an operational record.
- `PATCH /api/workspace/{type}/{id}` — update status/details with role-specific approval checks.
- `GET /api/md/signatory` and `POST /api/md/signatory` — MD-only signatory name, signature, seal and logo configuration.
- `POST /api/documents/generate` — create an immutable official document from an approved source record.
- `GET /api/documents` and `GET /api/documents/{id}` — list and retrieve generated documents within employee/branch scope.

Supported workspace record types include employees, onboarding, attendance, rosters, leaves, salary, payroll, payslips, documents, notices, complaints, helpdesk, advances, resignations, contracts, expenses, inventory, compliance and licences.

Official document generation supports payslips, employment contracts, onboarding confirmation letters, experience letters and leave approval letters. Each generated document stores a snapshot of the logo, MD display name, signature and seal versions in effect at generation time. The generator refuses to create an official document unless its linked source record is approved; experience letters additionally require `clearance_complete: true` in the approved resignation record. Until the MD uploads the signature and seal, the document clearly shows those assets as pending and is not represented as signed.

## Validation and live-deployment safety

- Run `npm test` for static project, JavaScript, role-boundary, migration-presence and deployment-workflow checks.
- The SQL migrations were validated locally against SQLite syntax; this does not apply them to the live D1 database.
- The GitHub Actions workflow has no push trigger. It can deploy only after a manual workflow dispatch with the exact confirmation text `DEPLOY`.
- Migrations `0002_workforce_operations.sql` and `0003_head_office_attendance_gate.sql` must be applied deliberately before the new API routes can be used against D1. Do not apply it until the deployment change has been reviewed and explicitly approved.
- No command in this development process connects to or modifies the existing Cloudflare Worker or D1 database.

## Known integration requirements before production use

The shared record workspace is a persisted CRUD/approval foundation, not a replacement for every specialist business rule. GPS geofencing, rotating QR, face recognition, OTP delivery, payroll statutory calculations, bank payment execution, biometric device integration, secure employee document upload/storage, scheduled payslip generation, automated notifications, and end-to-end role acceptance tests still require their dedicated implementations and provider/device configuration. Do not use the application for real payroll or statutory HR decisions until these are completed and tested.

## Authentication delivery configuration (required before enabling account creation / OTP)

The authentication update automatically generates initial passwords on the server. The password is never returned by the API or written to audit logs; it is delivered to the account's registered email address. The initial password has no time-based expiry and remains valid until the user changes it at first login. The first-login password-change gate remains enforced by the Worker.

Configure these Worker secrets/variables before using account provisioning or password recovery:

- `RESEND_API_KEY` (secret): Resend API key for transactional email.
- `EMAIL_FROM` (variable): verified sender, e.g. `ILVORA Workforce <workforce@your-verified-domain>`.
- `TWILIO_ACCOUNT_SID` (secret): Twilio account SID.
- `TWILIO_AUTH_TOKEN` (secret): Twilio auth token.
- `TWILIO_FROM_NUMBER` (variable): SMS-capable Twilio number in E.164 format.
- `OTP_PEPPER` (secret): high-entropy secret used to HMAC OTPs before storage.

Registered mobile numbers must be stored in E.164 format, e.g. `+919876543210`. Account creation requires a registered email and mobile. If email delivery fails, the account creation is rolled back; the system does not show or return a temporary password as a workaround.

Password recovery sends separate six-digit OTPs to the registered email and mobile only. Both codes are required to reset a password. OTPs expire 15 minutes after generation, are single-use, are stored only as hashes, and have a resend cooldown of 60 seconds. Resending invalidates the previous pair. Five failed attempts invalidate the current challenge. Do not enable production account provisioning until both providers have been configured and delivery has been tested.

### Authentication database migration

Apply `migrations/0004_auth_otp_contacts.sql` to the target D1 database only after reviewing it and taking a backup. This migration adds registered contact fields and OTP challenge storage. It has not been applied to any live database by this development process.
