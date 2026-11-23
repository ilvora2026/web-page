PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS branches (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  city TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','inactive')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN (
    'managing_director','administrator','head_office_admin',
    'branch_admin','employee','attendance_marker'
  )),
  branch_id TEXT REFERENCES branches(id),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','inactive','locked')),
  must_change_password INTEGER NOT NULL DEFAULT 1 CHECK(must_change_password IN (0,1)),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username_key TEXT NOT NULL,
  ip_key TEXT NOT NULL,
  attempted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  success INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_lookup ON login_attempts(username_key, ip_key, attempted_at);

CREATE TABLE IF NOT EXISTS role_module_access (
  role TEXT NOT NULL,
  module_prefix TEXT NOT NULL,
  PRIMARY KEY(role,module_prefix)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT REFERENCES users(id),
  actor_role TEXT,
  branch_id TEXT,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  details_json TEXT,
  ip_address TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_actor_time ON audit_events(actor_user_id,created_at);
CREATE INDEX IF NOT EXISTS idx_audit_branch_time ON audit_events(branch_id,created_at);

CREATE TABLE IF NOT EXISTS app_settings (
  setting_key TEXT PRIMARY KEY,
  setting_value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO branches(id,code,name,city) VALUES
 ('branch_kochi','HO-KOC','ILVORA Head Office','Kochi'),
 ('branch_kottarakkara','CL-KOT','ILVORA Health Clinic','Kottarakkara'),
 ('branch_thamarakulam','NH-THA','Neelambari Hospital','Thamarakulam');

INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('administrator','modules/ilvora-workforce-administrator-service1-dashboard-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-administrator-service1-dashboard-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('administrator','modules/ilvora-workforce-administrator-service10-system-settings-security-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-administrator-service10-system-settings-security-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('administrator','modules/ilvora-workforce-administrator-service11-system-monitoring-technical-operations-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-administrator-service11-system-monitoring-technical-operations-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('administrator','modules/ilvora-workforce-administrator-service12-finance-operational-expense-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-administrator-service12-finance-operational-expense-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('administrator','modules/ilvora-workforce-administrator-service13-procurement-inventory-assets-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-administrator-service13-procurement-inventory-assets-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('administrator','modules/ilvora-workforce-administrator-service14-contracts-agreements-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-administrator-service14-contracts-agreements-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('administrator','modules/ilvora-workforce-administrator-service15-licences-statutory-compliance-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-administrator-service15-licences-statutory-compliance-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('administrator','modules/ilvora-workforce-administrator-service2-salary-management-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-administrator-service2-salary-management-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('administrator','modules/ilvora-workforce-administrator-service3-payroll-management-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-administrator-service3-payroll-management-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('administrator','modules/ilvora-workforce-administrator-service4-account-access-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-administrator-service4-account-access-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('administrator','modules/ilvora-workforce-administrator-service5-payslip-authorisation-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-administrator-service5-payslip-authorisation-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('administrator','modules/ilvora-workforce-administrator-service6-payroll-reports-reconciliation-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-administrator-service6-payroll-reports-reconciliation-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('administrator','modules/ilvora-workforce-administrator-service7-advances-loans-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-administrator-service7-advances-loans-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('administrator','modules/ilvora-workforce-administrator-service8-compliance-disciplinary-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-administrator-service8-compliance-disciplinary-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('administrator','modules/ilvora-workforce-administrator-service9-hr-compliance-records-audit-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-administrator-service9-hr-compliance-records-audit-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('branch_admin','modules/ilvora-workforce-attendance-correction-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('branch_admin','modules/ilvora-workforce-branch-admin-service1-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('branch_admin','modules/ilvora-workforce-branch-admin-service2-onboarding-prototype-v5/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('branch_admin','modules/ilvora-workforce-branch-admin-service3-attendance-prototype-v2/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('branch_admin','modules/ilvora-workforce-branch-admin-service4-leave-management-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('branch_admin','modules/ilvora-workforce-branch-admin-service5-duty-roster-prototype-v2/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('branch_admin','modules/ilvora-workforce-branch-admin-service6-documents-policies-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('branch_admin','modules/ilvora-workforce-branch-admin-service7-complaints-grievance-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('branch_admin','modules/ilvora-workforce-branch-admin-service8-requests-helpdesk-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('branch_admin','modules/ilvora-workforce-branch-admin-service9-reports-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('employee','modules/ilvora-workforce-employee-service1-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('employee','modules/ilvora-workforce-employee-service2-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('employee','modules/ilvora-workforce-employee-service3-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('employee','modules/ilvora-workforce-employee-service4-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('employee','modules/ilvora-workforce-employee-service5-prototype-v3/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('employee','modules/ilvora-workforce-employee-service6-prototype-v2/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('employee','modules/ilvora-workforce-employee-service7-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('employee','modules/ilvora-workforce-employee-service8-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('employee','modules/ilvora-workforce-employee-service9-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('head_office_admin','modules/ilvora-workforce-head-office-service1-dashboard-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('head_office_admin','modules/ilvora-workforce-head-office-service10-branch-management-gps-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('head_office_admin','modules/ilvora-workforce-head-office-service11-branch-admin-authorisation-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('head_office_admin','modules/ilvora-workforce-head-office-service2-employee-approval-id-control-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('head_office_admin','modules/ilvora-workforce-head-office-service3-attendance-governance-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('head_office_admin','modules/ilvora-workforce-head-office-service4-leave-management-prototype-v2/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('head_office_admin','modules/ilvora-workforce-head-office-service5-duty-roster-governance-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('head_office_admin','modules/ilvora-workforce-head-office-service6-documents-policies-notices-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('head_office_admin','modules/ilvora-workforce-head-office-service7-complaints-grievance-governance-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('head_office_admin','modules/ilvora-workforce-head-office-service8-requests-helpdesk-governance-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('head_office_admin','modules/ilvora-workforce-head-office-service9-reports-analytics-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-md-executive-command-centre-prototype-v1/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('administrator','modules/ilvora-workforce-resignation-workflow-prototype-v2/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('branch_admin','modules/ilvora-workforce-resignation-workflow-prototype-v2/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('employee','modules/ilvora-workforce-resignation-workflow-prototype-v2/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('head_office_admin','modules/ilvora-workforce-resignation-workflow-prototype-v2/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-resignation-workflow-prototype-v2/');
INSERT OR IGNORE INTO role_module_access(role,module_prefix) VALUES('managing_director','modules/ilvora-workforce-signatory-payroll-experience-prototype-v2/');

INSERT OR IGNORE INTO app_settings(setting_key,setting_value) VALUES('bootstrap_completed','0');
