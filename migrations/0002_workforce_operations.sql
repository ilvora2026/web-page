PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS workforce_records (
  id TEXT PRIMARY KEY,
  record_type TEXT NOT NULL,
  branch_id TEXT REFERENCES branches(id),
  owner_user_id TEXT REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'draft',
  title TEXT NOT NULL,
  data_json TEXT NOT NULL DEFAULT '{}',
  created_by TEXT NOT NULL REFERENCES users(id),
  updated_by TEXT NOT NULL REFERENCES users(id),
  approved_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_workforce_type_branch ON workforce_records(record_type,branch_id,status);
CREATE INDEX IF NOT EXISTS idx_workforce_owner ON workforce_records(owner_user_id,record_type);
CREATE INDEX IF NOT EXISTS idx_workforce_created ON workforce_records(created_at);
CREATE TABLE IF NOT EXISTS document_assets (
  asset_key TEXT PRIMARY KEY CHECK(asset_key IN ('company_logo','md_signature','company_seal')),
  mime_type TEXT NOT NULL,
  data_url TEXT NOT NULL,
  display_name TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  uploaded_by TEXT NOT NULL REFERENCES users(id),
  uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS generated_documents (
  id TEXT PRIMARY KEY,
  document_type TEXT NOT NULL,
  record_id TEXT,
  employee_user_id TEXT REFERENCES users(id),
  branch_id TEXT REFERENCES branches(id),
  document_number TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  html_snapshot TEXT NOT NULL,
  asset_versions_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'final',
  generated_by TEXT NOT NULL REFERENCES users(id),
  approved_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_documents_employee ON generated_documents(employee_user_id,created_at);
CREATE INDEX IF NOT EXISTS idx_documents_branch ON generated_documents(branch_id,created_at);
INSERT OR IGNORE INTO role_module_access(role,module_prefix)
VALUES('attendance_marker','modules/ilvora-workforce-attendance-marker-capture-v1/');
CREATE TABLE IF NOT EXISTS branch_geofences (
  branch_id TEXT PRIMARY KEY REFERENCES branches(id) ON DELETE CASCADE,
  latitude REAL NOT NULL,
  longitude REAL NOT NULL,
  radius_m INTEGER NOT NULL DEFAULT 150 CHECK(radius_m BETWEEN 25 AND 2000),
  updated_by TEXT NOT NULL REFERENCES users(id),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  recipient_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  recipient_branch_id TEXT REFERENCES branches(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'announcement',
  created_by TEXT NOT NULL REFERENCES users(id),
  read_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK(recipient_user_id IS NOT NULL OR recipient_branch_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(recipient_user_id,created_at);
CREATE INDEX IF NOT EXISTS idx_notifications_branch ON notifications(recipient_branch_id,created_at);
INSERT OR IGNORE INTO app_settings(setting_key,setting_value) VALUES
 ('salary_cycle_days','30'),
 ('payslip_generation_day','12'),
 ('attendance_register_close_day','20'),
 ('paid_medical_leave_days_per_financial_year','5'),
 ('casual_leave_paid','0'),
 ('attendance_photo_retention_days','2');
