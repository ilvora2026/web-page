PRAGMA foreign_keys = ON;
-- Keep the Head Office as the only active branch. Other branch rows are retained inactive
-- so historical attendance, payroll and audit references are not destroyed.
UPDATE branches SET status='inactive' WHERE id<>'branch_kochi';
-- Existing non-executive accounts are moved to Head Office as the sole active branch.
UPDATE users SET branch_id='branch_kochi', updated_at=CURRENT_TIMESTAMP
WHERE role NOT IN ('managing_director','administrator') AND branch_id IS NOT NULL AND branch_id<>'branch_kochi';
UPDATE users SET status='inactive', updated_at=CURRENT_TIMESTAMP
WHERE role NOT IN ('managing_director','administrator')
  AND (lower(display_name) LIKE '%demo employee%'
       OR lower(display_name) LIKE '%sample employee%'
       OR lower(display_name) LIKE '%illustrative employee%'
       OR lower(username) LIKE 'demo_employee%'
       OR lower(username) LIKE 'sample_employee%');
DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE status='inactive' AND role NOT IN ('managing_director','administrator')
  AND (lower(display_name) LIKE '%demo employee%' OR lower(display_name) LIKE '%sample employee%' OR lower(display_name) LIKE '%illustrative employee%'
       OR lower(username) LIKE 'demo_employee%' OR lower(username) LIKE 'sample_employee%'));
DELETE FROM workforce_records WHERE lower(title) LIKE '%demo employee%' OR lower(title) LIKE '%sample employee%' OR lower(data_json) LIKE '%demo employee%' OR lower(data_json) LIKE '%sample employee%';
