-- Registered contact details and secure OTP challenges.
ALTER TABLE users ADD COLUMN registered_email TEXT;
ALTER TABLE users ADD COLUMN registered_mobile TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_registered_email ON users(lower(registered_email)) WHERE registered_email IS NOT NULL AND registered_email<>'';
CREATE TABLE IF NOT EXISTS otp_challenges (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL CHECK(purpose IN ('password_reset','email_verify','mobile_verify')),
  channel TEXT NOT NULL CHECK(channel IN ('email','sms')),
  otp_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  resend_after TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  consumed_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_otp_user_purpose ON otp_challenges(user_id,purpose,channel,created_at);
ALTER TABLE otp_challenges ADD COLUMN challenge_group TEXT;
CREATE INDEX IF NOT EXISTS idx_otp_group ON otp_challenges(challenge_group,purpose,channel);
