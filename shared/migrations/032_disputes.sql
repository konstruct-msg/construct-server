-- Migration 032: Disputes table for botnet report defense
-- Allows users to prove innocence when auto-banned by coordinated botnet reports.

-- Disputes: evidence submission against auto-bans/flags
CREATE TABLE IF NOT EXISTS disputes (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id        VARCHAR(32) NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    restriction_type VARCHAR(50) NOT NULL,   -- 'banned' | 'flagged'
    evidence_text    TEXT,                   -- user's explanation
    auto_evidence    TEXT,                   -- system-collected evidence (JSON)
    status           VARCHAR(20) NOT NULL DEFAULT 'pending_review',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at      TIMESTAMPTZ
);

CREATE INDEX idx_disputes_device ON disputes(device_id);
CREATE INDEX idx_disputes_status ON disputes(status) WHERE status = 'pending_review';

-- Add ban_expires_at index for efficient queries on temporary bans
CREATE INDEX idx_device_flags_ban_expires ON device_flags(ban_expires_at)
    WHERE ban_expires_at IS NOT NULL AND is_banned = TRUE;
