-- Migration 024: SentinelService tables
-- Privacy-first anti-spam infrastructure: metadata-only, no content analysis.
-- Device-based (not user-based) to handle account-switching attacks.

-- ─── Device flags (bans, flags, trust overrides) ──────────────────────────────
CREATE TABLE IF NOT EXISTS device_flags (
    device_id        VARCHAR(32) PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
    is_banned        BOOLEAN      NOT NULL DEFAULT FALSE,
    ban_reason       TEXT,
    banned_at        TIMESTAMPTZ,
    ban_expires_at   TIMESTAMPTZ,         -- NULL = permanent ban
    is_flagged       BOOLEAN      NOT NULL DEFAULT FALSE,
    flagged_at       TIMESTAMPTZ,
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_device_flags_banned   ON device_flags(is_banned)  WHERE is_banned = TRUE;
CREATE INDEX idx_device_flags_flagged  ON device_flags(is_flagged) WHERE is_flagged = TRUE;

-- ─── Spam reports ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS spam_reports (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_device_id  VARCHAR(32) NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    reported_device_id  VARCHAR(32) NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    category            VARCHAR(50) NOT NULL,  -- matches SpamCategory enum
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- No (reporter, reported) unique constraint: one reporter can file multiple reports
-- over time for different incidents.
CREATE INDEX idx_spam_reports_reported ON spam_reports(reported_device_id, created_at DESC);
CREATE INDEX idx_spam_reports_reporter ON spam_reports(reporter_device_id);

-- ─── Server-enforced device blocks ────────────────────────────────────────────
-- When device A blocks device B, the server stops delivering B's messages to A.
CREATE TABLE IF NOT EXISTS device_blocks (
    blocker_device_id  VARCHAR(32) NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    blocked_device_id  VARCHAR(32) NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (blocker_device_id, blocked_device_id)
);

CREATE INDEX idx_device_blocks_blocker ON device_blocks(blocker_device_id);
CREATE INDEX idx_device_blocks_blocked ON device_blocks(blocked_device_id);

-- ─── Restriction appeals ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS restriction_appeals (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id        VARCHAR(32) NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    restriction_type VARCHAR(50) NOT NULL,   -- 'rate_limited' | 'flagged' | 'banned'
    context          TEXT,                   -- user's explanation; no message content
    status           VARCHAR(20) NOT NULL DEFAULT 'pending_review',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at      TIMESTAMPTZ
);

CREATE INDEX idx_appeals_device  ON restriction_appeals(device_id);
CREATE INDEX idx_appeals_status  ON restriction_appeals(status) WHERE status = 'pending_review';
