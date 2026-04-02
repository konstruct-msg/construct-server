-- Migration 040: call_records
-- Stores completed/missed/declined call history for both participants.

CREATE TABLE call_records (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    call_id          TEXT        NOT NULL UNIQUE,
    caller_user_id   TEXT        NOT NULL,
    callee_user_id   TEXT        NOT NULL,
    call_type        TEXT        NOT NULL DEFAULT 'audio',   -- 'audio' | 'video'
    status           TEXT        NOT NULL,                   -- 'completed' | 'missed' | 'declined' | 'busy' | 'failed'
    offered_at_ms    BIGINT      NOT NULL,
    answered_at_ms   BIGINT,
    ended_at_ms      BIGINT      NOT NULL,
    duration_seconds INTEGER,                                -- NULL when call was not answered
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_call_records_caller ON call_records (caller_user_id, offered_at_ms DESC);
CREATE INDEX idx_call_records_callee ON call_records (callee_user_id, offered_at_ms DESC);
