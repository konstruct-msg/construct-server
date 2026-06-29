-- Drop the rate_limit_events table used by group-service for sliding-window
-- rate limiting. Replaced by Redis ZSets (sliding_window_check_and_record in
-- construct-rate-limit). Redis TTL handles expiry; no background cleanup needed.
--
-- The rate_limits table (construct-rate-limit PG fallback) is intentionally kept —
-- it's the fallback path if Redis is unavailable.
DROP TABLE IF EXISTS rate_limit_events;
