-- Migration 066: push_environment becomes a candidate LIST, not a single assertion.
--
-- `device_tokens.push_environment` / `voip_tokens.push_environment` now hold either one
-- environment ('sandbox' | 'production') or a comma-separated candidate list
-- ('sandbox,production'). A single value asserts which APNs endpoint the token belongs
-- to; the pair says it is unknown and both must be tried.
--
-- Why: APNs answers BadDeviceToken both for a genuinely dead token AND for a live token
-- sent to the wrong endpoint. The sender cannot tell those apart, so it deleted the row —
-- meaning any mislabelling silently cost a user their push notifications, permanently,
-- with the client happily re-registering the same wrong label on next foreground.
--
-- Two paths were writing labels they had no basis for:
--   * POST /api/v1/notifications/register-device hardcoded 'production' (the request body
--     carried no environment field at all);
--   * the gRPC RegisterDeviceToken mapped PUSH_ENVIRONMENT_UNSPECIFIED to 'sandbox'.
-- Both now record both candidates instead of guessing.
--
-- Existing rows carry those guesses and cannot be distinguished from correctly-asserted
-- ones, so relax every row to the candidate pair. The sender probes, then pins the row to
-- whichever endpoint accepted the token — so this costs one extra APNs round-trip per
-- token once, not per push. Rows whose label was already right re-pin to the same value.

UPDATE device_tokens
   SET push_environment = 'sandbox,production'
 WHERE push_environment IN ('sandbox', 'production');

UPDATE voip_tokens
   SET push_environment = 'sandbox,production'
 WHERE push_environment IN ('sandbox', 'production');

-- The 025 index on (user_id, push_environment) still works: it just carries the wider
-- value until the senders narrow each row again.
