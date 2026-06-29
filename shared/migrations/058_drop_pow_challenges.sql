-- PoW challenges moved to Redis (construct-queue `pow` module). Challenges are
-- pure short-lived cache (~10 min) — Redis TTL handles expiry automatically (the
-- old DB path had no cleanup job and grew unbounded). Per-IP rate-limit and
-- anti-spam counters are now Redis sorted sets (pow:ipch:*, pow:ipreg:*).
DROP TABLE IF EXISTS pow_challenges CASCADE;
