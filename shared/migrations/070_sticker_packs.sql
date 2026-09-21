-- Sticker packs: content-addressed, immutable, public. No TTL, no reaper.
--
-- Not `media_files`. Media is E2E ciphertext a sender uploads and the recipient fetches once,
-- and MEDIA_FILE_TTL_SECONDS deletes it after seven days. A sticker pack has to resolve for as
-- long as any message references it — a StickerRef inside E2EE names a pack by the hash of its
-- manifest and a sticker by its index, and the transcript keeps that reference forever. A
-- sticker that expired would render as its emoji fallback on every device that had not fetched
-- the pack yet, permanently. So: separate tables, no `expires_at`, and nothing sweeps them.
--
-- Both tables are keyed by what they contain. `sticker_blobs.sha256` is the hash of the WebP
-- bytes; `sticker_packs.pack_id` is the hash of the manifest's canonical bytes (proto3 binary,
-- pack_id and signature cleared — construct-protos conformance/knst_sticker_pack.json). A
-- changed pack is a different pack; nothing is ever updated in place except `listed`.
--
-- The pack's sticker order lives only in `manifest_bytes`: that is the signed message the
-- client verifies, and a second copy of the order in a join table would be a second carrier of
-- the same meaning that nothing enforces. GetStickerPackBlobs decodes the manifest to walk it.
--
-- Design: construct-docs/decisions/sticker-packs-content-addressed.md, backend/STICKER_SERVICE_SPEC.md.

CREATE TABLE sticker_blobs (
    sha256      BYTEA PRIMARY KEY,
    -- Static WebP, 512×512, at most 100 KiB. Refused at publish and re-checked by every client;
    -- the CHECK is the last line, not the first.
    bytes       BYTEA NOT NULL,
    width       INTEGER NOT NULL,
    height      INTEGER NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT sticker_blobs_sha256_len CHECK (octet_length(sha256) = 32),
    CONSTRAINT sticker_blobs_size CHECK (octet_length(bytes) BETWEEN 1 AND 102400)
);

CREATE TABLE sticker_packs (
    pack_id         BYTEA PRIMARY KEY,
    -- The signed StickerPackManifest exactly as published. Served byte-for-byte: the client
    -- re-hashes it, so any re-encoding here would change the pack's name.
    manifest_bytes  BYTEA NOT NULL,
    -- Denormalised from the manifest for the catalog row; the manifest stays authoritative.
    title           TEXT NOT NULL,
    publisher       TEXT NOT NULL,
    sticker_count   INTEGER NOT NULL,
    total_bytes     BIGINT NOT NULL,
    cover_sha256    BYTEA NOT NULL,
    published_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- false withdraws the pack from ListStickerPacks without deleting it: messages that
    -- reference it keep resolving. Also the state a pack is inserted in — the publish tool
    -- flips it last, so a pack that failed half-way is never in the catalog.
    listed          BOOLEAN NOT NULL DEFAULT false,
    CONSTRAINT sticker_packs_pack_id_len CHECK (octet_length(pack_id) = 32),
    CONSTRAINT sticker_packs_cover_len CHECK (octet_length(cover_sha256) = 32),
    CONSTRAINT sticker_packs_count CHECK (sticker_count BETWEEN 1 AND 120)
);

-- The catalog reads listed packs newest first, by (published_at, pack_id) as its cursor.
CREATE INDEX sticker_packs_listed_idx
    ON sticker_packs (published_at DESC, pack_id DESC)
    WHERE listed;
