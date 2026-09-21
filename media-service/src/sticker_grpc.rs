// ============================================================================
// StickerService — the four public RPCs
// ============================================================================
//
// Every handler is unauthenticated on purpose: pack bytes are the same for everyone, and a
// token would attach an identity to a fetch for no benefit. The abuse surface is bandwidth,
// and a per-IP window is the whole answer — a device fetches a pack once, ever.
//
// The service serves bytes it was given. It holds no signing key and verifies no signature;
// the client re-hashes the manifest, checks the signature against the pinned bundle key, and
// checks every blob against the hash the signed manifest names. What this service can do is
// withhold, never substitute — which is what makes the unauthenticated transport safe.
//
// Design: construct-docs/decisions/sticker-packs-content-addressed.md,
// backend/STICKER_SERVICE_SPEC.md.

use std::collections::HashSet;
use std::sync::Arc;

use prost::Message;
use sqlx::PgPool;
use tonic::{Request, Response, Status};
use tracing::{error, warn};

use construct_server_shared::shared::proto::messaging::v1::StickerPackManifest;
use construct_server_shared::shared::proto::services::v1 as proto;
use proto::sticker_service_server::StickerService;

use crate::rate_limit::SlidingWindowLimiter;
use crate::stickers::{self, PageCursor, rules};

#[derive(Clone)]
pub struct StickerGrpcService {
    pool: Arc<PgPool>,
    /// Per-IP window over all four RPCs together. Generous: a device that fetches every pack
    /// in the catalog once is still far under it.
    limiter: Arc<SlidingWindowLimiter<String>>,
}

impl StickerGrpcService {
    pub fn new(pool: Arc<PgPool>, limiter: Arc<SlidingWindowLimiter<String>>) -> Self {
        Self { pool, limiter }
    }

    fn gate(&self, metadata: &tonic::metadata::MetadataMap) -> Result<(), Status> {
        let ip = client_ip(metadata);
        if self.limiter.check_and_record(ip.clone()) {
            Ok(())
        } else {
            warn!(ip = %ip, "sticker rate limit exceeded");
            Err(Status::resource_exhausted("sticker rate limit exceeded"))
        }
    }

    async fn manifest_bytes(&self, pack_id: &[u8]) -> Result<Vec<u8>, Status> {
        stickers::get_manifest_bytes(&self.pool, pack_id)
            .await
            .map_err(|e| {
                error!(error = %e, "sticker_packs read failed");
                Status::internal("database error")
            })?
            .ok_or_else(|| Status::not_found("pack not found"))
    }
}

/// The connecting client behind Caddy. Rightmost `x-forwarded-for` hop, never the leftmost:
/// Caddy appends the real peer after anything the client pre-set, so the first entry is
/// attacker-controlled and the last is not. Same rule as key-service and messaging.
fn client_ip(metadata: &tonic::metadata::MetadataMap) -> String {
    if let Some(forwarded) = metadata
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        let ip = forwarded.split(',').next_back().unwrap_or("").trim();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }
    if let Some(real_ip) = metadata.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let ip = real_ip.trim();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }
    "unknown".to_string()
}

fn require_hash<'a>(bytes: &'a [u8], what: &str) -> Result<&'a [u8], Status> {
    if bytes.len() != rules::HASH_LEN {
        return Err(Status::invalid_argument(format!(
            "{what} must be {} bytes, got {}",
            rules::HASH_LEN,
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[tonic::async_trait]
impl StickerService for StickerGrpcService {
    async fn list_sticker_packs(
        &self,
        request: Request<proto::ListStickerPacksRequest>,
    ) -> Result<Response<proto::ListStickerPacksResponse>, Status> {
        self.gate(request.metadata())?;
        let req = request.into_inner();

        let after = if req.page_token.is_empty() {
            None
        } else {
            Some(
                PageCursor::decode(&req.page_token)
                    .map_err(|e| Status::invalid_argument(e.to_string()))?,
            )
        };
        let limit = stickers::page_size(req.page_size);

        let rows = stickers::list_packs(&self.pool, after.as_ref(), limit)
            .await
            .map_err(|e| {
                error!(error = %e, "sticker catalog read failed");
                Status::internal("database error")
            })?;

        // A full page may be the last one; the client learns that on the next, empty call.
        // Cheaper than a count query on every page for a catalog that fits in one.
        let next_page_token = if rows.len() as u32 == limit {
            rows.last()
                .map(|r| {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&r.pack_id);
                    PageCursor {
                        published_at_micros: r.published_at_micros,
                        pack_id: id,
                    }
                    .encode()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let packs = rows
            .into_iter()
            .map(|r| proto::StickerPackSummary {
                pack_id: r.pack_id,
                title: r.title,
                publisher: r.publisher,
                sticker_count: r.sticker_count.max(0) as u32,
                cover_sha256: r.cover_sha256,
                total_bytes: r.total_bytes.max(0) as u64,
            })
            .collect();

        Ok(Response::new(proto::ListStickerPacksResponse {
            packs,
            next_page_token,
        }))
    }

    async fn get_sticker_pack_manifest(
        &self,
        request: Request<proto::GetStickerPackManifestRequest>,
    ) -> Result<Response<proto::GetStickerPackManifestResponse>, Status> {
        self.gate(request.metadata())?;
        let req = request.into_inner();
        let pack_id = require_hash(&req.pack_id, "pack_id")?;

        let bytes = self.manifest_bytes(pack_id).await?;
        // Decoded here only to be re-encoded by tonic. prost round-trips a message it
        // produced byte-for-byte, and the publish tool wrote these bytes with the same
        // encoder; the client re-hashes what arrives, so a drift here would be a
        // NOT-verified pack on every device, not a silent one.
        let manifest = StickerPackManifest::decode(bytes.as_slice()).map_err(|e| {
            error!(error = %e, pack_id = %hex::encode(pack_id), "stored manifest does not decode");
            Status::internal("stored manifest is corrupt")
        })?;

        Ok(Response::new(proto::GetStickerPackManifestResponse {
            manifest: Some(manifest),
        }))
    }

    type GetStickerPackBlobsStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::GetStickerPackBlobsResponse, Status>>;

    async fn get_sticker_pack_blobs(
        &self,
        request: Request<proto::GetStickerPackBlobsRequest>,
    ) -> Result<Response<Self::GetStickerPackBlobsStream>, Status> {
        self.gate(request.metadata())?;
        let req = request.into_inner();
        let pack_id = require_hash(&req.pack_id, "pack_id")?;

        if req.have_sha256.len() > rules::MAX_HAVE {
            return Err(Status::invalid_argument(format!(
                "have_sha256 lists {} hashes, at most {} allowed",
                req.have_sha256.len(),
                rules::MAX_HAVE
            )));
        }
        for h in &req.have_sha256 {
            require_hash(h, "have_sha256 entry")?;
        }
        let have: HashSet<Vec<u8>> = req.have_sha256.into_iter().collect();

        let bytes = self.manifest_bytes(pack_id).await?;
        let manifest = StickerPackManifest::decode(bytes.as_slice()).map_err(|e| {
            error!(error = %e, pack_id = %hex::encode(pack_id), "stored manifest does not decode");
            Status::internal("stored manifest is corrupt")
        })?;

        // Manifest order, skipping what the client holds. A blob the manifest names and the
        // table lacks is a publish that did not finish — surfaced as an error mid-stream, not
        // skipped, so the client does not write a pack it will find incomplete.
        let wanted: Vec<Vec<u8>> = manifest
            .stickers
            .into_iter()
            .map(|e| e.sha256)
            .filter(|sha| !have.contains(sha))
            .collect();

        let pool = Arc::clone(&self.pool);
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            for sha in wanted {
                let item = match stickers::get_blob(&pool, &sha).await {
                    Ok(Some(data)) => Ok(proto::GetStickerPackBlobsResponse { sha256: sha, data }),
                    Ok(None) => {
                        error!(sha256 = %hex::encode(&sha), "manifest names a blob the store lacks");
                        Err(Status::data_loss("pack is missing a blob"))
                    }
                    Err(e) => {
                        error!(error = %e, "sticker_blobs read failed");
                        Err(Status::internal("database error"))
                    }
                };
                let stop = item.is_err();
                if tx.send(item).await.is_err() || stop {
                    break;
                }
            }
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn get_sticker_blob(
        &self,
        request: Request<proto::GetStickerBlobRequest>,
    ) -> Result<Response<proto::GetStickerBlobResponse>, Status> {
        self.gate(request.metadata())?;
        let req = request.into_inner();
        let sha = require_hash(&req.sha256, "sha256")?;

        let data = stickers::get_blob(&self.pool, sha)
            .await
            .map_err(|e| {
                error!(error = %e, "sticker_blobs read failed");
                Status::internal("database error")
            })?
            .ok_or_else(|| Status::not_found("blob not found"))?;

        Ok(Response::new(proto::GetStickerBlobResponse { data }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ip_takes_rightmost_forwarded_hop() {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert("x-forwarded-for", "1.1.1.1, 203.0.113.9".parse().unwrap());
        assert_eq!(client_ip(&m), "203.0.113.9");
    }

    #[test]
    fn client_ip_falls_back_to_real_ip_then_unknown() {
        let mut m = tonic::metadata::MetadataMap::new();
        assert_eq!(client_ip(&m), "unknown");
        m.insert("x-real-ip", "198.51.100.4".parse().unwrap());
        assert_eq!(client_ip(&m), "198.51.100.4");
    }

    #[test]
    fn require_hash_rejects_other_lengths() {
        assert!(require_hash(&[0u8; 32], "x").is_ok());
        let err = require_hash(&[0u8; 31], "pack_id").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("pack_id"));
        assert!(require_hash(&[], "x").is_err());
    }
}
