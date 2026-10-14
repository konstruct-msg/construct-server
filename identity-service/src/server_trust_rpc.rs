//! `ServerTrustService` — the server's public trust material over gRPC.
//!
//! Decision: construct-docs `decisions/veil-on-never-goes-direct.md`. The signed manifest and the
//! server-key delegations travelled only as plain HTTPS `/.well-known/construct-server`, a request
//! a client with VEIL `on` may not make: it would go around the tunnel. Asked here, they ride the
//! client's ordinary gRPC channel, which under `on` is the tunnel.
//!
//! Nothing is produced here. The manifest is the signed file the project domain serves, put in
//! `SERVER_TRUST_DIR` and served byte for byte; the delegations are the `*.delegation` files the gateway serves too. A server
//! able to change either could not make a client accept the change — the manifest is checked
//! against a key in the client's build, the delegations against roots in it.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use construct_crypto::server_trust::{
    load_delegations, load_signed_manifest, servable_delegations,
};
use construct_server_shared::shared::proto::services::v1::{
    GetServerTrustRequest, GetServerTrustResponse, server_trust_service_server::ServerTrustService,
};
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};

/// The directory changes once a quarter; the gateway caches its `/.well-known` copy as long.
const REFRESH: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct ServerTrustGrpc {
    dir: PathBuf,
    cached: Arc<RwLock<Option<(Instant, GetServerTrustResponse)>>>,
}

impl ServerTrustGrpc {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            cached: Arc::new(RwLock::new(None)),
        }
    }

    /// What the directory holds now. A part that cannot be read is served empty and logged —
    /// clients then keep what they cached, as they do when `/.well-known` omits it.
    fn read(&self, now: i64) -> GetServerTrustResponse {
        let delegations = match load_delegations(&self.dir) {
            Ok(all) => servable_delegations(all, now)
                .iter()
                .map(|d| d.encode())
                .collect(),
            Err(e) => {
                tracing::error!(error = %format!("{e:#}"), "SERVER_TRUST_DIR unreadable — serving no delegations");
                Vec::new()
            }
        };
        let signed_manifest = match load_signed_manifest(&self.dir) {
            Ok(m) => m.unwrap_or_default(),
            Err(e) => {
                tracing::error!(error = %format!("{e:#}"), "signed manifest unreadable — serving none");
                Vec::new()
            }
        };
        GetServerTrustResponse {
            signed_manifest,
            delegations,
        }
    }
}

#[tonic::async_trait]
impl ServerTrustService for ServerTrustGrpc {
    async fn get_server_trust(
        &self,
        _request: Request<GetServerTrustRequest>,
    ) -> Result<Response<GetServerTrustResponse>, Status> {
        if let Some((at, response)) = self.cached.read().await.as_ref()
            && at.elapsed() < REFRESH
        {
            return Ok(Response::new(response.clone()));
        }
        let response = self.read(chrono::Utc::now().timestamp());
        *self.cached.write().await = Some((Instant::now(), response.clone()));
        Ok(Response::new(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use construct_crypto::server_trust::{Delegation, SIGNED_MANIFEST_FILE};

    const VECTORS: &str =
        include_str!("../../crates/construct-crypto/tests/knst_server_trust.json");

    fn vector_delegation() -> Vec<u8> {
        let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        hex::decode(v["delegations"][0]["encoded"].as_str().unwrap()).unwrap()
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("server-trust-rpc-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    async fn ask(dir: PathBuf) -> GetServerTrustResponse {
        ServerTrustGrpc::new(dir)
            .get_server_trust(Request::new(GetServerTrustRequest {}))
            .await
            .unwrap()
            .into_inner()
    }

    /// The client checks a signature over these exact bytes; any re-serialisation breaks it.
    #[tokio::test]
    async fn serves_the_manifest_byte_for_byte() {
        let dir = scratch_dir("manifest");
        let manifest =
            b"{ \"signed_at\" : \"2026-10-14T00:00:00Z\",\n  \"signature\":\"ed25519:x\" }\n\n";
        std::fs::write(dir.join(SIGNED_MANIFEST_FILE), manifest).unwrap();
        assert_eq!(ask(dir).await.signed_manifest, manifest.to_vec());
    }

    #[tokio::test]
    async fn serves_the_delegations_the_gateway_serves() {
        let dir = scratch_dir("delegations");
        let encoded = vector_delegation();
        std::fs::write(dir.join("sender.delegation"), hex::encode(&encoded)).unwrap();
        // Not a delegation, and must not be read as one.
        std::fs::write(dir.join(SIGNED_MANIFEST_FILE), b"{}").unwrap();

        let response = ask(dir.clone()).await;
        let expected: Vec<Vec<u8>> = servable_delegations(
            vec![Delegation::decode(&encoded).unwrap()],
            chrono::Utc::now().timestamp(),
        )
        .iter()
        .map(|d| d.encode())
        .collect();
        assert!(
            !expected.is_empty(),
            "the vector's delegation must still be servable"
        );
        assert_eq!(response.delegations, expected);
        assert_eq!(response.signed_manifest, b"{}".to_vec());
    }

    /// No directory at all — a server before its ceremony — answers empty, not an error.
    #[tokio::test]
    async fn an_absent_directory_serves_nothing() {
        let dir =
            std::env::temp_dir().join(format!("server-trust-rpc-{}-absent", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let response = ask(dir).await;
        assert!(response.signed_manifest.is_empty());
        assert!(response.delegations.is_empty());
    }
}
