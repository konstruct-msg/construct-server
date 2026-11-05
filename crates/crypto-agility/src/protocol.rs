use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ProtocolVersion {
    #[serde(rename = "v1")]
    #[default]
    V1Classic = 1,
    #[serde(rename = "v2")]
    V2HybridPQ = 2,
}
