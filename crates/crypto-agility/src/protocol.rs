use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ProtocolVersion {
    #[serde(rename = "v1")]
    #[default]
    V1Classic = 1,
    #[serde(rename = "v2")]
    V2HybridPQ = 2,
}

impl ProtocolVersion {
    pub fn as_i32(&self) -> i32 {
        *self as i32
    }
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            1 => Some(Self::V1Classic),
            2 => Some(Self::V2HybridPQ),
            _ => None,
        }
    }
    pub fn is_post_quantum(&self) -> bool {
        matches!(self, Self::V2HybridPQ)
    }
}
