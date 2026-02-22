// pub mod deeplinks;  // TODO: Requires axum and qrcode dependencies
pub mod device_tokens;
pub mod federation;
pub mod keys;
pub mod media;
// pub mod messages;  // Removed: replaced by src/routes/messages.rs (Phase 2.8)

use crate::context::AppContext;
use construct_types::ClientMessage;
use crate::metrics;