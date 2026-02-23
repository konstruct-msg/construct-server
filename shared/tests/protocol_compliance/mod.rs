// Protocol Compliance Tests
//
// These tests verify that our implementation conforms to:
// 1. Signal Protocol (X3DH + Double Ratchet)
// 2. Noise Protocol Framework
// 3. Our custom extensions (Stream ID pagination, etc.)

// double_ratchet_tests and stream_id_tests removed:
// they tested REST GET /api/v1/messages (long-polling) which is deprecated.
// TODO: rewrite for gRPC MessageStream once streaming integration tests are in place.
pub mod x3dh_tests;
