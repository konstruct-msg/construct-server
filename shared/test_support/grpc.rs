//! Calls a real generated gRPC service, through whatever is layered on it, as a client would. The
//! crate builds server stubs only, and a handler called directly never meets a tower layer.
use http_body_util::Full;
use prost::bytes::Bytes;
use tonic::body::Body;
use tonic::codegen::{Service, http};

/// One unary or server-streaming call: its status when it failed before any message
/// (`Code::Ok` otherwise, the real status being in trailers) and its response headers.
pub(crate) async fn call<S, M, R>(
    mut service: S,
    path: &str,
    token: Option<&str>,
    message: &M,
) -> (tonic::Code, http::HeaderMap)
where
    S: Service<http::Request<Body>, Response = http::Response<R>>,
    S::Error: std::fmt::Debug,
    M: prost::Message,
{
    let encoded = message.encode_to_vec();
    let mut frame = Vec::with_capacity(encoded.len() + 5);
    frame.push(0);
    frame.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    frame.extend_from_slice(&encoded);

    let mut request = http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/grpc")
        .header("te", "trailers");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = service
        .call(
            request
                .body(Body::new(Full::new(Bytes::from(frame))))
                .unwrap(),
        )
        .await
        .unwrap();
    let code = response
        .headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i32>().ok())
        .map_or(tonic::Code::Ok, tonic::Code::from_i32);
    (code, response.headers().clone())
}
