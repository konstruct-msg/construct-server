//! A Redis that fails the commands a test names, shared by the services that must survive it.
use std::sync::Arc;
use tokio::sync::Mutex;

/// A TCP forwarder to the test Redis that answers `-ERR` to any command naming the armed key
/// fragment and forwards everything else. Isolates one read from others on the same connection,
/// which `CuttableRedis` cannot. Commands on a connection here are one at a time.
pub(crate) struct FaultyRedis {
    pub(crate) url: String,
    armed: tokio::sync::watch::Sender<Option<Vec<u8>>>,
}

impl FaultyRedis {
    pub(crate) async fn start(redis_url: &str) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let target = redis_url
            .trim_start_matches("redis://")
            .trim_end_matches('/')
            .to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a local port");
        let url = format!("redis://{}", listener.local_addr().expect("local addr"));
        let (armed, armed_rx) = tokio::sync::watch::channel(None::<Vec<u8>>);
        tokio::spawn(async move {
            while let Ok((inbound, _)) = listener.accept().await {
                let target = target.clone();
                let armed_rx = armed_rx.clone();
                tokio::spawn(async move {
                    let Ok(outbound) = tokio::net::TcpStream::connect(&target).await else {
                        return;
                    };
                    let (mut client_read, client_write) = inbound.into_split();
                    let (mut server_read, mut server_write) = outbound.into_split();
                    let client_write = Arc::new(Mutex::new(client_write));
                    let to_client = client_write.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 64 * 1024];
                        while let Ok(n) = server_read.read(&mut buf).await {
                            if n == 0 || to_client.lock().await.write_all(&buf[..n]).await.is_err()
                            {
                                return;
                            }
                        }
                    });
                    let mut buf = vec![0u8; 64 * 1024];
                    while let Ok(n) = client_read.read(&mut buf).await {
                        if n == 0 {
                            return;
                        }
                        let hit = armed_rx.borrow().as_ref().is_some_and(|needle| {
                            buf[..n]
                                .windows(needle.len())
                                .any(|w| w == needle.as_slice())
                        });
                        let sent = if hit {
                            client_write
                                .lock()
                                .await
                                .write_all(b"-ERR injected by FaultyRedis\r\n")
                                .await
                        } else {
                            server_write.write_all(&buf[..n]).await
                        };
                        if sent.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self { url, armed }
    }

    pub(crate) fn fail_commands_naming(&self, fragment: &str) {
        let _ = self.armed.send(Some(fragment.as_bytes().to_vec()));
    }

    #[allow(dead_code)] // not every service that fails it brings it back
    pub(crate) fn recover(&self) {
        let _ = self.armed.send(None);
    }
}
