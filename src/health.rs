//! Minimal HTTP server for liveness and readiness probes.
//!
//! - `GET /healthz` → 200 OK (liveness)
//! - `GET /readyz`  → 200 OK (readiness)
//!
//! Listens on `:8081`. No vault data is ever exposed.

use std::net::SocketAddr;

use tokio::net::TcpListener;
use tracing::info;

/// Start the health probe server on `0.0.0.0:8081`.
///
/// Runs until the process exits or the task is cancelled.
pub async fn serve() {
    let addr: SocketAddr = "0.0.0.0:8081".parse().unwrap();
    let listener = TcpListener::bind(addr).await.expect("bind health server");
    info!(%addr, "health server listening");

    loop {
        match listener.accept().await {
            Ok((mut stream, _peer)) => {
                tokio::spawn(async move {
                    handle_connection(&mut stream).await;
                });
            }
            Err(e) => {
                tracing::warn!(err = %e, "health server accept error");
            }
        }
    }
}

async fn handle_connection(stream: &mut tokio::net::TcpStream) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (reader, mut writer) = stream.split();
    let mut buf_reader = BufReader::new(reader);
    let mut request_line = String::new();

    if buf_reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    // Drain remaining headers to avoid broken-pipe resets.
    let mut line = String::new();
    loop {
        line.clear();
        match buf_reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) if line == "\r\n" || line == "\n" => break,
            _ => {}
        }
    }

    let path = request_line.split_whitespace().nth(1).unwrap_or("/");

    let response = match path {
        "/healthz" | "/readyz" => {
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nOK"
        }
        _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nContent-Type: text/plain\r\n\r\nNot Found",
    };

    let _ = writer.write_all(response.as_bytes()).await;
}
