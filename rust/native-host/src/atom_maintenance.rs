//! Same-origin panel access to the installer-owned local maintenance worker.

use std::fs::{self, File};
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const PREFIX: &str = "/api/v1/atom/maintenance";
const MAX_REPLY: u64 = 128 * 1024;

pub(crate) fn route(method: &str, path: &str) -> Option<&'static str> {
    match (method, path.strip_prefix(PREFIX)?) {
        ("GET", "") => Some("/"),
        ("GET" | "POST", "/network") => Some("/network"),
        ("POST", "/check") => Some("/check"),
        ("POST", "/upgrade") => Some("/upgrade"),
        ("POST", "/confirm") => Some("/confirm"),
        _ => None,
    }
}

pub(crate) fn socket() -> Option<std::path::PathBuf> {
    std::env::var_os("ATOM_MAINTENANCE_SOCKET").map(Into::into)
}

/// Shared with the Go installer's flock. Keep the file open until the write
/// finishes. The journal also blocks writes between a worker crash and recovery.
pub(crate) fn write_guard(socket: &Path) -> io::Result<Option<File>> {
    let directory = socket
        .parent()
        .ok_or_else(|| io::Error::other("invalid socket"))?;
    let lock = match File::open(directory.join("maintenance-writes.lock")) {
        Ok(file) => Some(file),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => return Err(err),
    };
    if let Some(file) = &lock {
        file.try_lock_shared()?;
    }
    #[derive(Deserialize)]
    struct Job {
        blocking: bool,
    }
    match fs::read(directory.join("maintenance-job.json")) {
        Ok(raw) if !serde_json::from_slice::<Job>(&raw)?.blocking => Ok(lock),
        Ok(_) => Err(io::Error::other("maintenance in progress")),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(lock),
        Err(err) => Err(err),
    }
}

pub(crate) async fn request(
    socket: &Path,
    method: &str,
    path: &'static str,
    body: &[u8],
    local: SocketAddr,
) -> io::Result<(u16, Vec<u8>)> {
    tokio::time::timeout(Duration::from_secs(8), async {
        let mut stream = UnixStream::connect(socket).await?;
        let headers = format!(
            "{method} {path} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nX-Atom-Local-Addr: {local}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes()).await?;
        stream.write_all(body).await?;
        let mut raw = Vec::new();
        stream.take(MAX_REPLY).read_to_end(&mut raw).await?;
        let invalid = || io::Error::other("invalid maintenance response");
        if raw.len() as u64 == MAX_REPLY {
            return Err(invalid());
        }
        let start = raw
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .ok_or_else(invalid)?;
        let headers = std::str::from_utf8(&raw[..start]).map_err(|_| invalid())?;
        let status: u16 = headers
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .filter(|status| matches!(status, 200 | 202 | 400 | 404 | 409 | 500 | 503))
            .ok_or_else(invalid)?;
        let expected = headers
            .split("\r\n")
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .ok_or_else(invalid)?;
        let body = raw.split_off(start + 4);
        if body.len() != expected {
            return Err(invalid());
        }
        Ok((status, body))
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_blocks_writes_after_the_worker_releases_its_lock() {
        let root =
            std::env::temp_dir().join(format!("atom-maintenance-lock-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let socket = root.join("maintenance.sock");
        let lock_path = root.join("maintenance-writes.lock");
        let lock = File::create(&lock_path).unwrap();
        lock.try_lock().unwrap();
        assert!(write_guard(&socket).is_err());
        fs::write(root.join("maintenance-job.json"), br#"{"blocking":true}"#).unwrap();
        drop(lock);
        assert!(write_guard(&socket).is_err());
        fs::write(root.join("maintenance-job.json"), br#"{"blocking":false}"#).unwrap();
        assert!(write_guard(&socket).unwrap().is_some());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn forwards_only_a_fixed_path_and_the_actual_listener_address() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let root =
                std::env::temp_dir().join(format!("atom-maintenance-rpc-{}", std::process::id()));
            fs::create_dir_all(&root).unwrap();
            let socket = root.join("rpc.sock");
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            let worker = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n{}") {
                    request.push(stream.read_u8().await.unwrap());
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with("POST /confirm HTTP/1.0\r\n"));
                assert!(request.contains("X-Atom-Local-Addr: 192.0.2.1:8080\r\n"));
                stream
                    .write_all(b"HTTP/1.0 202 Accepted\r\nContent-Length: 11\r\n\r\n{\"ok\":true}")
                    .await
                    .unwrap();
            });
            let path = route("POST", "/api/v1/atom/maintenance/confirm").unwrap();
            let (status, body) = request(
                &socket,
                "POST",
                path,
                b"{}",
                "192.0.2.1:8080".parse().unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(status, 202);
            assert_eq!(body, br#"{"ok":true}"#);
            worker.await.unwrap();
            fs::remove_dir_all(root).unwrap();
        });
    }
}
