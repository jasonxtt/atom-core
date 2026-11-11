//! Shared pieces of static serving: target decoding, MIME types, safe
//! redirects, and the page `/` shows when no WebUI is installed. The program
//! embeds no UI; the WebUI is `<config root>/ui/main/` (`external_ui.rs`).
use atomdns_upstream_core::TransportCancellation;
use std::io;
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub(crate) fn decoded_path(target: &str) -> Option<String> {
    let raw = target.split('?').next()?;
    if !raw.starts_with('/') {
        return None;
    }
    let mut result = String::new();
    for (index, component) in raw.split('/').enumerate() {
        if index > 0 {
            result.push('/');
        }
        let mut bytes = Vec::new();
        let mut input = component.bytes();
        while let Some(byte) = input.next() {
            let byte = if byte == b'%' {
                let high = char::from(input.next()?).to_digit(16)?;
                let low = char::from(input.next()?).to_digit(16)?;
                u8::try_from(high * 16 + low).ok()?
            } else {
                byte
            };
            if byte == 0 || byte == b'/' || byte == b'\\' || byte.is_ascii_control() {
                return None;
            }
            bytes.push(byte);
        }
        let part = std::str::from_utf8(&bytes).ok()?;
        if part == "." || part == ".." {
            return None;
        }
        result.push_str(part);
    }
    Some(result)
}

#[cfg(target_os = "linux")]
pub(crate) fn mime(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// Preserve only a syntactically valid query whose decoded bytes contain no
/// control characters. Redirect headers never reflect unsafe input.
#[cfg(target_os = "linux")]
pub(crate) fn redirect_target(path: &str, target: &str) -> Option<String> {
    let Some((_, query)) = target.split_once('?') else {
        return Some(path.to_owned());
    };
    let mut bytes = Vec::new();
    let mut input = query.bytes();
    while let Some(byte) = input.next() {
        let byte = if byte == b'%' {
            let high = char::from(input.next()?).to_digit(16)?;
            let low = char::from(input.next()?).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()?
        } else {
            byte
        };
        if byte.is_ascii_control() {
            return None;
        }
        bytes.push(byte);
    }
    std::str::from_utf8(&bytes).ok()?;
    Some(format!("{path}?{query}"))
}

/// `GET`/`HEAD /` without a usable `ui/main`: a short `404` page that says
/// so (and why, when `ui/main` was refused); the API is unaffected.
pub(crate) async fn write_not_installed<W: AsyncWrite + Unpin>(
    writer: &mut W,
    method: &str,
    refused: Option<&str>,
    shutdown: &TransportCancellation,
) -> io::Result<()> {
    let detail = match refused {
        Some(reason) => format!("<p>ui/main 未被使用：{}</p>", escape_html(reason)),
        None => String::new(),
    };
    let body = format!(
        "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><title>atomdns</title>\
         <p>atomdns 正在运行，但没有安装 WebUI。</p>{detail}\
         <p>把 atom-webui.tar.gz 解压到 &lt;配置根&gt;/ui/main/ 后重启即可；接口照常可用。</p></html>\n"
    );
    let response = async {
        writer
            .write_all(
                format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await?;
        if method != "HEAD" {
            writer.write_all(body.as_bytes()).await?;
        }
        writer.flush().await
    };
    tokio::select! {
        biased;
        () = shutdown.cancelled() => Ok(()),
        result = tokio::time::timeout(std::time::Duration::from_secs(10), response) => {
            result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "static response deadline"))?
        }
    }
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn the_not_installed_page_is_a_404_that_names_the_fix_and_escapes_the_reason() {
        crate::HostRuntime::new().unwrap().block_on(async {
            let shutdown = TransportCancellation::new();
            for (method, refused) in [
                ("GET", None),
                ("GET", Some("需要接口级别 <2>")),
                ("HEAD", None),
            ] {
                let (mut writer, mut reader) = tokio::io::duplex(4096);
                write_not_installed(&mut writer, method, refused, &shutdown)
                    .await
                    .unwrap();
                drop(writer);
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).await.unwrap();
                let text = String::from_utf8(bytes).unwrap();
                assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"), "{text}");
                assert!(text.contains("text/html; charset=utf-8"));
                let (_, body) = text.split_once("\r\n\r\n").unwrap();
                if method == "HEAD" {
                    assert!(body.is_empty());
                    continue;
                }
                assert!(body.contains("没有安装 WebUI") && body.contains("ui/main"));
                if refused.is_some() {
                    assert!(body.contains("需要接口级别 &lt;2&gt;"), "{body}");
                }
            }
        });
    }

    #[test]
    fn decoding_never_allows_component_separators_or_traversal() {
        for target in [
            "/assets/%2e%2e/x",
            "/assets/a%2fb",
            "/assets/%00",
            "/assets/%ff",
            "/assets/%",
            "/assets/a\\b",
        ] {
            assert!(decoded_path(target).is_none(), "{target}");
        }
        assert_eq!(
            decoded_path("/assets/a%20b.js?q=x"),
            Some("/assets/a b.js".into())
        );
    }
}
