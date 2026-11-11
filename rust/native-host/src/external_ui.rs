//! Startup-pinned UI registry and request-owned blocking file work: the WebUI
//! `<config root>/ui/main/` at `/`, every other `ui/<name>/` at `/<name>/`.
use atomdns_upstream_core::TransportCancellation;
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::{io, path::Path, sync::Arc};
use tokio::{io::AsyncWrite, sync::Semaphore};
#[cfg(target_os = "linux")]
use tokio::{io::AsyncWriteExt, sync::mpsc};

/// What a directory under `<config root>/ui/` is, as startup judged it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum Kind {
    /// It carries a `ui-manifest.json`: a atomdns UI package, mounted only when compatible.
    AtomdnsUi,
    /// No manifest: any static pages the operator put there, served as before.
    Static,
    /// Not served: a reserved or invalid name, or not a plain directory.
    Unusable,
}

/// One directory under `ui/` and whether (and why not) it is served (`main` at
/// `/`, any other name at `/<name>/`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) name: String,
    pub(crate) mounted: bool,
    pub(crate) kind: Kind,
    pub(crate) info: Option<crate::ui_manifest::UiInfo>,
    /// Fixed text without file contents; also set for an unmanaged (manifest-less) directory.
    pub(crate) reason: Option<String>,
}

/// At most this many directories are listed (a bound on health size, far above real use).
#[cfg(target_os = "linux")]
const MAX_LISTED: usize = 64;
/// The note for a directory served without a manifest.
#[cfg(target_os = "linux")]
pub(crate) const NO_MANIFEST_NOTE: &str = "非 atomdns UI 包（无 manifest）";

#[derive(Default)]
pub(crate) struct Registry {
    #[cfg(all(test, target_os = "linux"))]
    io_gate: Option<Arc<IoGate>>,
    #[cfg(target_os = "linux")]
    mounts: BTreeMap<String, Arc<std::os::fd::OwnedFd>>,
    /// `ui/main`, served at `/`.
    #[cfg(target_os = "linux")]
    main: Option<Arc<std::os::fd::OwnedFd>>,
    entries: Vec<Entry>,
}

/// The name of the directory served at `/`.
pub(crate) const MAIN: &str = "main";

/// Whether `route` (decoded) belongs to the API whatever `ui/main` holds.
fn api_route(route: &str) -> bool {
    ["/api", "/plugins", "/metrics"]
        .iter()
        .any(|prefix| route == *prefix || route.starts_with(&format!("{prefix}/")))
}

impl Registry {
    pub(crate) fn scan(base: Option<&Path>) -> Self {
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{Dir, Mode, OFlags, ResolveFlags, open, openat2};
            let mut registry = Self::default();
            let Some(base) = base else {
                return registry;
            };
            let scan = || -> Result<_, rustix::io::Errno> {
                let base = open(
                    base,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )?;
                let ui = openat2(
                    &base,
                    "ui",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
                )?;
                Ok(ui)
            };
            let ui = match scan() {
                Ok(ui) => ui,
                Err(rustix::io::Errno::NOENT) => return registry,
                Err(error) => {
                    crate::diag::warn_line!("native UI registry unavailable: {error}");
                    return registry;
                }
            };
            let mut skipped = 0;
            let result = (|| -> Result<(), rustix::io::Errno> {
                let mut dir = Dir::read_from(&ui)?;
                for entry in &mut dir {
                    let entry = entry?;
                    let Ok(name) = entry.file_name().to_str() else {
                        skipped += 1;
                        continue;
                    };
                    if matches!(name, "." | "..") {
                        continue;
                    }
                    // Plain files (a README, `.DS_Store`) are not UI directories: ignored silently.
                    if entry.file_type() == rustix::fs::FileType::RegularFile {
                        continue;
                    }
                    let unusable = |reason: &str| Entry {
                        name: name.to_owned(),
                        mounted: false,
                        kind: Kind::Unusable,
                        info: None,
                        reason: Some(reason.to_owned()),
                    };
                    if name.is_empty()
                        || name.contains(['/', '\\'])
                        || name.chars().any(char::is_control)
                    {
                        skipped += 1;
                        registry
                            .entries
                            .push(unusable("名称无效（含斜杠或控制字符）"));
                        continue;
                    }
                    if matches!(
                        name,
                        "root"
                            | "log"
                            | "log1"
                            | "legacy"
                            | "blog"
                            | "assets"
                            | "debug"
                            | "metrics"
                            | "plugins"
                            | "api"
                            | "chunks"
                    ) {
                        skipped += 1;
                        registry.entries.push(unusable("保留名，不会挂载"));
                        continue;
                    }
                    match openat2(
                        &ui,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                        Mode::empty(),
                        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
                    ) {
                        Ok(fd) => {
                            let (mounted, kind, info, reason) = match inspect(&fd) {
                                Inspection::NoManifest => {
                                    (true, Kind::Static, None, Some(NO_MANIFEST_NOTE.to_owned()))
                                }
                                Inspection::Package(Ok(info)) => {
                                    (true, Kind::AtomdnsUi, Some(info), None)
                                }
                                Inspection::Package(Err(reason)) => {
                                    crate::diag::warn_line!(
                                        "external UI package `ui/{name}` is not mounted: {reason}"
                                    );
                                    (false, Kind::AtomdnsUi, None, Some(reason))
                                }
                            };
                            if mounted && name == MAIN {
                                registry.main = Some(Arc::new(fd));
                            } else if mounted {
                                registry.mounts.insert(name.to_owned(), Arc::new(fd));
                            }
                            registry.entries.push(Entry {
                                name: name.to_owned(),
                                mounted,
                                kind,
                                info,
                                reason,
                            });
                        }
                        Err(_) => {
                            skipped += 1;
                            registry
                                .entries
                                .push(unusable("不是可用的目录（符号链接或无法读取）"));
                        }
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                crate::diag::warn_line!("native UI registry enumeration failed: {error}");
                return Self::default();
            }
            if skipped > 0 {
                crate::diag::warn_line!(
                    "native UI registry skipped {skipped} reserved, invalid, symlink or non-directory entries"
                );
            }
            registry.entries.sort_by(|a, b| a.name.cmp(&b.name));
            if registry.entries.len() > MAX_LISTED {
                crate::diag::warn_line!(
                    "native UI registry lists only the first {MAX_LISTED} of {} directories in health",
                    registry.entries.len()
                );
                registry.entries.truncate(MAX_LISTED);
            }
            registry
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = base;
            Self::default()
        }
    }

    /// Serves `ui/<name>/` at `/<name>/` and `ui/main` at every other path
    /// that is not an API route (`GET`/`HEAD` only); `/` without a usable
    /// `ui/main` is the "not installed" page. Returns false when the request
    /// belongs to the ordinary API dispatcher.
    pub(crate) async fn serve<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        target: &str,
        method: &str,
        slots: Arc<Semaphore>,
        shutdown: &TransportCancellation,
    ) -> io::Result<bool> {
        #[cfg(not(target_os = "linux"))]
        let _ = &slots;
        let raw = target.split('?').next().unwrap_or(target);
        let decoded = crate::static_ui::decoded_path(target);
        let route = decoded.as_deref().unwrap_or(raw);
        #[cfg(target_os = "linux")]
        {
            let name = route
                .strip_prefix('/')
                .unwrap_or(route)
                .split('/')
                .next()
                .unwrap_or("");
            if let Some(root) = self.mounts.get(name) {
                if !matches!(method, "GET" | "HEAD") {
                    quick(header(writer, 405, 0, "Allow: GET, HEAD\r\n"), shutdown).await?;
                    return Ok(true);
                }
                let Some(path) = decoded.as_deref() else {
                    quick(header(writer, 404, 0, ""), shutdown).await?;
                    return Ok(true);
                };
                if path == format!("/{name}") {
                    quick(redirect(writer, &format!("/{name}/"), target), shutdown).await?;
                    return Ok(true);
                }
                let relative = path[name.len() + 2..].to_owned();
                self.serve_file(
                    writer, root, path, relative, target, method, slots, shutdown,
                )
                .await?;
                return Ok(true);
            }
        }
        // `ui/main` is the WebUI at `/` only: `/main` and below are never its files (a
        // `main` inside it included), whatever `ui/main` holds.
        let main_path = route == format!("/{MAIN}") || route.starts_with(&format!("/{MAIN}/"));
        if api_route(route) || main_path || !matches!(method, "GET" | "HEAD") {
            return Ok(false);
        }
        #[cfg(target_os = "linux")]
        if let Some(root) = &self.main {
            let Some(path) = decoded.as_deref() else {
                quick(header(writer, 404, 0, ""), shutdown).await?;
                return Ok(true);
            };
            let relative = path[1..].to_owned();
            self.serve_file(
                writer, root, path, relative, target, method, slots, shutdown,
            )
            .await?;
            return Ok(true);
        }
        if route != "/" {
            return Ok(false);
        }
        let refused = self
            .entries
            .iter()
            .find(|entry| entry.name == MAIN && !entry.mounted)
            .and_then(|entry| entry.reason.as_deref());
        crate::static_ui::write_not_installed(writer, method, refused, shutdown).await?;
        Ok(true)
    }

    /// One file (or a directory's `index.html`) of the pinned `root`.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    async fn serve_file<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        root: &Arc<std::os::fd::OwnedFd>,
        path: &str,
        relative: String,
        target: &str,
        method: &str,
        slots: Arc<Semaphore>,
        shutdown: &TransportCancellation,
    ) -> io::Result<()> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let Some(permit) = slots.try_acquire_owned().ok() else {
            return quick(header(writer, 503, 0, ""), shutdown).await;
        };
        let permit = Arc::new(permit);
        let root = root.clone();
        let index = path.ends_with('/');
        let head = method == "HEAD";
        let (sender, mut receiver) = mpsc::channel(1);
        let worker_permit = permit.clone();
        #[cfg(test)]
        let gate = self.io_gate.clone();
        let worker = tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            if let Some(gate) = gate {
                gate.wait();
            }
            let _permit = worker_permit;
            read_file(root, &relative, index, head, sender);
        });
        // Cancellation/timeouts close the channel first, then join the
        // started operation. No dropped await can orphan an FD/permit.
        let transfer = async {
            match receiver.recv().await {
                Some(Event::Status(status)) => header(writer, status, 0, "").await,
                Some(Event::Directory) => redirect(writer, &format!("{path}/"), target).await,
                Some(Event::Ready(length)) => {
                    let kind = crate::static_ui::mime(if index { "index.html" } else { path });
                    header(writer, 200, length, &format!("Content-Type: {kind}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n")).await?;
                    while let Some(event) = receiver.recv().await {
                        match event {
                            Event::Chunk(bytes) => writer.write_all(&bytes).await?,
                            Event::Error(error) => return Err(error),
                            _ => {
                                return Err(io::Error::other("external UI worker protocol"));
                            }
                        }
                    }
                    writer.flush().await
                }
                _ => Err(io::Error::other("external UI worker failed")),
            }
        };
        let result = tokio::select! {
            biased;
            () = shutdown.cancelled() => Ok(()),
            result = tokio::time::timeout_at(deadline, transfer) => result.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "external UI response deadline"))),
        };
        receiver.close();
        drop(receiver);
        let joined = worker.await.map_err(io::Error::other);
        drop(permit);
        joined?;
        result
    }
}

impl Registry {
    /// Every directory under `ui/` that startup judged (sorted by name, at most 64).
    pub(crate) fn entries(&self) -> &[Entry] {
        &self.entries
    }
}

/// What the pinned directory of one `ui/<name>` holds.
#[cfg(target_os = "linux")]
enum Inspection {
    /// No `ui-manifest.json`: generic static pages.
    NoManifest,
    /// A atomdns UI package: compatible (`Ok`) or the reason it is refused.
    Package(Result<crate::ui_manifest::UiInfo, String>),
}

/// Looks for `ui-manifest.json` (beneath the directory, no symlinks, a regular file of at most
/// 64 KiB) and, when there is one, judges it and checks that `index.html` is a regular file.
#[cfg(target_os = "linux")]
fn inspect(root: &std::os::fd::OwnedFd) -> Inspection {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
    use std::io::Read;
    let open = |name: &str| {
        openat2(
            root,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map(std::fs::File::from)
    };
    let manifest = match open("ui-manifest.json") {
        Ok(file) => file,
        Err(rustix::io::Errno::NOENT) => return Inspection::NoManifest,
        Err(_) => {
            return Inspection::Package(Err(
                "ui-manifest.json 无法打开（符号链接或无法读取）".to_owned()
            ));
        }
    };
    let judged = (|| {
        let metadata = manifest
            .metadata()
            .map_err(|_| "ui-manifest.json 无法读取".to_owned())?;
        if !metadata.is_file() {
            return Err("ui-manifest.json 不是普通文件".to_owned());
        }
        if metadata.len() > crate::ui_manifest::MAX_MANIFEST_BYTES {
            return Err("ui-manifest.json 过大".to_owned());
        }
        let mut bytes = Vec::new();
        manifest
            .take(crate::ui_manifest::MAX_MANIFEST_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|_| "ui-manifest.json 无法读取".to_owned())?;
        let info = crate::ui_manifest::evaluate(&bytes)?;
        let index_is_file = open("index.html")
            .ok()
            .and_then(|file| file.metadata().ok())
            .is_some_and(|metadata| metadata.is_file());
        if !index_is_file {
            return Err("缺少 index.html".to_owned());
        }
        Ok(info)
    })();
    Inspection::Package(judged)
}

#[cfg(target_os = "linux")]
async fn redirect<W: AsyncWrite + Unpin>(
    writer: &mut W,
    path: &str,
    target: &str,
) -> io::Result<()> {
    // Encode decoded filesystem segments back into a URL, preserving only path separators.
    let mut encoded = String::new();
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    match crate::static_ui::redirect_target(&encoded, target) {
        Some(location) => header(writer, 301, 0, &format!("Location: {location}\r\n")).await,
        None => header(writer, 404, 0, "").await,
    }
}
#[cfg(target_os = "linux")]
async fn header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: u16,
    length: u64,
    extra: &str,
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        301 => "Moved Permanently",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    writer.write_all(format!("HTTP/1.1 {status} {reason}\r\n{extra}Content-Length: {length}\r\nConnection: close\r\n\r\n").as_bytes()).await
}
#[cfg(target_os = "linux")]
enum Event {
    Status(u16),
    Directory,
    Ready(u64),
    Chunk(Vec<u8>),
    Error(io::Error),
}
#[cfg(target_os = "linux")]
fn read_file(
    root: Arc<std::os::fd::OwnedFd>,
    relative: &str,
    index: bool,
    head: bool,
    sender: mpsc::Sender<Event>,
) {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
    use std::io::Read;
    let open = |path: &str| {
        openat2(
            &*root,
            path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
    };
    let path = if relative.is_empty() { "." } else { relative };
    let opened = open(path).map(std::fs::File::from);
    let mut file = match opened {
        Ok(file) => file,
        Err(error) => {
            let _ = sender.blocking_send(Event::Status(open_status(error)));
            return;
        }
    };
    let mut metadata = match file.metadata() {
        Ok(meta) => meta,
        Err(_) => {
            let _ = sender.blocking_send(Event::Status(500));
            return;
        }
    };
    if metadata.is_dir() {
        if !index {
            let _ = sender.blocking_send(Event::Directory);
            return;
        }
        file = match open(&format!("{path}/index.html")).map(std::fs::File::from) {
            Ok(file) => file,
            Err(error) => {
                let _ = sender.blocking_send(Event::Status(open_status(error)));
                return;
            }
        };
        metadata = match file.metadata() {
            Ok(meta) => meta,
            Err(_) => {
                let _ = sender.blocking_send(Event::Status(500));
                return;
            }
        };
    }
    if !metadata.is_file() {
        let _ = sender.blocking_send(Event::Status(404));
        return;
    }
    if metadata.len() > 16 * 1024 * 1024 {
        let _ = sender.blocking_send(Event::Status(413));
        return;
    }
    if sender.blocking_send(Event::Ready(metadata.len())).is_err() || head {
        return;
    }
    let mut remaining = metadata.len();
    while remaining > 0 {
        let mut chunk = vec![0; usize::try_from(remaining.min(64 * 1024)).unwrap_or(64 * 1024)];
        if let Err(error) = file.read_exact(&mut chunk) {
            let _ = sender.blocking_send(Event::Error(error));
            return;
        }
        remaining -= chunk.len() as u64;
        if sender.blocking_send(Event::Chunk(chunk)).is_err() {
            return;
        }
    }
}
#[cfg(target_os = "linux")]
fn open_status(error: rustix::io::Errno) -> u16 {
    match error {
        rustix::io::Errno::NXIO
        | rustix::io::Errno::NODEV
        | rustix::io::Errno::NOENT
        | rustix::io::Errno::NOTDIR
        | rustix::io::Errno::LOOP
        | rustix::io::Errno::XDEV
        | rustix::io::Errno::AGAIN => 404,
        _ => 500,
    }
}

#[cfg(target_os = "linux")]
async fn quick<F: std::future::Future<Output = io::Result<()>>>(
    response: F,
    shutdown: &TransportCancellation,
) -> io::Result<()> {
    tokio::select! {
        biased;
        () = shutdown.cancelled() => Ok(()),
        result = tokio::time::timeout(std::time::Duration::from_secs(10), response) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "external UI response deadline"))?,
    }
}

#[cfg(all(test, target_os = "linux"))]
#[derive(Default)]
struct IoGate {
    open: std::sync::Mutex<bool>,
    changed: std::sync::Condvar,
    entered: std::sync::atomic::AtomicUsize,
}
#[cfg(all(test, target_os = "linux"))]
impl IoGate {
    fn wait(&self) {
        self.entered
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.changed.wait(open).unwrap();
        }
    }
    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    const GOOD: &str = r#"{"manifest_schema":1,"ui_version":"v9","built_at":"2026-10-17T00:00:00Z","api_level":2,"requires_api_level":2}"#;

    /// A configuration root whose `ui/` holds one directory per `(name, files)` entry.
    fn root_with(label: &str, packages: &[(&str, &[(&str, &str)])]) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("atomdns-ui-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("ui")).unwrap();
        for (name, files) in packages {
            std::fs::create_dir_all(root.join("ui").join(name)).unwrap();
            for (file, text) in *files {
                std::fs::write(root.join("ui").join(name).join(file), text).unwrap();
            }
        }
        root
    }

    fn entry<'a>(registry: &'a Registry, name: &str) -> &'a Entry {
        registry
            .entries()
            .iter()
            .find(|entry| entry.name == name)
            .unwrap_or_else(|| panic!("no entry for {name}: {:?}", registry.entries()))
    }

    #[test]
    fn any_directory_name_works_and_a_manifest_decides_whether_a_package_is_mounted() {
        const NEWER: &str =
            r#"{"manifest_schema":1,"ui_version":"v","api_level":3,"requires_api_level":3}"#;
        let root = root_with(
            "names",
            &[
                // Different names, same package.
                (
                    "pg",
                    &[("ui-manifest.json", GOOD), ("index.html", "<html>")],
                ),
                ("a", &[("ui-manifest.json", GOOD), ("index.html", "<html>")]),
                // Without a manifest: generic static pages, as before, and noted as such.
                ("plain", &[("index.html", "<html>")]),
                ("newer", &[("ui-manifest.json", NEWER), ("index.html", "x")]),
                ("garbage", &[("ui-manifest.json", "{"), ("index.html", "x")]),
                ("no-index", &[("ui-manifest.json", GOOD)]),
                // Reserved names are listed as refused, whatever they contain.
                ("log", &[("ui-manifest.json", GOOD), ("index.html", "x")]),
                ("api", &[("index.html", "x")]),
            ],
        );
        std::fs::write(
            root.join("ui/README.txt"),
            "a plain file is not a UI directory",
        )
        .unwrap();
        let registry = Registry::scan(Some(&root));
        for name in ["pg", "a"] {
            let found = entry(&registry, name);
            assert!(found.mounted && found.kind == Kind::AtomdnsUi && found.reason.is_none());
            assert_eq!(found.info.as_ref().unwrap().ui_version, "v9");
            assert_eq!(
                found.info.as_ref().unwrap().built_at.as_deref(),
                Some("2026-10-17T00:00:00Z")
            );
            assert!(registry.mounts.contains_key(name));
        }
        let plain = entry(&registry, "plain");
        assert!(plain.mounted && plain.kind == Kind::Static && plain.info.is_none());
        assert_eq!(plain.reason.as_deref(), Some(NO_MANIFEST_NOTE));
        assert!(registry.mounts.contains_key("plain"));
        for (name, reason) in [
            ("newer", "需要接口级别 3"),
            ("garbage", "不是合法的 JSON"),
            ("no-index", "缺少 index.html"),
        ] {
            let found = entry(&registry, name);
            assert!(!found.mounted && found.kind == Kind::AtomdnsUi, "{name}");
            assert!(
                found.reason.as_deref().unwrap().contains(reason),
                "{name}: {found:?}"
            );
            assert!(
                !registry.mounts.contains_key(name),
                "{name}: a refused package is not mounted"
            );
        }
        for name in ["log", "api"] {
            let found = entry(&registry, name);
            assert!(!found.mounted && found.kind == Kind::Unusable, "{name}");
            assert!(found.reason.as_deref().unwrap().contains("保留名"));
            assert!(!registry.mounts.contains_key(name));
        }
        assert!(
            registry
                .entries()
                .iter()
                .all(|entry| entry.name != "README.txt")
        );
        let names: Vec<_> = registry
            .entries()
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "listed by name");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_manifest_that_is_a_symlink_or_too_large_is_not_followed() {
        let root = root_with("symlink", &[("pg", &[("index.html", "x")])]);
        std::fs::write(root.join("real.json"), GOOD).unwrap();
        std::os::unix::fs::symlink(root.join("real.json"), root.join("ui/pg/ui-manifest.json"))
            .unwrap();
        let registry = Registry::scan(Some(&root));
        let found = entry(&registry, "pg");
        assert!(!found.mounted && found.reason.as_deref().unwrap().contains("符号链接"));
        std::fs::remove_file(root.join("ui/pg/ui-manifest.json")).unwrap();
        std::fs::write(root.join("ui/pg/ui-manifest.json"), vec![b' '; 70 * 1024]).unwrap();
        let registry = Registry::scan(Some(&root));
        assert!(
            entry(&registry, "pg")
                .reason
                .as_deref()
                .unwrap()
                .contains("过大")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn symlinked_or_missing_ui_directories_are_listed_or_empty() {
        let root = std::env::temp_dir().join(format!("atomdns-ui-links-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("ui/real")).unwrap();
        std::fs::write(root.join("ui/real/index.html"), "x").unwrap();
        std::os::unix::fs::symlink(root.join("ui/real"), root.join("ui/link")).unwrap();
        let registry = Registry::scan(Some(&root));
        assert!(registry.mounts.contains_key("real") && !registry.mounts.contains_key("link"));
        let link = entry(&registry, "link");
        assert!(!link.mounted && link.kind == Kind::Unusable);
        // No ui directory at all, or no configuration root: nothing to list.
        assert!(
            Registry::scan(Some(&root.join("elsewhere")))
                .entries()
                .is_empty()
        );
        assert!(Registry::scan(None).entries().is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn blocking_owner_retains_permits_and_shutdown_joins_started_io() {
        let root = std::env::temp_dir().join(format!("atomdns-ui-owned-{}", std::process::id()));
        std::fs::create_dir_all(root.join("ui/demo")).unwrap();
        std::fs::write(root.join("ui/demo/index.html"), "proof").unwrap();
        let gate = Arc::new(IoGate::default());
        let mut registry = Registry::scan(Some(&root));
        registry.io_gate = Some(gate.clone());
        let registry = Arc::new(registry);
        crate::HostRuntime::new().unwrap().block_on(async {
            let slots = Arc::new(Semaphore::new(4));
            let shutdown = TransportCancellation::new();
            let mut tasks = Vec::new();
            let mut readers = Vec::new();
            for _ in 0..4 {
                let (mut writer, reader) = tokio::io::duplex(1024);
                readers.push(reader);
                let registry = registry.clone();
                let slots = slots.clone();
                let shutdown = shutdown.clone();
                tasks.push(tokio::task::spawn_local(async move {
                    registry
                        .serve(&mut writer, "/demo/", "HEAD", slots, &shutdown)
                        .await
                }));
            }
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while gate.entered.load(std::sync::atomic::Ordering::SeqCst) < 4 {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            })
            .await
            .unwrap();
            // The LocalSet keeps running while all filesystem owners stall.
            assert_eq!(slots.available_permits(), 0);
            let (mut writer, mut reader) = tokio::io::duplex(1024);
            registry
                .serve(&mut writer, "/demo/", "HEAD", slots.clone(), &shutdown)
                .await
                .unwrap();
            drop(writer);
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await.unwrap();
            assert!(bytes.starts_with(b"HTTP/1.1 503"));
            shutdown.cancel();
            tokio::task::yield_now().await;
            assert!(tasks.iter().all(|task| !task.is_finished()));
            assert_eq!(slots.available_permits(), 0);
            gate.release();
            for task in tasks {
                assert!(task.await.unwrap().unwrap());
            }
            assert_eq!(slots.available_permits(), 4);
            drop(readers);
        });
        std::fs::remove_dir_all(root).unwrap();
    }

    /// One request against `registry`: `None` when it belongs to the API dispatcher.
    fn request(registry: &Registry, method: &str, target: &str) -> Option<String> {
        crate::HostRuntime::new().unwrap().block_on(async {
            let (mut writer, mut reader) = tokio::io::duplex(1 << 20);
            let served = registry
                .serve(
                    &mut writer,
                    target,
                    method,
                    Arc::new(Semaphore::new(4)),
                    &TransportCancellation::new(),
                )
                .await
                .unwrap();
            drop(writer);
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await.unwrap();
            served.then(|| String::from_utf8_lossy(&bytes).into_owned())
        })
    }

    fn status(response: &Option<String>) -> &str {
        response
            .as_deref()
            .and_then(|text| text.split(' ').nth(1))
            .unwrap_or("api")
    }

    #[test]
    fn ui_main_is_served_at_the_root_and_never_shadows_the_api() {
        let root = root_with(
            "main",
            &[
                (
                    "main",
                    &[
                        ("ui-manifest.json", GOOD),
                        ("index.html", "MAIN-INDEX"),
                        ("app.js", "APP"),
                        ("metrics", "x"),
                    ],
                ),
                (
                    "aa",
                    &[("ui-manifest.json", GOOD), ("index.html", "AA-INDEX")],
                ),
                ("chunks", &[("index.html", "x")]),
            ],
        );
        for dir in ["main/chunks", "main/api/v1", "main/plugins"] {
            std::fs::create_dir_all(root.join("ui").join(dir)).unwrap();
        }
        std::fs::write(root.join("ui/main/chunks/c.js"), "CHUNK").unwrap();
        // A `main` inside the WebUI is still not served at `/main/`.
        std::fs::create_dir_all(root.join("ui/main/main")).unwrap();
        std::fs::write(root.join("ui/main/main/index.html"), "NESTED").unwrap();
        std::fs::write(root.join("ui/main/api/v1/capabilities"), "FAKE").unwrap();
        std::fs::write(root.join("secret.txt"), "SECRET").unwrap();
        std::os::unix::fs::symlink(root.join("secret.txt"), root.join("ui/main/link.txt")).unwrap();
        let registry = Registry::scan(Some(&root));
        let main = entry(&registry, "main");
        assert!(main.mounted && main.kind == Kind::AtomdnsUi);
        assert!(registry.main.is_some() && !registry.mounts.contains_key("main"));
        let chunks = entry(&registry, "chunks");
        assert!(!chunks.mounted && chunks.reason.as_deref().unwrap().contains("保留名"));

        let index = request(&registry, "GET", "/");
        assert_eq!(status(&index), "200");
        assert!(index.as_deref().unwrap().ends_with("MAIN-INDEX"));
        assert!(index.as_deref().unwrap().contains("text/html"));
        assert!(
            request(&registry, "GET", "/index.html")
                .unwrap()
                .ends_with("MAIN-INDEX")
        );
        assert!(
            request(&registry, "GET", "/app.js?v=1")
                .unwrap()
                .ends_with("APP")
        );
        assert!(
            request(&registry, "GET", "/chunks/c.js")
                .unwrap()
                .ends_with("CHUNK")
        );
        let head = request(&registry, "HEAD", "/").unwrap();
        assert!(head.starts_with("HTTP/1.1 200") && head.ends_with("\r\n\r\n"));
        assert!(
            request(&registry, "GET", "/aa/")
                .unwrap()
                .ends_with("AA-INDEX")
        );
        assert_eq!(status(&request(&registry, "GET", "/chunks")), "301");
        // Only `/`: `/main` is not a second address of the same UI, even when the UI holds
        // a `main` of its own (the dispatcher answers, with its 404).
        for target in ["/main/", "/main", "/main/index.html", "/%6dain/"] {
            assert_eq!(request(&registry, "GET", target), None, "{target}");
        }
        let encoded = request(&registry, "GET", "/main%2findex.html");
        assert_eq!(status(&encoded), "404");
        assert!(!encoded.unwrap().contains("NESTED"));
        // API routes are never answered from `ui/main`, whatever it holds.
        for target in [
            "/api/v1/capabilities",
            "/api",
            "/plugins/x/show",
            "/plugins",
            "/metrics",
        ] {
            assert_eq!(request(&registry, "GET", target), None, "{target}");
        }
        // Other methods go to the dispatcher (an unknown path stays its 404).
        assert_eq!(request(&registry, "POST", "/"), None);
        assert_eq!(request(&registry, "DELETE", "/app.js"), None);
        for target in [
            "/%2e%2e/secret.txt",
            "/chunks%2fc.js",
            "/a\\b",
            "/%00",
            "/link.txt",
            "/missing.js",
        ] {
            let response = request(&registry, "GET", target);
            assert_eq!(status(&response), "404", "{target}");
            assert!(!response.unwrap().contains("SECRET"), "{target}");
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn without_a_usable_ui_main_the_root_explains_and_everything_else_is_unchanged() {
        const NEWER: &str =
            r#"{"manifest_schema":1,"ui_version":"v","api_level":3,"requires_api_level":3}"#;
        let missing = root_with("no-main", &[("aa", &[("index.html", "AA")])]);
        let refused = root_with(
            "refused-main",
            &[("main", &[("ui-manifest.json", NEWER), ("index.html", "x")])],
        );
        let linked = root_with("linked-main", &[("real", &[("index.html", "REAL")])]);
        std::os::unix::fs::symlink(linked.join("ui/real"), linked.join("ui/main")).unwrap();
        for (root, reason) in [
            (&missing, None),
            (&refused, Some("需要接口级别 3")),
            (&linked, Some("符号链接")),
        ] {
            let registry = Registry::scan(Some(root));
            assert!(registry.main.is_none());
            let page = request(&registry, "GET", "/").unwrap();
            assert!(
                page.starts_with("HTTP/1.1 404") && page.contains("没有安装 WebUI"),
                "{page}"
            );
            if let Some(reason) = reason {
                assert!(page.contains(reason), "{page}");
            }
            assert_eq!(status(&request(&registry, "HEAD", "/")), "404");
            // Any other path is the dispatcher's, as is the API.
            assert_eq!(request(&registry, "GET", "/app.js"), None);
            assert_eq!(request(&registry, "GET", "/api/v1/system/health"), None);
        }
        assert!(
            request(&Registry::scan(Some(&missing)), "GET", "/aa/")
                .unwrap()
                .ends_with("AA")
        );
        for root in [missing, refused, linked] {
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}
