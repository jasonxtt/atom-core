//! atom fork: the panel login (atom `docs/design.md` §8, "面板登录").
//!
//! The credentials are `webinfo/atom_auth.json` (mode 0600): the user name,
//! a PBKDF2-HMAC-SHA256 hash of the password with its salt, and a random
//! key. Without the file the panel has no login, as before. With it, every
//! request except the UI files, the health document and the routes below
//! needs either
//!
//! - the session cookie `atom_session=<expiry>.<HMAC(key, expiry)>` that a
//!   login sets (30 days; changing the credentials draws a new key, which
//!   ends every session), or
//! - `Authorization: Bearer <key>`: the installer reads the key from the
//!   file (it runs as root) to call the API after a reinstall or upgrade.
//!
//! | path | methods |
//! |---|---|
//! | `auth` | GET `{enabled, authenticated, username}`, PUT `{username, password, current_password?}` (set or change), DELETE `{current_password?}` (turn the login off) |
//! | `auth/login` | POST `{username, password}` |
//! | `auth/logout` | POST |
//!
//! `current_password` is needed when a login is on and the request carries
//! a session cookie rather than the key.
//!
//! Changes (PUT, DELETE) run one at a time: the caller is judged again once
//! the lock is held, so a change that was overtaken by another one (which
//! draws a new key) answers 409 instead of going through on stale
//! credentials. At most [`MAX_HASHES`] password hashes run at once; more
//! requests answer 429.

use std::cell::RefCell;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex, Semaphore, SemaphorePermit};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::rand::SecureRandom as _;
use ring::{digest, hmac, pbkdf2};
use serde::{Deserialize, Serialize};

use crate::atom_rules_api::{error, json};
use crate::rule_sources::Reply;

pub(crate) const AUTH_FILE: &str = "atom_auth.json";
pub(crate) const PATH: &str = "/api/v1/atom/auth";
const COOKIE: &str = "atom_session";
const SESSION_SECONDS: u64 = 30 * 24 * 3600;
const ITERATIONS: u32 = 100_000;
const FAILURE_DELAY: Duration = Duration::from_secs(1);
/// Password hashes that may run at the same time (each takes a blocking thread).
const MAX_HASHES: usize = 2;
const MAX_USERNAME_CHARS: usize = 64;
const MAX_PASSWORD_BYTES: usize = 256;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    username: String,
    salt: String,
    hash: String,
    key: String,
}

/// The login state of one management listener.
pub(crate) struct PanelAuth {
    /// `None` without a configuration root (tests, embedders): no login.
    path: Option<PathBuf>,
    stored: RefCell<Option<Stored>>,
    /// Held for the whole of a PUT or DELETE.
    write_lock: Mutex<()>,
    hashing: Semaphore,
}

/// How a request proved itself.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Caller {
    /// No login is configured.
    Open,
    Key,
    Session,
    None,
}

impl PanelAuth {
    pub(crate) fn load(state_root: Option<&Path>) -> Result<Self, String> {
        let path = state_root.map(|root| root.join("webinfo").join(AUTH_FILE));
        let stored = match &path {
            None => None,
            Some(path) => match std::fs::read(path) {
                Ok(bytes) => Some(
                    serde_json::from_slice::<Stored>(&bytes)
                        .map_err(|e| format!("{}: {e}", path.display()))?,
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(format!("{}: {e}", path.display())),
            },
        };
        Ok(Self {
            path,
            stored: RefCell::new(stored),
            write_lock: Mutex::new(()),
            hashing: Semaphore::new(MAX_HASHES),
        })
    }

    /// Whether a request outside [`PATH`] may proceed.
    pub(crate) fn authorized(&self, cookie: Option<&str>, authorization: Option<&str>) -> bool {
        self.caller(cookie, authorization) != Caller::None
    }

    fn caller(&self, cookie: Option<&str>, authorization: Option<&str>) -> Caller {
        let stored = self.stored.borrow();
        let Some(stored) = stored.as_ref() else {
            return Caller::Open;
        };
        if let Some(given) = authorization.and_then(|value| value.strip_prefix("Bearer ")) {
            let want = digest::digest(&digest::SHA256, stored.key.as_bytes());
            let got = digest::digest(&digest::SHA256, given.trim().as_bytes());
            if digests_equal(want.as_ref(), got.as_ref()) {
                return Caller::Key;
            }
        }
        let session = cookie.and_then(|header| {
            header
                .split(';')
                .filter_map(|pair| pair.trim().split_once('='))
                .find(|(name, _)| *name == COOKIE)
                .map(|(_, value)| value)
        });
        if session.is_some_and(|value| session_valid(stored, value, now())) {
            Caller::Session
        } else {
            Caller::None
        }
    }

    /// Answers the routes under [`PATH`]; `None` for any other path.
    pub(crate) async fn handle(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        cookie: Option<&str>,
        authorization: Option<&str>,
    ) -> Option<Reply> {
        let rest = path.strip_prefix(PATH)?;
        let rest = rest.trim_end_matches('/');
        let caller = self.caller(cookie, authorization);
        Some(match (rest, method) {
            ("", "GET") => self.status(caller),
            ("", "PUT") => self.set(cookie, authorization, body).await,
            ("", "DELETE") => self.remove(cookie, authorization, body).await,
            ("/login", "POST") => self.login(body).await,
            ("/logout", "POST") => with_cookie(
                json(200, &serde_json::json!({ "ok": true })),
                format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"),
            ),
            ("" | "/login" | "/logout", _) => error(405, "method not allowed"),
            _ => error(404, "not found"),
        })
    }

    fn status(&self, caller: Caller) -> Reply {
        let stored = self.stored.borrow();
        let signed_in = matches!(caller, Caller::Key | Caller::Session);
        json(
            200,
            &serde_json::json!({
                "enabled": stored.is_some(),
                "authenticated": caller != Caller::None,
                "username": stored.as_ref().filter(|_| signed_in).map(|s| s.username.clone()),
            }),
        )
    }

    async fn login(&self, body: &[u8]) -> Reply {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Login {
            username: String,
            password: String,
        }
        let input: Login = match crate::atom_rules_api::body(body) {
            Ok(input) => input,
            Err(reply) => return reply,
        };
        if input.username.chars().count() > MAX_USERNAME_CHARS
            || input.password.len() > MAX_PASSWORD_BYTES
        {
            return error(400, "用户名或密码太长");
        }
        let Some(stored) = self.stored.borrow().clone() else {
            return error(409, "未开启登录");
        };
        let user_ok = input.username == stored.username;
        let password_ok = {
            let permit = match self.hash_permit() {
                Ok(permit) => permit,
                Err(reply) => return reply,
            };
            let ok = verify(&stored, input.password).await;
            drop(permit);
            ok
        };
        if !(user_ok && password_ok) {
            tokio::time::sleep(FAILURE_DELAY).await;
            return error(401, "用户名或密码错误");
        }
        // The credentials may have changed while the hash was checked.
        let current = self.stored.borrow().clone();
        match current {
            Some(current) if current.key == stored.key => {
                with_cookie(self.status(Caller::Session), session_cookie(&current))
            }
            _ => error(409, "登录信息刚被修改，请重试"),
        }
    }

    fn hash_permit(&self) -> Result<SemaphorePermit<'_>, Reply> {
        self.hashing
            .try_acquire()
            .map_err(|_| error(429, "同时验证的密码太多，请稍后再试"))
    }

    /// Takes the write lock and judges the caller again: credentials changed
    /// meanwhile (by the change that held the lock) turn a request that was
    /// fine before into a 409.
    async fn lock_for_change(
        &self,
        before: Caller,
        cookie: Option<&str>,
        authorization: Option<&str>,
    ) -> Result<(tokio::sync::MutexGuard<'_, ()>, Caller), Reply> {
        let guard = self.write_lock.lock().await;
        let now = self.caller(cookie, authorization);
        if now == Caller::None && before != Caller::None {
            return Err(error(409, "登录信息刚被修改，请重新登录后再试"));
        }
        Ok((guard, now))
    }

    /// The `current_password` check of a change made with a session.
    async fn confirm(&self, caller: Caller, current: Option<String>) -> Result<(), Reply> {
        match caller {
            Caller::Open | Caller::Key => Ok(()),
            Caller::None => Err(error(401, "未登录")),
            Caller::Session => {
                let Some(stored) = self.stored.borrow().clone() else {
                    return Ok(());
                };
                let Some(current) = current else {
                    return Err(error(400, "需要当前密码"));
                };
                if current.len() > MAX_PASSWORD_BYTES {
                    return Err(error(400, "当前密码太长"));
                }
                let permit = self.hash_permit()?;
                let ok = verify(&stored, current).await;
                drop(permit);
                if ok {
                    Ok(())
                } else {
                    tokio::time::sleep(FAILURE_DELAY).await;
                    Err(error(403, "当前密码不对"))
                }
            }
        }
    }

    async fn set(&self, cookie: Option<&str>, authorization: Option<&str>, body: &[u8]) -> Reply {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Set {
            username: String,
            password: String,
            #[serde(default)]
            current_password: Option<String>,
        }
        let before = self.caller(cookie, authorization);
        if before == Caller::None {
            return error(401, "未登录");
        }
        let input: Set = match crate::atom_rules_api::body(body) {
            Ok(input) => input,
            Err(reply) => return reply,
        };
        let username = input.username.trim().to_owned();
        if username.is_empty() || username.chars().count() > MAX_USERNAME_CHARS {
            return error(400, "用户名不能为空，最长 64 个字符");
        }
        if username.chars().any(char::is_control) {
            return error(400, "用户名不能含控制字符");
        }
        if input.password.is_empty() || input.password.len() > MAX_PASSWORD_BYTES {
            return error(400, "密码不能为空，最长 256 字节");
        }
        let (_write, caller) = match self.lock_for_change(before, cookie, authorization).await {
            Ok(held) => held,
            Err(reply) => return reply,
        };
        if let Err(reply) = self.confirm(caller, input.current_password).await {
            return reply;
        }
        let Some(path) = self.path.clone() else {
            return error(409, "没有配置目录，不能设置登录");
        };
        let permit = match self.hash_permit() {
            Ok(permit) => permit,
            Err(reply) => return reply,
        };
        let stored = match tokio::task::spawn_blocking(move || {
            new_stored(username, &input.password)
        })
        .await
        {
            Ok(Ok(stored)) => stored,
            Ok(Err(message)) => return error(500, message),
            Err(e) => return error(500, e),
        };
        drop(permit);
        if let Err(e) = save(&path, &stored) {
            return error(500, format!("{}: {e}", path.display()));
        }
        let cookie = session_cookie(&stored);
        *self.stored.borrow_mut() = Some(stored);
        with_cookie(self.status(Caller::Session), cookie)
    }

    async fn remove(
        &self,
        cookie: Option<&str>,
        authorization: Option<&str>,
        body: &[u8],
    ) -> Reply {
        #[derive(Default, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Remove {
            #[serde(default)]
            current_password: Option<String>,
        }
        let before = self.caller(cookie, authorization);
        if before == Caller::None {
            return error(401, "未登录");
        }
        let input: Remove = if body.iter().all(u8::is_ascii_whitespace) {
            Remove::default()
        } else {
            match crate::atom_rules_api::body(body) {
                Ok(input) => input,
                Err(reply) => return reply,
            }
        };
        let (_write, caller) = match self.lock_for_change(before, cookie, authorization).await {
            Ok(held) => held,
            Err(reply) => return reply,
        };
        if let Err(reply) = self.confirm(caller, input.current_password).await {
            return reply;
        }
        if let Some(path) = &self.path {
            match std::fs::remove_file(path) {
                // gone: the memory follows even when the directory cannot be synced
                Ok(()) => {
                    if let Err(e) = sync_directory(path.parent().unwrap_or_else(|| Path::new(".")))
                    {
                        eprintln!(
                            "atomdns: {}: cannot sync the directory: {e}",
                            path.display()
                        );
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return error(500, format!("{}: {e}", path.display())),
            }
        }
        *self.stored.borrow_mut() = None;
        with_cookie(
            self.status(Caller::Open),
            format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"),
        )
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Constant-time comparison of two digests: `hmac::verify` compares in constant time, so one digest keys the
/// check and the other keys the tag that is checked (`ring::constant_time` is deprecated for outside use).
fn digests_equal(want: &[u8], got: &[u8]) -> bool {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, got), b"atom-bearer");
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, want),
        b"atom-bearer",
        tag.as_ref(),
    )
    .is_ok()
}

fn session_key(stored: &Stored) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, stored.key.as_bytes())
}

fn session_value(stored: &Stored, expiry: u64) -> String {
    let tag = hmac::sign(
        &session_key(stored),
        format!("atom-session:{expiry}").as_bytes(),
    );
    format!("{expiry}.{}", B64.encode(tag.as_ref()))
}

fn session_valid(stored: &Stored, value: &str, now: u64) -> bool {
    let Some((expiry, tag)) = value.split_once('.') else {
        return false;
    };
    let (Ok(expiry), Ok(tag)) = (expiry.parse::<u64>(), B64.decode(tag)) else {
        return false;
    };
    expiry > now
        && hmac::verify(
            &session_key(stored),
            format!("atom-session:{expiry}").as_bytes(),
            &tag,
        )
        .is_ok()
}

fn session_cookie(stored: &Stored) -> String {
    let value = session_value(stored, now() + SESSION_SECONDS);
    format!("{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}")
}

fn with_cookie(mut reply: Reply, cookie: String) -> Reply {
    reply.headers.push(("Set-Cookie", cookie));
    reply
}

fn iterations() -> NonZeroU32 {
    NonZeroU32::new(ITERATIONS).expect("nonzero")
}

/// Checks a password off the DNS thread (the hash takes a while on a small
/// machine).
async fn verify(stored: &Stored, password: String) -> bool {
    let (Ok(salt), Ok(hash)) = (B64.decode(&stored.salt), B64.decode(&stored.hash)) else {
        return false;
    };
    tokio::task::spawn_blocking(move || {
        pbkdf2::verify(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations(),
            &salt,
            password.as_bytes(),
            &hash,
        )
        .is_ok()
    })
    .await
    .unwrap_or(false)
}

fn new_stored(username: String, password: &str) -> Result<Stored, String> {
    let random = ring::rand::SystemRandom::new();
    let mut salt = [0_u8; 16];
    let mut key = [0_u8; 32];
    random
        .fill(&mut salt)
        .and_then(|()| random.fill(&mut key))
        .map_err(|_| "no random bytes".to_owned())?;
    let mut hash = [0_u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations(),
        &salt,
        password.as_bytes(),
        &mut hash,
    );
    Ok(Stored {
        username,
        salt: B64.encode(salt),
        hash: B64.encode(hash),
        key: B64.encode(key),
    })
}

/// Replaces the file through a 0600 temporary file (new, with a random name:
/// an existing file or symlink of that name is never opened) and a rename,
/// then syncs the directory so that the rename survives a crash.
fn save(path: &Path, stored: &Stored) -> std::io::Result<()> {
    use std::io::Write as _;
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(directory)?;
    let mut bytes = serde_json::to_vec_pretty(stored).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    let (mut file, temporary) = create_temporary(directory)?;
    let outcome = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)
    })();
    if outcome.is_err() {
        let _ = std::fs::remove_file(&temporary);
        return outcome;
    }
    // The rename is done: the new credentials are the file. A failed directory sync only means the rename
    // may not survive a crash; the in-memory state must follow the file, so it is not an error here.
    if let Err(e) = sync_directory(directory) {
        eprintln!(
            "atomdns: {}: cannot sync the directory: {e}",
            path.display()
        );
    }
    Ok(())
}

fn create_temporary(directory: &Path) -> std::io::Result<(std::fs::File, PathBuf)> {
    let random = ring::rand::SystemRandom::new();
    for _ in 0..8 {
        let mut bytes = [0_u8; 9];
        random
            .fill(&mut bytes)
            .map_err(|_| std::io::Error::other("no random bytes"))?;
        let temporary = directory.join(format!(".{AUTH_FILE}.tmp-{}", B64.encode(bytes)));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        match options.open(&temporary) {
            Ok(file) => return Ok((file, temporary)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("no unused temporary file name"))
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> std::io::Result<()> {
    std::fs::File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("atom-auth-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("webinfo")).unwrap();
        dir
    }

    fn run<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(future)
    }

    fn body(reply: &Reply) -> serde_json::Value {
        serde_json::from_slice(&reply.body).unwrap()
    }

    fn cookie_of(reply: &Reply) -> String {
        let header = &reply
            .headers
            .iter()
            .find(|(name, _)| *name == "Set-Cookie")
            .unwrap()
            .1;
        header.split(';').next().unwrap().to_owned()
    }

    #[test]
    fn without_a_file_everything_is_open() {
        let root = scratch("open");
        let auth = PanelAuth::load(Some(&root)).unwrap();
        assert!(auth.authorized(None, None));
        let reply = run(auth.handle("GET", PATH, b"", None, None)).unwrap();
        assert_eq!(body(&reply)["enabled"], false);
        assert_eq!(body(&reply)["authenticated"], true);
        assert!(run(auth.handle("GET", "/api/v1/atom/rules", b"", None, None)).is_none());
    }

    #[test]
    fn set_login_change_and_remove() {
        let root = scratch("cycle");
        let auth = PanelAuth::load(Some(&root)).unwrap();
        let reply = run(auth.handle(
            "PUT",
            PATH,
            br#"{"username":" admin ","password":"pw1"}"#,
            None,
            None,
        ))
        .unwrap();
        assert_eq!(reply.status, 200, "{:?}", body(&reply));
        let first = cookie_of(&reply);
        assert!(!auth.authorized(None, None));
        assert!(auth.authorized(Some(&first), None));
        let file = root.join("webinfo").join(AUTH_FILE);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // Loading again keeps the login and the sessions.
        let auth = PanelAuth::load(Some(&root)).unwrap();
        assert!(auth.authorized(Some(&format!("a=b; {first}")), None));
        let stored: Stored = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        assert_eq!(stored.username, "admin");
        assert!(auth.authorized(None, Some(&format!("Bearer {}", stored.key))));
        assert!(!auth.authorized(None, Some("Bearer nope")));

        let reply = run(auth.handle("GET", PATH, b"", None, None)).unwrap();
        assert_eq!(
            body(&reply),
            serde_json::json!({"enabled": true, "authenticated": false, "username": null})
        );
        let bad = run(auth.handle(
            "POST",
            "/api/v1/atom/auth/login",
            br#"{"username":"admin","password":"x"}"#,
            None,
            None,
        ))
        .unwrap();
        assert_eq!(bad.status, 401);
        let good = run(auth.handle(
            "POST",
            "/api/v1/atom/auth/login",
            br#"{"username":"admin","password":"pw1"}"#,
            None,
            None,
        ))
        .unwrap();
        assert_eq!(good.status, 200);
        let session = cookie_of(&good);
        assert!(auth.authorized(Some(&session), None));
        assert_eq!(
            body(&run(auth.handle("GET", PATH, b"", Some(&session), None)).unwrap())["username"],
            "admin"
        );

        // A change with a session needs the current password; it ends the old sessions.
        let unauth = run(auth.handle(
            "PUT",
            PATH,
            br#"{"username":"a","password":"b"}"#,
            None,
            None,
        ))
        .unwrap();
        assert_eq!(unauth.status, 401);
        let missing = run(auth.handle(
            "PUT",
            PATH,
            br#"{"username":"a","password":"b"}"#,
            Some(&session),
            None,
        ))
        .unwrap();
        assert_eq!(missing.status, 400);
        let wrong = run(auth.handle(
            "PUT",
            PATH,
            br#"{"username":"a","password":"b","current_password":"x"}"#,
            Some(&session),
            None,
        ))
        .unwrap();
        assert_eq!(wrong.status, 403);
        let changed = run(auth.handle(
            "PUT",
            PATH,
            br#"{"username":"a","password":"b","current_password":"pw1"}"#,
            Some(&session),
            None,
        ))
        .unwrap();
        assert_eq!(changed.status, 200);
        assert!(!auth.authorized(Some(&session), None));
        let renewed = cookie_of(&changed);
        assert!(auth.authorized(Some(&renewed), None));

        let off = run(auth.handle(
            "DELETE",
            PATH,
            br#"{"current_password":"b"}"#,
            Some(&renewed),
            None,
        ))
        .unwrap();
        assert_eq!(off.status, 200);
        assert!(!file.exists());
        assert!(auth.authorized(None, None));
    }

    #[test]
    fn sessions_expire_and_refuse_forgeries() {
        let stored = new_stored("u".into(), "p").unwrap();
        let value = session_value(&stored, 100);
        assert!(session_valid(&stored, &value, 99));
        assert!(!session_valid(&stored, &value, 100));
        let forged = value.replacen("100", "200", 1);
        assert!(!session_valid(&stored, &forged, 99));
        assert!(!session_valid(&stored, "garbage", 0));
    }

    #[test]
    fn invalid_input_is_refused() {
        let root = scratch("invalid");
        let auth = PanelAuth::load(Some(&root)).unwrap();
        for input in [
            &br#"{"username":"","password":"p"}"#[..],
            br#"{"username":"u","password":""}"#,
            br#"{"username":"u","password":"p","x":1}"#,
        ] {
            assert_eq!(
                run(auth.handle("PUT", PATH, input, None, None))
                    .unwrap()
                    .status,
                400
            );
        }
        assert_eq!(
            run(auth.handle("PATCH", PATH, b"", None, None))
                .unwrap()
                .status,
            405
        );
        assert_eq!(
            run(auth.handle("GET", "/api/v1/atom/auth/x", b"", None, None))
                .unwrap()
                .status,
            404
        );
        std::fs::write(root.join("webinfo").join(AUTH_FILE), b"{").unwrap();
        assert!(PanelAuth::load(Some(&root)).is_err());
    }

    #[test]
    fn concurrent_changes_run_one_at_a_time() {
        let root = scratch("race");
        let auth = PanelAuth::load(Some(&root)).unwrap();
        let first = run(auth.handle(
            "PUT",
            PATH,
            br#"{"username":"u","password":"p1"}"#,
            None,
            None,
        ))
        .unwrap();
        let session = cookie_of(&first);
        let change = |password: &'static str| {
            let body =
                format!(r#"{{"username":"u","password":"{password}","current_password":"p1"}}"#);
            let auth = &auth;
            let session = session.clone();
            async move {
                auth.handle("PUT", PATH, body.as_bytes(), Some(&session), None)
                    .await
                    .unwrap()
                    .status
            }
        };
        let (a, b) = run(async { tokio::join!(change("p2"), change("p3")) });
        let mut both = [a, b];
        both.sort_unstable();
        // the one that came second holds a session the first change ended
        assert_eq!(both, [200, 409]);
        // and the file holds exactly one change, without leftovers
        let names: Vec<_> = std::fs::read_dir(root.join("webinfo"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, [AUTH_FILE]);
    }

    #[test]
    fn hashing_is_limited_and_inputs_are_bounded() {
        let root = scratch("limits");
        let auth = PanelAuth::load(Some(&root)).unwrap();
        let reply = run(auth.handle(
            "PUT",
            PATH,
            br#"{"username":"u","password":"p"}"#,
            None,
            None,
        ))
        .unwrap();
        let session = cookie_of(&reply);
        let busy = auth.hashing.try_acquire_many(MAX_HASHES as u32).unwrap();
        for (method, path, body) in [
            (
                "POST",
                "/api/v1/atom/auth/login",
                &br#"{"username":"u","password":"p"}"#[..],
            ),
            (
                "PUT",
                PATH,
                br#"{"username":"u","password":"q","current_password":"p"}"#,
            ),
        ] {
            let reply = run(auth.handle(method, path, body, Some(&session), None)).unwrap();
            assert_eq!(reply.status, 429, "{method} {path}");
        }
        drop(busy);
        let long = "x".repeat(MAX_PASSWORD_BYTES + 1);
        let login = format!(r#"{{"username":"u","password":"{long}"}}"#);
        let change = format!(r#"{{"username":"u","password":"q","current_password":"{long}"}}"#);
        assert_eq!(
            run(auth.handle(
                "POST",
                "/api/v1/atom/auth/login",
                login.as_bytes(),
                None,
                None
            ))
            .unwrap()
            .status,
            400
        );
        assert_eq!(
            run(auth.handle("PUT", PATH, change.as_bytes(), Some(&session), None))
                .unwrap()
                .status,
            400
        );
    }

    #[test]
    fn digests_compare_exactly() {
        let a = digest::digest(&digest::SHA256, b"a");
        let b = digest::digest(&digest::SHA256, b"b");
        assert!(digests_equal(a.as_ref(), a.as_ref()));
        assert!(!digests_equal(a.as_ref(), b.as_ref()));
        assert!(!digests_equal(a.as_ref(), &a.as_ref()[1..]));
    }

    #[cfg(unix)]
    #[test]
    fn the_temporary_file_is_new_and_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = scratch("temporary");
        let directory = root.join("webinfo");
        let (first, name1) = create_temporary(&directory).unwrap();
        let (_second, name2) = create_temporary(&directory).unwrap();
        assert_ne!(name1, name2);
        assert_eq!(
            first.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        // a name that is already taken (even by a symlink) is never opened
        let target = root.join("victim");
        std::fs::write(&target, b"keep").unwrap();
        let link = directory.join("planted");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        assert!(options.open(&link).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }
}
