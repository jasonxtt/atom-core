//! atom fork: `GET /api/v1/atom/system`, the machine's and the two
//! programs' CPU and memory plus recent system and proxy-traffic history
//! for the WebUI's overview (atom step 6b).
//!
//! Keeps the original counter fields (`cpu`, `memory`, `load`,
//! `uptime_seconds`, `atomdns`, `singbox`) backwards-compatible while adding a
//! lightweight in-process collector that caches the latest snapshot, computes
//! CPU usage rates, and maintains bounded multi-resolution ring buffers for
//! system metrics (3 min) and Clash API `/traffic` throughput (`3m`, `15m`,
//! `1h`). Read from `/proc` on Linux; on other systems `/proc` figures are
//! `null`.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use atomdns_upstream_core::TransportCancellation;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const SYSTEM_HISTORY_CAP: usize = 60;
const TRAFFIC_3M_CAP: usize = 90;
const TRAFFIC_15M_CAP: usize = 60;
const TRAFFIC_1H_CAP: usize = 60;
/// Maximum age of a cached background `/proc` snapshot before `/system` falls
/// back to a live read.
const SNAPSHOT_FRESH_SECS: u64 = 10;
/// Maximum age of the latest `/traffic` tick before treating live rate as stale.
const TRAFFIC_FRESH_SECS: u64 = 10;
/// Maximum single chunk size accepted from the local Clash API `/traffic` stream.
const MAX_TRAFFIC_CHUNK_BYTES: usize = 64 * 1024;
const MAX_TRAFFIC_HEADER_LINES: usize = 64;

/// Supported time windows for `GET /api/v1/atom/system?history=1&window=...`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrafficWindow {
    Min3,
    Min15,
    Hour1,
}

impl TrafficWindow {
    pub(crate) fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "3m" => Ok(Self::Min3),
            "15m" => Ok(Self::Min15),
            "1h" => Ok(Self::Hour1),
            _ => Err("window 只能是 3m、15m 或 1h"),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Min3 => "3m",
            Self::Min15 => "15m",
            Self::Hour1 => "1h",
        }
    }

    pub(crate) const fn step_seconds(self) -> u64 {
        match self {
            Self::Min3 => 2,
            Self::Min15 => 15,
            Self::Hour1 => 60,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct CpuCounters {
    cores: usize,
    busy_seconds: f64,
    total_seconds: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemoryFigures {
    total_bytes: u64,
    available_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct ProcessSnapshot {
    pid: u32,
    cpu_seconds: f64,
    resident_bytes: u64,
    start_time_seconds: Option<f64>,
}

#[derive(Clone, Debug)]
struct RawSystem {
    ts: u64,
    binary: Option<PathBuf>,
    cpu: Option<CpuCounters>,
    memory: Option<MemoryFigures>,
    load: Option<Vec<f64>>,
    uptime_seconds: Option<f64>,
    atomdns: Option<ProcessSnapshot>,
    singbox: Option<ProcessSnapshot>,
}

impl RawSystem {
    #[cfg(not(target_os = "linux"))]
    fn empty(ts: u64, binary: Option<PathBuf>) -> Self {
        Self {
            ts,
            binary,
            cpu: None,
            memory: None,
            load: None,
            uptime_seconds: None,
            atomdns: None,
            singbox: None,
        }
    }

    fn base_fields_json(&self) -> Value {
        let cpu = self.cpu.map(|cpu| {
            json!({
                "cores": cpu.cores,
                "busy_seconds": cpu.busy_seconds,
                "total_seconds": cpu.total_seconds,
            })
        });
        let memory = self.memory.map(|memory| {
            json!({
                "total_bytes": memory.total_bytes,
                "available_bytes": memory.available_bytes,
            })
        });
        let process_json = |proc: ProcessSnapshot| {
            let mut map = serde_json::Map::new();
            map.insert("pid".to_owned(), json!(proc.pid));
            map.insert("cpu_seconds".to_owned(), json!(proc.cpu_seconds));
            map.insert("resident_bytes".to_owned(), json!(proc.resident_bytes));
            if let Some(start) = proc.start_time_seconds {
                map.insert("start_time_seconds".to_owned(), json!(start));
            }
            Value::Object(map)
        };
        json!({
            "cpu": cpu,
            "memory": memory,
            "load": self.load,
            "uptime_seconds": self.uptime_seconds,
            "atomdns": self.atomdns.map(process_json),
            "singbox": self.singbox.map(process_json),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct CpuRates {
    cpu_percent: f64,
    atomdns_percent: Option<f64>,
    singbox_percent: Option<f64>,
}

impl CpuRates {
    fn to_json(self) -> Value {
        json!({
            "cpu_percent": self.cpu_percent,
            "atomdns_percent": self.atomdns_percent,
            "singbox_percent": self.singbox_percent,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct SystemPoint {
    ts: u64,
    cpu_percent: f64,
    atomdns_percent: Option<f64>,
    singbox_percent: Option<f64>,
    memory_used_bytes: u64,
}

impl SystemPoint {
    fn to_json(self) -> Value {
        json!({
            "ts": self.ts,
            "cpu_percent": self.cpu_percent,
            "atomdns_percent": self.atomdns_percent,
            "singbox_percent": self.singbox_percent,
            "memory_used_bytes": self.memory_used_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TrafficPoint {
    ts: u64,
    down_bps: u64,
    up_bps: u64,
}

impl TrafficPoint {
    fn to_json(self) -> Value {
        json!({
            "ts": self.ts,
            "down_bps": self.down_bps,
            "up_bps": self.up_bps,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct TrafficBucket {
    bucket_ts: u64,
    down_sum: u128,
    up_sum: u128,
    samples: u32,
}

#[derive(Debug)]
struct TrafficRing {
    step_secs: u64,
    cap: usize,
    points: VecDeque<TrafficPoint>,
    current: Option<TrafficBucket>,
}

impl TrafficRing {
    fn new(step_secs: u64, cap: usize) -> Self {
        Self {
            step_secs: step_secs.max(1),
            cap,
            points: VecDeque::with_capacity(cap),
            current: None,
        }
    }

    fn record(&mut self, ts: u64, down_bps: u64, up_bps: u64) {
        let bucket_ts = ts - (ts % self.step_secs);
        if let Some(current) = &mut self.current {
            if bucket_ts < current.bucket_ts {
                // Wall clock stepped backward: start fresh from this bucket.
                self.points.clear();
                self.current = None;
            } else if bucket_ts == current.bucket_ts {
                current.down_sum += u128::from(down_bps);
                current.up_sum += u128::from(up_bps);
                current.samples = current.samples.saturating_add(1);
                let count = u128::from(current.samples.max(1));
                let down_avg = u64::try_from(current.down_sum / count).unwrap_or(u64::MAX);
                let up_avg = u64::try_from(current.up_sum / count).unwrap_or(u64::MAX);
                if let Some(last) = self.points.back_mut() {
                    last.down_bps = down_avg;
                    last.up_bps = up_avg;
                }
                return;
            }
        }
        self.current = Some(TrafficBucket {
            bucket_ts,
            down_sum: u128::from(down_bps),
            up_sum: u128::from(up_bps),
            samples: 1,
        });
        self.points.push_back(TrafficPoint {
            ts: bucket_ts,
            down_bps,
            up_bps,
        });
        while self.points.len() > self.cap {
            self.points.pop_front();
        }
    }
}

#[derive(Debug)]
struct Telemetry {
    latest_raw: Option<RawSystem>,
    latest_rates: Option<CpuRates>,
    system_history: VecDeque<SystemPoint>,
    latest_traffic: Option<TrafficPoint>,
    traffic_3m: TrafficRing,
    traffic_15m: TrafficRing,
    traffic_1h: TrafficRing,
}

impl Telemetry {
    fn new() -> Self {
        Self {
            latest_raw: None,
            latest_rates: None,
            system_history: VecDeque::with_capacity(SYSTEM_HISTORY_CAP),
            latest_traffic: None,
            traffic_3m: TrafficRing::new(TrafficWindow::Min3.step_seconds(), TRAFFIC_3M_CAP),
            traffic_15m: TrafficRing::new(TrafficWindow::Min15.step_seconds(), TRAFFIC_15M_CAP),
            traffic_1h: TrafficRing::new(TrafficWindow::Hour1.step_seconds(), TRAFFIC_1H_CAP),
        }
    }

    fn record_system(&mut self, raw: RawSystem) {
        if let (Some(prev), Some(now_cpu)) = (self.latest_raw.as_ref(), raw.cpu) {
            if let Some(prev_cpu) = prev.cpu {
                let total = now_cpu.total_seconds - prev_cpu.total_seconds;
                if total > 0.0 {
                    let busy = (now_cpu.busy_seconds - prev_cpu.busy_seconds).max(0.0);
                    let cpu_percent = ((busy / total) * 100.0).clamp(0.0, 100.0);
                    let share = |before: Option<ProcessSnapshot>, after: Option<ProcessSnapshot>| {
                        match (before, after) {
                            (Some(a), Some(b)) if a.pid == b.pid => {
                                let delta = (b.cpu_seconds - a.cpu_seconds).max(0.0);
                                Some(((delta / total) * 100.0).clamp(0.0, 100.0))
                            }
                            _ => None,
                        }
                    };
                    let rates = CpuRates {
                        cpu_percent,
                        atomdns_percent: share(prev.atomdns, raw.atomdns),
                        singbox_percent: share(prev.singbox, raw.singbox),
                    };
                    self.latest_rates = Some(rates);
                    let memory_used_bytes = raw
                        .memory
                        .map_or(0, |mem| mem.total_bytes.saturating_sub(mem.available_bytes));
                    self.system_history.push_back(SystemPoint {
                        ts: raw.ts,
                        cpu_percent: rates.cpu_percent,
                        atomdns_percent: rates.atomdns_percent,
                        singbox_percent: rates.singbox_percent,
                        memory_used_bytes,
                    });
                    while self.system_history.len() > SYSTEM_HISTORY_CAP {
                        self.system_history.pop_front();
                    }
                }
            }
        } else if raw.cpu.is_none() {
            self.latest_rates = None;
        }
        self.latest_raw = Some(raw);
    }

    fn record_traffic(&mut self, ts: u64, down_bps: u64, up_bps: u64) {
        self.latest_traffic = Some(TrafficPoint {
            ts,
            down_bps,
            up_bps,
        });
        self.traffic_3m.record(ts, down_bps, up_bps);
        self.traffic_15m.record(ts, down_bps, up_bps);
        self.traffic_1h.record(ts, down_bps, up_bps);
    }

    fn traffic_points(&self, window: TrafficWindow) -> &VecDeque<TrafficPoint> {
        match window {
            TrafficWindow::Min3 => &self.traffic_3m.points,
            TrafficWindow::Min15 => &self.traffic_15m.points,
            TrafficWindow::Hour1 => &self.traffic_1h.points,
        }
    }

    fn fresh_raw(&self, binary: Option<&Path>, now_ts: u64) -> Option<RawSystem> {
        let raw = self.latest_raw.as_ref()?;
        if now_ts.saturating_sub(raw.ts) > SNAPSHOT_FRESH_SECS {
            return None;
        }
        if raw.binary.as_deref() != binary {
            return None;
        }
        Some(raw.clone())
    }

    fn render(
        &self,
        raw: &RawSystem,
        now_ts: u64,
        include_history: bool,
        window: TrafficWindow,
    ) -> Value {
        let mut value = raw.base_fields_json();
        let Some(map) = value.as_object_mut() else {
            return value;
        };
        let rates = self
            .latest_rates
            .filter(|_| raw.cpu.is_some())
            .map_or(Value::Null, CpuRates::to_json);
        let traffic = self
            .latest_traffic
            .filter(|point| now_ts.saturating_sub(point.ts) <= TRAFFIC_FRESH_SECS)
            .map_or(Value::Null, TrafficPoint::to_json);
        map.insert("rates".to_owned(), rates);
        map.insert("traffic".to_owned(), traffic);
        if include_history {
            let system: Vec<Value> = self
                .system_history
                .iter()
                .copied()
                .map(SystemPoint::to_json)
                .collect();
            let points: Vec<Value> = self
                .traffic_points(window)
                .iter()
                .copied()
                .map(TrafficPoint::to_json)
                .collect();
            map.insert(
                "history".to_owned(),
                json!({
                    "system": system,
                    "traffic": {
                        "window": window.as_str(),
                        "step_seconds": window.step_seconds(),
                        "points": points,
                    }
                }),
            );
        }
        value
    }
}

fn telemetry() -> &'static Mutex<Telemetry> {
    static STORE: OnceLock<Mutex<Telemetry>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(Telemetry::new()))
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The `cpu` line of `/proc/stat` in ticks: `(busy, total, cores)`; idle and
/// iowait are the not-busy part.
#[cfg(any(target_os = "linux", test))]
fn parse_cpu(text: &str) -> Option<(u64, u64, usize)> {
    let mut lines = text.lines();
    let fields: Vec<u64> = lines
        .next()?
        .strip_prefix("cpu ")?
        .split_whitespace()
        .filter_map(|field| field.parse().ok())
        .collect();
    // user nice system idle iowait irq softirq steal (guest time is already in user).
    let total: u64 = fields.iter().take(8).sum();
    let idle = fields.get(3)? + fields.get(4).copied().unwrap_or(0);
    let cores = lines
        .filter(|line| {
            line.strip_prefix("cpu")
                .and_then(|rest| rest.chars().next())
                .is_some_and(|c| c.is_ascii_digit())
        })
        .count();
    Some((total.saturating_sub(idle), total, cores.max(1)))
}

/// `MemTotal` and `MemAvailable` of `/proc/meminfo`, in bytes.
#[cfg(any(target_os = "linux", test))]
fn parse_meminfo(text: &str) -> Option<(u64, u64)> {
    let field = |name: &str| -> Option<u64> {
        let line = text.lines().find(|line| line.starts_with(name))?;
        let kib: u64 = line[name.len()..]
            .trim()
            .trim_end_matches("kB")
            .trim()
            .parse()
            .ok()?;
        Some(kib * 1024)
    };
    Some((field("MemTotal:")?, field("MemAvailable:")?))
}

#[cfg(target_os = "linux")]
fn cached_pid_store() -> &'static Mutex<Option<(PathBuf, u32)>> {
    static PID_CACHE: OnceLock<Mutex<Option<(PathBuf, u32)>>> = OnceLock::new();
    PID_CACHE.get_or_init(|| Mutex::new(None))
}

#[cfg(target_os = "linux")]
fn pid_matches_binary(pid: u32, wanted: Option<&Path>, name: &str) -> bool {
    let dir = PathBuf::from(format!("/proc/{pid}"));
    if let (Some(wanted), Ok(exe)) = (wanted, std::fs::read_link(dir.join("exe"))) {
        if exe == wanted {
            return true;
        }
    }
    std::fs::read_to_string(dir.join("comm")).is_ok_and(|comm| comm.trim() == name)
}

/// The process running `binary`: checks the cached PID first in O(1), then
/// falls back to scanning `/proc` (the only process whose `/proc/<pid>/exe` is
/// that file, or when none is, the only one named like the binary). Several
/// candidates: none (better no figures than another instance's).
#[cfg(target_os = "linux")]
fn find_process(binary: &Path) -> Option<u32> {
    let wanted = std::fs::canonicalize(binary).ok();
    let name = binary
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("sing-box")
        .to_owned();

    if let Ok(guard) = cached_pid_store().lock() {
        if let Some((cached_binary, pid)) = guard.as_ref() {
            if cached_binary == binary && pid_matches_binary(*pid, wanted.as_deref(), &name) {
                return Some(*pid);
            }
        }
    }

    let (mut by_exe, mut by_name) = (Vec::new(), Vec::new());
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let dir = entry.path();
        if let (Some(wanted), Ok(exe)) = (&wanted, std::fs::read_link(dir.join("exe"))) {
            if &exe == wanted {
                by_exe.push(pid);
                continue;
            }
        }
        if std::fs::read_to_string(dir.join("comm")).is_ok_and(|comm| comm.trim() == name) {
            by_name.push(pid);
        }
    }
    let found = match (by_exe.as_slice(), by_name.as_slice()) {
        ([pid], _) | ([], [pid]) => Some(*pid),
        _ => None,
    };
    if let Ok(mut guard) = cached_pid_store().lock() {
        *guard = found.map(|pid| (binary.to_path_buf(), pid));
    }
    found
}

/// `(cpu seconds, resident bytes)` of a process.
#[cfg(target_os = "linux")]
#[allow(clippy::cast_precision_loss)]
fn process(pid: u32) -> Option<(f64, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (ticks, _, _, _, rss_pages) = crate::process_metrics::parse_stat(&stat)?;
    let per_second = rustix::param::clock_ticks_per_second().max(1) as f64;
    Some((
        ticks as f64 / per_second,
        rss_pages * rustix::param::page_size() as u64,
    ))
}

/// When the proxy kernel process running `binary` started (seconds since the
/// epoch): the boot time plus its start time from `/proc/<pid>/stat`, which
/// works under systemd and OpenRC alike. `None` when it cannot be told.
#[cfg(target_os = "linux")]
pub(crate) fn started_at(binary: &Path) -> Option<u64> {
    let pid = find_process(binary)?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, _, start_ticks, _, _) = crate::process_metrics::parse_stat(&stat)?;
    let boot =
        crate::process_metrics::parse_boot_time(&std::fs::read_to_string("/proc/stat").ok()?)?;
    Some(boot + start_ticks / rustix::param::clock_ticks_per_second().max(1))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn started_at(_binary: &Path) -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
#[allow(clippy::cast_precision_loss)]
fn collect_raw(singbox_binary: Option<&Path>) -> RawSystem {
    let per_second = rustix::param::clock_ticks_per_second().max(1) as f64;
    let cpu = std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|text| parse_cpu(&text))
        .map(|(busy, total, cores)| CpuCounters {
            cores,
            busy_seconds: busy as f64 / per_second,
            total_seconds: total as f64 / per_second,
        });
    let memory = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| parse_meminfo(&text))
        .map(|(total_bytes, available_bytes)| MemoryFigures {
            total_bytes,
            available_bytes,
        });
    let load: Option<Vec<f64>> = std::fs::read_to_string("/proc/loadavg").ok().map(|text| {
        text.split_whitespace()
            .take(3)
            .filter_map(|field| field.parse().ok())
            .collect()
    });
    let uptime_seconds: Option<f64> = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|text| text.split_whitespace().next()?.parse().ok());
    let atomdns = crate::process_metrics::sample().map(|sample| ProcessSnapshot {
        pid: std::process::id(),
        cpu_seconds: sample.cpu_seconds,
        resident_bytes: sample.resident_bytes,
        start_time_seconds: Some(sample.start_time_seconds),
    });
    let singbox = singbox_binary
        .and_then(find_process)
        .and_then(|pid| process(pid).map(|figures| (pid, figures)))
        .map(|(pid, (cpu_seconds, resident_bytes))| ProcessSnapshot {
            pid,
            cpu_seconds,
            resident_bytes,
            start_time_seconds: None,
        });
    RawSystem {
        ts: now_unix_secs(),
        binary: singbox_binary.map(Path::to_path_buf),
        cpu,
        memory,
        load,
        uptime_seconds,
        atomdns,
        singbox,
    }
}

#[cfg(not(target_os = "linux"))]
fn collect_raw(singbox_binary: Option<&Path>) -> RawSystem {
    RawSystem::empty(now_unix_secs(), singbox_binary.map(Path::to_path_buf))
}

/// Serves `GET /api/v1/atom/system` (with optional `history` & `window`):
/// returns the warm in-memory collector snapshot immediately when fresh, or
/// falls back to a blocking `/proc` read on cold start / direct test calls.
pub(crate) async fn view(
    singbox_binary: Option<PathBuf>,
    include_history: bool,
    window: TrafficWindow,
) -> Result<Value, String> {
    let now_ts = now_unix_secs();
    if let Ok(guard) = telemetry().lock() {
        if let Some(raw) = guard.fresh_raw(singbox_binary.as_deref(), now_ts) {
            return Ok(guard.render(&raw, now_ts, include_history, window));
        }
    }
    let raw = tokio::task::spawn_blocking(move || collect_raw(singbox_binary.as_deref()))
        .await
        .map_err(|error| format!("任务异常结束: {error}"))?;
    let now_ts = now_unix_secs();
    let value = telemetry().lock().map_or_else(
        |_| raw.base_fields_json(),
        |guard| guard.render(&raw, now_ts, include_history, window),
    );
    Ok(value)
}

// ---------------------------------------------------------------------------
// Background collectors (system 3s + Clash API /traffic stream)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TrafficTick {
    #[serde(default)]
    up: u64,
    #[serde(default)]
    down: u64,
}

/// Runs the periodic `/proc` system sampler until `shutdown` is cancelled.
/// Takes a baseline immediately, a quick 500 ms warm-up sample so CPU rates
/// exist right after startup, and then samples every 3 seconds.
pub(crate) async fn run_system_collector<F>(mut binary_lookup: F, shutdown: TransportCancellation)
where
    F: FnMut() -> Option<PathBuf>,
{
    let mut first = true;
    loop {
        let binary = binary_lookup();
        let sampled = tokio::task::spawn_blocking(move || collect_raw(binary.as_deref())).await;
        if let Ok(raw) = sampled {
            if let Ok(mut guard) = telemetry().lock() {
                guard.record_system(raw);
            }
        }
        let delay = if first {
            first = false;
            Duration::from_millis(500)
        } else {
            Duration::from_secs(3)
        };
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep(delay) => {}
        }
    }
}

/// Runs the async Clash API `GET /traffic` stream reader until `shutdown` is
/// cancelled, feeding 1-second throughput ticks into the multi-resolution ring
/// buffers. Automatically reconnects if the proxy kernel restarts or switches.
pub(crate) async fn run_traffic_collector<F, G>(
    mut clash_target: F,
    mut secret_lookup: G,
    shutdown: TransportCancellation,
) where
    F: FnMut() -> Option<SocketAddr>,
    G: FnMut() -> Option<String>,
{
    loop {
        if shutdown.is_cancelled() {
            break;
        }
        let Some(address) = clash_target() else {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                () = tokio::time::sleep(Duration::from_secs(2)) => continue,
            }
        };
        let Some(secret) = secret_lookup() else {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                () = tokio::time::sleep(Duration::from_secs(2)) => continue,
            }
        };
        let _ = stream_traffic_once(address, &secret, &mut clash_target, &shutdown).await;
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep(Duration::from_secs(2)) => {}
        }
    }
}

async fn stream_traffic_once<F>(
    address: SocketAddr,
    secret: &str,
    clash_target: &mut F,
    shutdown: &TransportCancellation,
) -> Result<(), String>
where
    F: FnMut() -> Option<SocketAddr>,
{
    let connect = tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(address));
    let mut stream = tokio::select! {
        biased;
        () = shutdown.cancelled() => return Ok(()),
        result = connect => result
            .map_err(|_| "connect timeout".to_owned())?
            .map_err(|error| error.to_string())?,
    };
    let request = format!(
        "GET /traffic HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {secret}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| error.to_string())?;

    let mut reader = BufReader::new(stream);
    let chunked = read_traffic_headers(&mut reader, shutdown).await?;
    consume_traffic_stream(
        &mut reader,
        chunked,
        shutdown,
        || clash_target() == Some(address),
        |down, up| {
            if let Ok(mut guard) = telemetry().lock() {
                guard.record_traffic(now_unix_secs(), down, up);
            }
        },
    )
    .await
}

async fn read_traffic_headers<R>(
    reader: &mut R,
    shutdown: &TransportCancellation,
) -> Result<bool, String>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = String::new();
    let status_read = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line));
    let n = tokio::select! {
        biased;
        () = shutdown.cancelled() => return Err("cancelled".to_owned()),
        result = status_read => result
            .map_err(|_| "header timeout".to_owned())?
            .map_err(|error| error.to_string())?,
    };
    if n == 0 {
        return Err("eof".to_owned());
    }
    let status: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| "invalid status".to_owned())?;
    if status != 200 {
        return Err(format!("status {status}"));
    }

    let mut chunked = false;
    for _ in 0..MAX_TRAFFIC_HEADER_LINES {
        line.clear();
        let read = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line));
        let n = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Err("cancelled".to_owned()),
            result = read => result
                .map_err(|_| "header timeout".to_owned())?
                .map_err(|error| error.to_string())?,
        };
        if n == 0 || line == "\r\n" || line == "\n" {
            return Ok(chunked);
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
    }
    Err("too many headers".to_owned())
}

async fn consume_traffic_stream<R, C, O>(
    reader: &mut R,
    chunked: bool,
    shutdown: &TransportCancellation,
    mut still_valid: C,
    mut on_tick: O,
) -> Result<(), String>
where
    R: AsyncBufRead + Unpin,
    C: FnMut() -> bool,
    O: FnMut(u64, u64),
{
    let mut pending = String::new();
    let mut line = String::new();
    let mut chunk_buf = Vec::new();
    loop {
        if !still_valid() {
            return Ok(());
        }
        if chunked {
            line.clear();
            let read = tokio::time::timeout(Duration::from_secs(15), reader.read_line(&mut line));
            let n = tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                result = read => result
                    .map_err(|_| "idle timeout".to_owned())?
                    .map_err(|error| error.to_string())?,
            };
            if n == 0 {
                return Ok(());
            }
            let size_hex = line.trim().split(';').next().unwrap_or_default();
            if size_hex.is_empty() {
                continue;
            }
            let size = usize::from_str_radix(size_hex, 16)
                .map_err(|_| "invalid chunk size".to_owned())?;
            if size == 0 {
                return Ok(());
            }
            if size > MAX_TRAFFIC_CHUNK_BYTES {
                return Err("chunk too large".to_owned());
            }
            chunk_buf.resize(size, 0);
            let read_body =
                tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut chunk_buf));
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                result = read_body => {
                    result
                        .map_err(|_| "chunk timeout".to_owned())?
                        .map_err(|error| error.to_string())?;
                }
            }
            // Consume trailing CRLF after chunk payload.
            line.clear();
            let _ = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;
            if let Ok(text) = std::str::from_utf8(&chunk_buf) {
                pending.push_str(text);
                drain_traffic_lines(&mut pending, &mut on_tick);
            }
        } else {
            line.clear();
            let read = tokio::time::timeout(Duration::from_secs(15), reader.read_line(&mut line));
            let n = tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                result = read => result
                    .map_err(|_| "idle timeout".to_owned())?
                    .map_err(|error| error.to_string())?,
            };
            if n == 0 {
                return Ok(());
            }
            if let Ok(tick) = serde_json::from_str::<TrafficTick>(line.trim()) {
                on_tick(tick.down, tick.up);
            }
        }
    }
}

fn drain_traffic_lines<O: FnMut(u64, u64)>(pending: &mut String, on_tick: &mut O) {
    while let Some(pos) = pending.find('\n') {
        let trimmed = pending[..pos].trim();
        if let Ok(tick) = serde_json::from_str::<TrafficTick>(trimmed) {
            on_tick(tick.down, tick.up);
        }
        pending.drain(..=pos);
    }
    let trimmed = pending.trim();
    if !trimmed.is_empty() {
        if let Ok(tick) = serde_json::from_str::<TrafficTick>(trimmed) {
            on_tick(tick.down, tick.up);
            pending.clear();
        }
    }
    if pending.len() > MAX_TRAFFIC_CHUNK_BYTES {
        pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_sample(ts: u64, busy: f64, total: f64, used_mem: u64, atom_cpu: f64) -> RawSystem {
        RawSystem {
            ts,
            binary: None,
            cpu: Some(CpuCounters {
                cores: 2,
                busy_seconds: busy,
                total_seconds: total,
            }),
            memory: Some(MemoryFigures {
                total_bytes: 1000,
                available_bytes: 1000 - used_mem,
            }),
            load: Some(vec![0.1, 0.2, 0.3]),
            uptime_seconds: Some(120.0),
            atomdns: Some(ProcessSnapshot {
                pid: 10,
                cpu_seconds: atom_cpu,
                resident_bytes: 30,
                start_time_seconds: Some(1000.0),
            }),
            singbox: Some(ProcessSnapshot {
                pid: 20,
                cpu_seconds: atom_cpu * 2.0,
                resident_bytes: 40,
                start_time_seconds: None,
            }),
        }
    }

    #[test]
    fn the_cpu_line_gives_busy_total_and_cores() {
        let text = "cpu  100 5 50 800 20 3 2 0 7 0\ncpu0 50 2 25 400 10 1 1 0 0 0\n\
                    cpu1 50 3 25 400 10 2 1 0 0 0\nintr 1 2 3\n";
        // total = 100+5+50+800+20+3+2+0 = 980; idle = 800+20.
        assert_eq!(parse_cpu(text), Some((160, 980, 2)));
        assert_eq!(parse_cpu("intr 1\n"), None);
    }

    #[test]
    fn meminfo_gives_total_and_available_bytes() {
        let text = "MemTotal:        2000 kB\nMemFree:          100 kB\nMemAvailable:     1500 kB\n";
        assert_eq!(parse_meminfo(text), Some((2000 * 1024, 1500 * 1024)));
        assert_eq!(parse_meminfo("MemTotal: 1 kB\n"), None);
    }

    #[test]
    fn telemetry_computes_rates_and_caps_system_history() {
        let mut store = Telemetry::new();
        store.record_system(raw_sample(100, 10.0, 100.0, 200, 1.0));
        assert!(store.latest_rates.is_none());
        assert!(store.system_history.is_empty());

        store.record_system(raw_sample(103, 15.0, 110.0, 250, 2.0));
        let rates = store.latest_rates.expect("rates after two samples");
        assert!((rates.cpu_percent - 50.0).abs() < 1e-6);
        assert!((rates.atomdns_percent.unwrap() - 10.0).abs() < 1e-6);
        assert!((rates.singbox_percent.unwrap() - 20.0).abs() < 1e-6);
        assert_eq!(store.system_history.len(), 1);
        assert_eq!(store.system_history[0].memory_used_bytes, 250);

        for i in 0..70_u64 {
            #[allow(clippy::cast_precision_loss)]
            let step = i as f64;
            store.record_system(raw_sample(
                106 + i * 3,
                16.0 + step,
                120.0 + step * 10.0,
                300,
                2.5 + step * 0.1,
            ));
        }
        assert_eq!(store.system_history.len(), SYSTEM_HISTORY_CAP);
    }

    #[test]
    fn traffic_ring_aggregates_buckets_and_enforces_capacity() {
        let mut ring = TrafficRing::new(2, 3);
        // Same 2-second bucket [100, 101] -> averaged to (200, 40)
        ring.record(100, 100, 20);
        ring.record(101, 300, 60);
        assert_eq!(ring.points.len(), 1);
        assert_eq!(
            ring.points[0],
            TrafficPoint {
                ts: 100,
                down_bps: 200,
                up_bps: 40,
            }
        );

        // Next buckets push past cap = 3
        ring.record(102, 500, 50);
        ring.record(104, 600, 60);
        ring.record(106, 700, 70);
        assert_eq!(ring.points.len(), 3);
        assert_eq!(ring.points[0].ts, 102);
        assert_eq!(ring.points[2].ts, 106);

        // Backward wall-clock jump resets cleanly instead of panicking
        ring.record(50, 10, 5);
        assert_eq!(ring.points.len(), 1);
        assert_eq!(ring.points[0].ts, 50);
    }

    #[test]
    fn renders_rates_traffic_and_windowed_history() {
        let mut store = Telemetry::new();
        let first = raw_sample(1000, 10.0, 100.0, 200, 1.0);
        let second = raw_sample(1003, 12.0, 110.0, 240, 1.5);
        store.record_system(first);
        store.record_system(second.clone());
        store.record_traffic(1002, 4096, 1024);
        store.record_traffic(1003, 6144, 2048);

        let body = store.render(&second, 1004, true, TrafficWindow::Min3);
        assert!((body["rates"]["cpu_percent"].as_f64().unwrap() - 20.0).abs() < 1e-6);
        assert_eq!(body["traffic"]["down_bps"], 6144);
        assert_eq!(body["traffic"]["up_bps"], 2048);
        assert_eq!(body["history"]["system"].as_array().unwrap().len(), 1);
        assert_eq!(body["history"]["traffic"]["window"], "3m");
        assert_eq!(body["history"]["traffic"]["step_seconds"], 2);
        let points = body["history"]["traffic"]["points"].as_array().unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0]["down_bps"], 5120);
        assert_eq!(points[0]["up_bps"], 1536);
    }

    #[test]
    fn parses_chunked_and_plain_traffic_streams() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let chunk1 = "{\"up\":120,\"down\":480}\n";
            let chunk2 = "{\"up\":50,\"down\":900,\"upTotal\":170}\n";
            let raw_chunked = format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{chunk1}\r\n{:x}\r\n{chunk2}\r\n0\r\n\r\n",
                chunk1.len(),
                chunk2.len()
            );
            let mut reader = BufReader::new(raw_chunked.as_bytes());
            let shutdown = TransportCancellation::new();
            let chunked = read_traffic_headers(&mut reader, &shutdown).await.unwrap();
            assert!(chunked);
            let mut seen = Vec::new();
            consume_traffic_stream(&mut reader, chunked, &shutdown, || true, |d, u| {
                seen.push((d, u));
            })
            .await
            .unwrap();
            assert_eq!(seen, vec![(480, 120), (900, 50)]);

            let raw_plain = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"up\":1,\"down\":2}\n{\"up\":3,\"down\":4}\n";
            let mut reader = BufReader::new(raw_plain.as_bytes());
            let chunked = read_traffic_headers(&mut reader, &shutdown).await.unwrap();
            assert!(!chunked);
            let mut seen = Vec::new();
            consume_traffic_stream(&mut reader, chunked, &shutdown, || true, |d, u| {
                seen.push((d, u));
            })
            .await
            .unwrap();
            assert_eq!(seen, vec![(2, 1), (4, 3)]);
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_start_time_comes_from_proc() {
        let exe = std::env::current_exe().unwrap();
        let started = started_at(&exe).expect("this test process");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(started <= now && now - started < 3600, "{started} vs {now}");
    }
}
