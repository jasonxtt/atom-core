//! atom fork: `GET /api/v1/atom/system`, the machine's and the two
//! programs' CPU and memory for the WebUI's overview (atom step 6b).
//!
//! Counters, not rates: the CPU figures are seconds used since boot (the
//! machine) or since the program started; a UI takes two samples and divides
//! the differences (a program's share of the machine is its seconds over the
//! machine's `total_seconds`). The answer keeps no state between requests,
//! so several viewers do not disturb each other. Read from `/proc`; on other
//! systems every figure is `null`.

use std::path::Path;

use serde_json::{Value, json};

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

/// The process running `binary`: the only one whose `/proc/<pid>/exe` is
/// that file; when none is, the only one named `sing-box`. Several
/// candidates: none (better no figures than another instance's).
#[cfg(target_os = "linux")]
fn find_process(binary: &Path) -> Option<u32> {
    let wanted = std::fs::canonicalize(binary).ok();
    let (mut by_exe, mut by_name) = (Vec::new(), Vec::new());
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let dir = entry.path();
        if let (Some(wanted), Ok(exe)) = (&wanted, std::fs::read_link(dir.join("exe"))) {
            if &exe == wanted {
                by_exe.push(pid);
                continue;
            }
        }
        if std::fs::read_to_string(dir.join("comm")).is_ok_and(|comm| comm.trim() == "sing-box") {
            by_name.push(pid);
        }
    }
    match (by_exe.as_slice(), by_name.as_slice()) {
        ([pid], _) | ([], [pid]) => Some(*pid),
        _ => None,
    }
}

/// `(cpu seconds, resident bytes)` of a process.
#[cfg(target_os = "linux")]
fn process(pid: u32) -> Option<(f64, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (ticks, _, _, _, rss_pages) = crate::process_metrics::parse_stat(&stat)?;
    let per_second = rustix::param::clock_ticks_per_second().max(1) as f64;
    Some((
        ticks as f64 / per_second,
        rss_pages * rustix::param::page_size() as u64,
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn snapshot(singbox_binary: Option<&Path>) -> Value {
    let per_second = rustix::param::clock_ticks_per_second().max(1) as f64;
    let cpu = std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|text| parse_cpu(&text))
        .map(|(busy, total, cores)| {
            json!({
                "cores": cores,
                "busy_seconds": busy as f64 / per_second,
                "total_seconds": total as f64 / per_second,
            })
        });
    let memory = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| parse_meminfo(&text))
        .map(|(total, available)| json!({ "total_bytes": total, "available_bytes": available }));
    let load: Option<Vec<f64>> = std::fs::read_to_string("/proc/loadavg").ok().map(|text| {
        text.split_whitespace()
            .take(3)
            .filter_map(|field| field.parse().ok())
            .collect()
    });
    let uptime: Option<f64> = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|text| text.split_whitespace().next()?.parse().ok());
    let atomdns = crate::process_metrics::sample().map(|sample| {
        json!({
            "pid": std::process::id(),
            "cpu_seconds": sample.cpu_seconds,
            "resident_bytes": sample.resident_bytes,
            "start_time_seconds": sample.start_time_seconds,
        })
    });
    let singbox = singbox_binary
        .and_then(find_process)
        .and_then(|pid| process(pid).map(|figures| (pid, figures)))
        .map(|(pid, (cpu_seconds, resident_bytes))| {
            json!({ "pid": pid, "cpu_seconds": cpu_seconds, "resident_bytes": resident_bytes })
        });
    json!({
        "cpu": cpu,
        "memory": memory,
        "load": load,
        "uptime_seconds": uptime,
        "atomdns": atomdns,
        "singbox": singbox,
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn snapshot(_singbox_binary: Option<&Path>) -> Value {
    json!({
        "cpu": null, "memory": null, "load": null, "uptime_seconds": null,
        "atomdns": null, "singbox": null,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
