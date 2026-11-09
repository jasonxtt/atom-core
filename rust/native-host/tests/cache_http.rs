//! Real native cache lifecycle contract: the final saves at SIGTERM. (The HTTP
//! cache routes were removed in atom step 6.)
mod common;
use std::net::TcpListener;
use std::time::Duration;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
#[cfg(unix)]
#[test]
fn native_process_sigterm_drains_owners_and_reports_all_final_save_failures_with_exit_two() {
    use std::process::{Command, Stdio};
    let root = std::env::temp_dir().join(format!("cache-signal-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let (mut child, stderr) = common::ports::retry_addr_in_use(|| {
        let api_port = free_port();
        let dns_port = free_port();
        let yaml = format!(
            "log: {{level: error}}\napi: {{http: '127.0.0.1:{api_port}'}}\nplugins:\n  - tag: alpha\n    type: cache\n    args: {{dump_file: missing/alpha.gz}}\n  - tag: beta\n    type: cache\n    args: {{dump_file: missing/beta.gz}}\n  - tag: f\n    type: forward\n    args: {{upstreams: [{{addr: 'udp://127.0.0.1:25999'}}]}}\n  - tag: main\n    type: sequence\n    args: [{{exec: $alpha}}, {{exec: $beta}}, {{exec: $f}}]\n  - tag: dns\n    type: udp_server\n    args: {{listen: '127.0.0.1:{dns_port}', entry: main, enable_audit: false}}\n"
        );
        let config = root.join("config.yaml");
        std::fs::write(&config, yaml).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_atomdns"));
        command
            .args(["start", "-c"])
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        common::ports::spawn_ready(&mut command, Duration::from_secs(1), || {
            std::net::TcpStream::connect(("127.0.0.1", api_port)).is_ok()
        })
    });
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    for _ in 0..400 {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
    }
    let mut output = child.wait_with_output().unwrap();
    output.stderr = common::ports::collected_stderr(&stderr);
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(2), "{diagnostic}");
    assert!(diagnostic.contains("cache 0:"));
    assert!(diagnostic.contains("cache 1:"));
    std::fs::remove_dir_all(root).unwrap();
}
