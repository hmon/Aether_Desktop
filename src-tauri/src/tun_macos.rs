//! macOS TUN — a real full tunnel, unlike the Windows adapter (`tun.rs`), which
//! captures no routes. sing-box owns a utun device with the default routes and
//! hands every flow to the local SOCKS5 bridge, so UDP and apps that ignore the
//! system proxy go through the tunnel too. Aether's own processes (this app:
//! bridge, probes, smart-route bypasses; and every engine binary) go direct,
//! otherwise their traffic would loop back into the tunnel.
//!
//! utun needs root, so sing-box starts through the standard macOS
//! administrator prompt. The root shell stops it when this app exits or asks it
//! to; the routes disappear with the utun device. Cancelling the prompt keeps
//! the system-proxy data path, like a missing wintun.dll on Windows.

use crate::log::DiagnosticsLog;
use crate::profile::ConnectionProfile;
use anyhow::{Context, Result};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const TAG: &str = "tun";

/// Processes that reach the network directly instead of through the tunnel.
const DIRECT_PROCESSES: [&str; 8] = [
    "aether-desktop",
    "aether",
    "psiphon-tunnel-core",
    "tor",
    "lyrebird",
    "conjure-client",
    "snowflake-client",
    "xray",
];

pub struct Tunnel {
    child: Arc<Mutex<Child>>,
    stopping: Arc<AtomicBool>,
    stop_file: PathBuf,
    watcher: Option<JoinHandle<()>>,
}

impl Tunnel {
    /// Returns as soon as the administrator prompt is up; the watcher thread
    /// logs when the routes are live or why the tunnel did not start.
    pub fn establish(profile: &ConnectionProfile, _wintun_dll: &Path) -> Result<Self> {
        let singbox = std::env::current_exe()?
            .parent()
            .context("no install directory")?
            .join("engine/sing-box/sing-box");
        anyhow::ensure!(singbox.is_file(), "sing-box missing: {}", singbox.display());

        let dir = PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("Library/Application Support/studio.cluvex.aether.desktop");
        std::fs::create_dir_all(&dir)?;
        let config = dir.join("tun.json");
        let log = dir.join("tun.log");
        let stop_file = dir.join("tun.stop");
        let _ = std::fs::remove_file(&stop_file);
        std::fs::write(&config, config_json(profile.mtu).to_string())?;

        let script = format!(
            "[ -e {stop} ] && exit 0; {sb} run -c {cfg} >{log} 2>&1 & p=$!; \
             while kill -0 {pid} 2>/dev/null && kill -0 $p 2>/dev/null && [ ! -e {stop} ]; do sleep 1; done; \
             kill $p 2>/dev/null; wait $p; rm -f {stop}",
            sb = sh_quote(&singbox),
            cfg = sh_quote(&config),
            log = sh_quote(&log),
            stop = sh_quote(&stop_file),
            pid = std::process::id(),
        );
        let child = Command::new("/usr/bin/osascript")
            .args([
                "-e",
                "on run argv",
                "-e",
                "do shell script (item 1 of argv) with prompt \"Aether needs administrator rights to send all traffic through the tunnel (TUN mode).\" with administrator privileges",
                "-e",
                "end run",
                &script,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("could not start osascript")?;
        DiagnosticsLog::i(
            TAG,
            "TUN mode: waiting for the administrator prompt (cancel it to stay on the system proxy).",
        );

        let child = Arc::new(Mutex::new(child));
        let stopping = Arc::new(AtomicBool::new(false));
        let watcher = {
            let (child, stopping) = (child.clone(), stopping.clone());
            std::thread::spawn(move || watch(&child, &stopping, &log))
        };
        Ok(Self {
            child,
            stopping,
            stop_file,
            watcher: Some(watcher),
        })
    }

    pub fn counters(&self) -> (u64, u64) {
        (0, 0)
    }

    pub fn close(&mut self) {
        let Some(watcher) = self.watcher.take() else {
            return;
        };
        self.stopping.store(true, Ordering::Relaxed);
        let _ = std::fs::write(&self.stop_file, b"");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !watcher.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        // Still waiting means the prompt is still on screen: dismiss it.
        if !watcher.is_finished() {
            let _ = self.child.lock().map(|mut c| c.kill());
        }
        DiagnosticsLog::i(TAG, "TUN stopped; its routes went with the utun device.");
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.close();
    }
}

fn watch(child: &Mutex<Child>, stopping: &AtomicBool, log: &Path) {
    let mut up = false;
    loop {
        let exited = child.lock().ok().and_then(|mut c| c.try_wait().ok().flatten());
        if let Some(status) = exited {
            if !stopping.load(Ordering::Relaxed) {
                let mut why = String::new();
                if let Some(mut err) = child.lock().ok().and_then(|mut c| c.stderr.take()) {
                    let _ = err.read_to_string(&mut why);
                }
                let tail = std::fs::read_to_string(log).unwrap_or_default();
                let tail: Vec<&str> = tail.lines().rev().take(5).collect();
                DiagnosticsLog::w(
                    TAG,
                    &format!(
                        "TUN not running ({status}: {}); the system proxy remains the data path. {}",
                        why.trim(),
                        tail.into_iter().rev().collect::<Vec<_>>().join(" | ")
                    ),
                );
            }
            return;
        }
        if !up && default_route_is_utun() {
            up = true;
            DiagnosticsLog::i(
                TAG,
                "TUN up: all TCP/UDP now goes through the tunnel; Aether's own processes go direct.",
            );
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn default_route_is_utun() -> bool {
    Command::new("/sbin/route")
        .args(["-n", "get", "1.1.1.1"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("interface: utun"))
        .unwrap_or(false)
}

fn config_json(mtu: u32) -> serde_json::Value {
    serde_json::json!({
        "log": { "level": "warn", "timestamp": true },
        "dns": {
            "servers": [{ "type": "tcp", "tag": "remote", "server": "1.1.1.1", "detour": "proxy" }]
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": mtu,
            "auto_route": true
        }],
        "outbounds": [
            { "type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": crate::engine::SHARE_SOCKS_PORT },
            { "type": "direct", "tag": "direct" }
        ],
        "route": {
            "rules": [
                { "process_name": DIRECT_PROCESSES, "outbound": "direct" },
                { "port": 53, "action": "hijack-dns" },
                { "ip_is_private": true, "outbound": "direct" }
            ],
            "final": "proxy",
            "auto_detect_interface": true,
            "default_domain_resolver": "remote"
        }
    })
}

fn sh_quote(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_paths_with_spaces_and_quotes() {
        assert_eq!(
            sh_quote(Path::new("/a b/it's")),
            r"'/a b/it'\''s'"
        );
    }

    #[test]
    fn engine_and_app_bypass_the_tunnel_everything_else_is_proxied() {
        let c = config_json(1280);
        let rules = &c["route"]["rules"];
        assert_eq!(rules[0]["outbound"], "direct");
        assert!(rules[0]["process_name"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n == "aether"));
        assert_eq!(c["route"]["final"], "proxy");
        assert_eq!(c["outbounds"][0]["server_port"], 10810);
    }
}
