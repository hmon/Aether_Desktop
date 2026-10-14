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

use crate::diagnostics::{check, mask_ip, Check, Verdict};
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
/// The utun's own address; it is how our interface is told apart from other VPNs'.
const TUN_ADDR4: &str = "172.19.0.1";
const TRACE_URL: &str = "https://www.cloudflare.com/cdn-cgi/trace";

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

/// What the environment check reports.
#[derive(Clone)]
enum State {
    Off,
    Prompt,
    Up,
    Failed(String),
}

static STATE: Mutex<State> = Mutex::new(State::Off);

fn set_state(s: State) {
    *STATE.lock().unwrap_or_else(|e| e.into_inner()) = s;
}

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
        let singbox = singbox_path().context("no install directory")?;
        anyhow::ensure!(singbox.is_file(), "sing-box missing: {}", singbox.display());

        let dir = work_dir();
        std::fs::create_dir_all(&dir)?;
        let config = dir.join("tun.json");
        let log = dir.join("tun.log");
        let stop_file = dir.join("tun.stop");
        let _ = std::fs::remove_file(&stop_file);
        // IPv6 only when the network has it: an IPv6 route on a v4-only network
        // turns every instant "no route" into a 5 s timeout for direct traffic.
        let v6 = route_iface("-inet6", "default").is_some();
        std::fs::write(&config, config_json(profile.mtu, v6).to_string())?;

        // The DNS cache is flushed once the routes are up: answers cached before
        // (possibly the censor's) would otherwise keep being used.
        let script = format!(
            "[ -e {stop} ] && exit 0; {sb} run -c {cfg} >{log} 2>&1 & p=$!; \
             sleep 2; /usr/bin/dscacheutil -flushcache; /usr/bin/killall -HUP mDNSResponder; \
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
        set_state(State::Prompt);
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
        set_state(State::Off);
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
                let why = if why.contains("(-128)") {
                    "the administrator prompt was cancelled".to_string()
                } else {
                    format!("{status}: {}", why.trim())
                };
                let tail = std::fs::read_to_string(log).unwrap_or_default();
                let tail: Vec<&str> = tail.lines().rev().take(5).collect();
                DiagnosticsLog::w(
                    TAG,
                    &format!(
                        "TUN not running ({why}); the system proxy remains the data path. {}",
                        tail.into_iter().rev().collect::<Vec<_>>().join(" | ")
                    ),
                );
                set_state(State::Failed(why));
            }
            return;
        }
        if !up && own_utun().is_some_and(|o| route_iface("-inet", "1.1.1.1") == Some(o)) {
            up = true;
            set_state(State::Up);
            DiagnosticsLog::i(
                TAG,
                "TUN up: all TCP/UDP now goes through the tunnel; Aether's own processes go direct.",
            );
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

// ------------------------------------------------------------ environment check

/// Rows for the environment check: the bundled binary, whether our utun holds
/// the default route, where traffic outside the proxy really exits, and what
/// sing-box failed to connect.
pub fn checks() -> Vec<Check> {
    let mut out = vec![match singbox_path() {
        Some(p) if p.is_file() => check("TUN component", Verdict::Pass, format!("sing-box at {}", p.display())),
        _ => check(
            "TUN component",
            Verdict::Fail,
            "sing-box is missing: TUN mode is unavailable. Reinstall Aether.",
        ),
    }];
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let routes = match state {
        State::Off => check(
            "TUN routes",
            Verdict::Warn,
            "Not running (starts on Connect, after the administrator prompt)",
        ),
        State::Prompt => check("TUN routes", Verdict::Warn, "Waiting for the administrator prompt"),
        State::Failed(why) => check(
            "TUN routes",
            Verdict::Fail,
            format!("Not running: {why}. Only system-proxy apps are tunnelled."),
        ),
        State::Up => match (own_utun(), route_iface("-inet", "1.1.1.1")) {
            (Some(ours), Some(default)) if ours == default => {
                check("TUN routes", Verdict::Pass, format!("{ours} holds the default route"))
            }
            (Some(ours), Some(default)) => check(
                "TUN routes",
                Verdict::Fail,
                format!(
                    "{default} holds the default route, not Aether's {ours}: another VPN is active \
                     and traffic bypasses Aether. Disconnect it."
                ),
            ),
            (Some(ours), None) => check(
                "TUN routes",
                Verdict::Fail,
                format!("{ours} is up but there is no default route"),
            ),
            (None, _) => check(
                "TUN routes",
                Verdict::Fail,
                "sing-box was running but its utun interface is gone",
            ),
        },
    };
    let routed = routes.verdict == Verdict::Pass;
    out.push(routes);
    if routed {
        out.push(egress_check());
    }
    let log = std::fs::read_to_string(work_dir().join("tun.log")).unwrap_or_default();
    out.push(match summarize_log(&log) {
        None => check("TUN log", Verdict::Pass, "No failed connections"),
        Some(s) => check("TUN log", Verdict::Warn, s),
    });
    out
}

/// curl is not one of Aether's processes, so without a proxy it goes through
/// the utun; through the SOCKS bridge it shows the tunnel's own exit.
fn egress_check() -> Check {
    let socks = std::thread::spawn(|| {
        trace(Some(&format!("127.0.0.1:{}", crate::engine::SHARE_SOCKS_PORT)))
    });
    let tun = trace(None);
    let socks = socks.join().unwrap_or(Err(-1));
    let (verdict, detail) = match (tun, socks) {
        (Ok(a), Ok(b)) if a == b => (
            Verdict::Pass,
            format!("Apps outside the proxy exit at {} — the tunnel's exit", mask_ip(&a)),
        ),
        (Ok(a), Ok(b)) => (
            Verdict::Fail,
            format!(
                "LEAK: apps outside the proxy exit at {}, the tunnel at {}",
                mask_ip(&a),
                mask_ip(&b)
            ),
        ),
        (Ok(a), Err(_)) => (
            Verdict::Warn,
            format!(
                "Apps outside the proxy exit at {}; the comparison through the proxy failed",
                mask_ip(&a)
            ),
        ),
        (Err(6), _) => (
            Verdict::Fail,
            "DNS through the TUN failed: curl could not resolve www.cloudflare.com".to_string(),
        ),
        (Err(code), _) => (
            Verdict::Fail,
            format!("A request through the TUN failed (curl exit {code})"),
        ),
    };
    check("TUN egress", verdict, detail)
}

/// Exit IP from Cloudflare's trace, or curl's exit code.
fn trace(socks: Option<&str>) -> Result<String, i32> {
    let mut cmd = Command::new("/usr/bin/curl");
    cmd.args(["-s", "--max-time", "6", TRACE_URL]);
    match socks {
        Some(p) => cmd.args(["--socks5-hostname", p]),
        None => cmd.args(["--noproxy", "*"]),
    };
    let out = cmd.output().map_err(|_| -1)?;
    if !out.status.success() {
        return Err(out.status.code().unwrap_or(-1));
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("ip="))
        .map(String::from)
        .ok_or(-1)
}

/// sing-box logs only failures (level warn). Grouped by the causes seen in
/// the field; destinations themselves are not repeated. "context canceled" is
/// in-flight connections cut by a disconnect, not a failure.
fn summarize_log(log: &str) -> Option<String> {
    let errors: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("ERROR") && !l.contains("context canceled"))
        .collect();
    if errors.is_empty() {
        return None;
    }
    let block_page = errors.iter().filter(|l| l.contains("connection to 10.10.34.")).count();
    let ipv6 = errors.iter().filter(|l| l.contains("connection to [")).count();
    let other = errors.len() - block_page - ipv6;
    let mut s = format!("{} failed connection(s) since TUN started", errors.len());
    if block_page > 0 {
        s += &format!(
            "; {block_page} to 10.10.34.x, the censor's block page: an app used a poisoned DNS answer"
        );
    }
    if ipv6 > 0 {
        s += &format!("; {ipv6} over IPv6, which this network may not have");
    }
    if other > 0 {
        s += &format!("; {other} other (see tun.log)");
    }
    Some(s)
}

// ------------------------------------------------------------ helpers

fn singbox_path() -> Option<PathBuf> {
    Some(
        std::env::current_exe()
            .ok()?
            .parent()?
            .join("engine/sing-box/sing-box"),
    )
}

fn work_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
        .join("Library/Application Support/studio.cluvex.aether.desktop")
}

fn own_utun() -> Option<String> {
    let out = Command::new("/sbin/ifconfig").output().ok()?;
    utun_with_addr(&String::from_utf8_lossy(&out.stdout), TUN_ADDR4)
}

/// The interface whose block in `ifconfig` output carries `inet <addr>`.
fn utun_with_addr(ifconfig: &str, addr: &str) -> Option<String> {
    let needle = format!("inet {addr} ");
    let mut iface = None;
    for line in ifconfig.lines() {
        if !line.starts_with(['\t', ' ']) {
            iface = line.split(':').next().map(String::from);
        } else if line.trim_start().starts_with(&needle) {
            return iface;
        }
    }
    None
}

/// Interface `route get` picks for `dest` (`family` is `-inet` or `-inet6`).
fn route_iface(family: &str, dest: &str) -> Option<String> {
    let out = Command::new("/sbin/route").args(["-n", "get", family, dest]).output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface: "))
        .map(String::from)
}

fn config_json(mtu: u32, ipv6: bool) -> serde_json::Value {
    let mut address = vec![format!("{TUN_ADDR4}/30")];
    if ipv6 {
        address.push("fdfe:dcba:9876::1/126".into());
    }
    serde_json::json!({
        "log": { "level": "warn", "timestamp": true },
        "dns": {
            "servers": [{ "type": "tcp", "tag": "remote", "server": "1.1.1.1", "detour": "proxy" }]
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun",
            "address": address,
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
        assert_eq!(sh_quote(Path::new("/a b/it's")), r"'/a b/it'\''s'");
    }

    #[test]
    fn engine_and_app_bypass_the_tunnel_everything_else_is_proxied() {
        let c = config_json(1280, false);
        let rules = &c["route"]["rules"];
        assert_eq!(rules[0]["outbound"], "direct");
        assert!(rules[0]["process_name"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n == "aether"));
        assert_eq!(c["route"]["final"], "proxy");
        assert_eq!(c["outbounds"][0]["server_port"], 10810);
        assert_eq!(c["inbounds"][0]["address"].as_array().unwrap().len(), 1);
        assert_eq!(config_json(1280, true)["inbounds"][0]["address"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn finds_our_utun_among_other_vpns() {
        let ifconfig = "utun3: flags=8051<UP> mtu 1380\n\tinet6 fe80::1%utun3 prefixlen 64\n\
                        utun4: flags=8051<UP> mtu 4064\n\tinet 10.20.0.1 --> 10.20.0.1 netmask 0xfffffffc\n\
                        utun5: flags=8051<UP> mtu 1280\n\tinet 172.19.0.1 --> 172.19.0.1 netmask 0xfffffffc\n";
        assert_eq!(utun_with_addr(ifconfig, TUN_ADDR4).as_deref(), Some("utun5"));
        assert_eq!(utun_with_addr("utun4: flags\n\tinet 172.19.0.10 x\n", TUN_ADDR4), None);
    }

    #[test]
    fn log_summary_groups_known_causes() {
        let log = "+0330 ERROR [1 5.0s] connection: open connection to 10.10.34.35:443 using outbound/direct[direct]: i/o timeout\n\
                   +0330 ERROR [2 5.0s] connection: open connection to [2600:1900::1]:443 using outbound/direct[direct]: i/o timeout\n\
                   +0330 ERROR [3 5.0s] connection: open connection to 8.8.8.8:443 using outbound/proxy[proxy]: EOF\n\
                   +0330 ERROR [4 3.3s] connection: open connection to 1.2.3.4:443 using outbound/socks[proxy]: context canceled\n\
                   +0330 WARN something\n";
        let s = summarize_log(log).unwrap();
        assert!(s.starts_with("3 failed"), "{s}");
        assert!(s.contains("1 to 10.10.34.x") && s.contains("1 over IPv6") && s.contains("1 other"), "{s}");
        assert_eq!(summarize_log("+0330 WARN fine\n"), None);
    }
}
