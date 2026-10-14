//! پروکسی سیستمی ویندوز — معادل کاربردیِ `VpnService.establish()` اندروید.
//!
//! ریشهٔ باگ «کانکت می‌شود ولی هیچ سایتی باز نمی‌شود»: نسخهٔ قبلی دسکتاپ
//! هیچ مسیر داده‌ای بین سیستم و SOCKS5 موتور برقرار نمی‌کرد (Wintun فقط
//! ساخته می‌شد؛ نه مسیریابی داشت و نه رله). حالا هنگام اتصال:
//!   ۱. پل محلی HTTP↔SOCKS5 (`share.rs`) روی 127.0.0.1:10811 بالا می‌آید،
//!   ۲. پروکسی سیستمی ویندوز (WinINET — همان که Edge/Chrome/Firefox
//!      «system proxy» می‌خوانند) به آن پل تنظیم می‌شود،
//!   ۳. هنگام قطع، تنظیم برگردانده می‌شود.
//! این کار به دسترسی Administrator نیاز ندارد (HKCU) و همان نقش «کل
//! ترافیک از تونل برود» اندروید را روی ویندوز بازی می‌کند.
//!
//! ⚠ محدودیت ذاتی که ریشهٔ نشتی WebRTC بود: پروکسی WinINET **فقط TCP** را
//! می‌گیرد. هر سوکت UDP خامی (WebRTC/STUN، QUIC، بازی‌ها) از کنارش رد
//! می‌شود. جبرانش در `leakguard.rs` است و اعلام «متصل» دیگر به‌تنهایی معنی
//! «بدون نشتی» نمی‌دهد؛ خودآزما آن را جداگانه اثبات می‌کند.
//!
//! v1.2.0: رشتهٔ پروکسی به شکل «به‌ازای پروتکل» نوشته می‌شود و یک ورودی
//! `socks=` هم دارد. مرورگرهای کرومیوم همین ورودی را برمی‌دارند و با SOCKS5
//! نامِ مقصد را هم داخل تونل حل می‌کنند (بدون نشت DNS).

// macOS uses `mod mac` below; the registry path is Windows-only there.
#![cfg_attr(target_os = "macos", allow(dead_code))]

use crate::log::DiagnosticsLog;
use parking_lot::Mutex;
use std::process::Command;
use std::sync::OnceLock;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const BACKUP_KEY: &str = r"HKCU\Software\Aether\ProxyBackup";
/// مقصدهایی که هرگز نباید از پروکسی بروند (شبکهٔ محلی و خود لوپ‌بک).
const BYPASS: &str = "localhost;127.*;10.*;172.16.*;192.168.*;<local>";
#[derive(Clone, Debug)]
struct SavedProxy {
    server: Option<String>,
    override_list: Option<String>,
    enable: Option<String>,
    auto_config: Option<String>,
}

fn saved_proxy() -> &'static Mutex<Option<SavedProxy>> {
    static CELL: OnceLock<Mutex<Option<SavedProxy>>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(None))
}

/// فعال‌سازی پروکسی سیستمی روی پل محلی. `true` یعنی ثبت شد.
#[cfg(not(target_os = "macos"))]
pub fn enable(http_port: u16, socks_port: u16) -> bool {
    // Snapshot every value we touch exactly once. Disabling ProxyEnable is not
    // restoration: it destroys the user's previous proxy/PAC configuration.
    let mut saved = saved_proxy().lock();
    if saved.is_none() {
        *saved = Some(SavedProxy {
            server: reg_read("ProxyServer"),
            override_list: reg_read("ProxyOverride"),
            enable: reg_read("ProxyEnable"),
            auto_config: reg_read("AutoConfigURL"),
        });
    }
    if let Some(previous) = saved.as_ref() {
        let _ = reg(&["add", BACKUP_KEY, "/f"]);
        backup_write("ProxyServer", previous.server.as_deref());
        backup_write("ProxyOverride", previous.override_list.as_deref());
        backup_write("ProxyEnable", previous.enable.as_deref());
        backup_write("AutoConfigURL", previous.auto_config.as_deref());
        backup_write("AetherActive", Some("REG_DWORD\t1"));
    }
    drop(saved);
    let server = proxy_string(http_port, socks_port);
    let ok = reg(&[
        "add",
        KEY,
        "/v",
        "ProxyServer",
        "/t",
        "REG_SZ",
        "/d",
        &server,
        "/f",
    ]) && reg(&[
        "add",
        KEY,
        "/v",
        "ProxyOverride",
        "/t",
        "REG_SZ",
        "/d",
        BYPASS,
        "/f",
    ]) && reg(&[
        "add",
        KEY,
        "/v",
        "ProxyEnable",
        "/t",
        "REG_DWORD",
        "/d",
        "1",
        "/f",
    ]);
    if !ok {
        // Never leave a half-written proxy configuration behind.
        let _ = disable();
        return false;
    }
    broadcast_change();
    if ok {
        DiagnosticsLog::i(
            "sysproxy",
            &format!("System proxy enabled -> {server} (bypass: {BYPASS})"),
        );
    } else {
        DiagnosticsLog::e(
            "sysproxy",
            "Could not write the system proxy registry values.",
        );
    }
    ok
}

/// Recover only an interrupted Aether session. A normal app launch must not
/// disable an unrelated user proxy, PAC, VPN, or enterprise configuration.
#[cfg(not(target_os = "macos"))]
pub fn recover_stale() -> bool {
    let has_backup = load_persistent_backup().is_some();
    let points_to_aether = reg_read("ProxyServer")
        .map(|v| v.contains("127.0.0.1:10811"))
        .unwrap_or(false);
    if has_backup || points_to_aether {
        disable()
    } else {
        true
    }
}

/// غیرفعال‌سازی پروکسی سیستمی — در قطع اتصال، خطا و خروج برنامه صدا زده می‌شود.
#[cfg(not(target_os = "macos"))]
pub fn disable() -> bool {
    let snapshot = saved_proxy().lock().take().or_else(load_persistent_backup);
    let had_snapshot = snapshot.is_some();
    let ok = match snapshot {
        Some(previous) => {
            restore_value("ProxyServer", previous.server)
                && restore_value("ProxyOverride", previous.override_list)
                && restore_value("ProxyEnable", previous.enable)
                && restore_value("AutoConfigURL", previous.auto_config)
        }
        None => {
            // Crash recovery for builds that predate the persistent backup:
            // only touch a proxy that unmistakably points at Aether's bridge.
            let stale = reg_read("ProxyServer")
                .map(|v| v.contains("127.0.0.1:10811"))
                .unwrap_or(false);
            if stale {
                reg(&[
                    "add",
                    KEY,
                    "/v",
                    "ProxyEnable",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "0",
                    "/f",
                ]) && reg_delete("ProxyServer")
                    && reg_delete("ProxyOverride")
            } else {
                true
            }
        }
    };
    if ok && had_snapshot {
        let _ = reg(&["delete", BACKUP_KEY, "/f"]);
    }
    broadcast_change();
    if ok {
        DiagnosticsLog::i(
            "sysproxy",
            "System proxy settings restored to their pre-Aether state.",
        );
    } else {
        DiagnosticsLog::e(
            "sysproxy",
            "Could not fully restore the pre-Aether system proxy settings.",
        );
    }
    ok
}

/// رشتهٔ پروکسی WinINET به شکل «به‌ازای پروتکل».
/// HTTP/HTTPS از پل HTTP می‌روند و SOCKS5 برای برنامه‌هایی که آن را می‌فهمند.
fn proxy_string(http_port: u16, socks_port: u16) -> String {
    format!("http=127.0.0.1:{http_port};https=127.0.0.1:{http_port};socks=127.0.0.1:{socks_port}")
}

fn backup_write(name: &str, value: Option<&str>) {
    if let Some(value) = value {
        let _ = reg(&[
            "add", BACKUP_KEY, "/v", name, "/t", "REG_SZ", "/d", value, "/f",
        ]);
    }
}

fn load_persistent_backup() -> Option<SavedProxy> {
    if reg_read_backup("AetherActive").is_none() {
        return None;
    }
    Some(SavedProxy {
        server: reg_read_backup("ProxyServer"),
        override_list: reg_read_backup("ProxyOverride"),
        enable: reg_read_backup("ProxyEnable"),
        auto_config: reg_read_backup("AutoConfigURL"),
    })
}

fn reg_read_backup(name: &str) -> Option<String> {
    let output = reg_output(&["query", BACKUP_KEY, "/v", name])?;
    output.lines().find_map(|line| {
        let t = line.trim();
        if !t.starts_with(name) {
            return None;
        }
        let mut p = t[name.len()..].split_whitespace();
        let kind = p.next()?;
        Some(format!("{}\t{}", kind, p.collect::<Vec<_>>().join(" ")))
    })
}

fn reg_read(name: &str) -> Option<String> {
    let output = reg_output(&["query", KEY, "/v", name])?;
    output.lines().find_map(|line| {
        let t = line.trim();
        if !t.starts_with(name) {
            return None;
        }
        let mut parts = t[name.len()..].split_whitespace();
        let kind = parts.next()?;
        let value = parts.collect::<Vec<_>>().join(" ");
        Some(format!("{kind}\t{value}"))
    })
}

fn restore_value(name: &str, encoded: Option<String>) -> bool {
    match encoded {
        Some(raw) => {
            let mut parts = raw.splitn(2, '\t');
            let kind = parts.next().unwrap_or("REG_SZ");
            let value = parts.next().unwrap_or("");
            reg(&["add", KEY, "/v", name, "/t", kind, "/d", value, "/f"])
        }
        None => reg(&["delete", KEY, "/v", name, "/f"]) || reg_missing_ok(),
    }
}

fn reg_missing_ok() -> bool {
    true
}

fn reg_delete(name: &str) -> bool {
    reg(&["delete", KEY, "/v", name, "/f"]) || reg_missing_ok()
}

fn reg_output(args: &[&str]) -> Option<String> {
    let mut cmd = Command::new(
        std::path::Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join("System32")
            .join("reg.exe"),
    );
    cmd.args(args);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn reg(args: &[&str]) -> bool {
    let mut cmd = Command::new(
        std::path::Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
            .join("System32")
            .join("reg.exe"),
    );
    cmd.args(args);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.status().map(|s| s.success()).unwrap_or(false)
}

/// به WinINET اعلام می‌کند تنظیمات پروکسی عوض شد تا برنامه‌های باز (مرورگرها)
/// بدون ری‌استارت آن را بردارند — بدون این فراخوان، تغییر تا اجرای بعدی
/// برنامه‌ها دیده نمی‌شد.
#[cfg(windows)]
fn broadcast_change() {
    const INTERNET_OPTION_REFRESH: u32 = 37;
    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    #[link(name = "wininet")]
    extern "system" {
        fn InternetSetOptionW(
            hinternet: *mut core::ffi::c_void,
            dwoption: u32,
            lpbuffer: *mut core::ffi::c_void,
            dwbufferlength: u32,
        ) -> i32;
    }
    unsafe {
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null_mut(),
            0,
        );
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null_mut(),
            0,
        );
    }
}

#[cfg(not(windows))]
fn broadcast_change() {}

#[cfg(target_os = "macos")]
pub use mac::{disable, enable, recover_stale};

/// macOS: the same three proxies, set with `networksetup` on every enabled
/// network service that has a real device (Wi-Fi, Ethernet…). The previous
/// values go to disk first, so a crash is still restored on the next launch.
#[cfg(target_os = "macos")]
mod mac {
    use super::DiagnosticsLog;
    use serde::{Deserialize, Serialize};
    use std::path::PathBuf;
    use std::process::Command;

    const KINDS: [&str; 3] = ["webproxy", "securewebproxy", "socksfirewallproxy"];
    const BYPASS: [&str; 6] = [
        "localhost",
        "127.0.0.1",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "*.local",
    ];

    #[derive(Serialize, Deserialize)]
    struct Proxy {
        kind: String,
        enabled: bool,
        server: String,
        port: String,
    }

    #[derive(Serialize, Deserialize)]
    struct Service {
        name: String,
        proxies: Vec<Proxy>,
        bypass: Vec<String>,
    }

    fn ns(args: &[&str]) -> Option<String> {
        let out = Command::new("/usr/sbin/networksetup").args(args).output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn backup_path() -> PathBuf {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("Library/Application Support/studio.cluvex.aether.desktop/sysproxy-backup.json")
    }

    /// `(1) Wi-Fi` / `(Hardware Port: Wi-Fi, Device: en1)` pairs; disabled
    /// services are `(*) Name`, VPN services have an empty device.
    fn services() -> Vec<String> {
        parse_services(&ns(&["-listnetworkserviceorder"]).unwrap_or_default())
    }

    fn parse_services(order: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut current: Option<String> = None;
        for line in order.lines() {
            match line.strip_prefix('(').and_then(|r| r.split_once(") ")) {
                Some((idx, name)) if idx.bytes().all(|b| b.is_ascii_digit()) => {
                    current = Some(name.to_string());
                }
                _ => {
                    if let (Some(name), Some(dev)) = (current.take(), line.split("Device: ").nth(1)) {
                        if !dev.trim_end_matches(')').trim().is_empty() {
                            names.push(name);
                        }
                    }
                }
            }
        }
        names
    }

    fn read(svc: &str, kind: &str) -> Option<Proxy> {
        let out = ns(&[&format!("-get{kind}"), svc])?;
        let field = |k: &str| {
            out.lines()
                .find_map(|l| l.strip_prefix(k))
                .unwrap_or("")
                .trim()
                .to_string()
        };
        Some(Proxy {
            kind: kind.to_string(),
            enabled: field("Enabled:") == "Yes",
            server: field("Server:"),
            port: field("Port:"),
        })
    }

    fn read_bypass(svc: &str) -> Vec<String> {
        // "There aren't any bypass domains set on …" is the empty answer.
        ns(&["-getproxybypassdomains", svc])
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.contains(' '))
            .map(String::from)
            .collect()
    }

    fn set_bypass(svc: &str, domains: &[&str]) -> bool {
        let mut args = vec!["-setproxybypassdomains", svc];
        args.extend(if domains.is_empty() { &["Empty"][..] } else { domains });
        ns(&args).is_some()
    }

    pub fn enable(http_port: u16, socks_port: u16) -> bool {
        let path = backup_path();
        // An existing backup is the user's real state from an interrupted
        // session; snapshotting again would capture Aether's own values.
        if !path.exists() {
            let snapshot: Vec<Service> = services()
                .into_iter()
                .map(|name| Service {
                    proxies: KINDS.iter().filter_map(|k| read(&name, k)).collect(),
                    bypass: read_bypass(&name),
                    name,
                })
                .collect();
            let written = path
                .parent()
                .map(std::fs::create_dir_all)
                .unwrap_or(Ok(()))
                .and_then(|_| std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap_or_default()));
            if let Err(e) = written {
                DiagnosticsLog::e("sysproxy", &format!("Could not back up the proxy settings ({e})."));
                return false;
            }
        }
        let mut ok = false;
        for svc in services() {
            let mut this = set_bypass(&svc, &BYPASS);
            for (kind, port) in KINDS.iter().zip([http_port, http_port, socks_port]) {
                this &= ns(&[&format!("-set{kind}"), &svc, "127.0.0.1", &port.to_string()]).is_some();
            }
            ok |= this;
        }
        if !ok {
            let _ = disable();
            DiagnosticsLog::e("sysproxy", "networksetup could not set the system proxy.");
            return false;
        }
        DiagnosticsLog::i(
            "sysproxy",
            &format!("System proxy enabled -> http/https 127.0.0.1:{http_port}, socks 127.0.0.1:{socks_port}"),
        );
        true
    }

    pub fn disable() -> bool {
        let path = backup_path();
        let Some(snapshot) = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<Service>>(&b).ok())
        else {
            return true;
        };
        let mut ok = true;
        for svc in &snapshot {
            for p in &svc.proxies {
                if !p.server.is_empty() {
                    ok &= ns(&[&format!("-set{}", p.kind), &svc.name, &p.server, &p.port]).is_some();
                }
                if p.server.is_empty() || !p.enabled {
                    ok &= ns(&[&format!("-set{}state", p.kind), &svc.name, "off"]).is_some();
                }
            }
            let bypass: Vec<&str> = svc.bypass.iter().map(String::as_str).collect();
            ok &= set_bypass(&svc.name, &bypass);
        }
        if ok {
            let _ = std::fs::remove_file(&path);
            DiagnosticsLog::i("sysproxy", "System proxy settings restored to their pre-Aether state.");
        } else {
            DiagnosticsLog::e("sysproxy", "Could not fully restore the pre-Aether system proxy settings.");
        }
        ok
    }

    pub fn recover_stale() -> bool {
        !backup_path().exists() || disable()
    }

    #[test]
    fn parse_services_keeps_enabled_hardware_services() {
        let order = "An asterisk (*) denotes that a network service is disabled.\n\
            (1) Ethernet\n(Hardware Port: Ethernet, Device: en0)\n\n\
            (2) Wi-Fi (Home)\n(Hardware Port: Wi-Fi, Device: en1)\n\n\
            (*) Thunderbolt Bridge\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n\n\
            (3) V2BOX\n(Hardware Port: hossin.asaadi.V2Box, Device: )\n";
        assert_eq!(parse_services(order), ["Ethernet", "Wi-Fi (Home)"]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_string_covers_http_https_and_socks() {
        let s = proxy_string(10811, 10810);
        assert!(s.contains("http=127.0.0.1:10811"));
        assert!(s.contains("https=127.0.0.1:10811"));
        assert!(s.contains("socks=127.0.0.1:10810"));
    }

    /// لوپ‌بک و شبکهٔ محلی هرگز نباید از پروکسی بروند.
    #[test]
    fn bypass_keeps_loopback_and_lan_direct() {
        for needle in ["localhost", "127.*", "<local>"] {
            assert!(BYPASS.contains(needle));
        }
    }
}
