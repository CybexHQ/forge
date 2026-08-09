//! Host utilization sampling (/proc, /sys) for the periodic Pulse report.
//!
//! Manage validates the reported bounds strictly and rejects the whole report
//! on violation, so every value is clamped into the accepted ranges here.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;

const SAMPLE_WINDOW: Duration = Duration::from_millis(500);

#[derive(Clone, Debug, Serialize)]
pub struct HostStats {
    pub cpu_percent: i32,
    pub cpu_cores: i32,
    pub memory_total_bytes: i64,
    pub memory_used_bytes: i64,
    pub network_rx_bytes_per_sec: i64,
    pub network_tx_bytes_per_sec: i64,
    pub network_link_mbps: i32,
    pub uptime_seconds: i64,
}

/// Sample host utilization over a short window. Returns `None` when /proc is
/// unreadable; individual metrics degrade to zero rather than failing the
/// report.
pub async fn sample() -> Option<HostStats> {
    let cpu_first = read_cpu_totals();
    let iface = primary_interface();
    let net_first = iface.as_deref().and_then(read_interface_bytes);
    tokio::time::sleep(SAMPLE_WINDOW).await;
    let cpu_second = read_cpu_totals();
    let net_second = iface.as_deref().and_then(read_interface_bytes);

    let cpu_percent = match (cpu_first, cpu_second) {
        (Some(first), Some(second)) => cpu_busy_percent(first, second),
        _ => 0,
    };
    let (memory_total_bytes, memory_used_bytes) = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .map_or((0, 0), |raw| parse_meminfo(&raw));
    if memory_total_bytes == 0 && cpu_first.is_none() {
        return None;
    }
    let (network_rx_bytes_per_sec, network_tx_bytes_per_sec) = match (net_first, net_second) {
        (Some(first), Some(second)) => rate_per_second(first, second, SAMPLE_WINDOW),
        _ => (0, 0),
    };
    Some(HostStats {
        cpu_percent: cpu_percent.clamp(0, 100),
        cpu_cores: cpu_core_count().clamp(0, 4096),
        memory_total_bytes,
        memory_used_bytes: memory_used_bytes.min(memory_total_bytes),
        network_rx_bytes_per_sec: network_rx_bytes_per_sec.max(0),
        network_tx_bytes_per_sec: network_tx_bytes_per_sec.max(0),
        network_link_mbps: iface
            .as_deref()
            .map(interface_link_mbps)
            .unwrap_or(0)
            .clamp(0, 1_000_000),
        uptime_seconds: read_uptime_seconds().max(0),
    })
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CpuTotals {
    total: u64,
    idle: u64,
}

fn read_cpu_totals() -> Option<CpuTotals> {
    parse_cpu_totals(&std::fs::read_to_string("/proc/stat").ok()?)
}

/// Parse the aggregate `cpu ` line: user nice system idle iowait irq softirq
/// steal. Idle time includes iowait, matching common utilization tooling.
pub fn parse_cpu_totals(stat: &str) -> Option<CpuTotals> {
    let line = stat.lines().find(|line| line.starts_with("cpu "))?;
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|field| field.parse().ok())
        .collect();
    if fields.len() < 4 {
        return None;
    }
    let idle = fields[3] + fields.get(4).copied().unwrap_or(0);
    Some(CpuTotals {
        total: fields.iter().take(8).sum(),
        idle,
    })
}

pub fn cpu_busy_percent(first: CpuTotals, second: CpuTotals) -> i32 {
    let total = second.total.saturating_sub(first.total);
    if total == 0 {
        return 0;
    }
    let idle = second.idle.saturating_sub(first.idle).min(total);
    (((total - idle) as f64 / total as f64) * 100.0).round() as i32
}

fn cpu_core_count() -> i32 {
    std::thread::available_parallelism().map_or(0, |value| value.get() as i32)
}

/// MemTotal and MemTotal - MemAvailable from /proc/meminfo, in bytes.
pub fn parse_meminfo(raw: &str) -> (i64, i64) {
    let field = |name: &str| -> i64 {
        raw.lines()
            .find(|line| line.starts_with(name))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0)
            .saturating_mul(1024)
    };
    let total = field("MemTotal:");
    let available = field("MemAvailable:").min(total);
    (total, total - available)
}

/// Interface of the default IPv4 route (destination 00000000), so throughput
/// and link speed describe the uplink Manage and devices actually use.
fn primary_interface() -> Option<String> {
    let route = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_default_route_interface(&route)
}

pub fn parse_default_route_interface(route: &str) -> Option<String> {
    route
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let iface = fields.next()?;
            let destination = fields.next()?;
            (destination == "00000000").then(|| iface.to_string())
        })
        .next()
}

fn read_interface_bytes(iface: &str) -> Option<(u64, u64)> {
    parse_interface_bytes(&std::fs::read_to_string("/proc/net/dev").ok()?, iface)
}

pub fn parse_interface_bytes(dev: &str, iface: &str) -> Option<(u64, u64)> {
    for line in dev.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix(&format!("{iface}:")) else {
            continue;
        };
        let fields: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|field| field.parse().ok())
            .collect();
        // rx bytes is field 0, tx bytes is field 8 in /proc/net/dev.
        if fields.len() >= 9 {
            return Some((fields[0], fields[8]));
        }
    }
    None
}

fn rate_per_second(first: (u64, u64), second: (u64, u64), window: Duration) -> (i64, i64) {
    let seconds = window.as_secs_f64();
    if seconds <= 0.0 {
        return (0, 0);
    }
    let rate = |before: u64, after: u64| (after.saturating_sub(before) as f64 / seconds) as i64;
    (rate(first.0, second.0), rate(first.1, second.1))
}

/// Negotiated link speed in Mb/s; 0 when the driver does not expose one
/// (virtual interfaces may report -1 or nothing).
fn interface_link_mbps(iface: &str) -> i32 {
    std::fs::read_to_string(Path::new("/sys/class/net").join(iface).join("speed"))
        .ok()
        .and_then(|raw| raw.trim().parse::<i32>().ok())
        .filter(|speed| *speed > 0)
        .unwrap_or(0)
}

fn read_uptime_seconds() -> i64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|raw| raw.split_whitespace().next().map(str::to_string))
        .and_then(|value| value.parse::<f64>().ok())
        .map_or(0, |value| value as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_totals_and_busy_percent() {
        let first = parse_cpu_totals("cpu  100 0 100 700 100 0 0 0 0 0\n").expect("first sample");
        let second = parse_cpu_totals("cpu  200 0 200 1200 200 0 0 0 0 0\n").expect("second");
        // 800 total delta, 600 idle(+iowait) delta -> 25% busy.
        assert_eq!(cpu_busy_percent(first, second), 25);
        assert_eq!(cpu_busy_percent(first, first), 0);
    }

    #[test]
    fn meminfo_reports_used_from_available() {
        let raw = "MemTotal:       16425748 kB\nMemFree:         1000000 kB\nMemAvailable:    8212874 kB\n";
        let (total, used) = parse_meminfo(raw);
        assert_eq!(total, 16425748 * 1024);
        assert_eq!(used, (16425748 - 8212874) * 1024);
    }

    #[test]
    fn meminfo_missing_fields_degrade_to_zero() {
        assert_eq!(parse_meminfo(""), (0, 0));
    }

    #[test]
    fn default_route_interface_is_found() {
        let route =
            "Iface\tDestination\tGateway\nlo\t0000007F\t00000000\neth0\t00000000\t0119770A\n";
        assert_eq!(
            parse_default_route_interface(route).as_deref(),
            Some("eth0")
        );
    }

    #[test]
    fn interface_bytes_parse_rx_and_tx() {
        let dev = "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n";
        assert_eq!(parse_interface_bytes(dev, "eth0"), Some((1000, 2000)));
        assert_eq!(parse_interface_bytes(dev, "eth1"), None);
    }

    #[test]
    fn live_sample_reports_plausible_values() {
        let stats = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(sample())
            .expect("host stats on linux");
        assert!((0..=100).contains(&stats.cpu_percent));
        assert!(stats.memory_total_bytes > 0);
        assert!(stats.memory_used_bytes <= stats.memory_total_bytes);
        assert!(stats.uptime_seconds > 0);
    }
}
