//! Parser for `nix --log-format internal-json` output.
//!
//! Nix emits one JSON event per stderr line, prefixed with `@nix `. We track
//! build/substitution activities to derive real progress (done/expected
//! derivation counts plus the derivation currently building) and re-render the
//! events as a human-readable log equivalent to `--print-build-logs` output.
//! Unknown or malformed lines pass through verbatim so no output is ever lost.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

const NIX_JSON_PREFIX: &str = "@nix ";

// Activity types (nix src/libutil/logging.hh).
const ACT_COPY_PATH: u64 = 100;
const ACT_COPY_PATHS: u64 = 103;
const ACT_BUILDS: u64 = 104;
const ACT_BUILD: u64 = 105;
// Result types.
const RES_BUILD_LOG_LINE: u64 = 101;
const RES_PROGRESS: u64 = 105;
const RES_SET_EXPECTED: u64 = 106;
const RES_POST_BUILD_LOG_LINE: u64 = 107;
// Default nix verbosity is `info`; start/msg events above this level are
// suppressed from the rendered log, matching non-JSON output.
const LVL_INFO: u64 = 3;

#[derive(Debug, Deserialize)]
struct NixJsonEvent {
    action: String,
    #[serde(default)]
    id: u64,
    #[serde(rename = "type", default)]
    activity_type: u64,
    #[serde(default)]
    level: u64,
    #[serde(default)]
    text: String,
    #[serde(default)]
    msg: String,
    #[serde(default)]
    fields: Vec<Value>,
}

#[derive(Debug)]
struct Activity {
    activity_type: u64,
    build_name: String,
}

/// Aggregate progress derived from the event stream so far.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuildProgressSnapshot {
    pub builds_expected: u64,
    pub builds_done: u64,
    pub builds_running: u64,
    pub fetches_expected: u64,
    pub fetches_done: u64,
    pub current_build: Option<String>,
}

impl BuildProgressSnapshot {
    /// Percent within `range` (e.g. 25..=79 for the Pulse "building" phase)
    /// plus a status message, or `None` until the stream has produced
    /// something more informative than the static phase label.
    pub fn progress_update(&self, range_start: i32, range_end: i32) -> Option<(i32, String)> {
        let span = (range_end - range_start).max(0) as u64;
        if self.builds_expected > 0 || self.builds_done > 0 || self.builds_running > 0 {
            let expected = self
                .builds_expected
                .max(self.builds_done + self.builds_running)
                .max(1);
            let done = self.builds_done.min(expected);
            let percent = range_start + (span * done / expected) as i32;
            let mut message = format!("Built {done}/{expected} derivations");
            if let Some(current) = self.current_build.as_deref() {
                message.push_str(&format!(" · building {current}"));
                if self.builds_running > 1 {
                    message.push_str(&format!(" (+{} more)", self.builds_running - 1));
                }
            }
            return Some((percent.clamp(range_start, range_end), message));
        }
        if self.fetches_expected > 0 || self.fetches_done > 0 {
            let expected = self.fetches_expected.max(self.fetches_done).max(1);
            let done = self.fetches_done.min(expected);
            let percent = range_start + (span * done / expected) as i32;
            let message = format!("Fetched {done}/{expected} store paths from cache");
            return Some((percent.clamp(range_start, range_end), message));
        }
        None
    }
}

/// Stateful line-by-line parser for one `internal-json` stream.
///
/// Progress is taken from two redundant sources and merged with `max`: the
/// `resProgress [done, expected, running, failed]` events nix emits on its
/// aggregate "builds"/"copy paths" activities (authoritative when present),
/// and our own count of started/stopped per-derivation activities (fallback).
#[derive(Debug, Default)]
pub struct InternalJsonParser {
    activities: HashMap<u64, Activity>,
    build_start_order: Vec<u64>,
    observed_builds_done: u64,
    observed_fetches_done: u64,
    reported_builds_done: u64,
    reported_builds_expected: u64,
    reported_fetches_done: u64,
    reported_fetches_expected: u64,
}

impl InternalJsonParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> BuildProgressSnapshot {
        let builds_running = self.build_start_order.len() as u64;
        let builds_done = self.reported_builds_done.max(self.observed_builds_done);
        let fetches_done = self.reported_fetches_done.max(self.observed_fetches_done);
        BuildProgressSnapshot {
            builds_expected: self.reported_builds_expected,
            builds_done,
            builds_running,
            fetches_expected: self.reported_fetches_expected,
            fetches_done,
            current_build: self
                .build_start_order
                .iter()
                .rev()
                .find_map(|id| self.activities.get(id))
                .map(|activity| activity.build_name.clone()),
        }
    }

    /// Consume one line of stderr. Returns the human-readable rendering of the
    /// line, or `None` when the event carries no displayable text.
    pub fn feed_line(&mut self, line: &str) -> Option<String> {
        let Some(payload) = line.strip_prefix(NIX_JSON_PREFIX) else {
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                return None;
            }
            return Some(trimmed.to_string());
        };
        let Ok(event) = serde_json::from_str::<NixJsonEvent>(payload) else {
            // Never drop output we cannot interpret.
            return Some(line.trim_end().to_string());
        };
        match event.action.as_str() {
            "start" => self.handle_start(event),
            "stop" => self.handle_stop(event),
            "result" => self.handle_result(event),
            "msg" => {
                let msg = event.msg.trim_end();
                (event.level <= LVL_INFO && !msg.is_empty()).then(|| msg.to_string())
            }
            _ => None,
        }
    }

    fn handle_start(&mut self, event: NixJsonEvent) -> Option<String> {
        let build_name = if event.activity_type == ACT_BUILD {
            let name = event
                .fields
                .first()
                .and_then(Value::as_str)
                .map(derivation_display_name)
                .unwrap_or_default();
            self.build_start_order.push(event.id);
            name
        } else {
            String::new()
        };
        self.activities.insert(
            event.id,
            Activity {
                activity_type: event.activity_type,
                build_name,
            },
        );
        let text = event.text.trim_end();
        (event.level <= LVL_INFO && !text.is_empty()).then(|| text.to_string())
    }

    fn handle_stop(&mut self, event: NixJsonEvent) -> Option<String> {
        if let Some(activity) = self.activities.remove(&event.id) {
            match activity.activity_type {
                ACT_BUILD => self.observed_builds_done += 1,
                ACT_COPY_PATH => self.observed_fetches_done += 1,
                _ => {}
            }
        }
        self.build_start_order.retain(|id| *id != event.id);
        None
    }

    fn handle_result(&mut self, event: NixJsonEvent) -> Option<String> {
        match event.activity_type {
            RES_BUILD_LOG_LINE | RES_POST_BUILD_LOG_LINE => {
                let line = event.fields.first().and_then(Value::as_str)?;
                let line = line.trim_end();
                if line.is_empty() {
                    return None;
                }
                let prefix = self
                    .activities
                    .get(&event.id)
                    .filter(|activity| !activity.build_name.is_empty())
                    .map(|activity| format!("{}> ", activity.build_name))
                    .unwrap_or_default();
                Some(format!("{prefix}{line}"))
            }
            RES_PROGRESS => {
                let aggregate_type = self
                    .activities
                    .get(&event.id)
                    .map(|activity| activity.activity_type)?;
                let done = event.fields.first().and_then(Value::as_u64)?;
                let expected = event.fields.get(1).and_then(Value::as_u64)?;
                match aggregate_type {
                    ACT_BUILDS => {
                        self.reported_builds_done = self.reported_builds_done.max(done);
                        self.reported_builds_expected = self.reported_builds_expected.max(expected);
                    }
                    ACT_COPY_PATHS => {
                        self.reported_fetches_done = self.reported_fetches_done.max(done);
                        self.reported_fetches_expected =
                            self.reported_fetches_expected.max(expected);
                    }
                    _ => {}
                }
                None
            }
            RES_SET_EXPECTED => {
                let expected_type = event.fields.first().and_then(Value::as_u64)?;
                let expected = event.fields.get(1).and_then(Value::as_u64)?;
                match expected_type {
                    ACT_BUILD => {
                        self.reported_builds_expected = self.reported_builds_expected.max(expected)
                    }
                    ACT_COPY_PATH => {
                        self.reported_fetches_expected =
                            self.reported_fetches_expected.max(expected)
                    }
                    _ => {}
                }
                None
            }
            _ => None,
        }
    }
}

/// `/nix/store/<32-char-hash>-firefox-128.0.drv` → `firefox-128.0`.
pub(crate) fn derivation_display_name(drv_path: &str) -> String {
    let file_name = drv_path.rsplit('/').next().unwrap_or(drv_path);
    let file_name = file_name.strip_suffix(".drv").unwrap_or(file_name);
    match file_name.split_once('-') {
        Some((hash, rest))
            if hash.len() == 32 && hash.bytes().all(|byte| byte.is_ascii_alphanumeric()) =>
        {
            rest.to_string()
        }
        _ => file_name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start_build(parser: &mut InternalJsonParser, id: u64, drv: &str) -> Option<String> {
        parser.feed_line(&format!(
            r#"@nix {{"action":"start","id":{id},"level":3,"parent":0,"text":"building '{drv}'","type":105,"fields":["{drv}","",1,1]}}"#
        ))
    }

    #[test]
    fn passes_through_non_json_lines() {
        let mut parser = InternalJsonParser::new();
        assert_eq!(
            parser.feed_line("warning: something odd"),
            Some("warning: something odd".to_string())
        );
        assert_eq!(parser.feed_line("   "), None);
    }

    #[test]
    fn passes_through_malformed_json_events() {
        let mut parser = InternalJsonParser::new();
        assert_eq!(
            parser.feed_line("@nix {not json"),
            Some("@nix {not json".to_string())
        );
    }

    #[test]
    fn renders_msgs_and_respects_verbosity() {
        let mut parser = InternalJsonParser::new();
        assert_eq!(
            parser.feed_line(r#"@nix {"action":"msg","level":0,"msg":"error: build failed"}"#),
            Some("error: build failed".to_string())
        );
        assert_eq!(
            parser.feed_line(r#"@nix {"action":"msg","level":5,"msg":"chatty detail"}"#),
            None
        );
    }

    #[test]
    fn tracks_build_counts_and_current_build() {
        let mut parser = InternalJsonParser::new();
        parser.feed_line(r#"@nix {"action":"result","id":1,"type":106,"fields":[105,3]}"#);
        let rendered = start_build(
            &mut parser,
            7,
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-firefox-128.0.drv",
        );
        assert_eq!(
            rendered.as_deref(),
            Some("building '/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-firefox-128.0.drv'")
        );
        let snapshot = parser.snapshot();
        assert_eq!(snapshot.builds_expected, 3);
        assert_eq!(snapshot.builds_running, 1);
        assert_eq!(snapshot.current_build.as_deref(), Some("firefox-128.0"));

        parser.feed_line(r#"@nix {"action":"stop","id":7}"#);
        let snapshot = parser.snapshot();
        assert_eq!(snapshot.builds_done, 1);
        assert_eq!(snapshot.builds_running, 0);
        assert_eq!(snapshot.current_build, None);

        let (percent, message) = snapshot.progress_update(25, 79).expect("progress");
        assert_eq!(percent, 25 + (54 / 3));
        assert_eq!(message, "Built 1/3 derivations");
    }

    #[test]
    fn prefixes_build_log_lines_with_derivation_name() {
        let mut parser = InternalJsonParser::new();
        start_build(
            &mut parser,
            9,
            "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-glibc-2.39.drv",
        );
        assert_eq!(
            parser.feed_line(
                r#"@nix {"action":"result","id":9,"type":101,"fields":["configuring"]}"#
            ),
            Some("glibc-2.39> configuring".to_string())
        );
    }

    #[test]
    fn fetch_only_closures_report_fetch_progress() {
        let mut parser = InternalJsonParser::new();
        parser.feed_line(r#"@nix {"action":"result","id":1,"type":106,"fields":[100,10]}"#);
        parser.feed_line(
            r#"@nix {"action":"start","id":4,"level":3,"parent":0,"text":"copying path '/nix/store/x' from 'https://cache'","type":100,"fields":[]}"#,
        );
        parser.feed_line(r#"@nix {"action":"stop","id":4}"#);
        let (percent, message) = parser.snapshot().progress_update(25, 79).expect("progress");
        assert_eq!(percent, 25 + (54 / 10));
        assert_eq!(message, "Fetched 1/10 store paths from cache");
    }

    #[test]
    fn expected_never_drops_below_observed_builds() {
        let mut parser = InternalJsonParser::new();
        for id in 0..4 {
            start_build(
                &mut parser,
                10 + id,
                "/nix/store/cccccccccccccccccccccccccccccccc-pkg-1.0.drv",
            );
            parser.feed_line(&format!(r#"@nix {{"action":"stop","id":{}}}"#, 10 + id));
        }
        let (percent, message) = parser.snapshot().progress_update(25, 79).expect("progress");
        assert_eq!(percent, 79);
        assert_eq!(message, "Built 4/4 derivations");
    }

    // Condensed from a real `nix build --log-format internal-json` (nix 2.26)
    // stream: counts come from resProgress on the aggregate Builds activity
    // (type 104), not from resSetExpected.
    #[test]
    fn replays_real_nix_stream_shape() {
        let mut parser = InternalJsonParser::new();
        let lines = [
            r#"@nix {"action":"msg","level":3,"msg":"this derivation will be built:"}"#,
            r#"@nix {"action":"start","id":47,"level":0,"parent":0,"text":"","type":102}"#,
            r#"@nix {"action":"start","id":48,"level":0,"parent":0,"text":"","type":104}"#,
            r#"@nix {"action":"start","id":49,"level":0,"parent":0,"text":"","type":103}"#,
            r#"@nix {"action":"result","fields":[0,1,0,0],"id":48,"type":105}"#,
            r#"@nix {"action":"result","fields":[101,0],"id":47,"type":106}"#,
            r#"@nix {"action":"start","fields":["/nix/store/z2i2anvj3jlpfmbz9ggalg5qpwz3ag8h-probe.drv","",1,1],"id":51,"level":3,"parent":0,"text":"building '/nix/store/z2i2anvj3jlpfmbz9ggalg5qpwz3ag8h-probe.drv'","type":105}"#,
            r#"@nix {"action":"result","fields":[0,1,1,0],"id":48,"type":105}"#,
            r#"@nix {"action":"result","fields":["hello-from-builder"],"id":51,"type":101}"#,
        ];
        let rendered: Vec<String> = lines
            .iter()
            .filter_map(|line| parser.feed_line(line))
            .collect();
        assert_eq!(
            rendered,
            vec![
                "this derivation will be built:".to_string(),
                "building '/nix/store/z2i2anvj3jlpfmbz9ggalg5qpwz3ag8h-probe.drv'".to_string(),
                "probe> hello-from-builder".to_string(),
            ]
        );
        let snapshot = parser.snapshot();
        assert_eq!(snapshot.builds_expected, 1);
        assert_eq!(snapshot.builds_done, 0);
        assert_eq!(snapshot.builds_running, 1);
        assert_eq!(snapshot.current_build.as_deref(), Some("probe"));
        let (percent, message) = snapshot.progress_update(25, 79).expect("progress");
        assert_eq!(percent, 25);
        assert_eq!(message, "Built 0/1 derivations · building probe");

        parser.feed_line(r#"@nix {"action":"result","fields":[1,1,0,0],"id":48,"type":105}"#);
        parser.feed_line(r#"@nix {"action":"stop","id":51}"#);
        parser.feed_line(r#"@nix {"action":"stop","id":48}"#);
        let (percent, message) = parser.snapshot().progress_update(25, 79).expect("progress");
        assert_eq!(percent, 79);
        assert_eq!(message, "Built 1/1 derivations");
    }

    #[test]
    fn derivation_names_strip_store_hash() {
        assert_eq!(
            derivation_display_name(
                "/nix/store/dddddddddddddddddddddddddddddddd-nixos-system-host-24.11.drv"
            ),
            "nixos-system-host-24.11"
        );
        assert_eq!(derivation_display_name("weird"), "weird");
    }
}
