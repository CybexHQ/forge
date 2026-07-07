const REDACTION: &str = "[REDACTED]";
const SENSITIVE_VALUE_KEYS: &[&str] = &[
    "secret-key=",
    "secret_key=",
    "password=",
    "passwd=",
    "secret=",
    "token=",
    "api-key=",
    "api_key=",
    "apikey=",
    "private-key=",
    "private_key=",
    "authorization=",
    "bearer ",
];

pub(crate) fn contains_sensitive_key_value(text: &str) -> bool {
    next_sensitive_key(text).is_some()
}

pub(crate) fn redact_sensitive_key_values(text: &str) -> String {
    let mut remaining = text;
    let mut redacted = String::with_capacity(text.len());

    while let Some((position, key_len)) = next_sensitive_key(remaining) {
        redacted.push_str(&remaining[..position]);
        redacted.push_str(&remaining[position..position + key_len]);
        redacted.push_str(REDACTION);

        let value = &remaining[position + key_len..];
        let end = sensitive_value_end(value);
        remaining = &value[end..];
    }

    redacted.push_str(remaining);
    redacted
}

fn next_sensitive_key(text: &str) -> Option<(usize, usize)> {
    let lower = text.to_ascii_lowercase();
    SENSITIVE_VALUE_KEYS
        .iter()
        .filter_map(|key| lower.find(key).map(|position| (position, key.len())))
        .min_by_key(|(position, _)| *position)
}

fn sensitive_value_end(value: &str) -> usize {
    value
        .find(|ch: char| ch.is_whitespace() || ch == '&')
        .unwrap_or(value.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_sensitive_key_values_without_leaking_suffixes() {
        let redacted = redact_sensitive_key_values(
            "copy file:///cache?secret-key=/tmp/cache.key&compression=zstd token=abc password=hunter2",
        );

        assert_eq!(
            redacted,
            "copy file:///cache?secret-key=[REDACTED]&compression=zstd token=[REDACTED] password=[REDACTED]"
        );
        assert!(!redacted.contains("/tmp/cache.key"));
        assert!(!redacted.contains("abc"));
        assert!(!redacted.contains("hunter2"));
    }

    #[test]
    fn redacts_case_insensitive_keys() {
        let redacted = redact_sensitive_key_values("Secret=abc TOKEN=def");

        assert_eq!(redacted, "Secret=[REDACTED] TOKEN=[REDACTED]");
    }

    #[test]
    fn redacts_api_key_and_bearer_shapes() {
        let redacted = redact_sensitive_key_values(
            "curl -H 'Authorization: Bearer eyJhbGci' https://x/?api_key=k1&apikey=k2 private_key=pk",
        );

        assert!(!redacted.contains("eyJhbGci"));
        assert!(!redacted.contains("k1"));
        assert!(!redacted.contains("k2"));
        assert!(!redacted.contains("pk"));
    }
}
