use crate::protected_material::next_modular_password_hash;

const REDACTION: &str = "[REDACTED]";

pub(crate) fn contains_sensitive_key_value(text: &str) -> bool {
    redact_sensitive_key_values(text) != text
}

pub(crate) fn redact_sensitive_key_values(text: &str) -> String {
    let redacted = redact_assignments(text);
    let redacted = redact_quoted_key_values(&redacted);
    let redacted = redact_bearer_values(&redacted);
    let redacted = redact_url_userinfo(&redacted);
    redact_modular_password_hashes(&redacted)
}

fn redact_url_userinfo(text: &str) -> String {
    let mut cursor = 0;
    let mut redacted = String::with_capacity(text.len());

    while let Some(relative_scheme_end) = text[cursor..].find("://") {
        let scheme_end = cursor + relative_scheme_end;
        let authority_start = scheme_end + 3;
        let authority_end = text[authority_start..]
            .find(|ch: char| {
                ch.is_whitespace() || matches!(ch, '/' | '?' | '#' | '\'' | '"' | '`' | ';' | ',')
            })
            .map(|offset| authority_start + offset)
            .unwrap_or(text.len());
        let Some(at_offset) = text[authority_start..authority_end].rfind('@') else {
            redacted.push_str(&text[cursor..authority_start]);
            cursor = authority_start;
            continue;
        };
        let at = authority_start + at_offset;
        redacted.push_str(&text[cursor..authority_start]);
        redacted.push_str(REDACTION);
        redacted.push('@');
        cursor = at + 1;
    }
    redacted.push_str(&text[cursor..]);
    redacted
}

fn redact_assignments(text: &str) -> String {
    let mut remaining = text;
    let mut redacted = String::with_capacity(text.len());

    while let Some((value_start, value_end)) = next_sensitive_assignment(remaining) {
        redacted.push_str(&remaining[..value_start]);
        redacted.push_str(REDACTION);
        remaining = &remaining[value_end..];
    }

    redacted.push_str(remaining);
    redacted
}

fn next_sensitive_assignment(text: &str) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    for (equals, _) in text.match_indices('=') {
        if bytes.get(equals.wrapping_sub(1)) == Some(&b'=') || bytes.get(equals + 1) == Some(&b'=')
        {
            continue;
        }
        let Some(key) = assignment_key(text, equals) else {
            continue;
        };
        if !sensitive_assignment_key(key) {
            continue;
        }

        let mut value_start = equals + 1;
        while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
            value_start += 1;
        }
        if value_start == bytes.len() {
            continue;
        }
        let value_end = sensitive_value_end(text, value_start);
        if value_end > value_start {
            return Some((value_start, value_end));
        }
    }
    None
}

fn redact_quoted_key_values(text: &str) -> String {
    let mut remaining = text;
    let mut redacted = String::with_capacity(text.len());

    while let Some((value_start, value_end)) = next_sensitive_quoted_key_value(remaining) {
        redacted.push_str(&remaining[..value_start]);
        redacted.push_str(REDACTION);
        remaining = &remaining[value_end..];
    }

    redacted.push_str(remaining);
    redacted
}

fn next_sensitive_quoted_key_value(text: &str) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    for (colon, _) in text.match_indices(':') {
        let mut key_end = colon;
        while key_end > 0 && bytes[key_end - 1].is_ascii_whitespace() {
            key_end -= 1;
        }
        if key_end == 0 || !matches!(bytes[key_end - 1], b'\'' | b'"') {
            continue;
        }
        let Some(key) = assignment_key(text, colon) else {
            continue;
        };
        if !sensitive_assignment_key(key) {
            continue;
        }
        let mut value_start = colon + 1;
        while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
            value_start += 1;
        }
        if value_start == bytes.len() {
            continue;
        }
        let value_end = sensitive_value_end(text, value_start);
        if value_end > value_start {
            return Some((value_start, value_end));
        }
    }
    None
}

fn assignment_key(text: &str, equals: usize) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut end = equals;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if end > 0 && matches!(bytes[end - 1], b'\'' | b'"') {
        let quote = bytes[end - 1];
        let start = bytes[..end - 1].iter().rposition(|byte| *byte == quote)?;
        return (start + 1 < end - 1).then_some(&text[start + 1..end - 1]);
    }
    let mut start = end;
    while start > 0
        && (bytes[start - 1].is_ascii_alphanumeric() || matches!(bytes[start - 1], b'_' | b'-'))
    {
        start -= 1;
    }
    (start < end).then_some(&text[start..end])
}

fn sensitive_assignment_key(value: &str) -> bool {
    let canonical = value
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect::<String>();
    [
        "password",
        "passwd",
        "secret",
        "secretkey",
        "token",
        "apikey",
        "privatekey",
        "authorization",
        "credential",
        "credentials",
    ]
    .iter()
    .any(|part| canonical == *part || canonical.ends_with(part))
        || ([
            "password",
            "passwd",
            "secret",
            "token",
            "apikey",
            "privatekey",
            "credential",
        ]
        .iter()
        .any(|part| canonical.contains(part))
            && ["file", "path", "ref", "reference"]
                .iter()
                .any(|suffix| canonical.ends_with(suffix)))
}

fn sensitive_value_end(text: &str, start: usize) -> usize {
    let Some(first) = text[start..].chars().next() else {
        return start;
    };
    if matches!(first, '\'' | '"') {
        let quote_len = first.len_utf8();
        let mut escaped = false;
        for (offset, ch) in text[start + quote_len..].char_indices() {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == first {
                return start + quote_len + offset + ch.len_utf8();
            }
        }
        return text.len();
    }
    text[start..]
        .find(|ch: char| ch.is_whitespace() || matches!(ch, '&' | ';' | ','))
        .map(|offset| start + offset)
        .unwrap_or(text.len())
}

fn redact_bearer_values(text: &str) -> String {
    let mut remaining = text;
    let mut redacted = String::with_capacity(text.len());

    while let Some(start) = remaining.to_ascii_lowercase().find("bearer ") {
        let value_start = start + "bearer ".len();
        redacted.push_str(&remaining[..value_start]);
        let value_end = sensitive_value_end(remaining, value_start);
        if value_end == value_start {
            redacted.push_str(&remaining[value_start..]);
            remaining = "";
            break;
        }
        redacted.push_str(REDACTION);
        remaining = &remaining[value_end..];
    }

    redacted.push_str(remaining);
    redacted
}

fn redact_modular_password_hashes(text: &str) -> String {
    let mut remaining = text;
    let mut redacted = String::with_capacity(text.len());

    while let Some((start, end)) = next_modular_password_hash(remaining) {
        redacted.push_str(&remaining[..start]);
        redacted.push_str(REDACTION);
        remaining = &remaining[end..];
    }

    redacted.push_str(remaining);
    redacted
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD_HASH: &str = "$6$rounds=5000$abcdefghijklmnop$uHL2DmwkR2iK6s.wDbxLW3GxvjJT7qW2rEHemZz3oMlKlfj8JwHc99.FNZrTO4drUslZ0MRyYkBDumQxKdL8q/";

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

    #[test]
    fn redacts_spaced_nix_assignments_and_bare_modular_hashes() {
        let sentinel = "CYBEX_JAMES_PROTECTED_SENTINEL_7f922a";
        let redacted = redact_sensitive_key_values(&format!(
            "users.users.alice.hashedPassword = \"{sentinel}\"; stray {PASSWORD_HASH} done"
        ));

        assert!(redacted.contains("hashedPassword = [REDACTED];"));
        assert!(!redacted.contains(sentinel));
        assert!(!redacted.contains(PASSWORD_HASH));
        assert!(redacted.contains("stray [REDACTED] done"));
    }

    #[test]
    fn redacts_json_credential_values() {
        let sentinel = "CYBEX_JAMES_PROTECTED_SENTINEL_7f922a";
        let redacted = redact_sensitive_key_values(&format!(
            r#"{{"password":"{sentinel}","normal":"visible","access_token":"token-value"}}"#
        ));

        assert!(!redacted.contains(sentinel));
        assert!(!redacted.contains("token-value"));
        assert!(redacted.contains(r#""password":[REDACTED]"#));
        assert!(redacted.contains(r#""normal":"visible""#));
    }

    #[test]
    fn redacts_url_userinfo_without_hiding_the_endpoint() {
        let redacted = redact_sensitive_key_values(
            "fetch https://alice:protected@example.invalid/source and ssh://token@example.invalid/repo",
        );

        assert_eq!(
            redacted,
            "fetch https://[REDACTED]@example.invalid/source and ssh://[REDACTED]@example.invalid/repo"
        );
        assert!(!redacted.contains("alice"));
        assert!(!redacted.contains("protected"));
        assert!(!redacted.contains("token"));
    }
}
