//! Shared Go-style duration string parsing (`"5m"`, `"1h30m"`, etc.).
//!
//! Used both for the per-CR `spec.syncInterval` field and for operator-level
//! vault cache refresh intervals configured via environment variables.

use std::time::Duration;

/// Parse a Go-style duration string supporting `ns`, `us`/`µs`, `ms`, `s`, `m`, `h` units.
///
/// Units may be combined (`"1h30m"`). An empty string is an error here — callers that
/// want an empty string to mean "use the default" should check for it before calling.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration string".to_string());
    }

    let mut total_secs: u64 = 0;
    let mut remaining = s;

    while !remaining.is_empty() {
        // Read number.
        let num_end = remaining
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(remaining.len());
        if num_end == 0 {
            return Err(format!("unexpected char in duration {s:?}"));
        }
        let num: u64 = remaining[..num_end]
            .parse()
            .map_err(|_| format!("invalid number in duration {s:?}"))?;
        remaining = &remaining[num_end..];

        // Read unit.
        if remaining.is_empty() {
            return Err(format!("missing unit in duration {s:?}"));
        }
        let (unit, rest) = if let Some(r) = remaining.strip_prefix("ns") {
            ("ns", r)
        } else if let Some(r) = remaining.strip_prefix("µs") {
            ("us", r)
        } else if let Some(r) = remaining.strip_prefix("us") {
            ("us", r)
        } else if let Some(r) = remaining.strip_prefix("ms") {
            ("ms", r)
        } else if let Some(r) = remaining.strip_prefix('s') {
            ("s", r)
        } else if let Some(r) = remaining.strip_prefix('m') {
            ("m", r)
        } else if let Some(r) = remaining.strip_prefix('h') {
            ("h", r)
        } else {
            return Err(format!(
                "unknown unit in duration {s:?}: {:?}",
                &remaining[..1]
            ));
        };

        let secs = match unit {
            "ns" => 0,
            "us" => 0,
            "ms" => 0,
            "s" => num,
            "m" => num * 60,
            "h" => num * 3600,
            _ => unreachable!(),
        };
        total_secs = total_secs.saturating_add(secs);
        remaining = rest;
    }

    Ok(Duration::from_secs(total_secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_5m() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn test_parse_duration_1h() {
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_duration_1h30m() {
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
    }

    #[test]
    fn test_parse_duration_30s() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn test_parse_duration_empty_is_error() {
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("5x").is_err());
    }
}
