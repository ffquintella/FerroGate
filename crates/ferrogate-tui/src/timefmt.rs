//! Calendar dates and durations for display and for the date filters, in UTC.
//!
//! Uses the proleptic Gregorian day-number algorithm (H. Hinnant,
//! "chrono-Compatible Low-Level Date Algorithms") so the crate needs no date
//! library. Only dates between years 1970 and 9999 are accepted as input.

/// Seconds per day.
pub const DAY: i64 = 86_400;

/// Days since 1970-01-01 of a civil date.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Civil date of a day number since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (
        y,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

/// Parse `YYYY-MM-DD` (exactly that shape) to the Unix time of its midnight
/// UTC. `None` for anything else, including impossible dates.
#[must_use]
pub fn parse_date(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        let s = text.get(r)?;
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    let y = i64::from(digits(0..4)?);
    let m = digits(5..7)?;
    let d = digits(8..10)?;
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return None;
    }
    Some(days_from_civil(y, m, d) * DAY)
}

/// `YYYY-MM-DD` of a Unix time (UTC).
#[must_use]
pub fn date(unix: i64) -> String {
    let (y, m, d) = civil_from_days(unix.div_euclid(DAY));
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DD HH:MM` of a Unix time (UTC), or `—` for 0 (unset).
#[must_use]
pub fn datetime(unix: i64) -> String {
    if unix == 0 {
        return "—".to_string();
    }
    let secs = unix.rem_euclid(DAY);
    format!(
        "{} {:02}:{:02}",
        date(unix),
        secs / 3600,
        (secs % 3600) / 60
    )
}

/// A compact age such as `45s`, `12m`, `5h`, `3d` (from `then` to `now`).
#[must_use]
pub fn age(now: i64, then: i64) -> String {
    if then == 0 {
        return "—".to_string();
    }
    let s = now.saturating_sub(then).max(0);
    match s {
        0..=59 => format!("{s}s"),
        60..=3_599 => format!("{}m", s / 60),
        3_600..=86_399 => format!("{}h", s / 3_600),
        _ => format!("{}d", s / DAY),
    }
}

/// `mm:ss` of a number of seconds (negative shows as `0:00`).
#[must_use]
pub fn clock(secs: i64) -> String {
    let s = secs.max(0);
    format!("{}:{:02}", s / 60, s % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_round_trip_and_reject_malformed_input() {
        assert_eq!(parse_date("1970-01-01"), Some(0));
        assert_eq!(parse_date("2026-10-14"), Some(1_791_936_000));
        assert_eq!(date(1_791_936_000), "2026-10-14");
        assert_eq!(
            parse_date("2024-02-29").map(date).as_deref(),
            Some("2024-02-29")
        );
        for bad in [
            "2023-02-29",
            "2026-13-01",
            "2026-00-10",
            "2026-1-01",
            "26-10-14",
            "2026/10/14",
            "1969-12-31",
            "２０２６-10-14",
            "",
        ] {
            assert_eq!(parse_date(bad), None, "{bad}");
        }
        assert_eq!(datetime(1_791_936_000 + 3_725), "2026-10-14 01:02");
        assert_eq!(datetime(0), "—");
    }

    #[test]
    fn ages_and_clocks_are_compact() {
        assert_eq!(age(100, 55), "45s");
        assert_eq!(age(10_000, 10_000 - 720), "12m");
        assert_eq!(age(DAY * 3 + 5, 5), "3d");
        assert_eq!(age(5, 0), "—");
        assert_eq!(clock(872), "14:32");
        assert_eq!(clock(-3), "0:00");
    }
}
