//! Calendar dates and durations for display and for the date filters, in UTC.
//!
//! The implementation moved to `ferrogate_admin_client::timefmt` (shared with
//! the tray admin client, T283); this module keeps the TUI's paths.

pub use ferrogate_admin_client::timefmt::{age, clock, date, datetime, parse_date, DAY};

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
