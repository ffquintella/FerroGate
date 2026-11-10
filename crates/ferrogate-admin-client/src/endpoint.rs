//! The admin endpoint (F20 §2): `https://host:port` with an **explicit**
//! port. Without one the transport would dial 8443, the main listener, whose
//! certificate the admin listener shares by default: the pin would match and
//! the password would reach the wrong listener.

use crate::display::inert;

/// The default admin listener (F20 §2).
pub const DEFAULT_ENDPOINT: &str = "https://127.0.0.1:8444";
/// Longest endpoint accepted, in bytes.
pub const MAX_ENDPOINT_LEN: usize = 512;

/// Why [`check_endpoint`] refuses an endpoint, for front ends that word the
/// reason in their own language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointProblem {
    /// Longer than [`MAX_ENDPOINT_LEN`] bytes.
    TooLong,
    /// Not an `https://` URL: admin traffic is never plaintext.
    NotHttps,
    /// Not a valid URL.
    NotUrl,
    /// No host, or user information (`user@host`).
    NoHost,
    /// A path (other than `/`) or a query.
    PathOrQuery,
    /// No explicit, non-zero port.
    NoPort,
}

/// The first reason `endpoint` is not `https://host:port` with an explicit,
/// non-zero port and no user information, path or query; `None` when it is.
#[must_use]
pub fn endpoint_problem(endpoint: &str) -> Option<EndpointProblem> {
    if endpoint.len() > MAX_ENDPOINT_LEN {
        return Some(EndpointProblem::TooLong);
    }
    if !endpoint.starts_with("https://") {
        return Some(EndpointProblem::NotHttps);
    }
    let Ok(uri) = endpoint.parse::<tonic::transport::Uri>() else {
        return Some(EndpointProblem::NotUrl);
    };
    let authority = uri
        .authority()
        .map(tonic::codegen::http::uri::Authority::as_str)
        .unwrap_or_default();
    if authority.contains('@') || uri.host().is_none_or(str::is_empty) {
        return Some(EndpointProblem::NoHost);
    }
    if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
        return Some(EndpointProblem::PathOrQuery);
    }
    match uri.port_u16() {
        Some(p) if p != 0 => None,
        _ => Some(EndpointProblem::NoPort),
    }
}

/// Check an admin endpoint: `https://host:port` with an explicit, non-zero
/// port, no user information, path or query (see [`endpoint_problem`]).
///
/// # Errors
///
/// An operator-facing reason (the endpoint is echoed inert and cut).
pub fn check_endpoint(endpoint: &str) -> Result<(), String> {
    let Some(problem) = endpoint_problem(endpoint) else {
        return Ok(());
    };
    let shown = inert(endpoint, 80);
    Err(match problem {
        EndpointProblem::TooLong => format!(
            "the admin endpoint is longer than {MAX_ENDPOINT_LEN} bytes (got `{shown}`)"
        ),
        EndpointProblem::NotHttps => format!(
            "the admin endpoint must be an https:// URL (got `{shown}`): admin traffic is never plaintext"
        ),
        EndpointProblem::NotUrl => format!("the admin endpoint `{shown}` is not a valid URL"),
        EndpointProblem::NoHost => {
            format!("the admin endpoint `{shown}` needs a host and no user information")
        }
        EndpointProblem::PathOrQuery => {
            format!("the admin endpoint `{shown}` takes no path or query (https://host:port)")
        }
        EndpointProblem::NoPort => format!(
            "the admin endpoint `{shown}` needs an explicit port, e.g. {DEFAULT_ENDPOINT} \
             (the admin listener's default); without one the main listener (8443) would \
             receive your password"
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_endpoint_needs_https_a_host_and_an_explicit_port() {
        assert!(check_endpoint("https://cmis-1:8444").is_ok());
        assert!(check_endpoint("https://[::1]:8444/").is_ok());
        for (bad, why) in [
            ("http://cmis-1:8444", "https://"),
            ("https://cmis-1", "explicit port"),
            ("https://cmis-1:0", "explicit port"),
            ("https://u:p@cmis-1:8444", "user information"),
            ("https://cmis-1:8444/admin", "no path"),
            ("https://cmis-1:8444/?x=1", "no path"),
        ] {
            let e = check_endpoint(bad).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
        let long = format!("https://{}:1", "a".repeat(MAX_ENDPOINT_LEN));
        assert!(check_endpoint(&long).is_err());
    }

    #[test]
    fn each_refusal_has_a_typed_reason() {
        assert_eq!(endpoint_problem("https://cmis-1:8444"), None);
        for (bad, want) in [
            ("http://cmis-1:8444", EndpointProblem::NotHttps),
            ("cmis-1:8444", EndpointProblem::NotHttps),
            ("https://cmis 1:8444", EndpointProblem::NotUrl),
            ("https://u@cmis-1:8444", EndpointProblem::NoHost),
            ("https://cmis-1:8444/admin", EndpointProblem::PathOrQuery),
            ("https://cmis-1:8444?x", EndpointProblem::PathOrQuery),
            ("https://cmis-1", EndpointProblem::NoPort),
        ] {
            assert_eq!(endpoint_problem(bad), Some(want), "{bad}");
        }
        let long = format!("https://{}:1", "a".repeat(MAX_ENDPOINT_LEN));
        assert_eq!(endpoint_problem(&long), Some(EndpointProblem::TooLong));
    }

    #[test]
    fn a_hostile_endpoint_is_echoed_inert() {
        let e = check_endpoint("http://x\u{1b}]52;c;AAAA\u{7}:1").unwrap_err();
        assert!(!e.contains('\u{1b}') && !e.contains('\u{7}'), "{e}");
    }
}
