//! The admin channel (F20 §2): only `https://host:port`, only through
//! [`ferro_transport::connect_pinned`] (TLS 1.3, hybrid `X25519MLKEM768`, SPKI
//! pinning). The handshake, and so the pin check, completes before the first
//! RPC: a wrong pin is refused before any username, password or code is sent.

use std::future::Future;
use std::time::Duration;

use ferro_crypto::pin::SpkiPin;
use tonic::transport::Channel;

use crate::display::inert;
use crate::endpoint::check_endpoint;

/// How long dialling (TCP + pinned TLS handshake) may take before the
/// client reports the endpoint unreachable, instead of waiting for the
/// operating system's TCP timeout behind a firewall that drops packets.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default deadline of one admin RPC. A server that stops answering cannot
/// hold a serial client, so a lock's `Logout` never waits longer than this.
pub const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// Run one RPC with a deadline: a server that stops answering yields
/// `DEADLINE_EXCEEDED` instead of holding the caller.
///
/// # Errors
/// The call's own status, or `DEADLINE_EXCEEDED`.
pub async fn within<T>(
    limit: Duration,
    call: impl Future<Output = Result<T, tonic::Status>>,
) -> Result<T, tonic::Status> {
    tokio::time::timeout(limit, call)
        .await
        .unwrap_or_else(|_| Err(tonic::Status::deadline_exceeded("timeout")))
}

/// Dial the admin listener at `endpoint`, pinned to `pins`, within
/// `connect_timeout`.
///
/// # Errors
/// A short, inert reason: a refused endpoint, no pin, no answer in time, or
/// the transport's cause (refused, pin mismatch, no hybrid group).
pub async fn dial(
    endpoint: &str,
    pins: &[SpkiPin],
    connect_timeout: Duration,
) -> Result<Channel, String> {
    check_endpoint(endpoint)?;
    if pins.is_empty() {
        return Err("the admin endpoint needs an SPKI pin".into());
    }
    let connect = ferro_transport::connect_pinned(endpoint, pins.to_vec());
    tokio::time::timeout(connect_timeout, connect)
        .await
        .map_err(|_| format!("no answer within {connect_timeout:?} (endpoint unreachable?)"))?
        .map_err(|e| inert(&format!("{e:#}"), 160))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_call_that_never_answers_meets_its_deadline() {
        let never = std::future::pending::<Result<(), tonic::Status>>();
        let e = within(Duration::from_millis(20), never).await.unwrap_err();
        assert_eq!(e.code(), tonic::Code::DeadlineExceeded);
    }

    #[tokio::test]
    async fn plaintext_portless_or_unpinned_endpoints_are_never_dialled() {
        let pin = [SpkiPin::from_hex(&"a".repeat(96)).unwrap()];
        let e = dial("http://127.0.0.1:1", &pin, CONNECT_TIMEOUT)
            .await
            .unwrap_err();
        assert!(e.contains("https://"), "{e}");
        let e = dial("https://127.0.0.1", &pin, CONNECT_TIMEOUT)
            .await
            .unwrap_err();
        assert!(e.contains("explicit port"), "{e}");
        let e = dial("https://127.0.0.1:1", &[], CONNECT_TIMEOUT)
            .await
            .unwrap_err();
        assert!(e.contains("SPKI pin"), "{e}");
    }
}
