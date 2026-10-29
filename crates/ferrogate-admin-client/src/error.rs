//! Failures, reduced to what a UI may show (F20 §13a): the status code, the
//! server's stable reason made inert, and no credential detail. Every
//! credential failure is the same [`ClientError::Rejected`] (F20 §6).

use crate::display::inert;
use crate::webauthn::AuthenticatorError;

/// A gRPC failure: status code, the server's stable reason (inert, at most
/// 64 characters), the offending field and the `retry-after` hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    /// gRPC status code.
    pub code: tonic::Code,
    /// Reason string from the server, made inert.
    pub reason: String,
    /// `x-ferrogate-field`, made inert, when present.
    pub field: Option<String>,
    /// `retry-after` seconds, when present.
    pub retry_after: Option<u64>,
}

impl RpcError {
    /// Build from a status.
    #[must_use]
    pub fn from_status(s: &tonic::Status) -> Self {
        let meta = |k: &str| {
            s.metadata()
                .get(k)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        Self {
            code: s.code(),
            reason: inert(s.message(), 64),
            field: meta("x-ferrogate-field").map(|f| inert(&f, 64)),
            retry_after: meta("retry-after").and_then(|v| v.parse().ok()),
        }
    }

    /// A local failure that never reached the server.
    #[must_use]
    pub fn local(code: tonic::Code, reason: &str) -> Self {
        Self {
            code,
            reason: inert(reason, 160),
            field: None,
            retry_after: None,
        }
    }

    /// The server asked for a fresh second factor.
    #[must_use]
    pub fn is_step_up_required(&self) -> bool {
        self.code == tonic::Code::FailedPrecondition && self.reason == "step_up_required"
    }

    /// The session is gone (expired, revoked, IP mismatch, …).
    #[must_use]
    pub fn is_session_invalid(&self) -> bool {
        self.code == tonic::Code::Unauthenticated && self.reason == "session_invalid"
    }
}

/// Why a sign-in or step-up did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// The admin listener could not be reached, or failed the pin check;
    /// nothing was sent.
    Connect(String),
    /// Any credential failure (one generic message, F20 §6).
    Rejected,
    /// Throttled: retry after this many seconds (F20 §8).
    Throttled(u64),
    /// The chosen second factor is not offered to this account from this
    /// client (F20 §5 policy); the credentials were wiped unsent.
    FactorNotOffered,
    /// The security key did not answer (cancelled, absent, unsupported).
    Authenticator(AuthenticatorError),
    /// No session, or the server ended it (`session_invalid`).
    SessionEnded,
    /// Another server error.
    Other(RpcError),
}

impl ClientError {
    /// Classify the failure of a credential exchange (`Login`, `StepUp`):
    /// every `UNAUTHENTICATED` other than a dead session is "rejected".
    #[must_use]
    pub fn from_credential_status(s: &tonic::Status) -> Self {
        let e = RpcError::from_status(s);
        match e.code {
            _ if e.is_session_invalid() => Self::SessionEnded,
            tonic::Code::Unauthenticated => Self::Rejected,
            tonic::Code::ResourceExhausted => Self::Throttled(e.retry_after.unwrap_or(60)),
            _ => Self::Other(e),
        }
    }

    /// Whether the call reported a deadline (the channel is then redialled).
    #[must_use]
    pub fn is_deadline(&self) -> bool {
        matches!(self, Self::Other(e) if e.code == tonic::Code::DeadlineExceeded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_are_classified_and_made_inert() {
        let e = RpcError::from_status(&tonic::Status::failed_precondition("step_up_required"));
        assert!(e.is_step_up_required());
        let mut s = tonic::Status::invalid_argument("bad\u{1b}[2Jvalue");
        s.metadata_mut()
            .insert("x-ferrogate-field", "terms.note".parse().unwrap());
        let e = RpcError::from_status(&s);
        assert_eq!(e.reason, "bad\\x1b[2Jvalue");
        assert_eq!(e.field.as_deref(), Some("terms.note"));
    }

    #[test]
    fn credential_failures_are_generic() {
        let c = |s: tonic::Status| ClientError::from_credential_status(&s);
        assert_eq!(
            c(tonic::Status::unauthenticated("invalid_credentials")),
            ClientError::Rejected
        );
        assert_eq!(
            c(tonic::Status::unauthenticated("anything else")),
            ClientError::Rejected
        );
        assert_eq!(
            c(tonic::Status::unauthenticated("session_invalid")),
            ClientError::SessionEnded
        );
        let mut t = tonic::Status::resource_exhausted("login_throttled");
        t.metadata_mut()
            .insert("retry-after", "90".parse().unwrap());
        assert_eq!(c(t), ClientError::Throttled(90));
        assert_eq!(
            c(tonic::Status::resource_exhausted("login_throttled")),
            ClientError::Throttled(60)
        );
        assert!(c(tonic::Status::deadline_exceeded("timeout")).is_deadline());
    }
}
