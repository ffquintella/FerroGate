//! A blocking client for the local MIA helper API (features F08, F19).
//!
//! An application on a FerroGate host asks the MIA for short-lived, DPoP-bound
//! child tokens over a local socket (a Unix Domain Socket on Linux and macOS,
//! a named pipe on Windows). The MIA identifies the application from the
//! kernel — never from anything sent here — and mints only for binaries on
//! the host's signed allowlist.
//!
//! The update flow F19 §7.6 describes:
//!
//! ```no_run
//! # fn main() -> Result<(), ferrogate_sdk_rust::helper::HelperError> {
//! use ferrogate_sdk_rust::helper::{self, HelperError, LocalState, RegistrationResp};
//!
//! match helper::request_token("https://api.example.com", "dpop-jkt", 300) {
//!     Ok(token) => println!("token expires at {}", token.exp),
//!     Err(HelperError::PermissionDenied) => {
//!         // Not (or no longer) approved: ask for this binary to be approved.
//!         match helper::register_self(Some("needs API access"))? {
//!             RegistrationResp::AlreadyApproved { .. } => { /* retry the token */ }
//!             RegistrationResp::Submitted { state: LocalState::AutoApproved, retry_after, .. } => {
//!                 // The agent is syncing its allowlist; retry after `retry_after` s.
//!                 let _ = retry_after;
//!             }
//!             other => println!("waiting for approval: {other:?}"),
//!         }
//!     }
//!     Err(e) => return Err(e),
//! }
//! # Ok(()) }
//! ```
//!
//! A token refusal stays non-informative (no oracle): registration answers
//! only about the caller's own requests.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use mia_helper_proto::{
    format_id, parse_id, ChildToken, ErrorCode, LocalRequestStatus, LocalState, RegErrorCode,
    RegistrationResp, DEFAULT_ENDPOINT, ID_LEN,
};
use mia_helper_proto::{HelperFrame, HelperOp, HelperReq, HelperResp, ProtoError};

/// The environment variable naming the helper endpoint, as for the daemon.
pub const ENDPOINT_ENV: &str = "FERROGATE_HELPER_SOCKET";

/// Default time allowed for the agent's answer. Registration hashes the
/// binary, which takes a few seconds for a large one.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Why a helper call failed.
#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    /// The agent could not be reached (not running, no permission on the
    /// socket, wrong endpoint).
    #[error("cannot reach the MIA helper at {endpoint}: {source}")]
    Unavailable {
        /// The endpoint tried.
        endpoint: String,
        /// The connect error.
        source: std::io::Error,
    },
    /// The agent closed the connection without answering a v2 request: it
    /// predates app registration (helper protocol v2).
    #[error("the MIA agent predates app registration (helper protocol v2); upgrade it")]
    AgentTooOld,
    /// The caller is not authenticated or not on the allowlist.
    #[error("permission denied")]
    PermissionDenied,
    /// The agent refused the token request for another reason.
    #[error("token refused: {code:?}")]
    Refused {
        /// The refusal opcode.
        code: ErrorCode,
        /// Suggested seconds before retrying.
        retry_after: Option<u32>,
    },
    /// The agent refused the registration operation.
    #[error("registration refused: {}", code.as_str())]
    Registration {
        /// The refusal opcode.
        code: RegErrorCode,
        /// Suggested seconds before retrying.
        retry_after: Option<u32>,
    },
    /// I/O or framing failed mid-exchange.
    #[error("helper protocol: {0}")]
    Protocol(String),
}

/// A helper-API client bound to one endpoint.
#[derive(Debug, Clone)]
pub struct HelperClient {
    endpoint: PathBuf,
    timeout: Duration,
}

impl Default for HelperClient {
    /// The well-known endpoint ([`DEFAULT_ENDPOINT`]).
    fn default() -> Self {
        Self::new(DEFAULT_ENDPOINT)
    }
}

impl HelperClient {
    /// A client for `endpoint` (a socket path, or a pipe name on Windows).
    #[must_use]
    pub fn new(endpoint: impl Into<PathBuf>) -> Self {
        Self {
            endpoint: endpoint.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// The endpoint from [`ENDPOINT_ENV`], else [`DEFAULT_ENDPOINT`].
    #[must_use]
    pub fn from_env() -> Self {
        std::env::var_os(ENDPOINT_ENV)
            .filter(|v| !v.is_empty())
            .map_or_else(Self::default, Self::new)
    }

    /// The same client with another answer timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    /// Request a child token for `audience`, bound to the DPoP key whose JWK
    /// thumbprint is `dpop_jkt`, valid for `ttl_secs` (the agent caps it).
    pub fn request_token(
        &self,
        audience: &str,
        dpop_jkt: &str,
        ttl_secs: u32,
    ) -> Result<ChildToken, HelperError> {
        // The v1 shape: understood by every agent version.
        let req = HelperReq {
            audience: audience.to_string(),
            dpop_jkt: dpop_jkt.to_string(),
            ttl_secs,
        };
        match self.exchange::<_, HelperResp>(&req, false)? {
            HelperResp::Token(token) => Ok(token),
            HelperResp::Error {
                code: ErrorCode::PermissionDenied,
                ..
            } => Err(HelperError::PermissionDenied),
            HelperResp::Error { code, retry_after } => {
                Err(HelperError::Refused { code, retry_after })
            }
        }
    }

    /// Ask for the running application's own binary to be approved for the
    /// current user. The answer is the request's state; an
    /// [`RegistrationResp::AlreadyApproved`] means the token request can be
    /// retried at once.
    pub fn register_self(&self, reason: Option<&str>) -> Result<RegistrationResp, HelperError> {
        let op = HelperOp::RegisterSelf {
            client_request_id: new_request_id(),
            reason: reason.map(str::to_string),
        };
        match self.exchange(&HelperFrame::new(op), true)? {
            RegistrationResp::Error { code, retry_after } => {
                Err(HelperError::Registration { code, retry_after })
            }
            other => Ok(other),
        }
    }

    /// The state of the caller's own registration requests (`ids`: local or
    /// CMIS request ids; empty: all of them, newest first).
    pub fn registration_status(
        &self,
        ids: &[[u8; ID_LEN]],
    ) -> Result<Vec<LocalRequestStatus>, HelperError> {
        let op = HelperOp::RequestStatus {
            request_ids: ids.to_vec(),
        };
        match self.exchange(&HelperFrame::new(op), true)? {
            RegistrationResp::Status(items) => Ok(items),
            RegistrationResp::Error { code, retry_after } => {
                Err(HelperError::Registration { code, retry_after })
            }
            other => Err(HelperError::Protocol(format!(
                "unexpected answer {other:?}"
            ))),
        }
    }

    /// One request/response exchange. `v2`: an early close means the agent
    /// predates protocol v2.
    fn exchange<Q: serde::Serialize, A: serde::de::DeserializeOwned>(
        &self,
        request: &Q,
        v2: bool,
    ) -> Result<A, HelperError> {
        let frame = mia_helper_proto::encode_frame(request)
            .map_err(|e| HelperError::Protocol(e.to_string()))?;
        let mut conn = self.connect()?;
        conn.write_all(&frame)
            .and_then(|()| conn.flush())
            .map_err(|e| HelperError::Protocol(e.to_string()))?;
        match mia_helper_proto::read_frame::<_, A>(&mut conn) {
            Ok(answer) => Ok(answer),
            Err(ProtoError::Io(e)) if v2 && e.kind() == std::io::ErrorKind::UnexpectedEof => {
                Err(HelperError::AgentTooOld)
            }
            Err(e) => Err(HelperError::Protocol(e.to_string())),
        }
    }

    #[cfg(unix)]
    fn connect(&self) -> Result<impl Read + Write, HelperError> {
        let stream = std::os::unix::net::UnixStream::connect(&self.endpoint).map_err(|source| {
            HelperError::Unavailable {
                endpoint: self.endpoint.display().to_string(),
                source,
            }
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(Duration::from_secs(10))))
            .map_err(|e| HelperError::Protocol(e.to_string()))?;
        Ok(stream)
    }

    #[cfg(windows)]
    fn connect(&self) -> Result<impl Read + Write, HelperError> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.endpoint)
            .map_err(|source| HelperError::Unavailable {
                endpoint: self.endpoint.display().to_string(),
                source,
            })
    }
}

/// A fresh UUIDv4 idempotency id.
fn new_request_id() -> [u8; ID_LEN] {
    use rand_core::{Rng as _, UnwrapErr};
    let mut out = [0u8; ID_LEN];
    UnwrapErr(getrandom::SysRng).fill_bytes(&mut out);
    mia_helper_proto::uuid_v4(out)
}

/// [`HelperClient::request_token`] on [`HelperClient::from_env`].
pub fn request_token(
    audience: &str,
    dpop_jkt: &str,
    ttl_secs: u32,
) -> Result<ChildToken, HelperError> {
    HelperClient::from_env().request_token(audience, dpop_jkt, ttl_secs)
}

/// [`HelperClient::register_self`] on [`HelperClient::from_env`].
pub fn register_self(reason: Option<&str>) -> Result<RegistrationResp, HelperError> {
    HelperClient::from_env().register_self(reason)
}

/// [`HelperClient::registration_status`] on [`HelperClient::from_env`].
pub fn registration_status(ids: &[[u8; ID_LEN]]) -> Result<Vec<LocalRequestStatus>, HelperError> {
    HelperClient::from_env().registration_status(ids)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use mia_helper_proto::{decode_request, Request};
    use std::os::unix::net::UnixListener;

    /// A one-shot fake agent: answers each connection with `answer(request)`;
    /// `None` closes without answering (an agent older than v2).
    fn fake_agent(
        tag: &str,
        connections: usize,
        answer: impl Fn(Request) -> Option<Vec<u8>> + Send + 'static,
    ) -> (PathBuf, std::thread::JoinHandle<()>) {
        let dir = std::env::temp_dir().join(format!("sdk-helper-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mia.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            for _ in 0..connections {
                let (mut conn, _) = listener.accept().unwrap();
                let body = mia_helper_proto::read_frame_body(&mut conn).unwrap();
                if let Some(reply) = answer(decode_request(&body).unwrap()) {
                    conn.write_all(&reply).unwrap();
                }
            }
        });
        (path, handle)
    }

    fn frame<T: serde::Serialize>(v: &T) -> Vec<u8> {
        mia_helper_proto::encode_frame(v).unwrap()
    }

    #[test]
    fn tokens_are_requested_with_the_v1_shape() {
        let (path, h) = fake_agent("token", 2, |req| {
            let Request::Legacy(req) = req else {
                panic!("expected a v1 request")
            };
            Some(if req.audience == "https://api.example.com" {
                frame(&HelperResp::Token(ChildToken {
                    jws: "a.b.c".into(),
                    exp: 42,
                }))
            } else {
                frame(&HelperResp::Error {
                    code: ErrorCode::PermissionDenied,
                    retry_after: None,
                })
            })
        });
        let client = HelperClient::new(&path);
        let token = client
            .request_token("https://api.example.com", "jkt", 60)
            .unwrap();
        assert_eq!(token.jws, "a.b.c");
        assert!(matches!(
            client.request_token("https://other", "jkt", 60),
            Err(HelperError::PermissionDenied)
        ));
        h.join().unwrap();
    }

    #[test]
    fn register_self_and_status_use_the_v2_envelope() {
        let (path, h) = fake_agent("register", 3, |req| {
            let Request::V2(frame_in) = req else {
                panic!("expected a v2 frame")
            };
            Some(match frame_in.op {
                HelperOp::RegisterSelf { reason, .. } => {
                    assert_eq!(reason.as_deref(), Some("why"));
                    frame(&RegistrationResp::Submitted {
                        request_id: Some([1; 16]),
                        local_id: [2; 16],
                        state: LocalState::Pending,
                        revision: Some(1),
                        approval_id: None,
                        retry_after: None,
                    })
                }
                HelperOp::RequestStatus { request_ids } if request_ids.is_empty() => {
                    frame(&RegistrationResp::Status(vec![]))
                }
                _ => frame(&RegistrationResp::Error {
                    code: RegErrorCode::RateLimited,
                    retry_after: Some(30),
                }),
            })
        });
        let client = HelperClient::new(&path);
        assert!(matches!(
            client.register_self(Some("why")).unwrap(),
            RegistrationResp::Submitted {
                state: LocalState::Pending,
                ..
            }
        ));
        assert_eq!(client.registration_status(&[]).unwrap().len(), 0);
        assert!(matches!(
            client.registration_status(&[[9; 16]]),
            Err(HelperError::Registration {
                code: RegErrorCode::RateLimited,
                retry_after: Some(30)
            })
        ));
        h.join().unwrap();
    }

    #[test]
    fn an_agent_that_drops_v2_frames_is_too_old() {
        let (path, h) = fake_agent("old", 1, |_| None);
        assert!(matches!(
            HelperClient::new(&path).register_self(None),
            Err(HelperError::AgentTooOld)
        ));
        h.join().unwrap();
    }

    #[test]
    fn a_missing_agent_is_unavailable() {
        let client = HelperClient::new("/nonexistent/ferrogate/mia.sock");
        assert!(matches!(
            client.request_token("a", "b", 1),
            Err(HelperError::Unavailable { .. })
        ));
    }
}
