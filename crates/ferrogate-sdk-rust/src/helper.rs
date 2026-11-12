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
    fn exchange<Q, A>(&self, request: &Q, v2: bool) -> Result<A, HelperError>
    where
        Q: serde::Serialize,
        A: serde::de::DeserializeOwned + Send + 'static,
    {
        let frame = mia_helper_proto::encode_frame(request)
            .map_err(|e| HelperError::Protocol(e.to_string()))?;
        let conn = self.connect()?;
        #[cfg(unix)]
        {
            exchange_on(conn, &frame, v2)
        }
        // A synchronous pipe handle has no read timeout: bound the exchange
        // with a helper thread instead.
        #[cfg(windows)]
        {
            let timeout = self.timeout;
            with_deadline(timeout, move || exchange_on(conn, &frame, v2))
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

    /// Open the helper pipe as the documented client contract requires: only
    /// a local `\\.\pipe\` name, desired access `GENERIC_READ |
    /// FILE_WRITE_DATA` (the pipe DACL denies `GENERIC_WRITE` to the client
    /// group), `SECURITY_IDENTIFICATION`, and a short retry while busy.
    #[cfg(windows)]
    fn connect(&self) -> Result<std::fs::File, HelperError> {
        use std::os::windows::fs::OpenOptionsExt as _;
        let unavailable = |source| HelperError::Unavailable {
            endpoint: self.endpoint.display().to_string(),
            source,
        };
        if !is_local_pipe_name(self.endpoint.as_os_str()) {
            return Err(unavailable(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                r"not a local named pipe (expected \\.\pipe\<name>)",
            )));
        }
        let mut attempt = 1;
        loop {
            match std::fs::OpenOptions::new()
                .access_mode(PIPE_CLIENT_DESIRED_ACCESS)
                // std ORs in SECURITY_SQOS_PRESENT.
                .security_qos_flags(SECURITY_IDENTIFICATION)
                .open(&self.endpoint)
            {
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempt < BUSY_ATTEMPTS => {
                    attempt += 1;
                    std::thread::sleep(BUSY_RETRY_DELAY);
                }
                other => return other.map_err(unavailable),
            }
        }
    }
}

/// Write `frame` on `conn` and read one answer. `v2`: an early close means
/// the agent predates protocol v2.
fn exchange_on<S: Read + Write, A: serde::de::DeserializeOwned>(
    mut conn: S,
    frame: &[u8],
    v2: bool,
) -> Result<A, HelperError> {
    conn.write_all(frame)
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

/// Desired access for the Windows helper pipe: `GENERIC_READ |
/// FILE_WRITE_DATA`. Mirrors `ferro_winauth::pipe_acl::PIPE_CLIENT_DESIRED_ACCESS`
/// (pinned by a test) without pulling that FFI crate into applications.
#[cfg_attr(not(windows), allow(dead_code))]
const PIPE_CLIENT_DESIRED_ACCESS: u32 = 0x8000_0002;

/// `SECURITY_IDENTIFICATION`: a server squatting the pipe name may learn who
/// the caller is but never impersonate it. Mirrors `ferro_winauth::pipe_acl`.
#[cfg_attr(not(windows), allow(dead_code))]
const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;

/// `ERROR_PIPE_BUSY`: every instance of the pipe is connected right now.
#[cfg(windows)]
const ERROR_PIPE_BUSY: i32 = 231;

/// Attempts on `ERROR_PIPE_BUSY` before giving up (about one second).
#[cfg(windows)]
const BUSY_ATTEMPTS: u32 = 20;

/// Pause between attempts while the pipe is busy.
#[cfg(windows)]
const BUSY_RETRY_DELAY: Duration = Duration::from_millis(50);

/// Whether `name` is a local pipe `\\.\pipe\<name>` that cannot resolve to a
/// file or a remote host (no `\`, `/`, NUL, `.`/`..`; at most 256 UTF-16
/// units). Mirrors `ferro_winauth::pipe_client::is_local_pipe_name` (pinned
/// by a test): a client handed a file path must not write its frame into it.
#[cfg_attr(not(windows), allow(dead_code))]
fn is_local_pipe_name(name: &std::ffi::OsStr) -> bool {
    const PREFIX: &str = r"\\.\pipe\";
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(prefix) = name.get(..PREFIX.len()) else {
        return false;
    };
    let rest = &name[PREFIX.len()..];
    prefix.eq_ignore_ascii_case(PREFIX)
        && !rest.is_empty()
        && rest != "."
        && rest != ".."
        && !rest.contains(['\\', '/', '\0'])
        && name.encode_utf16().count() <= 256
}

/// Run `f` on a helper thread and give up after `timeout`. On timeout the
/// thread is abandoned; it still owns the pipe handle and ends when the agent
/// closes its end.
#[cfg(any(windows, test))]
fn with_deadline<T: Send + 'static>(
    timeout: Duration,
    f: impl FnOnce() -> Result<T, HelperError> + Send + 'static,
) -> Result<T, HelperError> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("ferrogate-helper-io".into())
        .spawn(move || {
            // The receiver is gone after a timeout; nothing left to tell.
            let _ = tx.send(f());
        })
        .map_err(|e| HelperError::Protocol(e.to_string()))?;
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(HelperError::Protocol(format!(
            "no answer from the MIA helper within {} s",
            timeout.as_secs_f32()
        ))),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(HelperError::Protocol(
            "the helper exchange thread panicked".into(),
        )),
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

/// Tests that run on every platform, so Windows CI covers the exchange logic
/// and the pipe contract too.
#[cfg(test)]
mod portable_tests {
    use super::*;
    use std::io::Cursor;

    /// An in-memory connection: reads `input`, records what is written.
    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_pipe_contract_matches_the_server_dacl() {
        use ferro_winauth::pipe_acl;
        assert_eq!(
            PIPE_CLIENT_DESIRED_ACCESS,
            pipe_acl::PIPE_CLIENT_DESIRED_ACCESS
        );
        assert_eq!(SECURITY_IDENTIFICATION, pipe_acl::SECURITY_IDENTIFICATION);
    }

    #[test]
    fn pipe_names_are_checked_like_the_agent_side_check() {
        for name in [
            r"\\.\pipe\ferrogate-mia",
            r"\\.\PIPE\ferrogate-mia-hml",
            r"\\.\pipe\ferrogate-mia.default",
            "",
            r"C:\ProgramData\FerroGate\allowlist.cbor",
            r"\\server\pipe\ferrogate-mia",
            r"\\?\pipe\ferrogate-mia",
            r"\\.\pipe\",
            r"\\.\pipe\..",
            r"\\.\pipe\..\C:\Windows\win.ini",
            r"\\.\pipe\a/b",
            "/run/ferrogate/mia.sock",
        ] {
            let name = std::ffi::OsStr::new(name);
            assert_eq!(
                is_local_pipe_name(name),
                ferro_winauth::pipe_client::is_local_pipe_name(name),
                "{name:?}"
            );
        }
        assert!(is_local_pipe_name(std::ffi::OsStr::new(DEFAULT_PIPE)));
    }

    /// The Windows default, checked on every platform.
    const DEFAULT_PIPE: &str = r"\\.\pipe\ferrogate-mia";

    #[test]
    fn one_exchange_writes_the_frame_and_decodes_the_answer() {
        let req = HelperReq {
            audience: "https://api.example.com".into(),
            dpop_jkt: "jkt".into(),
            ttl_secs: 60,
        };
        let frame = mia_helper_proto::encode_frame(&req).unwrap();
        let answer = mia_helper_proto::encode_frame(&HelperResp::Token(ChildToken {
            jws: "a.b.c".into(),
            exp: 42,
        }))
        .unwrap();
        let mut conn = Duplex {
            input: Cursor::new(answer),
            output: Vec::new(),
        };
        let resp: HelperResp = exchange_on(&mut conn, &frame, false).unwrap();
        assert!(matches!(resp, HelperResp::Token(t) if t.jws == "a.b.c"));
        assert_eq!(conn.output, frame);
    }

    #[test]
    fn an_early_close_on_a_v2_frame_means_an_old_agent() {
        let conn = Duplex {
            input: Cursor::new(Vec::new()),
            output: Vec::new(),
        };
        let res: Result<RegistrationResp, _> = exchange_on(conn, b"frame", true);
        assert!(matches!(res, Err(HelperError::AgentTooOld)));
    }

    #[test]
    fn a_silent_agent_times_out() {
        let started = std::time::Instant::now();
        let res = with_deadline(Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_secs(5));
            Ok(())
        });
        assert!(matches!(res, Err(HelperError::Protocol(_))));
        assert!(started.elapsed() < Duration::from_secs(4));
    }
}

/// Windows only: a real named pipe, served the way the agent serves it.
#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::ffi::OsString;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// A one-shot fake agent on a fresh pipe: answers the first request with
    /// `answer(request body)`, or stays silent for `None`.
    fn fake_pipe_agent(
        tag: &str,
        answer: impl FnOnce(Vec<u8>) -> Option<Vec<u8>> + Send + 'static,
    ) -> (PathBuf, std::thread::JoinHandle<()>) {
        let name = format!(r"\\.\pipe\ferrogate-sdk-{tag}-{}", std::process::id());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Created before the client dials, so there is no race; default DACL
        // (the test user owns the pipe).
        let mut server = {
            let _guard = rt.enter();
            ferro_winauth::create_server_pipe(&OsString::from(&name), true, None).unwrap()
        };
        let handle = std::thread::spawn(move || {
            rt.block_on(async move {
                server.connect().await.unwrap();
                let mut len = [0u8; 4];
                server.read_exact(&mut len).await.unwrap();
                let mut body = vec![0u8; mia_helper_proto::frame_len(len).unwrap()];
                server.read_exact(&mut body).await.unwrap();
                match answer(body) {
                    Some(reply) => server.write_all(&reply).await.unwrap(),
                    None => tokio::time::sleep(Duration::from_secs(3)).await,
                }
            });
        });
        (PathBuf::from(name), handle)
    }

    #[test]
    fn a_token_is_requested_over_the_pipe() {
        let (pipe, h) = fake_pipe_agent("token", |body| {
            let mia_helper_proto::Request::Legacy(req) =
                mia_helper_proto::decode_request(&body).unwrap()
            else {
                panic!("expected a v1 request")
            };
            assert_eq!(req.audience, "https://api.example.com");
            Some(
                mia_helper_proto::encode_frame(&HelperResp::Token(ChildToken {
                    jws: "a.b.c".into(),
                    exp: 42,
                }))
                .unwrap(),
            )
        });
        let token = HelperClient::new(&pipe)
            .request_token("https://api.example.com", "jkt", 60)
            .unwrap();
        assert_eq!(token.jws, "a.b.c");
        h.join().unwrap();
    }

    #[test]
    fn a_silent_pipe_server_times_out() {
        let (pipe, h) = fake_pipe_agent("silent", |_| None);
        let res = HelperClient::new(&pipe)
            .with_timeout(Duration::from_millis(300))
            .request_token("a", "b", 1);
        assert!(matches!(res, Err(HelperError::Protocol(_))));
        h.join().unwrap();
    }

    #[test]
    fn a_file_endpoint_is_refused_and_left_untouched() {
        let path = std::env::temp_dir().join(format!("sdk-not-a-pipe-{}", std::process::id()));
        std::fs::write(&path, b"keep").unwrap();
        let res = HelperClient::new(&path).request_token("a", "b", 1);
        assert!(matches!(res, Err(HelperError::Unavailable { .. })));
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_missing_pipe_is_unavailable() {
        let res = HelperClient::new(r"\\.\pipe\ferrogate-sdk-absent").request_token("a", "b", 1);
        assert!(matches!(res, Err(HelperError::Unavailable { .. })));
    }
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
