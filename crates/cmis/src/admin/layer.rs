//! The tower layer that enforces [`METHOD_ACCESS`](super::authz::METHOD_ACCESS)
//! on every gRPC listener (F20 §7 "Enforcement").
//!
//! For each request it looks the gRPC path up in the table and:
//!
//! - refuses an unclassified path with `PERMISSION_DENIED
//!   (method_not_classified)` (deny by default);
//! - passes public and host-authenticated methods through unchanged;
//! - refuses admin methods on a plaintext listener with `FAILED_PRECONDITION
//!   (tls_required)`;
//! - serves the `Admin` service only on the admin listener, and the legacy
//!   admin RPCs on the main listener only while `CMIS_LEGACY_ADMIN_ON_MAIN`;
//! - for session methods, authenticates and authorizes through
//!   [`AdminAuthz::authorize`] and inserts the resulting [`AdminContext`] into
//!   the request extensions, removing the `authorization` header so the token
//!   never reaches handler code.
//!
//! A tower layer rather than a tonic interceptor: interceptors are
//! synchronous, and session checks need asynchronous store reads (ADR-0005).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tonic::codegen::http;
use tonic::Status;
use tower::{Layer, Service};

use super::authz::{access_for, paths, peer_info, Access, AdminAuthz, AdminContext, SessionRule};

/// Which listener a layer instance guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerKind {
    /// The host-facing listener (`CMIS_LISTEN`).
    Main,
    /// The admin listener (`CMIS_ADMIN_LISTEN`).
    Admin,
}

#[derive(Debug)]
struct LayerConfig {
    authz: Option<Arc<AdminAuthz>>,
    listener: ListenerKind,
    tls: bool,
    legacy_admin_on_main: bool,
    /// Unix time of the last unclassified-method denial written to the audit
    /// log (they are rate-limited: anyone can send unknown paths).
    last_unclassified_audit: AtomicI64,
}

/// Unclassified-method denials reach the WORM audit log at most this often
/// per listener; every one is still logged.
const UNCLASSIFIED_AUDIT_INTERVAL_SECS: i64 = 60;

/// Enforces the method access table; see the module docs.
#[derive(Debug, Clone)]
pub struct AdminAuthLayer {
    cfg: Arc<LayerConfig>,
}

impl AdminAuthLayer {
    /// A layer for one listener. `authz` is `None` when the admin subsystem
    /// failed to start: every admin method then answers `UNAVAILABLE`. `tls`
    /// says whether the listener terminates TLS.
    #[must_use]
    pub fn new(
        authz: Option<Arc<AdminAuthz>>,
        listener: ListenerKind,
        tls: bool,
        legacy_admin_on_main: bool,
    ) -> Self {
        Self {
            cfg: Arc::new(LayerConfig {
                authz,
                listener,
                tls,
                legacy_admin_on_main,
                last_unclassified_audit: AtomicI64::new(i64::MIN),
            }),
        }
    }
}

impl<S> Layer<S> for AdminAuthLayer {
    type Service = AdminAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AdminAuthService {
            inner,
            cfg: Arc::clone(&self.cfg),
        }
    }
}

/// The service produced by [`AdminAuthLayer`].
#[derive(Debug, Clone)]
pub struct AdminAuthService<S> {
    inner: S,
    cfg: Arc<LayerConfig>,
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

impl<S, B> Service<http::Request<B>> for AdminAuthService<S>
where
    S: Service<http::Request<B>, Response = http::Response<tonic::body::Body>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        // The ready service handles this call; leave a fresh clone behind.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let cfg = Arc::clone(&self.cfg);
        Box::pin(async move {
            match admit(&cfg, &mut req).await {
                Ok(()) => inner.call(req).await,
                Err(status) => Ok(status.into_http()),
            }
        })
    }
}

const NO_RULE: SessionRule = SessionRule {
    permission: None,
    step_up: false,
    allow_restricted: false,
    allow_factor_enrollment: false,
};

async fn admit<B>(cfg: &LayerConfig, req: &mut http::Request<B>) -> Result<(), Status> {
    // Only this layer may put an AdminContext into a request.
    req.extensions_mut().remove::<AdminContext>();
    let path = req.uri().path().to_string();
    let Some(access) = access_for(&path) else {
        tracing::warn!(
            event = "admin.authz.unclassified",
            method = %path.chars().take(128).collect::<String>(),
            "call to an unclassified gRPC method refused"
        );
        if let Some(authz) = &cfg.authz {
            // Unauthenticated callers can send any path: keep the WORM audit
            // log from being flooded by recording at most one per interval.
            let now = authz.state().now();
            let last = cfg.last_unclassified_audit.load(Ordering::Relaxed);
            if now.saturating_sub(last) >= UNCLASSIFIED_AUDIT_INTERVAL_SECS
                && cfg
                    .last_unclassified_audit
                    .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                authz.deny(None, &path, NO_RULE, "method_not_classified");
            }
        }
        return Err(Status::permission_denied("method_not_classified"));
    };
    let admin_service = path.starts_with(paths::ADMIN);
    if admin_service && cfg.listener == ListenerKind::Main {
        return Err(Status::unimplemented("admin_listener_only"));
    }
    match access {
        Access::Public | Access::Host => Ok(()),
        Access::AdminPublic => {
            if !cfg.tls {
                return Err(Status::failed_precondition("tls_required"));
            }
            if cfg.authz.is_none() {
                return Err(Status::unavailable("auth_unavailable"));
            }
            Ok(())
        }
        Access::Session(rule) => {
            if !cfg.tls {
                return Err(Status::failed_precondition("tls_required"));
            }
            if cfg.listener == ListenerKind::Main && !cfg.legacy_admin_on_main {
                return Err(Status::unimplemented("admin_listener_only"));
            }
            let authz = cfg
                .authz
                .as_ref()
                .ok_or_else(|| Status::unavailable("auth_unavailable"))?;
            let peer = peer_info(req.extensions());
            let header = req
                .headers_mut()
                .remove(http::header::AUTHORIZATION)
                .map(|v| zeroize::Zeroizing::new(v.as_bytes().to_vec()));
            let ctx = authz
                .authorize(&path, rule, header.as_deref().map(Vec::as_slice), &peer)
                .await?;
            req.extensions_mut().insert(ctx);
            Ok(())
        }
    }
}
