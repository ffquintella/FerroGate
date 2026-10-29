//! The session token's only home (F20 §12): a [`SessionSlot`] shared by the
//! client, the [`Bearer`] interceptor and the UI's [`SessionHandle`].
//!
//! Ending a session (lock, quit) empties the slot at once and moves its
//! epoch, so a token still in flight (a sign-in or step-up answered after the
//! lock) is handed back for logout instead of adopted.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::mpsc;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::service::Interceptor;
use zeroize::Zeroizing;

use crate::secret::SessionToken;

/// The token and its epoch.
struct Slot {
    token: SessionToken,
    epoch: u64,
}

/// The shared session slot. Cloning shares the same slot (it is how the
/// interceptor and the UI handle reach it); the token itself is never cloned.
#[derive(Clone)]
pub struct SessionSlot(Arc<Mutex<Slot>>);

static_assertions::assert_not_impl_any!(SessionSlot: std::fmt::Debug, std::fmt::Display);

impl Default for SessionSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionSlot {
    /// An empty slot at epoch 0.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Slot {
            token: SessionToken::none(),
            epoch: 0,
        })))
    }

    /// Lock the slot. A poisoned lock is still used: wiping must never fail.
    fn lock(&self) -> MutexGuard<'_, Slot> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether a session token is held.
    #[must_use]
    pub fn has_token(&self) -> bool {
        self.lock().token.is_set()
    }

    /// The current epoch (read before a call that may return a token).
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.lock().epoch
    }

    /// Drop the token (the server already ended the session).
    pub fn wipe(&self) {
        self.lock().token = SessionToken::none();
    }

    /// Take the token out and move the epoch: the session is over here.
    #[must_use]
    pub fn end(&self) -> SessionToken {
        let mut s = self.lock();
        s.epoch = s.epoch.wrapping_add(1);
        std::mem::take(&mut s.token)
    }

    /// Keep `token` when no lock or quit happened since `epoch`; otherwise
    /// hand it back so the caller logs it out.
    #[must_use]
    pub fn adopt(&self, token: String, epoch: u64) -> Option<SessionToken> {
        let token = SessionToken::from_server(token);
        let mut s = self.lock();
        if s.epoch == epoch {
            s.token = token;
            None
        } else {
            Some(token)
        }
    }

    /// The interceptor that sends this slot's token.
    #[must_use]
    pub fn bearer(&self) -> Bearer {
        Bearer(self.clone())
    }

    /// The UI's handle: [`SessionHandle::end`] wipes the token at once and
    /// hands the `Logout` to `logout_tx`.
    #[must_use]
    pub fn handle(&self, logout_tx: mpsc::UnboundedSender<SessionToken>) -> SessionHandle {
        SessionHandle {
            slot: self.clone(),
            logout_tx,
        }
    }
}

/// `Bearer <token>`, marked sensitive (never printed by tonic or `http`).
///
/// # Errors
/// `INTERNAL` when the token is not ASCII (the server only issues ASCII).
pub fn bearer_value(token: &SessionToken) -> Result<MetadataValue<Ascii>, tonic::Status> {
    let header = Zeroizing::new(format!("Bearer {}", token.expose()));
    let mut value: MetadataValue<Ascii> = header
        .parse()
        .map_err(|_| tonic::Status::internal("session token is not ASCII"))?;
    value.set_sensitive(true);
    Ok(value)
}

/// Adds `authorization: Bearer <token>` while a session exists.
#[derive(Clone)]
pub struct Bearer(SessionSlot);

impl Interceptor for Bearer {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        let value = {
            let s = self.0.lock();
            if !s.token.is_set() {
                return Ok(req);
            }
            bearer_value(&s.token)?
        };
        req.metadata_mut().insert("authorization", value);
        Ok(req)
    }
}

/// The UI's hold on the session: ends it at once on lock and quit, without
/// waiting for the client (which may be inside an RPC) or the network.
pub struct SessionHandle {
    slot: SessionSlot,
    logout_tx: mpsc::UnboundedSender<SessionToken>,
}

static_assertions::assert_not_impl_any!(SessionHandle: std::fmt::Debug, std::fmt::Display, Clone);

impl SessionHandle {
    /// End the session now: the token leaves the slot (no later RPC carries
    /// it), the epoch moves (a token still in flight is logged out, not
    /// adopted), and the token goes to the logout task. If that task is gone
    /// the token is wiped here.
    pub fn end(&self) {
        let token = self.slot.end();
        // A send error hands the token back inside the error, dropped (and
        // wiped) right here.
        let _ = self.logout_tx.send(token);
    }

    /// Whether a session token is held.
    #[must_use]
    pub fn has_session(&self) -> bool {
        self.slot.has_token()
    }

    /// The slot's current epoch: stamp a request with it when it is queued,
    /// so one queued before an [`SessionHandle::end`] is never sent.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.slot.epoch()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bearer_header_is_sensitive_and_follows_rotation() {
        let slot = SessionSlot::new();
        let mut b = slot.bearer();
        let req = b.call(tonic::Request::new(())).unwrap();
        assert!(req.metadata().get("authorization").is_none());
        assert!(slot.adopt("fgas_abc".into(), slot.epoch()).is_none());
        let req = b.call(tonic::Request::new(())).unwrap();
        let v = req.metadata().get("authorization").unwrap();
        assert_eq!(v, "Bearer fgas_abc");
        assert!(v.is_sensitive());
        assert!(slot.adopt("fgas_def".into(), slot.epoch()).is_none());
        let req = b.call(tonic::Request::new(())).unwrap();
        assert_eq!(
            req.metadata().get("authorization").unwrap(),
            "Bearer fgas_def"
        );
    }

    #[test]
    fn ending_the_session_wipes_at_once_and_a_late_token_is_not_adopted() {
        let slot = SessionSlot::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let handle = slot.handle(tx);
        let epoch = slot.epoch();
        assert!(slot.adopt("fgas_a".into(), epoch).is_none());
        assert!(handle.has_session());
        handle.end();
        assert!(!slot.has_token());
        assert_eq!(rx.try_recv().unwrap().expose(), "fgas_a");
        // Answered after the lock: handed back for logout, never adopted.
        let orphan = slot.adopt("fgas_b".into(), epoch).expect("not adopted");
        assert_eq!(orphan.expose(), "fgas_b");
        assert!(!slot.has_token());
        // Without a logout task the token is wiped right away.
        drop(rx);
        assert!(slot.adopt("fgas_c".into(), slot.epoch()).is_none());
        handle.end();
        assert!(!slot.has_token());
    }
}
