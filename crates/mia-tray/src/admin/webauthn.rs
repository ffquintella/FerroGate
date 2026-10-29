//! The platform's FIDO2 authenticator for the admin client (F22 §3a).
//!
//! The protocol side — the request, the `clientDataJSON`, the RP ID check —
//! lives in `ferrogate_admin_client::webauthn` behind its `Authenticator`
//! trait. This module only picks the platform backend.

//! No backend ships yet: Windows `webauthn.dll`, macOS AuthenticationServices
//! and Linux CTAP2 over USB HID need native bindings and a hardware key to
//! verify, so [`platform`] returns `None` and the window disables the key
//! button with an explanation (a TOTP code still works unless the server's
//! FIDO2 policy requires a key). Tests drive the flow with a test double.

use std::sync::Arc;

use ferrogate_admin_client::webauthn::Authenticator;

/// The security-key backend of this platform, when one is built in.
#[must_use]
pub fn platform() -> Option<Arc<dyn Authenticator>> {
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_backend_is_claimed_until_one_is_built() {
        assert!(super::platform().is_none());
    }
}
