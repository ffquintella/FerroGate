//! The checks every security-key backend of the admin client (USB HID on
//! macOS and Linux, `webauthn.dll` on Windows) runs on a request before it
//! touches a key: the request must be one this client builds — the admin RP
//! ID, its own origin and `clientDataJSON` hash, user verification required,
//! and every field within the client's `MAX_*` bounds.

use ferrogate_admin_client::webauthn::{
    valid_rp_id, AssertionRequest, AuthenticatorError, CreationRequest, CREATION_TIMEOUT,
    MAX_ALLOW_CREDENTIALS, MAX_CREDENTIAL_ID_LEN, MAX_EXCLUDE_CREDENTIALS, MAX_NAME_LEN,
    MAX_USER_HANDLE_LEN, TIMEOUT_RANGE,
};
use sha2::{Digest as _, Sha256};

fn ids_ok(ids: &[Vec<u8>], most: usize) -> bool {
    ids.len() <= most
        && ids
            .iter()
            .all(|id| !id.is_empty() && id.len() <= MAX_CREDENTIAL_ID_LEN)
}

/// The admin RP ID, its own origin and the hash of its own `clientDataJSON`.
fn bound_to_rp(rp_id: &str, origin: &str, client_data_json: &[u8], hash: &[u8; 32]) -> bool {
    let own: [u8; 32] = Sha256::digest(client_data_json).into();
    valid_rp_id(rp_id) && origin == format!("https://{rp_id}") && own == *hash
}

/// Refuse an assertion request this client would never build.
///
/// # Errors
/// [`AuthenticatorError::BadRequest`].
pub(crate) fn check_assertion(r: &AssertionRequest) -> Result<(), AuthenticatorError> {
    let ok = bound_to_rp(
        &r.rp_id,
        &r.origin,
        &r.client_data_json,
        &r.client_data_hash,
    ) && r.user_verification_required
        && ids_ok(&r.allow_credential_ids, MAX_ALLOW_CREDENTIALS)
        && (TIMEOUT_RANGE.0..=TIMEOUT_RANGE.1).contains(&r.timeout);
    ok.then_some(()).ok_or(AuthenticatorError::BadRequest)
}

/// Refuse a creation request this client would never build.
///
/// # Errors
/// [`AuthenticatorError::BadRequest`].
pub(crate) fn check_creation(r: &CreationRequest) -> Result<(), AuthenticatorError> {
    let ok = r.is_consistent()
        && (1..=MAX_USER_HANDLE_LEN).contains(&r.user_id.len())
        && [&r.rp_name, &r.user_name, &r.display_name]
            .iter()
            .all(|s| s.len() <= MAX_NAME_LEN)
        && ids_ok(&r.exclude_credential_ids, MAX_EXCLUDE_CREDENTIALS)
        && (TIMEOUT_RANGE.0..=CREATION_TIMEOUT).contains(&r.timeout);
    ok.then_some(()).ok_or(AuthenticatorError::BadRequest)
}
