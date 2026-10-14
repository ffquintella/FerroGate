//! The acceptance policy for an allowlist body (F19 §6.2): signature and
//! freshness, then the host binding, trust domain and generation rules
//! against what this host already holds. Pure functions over their inputs,
//! so every rejection is unit-tested.

use ferro_crypto::composite::CompositePublicKey;

use super::state::SyncState;
use crate::helper::allowlist::{Allowlist, AllowlistError};

/// Why a body was refused. The current allowlist stays in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// The response or the envelope did not parse.
    Malformed,
    /// The signature did not verify under `allowlist.key` and the v2 context.
    BadSignature,
    /// The body names another host.
    WrongHost,
    /// The body names another trust domain than the host's SVID.
    TrustDomain,
    /// The generation is below the held one.
    Rollback,
    /// The generation equals the held one but the entries differ.
    GenerationConflict,
    /// Past its `not_after`.
    Expired,
    /// Issued in the future (beyond the clock-skew leeway).
    NotYetValid,
    /// Older than `allowlist.max_age_secs`.
    TooOld,
    /// No `allowlist.key` to verify with.
    NoKey,
    /// A v1 body offered while a v2 generation is held.
    Downgrade,
}

impl RejectReason {
    /// The stable opcode (audit `reason`, status, logs).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::BadSignature => "bad_signature",
            Self::WrongHost => "wrong_host",
            Self::TrustDomain => "trust_domain",
            Self::Rollback => "rollback",
            Self::GenerationConflict => "generation_conflict",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::TooOld => "too_old",
            Self::NoKey => "no_key",
            Self::Downgrade => "downgrade",
        }
    }

    /// The reason for a load failure.
    #[must_use]
    pub fn of_load(e: &AllowlistError) -> Self {
        match e {
            AllowlistError::BadSignature | AllowlistError::MalformedSignature => Self::BadSignature,
            AllowlistError::Expired => Self::Expired,
            AllowlistError::NotYetValid => Self::NotYetValid,
            AllowlistError::TooOld => Self::TooOld,
            AllowlistError::Cbor(_) | AllowlistError::MalformedEntry => Self::Malformed,
        }
    }
}

/// A refusal, with the refused body's generation when it parsed (0 otherwise)
/// for the `AllowlistSyncRejected` audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejection {
    /// Why.
    pub reason: RejectReason,
    /// Generation of the refused body, 0 when unknown.
    pub generation: u64,
}

impl Rejection {
    const fn new(reason: RejectReason, generation: u64) -> Self {
        Self { reason, generation }
    }
}

/// What a body is checked against.
#[derive(Debug, Clone, Copy)]
pub struct Expectations<'a> {
    /// This host's UUID; `None` when unknown (a v2 body is then refused).
    pub host_uuid: Option<&'a str>,
    /// The SVID's trust domain, when known.
    pub trust_domain: Option<&'a str>,
    /// The held v2 generation, if any.
    pub held: Option<&'a SyncState>,
}

/// Verify a `SyncAllowlist` body: a v2 envelope under the v2 context, fresh,
/// then [`admit`]. `served_generation` is the response's `generation`, which
/// must equal the body's.
pub fn verify_synced(
    envelope: &[u8],
    trusted: &CompositePublicKey,
    expect: &Expectations<'_>,
    served_generation: u64,
    now: i64,
    max_age_secs: i64,
) -> Result<Allowlist, Rejection> {
    let allowlist = Allowlist::load_v2(envelope, trusted, now, max_age_secs)
        .map_err(|e| Rejection::new(RejectReason::of_load(&e), 0))?;
    let generation = allowlist.generation().unwrap_or(0);
    if generation != served_generation {
        return Err(Rejection::new(RejectReason::Malformed, generation));
    }
    admit(&allowlist, expect, true)?;
    Ok(allowlist)
}

/// Whether an already-verified allowlist may be put in force on this host:
///
/// - a v2 body must name this host (and, when known, its trust domain); with
///   no known host it is refused (fail closed);
/// - its generation must not be below the held one, and an equal generation
///   must carry the held entries digest;
/// - with `refuse_downgrade`, a v1 body is refused while a v2 generation is
///   held (the sync is on, so v1 could only roll approvals back).
pub fn admit(
    allowlist: &Allowlist,
    expect: &Expectations<'_>,
    refuse_downgrade: bool,
) -> Result<(), Rejection> {
    let Some(generation) = allowlist.generation() else {
        return if refuse_downgrade && expect.held.is_some() {
            Err(Rejection::new(RejectReason::Downgrade, 0))
        } else {
            Ok(())
        };
    };
    let reject = |reason| Err(Rejection::new(reason, generation));
    if expect
        .host_uuid
        .is_none_or(|h| allowlist.host_uuid() != Some(h))
    {
        return reject(RejectReason::WrongHost);
    }
    if expect
        .trust_domain
        .is_some_and(|td| allowlist.trust_domain() != td)
    {
        return reject(RejectReason::TrustDomain);
    }
    if let Some(held) = expect.held {
        if generation < held.generation {
            return reject(RejectReason::Rollback);
        }
        if generation == held.generation && allowlist.entries_digest() != held.digest() {
            return reject(RejectReason::GenerationConflict);
        }
    }
    Ok(())
}
