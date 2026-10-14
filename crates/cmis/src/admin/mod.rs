//! Administrator authentication and authorization (feature F20, ADR-0005).
//!
//! Wave A of F20 Phase 0. Implemented here: local admin accounts with Argon2id
//! passwords and a mandatory TOTP second factor; opaque, IP-bound sessions with
//! idle and absolute expiry, step-up and server-side revocation; NRM §5.3.5
//! progressive login throttling; group-only RBAC through one method → access
//! table ([`authz::METHOD_ACCESS`]) enforced by a tower layer on every listener
//! ([`layer::AdminAuthLayer`]) and re-checked by every admin handler
//! ([`authz::require`]); bootstrap of the first account; and the
//! `ferrogate.admin.v1.Admin` service ([`service::AdminSvc`]).
//!
//! Wave B adds the FIDO2 / WebAuthn second factor: the relying-party
//! verifier ([`webauthn`]), the factor policy, ceremonies, clone detection
//! and factor-management RPCs ([`factors`]), and the
//! `CMIS_ADMIN_TRAY_FIDO2_GROUPS` policy.
//!
//! Wave C authenticates the host method `AppendAuditEvent` with the F19 §7.1
//! host proof; that lives outside this module, in [`crate::host_auth`],
//! because it authenticates hosts, not administrators.
//!
//! F19 adds the application-approval operations ([`apps`]): listings,
//! approve, deny, edit, revoke, the lineage freeze and the single-step
//! direct registration, all behind the same table and guard.

pub(crate) mod codec;

pub mod apps;
pub mod authz;
pub mod bootstrap;
pub mod clock;
pub mod config;
pub mod factors;
pub mod keys;
pub mod layer;
pub mod password;
pub mod service;
pub mod session;
pub mod state;
pub mod throttle;
pub mod totp;
pub mod webauthn;

pub use authz::{AdminAuthz, AdminContext, Permission};
pub use config::AdminConfig;
pub use layer::{AdminAuthLayer, ListenerKind};
pub use service::AdminSvc;
pub use state::AdminState;
