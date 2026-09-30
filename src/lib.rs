//! Global gates, unique identities, suspension and blind passports for cvld.
//! Native service facade; see the README and implemented contract for its trust boundary.
#![forbid(unsafe_code)]
#[cfg(feature = "development-gate")]
pub mod development;
mod facade;
mod fingerprint;
pub mod storage;
mod types;
pub use facade::{Global, Limits};
pub use fingerprint::FingerprintKey;
pub use types::*;
/// Exact leaf versions used by this facade, for service and holder composition.
pub use {cpsd, crlt, csgn};

/// Result with privacy-preserving errors; no raw evidence or identifiers.
pub type Result<T> = std::result::Result<T, Error>;
/// Rejections never include raw request data, identifiers or backend messages.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid identifier shape.
    #[error("invalid identifier")]
    InvalidIdentifier,
    /// Time outside the cpsd timestamp range or a caller bound.
    #[error("invalid time")]
    InvalidTime,
    /// Invalid, stale or incorrectly scoped signed policy.
    #[error("invalid policy")]
    Policy,
    /// Policy has not been installed.
    #[error("policy missing")]
    NoPolicy,
    /// Signature, key, kind or authenticated validity failed.
    #[error("signature rejected")]
    Signature,
    /// Persisted key identity differs from this service instance.
    #[error("service key binding mismatch")]
    KeyMismatch,
    /// A development-only gate reached a production boundary.
    #[error("development gate disabled")]
    DevelopmentDisabled,
    /// Gate/provider not enabled by policy.
    #[error("gate disabled")]
    GateDisabled,
    /// Gate evidence is absent, stale, or does not reach the shared expiry.
    #[error("gate requirements not satisfied")]
    Gates,
    /// Another account already owns the uniqueness input or issuer tag.
    #[error("identity already claimed")]
    Duplicate,
    /// Existing account cannot switch its established uniqueness input.
    #[error("uniqueness input changed")]
    UniquenessChanged,
    /// Holder changed the secret used for the established issuer tag.
    #[error("holder secret changed")]
    HolderChanged,
    /// No account exists for this authenticated subject.
    #[error("unknown subject")]
    UnknownSubject,
    /// Account currently cannot obtain a passport.
    #[error("subject suspended")]
    Suspended,
    /// Temporary suspension requires a preceding warning.
    #[error("warning required")]
    WarningRequired,
    /// Missing, expired, reused or incorrectly bound challenge.
    #[error("invalid challenge")]
    Challenge,
    /// Outstanding challenge or page limit reached.
    #[error("capacity reached")]
    Capacity,
    /// The cpsd proof or issuance request is invalid.
    #[error("passport proof rejected")]
    Passport,
    /// Concurrent change; reread and retry a fresh operation.
    #[error("concurrent state change")]
    Conflict,
    /// Storage failed; remote outcomes may be uncertain.
    #[error("storage operation failed")]
    Storage,
    /// Persisted data cannot be decoded.
    #[error("invalid stored data")]
    Encoding,
    /// Revision or epoch cannot advance without wrapping.
    #[error("counter exhausted")]
    Exhausted,
}
pub(crate) fn validate_id(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 128 || !value.bytes().all(|b| b.is_ascii_graphic()) {
        Err(Error::InvalidIdentifier)
    } else {
        Ok(())
    }
}
pub(crate) fn time(value: u64) -> Result<()> {
    if value == 0 || value >= cpsd::TIME_LIMIT {
        Err(Error::InvalidTime)
    } else {
        Ok(())
    }
}
