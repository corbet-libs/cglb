use crate::{Error, Result, validate_id};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, future::Future};
use zeroize::Zeroizing;

/// Authenticated opaque global identity. Never a community pseudonym or address.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct Subject(String);
impl Subject {
    /// Validate a service-assigned identifier, 1–128 ASCII graphic bytes.
    pub fn new(id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        validate_id(&id)?;
        Ok(Self(id))
    }
    /// Borrow the private global identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for Subject {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
impl std::fmt::Debug for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Subject([redacted])")
    }
}
/// Explicit runtime boundary in addition to the compile-time test-gate feature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Reject every development gate and development gate policy.
    Production,
    /// Permit the opt-in synthetic gate in isolated development deployments.
    #[cfg(feature = "development-gate")]
    Development,
}
/// One required gate and trusted provider in a signed global policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatePolicy {
    /// cpsd gate identifier.
    pub gate: String,
    /// Enabled provider identifier.
    pub provider: String,
    /// Whether canonical evidence must reserve a uniqueness fingerprint.
    pub uniqueness: bool,
}
/// Signed settings payload accepted from the configured policy authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Wire format version; currently one.
    pub version: u32,
    /// Fixed global service scope.
    pub scope: String,
    /// Strictly increasing authority revision.
    pub revision: u64,
    /// Epoch must exceed even locally advanced suspension epochs.
    pub epoch: u64,
    /// Common inclusive passport and global-gate expiry, in Unix seconds.
    pub shared_expiry: u64,
    /// All these gates are required; at least one must establish uniqueness.
    pub gates: Vec<GatePolicy>,
}
/// Global gate result without raw evidence or trust scores.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateResult {
    /// Gate identifier.
    pub gate: String,
    /// Always global.
    pub level: Level,
    /// Private, authenticated global subject.
    pub subject: Subject,
    /// Trusted provider identifier.
    pub provider: String,
    /// Actual evidence expiry; issuance never rounds this upward.
    pub valid_until: u64,
}
/// This facade only accepts global results.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// A property of a person, independent of a community.
    Global,
}
/// Transient output of trusted gate code. Never serialized or logged.
pub struct GateEvidence {
    /// Proof expiry selected by the provider, not the member.
    pub valid_until: u64,
    /// Canonical input used immediately for HMAC and then wiped on drop.
    pub uniqueness: Option<Zeroizing<Vec<u8>>>,
}
/// Minimal seam for future global gate leaves. Implementations are trusted code.
///
/// Normalize uniqueness input consistently within the gate, across providers.
/// Verification must authenticate the evidence, bind it to this subject/session,
/// and return no raw data beyond the transient canonical uniqueness input.
pub trait GlobalGate: Send + Sync {
    /// Stable gate identifier, shared across providers.
    fn id(&self) -> &str;
    /// Provider identifier enabled by policy.
    fn provider(&self) -> &str;
    /// True for synthetic adapters; production instances reject them.
    fn development_only(&self) -> bool;
    /// Verify hostile input using the gate leaf's own executing logic.
    fn verify(
        &self,
        subject: &Subject,
        input: &[u8],
        now: u64,
    ) -> impl Future<Output = Result<GateEvidence>> + Send;
}
/// Permanent suspension categories. Legal evidence stays outside this database.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermanentReason {
    /// The service has verified an applicable legal order.
    LegalOrder,
    /// The service has authenticated the holder's self-ban request.
    SelfBan,
}
/// Current suspension, without a history or free-text reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Suspension {
    /// Renewal becomes eligible again at this Unix second.
    Temporary {
        /// Exclusive end of the suspension.
        until: u64,
    },
    /// Irreversible through this API.
    Permanent(PermanentReason),
}
impl Suspension {
    pub(crate) fn active(&self, now: u64) -> bool {
        match self {
            Self::Temporary { until } => now < *until,
            Self::Permanent(_) => true,
        }
    }
}
/// Private administrative revocation entry. Never distribute to communities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    /// Global identity, accessible only to the authenticated global service.
    pub subject: Subject,
    /// Current suspension.
    pub suspension: Suspension,
}
/// Signed public view for authenticated epoch and issuer-key distribution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    /// Wire version, currently one.
    pub version: u32,
    /// Global scope.
    pub scope: String,
    /// Effective epoch, including suspension bumps.
    pub epoch: u64,
    /// Authority's current policy revision.
    pub policy_revision: u64,
    /// Common inclusive expiry for the current passport cohort.
    pub shared_expiry: u64,
    /// cpsd's canonical public-key encoding; no holder identifiers.
    pub issuer_public_key: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct State {
    pub policy: Policy,
    pub epoch: u64,
}
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Account {
    pub tag: Option<Vec<u8>>,
    pub gates: BTreeMap<String, GateResult>,
    pub fingerprints: BTreeMap<String, String>,
    pub warned: bool,
    pub suspension: Option<Suspension>,
}
impl Account {
    pub(crate) fn eligible(&self, now: u64) -> Result<()> {
        if self.suspension.as_ref().is_some_and(|s| s.active(now)) {
            Err(Error::Suspended)
        } else {
            Ok(())
        }
    }
}
#[derive(Serialize, Deserialize)]
pub(crate) struct Pending {
    pub subject: Subject,
    pub epoch: u64,
    pub issuer: Vec<u8>,
    pub deadline: u64,
}
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Binding {
    pub issuer: Vec<u8>,
    pub fingerprint_key_check: String,
}
