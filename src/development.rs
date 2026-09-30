//! Synthetic gate, compiled only with `development-gate` and refused in production.
use crate::{GateEvidence, GlobalGate, Result, Subject};
use zeroize::Zeroizing;
/// Always-passing gate for isolated development. Its input is a synthetic
/// uniqueness token, not a phone number or real identity attribute.
pub struct DevelopmentGate {
    valid_until: u64,
}
impl DevelopmentGate {
    /// Set the test provider's evidence expiry.
    pub fn new(valid_until: u64) -> Self {
        Self { valid_until }
    }
}
impl GlobalGate for DevelopmentGate {
    fn id(&self) -> &str {
        "development"
    }
    fn provider(&self) -> &str {
        "cglb.test"
    }
    fn development_only(&self) -> bool {
        true
    }
    async fn verify(
        &self,
        _: &crate::CheckId,
        _: &Subject,
        input: &[u8],
        _: u64,
    ) -> Result<GateEvidence> {
        Ok(GateEvidence {
            valid_until: self.valid_until,
            uniqueness: Some(Zeroizing::new(input.to_vec())),
        })
    }
}
