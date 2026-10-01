use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// Service-provided 256-bit HMAC key. No getter, Debug or serialization.
pub struct FingerprintKey(Zeroizing<[u8; 32]>);
impl FingerprintKey {
    /// Copy a secret-store key and wipe the input. Keep this key stable while
    /// reservations exist; rotating it requires a separate migration protocol.
    pub fn from_bytes(bytes: &mut [u8; 32]) -> Self {
        let key = Self(Zeroizing::new(*bytes));
        bytes.zeroize();
        key
    }
    pub(crate) fn fingerprint(&self, scope: &str, gate: &str, value: &[u8]) -> String {
        hex(&self.digest(
            b"cglb/uniqueness/v1",
            &[scope.as_bytes(), gate.as_bytes(), value],
        ))
    }
    pub(crate) fn person_id(&self, scope: &str, subject: &crate::Subject) -> [u8; 32] {
        self.digest(
            b"cglb/cpsd-person/v1",
            &[scope.as_bytes(), subject.as_str().as_bytes()],
        )
    }
    pub(crate) fn check_id(
        &self,
        scope: &str,
        subject: &crate::Subject,
        gate: &str,
        provider: &str,
        check: &crate::CheckId,
    ) -> crate::CheckId {
        crate::CheckId(hex(&self.digest(
            b"cglb/provider-check/v1",
            &[
                scope.as_bytes(),
                subject.as_str().as_bytes(),
                gate.as_bytes(),
                provider.as_bytes(),
                check.as_str().as_bytes(),
            ],
        )))
    }
    fn digest(&self, domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.0.as_ref()).expect("HMAC accepts a 32-byte key");
        mac.update(domain);
        for field in fields {
            mac.update(&(field.len() as u64).to_be_bytes());
            mac.update(field);
        }
        mac.finalize().into_bytes().into()
    }
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(result, "{b:02x}").expect("writing to a String cannot fail");
    }
    result
}

#[cfg(test)]
#[path = "tests/fingerprint.rs"]
mod tests;
