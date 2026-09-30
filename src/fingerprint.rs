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
mod tests {
    use super::*;
    #[test]
    fn independent_hmac_vector_and_domain_separation() {
        let mut seed = [9; 32];
        let key = FingerprintKey::from_bytes(&mut seed);
        assert_eq!(seed, [0; 32]);
        let fingerprint = key.fingerprint("global", "development", b"synthetic-a");
        assert_eq!(
            fingerprint,
            "6070b5bdd7f8ab5ed68bbac5e08e4e43d3e5aa93a657824a7b9b44dca5de26e0"
        );
        assert_ne!(
            fingerprint,
            key.fingerprint("other", "development", b"synthetic-a")
        );
        assert_ne!(
            fingerprint,
            key.fingerprint("global", "other", b"synthetic-a")
        );
        assert_ne!(
            key.fingerprint("a", "bc", b"d"),
            key.fingerprint("ab", "c", b"d")
        );
        assert_ne!(
            fingerprint,
            FingerprintKey::from_bytes(&mut [8; 32]).fingerprint(
                "global",
                "development",
                b"synthetic-a"
            )
        );
    }
}
