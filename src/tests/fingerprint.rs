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
