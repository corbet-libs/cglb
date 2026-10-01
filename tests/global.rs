//! Real cryptographic global-facade round trips and adversarial lifecycle tests.
#![cfg(all(feature = "development-gate", cglb_development))]
use cglb::{
    development::DevelopmentGate,
    storage::{LibsqlStore, MemoryStore, Store},
    *,
};
use cpsd::{
    GateId, HolderSecret, KeyId,
    rand::{SeedableRng, rngs::StdRng},
};

const DAY: u64 = 86_400;
const COHORT: u64 = 5 * DAY;
fn check() -> CheckId {
    CheckId::generate(&mut cpsd::rand::rngs::OsRng)
}
fn session(who: &Subject) -> Session {
    Session::authenticated(who.clone(), [7; 32]).unwrap()
}
fn challenges(scope: &str, capacity: usize) -> cpsd::MemoryStore {
    cpsd::MemoryStore::new(cpsd::CommunityId::new(scope.as_bytes()).unwrap(), capacity).unwrap()
}
fn migrations() -> Vec<crlt::Migration<'static>> {
    vec![
        crlt::Migration::new(1, "global", storage::SCHEMA),
        crlt::Migration::new(2, "signing", csgn::SCHEMA),
        crlt::Migration::new(3, "challenges", cpsd::storage::libsql::SCHEMA),
        crlt::Migration::new(
            4,
            "issuer continuity",
            cpsd::storage::libsql::ISSUANCE_SCHEMA,
        ),
        crlt::Migration::new(
            5,
            "unique holders",
            cpsd::storage::libsql::ISSUANCE_UNIQUENESS_SCHEMA,
        ),
    ]
}
fn leaf(db: &crlt::Db, scope: &str) -> cpsd::storage::libsql::LibsqlStore {
    cpsd::storage::libsql::LibsqlStore::new(
        db,
        cpsd::CommunityId::new(scope.as_bytes()).unwrap(),
        20,
    )
    .unwrap()
}
fn subject(id: &str) -> Subject {
    Subject::new(id).unwrap()
}
fn issuer(seed: u64, gates: &[&str]) -> cpsd::IssuerKey {
    cpsd::IssuerKey::generate(
        &mut StdRng::seed_from_u64(seed),
        KeyId::new("shared-key").unwrap(),
        gates.iter().map(|s| GateId::new(*s).unwrap()).collect(),
    )
    .unwrap()
}
fn fingerprint_key(seed: u8) -> FingerprintKey {
    FingerprintKey::from_bytes(&mut [seed; 32])
}
async fn signer<K: csgn::Store>(store: K, scope: &str) -> csgn::PersistentSigner<K> {
    csgn::PersistentSigner::create(
        store,
        format!("cglb:{scope}"),
        csgn::SecretKey::from_seed(&mut [2; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap()
}
async fn authority() -> csgn::PersistentSigner<csgn::MemoryStore> {
    csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "policy-authority",
        csgn::SecretKey::from_seed(&mut [3; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap()
}
fn policy(scope: &str, revision: u64, epoch: u64, shared_expiry: u64) -> Policy {
    Policy {
        version: 1,
        scope: scope.into(),
        revision,
        epoch,
        shared_expiry,
        gates: vec![GatePolicy {
            gate: "development".into(),
            provider: "cglb.test".into(),
            uniqueness: true,
        }],
    }
}
async fn install<S: Store, K: csgn::Store, I: cpsd::IssuanceStore>(
    global: &Global<S, K, I>,
    authority: &mut csgn::PersistentSigner<csgn::MemoryStore>,
    policy: &Policy,
    now: u64,
) -> Result<()> {
    let bytes = authority
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(policy).unwrap(),
            now / DAY * DAY,
            policy.shared_expiry + DAY,
        )
        .await
        .unwrap();
    global
        .install_policy(&bytes, authority.key_ring().unwrap(), now)
        .await
}
async fn make<S: Store, K: csgn::Store, I: cpsd::IssuanceStore>(
    store: S,
    key_store: K,
    issuance: I,
    capacity: u32,
) -> Global<S, K, I> {
    let signer = signer(key_store, store.scope()).await;
    Global::open(
        store,
        issuance,
        issuer(1, &["development"]),
        signer,
        fingerprint_key(9),
        Mode::Development,
        Limits {
            challenge_ttl: 60,
            pending_capacity: capacity,
        },
    )
    .await
    .unwrap()
}
async fn issue<S: Store, K: csgn::Store, I: cpsd::IssuanceStore>(
    global: &Global<S, K, I>,
    rng: &mut StdRng,
    who: &Subject,
    secret: &HolderSecret,
    now: u64,
) -> cpsd::Passport {
    let challenge = global
        .challenge(rng, &session(who), now, now + 10)
        .await
        .unwrap();
    let (request, pending) =
        cpsd::request_issue(rng, secret, global.issuer_public_key(), &challenge).unwrap();
    let blind = global
        .issue(rng, &session(who), &challenge, &request, now)
        .await
        .unwrap();
    assert!(matches!(
        global
            .issue(rng, &session(who), &challenge, &request, now)
            .await,
        Err(Error::Challenge)
    ));
    assert_eq!(blind.attributes().valid_until, COHORT);
    assert!(
        blind
            .attributes()
            .gates
            .values()
            .all(|expiry| *expiry == COHORT)
    );
    pending.finish(&blind).unwrap()
}
async fn present_trusted(
    passport: &cpsd::Passport,
    rng: &mut StdRng,
    request: &cpsd::PresentationRequest,
) -> std::result::Result<cpsd::Presentation, cpsd::Error> {
    let mut signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        std::str::from_utf8(request.community().as_bytes()).unwrap(),
        csgn::SecretKey::from_seed(&mut [8; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    let signed = signer
        .sign(
            csgn::Kind::Credential,
            &request.to_bytes(),
            0,
            request.now() + 1,
        )
        .await
        .unwrap();
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        request.community().clone(),
        signer.key_ring().unwrap().clone(),
    );
    passport.present(rng, &expected, &signed, request.now())
}

async fn scenario<S: Store, K: csgn::Store, I: cpsd::IssuanceStore>(
    store: S,
    key_store: K,
    issuance: I,
) {
    let scope = store.scope().to_owned();
    let mut global = make(store, key_store, issuance, 20).await;
    let mut authority = authority().await;
    install(&global, &mut authority, &policy(&scope, 1, 1, COHORT), 10)
        .await
        .unwrap();
    let mut rng = StdRng::seed_from_u64(99);
    let alice = subject("synthetic-a");
    let bob = subject("synthetic-b");
    let gate = DevelopmentGate::new(COHORT + DAY);
    global
        .run_gate(&gate, &alice, b"synthetic-unique-a", 100, &check())
        .await
        .unwrap();
    assert!(matches!(
        global
            .run_gate(&gate, &bob, b"synthetic-unique-a", 100, &check())
            .await,
        Err(Error::Duplicate)
    ));
    assert!(matches!(
        global
            .run_gate(&gate, &alice, b"changed", 100, &check())
            .await,
        Err(Error::UniquenessChanged)
    ));
    global
        .run_gate(&gate, &bob, b"synthetic-unique-b", 100, &check())
        .await
        .unwrap();
    let secret = HolderSecret::generate(&mut rng);
    let passport = issue(&global, &mut rng, &alice, &secret, 100).await;
    let renewed = issue(&global, &mut rng, &alice, &secret, 101).await;
    let community = cpsd::CommunityId::new(b"community-a").unwrap();
    let request = cpsd::PresentationRequest::for_epoch(
        &mut rng,
        community.clone(),
        1,
        [GateId::new("development").unwrap()],
        200,
        COHORT,
    )
    .unwrap();
    let proof = present_trusted(&passport, &mut rng, &request)
        .await
        .unwrap();
    let mut community_signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "community-a",
        csgn::SecretKey::from_seed(&mut [87; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    let signed_request = community_signer
        .sign(
            csgn::Kind::Credential,
            &request.to_bytes(),
            0,
            request.now() + 1,
        )
        .await
        .unwrap();
    let wrong_origin = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new(b"community-b").unwrap(),
        community_signer.key_ring().unwrap().clone(),
    );
    assert!(
        passport
            .present(&mut rng, &wrong_origin, &signed_request, request.now())
            .is_err()
    );
    let pseudonym = cpsd::verify(
        &mut rng,
        &[global.issuer_public_key().clone()],
        &request,
        &proof,
    )
    .unwrap();
    let again = present_trusted(&renewed, &mut rng, &request).await.unwrap();
    assert_eq!(
        pseudonym,
        cpsd::verify(
            &mut rng,
            &[global.issuer_public_key().clone()],
            &request,
            &again
        )
        .unwrap()
    );
    assert_eq!(pseudonym, secret.pseudonym(&community));
    assert_ne!(
        pseudonym,
        secret.pseudonym(&cpsd::CommunityId::new(b"community-b").unwrap())
    );

    let challenge = global
        .challenge(&mut rng, &session(&alice), 102, 112)
        .await
        .unwrap();
    let other_secret = HolderSecret::generate(&mut rng);
    let (changed, _) = cpsd::request_issue(
        &mut rng,
        &other_secret,
        global.issuer_public_key(),
        &challenge,
    )
    .unwrap();
    assert!(matches!(
        global
            .issue(&mut rng, &session(&alice), &challenge, &changed, 102)
            .await,
        Err(Error::HolderChanged)
    ));
    assert!(matches!(
        global
            .issue(&mut rng, &session(&bob), &challenge, &changed, 102)
            .await,
        Err(Error::Challenge)
    ));
    let bob_challenge = global
        .challenge(&mut rng, &session(&bob), 102, 112)
        .await
        .unwrap();
    let (duplicate, _) = cpsd::request_issue(
        &mut rng,
        &secret,
        global.issuer_public_key(),
        &bob_challenge,
    )
    .unwrap();
    assert!(matches!(
        global
            .issue(&mut rng, &session(&bob), &bob_challenge, &duplicate, 102)
            .await,
        Err(Error::Duplicate)
    ));
    let bob_secret = HolderSecret::generate(&mut rng);
    let (request, pending) = cpsd::request_issue(
        &mut rng,
        &bob_secret,
        global.issuer_public_key(),
        &bob_challenge,
    )
    .unwrap();
    let blind = global
        .issue(&mut rng, &session(&bob), &bob_challenge, &request, 103)
        .await
        .unwrap();
    pending.finish(&blind).unwrap();
    // Alice's failed holder-change proof also leaves a valid challenge.
    let (request, pending) =
        cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &challenge).unwrap();
    let blind = global
        .issue(&mut rng, &session(&alice), &challenge, &request, 103)
        .await
        .unwrap();
    pending.finish(&blind).unwrap();
    assert!(matches!(
        global
            .suspend(&alice, Suspension::Temporary { until: DAY }, 200)
            .await,
        Err(Error::WarningRequired)
    ));
    global.warn(&alice).await.unwrap();
    assert_eq!(
        global
            .suspend(&alice, Suspension::Temporary { until: DAY }, 200)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        global
            .suspend(&alice, Suspension::Temporary { until: DAY }, 200)
            .await
            .unwrap(),
        2
    );
    assert!(matches!(
        global.challenge(&mut rng, &session(&alice), 201, 211).await,
        Err(Error::Suspended)
    ));
    assert!(matches!(
        global
            .run_gate(&gate, &alice, b"synthetic-unique-a", 201, &check())
            .await,
        Err(Error::Suspended)
    ));
    let fresh_request = cpsd::PresentationRequest::for_epoch(
        &mut rng,
        community,
        2,
        [GateId::new("development").unwrap()],
        250,
        COHORT,
    )
    .unwrap();
    assert!(
        present_trusted(&passport, &mut rng, &fresh_request)
            .await
            .is_err()
    );
    assert_eq!(global.revocations("", 10).await.unwrap().len(), 1);
    let signed = global.signed_status(201, 2 * DAY).await.unwrap();
    let status = Status::verify(&signed, global.key_ring().unwrap(), &scope, 2, 1, 250).unwrap();
    assert_eq!(status.epoch, 2);
    let payload = global
        .key_ring()
        .unwrap()
        .verify(&signed, csgn::Kind::SettingsSnapshot, 250)
        .unwrap();
    let json = std::str::from_utf8(payload.payload()).unwrap();
    assert!(!json.contains(alice.as_str()));
    assert!(!json.contains("synthetic-unique"));
    assert!(Status::verify(&signed, global.key_ring().unwrap(), &scope, 3, 1, 250).is_err());
    assert!(Status::verify(&signed, global.key_ring().unwrap(), "other", 2, 1, 250).is_err());
    global
        .rotate_signing_key(csgn::SecretKey::from_seed(&mut [4; 32]), 250)
        .await
        .unwrap();
    assert!(Status::verify(&signed, global.key_ring().unwrap(), &scope, 2, 1, 250).is_ok());
    issue(&global, &mut rng, &alice, &secret, DAY).await;
    assert!(global.revocations("", 10).await.unwrap().is_empty());
    assert_eq!(
        global
            .suspend(
                &alice,
                Suspension::Permanent(PermanentReason::SelfBan),
                DAY + 1
            )
            .await
            .unwrap(),
        3
    );
    assert!(matches!(global.warn(&alice).await, Err(Error::Suspended)));
    assert!(matches!(
        global
            .challenge(&mut rng, &session(&alice), DAY + 2, DAY + 12)
            .await,
        Err(Error::Suspended)
    ));
    assert!(matches!(
        global
            .suspend(&alice, Suspension::Temporary { until: 2 * DAY }, DAY + 2)
            .await,
        Err(Error::Suspended)
    ));
    let replacement = subject("synthetic-replacement");
    assert!(matches!(
        global
            .run_gate(
                &gate,
                &replacement,
                b"synthetic-unique-a",
                DAY + 2,
                &check()
            )
            .await,
        Err(Error::Duplicate)
    ));
    assert_eq!(
        global
            .suspend(
                &bob,
                Suspension::Permanent(PermanentReason::LegalOrder),
                DAY + 3
            )
            .await
            .unwrap(),
        4
    );
    assert_eq!(global.revocations("", 1).await.unwrap().len(), 1);
    assert_eq!(
        global.revocations(alice.as_str(), 10).await.unwrap().len(),
        1
    );
}
#[tokio::test]
async fn memory_real_crypto_lifecycle() {
    scenario(
        MemoryStore::new("global").unwrap(),
        csgn::MemoryStore::default(),
        challenges("global", 20),
    )
    .await;
}
#[tokio::test]
async fn libsql_real_crypto_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let db = crlt::Db::open(crlt::Config::new(
        format!("file://{}", dir.path().join("global.db").display()),
        "",
    ))
    .await
    .unwrap();
    db.migrate(&migrations()).await.unwrap();
    let store = LibsqlStore::new(&db, "global").unwrap();
    let keys = csgn::LibsqlStore::new(db.community("global").unwrap());
    store.check_query_plans().await.unwrap();
    keys.check_query_plans().await.unwrap();
    scenario(store.clone(), keys, leaf(&db, "global")).await;
    let rows = store.list("account", "", 10).await.unwrap();
    for row in rows.records.values() {
        let json = std::str::from_utf8(&row.value).unwrap();
        assert!(!json.contains("synthetic-unique"));
        assert!(!json.contains("issued"));
        assert!(!json.contains("login"));
    }
}
#[tokio::test]
async fn short_evidence_bad_proofs_capacity_and_expiry() {
    let global = make(
        MemoryStore::new("test").unwrap(),
        csgn::MemoryStore::default(),
        challenges("test", 20),
        1,
    )
    .await;
    let mut authority = authority().await;
    install(&global, &mut authority, &policy("test", 1, 1, COHORT), 10)
        .await
        .unwrap();
    let mut rng = StdRng::seed_from_u64(55);
    let who = subject("a");
    global
        .run_gate(
            &DevelopmentGate::new(COHORT - DAY),
            &who,
            b"token",
            100,
            &check(),
        )
        .await
        .unwrap();
    assert!(matches!(
        global.challenge(&mut rng, &session(&who), 100, 110).await,
        Err(Error::Gates)
    ));
    global
        .run_gate(&DevelopmentGate::new(COHORT), &who, b"token", 100, &check())
        .await
        .unwrap();
    assert!(matches!(
        global.challenge(&mut rng, &session(&who), 100, 161).await,
        Err(Error::InvalidTime)
    ));
    let challenge = global
        .challenge(&mut rng, &session(&who), 100, 110)
        .await
        .unwrap();
    assert!(matches!(
        global.challenge(&mut rng, &session(&who), 100, 110).await,
        Err(Error::Capacity)
    ));
    let secret = HolderSecret::generate(&mut rng);
    let wrong_nonce = cpsd::IssuanceChallenge::generate(&mut rng);
    let (invalid, _) =
        cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &wrong_nonce).unwrap();
    assert!(matches!(
        global
            .issue(&mut rng, &session(&who), &challenge, &invalid, 100)
            .await,
        Err(Error::Passport)
    ));
    assert_eq!(global.prune_challenges(110, 10).await.unwrap(), 0);
    let (valid, pending) =
        cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &challenge).unwrap();
    let blind = global
        .issue(&mut rng, &session(&who), &challenge, &valid, 110)
        .await
        .unwrap();
    pending.finish(&blind).unwrap();
    let stale = global
        .challenge(&mut rng, &session(&who), 111, 112)
        .await
        .unwrap();
    let (request, _) =
        cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &stale).unwrap();
    assert!(matches!(
        global
            .issue(&mut rng, &session(&who), &stale, &request, 113)
            .await,
        Err(Error::Challenge)
    ));
    assert_eq!(global.prune_challenges(113, 10).await.unwrap(), 1);
    let stale_epoch = global
        .challenge(&mut rng, &session(&who), 114, 124)
        .await
        .unwrap();
    let (request, _) =
        cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &stale_epoch).unwrap();
    install(&global, &mut authority, &policy("test", 2, 2, COHORT), 114)
        .await
        .unwrap();
    assert!(matches!(
        global
            .issue(&mut rng, &session(&who), &stale_epoch, &request, 114)
            .await,
        Err(Error::Challenge)
    ));
}
#[tokio::test]
async fn policies_are_authenticated_scoped_monotonic_and_bounded() {
    let global = make(
        MemoryStore::new("test").unwrap(),
        csgn::MemoryStore::default(),
        challenges("test", 20),
        10,
    )
    .await;
    let mut authority = authority().await;
    let good = policy("test", 1, 1, COHORT);
    install(&global, &mut authority, &good, 10).await.unwrap();
    install(&global, &mut authority, &good, 10).await.unwrap();
    let mut invalid = vec![
        policy("wrong", 2, 2, COHORT),
        policy("test", 1, 2, COHORT),
        policy("test", 2, 1, COHORT),
    ];
    let mut no_unique = policy("test", 2, 2, COHORT);
    no_unique.gates[0].uniqueness = false;
    invalid.push(no_unique);
    let mut duplicate = policy("test", 2, 2, COHORT);
    duplicate.gates.push(duplicate.gates[0].clone());
    invalid.push(duplicate);
    let mut unknown = policy("test", 2, 2, COHORT);
    unknown.gates[0].gate = "unknown".into();
    invalid.push(unknown);
    for policy in invalid {
        assert!(install(&global, &mut authority, &policy, 10).await.is_err());
    }
    let bytes = serde_json::to_vec(&policy("test", 2, 2, COHORT)).unwrap();
    let mut signed = authority
        .sign(csgn::Kind::SettingsSnapshot, &bytes, 10, COHORT + DAY)
        .await
        .unwrap();
    signed[10] ^= 1;
    assert!(matches!(
        global
            .install_policy(&signed, authority.key_ring().unwrap(), 10)
            .await,
        Err(Error::Signature)
    ));
    let wrong_kind = authority
        .sign(csgn::Kind::Credential, &bytes, 10, COHORT + DAY)
        .await
        .unwrap();
    assert!(matches!(
        global
            .install_policy(&wrong_kind, authority.key_ring().unwrap(), 10)
            .await,
        Err(Error::Signature)
    ));
    let short = authority
        .sign(csgn::Kind::SettingsSnapshot, &bytes, 10, COHORT)
        .await
        .unwrap();
    assert!(matches!(
        global
            .install_policy(&short, authority.key_ring().unwrap(), 10)
            .await,
        Err(Error::Policy)
    ));
}
#[tokio::test]
async fn production_rejects_development_and_stored_key_changes() {
    let store = MemoryStore::new("test").unwrap();
    let keys = csgn::MemoryStore::default();
    let sign = signer(keys.clone(), "test").await;
    assert!(matches!(
        Global::open(
            store.clone(),
            challenges("test", 20),
            issuer(1, &["development"]),
            sign,
            fingerprint_key(9),
            Mode::Production,
            Limits {
                challenge_ttl: 60,
                pending_capacity: 10
            }
        )
        .await,
        Err(Error::DevelopmentDisabled)
    ));
    let sign = csgn::PersistentSigner::open(
        keys.clone(),
        "cglb:test",
        csgn::SecretKey::from_seed(&mut [2; 32]),
        10,
    )
    .await
    .unwrap();
    let global = Global::open(
        store.clone(),
        challenges("test", 20),
        issuer(1, &["real-gate"]),
        sign,
        fingerprint_key(9),
        Mode::Production,
        Limits {
            challenge_ttl: 60,
            pending_capacity: 10,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        global
            .run_gate(
                &DevelopmentGate::new(COHORT),
                &subject("a"),
                b"test",
                100,
                &check()
            )
            .await,
        Err(Error::DevelopmentDisabled)
    ));
    drop(global);
    for (seed, hmac) in [(2, 9), (1, 8)] {
        let sign = csgn::PersistentSigner::open(
            keys.clone(),
            "cglb:test",
            csgn::SecretKey::from_seed(&mut [2; 32]),
            10,
        )
        .await
        .unwrap();
        assert!(matches!(
            Global::open(
                store.clone(),
                challenges("test", 20),
                issuer(seed, &["real-gate"]),
                sign,
                fingerprint_key(hmac),
                Mode::Production,
                Limits {
                    challenge_ttl: 60,
                    pending_capacity: 10
                }
            )
            .await,
            Err(Error::KeyMismatch)
        ));
    }
}

#[tokio::test]
async fn optional_unique_input_and_rounded_provider_expiry_follow_the_signed_policy() {
    let store = MemoryStore::new("test").unwrap();
    let global = Global::open(
        store.clone(), challenges("test", 20), issuer(1, &["development", "unique"]),
        signer(csgn::MemoryStore::default(), "test").await, fingerprint_key(9),
        Mode::Development, Limits { challenge_ttl: 60, pending_capacity: 10 },
    ).await.unwrap();
    let mut authority = authority().await;
    let mut rules = policy("test", 1, 1, COHORT);
    rules.gates[0].uniqueness = false;
    rules.gates.push(GatePolicy { gate: "unique".into(), provider: "external".into(), uniqueness: true });
    install(&global, &mut authority, &rules, 100).await.unwrap();
    assert!(matches!(global.run_gate(&DevelopmentGate::new(101), &subject("expired"), b"input", 100, &check()).await, Err(Error::Gates)));
    let result = global.run_gate(&DevelopmentGate::new(COHORT), &subject("member"), b"input", 100, &check()).await.unwrap();
    assert_eq!(result.valid_until, COHORT);
    assert!(store.list("fingerprint", "", 10).await.unwrap().records.is_empty());
    let key = storage::Key::new("account", "member");
    let saved = store.read(std::slice::from_ref(&key)).await.unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&saved.records[&key].value).unwrap();
    assert_eq!(saved["fingerprints"], serde_json::json!({}));
    let mut rng = StdRng::seed_from_u64(77);
    assert!(matches!(global.challenge(&mut rng, &session(&subject("member")), 100, 150).await, Err(Error::Gates)));
}

#[tokio::test]
async fn leaf_capacity_and_missing_nonce_refuse_without_releasing_the_person_binding() {
    use cpsd::ChallengeStore;
    let store = MemoryStore::new("test").unwrap();
    let leaf = challenges("test", 1);
    let global = make(store.clone(), csgn::MemoryStore::default(), leaf.clone(), 10).await;
    let mut authority = authority().await;
    install(&global, &mut authority, &policy("test", 1, 1, COHORT), 100).await.unwrap();
    for id in ["first", "second"] {
        global.run_gate(&DevelopmentGate::new(COHORT), &subject(id), id.as_bytes(), 100, &check()).await.unwrap();
    }
    let mut rng = StdRng::seed_from_u64(19);
    global.challenge(&mut rng, &session(&subject("first")), 100, 110).await.unwrap();
    assert!(matches!(global.challenge(&mut rng, &session(&subject("second")), 100, 110).await, Err(Error::Capacity)));
    assert_eq!(global.prune_challenges(111, 10).await.unwrap(), 2);
    let auth = session(&subject("first"));
    let challenge = global.challenge(&mut rng, &auth, 112, 120).await.unwrap();
    let secret = HolderSecret::generate(&mut rng);
    let (request, _) = cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &challenge).unwrap();
    assert_eq!(leaf.prune(121).await.unwrap(), 1);
    assert!(matches!(global.issue(&mut rng, &auth, &challenge, &request, 113).await, Err(Error::Challenge)));
    let replacement = global.challenge(&mut rng, &auth, 122, 130).await.unwrap();
    assert_ne!(replacement.to_bytes(), challenge.to_bytes());
    assert_eq!(store.list("challenge", "", 10).await.unwrap().records.len(), 1);
}

#[tokio::test]
async fn actual_sqlite_write_refusals_bound_retries_and_preserve_atomic_batches() {
    // The separate driver installs hostile on-disk fixtures after crlt opens.
    // Every facade operation still runs through the actual crlt/libSQL stores.
    for action in ["IGNORE", "ABORT, 'write refused'"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("write-refusal.db");
        let db = crlt::Db::open(crlt::Config::new(format!("file://{}", path.display()), "")).await.unwrap();
        db.migrate(&migrations()).await.unwrap();
        let store = LibsqlStore::new(&db, "test").unwrap();
        let global = make(store.clone(), csgn::MemoryStore::default(), leaf(&db, "test"), 10).await;
        let mut authority = authority().await;
        install(&global, &mut authority, &policy("test", 1, 1, COHORT), 100).await.unwrap();
        let raw_db = libsql::Builder::new_local(&path).build().await.unwrap();
        let raw = raw_db.connect().unwrap();
        raw.execute_batch(&format!("CREATE TRIGGER refuse_write BEFORE INSERT ON cglb_record WHEN NEW.bucket = 'account' BEGIN SELECT RAISE({action}); END;")).await.unwrap();
        let error = global.run_gate(&DevelopmentGate::new(COHORT), &subject("member"), b"unique", 100, &check()).await.unwrap_err();
        assert!(matches!((&error, action), (Error::Conflict, "IGNORE") | (Error::Storage, "ABORT, 'write refused'")));
        assert!(store.list("account", "", 10).await.unwrap().records.is_empty());
        assert!(store.list("fingerprint", "", 10).await.unwrap().records.is_empty());
        raw.execute_batch("DROP TRIGGER refuse_write").await.unwrap();
        global.run_gate(&DevelopmentGate::new(COHORT), &subject("member"), b"unique", 100, &check()).await.unwrap();
        raw.execute_batch(&format!("CREATE TRIGGER refuse_write BEFORE INSERT ON cglb_record WHEN NEW.bucket = 'challenge' BEGIN SELECT RAISE({action}); END;")).await.unwrap();
        let mut rng = StdRng::seed_from_u64(71);
        let error = global.challenge(&mut rng, &session(&subject("member")), 100, 150).await.unwrap_err();
        assert!(matches!((&error, action), (Error::Conflict, "IGNORE") | (Error::Storage, "ABORT, 'write refused'")));
        assert!(store.list("challenge", "", 10).await.unwrap().records.is_empty());
        raw.execute_batch("DROP TRIGGER refuse_write").await.unwrap();
        global.challenge(&mut rng, &session(&subject("member")), 100, 150).await.unwrap();
    }
}

#[tokio::test]
async fn real_nonce_storage_side_effects_cannot_change_a_reserved_issuance() {
    let zeros = serde_json::to_string(&[0u8; 32]).unwrap();
    let nonce = serde_json::to_string(&[8u8; 32]).unwrap();
    for (bucket, entry, field, value) in [
        ("challenge", "member", "epoch", "99".to_owned()),
        ("meta", "state", "local_epoch", "1".to_owned()),
        ("challenge", "member", "session", format!("json('{zeros}')")),
        ("challenge", "member", "deadline", "149".to_owned()),
        ("challenge", "member", "nonce", format!("json('{nonce}')")),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonce-change.db");
        let db = crlt::Db::open(crlt::Config::new(format!("file://{}", path.display()), "")).await.unwrap();
        db.migrate(&migrations()).await.unwrap();
        let store = LibsqlStore::new(&db, "test").unwrap();
        let global = make(store, csgn::MemoryStore::default(), leaf(&db, "test"), 10).await;
        let mut authority = authority().await;
        install(&global, &mut authority, &policy("test", 1, 1, COHORT), 100).await.unwrap();
        global.run_gate(&DevelopmentGate::new(COHORT), &subject("member"), b"unique", 100, &check()).await.unwrap();
        let raw_db = libsql::Builder::new_local(&path).build().await.unwrap();
        let raw = raw_db.connect().unwrap();
        raw.execute_batch(&format!("CREATE TRIGGER change_reservation AFTER INSERT ON cpsd_challenges BEGIN UPDATE cglb_record SET value = CAST(json_set(CAST(value AS TEXT), '$.{field}', {value}) AS BLOB), revision = revision + 1 WHERE community_id = 'test' AND bucket = '{bucket}' AND entry_key = '{entry}'; END;")).await.unwrap();
        let mut rng = StdRng::seed_from_u64(72);
        assert!(matches!(global.challenge(&mut rng, &session(&subject("member")), 100, 150).await, Err(Error::Challenge)), "{field}");
        raw.execute_batch("DROP TRIGGER change_reservation").await.unwrap();
        assert_eq!(global.prune_challenges(151, 10).await.unwrap(), 1);
        global.challenge(&mut rng, &session(&subject("member")), 152, 160).await.unwrap();
    }
}

#[tokio::test]
async fn post_crypto_storage_failure_never_releases_an_uncommitted_passport() {
    for action in ["IGNORE", "ABORT, 'commit refused'", "owner-revision"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("issuance-commit.db");
        let db = crlt::Db::open(crlt::Config::new(format!("file://{}", path.display()), "")).await.unwrap();
        db.migrate(&migrations()).await.unwrap();
        let store = LibsqlStore::new(&db, "test").unwrap();
        let global = make(store.clone(), csgn::MemoryStore::default(), leaf(&db, "test"), 10).await;
        let mut authority = authority().await;
        install(&global, &mut authority, &policy("test", 1, 1, COHORT), 100).await.unwrap();
        let who = subject("member");
        global.run_gate(&DevelopmentGate::new(COHORT), &who, b"unique", 100, &check()).await.unwrap();
        let mut rng = StdRng::seed_from_u64(73);
        let auth = session(&who);
        let challenge = global.challenge(&mut rng, &auth, 100, 150).await.unwrap();
        let secret = HolderSecret::generate(&mut rng);
        let (request, _) = cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &challenge).unwrap();
        let raw_db = libsql::Builder::new_local(&path).build().await.unwrap();
        let raw = raw_db.connect().unwrap();
        let trigger = if action == "owner-revision" {
            "CREATE TRIGGER refuse_commit AFTER INSERT ON cpsd_issuer_tags BEGIN UPDATE cglb_record SET revision = revision + 1 WHERE community_id = 'test' AND bucket = 'account' AND entry_key = 'member'; END;".to_owned()
        } else {
            format!("CREATE TRIGGER refuse_commit BEFORE UPDATE ON cglb_record WHEN NEW.bucket = 'challenge' AND NEW.value IS NULL BEGIN SELECT RAISE({action}); END;")
        };
        raw.execute_batch(&trigger).await.unwrap();
        let result = global.issue(&mut rng, &auth, &challenge, &request, 101).await;
        if action == "ABORT, 'commit refused'" { assert!(matches!(result, Err(Error::Storage))); }
        else { assert!(matches!(result, Err(Error::Conflict))); }
        raw.execute_batch("DROP TRIGGER refuse_commit").await.unwrap();
        assert!(matches!(global.issue(&mut rng, &auth, &challenge, &request, 102).await, Err(Error::Challenge)));
        assert_eq!(store.list("challenge", "", 10).await.unwrap().records.len(), 1);
        assert_eq!(global.prune_challenges(151, 10).await.unwrap(), 1);
        issue(&global, &mut rng, &who, &secret, 152).await;
    }
}

#[tokio::test]
async fn durable_renewal_after_reopen_keeps_identity_and_rejects_new_secret() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("restart.db").display());
    let db = crlt::Db::open(crlt::Config::new(&url, "")).await.unwrap();
    let migrations = migrations();
    db.migrate(&migrations).await.unwrap();
    let store = LibsqlStore::new(&db, "global").unwrap();
    let keys = csgn::LibsqlStore::new(db.community("global").unwrap());
    let global = make(store, keys, leaf(&db, "global"), 10).await;
    let mut authority = authority().await;
    install(&global, &mut authority, &policy("global", 1, 1, COHORT), 10)
        .await
        .unwrap();
    let alice = subject("a");
    let mut rng = StdRng::seed_from_u64(20);
    let secret = HolderSecret::generate(&mut rng);
    global
        .run_gate(
            &DevelopmentGate::new(COHORT),
            &alice,
            b"synthetic",
            100,
            &check(),
        )
        .await
        .unwrap();
    issue(&global, &mut rng, &alice, &secret, 100).await;
    drop(global);
    drop(db);
    let db = crlt::Db::open(crlt::Config::new(&url, "")).await.unwrap();
    db.migrate(&migrations).await.unwrap();
    let store = LibsqlStore::new(&db, "global").unwrap();
    let keys = csgn::LibsqlStore::new(db.community("global").unwrap());
    let sign = csgn::PersistentSigner::open(
        keys,
        "cglb:global",
        csgn::SecretKey::from_seed(&mut [2; 32]),
        101,
    )
    .await
    .unwrap();
    let global = Global::open(
        store,
        leaf(&db, "global"),
        issuer(1, &["development"]),
        sign,
        fingerprint_key(9),
        Mode::Development,
        Limits {
            challenge_ttl: 60,
            pending_capacity: 10,
        },
    )
    .await
    .unwrap();
    let challenge = global
        .challenge(&mut rng, &session(&alice), 102, 112)
        .await
        .unwrap();
    let other_secret = HolderSecret::generate(&mut rng);
    let (request, _) = cpsd::request_issue(
        &mut rng,
        &other_secret,
        global.issuer_public_key(),
        &challenge,
    )
    .unwrap();
    assert!(matches!(
        global
            .issue(&mut rng, &session(&alice), &challenge, &request, 102)
            .await,
        Err(Error::HolderChanged)
    ));
    let (request, pending) =
        cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &challenge).unwrap();
    let blind = global
        .issue(&mut rng, &session(&alice), &challenge, &request, 103)
        .await
        .unwrap();
    pending.finish(&blind).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_issuance_consumes_once() {
    let dir = tempfile::tempdir().unwrap();
    let db = crlt::Db::open(crlt::Config::new(
        format!("file://{}", dir.path().join("issuance-race.db").display()),
        "",
    ))
    .await
    .unwrap();
    db.migrate(&migrations()).await.unwrap();
    let global = make(
        LibsqlStore::new(&db, "global").unwrap(),
        csgn::MemoryStore::default(),
        leaf(&db, "global"),
        10,
    )
    .await;
    let mut authority = authority().await;
    install(&global, &mut authority, &policy("global", 1, 1, COHORT), 10)
        .await
        .unwrap();
    let who = subject("a");
    let mut rng = StdRng::seed_from_u64(8);
    global
        .run_gate(
            &DevelopmentGate::new(COHORT),
            &who,
            b"synthetic",
            100,
            &check(),
        )
        .await
        .unwrap();
    let secret = HolderSecret::generate(&mut rng);
    let challenge = global
        .challenge(&mut rng, &session(&who), 100, 110)
        .await
        .unwrap();
    let (request, pending) =
        cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &challenge).unwrap();
    let global = std::sync::Arc::new(global);
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let mut tasks = Vec::new();
    for seed in [21, 22] {
        let global = global.clone();
        let barrier = barrier.clone();
        let request = request.clone();
        let who = who.clone();
        tasks.push(tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(seed);
            barrier.wait().await;
            global
                .issue(&mut rng, &session(&who), &challenge, &request, 100)
                .await
        }));
    }
    let left = tasks.remove(0).await.unwrap();
    let right = tasks.remove(0).await.unwrap();
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(
        matches!(left, Err(Error::Conflict | Error::Challenge))
            || matches!(right, Err(Error::Conflict | Error::Challenge))
    );
    pending.finish(&left.or(right).unwrap()).unwrap();
}
