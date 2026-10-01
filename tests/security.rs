//! Production-mode policy, provider-idempotency and challenge-capacity regressions.
use cglb::{
    storage::{MemoryStore, Store},
    *,
};
use cpsd::rand::{SeedableRng, rngs::StdRng};
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
const DAY: u64 = 86_400;
const COHORT: u64 = 5 * DAY;
type Facade = Global<MemoryStore, csgn::MemoryStore, cpsd::MemoryStore>;
fn subject(id: &str) -> Subject {
    Subject::new(id).unwrap()
}
fn session(id: &str) -> Session {
    Session::authenticated(subject(id), [7; 32]).unwrap()
}
fn check() -> CheckId {
    CheckId::generate(&mut cpsd::rand::rngs::OsRng)
}
fn issuer() -> cpsd::IssuerKey {
    cpsd::IssuerKey::generate(
        &mut StdRng::seed_from_u64(1),
        cpsd::KeyId::new("key").unwrap(),
        vec![cpsd::GateId::new("phone").unwrap()],
    )
    .unwrap()
}
fn fingerprints() -> FingerprintKey {
    FingerprintKey::from_bytes(&mut [9; 32])
}
async fn open(
    store: MemoryStore,
    keys: csgn::MemoryStore,
    issuance: cpsd::MemoryStore,
    reopen: bool,
) -> Facade {
    let key = csgn::SecretKey::from_seed(&mut [2; 32]);
    let signer = if reopen {
        csgn::PersistentSigner::open(keys, "cglb:global", key, 0)
            .await
            .unwrap()
    } else {
        csgn::PersistentSigner::create(keys, "cglb:global", key, 0, 30 * DAY)
            .await
            .unwrap()
    };
    Global::open(
        store,
        issuance,
        issuer(),
        signer,
        fingerprints(),
        Mode::Production,
        Limits {
            challenge_ttl: 60,
            pending_capacity: 2,
        },
    )
    .await
    .unwrap()
}
async fn make() -> (Facade, MemoryStore, csgn::MemoryStore, cpsd::MemoryStore) {
    let store = MemoryStore::new("global").unwrap();
    let keys = csgn::MemoryStore::default();
    let issuance = cpsd::MemoryStore::new(cpsd::CommunityId::new(b"global").unwrap(), 2).unwrap();
    let global = open(store.clone(), keys.clone(), issuance.clone(), false).await;
    install(&global, 1, 1, COHORT, 100, "sms").await.unwrap();
    (global, store, keys, issuance)
}
async fn install(
    global: &Facade,
    revision: u64,
    epoch: u64,
    expiry: u64,
    now: u64,
    provider: &str,
) -> Result<()> {
    let mut authority = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "global-authority",
        csgn::SecretKey::from_seed(&mut [3; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    let policy = Policy {
        version: 1,
        scope: "global".into(),
        revision,
        epoch,
        shared_expiry: expiry,
        gates: vec![GatePolicy {
            gate: "phone".into(),
            provider: provider.into(),
            uniqueness: true,
        }],
    };
    let bytes = authority
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&policy).unwrap(),
            now / DAY * DAY,
            expiry + DAY,
        )
        .await
        .unwrap();
    global
        .install_policy(&bytes, authority.key_ring().unwrap(), now)
        .await
}
// External provider fixture: billing/result delivery is idempotent by key.
// All facade storage, policy, HMAC and challenge logic remain the real code.
#[derive(Default)]
struct Provider {
    charged: Mutex<BTreeSet<String>>,
    calls: AtomicUsize,
    delay: AtomicBool,
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
impl GlobalGate for Provider {
    fn id(&self) -> &str {
        "phone"
    }
    fn provider(&self) -> &str {
        "sms"
    }
    fn development_only(&self) -> bool {
        false
    }
    async fn verify(
        &self,
        key: &CheckId,
        who: &Subject,
        input: &[u8],
        _: u64,
    ) -> Result<GateEvidence> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let first = self.charged.lock().unwrap().insert(key.as_str().into());
        if first && who.as_str() == "alice" && self.delay.load(Ordering::SeqCst) {
            self.started.notify_one();
            self.release.notified().await;
        }
        // Canonicalization belongs to the provider leaf. These fixture spellings
        // deliberately normalize to one value across requests.
        let canonical = input.iter().copied().filter(|b| *b != b' ').collect();
        Ok(GateEvidence {
            valid_until: COHORT + 37,
            uniqueness: Some(zeroize::Zeroizing::new(canonical)),
        })
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_paid_check_survives_unrelated_writes_and_cancelled_delivery_without_rebilling() {
    let (global, store, keys, issuance) = make().await;
    let global = Arc::new(global);
    let provider = Arc::new(Provider::default());
    let alice = subject("alice");
    global
        .run_gate(&*provider, &alice, b"+100", 100, &check())
        .await
        .unwrap();
    provider.delay.store(true, Ordering::SeqCst);
    let id = check();
    let g = global.clone();
    let p = provider.clone();
    let c = id.clone();
    let task =
        tokio::spawn(async move { g.run_gate(&*p, &subject("alice"), b"+100", 100, &c).await });
    provider.started.notified().await;
    global
        .run_gate(&*provider, &subject("bob"), b"+200", 100, &check())
        .await
        .unwrap();
    global.warn(&alice).await.unwrap();
    provider.release.notify_one();
    assert_eq!(task.await.unwrap().unwrap().valid_until, COHORT);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
    global
        .run_gate(&*provider, &alice, b"+100", 100, &id)
        .await
        .unwrap();
    assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
    assert!(matches!(
        global
            .run_gate(&*provider, &alice, b"changed", 100, &id)
            .await,
        Err(Error::Conflict)
    ));
    let id = check();
    let g = global.clone();
    let p = provider.clone();
    let c = id.clone();
    let task =
        tokio::spawn(async move { g.run_gate(&*p, &subject("alice"), b"+100", 100, &c).await });
    provider.started.notified().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    global
        .run_gate(&*provider, &alice, b"+100", 100, &id)
        .await
        .unwrap();
    assert_eq!(provider.charged.lock().unwrap().len(), 4);
    drop(global);
    let reopened = open(store, keys, issuance, true).await;
    let before = provider.calls.load(Ordering::SeqCst);
    reopened
        .run_gate(&*provider, &alice, b"+100", 100, &id)
        .await
        .unwrap();
    assert_eq!(provider.calls.load(Ordering::SeqCst), before);
}
#[tokio::test]
async fn one_person_cannot_exhaust_global_challenges_and_sessions_cannot_swap() {
    let (global, _, _, _) = make().await;
    let provider = Provider::default();
    let mut rng = StdRng::seed_from_u64(5);
    for (name, input) in [("alice", b"+100"), ("bob", b"+200"), ("charlie", b"+300")] {
        global
            .run_gate(&provider, &subject(name), input, 100, &check())
            .await
            .unwrap();
    }
    let a = global
        .challenge(&mut rng, &session("alice"), 100, 120)
        .await
        .unwrap();
    for _ in 0..5 {
        assert!(matches!(
            global
                .challenge(&mut rng, &session("alice"), 100, 120)
                .await,
            Err(Error::Capacity)
        ));
    }
    global
        .challenge(&mut rng, &session("bob"), 100, 120)
        .await
        .unwrap();
    assert!(matches!(
        global
            .challenge(&mut rng, &session("charlie"), 100, 120)
            .await,
        Err(Error::Capacity)
    ));
    let secret = cpsd::HolderSecret::generate(&mut rng);
    let (request, _) =
        cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &a).unwrap();
    let wrong = Session::authenticated(subject("alice"), [8; 32]).unwrap();
    assert!(matches!(
        global.issue(&mut rng, &wrong, &a, &request, 101).await,
        Err(Error::Challenge)
    ));
    assert_eq!(global.prune_challenges(120, 10).await.unwrap(), 0);
    assert_eq!(global.prune_challenges(121, 10).await.unwrap(), 2);
    global
        .challenge(&mut rng, &session("charlie"), 121, 140)
        .await
        .unwrap();
}
#[tokio::test]
async fn authority_policy_epoch_is_independent_of_suspensions_and_status_is_coarse() {
    let (mut global, store, _, _) = make().await;
    let provider = Provider::default();
    let who = subject("alice");
    global
        .run_gate(&provider, &who, b"+1 00", 100, &check())
        .await
        .unwrap();
    assert!(matches!(
        global
            .run_gate(&provider, &subject("bob"), b"+100", 100, &check())
            .await,
        Err(Error::Duplicate)
    ));
    global.warn(&who).await.unwrap();
    assert_eq!(
        global
            .suspend(&who, Suspension::Temporary { until: DAY }, 200)
            .await
            .unwrap(),
        2
    );
    install(&global, 2, 2, COHORT, 201, "sms").await.unwrap();
    assert!(
        install(&global, 3, u64::MAX, COHORT, 201, "sms")
            .await
            .is_err()
    );
    let signed = global.signed_status(202, 2 * DAY + 123).await.unwrap();
    let status = Status::verify(&signed, global.key_ring().unwrap(), "global", 3, 2, 202).unwrap();
    assert_eq!(status.purpose, "global-passport-status");
    let envelope = global
        .key_ring()
        .unwrap()
        .verify(&signed, csgn::Kind::SettingsSnapshot, 202)
        .unwrap();
    assert_eq!(envelope.issued_at(), 0);
    assert_eq!(envelope.valid_until(), 2 * DAY);
    assert!(
        global
            .key_ring()
            .unwrap()
            .verify(&signed, csgn::Kind::RevocationListSnapshot, 202)
            .is_err()
    );
    assert!(
        !std::str::from_utf8(envelope.payload())
            .unwrap()
            .contains("alice")
    );
    let rows = store.list("account", "", 10).await.unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&rows.records.values().next().unwrap().value).unwrap();
    assert_eq!(value["gates"]["phone"]["valid_until"], COHORT);
    assert!(value.get("tag").is_none());
}

#[tokio::test]
async fn beacon_reuses_exact_bytes_and_refreshes_owner_version_and_lifetime() {
    let (mut global, _, _, _) = make().await;
    let first = global.public_status(100, 2 * DAY + 123).await.unwrap();
    assert_eq!(global.public_status(101, 2 * DAY).await.unwrap(), first);
    assert!(matches!(
        global.public_status(102, 102).await,
        Err(Error::InvalidTime)
    ));
    let longer = global.public_status(103, 3 * DAY).await.unwrap();
    assert_ne!(longer, first);
    assert_eq!(
        global
            .key_ring()
            .unwrap()
            .verify(&longer, csgn::Kind::SettingsSnapshot, 103)
            .unwrap()
            .valid_until(),
        3 * DAY
    );
    install(&global, 2, 2, COHORT, 104, "sms").await.unwrap();
    let current = global.public_status(105, 3 * DAY).await.unwrap();
    let status = Status::verify(&current, global.key_ring().unwrap(), "global", 2, 2, 105).unwrap();
    assert_eq!((status.epoch, status.policy_revision), (2, 2));
    assert_ne!(current, longer);
    assert!(matches!(
        global.public_status(104, 3 * DAY).await,
        Err(Error::Signature)
    ));
    assert_eq!(global.public_status(106, 3 * DAY).await.unwrap(), current);
    let renewed = global.public_status(3 * DAY, 4 * DAY).await.unwrap();
    assert_ne!(renewed, current);
    assert!(
        Status::verify(
            &renewed,
            global.key_ring().unwrap(),
            "global",
            2,
            2,
            3 * DAY,
        )
        .is_ok()
    );
}

#[tokio::test]
async fn beacon_refuses_signed_documents_with_invalid_owner_payloads() {
    let (mut global, _, _, _) = make().await;
    let bytes = global.public_status(100, 2 * DAY).await.unwrap();
    let original = Status::verify(&bytes, global.key_ring().unwrap(), "global", 1, 1, 100).unwrap();
    let mut signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "cglb:global",
        csgn::SecretKey::from_seed(&mut [44; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    for field in ["version", "purpose", "scope", "cohort", "issuer-key"] {
        let mut invalid = original.clone();
        match field {
            "version" => invalid.version = 1,
            "purpose" => invalid.purpose = "other".into(),
            "scope" => invalid.scope = "other".into(),
            "cohort" => invalid.shared_expiry += 1,
            _ => invalid.issuer_public_key.clear(),
        }
        let bytes = signer
            .sign(
                csgn::Kind::SettingsSnapshot,
                &serde_json::to_vec(&invalid).unwrap(),
                0,
                2 * DAY,
            )
            .await
            .unwrap();
        let mut cache = cbcn::document::Cache::<Status>::default();
        assert!(
            cache
                .install(signer.key_ring().unwrap(), bytes, 100)
                .is_err(),
            "{field}"
        );
        assert!(matches!(cache.current(100), Err(cbcn::Error::Unavailable)));
    }
}

#[test]
fn authenticated_identifiers_enforce_bounds_and_redact_debug_output() {
    for invalid in [
        String::new(),
        "x".repeat(129),
        "contains space".into(),
        "é".into(),
    ] {
        assert!(matches!(
            Subject::new(&invalid),
            Err(Error::InvalidIdentifier)
        ));
        assert!(serde_json::from_value::<Subject>(serde_json::json!(invalid)).is_err());
    }
    let who = subject(&"x".repeat(128));
    assert_eq!(format!("{who:?}"), "Subject([redacted])");
    assert!(matches!(
        Session::authenticated(who.clone(), [0; 32]),
        Err(Error::InvalidIdentifier)
    ));
    assert_eq!(
        Session::authenticated(who.clone(), [1; 32])
            .unwrap()
            .subject(),
        &who
    );
    assert_eq!(format!("{:?}", check()), "CheckId([redacted])");
}

#[tokio::test]
async fn open_refuses_cross_scope_keys_unaligned_signers_and_invalid_limits() {
    for case in [
        "scope",
        "activation",
        "issuer",
        "zero-ttl",
        "large-ttl",
        "capacity",
    ] {
        let signing_scope = if case == "issuer" {
            "cglb:other"
        } else {
            "cglb:global"
        };
        let signer = csgn::PersistentSigner::create(
            csgn::MemoryStore::default(),
            signing_scope,
            csgn::SecretKey::from_seed(&mut [2; 32]),
            u64::from(case == "activation"),
            30 * DAY,
        )
        .await
        .unwrap();
        let scope = if case == "scope" {
            b"other".as_slice()
        } else {
            b"global".as_slice()
        };
        let issuance = cpsd::MemoryStore::new(cpsd::CommunityId::new(scope).unwrap(), 2).unwrap();
        let limits = Limits {
            challenge_ttl: match case {
                "zero-ttl" => 0,
                "large-ttl" => cpsd::TIME_LIMIT,
                _ => 60,
            },
            pending_capacity: u32::from(case != "capacity"),
        };
        let result = Global::open(
            MemoryStore::new("global").unwrap(),
            issuance,
            issuer(),
            signer,
            fingerprints(),
            Mode::Production,
            limits,
        )
        .await;
        match case {
            "scope" | "issuer" => assert!(matches!(result, Err(Error::KeyMismatch)), "{case}"),
            "activation" => assert!(matches!(result, Err(Error::InvalidTime))),
            _ => assert!(matches!(result, Err(Error::Capacity)), "{case}"),
        }
    }
}

#[tokio::test]
async fn policy_refusals_authenticate_each_invalid_field_before_state_changes() {
    let store = MemoryStore::new("global").unwrap();
    let global = open(
        store.clone(),
        csgn::MemoryStore::default(),
        cpsd::MemoryStore::new(cpsd::CommunityId::new(b"global").unwrap(), 2).unwrap(),
        false,
    )
    .await;
    let mut authority = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "authority",
        csgn::SecretKey::from_seed(&mut [3; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    let original = Policy {
        version: 1,
        scope: "global".into(),
        revision: 1,
        epoch: 1,
        shared_expiry: COHORT,
        gates: vec![GatePolicy {
            gate: "phone".into(),
            provider: "sms".into(),
            uniqueness: true,
        }],
    };
    for case in [
        "version",
        "revision",
        "epoch",
        "cohort",
        "expired",
        "empty",
        "many",
        "first-epoch",
        "provider",
    ] {
        let mut invalid = original.clone();
        match case {
            "version" => invalid.version = 2,
            "revision" => invalid.revision = 0,
            "epoch" => invalid.epoch = 0,
            "cohort" => invalid.shared_expiry += 1,
            "expired" => invalid.shared_expiry = 0,
            "empty" => invalid.gates.clear(),
            "many" => invalid.gates = vec![invalid.gates[0].clone(); cpsd::MAX_GATES + 1],
            "first-epoch" => invalid.epoch = 2,
            _ => invalid.gates[0].provider = "cglb.test".into(),
        }
        let bytes = authority
            .sign(
                csgn::Kind::SettingsSnapshot,
                &serde_json::to_vec(&invalid).unwrap(),
                0,
                COHORT + DAY,
            )
            .await
            .unwrap();
        let result = global
            .install_policy(&bytes, authority.key_ring().unwrap(), 100)
            .await;
        if case == "provider" {
            assert!(matches!(result, Err(Error::DevelopmentDisabled)));
        } else {
            assert!(matches!(result, Err(Error::Policy)), "{case}");
        }
        assert!(
            store
                .read(&[storage::Key::new("meta", "state")])
                .await
                .unwrap()
                .records
                .is_empty()
        );
    }
    for now in [0, cpsd::TIME_LIMIT] {
        assert!(matches!(
            global.prune_challenges(now, 1).await,
            Err(Error::InvalidTime)
        ));
    }
}

#[tokio::test]
async fn operations_refuse_invalid_inputs_expired_policy_and_changed_storage_binding() {
    let (global, store, _, _) = make().await;
    let provider = Provider::default();
    for value in ["short".into(), "g".repeat(64), "A".repeat(64)] {
        let id: CheckId = serde_json::from_value(serde_json::json!(value)).unwrap();
        assert!(matches!(
            global
                .run_gate(&provider, &subject("member"), b"input", 100, &id)
                .await,
            Err(Error::InvalidIdentifier)
        ));
    }
    for limit in [0, 1001] {
        assert!(matches!(
            global.revocations("", limit).await,
            Err(Error::Capacity)
        ));
        assert!(matches!(
            global.prune_challenges(100, limit).await,
            Err(Error::Capacity)
        ));
    }
    for until in [100, DAY + 1] {
        assert!(matches!(
            global
                .suspend(&subject("member"), Suspension::Temporary { until }, 100)
                .await,
            Err(Error::InvalidTime)
        ));
    }
    let mut rng = StdRng::seed_from_u64(77);
    assert!(matches!(
        global
            .challenge(&mut rng, &session("member"), 100, 100)
            .await,
        Err(Error::InvalidTime)
    ));
    assert!(matches!(
        global
            .challenge(&mut rng, &session("member"), COHORT, COHORT + 1)
            .await,
        Err(Error::InvalidTime)
    ));
    assert!(matches!(
        global
            .run_gate(
                &provider,
                &subject("member"),
                b"input",
                COHORT + 1,
                &check()
            )
            .await,
        Err(Error::Policy)
    ));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    let key = storage::Key::new("meta", "binding");
    let read = store.read(std::slice::from_ref(&key)).await.unwrap();
    store
        .compare_exchange(&read, vec![storage::Change { key, record: None }])
        .await
        .unwrap();
    assert!(matches!(
        global.warn(&subject("member")).await,
        Err(Error::KeyMismatch)
    ));
}

#[tokio::test]
async fn imported_account_mismatches_cannot_authorize_issuance() {
    let (global, store, _, _) = make().await;
    let provider = Provider::default();
    global
        .run_gate(&provider, &subject("member"), b"unique", 100, &check())
        .await
        .unwrap();
    let key = storage::Key::new("account", "member");
    let original = store
        .read(std::slice::from_ref(&key))
        .await
        .unwrap()
        .records[&key]
        .clone();
    let mut rng = StdRng::seed_from_u64(12);
    for field in ["subject", "provider", "expiry", "fingerprint"] {
        let mut value: serde_json::Value = serde_json::from_slice(&original.value).unwrap();
        match field {
            "subject" => value["gates"]["phone"]["subject"] = serde_json::json!("other"),
            "provider" => value["gates"]["phone"]["provider"] = serde_json::json!("other"),
            "expiry" => value["gates"]["phone"]["valid_until"] = serde_json::json!(COHORT - DAY),
            _ => value["fingerprints"] = serde_json::json!({}),
        }
        let read = store.read(std::slice::from_ref(&key)).await.unwrap();
        store
            .compare_exchange(
                &read,
                vec![storage::Change {
                    key: key.clone(),
                    record: Some(storage::Record {
                        value: serde_json::to_vec(&value).unwrap(),
                        deadline: 0,
                    }),
                }],
            )
            .await
            .unwrap();
        assert!(
            matches!(
                global
                    .challenge(&mut rng, &session("member"), 100, 150)
                    .await,
                Err(Error::Gates)
            ),
            "{field}"
        );
        assert!(
            store
                .list("challenge", "", 10)
                .await
                .unwrap()
                .records
                .is_empty()
        );
    }
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_a_provider_during_verification_refuses_its_late_receipt() {
    let (global, store, _, _) = make().await;
    let global = Arc::new(global);
    let provider = Arc::new(Provider::default());
    provider.delay.store(true, Ordering::SeqCst);
    let task = {
        let global = global.clone();
        let provider = provider.clone();
        tokio::spawn(async move {
            global
                .run_gate(&*provider, &subject("alice"), b"unique", 100, &check())
                .await
        })
    };
    provider.started.notified().await;
    install(&global, 2, 2, COHORT, 100, "replacement")
        .await
        .unwrap();
    provider.release.notify_one();
    assert!(matches!(task.await.unwrap(), Err(Error::GateDisabled)));
    assert!(
        store
            .list("account", "", 10)
            .await
            .unwrap()
            .records
            .is_empty()
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn status_refuses_tampering_future_minima_and_regressing_publication_time() {
    let (mut global, _, _, _) = make().await;
    assert!(matches!(
        global.signed_status(100, 100).await,
        Err(Error::Signature)
    ));
    let original = global.signed_status(100, 2 * DAY).await.unwrap();
    let mut tampered = original.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        Status::verify(&tampered, global.key_ring().unwrap(), "global", 1, 1, 100),
        Err(Error::Signature)
    ));
    assert!(matches!(
        Status::verify(&original, global.key_ring().unwrap(), "global", 1, 2, 100),
        Err(Error::Policy)
    ));
    assert!(matches!(
        global.signed_status(90, 2 * DAY).await,
        Err(Error::Signature)
    ));
    assert_eq!(global.public_status(100, 2 * DAY).await.unwrap(), original);
}

#[tokio::test]
async fn open_refuses_a_real_signer_invalidated_by_a_competing_writer() {
    let keys = csgn::MemoryStore::default();
    let mut stale = csgn::PersistentSigner::create(
        keys.clone(),
        "cglb:global",
        csgn::SecretKey::from_seed(&mut [2; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    let mut winner = csgn::PersistentSigner::open(
        keys,
        "cglb:global",
        csgn::SecretKey::from_seed(&mut [2; 32]),
        0,
    )
    .await
    .unwrap();
    winner
        .sign(csgn::Kind::SettingsSnapshot, b"winner", 0, DAY)
        .await
        .unwrap();
    assert!(
        stale
            .sign(csgn::Kind::SettingsSnapshot, b"stale", 0, DAY)
            .await
            .is_err()
    );
    let issuance = cpsd::MemoryStore::new(cpsd::CommunityId::new(b"global").unwrap(), 2).unwrap();
    assert!(matches!(
        Global::open(
            MemoryStore::new("global").unwrap(),
            issuance,
            issuer(),
            stale,
            fingerprints(),
            Mode::Production,
            Limits {
                challenge_ttl: 60,
                pending_capacity: 2
            }
        )
        .await,
        Err(Error::Signature)
    ));
}

#[tokio::test]
async fn reserved_provider_names_and_mismatched_replayed_receipts_refuse() {
    struct NamedProvider(&'static str, &'static str);
    impl GlobalGate for NamedProvider {
        fn id(&self) -> &str {
            self.0
        }
        fn provider(&self) -> &str {
            self.1
        }
        fn development_only(&self) -> bool {
            false
        }
        async fn verify(&self, _: &CheckId, _: &Subject, _: &[u8], _: u64) -> Result<GateEvidence> {
            panic!("unauthorized external provider must not be called")
        }
    }
    let (global, store, _, _) = make().await;
    for gate in [
        NamedProvider("development", "sms"),
        NamedProvider("phone", "cglb.test"),
    ] {
        assert!(matches!(
            global
                .run_gate(&gate, &subject("member"), b"input", 100, &check())
                .await,
            Err(Error::DevelopmentDisabled)
        ));
    }
    assert!(matches!(
        global
            .run_gate(
                &NamedProvider("phone", "other"),
                &subject("member"),
                b"input",
                100,
                &check()
            )
            .await,
        Err(Error::GateDisabled)
    ));
    let provider = Provider::default();
    let id = check();
    global
        .run_gate(&provider, &subject("member"), b"input", 100, &id)
        .await
        .unwrap();
    let key = storage::Key::new("account", "member");
    let original = store
        .read(std::slice::from_ref(&key))
        .await
        .unwrap()
        .records[&key]
        .clone();
    for field in ["provider", "valid_until"] {
        let mut value: serde_json::Value = serde_json::from_slice(&original.value).unwrap();
        value["gates"]["phone"][field] = if field == "provider" {
            serde_json::json!("other")
        } else {
            serde_json::json!(99)
        };
        let read = store.read(std::slice::from_ref(&key)).await.unwrap();
        store
            .compare_exchange(
                &read,
                vec![storage::Change {
                    key: key.clone(),
                    record: Some(storage::Record {
                        value: serde_json::to_vec(&value).unwrap(),
                        deadline: 0,
                    }),
                }],
            )
            .await
            .unwrap();
        assert!(matches!(
            global
                .run_gate(&provider, &subject("member"), b"input", 100, &id)
                .await,
            Err(Error::Gates)
        ));
    }
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cached_status_observes_revision_changes_and_refuses_same_version_equivocation() {
    let (mut global, store, _, _) = make().await;
    let first = global.public_status(100, 2 * DAY).await.unwrap();
    let key = storage::Key::new("meta", "state");
    let observed = store.read(std::slice::from_ref(&key)).await.unwrap();
    let mut state: serde_json::Value =
        serde_json::from_slice(&observed.records[&key].value).unwrap();
    state["policy"]["revision"] = serde_json::json!(2);
    store
        .compare_exchange(
            &observed,
            vec![storage::Change {
                key: key.clone(),
                record: Some(storage::Record {
                    value: serde_json::to_vec(&state).unwrap(),
                    deadline: 0,
                }),
            }],
        )
        .await
        .unwrap();
    let second = global.public_status(100, 2 * DAY).await.unwrap();
    assert_ne!(first, second);
    Status::verify(&second, global.key_ring().unwrap(), "global", 1, 2, 100).unwrap();
    let mut changed = state.clone();
    changed["policy"]["shared_expiry"] = serde_json::json!(COHORT + DAY);
    let observed = store.read(std::slice::from_ref(&key)).await.unwrap();
    store
        .compare_exchange(
            &observed,
            vec![storage::Change {
                key: key.clone(),
                record: Some(storage::Record {
                    value: serde_json::to_vec(&changed).unwrap(),
                    deadline: 0,
                }),
            }],
        )
        .await
        .unwrap();
    assert!(matches!(
        global.public_status(100, 2 * DAY).await,
        Err(Error::Signature)
    ));
    let observed = store.read(std::slice::from_ref(&key)).await.unwrap();
    store
        .compare_exchange(
            &observed,
            vec![storage::Change {
                key,
                record: Some(storage::Record {
                    value: serde_json::to_vec(&state).unwrap(),
                    deadline: 0,
                }),
            }],
        )
        .await
        .unwrap();
    assert_eq!(global.public_status(100, 2 * DAY).await.unwrap(), second);
}
