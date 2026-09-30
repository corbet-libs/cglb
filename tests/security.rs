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
