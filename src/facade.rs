use crate::{
    fingerprint::hex,
    storage::{Change, Key, ReadSet, Record, Store},
    *,
};
use cpsd::{
    IssuanceChallenge, IssuanceRequest, IssuerKey, PassportAttributes,
    rand::{CryptoRng, RngCore},
};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::BTreeSet;

fn meta(id: &str) -> Key {
    Key::new("meta", id)
}
fn account(subject: &Subject) -> Key {
    Key::new("account", subject.as_str())
}
fn get<T: DeserializeOwned>(read: &ReadSet, key: &Key) -> Result<Option<T>> {
    read.records
        .get(key)
        .map(|r| serde_json::from_slice(&r.value).map_err(|_| Error::Encoding))
        .transpose()
}
fn put(key: Key, value: &impl Serialize) -> Result<Change> {
    Ok(Change {
        key,
        record: Some(Record {
            value: serde_json::to_vec(value).map_err(|_| Error::Encoding)?,
            deadline: 0,
        }),
    })
}
fn delete(key: Key) -> Change {
    Change { key, record: None }
}
fn count(read: &ReadSet) -> Result<u32> {
    Ok(get(read, &meta("pending-count"))?.unwrap_or(0))
}

/// Service-selected resource limits. No credentials or clocks are discovered.
#[derive(Clone, Copy)]
pub struct Limits {
    /// Maximum outstanding challenge lifetime in seconds.
    pub challenge_ttl: u64,
    /// Maximum number of pending challenges, including expired unpruned ones.
    pub pending_capacity: u32,
}
/// Global service facade. Keep its stores and keys separate from every community.
///
/// Methods require already authenticated/authorized callers. One csgn writer
/// owns publication. Concurrent identity operations are fenced by storage CAS.
pub struct Global<S, K> {
    store: S,
    issuer: IssuerKey,
    signer: csgn::PersistentSigner<K>,
    fingerprints: FingerprintKey,
    binding: Binding,
    mode: Mode,
    limits: Limits,
}
impl<S: Store, K: csgn::Store> Global<S, K> {
    /// Open or initialize key bindings. Existing stores reject a changed HMAC
    /// key or BBS issuer. The signer must be named `cglb:<scope>`.
    pub async fn open(
        store: S,
        issuer: IssuerKey,
        signer: csgn::PersistentSigner<K>,
        fingerprints: FingerprintKey,
        mode: Mode,
        limits: Limits,
    ) -> Result<Self> {
        validate_id(store.scope())?;
        if limits.challenge_ttl == 0
            || limits.challenge_ttl >= cpsd::TIME_LIMIT
            || limits.pending_capacity == 0
        {
            return Err(Error::Capacity);
        }
        if signer.key_ring().map_err(|_| Error::Signature)?.issuer()
            != format!("cglb:{}", store.scope())
        {
            return Err(Error::KeyMismatch);
        }
        if mode == Mode::Production
            && issuer
                .public_key()
                .gates()
                .iter()
                .any(|g| g.as_str() == "development")
        {
            return Err(Error::DevelopmentDisabled);
        }
        let binding = Binding {
            issuer: issuer.public_key().to_bytes(),
            fingerprint_key_check: fingerprints.fingerprint(
                store.scope(),
                "",
                b"cglb/key-check/v1",
            ),
        };
        let read = store.read(&[meta("binding")]).await?;
        match get::<Binding>(&read, &meta("binding"))? {
            Some(saved) if saved != binding => return Err(Error::KeyMismatch),
            Some(_) => (),
            None => {
                store
                    .compare_exchange(read.revision, vec![put(meta("binding"), &binding)?])
                    .await?
            }
        }
        Ok(Self {
            store,
            issuer,
            signer,
            fingerprints,
            binding,
            mode,
            limits,
        })
    }
    async fn read(&self, mut keys: Vec<Key>) -> Result<ReadSet> {
        keys.extend([meta("binding"), meta("state")]);
        let read = self.store.read(&keys).await?;
        if get::<Binding>(&read, &meta("binding"))?.as_ref() != Some(&self.binding) {
            return Err(Error::KeyMismatch);
        }
        Ok(read)
    }
    fn state(&self, read: &ReadSet, now: u64) -> Result<State> {
        time(now)?;
        let state: State = get(read, &meta("state"))?.ok_or(Error::NoPolicy)?;
        if state.policy.shared_expiry < now {
            return Err(Error::Policy);
        }
        Ok(state)
    }
    /// Import the local typed global-policy wire format from a trusted csgn
    /// settings authority. This authority/ring must be service configured.
    pub async fn install_policy(
        &self,
        cose: &[u8],
        trusted: &csgn::KeyRing,
        now: u64,
    ) -> Result<()> {
        time(now)?;
        let verified = trusted
            .verify(cose, csgn::Kind::SettingsSnapshot, now)
            .map_err(|_| Error::Signature)?;
        let policy: Policy =
            serde_json::from_slice(verified.payload()).map_err(|_| Error::Policy)?;
        if policy.version != 1
            || policy.scope != self.store.scope()
            || policy.revision == 0
            || policy.epoch == 0
            || policy.shared_expiry < now
            || policy.shared_expiry >= verified.valid_until()
            || policy.gates.is_empty()
            || policy.gates.len() > cpsd::MAX_GATES
            || !policy.gates.iter().any(|g| g.uniqueness)
        {
            return Err(Error::Policy);
        }
        time(policy.shared_expiry)?;
        let mut seen = BTreeSet::new();
        for gate in &policy.gates {
            let id = cpsd::GateId::new(&gate.gate).map_err(|_| Error::Policy)?;
            validate_id(&gate.provider).map_err(|_| Error::Policy)?;
            if !seen.insert(&gate.gate) || !self.issuer.public_key().gates().contains(&id) {
                return Err(Error::Policy);
            }
            if self.mode == Mode::Production
                && (gate.gate == "development" || gate.provider == "cglb.test")
            {
                return Err(Error::DevelopmentDisabled);
            }
        }
        let read = self.read(vec![]).await?;
        if let Some(old) = get::<State>(&read, &meta("state"))? {
            if old.policy == policy {
                return Ok(());
            }
            if policy.revision <= old.policy.revision || policy.epoch <= old.epoch {
                return Err(Error::Policy);
            }
        }
        let state = State {
            epoch: policy.epoch,
            policy,
        };
        self.store
            .compare_exchange(read.revision, vec![put(meta("state"), &state)?])
            .await
    }
    /// Execute a trusted adapter, validate policy, and atomically reserve any
    /// uniqueness input. Input and canonical evidence are never persisted.
    pub async fn run_gate<G: GlobalGate>(
        &self,
        gate: &G,
        subject: &Subject,
        input: &[u8],
        now: u64,
    ) -> Result<GateResult> {
        time(now)?;
        if self.mode == Mode::Production
            && (gate.development_only()
                || gate.id() == "development"
                || gate.provider() == "cglb.test")
        {
            return Err(Error::DevelopmentDisabled);
        }
        // Check configuration before invoking a possibly costly provider.
        let before = self.read(vec![account(subject)]).await?;
        let state = self.state(&before, now)?;
        let required = state
            .policy
            .gates
            .iter()
            .find(|g| g.gate == gate.id() && g.provider == gate.provider())
            .ok_or(Error::GateDisabled)?;
        let existing: Account = get(&before, &account(subject))?.unwrap_or_default();
        existing.eligible(now)?;
        let evidence = gate.verify(subject, input, now).await?;
        time(evidence.valid_until)?;
        if evidence.valid_until < now {
            return Err(Error::Gates);
        }
        let fingerprint = if required.uniqueness {
            let canonical = evidence.uniqueness.as_ref().ok_or(Error::Gates)?;
            Some(
                self.fingerprints
                    .fingerprint(self.store.scope(), gate.id(), canonical),
            )
        } else {
            None
        };
        let fingerprint_key = fingerprint
            .as_ref()
            .map(|f| Key::new("fingerprint", format!("{}:{f}", gate.id())));
        let mut keys = vec![account(subject)];
        keys.extend(fingerprint_key.iter().cloned());
        let read = self.read(keys).await?;
        if read.revision != before.revision {
            return Err(Error::Conflict);
        }
        let mut person = existing;
        let mut changes = vec![];
        if let (Some(fingerprint), Some(key)) = (fingerprint, fingerprint_key) {
            if person
                .fingerprints
                .get(gate.id())
                .is_some_and(|old| old != &fingerprint)
            {
                return Err(Error::UniquenessChanged);
            }
            if get::<Subject>(&read, &key)?.is_some_and(|owner| owner != *subject) {
                return Err(Error::Duplicate);
            }
            person.fingerprints.insert(gate.id().into(), fingerprint);
            changes.push(put(key, subject)?);
        }
        let result = GateResult {
            gate: gate.id().into(),
            level: Level::Global,
            subject: subject.clone(),
            provider: gate.provider().into(),
            valid_until: evidence.valid_until,
        };
        // Only current policy gates are retained; immutable fingerprint reservations remain.
        person
            .gates
            .retain(|id, _| state.policy.gates.iter().any(|g| &g.gate == id));
        person.gates.insert(gate.id().into(), result.clone());
        changes.push(put(account(subject), &person)?);
        self.store.compare_exchange(read.revision, changes).await?;
        Ok(result)
    }
    fn attributes(
        &self,
        state: &State,
        person: &Account,
        subject: &Subject,
        now: u64,
    ) -> Result<PassportAttributes> {
        person.eligible(now)?;
        let mut attrs = PassportAttributes::new(state.policy.shared_expiry, state.epoch);
        for requirement in &state.policy.gates {
            let passed = person.gates.get(&requirement.gate).ok_or(Error::Gates)?;
            if passed.subject != *subject
                || passed.provider != requirement.provider
                || passed.valid_until < state.policy.shared_expiry
                || (requirement.uniqueness && !person.fingerprints.contains_key(&requirement.gate))
            {
                return Err(Error::Gates);
            }
            attrs = attrs.with_gate(
                cpsd::GateId::new(&requirement.gate).map_err(|_| Error::Encoding)?,
                state.policy.shared_expiry,
            );
        }
        Ok(attrs)
    }
    /// Create a subject/key/epoch-bound nonce. Expired outstanding rows count
    /// towards capacity until pruned. Time and deadline come from the service.
    pub async fn challenge<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        subject: &Subject,
        now: u64,
        deadline: u64,
    ) -> Result<IssuanceChallenge> {
        time(now)?;
        time(deadline)?;
        if deadline <= now || deadline - now > self.limits.challenge_ttl {
            return Err(Error::InvalidTime);
        }
        let challenge = IssuanceChallenge::generate(rng);
        let key = Key::new("challenge", hex(&challenge.to_bytes()));
        let read = self
            .read(vec![account(subject), meta("pending-count"), key.clone()])
            .await?;
        let state = self.state(&read, now)?;
        if deadline > state.policy.shared_expiry {
            return Err(Error::InvalidTime);
        }
        let person: Account = get(&read, &account(subject))?.ok_or(Error::UnknownSubject)?;
        self.attributes(&state, &person, subject, now)?;
        if read.records.contains_key(&key) {
            return Err(Error::Challenge);
        }
        let count = count(&read)?;
        if count >= self.limits.pending_capacity {
            return Err(Error::Capacity);
        }
        let pending = Pending {
            subject: subject.clone(),
            epoch: state.epoch,
            issuer: self.binding.issuer.clone(),
            deadline,
        };
        let mut change = put(key, &pending)?;
        change.record.as_mut().ok_or(Error::Encoding)?.deadline = deadline;
        self.store
            .compare_exchange(
                read.revision,
                vec![change, put(meta("pending-count"), &(count + 1))?],
            )
            .await?;
        Ok(challenge)
    }
    /// Verify and blind-sign through cpsd, then atomically consume the nonce and
    /// bind its verified issuer tag before any passport response escapes.
    ///
    /// This composes cpsd's pure operation with the same single-use boundary as
    /// issue_blind_once, extended to commit identity continuity in the same CAS.
    pub async fn issue<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        subject: &Subject,
        challenge: &IssuanceChallenge,
        request: &IssuanceRequest,
        now: u64,
    ) -> Result<cpsd::BlindPassport> {
        let pending_key = Key::new("challenge", hex(&challenge.to_bytes()));
        let tag = request.issuer_tag().to_bytes().to_vec();
        let tag_key = Key::new("tag", hex(&tag));
        let read = self
            .read(vec![
                account(subject),
                meta("pending-count"),
                pending_key.clone(),
                tag_key.clone(),
            ])
            .await?;
        let state = self.state(&read, now)?;
        let pending: Pending = get(&read, &pending_key)?.ok_or(Error::Challenge)?;
        if pending.subject != *subject
            || pending.epoch != state.epoch
            || pending.issuer != self.binding.issuer
            || now > pending.deadline
        {
            return Err(Error::Challenge);
        }
        let mut person: Account = get(&read, &account(subject))?.ok_or(Error::UnknownSubject)?;
        let attributes = self.attributes(&state, &person, subject, now)?;
        if person.tag.as_ref().is_some_and(|old| old != &tag) {
            return Err(Error::HolderChanged);
        }
        if get::<Subject>(&read, &tag_key)?.is_some_and(|owner| owner != *subject) {
            return Err(Error::Duplicate);
        }
        let passport = self
            .issuer
            .issue_blind(rng, request, challenge, &attributes)
            .map_err(|_| Error::Passport)?;
        // Only the successful leaf proof makes the untrusted tag authoritative.
        person.tag = Some(tag);
        let remaining = count(&read)?.checked_sub(1).ok_or(Error::Encoding)?;
        let mut changes = vec![
            put(tag_key, subject)?,
            delete(pending_key),
            put(meta("pending-count"), &remaining)?,
        ];
        if person.suspension.is_some() {
            person.suspension = None;
            changes.push(delete(Key::new("revocation", subject.as_str())));
        }
        changes.push(put(account(subject), &person)?);
        self.store.compare_exchange(read.revision, changes).await?;
        Ok(passport)
    }
    /// Record that the service delivered a warning; no time or message is stored.
    pub async fn warn(&self, subject: &Subject) -> Result<()> {
        let read = self.read(vec![account(subject)]).await?;
        let mut person: Account = get(&read, &account(subject))?.ok_or(Error::UnknownSubject)?;
        if matches!(person.suspension, Some(Suspension::Permanent(_))) {
            return Err(Error::Suspended);
        }
        person.warned = true;
        self.store
            .compare_exchange(read.revision, vec![put(account(subject), &person)?])
            .await
    }
    /// Apply an authorized suspension and atomically advance the public epoch.
    /// Permanent records cannot be replaced or downgraded. Exact retries are idempotent.
    pub async fn suspend(
        &self,
        subject: &Subject,
        suspension: Suspension,
        now: u64,
    ) -> Result<u64> {
        time(now)?;
        if let Suspension::Temporary { until } = &suspension {
            time(*until)?;
            if *until <= now {
                return Err(Error::InvalidTime);
            }
        }
        let read = self.read(vec![account(subject)]).await?;
        // Suspension still works when the previous passport policy has expired.
        let mut state: State = get(&read, &meta("state"))?.ok_or(Error::NoPolicy)?;
        let mut person: Account = get(&read, &account(subject))?.ok_or(Error::UnknownSubject)?;
        if person.suspension.as_ref() == Some(&suspension) {
            return Ok(state.epoch);
        }
        if matches!(person.suspension, Some(Suspension::Permanent(_))) {
            return Err(Error::Suspended);
        }
        if matches!(suspension, Suspension::Temporary { .. }) && !person.warned {
            return Err(Error::WarningRequired);
        }
        state.epoch = state.epoch.checked_add(1).ok_or(Error::Exhausted)?;
        person.suspension = Some(suspension.clone());
        person.warned = false;
        let revocation = Revocation {
            subject: subject.clone(),
            suspension,
        };
        self.store
            .compare_exchange(
                read.revision,
                vec![
                    put(account(subject), &person)?,
                    put(meta("state"), &state)?,
                    put(Key::new("revocation", subject.as_str()), &revocation)?,
                ],
            )
            .await?;
        Ok(state.epoch)
    }
    /// Private administrative list, paginated by subject ID (exclusive cursor).
    pub async fn revocations(&self, after: &str, limit: u32) -> Result<Vec<Revocation>> {
        if limit == 0 || limit > 1000 {
            return Err(Error::Capacity);
        }
        let read = self.store.list("revocation", after, limit).await?;
        read.records
            .values()
            .map(|r| serde_json::from_slice(&r.value).map_err(|_| Error::Encoding))
            .collect()
    }
    /// Delete a bounded batch of expired pending nonces, maintaining capacity.
    pub async fn prune_challenges(&self, now: u64, limit: u32) -> Result<usize> {
        time(now)?;
        if limit == 0 || limit > 1000 {
            return Err(Error::Capacity);
        }
        let expired = self.store.expired(now, limit).await?;
        if expired.records.is_empty() {
            return Ok(0);
        }
        let read = self.read(vec![meta("pending-count")]).await?;
        if read.revision != expired.revision {
            return Err(Error::Conflict);
        }
        let size = expired.records.len();
        let remaining = count(&read)?
            .checked_sub(size as u32)
            .ok_or(Error::Encoding)?;
        let mut changes: Vec<_> = expired.records.into_keys().map(delete).collect();
        changes.push(put(meta("pending-count"), &remaining)?);
        self.store.compare_exchange(read.revision, changes).await?;
        Ok(size)
    }
    /// Sign public epoch/status without exposing the private revocation list.
    pub async fn signed_status(&mut self, now: u64, valid_until: u64) -> Result<Vec<u8>> {
        time(now)?;
        let read = self.read(vec![]).await?;
        let state: State = get(&read, &meta("state"))?.ok_or(Error::NoPolicy)?;
        let status = Status {
            version: 1,
            scope: self.store.scope().into(),
            epoch: state.epoch,
            policy_revision: state.policy.revision,
            shared_expiry: state.policy.shared_expiry,
            issuer_public_key: self.binding.issuer.clone(),
        };
        let payload = serde_json::to_vec(&status).map_err(|_| Error::Encoding)?;
        let signed = self
            .signer
            .sign(
                csgn::Kind::RevocationListSnapshot,
                &payload,
                now,
                valid_until,
            )
            .await
            .map_err(|_| Error::Signature)?;
        // Do not publish a snapshot superseded while its signing state committed.
        let current = self.read(vec![]).await?;
        if current.revision != read.revision {
            return Err(Error::Conflict);
        }
        Ok(signed)
    }
    /// Public COSE key ring. Its transport and freshness must be authenticated.
    pub fn key_ring(&self) -> Result<&csgn::KeyRing> {
        self.signer.key_ring().map_err(|_| Error::Signature)
    }
    /// Publish the BBS public key to holders through an authenticated channel.
    pub fn issuer_public_key(&self) -> &cpsd::IssuerPublicKey {
        self.issuer.public_key()
    }
    /// Delegate durable COSE rotation; provision the new seed before calling.
    pub async fn rotate_signing_key(&mut self, key: csgn::SecretKey, now: u64) -> Result<()> {
        self.signer
            .rotate(key, now)
            .await
            .map_err(|_| Error::Signature)
    }
}
impl Status {
    /// Verify against a trusted ring and freshness minima held by the consumer.
    /// Refresh minima through an authenticated channel; old signatures alone
    /// cannot establish that an epoch is still current.
    pub fn verify(
        cose: &[u8],
        ring: &csgn::KeyRing,
        scope: &str,
        minimum_epoch: u64,
        minimum_revision: u64,
        now: u64,
    ) -> Result<Self> {
        if ring.issuer() != format!("cglb:{scope}") {
            return Err(Error::Signature);
        }
        let verified = ring
            .verify(cose, csgn::Kind::RevocationListSnapshot, now)
            .map_err(|_| Error::Signature)?;
        let value: Self =
            serde_json::from_slice(verified.payload()).map_err(|_| Error::Encoding)?;
        if value.version != 1
            || value.scope != scope
            || value.epoch < minimum_epoch
            || value.policy_revision < minimum_revision
        {
            return Err(Error::Policy);
        }
        time(value.shared_expiry)?;
        cpsd::IssuerPublicKey::from_bytes(&value.issuer_public_key).map_err(|_| Error::Encoding)?;
        Ok(value)
    }
}
