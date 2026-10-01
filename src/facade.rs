use crate::{
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
pub struct Global<S, K, I> {
    issuance: I,
    store: S,
    issuer: IssuerKey,
    signer: csgn::PersistentSigner<K>,
    fingerprints: FingerprintKey,
    binding: Binding,
    beacon: cbcn::document::Cache<Status>,
    mode: Mode,
    limits: Limits,
}
impl<S: Store, K: csgn::Store, I: cpsd::IssuanceStore> Global<S, K, I> {
    /// Open or initialize key bindings. Existing stores reject a changed HMAC
    /// key or BBS issuer. The signer must be named `cglb:<scope>`.
    pub async fn open(
        store: S,
        issuance: I,
        issuer: IssuerKey,
        signer: csgn::PersistentSigner<K>,
        fingerprints: FingerprintKey,
        mode: Mode,
        limits: Limits,
    ) -> Result<Self> {
        validate_id(store.scope())?;
        if issuance.community().as_bytes() != store.scope().as_bytes() {
            return Err(Error::KeyMismatch);
        }
        if signer
            .key_ring()
            .map_err(|_| Error::Signature)?
            .active()
            .ok_or(Error::Signature)?
            .activated_at()
            % 86_400
            != 0
        {
            return Err(Error::InvalidTime);
        }
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
            version: 2,
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
                    .compare_exchange(&read, vec![put(meta("binding"), &binding)?])
                    .await?
            }
        }
        Ok(Self {
            issuance,
            store,
            issuer,
            signer,
            fingerprints,
            binding,
            beacon: cbcn::document::Cache::default(),
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
            || !policy.shared_expiry.is_multiple_of(86_400)
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
        let local_epoch = if let Some(old) = get::<State>(&read, &meta("state"))? {
            if old.policy == policy {
                return Ok(());
            }
            if policy.revision <= old.policy.revision
                || policy.epoch != old.policy.epoch.checked_add(1).ok_or(Error::Exhausted)?
            {
                return Err(Error::Policy);
            }
            old.local_epoch
        } else {
            if policy.epoch != 1 {
                return Err(Error::Policy);
            }
            0
        };
        let state = State {
            policy,
            local_epoch,
        };
        state.epoch()?;
        self.store
            .compare_exchange(&read, vec![put(meta("state"), &state)?])
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
        check: &CheckId,
    ) -> Result<GateResult> {
        time(now)?;
        check.validate()?;
        if self.mode == Mode::Production
            && (gate.development_only()
                || gate.id() == "development"
                || gate.provider() == "cglb.test")
        {
            return Err(Error::DevelopmentDisabled);
        }
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
        let provider_check = self.fingerprints.check_id(
            self.store.scope(),
            subject,
            gate.id(),
            gate.provider(),
            check,
        );
        let input_binding =
            self.fingerprints
                .fingerprint(self.store.scope(), provider_check.as_str(), input);
        if existing.check_ids.get(gate.id()) == Some(&provider_check) {
            if existing.check_inputs.get(gate.id()) != Some(&input_binding) {
                return Err(Error::Conflict);
            }
            return existing
                .gates
                .get(gate.id())
                .filter(|r| r.provider == gate.provider() && r.valid_until >= now)
                .cloned()
                .ok_or(Error::Gates);
        }
        // A provider must deduplicate this key across concurrent calls, outages
        // and caller cancellation. It is independent of policy and retry time.
        let evidence = gate.verify(&provider_check, subject, input, now).await?;
        time(evidence.valid_until)?;
        let valid_until = evidence.valid_until / 86_400 * 86_400;
        if valid_until < now {
            return Err(Error::Gates);
        }
        let fingerprint = if required.uniqueness {
            Some(self.fingerprints.fingerprint(
                self.store.scope(),
                gate.id(),
                evidence.uniqueness.as_ref().ok_or(Error::Gates)?,
            ))
        } else {
            None
        };
        let fingerprint_key = fingerprint
            .as_ref()
            .map(|value| Key::new("fingerprint", format!("{}:{value}", gate.id())));
        let result = GateResult {
            gate: gate.id().into(),
            level: Level::Global,
            subject: subject.clone(),
            provider: gate.provider().into(),
            valid_until,
        };
        // Retry only the commit. Never repeat a paid verification after a CAS
        // conflict, and never couple the receipt to another person's revision.
        for _ in 0..16 {
            let mut keys = vec![account(subject)];
            keys.extend(fingerprint_key.iter().cloned());
            let read = self.read(keys).await?;
            let current = self.state(&read, now)?;
            if !current.policy.gates.contains(required) {
                return Err(Error::GateDisabled);
            }
            let mut person: Account = get(&read, &account(subject))?.unwrap_or_default();
            person.eligible(now)?;
            let mut changes = vec![];
            if let (Some(value), Some(key)) = (&fingerprint, &fingerprint_key) {
                if person
                    .fingerprints
                    .get(gate.id())
                    .is_some_and(|old| old != value)
                {
                    return Err(Error::UniquenessChanged);
                }
                if get::<Subject>(&read, key)?.is_some_and(|owner| owner != *subject) {
                    return Err(Error::Duplicate);
                }
                person.fingerprints.insert(gate.id().into(), value.clone());
                changes.push(put(key.clone(), subject)?);
            }
            person
                .gates
                .retain(|id, _| current.policy.gates.iter().any(|g| &g.gate == id));
            person
                .check_ids
                .retain(|id, _| person.gates.contains_key(id));
            person
                .check_inputs
                .retain(|id, _| person.gates.contains_key(id));
            person.gates.insert(gate.id().into(), result.clone());
            person
                .check_ids
                .insert(gate.id().into(), provider_check.clone());
            person
                .check_inputs
                .insert(gate.id().into(), input_binding.clone());
            changes.push(put(account(subject), &person)?);
            match self.store.compare_exchange(&read, changes).await {
                Ok(()) => return Ok(result),
                Err(Error::Conflict) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(Error::Conflict)
    }
    fn attributes(
        &self,
        state: &State,
        person: &Account,
        subject: &Subject,
        now: u64,
    ) -> Result<PassportAttributes> {
        person.eligible(now)?;
        let mut attrs = PassportAttributes::new(state.policy.shared_expiry, state.epoch()?);
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
    fn authenticated_issuance(&self, session: &Session) -> cpsd::AuthenticatedIssuance {
        cpsd::AuthenticatedIssuance::new(
            self.fingerprints
                .person_id(self.store.scope(), &session.subject),
            session.id,
        )
    }
    /// Reserve one outstanding issuance per person, before invoking cpsd.
    /// The short protocol deadline retains seconds to bound challenge replay and
    /// capacity. A cancelled request retains only this bounded pending slot.
    pub async fn challenge<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        session: &Session,
        now: u64,
        deadline: u64,
    ) -> Result<IssuanceChallenge> {
        time(now)?;
        time(deadline)?;
        if deadline <= now || deadline - now > self.limits.challenge_ttl {
            return Err(Error::InvalidTime);
        }
        let subject = &session.subject;
        let key = Key::new("challenge", subject.as_str());
        let mut epoch = None;
        for _ in 0..16 {
            let read = self
                .read(vec![account(subject), key.clone(), meta("pending-count")])
                .await?;
            let state = self.state(&read, now)?;
            if deadline > state.policy.shared_expiry {
                return Err(Error::InvalidTime);
            }
            let person: Account = get(&read, &account(subject))?.ok_or(Error::UnknownSubject)?;
            self.attributes(&state, &person, subject, now)?;
            let previous: Option<Pending> = get(&read, &key)?;
            if previous.as_ref().is_some_and(|p| p.deadline >= now) {
                return Err(Error::Capacity);
            }
            let count = count(&read)?;
            if previous.is_none() && count >= self.limits.pending_capacity {
                return Err(Error::Capacity);
            }
            let pending = Pending {
                epoch: state.epoch()?,
                session: session.id,
                nonce: None,
                deadline,
            };
            let mut change = put(key.clone(), &pending)?;
            change.record.as_mut().ok_or(Error::Encoding)?.deadline = deadline;
            let next = count + u32::from(previous.is_none());
            match self
                .store
                .compare_exchange(&read, vec![change, put(meta("pending-count"), &next)?])
                .await
            {
                Ok(()) => {
                    epoch = Some(pending.epoch);
                    break;
                }
                Err(Error::Conflict) => continue,
                Err(error) => return Err(error),
            }
        }
        let epoch = epoch.ok_or(Error::Conflict)?;
        // cpsd owns nonce storage, replay, person/session binding and continuity.
        // Pruning never releases its permanent holder-tag bindings.
        self.issuance.prune(now).await.map_err(passport_error)?;
        let challenge = cpsd::issuance_challenge(
            rng,
            &self.issuance,
            self.issuer.public_key(),
            &self.authenticated_issuance(session),
            deadline,
        )
        .await
        .map_err(passport_error)?;
        let read = self.read(vec![account(subject), key.clone()]).await?;
        let state = self.state(&read, now)?;
        let person: Account = get(&read, &account(subject))?.ok_or(Error::UnknownSubject)?;
        self.attributes(&state, &person, subject, now)?;
        let mut pending: Pending = get(&read, &key)?.ok_or(Error::Challenge)?;
        if pending.epoch != epoch
            || state.epoch()? != epoch
            || pending.session != session.id
            || pending.deadline != deadline
            || pending.nonce.is_some()
        {
            return Err(Error::Challenge);
        }
        pending.nonce = Some(challenge.to_bytes());
        let mut change = put(key, &pending)?;
        change.record.as_mut().ok_or(Error::Encoding)?.deadline = deadline;
        self.store.compare_exchange(&read, vec![change]).await?;
        Ok(challenge)
    }
    /// Delegate blind issuance, atomic nonce consumption and holder continuity
    /// to cpsd, then fence current person/policy state before releasing a response.
    /// No issuer tag or holder continuity implementation exists in cglb.
    pub async fn issue<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        session: &Session,
        challenge: &IssuanceChallenge,
        request: &IssuanceRequest,
        now: u64,
    ) -> Result<cpsd::BlindPassport> {
        let subject = &session.subject;
        let pending_key = Key::new("challenge", subject.as_str());
        let revocation_key = Key::new("revocation", subject.as_str());
        let read = self
            .read(vec![
                account(subject),
                pending_key.clone(),
                revocation_key.clone(),
            ])
            .await?;
        let state = self.state(&read, now)?;
        let pending: Pending = get(&read, &pending_key)?.ok_or(Error::Challenge)?;
        if pending.epoch != state.epoch()?
            || pending.session != session.id
            || pending.nonce != Some(challenge.to_bytes())
            || now > pending.deadline
        {
            return Err(Error::Challenge);
        }
        let person: Account = get(&read, &account(subject))?.ok_or(Error::UnknownSubject)?;
        let attributes = self.attributes(&state, &person, subject, now)?;
        let passport = cpsd::issue_blind_once(
            rng,
            &self.issuance,
            &self.issuer,
            &self.authenticated_issuance(session),
            request,
            challenge,
            &attributes,
            now,
        )
        .await
        .map_err(passport_error)?;
        // Capacity bookkeeping may change for other people while BBS runs.
        // Refresh only that counter; keep the original identity/policy fence.
        for _ in 0..16 {
            let mut commit = self.store.read(&[meta("pending-count")]).await?;
            let remaining = count(&commit)?.checked_sub(1).ok_or(Error::Encoding)?;
            commit.revisions.extend(read.revisions.clone());
            let mut changes = vec![
                delete(pending_key.clone()),
                put(meta("pending-count"), &remaining)?,
            ];
            if person.suspension.is_some() {
                let mut cleared = person.clone();
                cleared.suspension = None;
                changes.push(delete(revocation_key.clone()));
                changes.push(put(account(subject), &cleared)?);
            }
            match self.store.compare_exchange(&commit, changes).await {
                Ok(()) => return Ok(passport),
                Err(Error::Conflict) => {
                    let current = self
                        .store
                        .read(&read.revisions.keys().cloned().collect::<Vec<_>>())
                        .await?;
                    if current.revisions != read.revisions {
                        return Err(Error::Conflict);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(Error::Conflict)
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
            .compare_exchange(&read, vec![put(account(subject), &person)?])
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
            if *until <= now || *until % 86_400 != 0 {
                return Err(Error::InvalidTime);
            }
        }
        let read = self
            .read(vec![
                account(subject),
                Key::new("revocation", subject.as_str()),
            ])
            .await?;
        // Suspension still works when the previous passport policy has expired.
        let mut state: State = get(&read, &meta("state"))?.ok_or(Error::NoPolicy)?;
        let mut person: Account = get(&read, &account(subject))?.ok_or(Error::UnknownSubject)?;
        if person.suspension.as_ref() == Some(&suspension) {
            return state.epoch();
        }
        if matches!(person.suspension, Some(Suspension::Permanent(_))) {
            return Err(Error::Suspended);
        }
        if matches!(suspension, Suspension::Temporary { .. }) && !person.warned {
            return Err(Error::WarningRequired);
        }
        state.local_epoch = state.local_epoch.checked_add(1).ok_or(Error::Exhausted)?;
        state.epoch()?;
        person.suspension = Some(suspension.clone());
        person.warned = false;
        let revocation = Revocation {
            subject: subject.clone(),
            suspension,
        };
        self.store
            .compare_exchange(
                &read,
                vec![
                    put(account(subject), &person)?,
                    put(meta("state"), &state)?,
                    put(Key::new("revocation", subject.as_str()), &revocation)?,
                ],
            )
            .await?;
        state.epoch()
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
    /// Prune expired protocol slots; uniqueness and cpsd tag bindings remain burned.
    pub async fn prune_challenges(&self, now: u64, limit: u32) -> Result<usize> {
        time(now)?;
        if limit == 0 || limit > 1000 {
            return Err(Error::Capacity);
        }
        self.issuance.prune(now).await.map_err(passport_error)?;
        let expired = self.store.expired(now, limit).await?;
        if expired.records.is_empty() {
            return Ok(0);
        }
        let mut read = self.read(vec![meta("pending-count")]).await?;
        read.revisions.extend(expired.revisions.clone());
        let size = expired.records.len();
        let remaining = count(&read)?
            .checked_sub(size as u32)
            .ok_or(Error::Encoding)?;
        let mut changes: Vec<_> = expired.records.into_keys().map(delete).collect();
        changes.push(put(meta("pending-count"), &remaining)?);
        self.store.compare_exchange(&read, changes).await?;
        Ok(size)
    }
    /// Reuse original signed public bytes while their owner version is current.
    /// Private suspension lists remain in storage. The requested deadline must
    /// remain future after the existing UTC-day rounding.
    pub async fn public_status(&mut self, now: u64, valid_until: u64) -> Result<Vec<u8>> {
        time(now)?;
        time(valid_until)?;
        let deadline = valid_until / 86_400 * 86_400;
        if deadline <= now {
            return Err(Error::InvalidTime);
        }
        let read = self.read(vec![]).await?;
        let state: State = get(&read, &meta("state"))?.ok_or(Error::NoPolicy)?;
        match self.beacon.current(now) {
            Ok(bytes) => {
                let ring = self.key_ring()?;
                let current = Status::verify(
                    &bytes,
                    ring,
                    self.store.scope(),
                    state.epoch()?,
                    state.policy.revision,
                    now,
                );
                let lifetime = ring
                    .verify(&bytes, csgn::Kind::SettingsSnapshot, now)
                    .map(|value| value.valid_until() >= deadline)
                    .unwrap_or(false);
                if let Ok(current) = current
                    && current.epoch == state.epoch()?
                    && current.policy_revision == state.policy.revision
                    && current.shared_expiry == state.policy.shared_expiry
                    && current.issuer_public_key == self.binding.issuer
                    && lifetime
                {
                    let latest = self.read(vec![]).await?;
                    if latest.revisions != read.revisions {
                        return Err(Error::Conflict);
                    }
                    return Ok(bytes.as_ref().to_vec());
                }
            }
            Err(cbcn::Error::ClockRegression) => return Err(Error::Signature),
            Err(_) => (),
        }
        self.signed_status(now, valid_until).await
    }

    /// Sign public epoch/status without exposing the private revocation list.
    pub async fn signed_status(&mut self, now: u64, valid_until: u64) -> Result<Vec<u8>> {
        time(now)?;
        let read = self.read(vec![]).await?;
        let state: State = get(&read, &meta("state"))?.ok_or(Error::NoPolicy)?;
        let status = Status {
            version: 2,
            purpose: "global-passport-status".into(),
            scope: self.store.scope().into(),
            epoch: state.epoch()?,
            policy_revision: state.policy.revision,
            shared_expiry: state.policy.shared_expiry,
            issuer_public_key: self.binding.issuer.clone(),
        };
        let payload = serde_json::to_vec(&status).map_err(|_| Error::Encoding)?;
        let signed = self
            .signer
            .sign(
                csgn::Kind::SettingsSnapshot,
                &payload,
                now / 86_400 * 86_400,
                valid_until / 86_400 * 86_400,
            )
            .await
            .map_err(|_| Error::Signature)?;
        // Do not publish a snapshot superseded while its signing state committed.
        let current = self.read(vec![]).await?;
        if current.revisions != read.revisions {
            return Err(Error::Conflict);
        }
        let ring = self.signer.key_ring().map_err(|_| Error::Signature)?;
        let published = self
            .beacon
            .install(ring, signed, now)
            .map_err(|_| Error::Signature)?;
        Ok(published.as_ref().to_vec())
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
            .rotate(key, now / 86_400 * 86_400)
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
            .verify(cose, csgn::Kind::SettingsSnapshot, now)
            .map_err(|_| Error::Signature)?;
        let value: Self =
            serde_json::from_slice(verified.payload()).map_err(|_| Error::Encoding)?;
        value.validate_publication(ring.issuer())?;
        if value.scope != scope
            || value.epoch < minimum_epoch
            || value.policy_revision < minimum_revision
        {
            return Err(Error::Policy);
        }
        Ok(value)
    }
    fn validate_publication(&self, issuer: &str) -> Result<()> {
        if issuer != format!("cglb:{}", self.scope)
            || self.version != 2
            || self.purpose != "global-passport-status"
            || !self.shared_expiry.is_multiple_of(86_400)
        {
            return Err(Error::Policy);
        }
        time(self.shared_expiry)?;
        cpsd::IssuerPublicKey::from_bytes(&self.issuer_public_key).map_err(|_| Error::Encoding)?;
        Ok(())
    }
}
impl cbcn::document::Document for Status {
    const KIND: csgn::Kind = csgn::Kind::SettingsSnapshot;

    fn version(&self, issuer: &str) -> cbcn::Result<cbcn::document::Version> {
        self.validate_publication(issuer)
            .map_err(|_| cbcn::Error::Incoherent)?;
        Ok(cbcn::document::Version {
            revision: self.policy_revision,
            epoch: self.epoch,
        })
    }
}

fn passport_error(error: cpsd::Error) -> Error {
    match error {
        cpsd::Error::IssuerTagMismatch => Error::HolderChanged,
        cpsd::Error::IssuerTagClaimed => Error::Duplicate,
        cpsd::Error::InvalidChallenge | cpsd::Error::ChallengeConflict => Error::Challenge,
        cpsd::Error::StorageCapacity => Error::Capacity,
        cpsd::Error::Storage => Error::Storage,
        _ => Error::Passport,
    }
}
