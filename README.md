# cglb

**Global facade of cvld: verifies a real, unique person once; global gates, uniqueness, suspension, passport issuance.**

Part of `cvld`, the permanent door of the cmtymeet trust stack. Status: in
development; interfaces may change.

## Scope

### Purpose

`cglb` checks a real, unique person once and issues the blind passport from which every community derives an unlinkable pseudonym.

### Owns

- The global gates: phone, government document, human, Privacy Pass, mailbox, third-party provider, and platform fee. A proof about the person is global; a proof about the relationship to one community belongs to the community side.
- Uniqueness as a module: one keyed fingerprint per uniqueness gate, one passport per person, with used fingerprints never released.
- Suspension as a module: temporary platform-wide suspension only after a warning, and permanent suspension, enforced through short validity periods and policy epochs.
- Passport issuance through `cpsd`, where the issuer never sees the holder secret.
- Its own service with its own database and its own `csgn` signing keys, separate from every community.
- Publication of its public material through `cbcn` by reference.

Storage goes only through `crlt` with every query index-backed. Clock, randomness, secrets, and storage handles are supplied by the caller. The operator keeps no login dates, request logs, raw gate data, or identifiers in errors.

### Never

- Sees or stores community pseudonyms, memberships, community databases, or community policy; the separation between the global side and the community side is a firewall.
- Shares signing keys with communities.
- Keeps raw provider evidence, proofs, issued passports, or login dates.
- Releases a fingerprint or issues a replacement identity after expiry, loss of all passkeys, or suspension; there is no recovery path.
- Hard-codes provider order, fallback, or minimum standards; ordering and fallback belong to `cfbk` with `crbk` settings.
- Runs a paid provider without approval, or includes the development gate in a release build.
- Lets one community identity carry over into another community.
- Uses trust scores or confidence levels; a gate is either on or off.

### States

| Entity | Lifecycle |
|---|---|
| Person | Unknown, gate checks in progress, eligible, passport issued, renewed; eligible can move to temporarily suspended and back only after a warning; permanently suspended is terminal |
| Uniqueness reservation | Absent, then burned; burned is terminal and never released |
| Issuance slot | None, pending with a short deadline, then consumed or expired; at most one pending slot per person |

### Test obligations

- Same holder in the same community yields the same pseudonym; the same holder in different communities stays unlinkable; the issuer never sees the holder secret.
- Equivalent spellings of one phone number reserve one identity; a used fingerprint cannot serve a second person; one holder secret cannot attach to a second person to bypass a suspension.
- Expiry, loss of all passkeys, and suspension never release a fingerprint, and no reset or recovery interface exists.
- Temporary suspension requires a prior warning; an epoch increase makes old passports fail at the next verification; a suspended person cannot renew; permanent suspension has no reversal.
- Retries with the same check identifier never charge twice; a provider without an idempotent billing interface cannot back a paid gate.
- A gate or provider that is switched off never runs; a gate without an approved provider stays unavailable and never passes.
- No community identifier enters a request, a stored row, or the public status.
- The development gate is absent from release builds and refused in production mode.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under the [Functional Source License, Version 1.1, ALv2 Future License](LICENSE.md).

## Contract and dependency survey

See [docs/CONTRACT.md](docs/CONTRACT.md). The global service owns its own database
and signing keys. Community databases and pseudonyms never enter this facade.

Reviewed GitHub main, upstream documentation and crates.io on 2026-09-30:

| Need | Candidates and decision |
|---|---|
| Database | [crlt](https://github.com/corbet-foss/crlt) already supplies scoped transactions and indexed plans over official [libsql](https://github.com/tursodatabase/libsql). Follow crlt main with one locked source revision; a direct libsql fallback is unnecessary. |
| Anonymous passport | [cpsd](https://github.com/corbet-foss/cpsd) implements Dock blind BBS+ issuance, issuer tags and shared-expiry proofs. Use its main API with a reproducible lock; no duplicate crypto or separate BBS stack. |
| Signed policy/status | [csgn](https://github.com/corbet-foss/csgn) supplies durable Ed25519 COSE signing, verification and rotation. Use its main API instead of coset/dalek directly. |
| Uniqueness | [RustCrypto hmac 0.13](https://crates.io/crates/hmac) and [sha2 0.11](https://crates.io/crates/sha2), MIT/Apache-2.0, supply the required keyed fingerprint. cpns implements holder-salted field pins, a different contract; ring adds a separate native crypto stack. |
| Data and errors | serde/serde_json supply typed serialization; zeroize handles owned secret buffers; thiserror supplies typed errors. All are permissively licensed. |

The selected leaves are LGPL-3.0-only WITH LGPL-3.0-linking-exception. Gate,
policy and identity decisions stay in this FSL facade. Wallet passkey
authentication and throttling belong to the service composition using ckyh/cthl;
they are not reimplemented here. cvch is a community voucher, outside the global
catalogue. No GPL/AGPL-only dependency is permitted.

## Service API

- `Global::open` binds the fixed global scope, BBS issuer, HMAC key and durable
  `csgn::PersistentSigner`. Existing state rejects changed BBS/HMAC keys.
- `install_policy` verifies a COSE settings snapshot containing the local typed
  `Policy` format against a service-configured authority ring. Integrating that
  payload with cplc's policy publisher remains a service adapter responsibility.
- `run_gate` executes a trusted `GlobalGate` implementation and records only its
  result and HMAC reservation. `development::DevelopmentGate` requires the
  non-default `development-gate` feature, a development build and `Mode::Development`.
- `challenge` and `issue` drive cpsd blind issuance. The holder uses cpsd
  `request_issue`, `PendingIssuance::finish`, and `PresentationRequest::for_epoch`.
- `warn`, `suspend`, and paginated private `revocations` manage current suspension
  state. `signed_status` publishes a COSE epoch view; `Status::verify` requires
  the consumer's trusted ring and epoch/revision minima.
- `rotate_signing_key` delegates durable COSE rotation to csgn. `key_ring` and
  `issuer_public_key` expose only public material. `prune_challenges` releases
  expired pending capacity in bounded batches.

Use an opaque service-assigned `Subject`; authentication and authorization happen
before these calls. `Limits` explicitly bounds nonce lifetime and pending count.
The caller supplies authoritative Unix-second times and a cryptographic RNG.
Never use the deterministic seeds from tests in a service.

Install the complete service migration history before opening adapters:

```rust,no_run
use crlt::{Config, Db, Migration};
use cglb::storage;
# async fn example(url: String, token: String) -> Result<(), Box<dyn std::error::Error>> {
let db = Db::open(Config::new(url, token)).await?;
let migrations: Vec<_> = cglb::SCHEMAS.iter().enumerate()
    .map(|(i, (name, sql))| Migration::new(i as u32 + 1, name, sql)).collect();
db.migrate(&migrations).await?;
let identities = storage::LibsqlStore::new(&db, "global")?;
let signing = csgn::LibsqlStore::new(db.community("global")?);
identities.check_query_plans().await?;
signing.check_query_plans().await?;
# Ok(())
# }
```

Use a physically separate global database. `community_id` is the immutable global
namespace, not a community identifier received from a wallet. Keys come from the
service secret store. One csgn writer serializes signing and ring publication.
Do not enable SQL/HTTP debug logging of inputs.

## Validation and remaining boundaries

GitHub Actions runs stable Rust formatting, Clippy with warnings denied, tests for
both the production default and opt-in development gate, and resolved dependency
license/pin checks. Real memory and local libSQL tests cover blind issuance and
proofs, uniqueness/tag continuity, shared expiry, replay, malformed requests,
suspension and epochs, COSE rotation, restart, conflicts, rollback, namespace
isolation, query plans and pending-capacity cleanup. An independent HMAC vector
checks framing and gate/scope separation. Cargo is never run on the workstation.

`optional_real_turso` prints a skip unless both `TURSO_URL` and `TURSO_TOKEN` are
nonempty. It migrates a disposable database and cleans up synthetic rows. Never
supply credentials in public CI or commit them. Local tests do not establish a
live Turso result.

Real global gate providers, service HTTP/MCP routing, wallet passkeys, warning
transport, verified legal-order intake and freshness distribution are outside this
library. cpsd has no private individual accumulator revocation yet: suspension
bumps the entire epoch and old passports fail once verifiers refresh. Public
status deliberately contains no individual revocation entries. BBS issuer and
HMAC-key rotation require a future explicit migration protocol; reopening with
changed keys fails closed. No cryptographic security certification is claimed.

## Security contract update

The implemented API is `Global<S,K,I>` with an explicit cpsd issuance store and an
authenticated `Session`. `run_gate` takes a retry-stable `CheckId`. Per-row revisions
isolate unrelated people, and provider APIs must guarantee idempotent billing.
There is one pending challenge per person. Holder continuity belongs solely to
cpsd. Uniqueness reservations and holder bindings are permanent: **NO RETURN**.

Global policy authority epochs are independent of suspension bumps. Stored gate
expiries and status signatures use UTC days; short challenge deadlines retain
seconds for replay/capacity bounds. Status is a purpose-bound SettingsSnapshot.
The development gate is absent in release builds, including hardened builds.
See [the current contract](docs/CONTRACT.md) for migration and provider obligations.

## Continuous verification

Dependency updates follow main and are tested against one CI-resolved lockfile.
Line and branch coverage target 100%; failures remain blocking. See
[the coverage contract](docs/COVERAGE.md) for measurement and exclusions.

Public status publication reuses `cbcn::document::Cache<Status>` and the existing
`csgn` COSE implementation. This shared typed cache was chosen over a second local
cache or generic HTTP cache because it preserves the original signed bytes and
checks issuer, kind, lifetime and policy floors. `Global::public_status` also
fences against the durable current version; private revocations are never cached.

The volatile and SQL stores select bounded expired challenges by deadline and
then key, so a lexically early newer row cannot displace an older expired row.
Real parity tests use opposing key/deadline order and a non-challenge row; imported
SQLite type corruption and exhausted revisions must refuse without partial writes.
