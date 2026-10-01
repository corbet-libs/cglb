# cglb

**Global facade of cvld: verifies a real, unique person once; global gates, uniqueness, suspension, passport issuance.**

Part of `cvld`, the permanent door of the cmtymeet trust stack. Status: in
development; interfaces may change.

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
