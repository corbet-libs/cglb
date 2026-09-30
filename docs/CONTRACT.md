# cglb contract

cglb is the native global facade of cvld, behind `wallet.cmeet.me`. It owns a
separate service and database. Neither it nor a community service receives the
other's database capability. Every table still carries crlt's `community_id`,
used here as the fixed global service namespace.

The facade composes crlt storage, cpsd blind passport issuance and csgn durable
COSE signing. Those LGPL leaves execute database and cryptographic operations.
RustCrypto HMAC-SHA256 supplies keyed, domain-separated uniqueness fingerprints;
the service supplies a stable secret key. No private key enters the database.
No login dates, request logs, raw gate evidence, community pseudonyms or passport
copies are stored. Only current identity, gate and suspension state is retained.

## Issuance and gates

Trusted gate adapters return a proof expiry and optional canonical uniqueness
input. Only the feature-gated development test gate ships here. A production
instance rejects development adapters and development policy. Real global gates
remain future leaf integrations. Adapter code is trusted; member input is not
an authorization to record a gate.

Policy arrives as a csgn settings snapshot from an explicitly trusted authority.
It binds the global scope, monotonically increasing revision and epoch, enabled
gates/providers, uniqueness requirements and one common expiry. At least one
uniqueness gate is mandatory. The public BBS catalogue must contain every gate.

Gate recording claims a fingerprint atomically. Another subject cannot claim it,
and a subject cannot switch an already claimed uniqueness value. Reservations
survive expiry and permanent suspension. Issuance requires every policy gate to
reach the common expiry; shorter evidence is never rounded upward. Passport and
included gates are signed with that same expiry, enabling cpsd's fast proof mode.

A random issuance challenge is bound to the authenticated global subject, issuer
key and current epoch. Successful issuance atomically consumes it and binds the
verified cpsd issuer tag. Renewal requires that same tag; a tag cannot belong to
two subjects. Invalid proofs and failed policy checks release no passport.
Pending challenges have bounded lifetimes and can be pruned; there is no consumed
challenge history. Lost responses require a new challenge with the same secret.

## Suspension and publication

Temporary suspension requires a prior warning and a finite future deadline.
Permanent suspension accepts only legal-order or self-ban categories. Every
suspension atomically updates the private revocation list and advances the global
epoch. Temporary expiry allows renewal; permanent suspension has no reversal API.

cpsd currently cannot privately prove individual nonrevocation. Advancing the
epoch therefore invalidates the whole older passport cohort once verifiers adopt
the new authenticated epoch. Active holders renew with the same secret. Public
signed status exposes the epoch, policy revision, common expiry and BBS public
key, never global subject IDs or issuer tags. The individual revocation list is
private administrative state. This is not an accumulator or immediate revocation
at an offline verifier. Snapshot freshness and distribution belong to the service.

## Storage and trust boundary

A small revisioned storage trait supplies consistent reads and atomic
compare-and-exchange batches, with real memory and crlt/libSQL adapters. The
facade owns decisions; storage adapters own only persistence. Composite primary
keys index point reads and bounded bucket scans; a deadline index supports
challenge pruning. Conflicts fail closed and require a fresh operation. A remote
timeout may have committed: reopen/read state, never assume rollback or blindly
retry. Deployment must prevent database rollback.

The service owns authentication, root/self-ban authorization, verified legal
orders, warning delivery, clocks, throttling, secret provisioning and physical
database routing. An authenticated subject ID must be opaque and stable. Library
methods are trusted service APIs, not directly exposed member endpoints. One
csgn writer serializes signing/key-ring publication; its persistence fences stale
writers. All private keys remain in the platform secret store or process memory.

This library targets current stable native Rust. Device-side proofs remain in
cpsd. FSL-1.1-ALv2; no GPL/AGPL-only dependency; never publish to a registry.
Tests and format/Clippy checks run only in GitHub Actions. Live Turso tests run
only when both TURSO_URL and TURSO_TOKEN are nonempty, with a disposable database
and no credentials in the repository or public CI.
