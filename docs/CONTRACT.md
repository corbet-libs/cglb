# cglb contract

cglb is cvld's separate global issuer. Its authenticated service owns global
person IDs, session IDs, provider selection, authority trust, legal/self-ban
permission, secrets, clocks and transport limits. Community pseudonyms, community
policies and community databases never enter this facade. No login dates, raw
provider evidence, proof payloads or issued passports are stored.

## One owner per operation

`Global<S,K,I>` composes a cglb store, csgn durable signer and cpsd IssuanceStore.
`Session::authenticated` imports a stable opaque person and nonzero session ID
from the service authentication layer; it is not a client-deserializable receipt.
The facade checks eligibility and policy. cpsd alone generates/reserves issuance
nonces, verifies blind issuance, atomically consumes the nonce and enforces both
directions of permanent person/holder-tag continuity. cglb keeps no issuer tags,
implements no continuity check and exports only issuer protocol messages, never
holder APIs. Wallet origin authentication and unsigned-request compile failures
remain cpsd's responsibility; tests exercise real signed requests and wrong origins.

The service appends `SCHEMAS` to its complete migration history for a NEW global
database: cglb rows, csgn state, cpsd challenges, cpsd issuer tags and their unique
owner index. All SQL uses crlt with scope keys and index checks. A version-two
binding refuses old layouts. Existing installations require an explicit upgrade
preserving every burned fingerprint and moving holder bindings into cpsd; never
reset the database or silently discard an old tag. Global BBS and HMAC keys remain
immutable; only the COSE key can rotate through csgn.

## Provider checks and concurrency

`run_gate` requires a fresh `CheckId` for a new check. Keep that ID unchanged for
all retries, including after disconnects, cancellation, restarts or uncertain
commits. The facade derives a stable provider idempotency key bound to scope,
person, gate and provider. A provider leaf MUST use the provider's idempotent API:
repeated delivery must return the same outcome without charging again, and reuse
with a different input must be refused. Providers without this guarantee cannot
implement the paid gate contract. cglb does not claim exactly-once network delivery.

Only the latest check ID/input commitment accompanies each current gate result;
there is no check history. Exact completed retries use the retained result.
After a slow provider returns, the facade rereads current eligibility and policy,
then retries only the atomic storage commit. It never calls the provider again
because of a CAS conflict. Unrelated people cannot invalidate the check.
Cancellation before persistence is retried through the same provider key.

Each cglb record has an independent increasing revision. CAS validates only the
observed keys, including missing keys; every changed key must have been observed.
Deletion retains the key revision to prevent ABA. Read-only operations take no
write transaction. Composite indexes cover lookups, pages and challenge expiry.
The global pending count coordinates only short challenge-capacity transactions;
it is not a revision counter for identity operations.

## Gates, time and no return

Provider leaves must authenticate evidence to the person/session and normalize
uniqueness inputs identically across providers, such as canonical E.164 for a
phone gate. Canonicalization precedes the shared HMAC; the transient canonical
bytes are zeroized. Tests show equivalent provider spellings reserve one identity.
Real phone/other providers remain separate integrations; no normalization is
inferred from raw client input by the facade.

**NO RETURN:** uniqueness fingerprints are burned forever. Gate expiry,
registration expiry, holder-secret loss, passkey loss and suspension never release
one. A person cannot switch an established uniqueness value. A holder who loses
the secret cannot obtain a replacement identity or community pseudonym. There is
no release, recovery or tombstone-reset API. cpsd also prevents the same holder
secret from binding to a second person and bypassing a suspension.

Retained gate expiries round DOWN to UTC days; rounding never extends evidence.
Shared passport cohort expiry must be a day boundary. Eligibility requires every
configured gate to reach that cohort. Temporary suspension ends must be day
boundaries. csgn key activation/rotation, signed status issuance and status expiry
use days. The signer must have been created with day-aligned activation.

Issuance challenges retain seconds: their short deadline bounds proof replay and
resource use. This is a transient protocol slot, not an activity timestamp. One
person may hold at most one pending slot, across sessions, within the global
capacity. The slot is reserved before cpsd is called, so cancellation cannot
allocate unlimited orphan nonces. Issuance removes it; expiry/pruning frees it.
A lost or uncertain response may require waiting for that short deadline before
a new challenge. Pruning never touches permanent uniqueness or holder bindings.

## Policy, suspension and publications

A separate authenticated global authority signs the typed `Policy` JSON as a
csgn SettingsSnapshot; the service supplies its pinned ring. A community cplc
signer never signs global policy. Revision increases and authority epoch advances
by exactly one, starting at one. Effective passport epoch is authority epoch plus
a separate local suspension counter. Policy acceptance never depends on the
authority knowing that counter. Invalid large jumps cannot exhaust revocation.

Temporary suspension requires a warning; permanent legal/self-ban suspension has
no reversal API. Suspensions atomically update private state and the effective
epoch. cpsd cannot privately prove individual nonrevocation, so the new epoch
invalidates the old global cohort once verifiers adopt it. Eligible people renew;
suspended people cannot. cmty requires a fresh presentation at credential renewal,
against the current authenticated global epoch. Offline credentials retain their
bounded lifetime; this is not an offline revocation accumulator.

Public `Status` is a version-two SettingsSnapshot with exact purpose
`global-passport-status`, effective epoch, authority revision, shared cohort expiry
and BBS public key. It contains no person or revocation list. Verification requires
the authenticated `cglb:<scope>` ring and consumer-maintained epoch/revision floors.
The private revocation list stays administrative. Status publication rechecks its
observed state after signing. One csgn writer owns COSE signing/key rotation.

## Development boundary and validation

There is one synthetic global gate: `development::DevelopmentGate`. It needs the
`development-gate` Cargo feature AND a development build. build.rs omits it from
release profiles even when debug assertions and every feature are enabled.
`Mode::Production` additionally refuses synthetic issuer catalogues, policies and
providers at runtime. Feature unification cannot enable it in production. cgts
contains no development gate implementation.

GitHub Actions runs format, Clippy, real memory/libSQL/crypto tests, release tests,
a hardened-release negative compilation probe, dependency-license review and the
shared duplicate/floating-revision check. Every Corbet dependency must resolve
once at an explicit full revision. Builds never run on the workstation.
