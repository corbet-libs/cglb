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
| Database | [crlt](https://github.com/corbet-foss/crlt) already supplies scoped transactions and indexed plans over official [libsql](https://github.com/tursodatabase/libsql). Use crlt pinned by revision; a direct libsql fallback is unnecessary. |
| Anonymous passport | [cpsd](https://github.com/corbet-foss/cpsd) implements Dock blind BBS+ issuance, issuer tags and shared-expiry proofs. Use its pinned API; no duplicate crypto or separate BBS stack. |
| Signed policy/status | [csgn](https://github.com/corbet-foss/csgn) supplies durable Ed25519 COSE signing, verification and rotation. Use its pinned API instead of coset/dalek directly. |
| Uniqueness | [RustCrypto hmac 0.13](https://crates.io/crates/hmac) and [sha2 0.11](https://crates.io/crates/sha2), MIT/Apache-2.0, supply the required keyed fingerprint. cpns implements holder-salted field pins, a different contract; ring adds a separate native crypto stack. |
| Data and errors | serde/serde_json supply typed serialization; zeroize handles owned secret buffers; thiserror supplies typed errors. All are permissively licensed. |

The selected leaves are LGPL-3.0-only WITH LGPL-3.0-linking-exception. Gate,
policy and identity decisions stay in this FSL facade. Wallet passkey
authentication and throttling belong to the service composition using cpky/cthl;
they are not reimplemented here. cvch is a community voucher, outside the global
catalogue. No GPL/AGPL-only dependency is permitted.
