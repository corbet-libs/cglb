# Coverage contract

CI targets 100% of reachable production lines and branches. Stable Rust runs
the existing native and wasm checks. Nightly Rust is used only for LLVM branch
instrumentation, which currently requires it. Both jobs use the same resolved
Cargo.lock snapshot; all build and test commands after resolution use --locked.

The coverage job executes real tests with cargo-llvm-cov and retains the raw JSON
even when the gate fails. The checker compares integer covered/total counts for
both metrics; rounded percentages cannot pass. An empty report cannot pass.
The report excludes integration-test harness files under tests/, not production
code. No production source exclusions are currently approved.

A failing gate is missing evidence, not permission to lower the threshold or
change domain behavior. Add meaningful failure and round-trip tests. Document
any genuinely unreachable defensive branch precisely before excluding it. Native
coverage does not establish browser execution; keep the actual wasm vectors.

First-party dependencies follow main. Their resolved full revisions remain in
Cargo.lock, with exactly one source per first-party crate. Dependabot maintains
committed snapshots; CI refreshes once per run and retains the tested snapshot.
Auto-merge requires protected main and successful substantive checks on the
exact current Dependabot head. It never executes PR code with write permissions.

## Emitted source metric

The acceptance metric is now 100% of upstream LLVM LCOV's emitted production
source line counters (DA) and branch counters (BRDA), from the same execution as
the retained raw JSON. This is source coverage, not every generic instantiation.
LLVM JSON and LCOV summary totals can count generic copies differently from
the merged source records. The original JSON checker remains diagnostic code;
its stricter instantiation totals are not described as passed.

The source gate requires a nonempty report, an exact file inventory matching the
companion JSON, matching raw summary metadata, complete emitted branch counts
and no duplicate, unknown or zero counters. Raw reports retain every production counter. The three precise branch proposals below are applied only after validating the complete report inventories.
Actual browser/device execution remains separate from native coverage.

The coverage job sets `CARGO_PROFILE_TEST_OPT_LEVEL=0` for this workspace. The
ordinary native/performance and release/browser profiles are unchanged; the
existing upstream pairing dependency optimization override remains. An earlier
optimized profile reported zero for an accessor exercised by real assertions.
The [rustc coverage guide](https://doc.rust-lang.org/rustc/instrument-coverage.html)
explains that optimizing functions away can invalidate coverage mapping. This
measurement configuration retains owned bodies instead of excluding them. It
is a diagnostic correction, not evidence that the remaining gaps are covered.

## Proposed invariant exceptions

These are review proposals, not independent security acceptance. Run
[36938685007](https://github.com/corbet-libs/cglb/actions/runs/36938685007),
head `1ed3789b427ff9877e05a45f610ca411be05fb74`, executed all 1,057
production lines and 229 of 232 emitted branch arms. Ordinary native,
all-feature, strict Clippy and release suites passed. The real cached-publication
concurrent-write test now executes the previously missing revision-conflict line;
no race, storage error, cryptographic error or resource failure is excluded.

Only these three native arms are proposed:

- `src/facade.rs:193`, block 0 arm 0: `gate.gate == "development"` cannot be true
  here in production mode. `Global::open` rejects any production issuer whose
  catalogue contains that gate. `install_policy` first rejects gates absent from
  the same catalogue at line 189. The issuer is a private, owned field with no
  replacement API. The exact CPSD source bound in the manifest gives its public
  key private fields and read-only catalogue access. The other reserved-provider
  arm is reachable and executed; it remains required.
- `src/facade.rs:680`, block 0 arm 1: an issuer mismatch cannot arise from this
  private cache. Its sole installation path is `signed_status`, which constructs
  `Status.issuer_public_key` from the immutable `self.binding.issuer`, signs that
  payload, and installs those exact bytes. The cache starts empty on every open;
  neither the cache nor the binding has a public mutable accessor or importer.
  The bound Beacon implementation retains the exact installed signed bytes in an
  immutable `Arc<[u8]>`; the bound Signatures implementation authenticates those
  payload bytes. Imported storage binding changes are refused by `read` before
  the cache path. Tests exercise policy-version rollback, changed shared expiry,
  valid cache reuse, actual signer invalidation and concurrent storage changes.
- `src/facade.rs:770`, block 0 arm 0: a scope mismatch is impossible after the two
  preceding checks. The first requires `ring.issuer() == format!("cglb:{scope}")`;
  `validate_publication` then requires that same issuer to equal the same literal
  prefix plus `value.scope`. Prefix concatenation is injective. The bound key-ring
  API returns an immutable issuer string and this code cannot change it. Epoch
  and revision refusal arms on the same compound condition remain required.

Each proposal binds the exact source line/arm, the SHA-256 of the complete owned
source file and the unique full Git identity of relevant upstream packages in
Cargo.lock. An upstream change requires renewed proof; unrelated dependency
refreshes do not silently invalidate or broaden the exception. The checker still
reconciles raw JSON, LCOV and annotated source before subtracting only these
three arms. All 1,057 lines remain required. Seventeen checker regressions cover
missing/duplicate counters, changed source, package identity drift and invalid
exceptions. No production code was changed to satisfy these proofs.

Upstream evidence: [CPSD immutable issuer API](https://github.com/corbet-foss/cpsd/blob/a23616e906ffa924aa5bda667e7ea1edf3a692d4/src/issuer.rs),
[Beacon exact-byte cache](https://github.com/corbet-foss/cbcn/blob/53ed942cdc1439fcedbc9914cf6cc44f83020d29/src/document.rs),
[Signatures](https://github.com/corbet-foss/csgn/tree/fac7f49eeb4e4bb9b72de640b46e55d8fe99119c).
