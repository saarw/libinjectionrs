Here’s a concrete, end-to-end plan to port libinjection from C to Rust, verify it against upstream tests, and compare performance with the C implementation. It’s organized as phased work with explicit deliverables, acceptance criteria, and ready-to-run scaffolding for testing and benchmarking.

⸻

Phase 0 — Project setup & baseline

Goals
	•	Create a clean Rust workspace and vendor the C reference so we can do differential testing and benchmarking from day one.
	•	Lock down reproducibility (toolchains, flags, fixtures).

Tasks
	1.	Repository layout

libinjection-rs/
├─ libinjection-c/           # git submodule or tarball of upstream C
├─ libinjection-rs/          # pure-Rust crate (the port)
├─ ffi-harness/              # small C build to expose a stable C API for tests/bench
├─ comparison-bin/           # CLI that can call both C and Rust for differential runs
├─ benches/                  # Criterion benchmarks
├─ fuzz/                     # cargo-fuzz targets
├─ testdata/                 # copied/linked upstream test corpora + extras
└─ ci/                       # CI workflows, sanitizer scripts


	2.	Toolchains
	•	Pin Rust with rust-toolchain.toml (stable channel).
	•	Build C with -O3 -fno-omit-frame-pointer -g for fair comparisons (you’ll test -O2/-O3 later).
	3.	Licensing & attribution
	•	Verify upstream license and add it to THIRD_PARTY.md. Keep original copyright headers in ported code where appropriate.
	4.	CI
	•	GitHub Actions (or similar) matrix: Ubuntu/macOS/Windows; 64-bit; Release/Debug.
	•	Jobs: build, unit tests, upstream test corpus, fuzz smoke, benchmarks (report artifacts), Clippy + rustfmt, sanitizers (UBSan/ASan for C; Miri for Rust nightly as a check).

Deliverables
	•	Workspace skeleton building successfully on all platforms.
	•	CI green on “hello world” tests.

Acceptance criteria
	•	cargo test passes (trivial).
	•	C reference builds in ffi-harness and a trivial call succeeds.

⸻

Phase 1 — Define the Rust API surface

Goals
	•	Commit to a stable Rust API that mirrors libinjection behavior but feels idiomatic.

Tasks
	1.	Inventory upstream entry points & structs
	•	Functions like SQLi/XSS detection routines, tokenizers, result enums/flags, and any configuration knobs.
	2.	Design Rust types
	•	Replace C integers/flags with Rust enums + bitflags where relevant.
	•	Newtypes around byte slices for inputs (&[u8]) and iterator/tokenizer abstractions.
	•	Avoid heap allocations in hot paths; prefer stack and SmallVec where necessary.
	3.	Error handling
	•	Use Result<_, Error> only where fallible; otherwise booleans or enums for classification.
	4.	no_std toggle
	•	Consider a no_std feature (if upstream allows) with alloc optionality.

Deliverables
	•	libinjection-rs crate skeleton with public API and documentation comments.
	•	docs/ARCHITECTURE.md describing mappings from C constructs to Rust types.

Acceptance criteria
	•	API approved and frozen before porting internals.
	•	Example snippets compile in doc-tests.

⸻

Phase 2 — Strategy for the port (translation vs. reimplementation)

Goals
	•	Choose a method that preserves behavior and enables optimization.

Options (you can also combine)
	1.	Transliteration first, then refactor
	•	Port line-by-line with minimal changes; keep close to control flow and state machines.
	•	Pros: Easier to verify equivalence early.
	•	Cons: Initial code is less idiomatic.
	2.	Spec-driven reimplementation
	•	Recreate the state machines/heuristics from a spec you derive from tests + code comments.
	•	Pros: Cleaner Rust; room for algorithmic improvements.
	•	Cons: Higher risk of subtle behavioral drift.

Recommendation
	•	Start with transliteration to reach full test parity fast; then refactor behind tests and a differential oracle.

Deliverables
	•	A written mapping guide: C → Rust idioms, pointer arithmetic plan, buffer handling, character classes, and tables.

Acceptance criteria
	•	Agreement on which internal functions remain internal/private vs. public.

⸻

Phase 3 — Implement core modules incrementally

Goals
	•	Port tokenizer, detectors, and helpers in small, testable pieces.

Tasks (repeatable pattern)
	1.	Pick a leaf module (e.g., character classification tables).
	2.	Port to Rust (const tables, match, bit-sets).
	3.	Write unit tests based on upstream fixtures for that module.
	4.	Add differential tests that run both Rust and C on the same inputs.
	5.	Only then move to the next module (e.g., SQL tokenizer → SQLi detector → XSS detector).

Implementation notes
	•	Character handling: operate on bytes; only convert to char when necessary. Normalize case with ASCII-only fast paths.
	•	State machines: use explicit enums for states; prefer while loops over recursion; consider #[inline] on small hot functions.
	•	SIMD: add an optional simd feature flag using std::simd (portable). Provide a scalar fallback.
	•	Allocation: avoid String in hot paths; operate on &[u8] and temporary fixed-size buffers where possible.
	•	Unsafe: keep unsafe blocks minimal and well-commented; wrap them in safe APIs with tests.

Deliverables
	•	Working Rust implementations for each module with unit tests.

Acceptance criteria
	•	Module-level test parity (100% of relevant upstream vectors pass for that module).

⸻

Phase 4 — Verification with upstream tests (functional parity)

Goals
	•	Ensure behavior matches C exactly (byte-for-byte where applicable).

Test sources
	•	Copy upstream test files/corpora into testdata/.
	•	If upstream has generators, check them in or re-implement in Rust to avoid build-time codegen.

Differential test harness

Add an integration test that feeds the same cases to both implementations.

Example (tests/diff.rs):

use std::fs;
use std::path::Path;
use comparison_bin::oracle; // calls into C via FFI
use libinjection_rs::{analyze_input, Outcome}; // your Rust API

#[test]
fn corpus_equivalence() {
    let dir = Path::new("testdata/sql");
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("txt") { continue; }
        let input = fs::read(&path).unwrap();
        let rust_out = analyze_input(&input);
        let c_out = oracle::analyze_input(&input);
        assert_eq!(rust_out, c_out, "mismatch on {}", path.display());
    }
}

Oracle (C) build
	•	Compile upstream C into a static lib and expose a thin C API (stable argument/return types). Link it into comparison-bin and the test harness via cc crate in build.rs.

Property-based testing
	•	Use proptest to generate random byte sequences, plus structured tokens (quotes, comments, operators). Assert equality of Rust vs. C for results and selected internal invariants.

Edge cases
	•	Empty input, all-ASCII/all-non-ASCII, long runs of delimiters, deeply nested comment patterns, unterminated quotes, mixed encodings, oversized inputs.

Fuzzing
	•	Add cargo-fuzz target comparing Rust output to the C oracle. Crash or divergence = bug.
	•	Seed corpus = upstream tests.
	•	Sanitizers: run the C side under ASan/UBSan builds inside fuzz job to catch UB.

Coverage
	•	Use cargo tarpaulin or grcov to track Rust coverage; aim for >90% on decision logic.

Deliverables
	•	Passing differential tests over full upstream corpus.
	•	Reproducible fuzzing setup.

Acceptance criteria
	•	100% upstream corpus parity.
	•	Zero known divergences unless explicitly documented (and justified with upstream ambiguity).

⸻

Phase 5 — Performance benchmarking & profiling

Goals
	•	Compare throughput and latency vs. C, find hotspots, and optimize safely.

Methodology
	1.	Microbenchmarks with criterion:
	•	Tokenize and classify typical inputs (benign SQL, common injection patterns, long literals).
	•	Parameterize by input size: 64B, 256B, 1KB, 4KB, 32KB.
	•	Report: ns/op, bytes/s, and instruction counts (if available).
	2.	Macro/realistic workloads
	•	Replay captured (sanitized) traffic: a mix of URLs, POST bodies, headers.
	•	Include worst cases (pathological nesting, long comments) to detect DoS-y behavior.
	3.	Baselines
	•	Build C with -O2 and -O3. Build Rust with --release (LTO on/off) and compare.
	•	Run each test with CPU frequency governor pinned, warm caches, and isolated cores if possible.
	4.	Profiling
	•	Linux: perf stat for cycles, instructions, branches, branch-miss, L1/L2 misses; perf record + inferno for flamegraphs.
	•	macOS: Instruments + dtrace equivalents.
	•	Windows: Windows Performance Analyzer or xperf.
	5.	SIMD experiments
	•	Benchmark scalar vs. std::simd paths for common scanning routines (ASCII classification, quote finding).
	•	Verify identical results and add runtime CPU-feature gating if you include vendor intrinsics.

Example Criterion bench (benches/sqli.rs):

use criterion::{criterion_group, criterion_main, Criterion, Throughput, black_box};
use libinjection_rs::analyze_input;
use comparison_bin::oracle;

fn bench_rust_vs_c(c: &mut Criterion) {
    let samples = include_bytes!("../testdata/mixed_corpus.bin");
    let mut g = c.benchmark_group("sqli_mixed");
    g.throughput(Throughput::Bytes(samples.len() as u64));

    g.bench_function("rust", |b| b.iter(|| {
        let _ = analyze_input(black_box(samples));
    }));

    g.bench_function("c_ref", |b| b.iter(|| {
        let _ = oracle::analyze_input(black_box(samples));
    }));

    g.finish();
}

criterion_group!(benches, bench_rust_vs_c);
criterion_main!(benches);

Deliverables
	•	Benchmark suite with saved baselines (criterion stores them) and flamegraphs for hot paths.
	•	A Markdown report with tables/plots and interpretation.

Acceptance criteria
	•	Rust meets or exceeds C in at least the common-case paths, or documented tradeoffs with follow-up optimization plan.

⸻

Phase 6 — Optimization passes (guided by data)

Candidate improvements
	•	Branch reduction in hot loops (restructure state transitions; use lookup tables).
	•	Slice iterators over indices; minimize bounds checks with safe iter patterns (e.g., manual chunking) or get_unchecked inside audited unsafe blocks.
	•	Inlining of tiny helpers; add #[cold] to rare error paths.
	•	Allocation-free token stacks (e.g., fixed arrays or SmallVec<[T; N]>).
	•	SIMD scanning for quote/delimiter detection and ASCII class membership.
	•	String normalization using ASCII-only fast paths with a slow non-ASCII fallback.
	•	Feature flags for simd, alloc, serde (if you expose structured results).

Deliverables
	•	PRs that each change one hotspot with benchmarks showing improvement and unchanged behavior (differential tests green).

Acceptance criteria
	•	No performance regressions elsewhere (check Criterion’s change detection).
	•	No new divergences in results.

⸻

Phase 7 — Robustness, safety & maintenance

Goals
	•	Harden the crate for production use and long-term maintainability.

Tasks
	•	Document invariants for any unsafe blocks and add targeted tests that would fail if invariants break.
	•	Miri runs (nightly) for UB detection on unit tests.
	•	Sanitizer CI (ASan/UBSan) for the C oracle paths.
	•	API polish: clear docs, examples, and a README with usage, feature flags, and performance notes.
	•	Versioning: start at 0.1.0, semantic versioning with a changelog.
	•	Release artifacts: cargo publish dry runs; cargo deny for license and advisories; cargo audit in CI.

Deliverables
	•	Audited codebase, documented unsafe, published crate (optional).

Acceptance criteria
	•	Security review checklist completed; CI includes audits and denies.

⸻

How to wire the C oracle (FFI harness) quickly
	1.	Expose a minimal C API (in ffi-harness/ffi.c):

// Provide a single function that returns a small POD struct or bitflags.
#include "libinjection.h"

int ffi_analyze(const unsigned char* data, size_t len) {
    // Call whichever upstream entrypoint; return int/flags for comparison.
    return libinjection_sqli_check(data, len); // example name; match upstream
}


	2.	Build via cc crate (in comparison-bin/build.rs):

fn main() {
    cc::Build::new()
        .file("ffi-harness/ffi.c")
        .include("libinjection-c/src")
        .define("NDEBUG", None)
        .flag_if_supported("-O3")
        .compile("ffi_oracle");
    println!("cargo:rerun-if-changed=ffi-harness/ffi.c");
}


	3.	Bind in Rust (in comparison-bin/src/oracle.rs):

#[link(name = "ffi_oracle", kind = "static")]
extern "C" {
    fn ffi_analyze(ptr: *const u8, len: usize) -> i32;
}

pub fn analyze_input(bytes: &[u8]) -> i32 {
    unsafe { ffi_analyze(bytes.as_ptr(), bytes.len()) }
}


	4.	Normalize outputs
	•	Create a Rust enum mirroring C’s flags, and a From<i32> conversion to compare apples to apples.

⸻

Test corpus ingestion & expansion
	•	Upstream tests: convert to a canonical CSV/JSONL (input,expected) for easy parsing.
	•	Augmented corpus:
	•	Randomly generated benign SQL statements (via grammar or simple templates).
	•	Known attack patterns (OWASP cheatsheets) to ensure detector recall.
	•	Pathological strings (very long quoted strings, NUL bytes, mixed encodings).
	•	Golden files: store expected outputs for both C and Rust to detect accidental changes. Regenerate only from the C oracle unless upstream behaviour changes.

⸻

Reproducible performance report
	•	Script scripts/run_benches.sh:
	•	Pins CPU governor, clears page cache (if permissible), runs each bench 10×, saves criterion reports.
	•	Script scripts/compare_baselines.rs:
	•	Parses Criterion JSON to produce a summary table: mean, std dev, percent change, and a verdict (faster/similar/slower).
	•	Artifacts:
	•	Commit benches/reports/<date>/ (or attach to CI artifacts).
	•	Include flamegraphs (perf script | inferno-flamegraph > flame.svg).

⸻

Risk management & gotchas
	•	Behavioral drift: tiny changes in tokenization can ripple; rely on differential tests as a guardrail.
	•	Locale/encoding: enforce ASCII semantics where expected; document non-ASCII behavior explicitly.
	•	Undefined behavior in C: if the oracle exhibits UB for certain inputs, define Rust behavior and document the divergence.
	•	SIMD portability: always have a scalar fallback and a test to ensure both paths produce identical results.
	•	Time-dependent tests: avoid; tests must be deterministic.

⸻

Deliverable checklist (copy/paste into your issue tracker)
	•	Repo scaffold + CI
	•	API design & ARCHITECTURE.md
	•	Character classes ported + tests
	•	Tokenizer ported + tests + diff tests
	•	SQLi detector ported + tests + diff tests
	•	XSS detector ported + tests + diff tests (if in scope)
	•	Property tests (Rust vs C)
	•	Fuzz target + initial corpus
	•	Criterion microbenches + mixed workload bench
	•	Profiling report & hotspot list
	•	SIMD feature flag + identicalness tests
	•	Optimization PRs (documented)
	•	Safety audit of unsafe blocks
	•	Coverage ≥90% decision logic
	•	Performance report with baselines & flamegraphs
	•	Docs, examples, changelog
	•	(Optional) Publish crate

⸻

Quickstart command map

# 0) Clone + submodule
git clone <repo> && cd libinjection-rs
git submodule add <upstream-url> libinjection-c

# 1) Build everything
cargo build --workspace --release

# 2) Run unit + integration + differential tests
cargo test --all-features

# 3) Fuzz (requires nightly)
cargo +nightly fuzz run diff_target -- -runs=100000

# 4) Benchmarks
cargo bench

# 5) Perf (Linux example)
perf stat -e cycles,instructions,branches,branch-misses \
  target/release/benchmarks


⸻

If you want, I can adapt this to your exact upstream version (API names, test file formats) and drop in the initial repo skeleton with the FFI oracle wired up.