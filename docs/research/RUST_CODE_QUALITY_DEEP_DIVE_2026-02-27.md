# Rust Code Quality Deep Dive (2026-02-27)

## Context

There is no reliable way to prove whether code was or was not AI-assisted from source text alone. In practice, reviewers judge maintainability signals. This document captures those signals and how to apply them in `rjd`.

## Sources

- Rust style guide: https://doc.rust-lang.org/style-guide/
- Rust API Guidelines: https://rust-lang.github.io/api-guidelines/
- Clippy lint index: https://rust-lang.github.io/rust-clippy/stable/index.html
- "Asleep at the Keyboard?" (Copilot security study): https://arxiv.org/abs/2108.09293
- "A Comprehensive Evaluation of AI's Impact on Programming Through Human-AI Collaboration" (security quality analysis): https://www.nature.com/articles/s41598-025-90809-0
- GitHub + Wakefield research summary on agentic tooling and review requirements: https://github.blog/ai-and-ml/generative-ai/how-ai-code-generation-works/

## What typically reads as low-trust or "machine-like"

1. Weak abstraction boundaries
- Helpers exist only to mechanically split code, not because of stable domain concepts.
- Same logic repeated with tiny parameter changes.

2. Brittle parsers for structured formats
- String slicing / regex against XML/JSON/TOML when a parser is available.
- Passes happy-path tests but fails on whitespace, namespaces, casing, or malformed input.

3. Over-explaining comments
- Comments narrate obvious lines instead of documenting constraints or edge cases.
- Comment density is high but design intent is still unclear.

4. Generic naming and flattened domain language
- Names like `value`, `data`, `result2`, `helper_fn` spread across critical paths.
- Hard to map code to domain concepts (toolchain, runtime, installation source, etc.).

5. Incomplete failure-path testing
- Many direct-path tests, few malformed-input tests.
- Edge-case behavior is implicit rather than validated.

## Three-pass review method used for this repo

1. Correctness pass
- Remove brittle implementations, tighten parsing, test edge cases.

2. Idiomatic pass
- Enforce `cargo fmt`, `clippy -D warnings`, and simplify naming/control flow where needed.

3. Ownership pass
- Keep comments sparse and specific.
- Ensure docs explain tradeoffs, not slogans.
- Verify behavior with integration command paths used by the toolkit.

## Changes applied in this pass

1. Replaced ad-hoc Maven `toolchains.xml` parsing with `roxmltree`.
- Reason: structured parser is more robust and easier for reviewers to trust.

2. Expanded parser coverage tests.
- Added namespaced XML fixture (`mvn:*` tags).
- Kept unresolved environment placeholder behavior explicit in tests.

3. Tightened research docs language.
- Removed repetitive templated wording.
- Kept short, operational explanations and concrete follow-up items.

## Ongoing quality gate for rjd

- `cargo fmt --all`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test -q`
- toolkit integration command:
  - `cargo run -q -p hytale-toolkit-cli -- java-doctor --loader-check --require-major 21 --require-jdk`
