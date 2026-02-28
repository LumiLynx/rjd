# CI/CD Research Notes (2026-02-27)

This is the change log for the CI/CD pass in `rjd`, with references and rationale.

## Main references

- Workflow syntax: https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions
- `GITHUB_TOKEN` permissions: https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication
- Artifact flow between jobs: https://docs.github.com/en/actions/how-tos/writing-workflows/choosing-what-your-workflow-does/storing-and-sharing-data-from-a-workflow
- Artifact actions:
  - https://github.com/actions/upload-artifact
  - https://github.com/actions/download-artifact
- Rust setup/cache actions used in this repo:
  - https://github.com/dtolnay/rust-toolchain
  - https://github.com/Swatinem/rust-cache
- Security tooling:
  - https://github.com/RustSec/cargo-audit
  - https://github.com/taiki-e/install-action

## What changed

### CI (`.github/workflows/ci.yml`)

- `push` is now scoped to `master` and `main`.
- Concurrency cancellation is enabled so only the newest run on a ref keeps running.
- Job timeouts were added.
- Lint checks are stricter and deterministic:
  - `cargo fmt --all --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
- Tests stay cross-platform and now run with `--locked`.
- Added a release-build verification matrix (`cargo build --release --locked`).
- Windows smoke tests remain in place and now wait for both test and release-build jobs.

### Security (`.github/workflows/security.yml`)

- Weekly `cargo audit` run.
- Manual trigger when you want to run it immediately.

### Release (`.github/workflows/release.yml`)

- Triggered by `v*` tags.
- Builds binaries on Linux/macOS/Windows.
- Packages archives and `.sha256` files.
- Publishes everything to the GitHub Release for that tag.

## Why this shape

The target was a practical baseline, not a sprawling pipeline:

- good quality signal before merge
- cross-platform build confidence
- recurring vulnerability check
- consistent tagged releases with downloadable artifacts

## Next hardening steps

1. Pin third-party actions to commit SHAs.
2. Add Dependabot for `github-actions` and `cargo`.
3. Enforce required status checks in branch protection.
4. Add SBOM/provenance generation in release builds.
