# rjd (Rust Java Doctor)

Standalone Rust crate for Java runtime discovery and diagnostics.

## Scope

`rjd` is built to be reusable across projects. It discovers Java installations from:

- `JAVA_HOME`, `JDK_HOME`, `JRE_HOME`
- `PATH` (`java`, `javac`)
- OS-native locations (Linux/macOS/Windows)
- Tool-managed installs (SDKMAN, asdf, jabba, Gradle, IntelliJ, mise)
- Runtime bundles (Minecraft/Hytale style runtime folders)

Validation uses `java -XshowSettings:properties -version` first, then falls back to `java -version`.

## Library Usage

```rust
use rjd::{JavaDoctor, JavaDoctorOptions, JavaDoctorRequirements};

let report = JavaDoctor::doctor_report_with_options(JavaDoctorOptions::default());
let checks = JavaDoctor::evaluate_requirements(
    &report,
    &JavaDoctorRequirements {
        require_major: Some(17),
        require_jdk: true,
        require_jvm_library: true,
    },
);
```

## CLI Usage

```bash
cargo run --bin rjd -- list
cargo run --bin rjd -- list --csv
cargo run --bin rjd -- doctor --active
cargo run --bin rjd -- doctor --loader-check
cargo run --bin rjd -- doctor --require-major 17 --require-jdk --strict-json
cargo run --bin rjd -- compat --javahome
cargo run --bin rjd -- compat --javaminversion 21 --quiet
```

Exit codes:

- `0`: success / checks passed
- `3`: doctor requirements failed
- `1`: internal/runtime error

## Diagnostics

In addition to plain runtime discovery:

- source attribution with per-source counters
- optional active process correlation
- JVM shared-library detection (`jvm.dll`, `libjvm.so`, `libjvm.dylib`)
- architecture fallback via binary headers (PE/ELF/Mach-O)
- requirement checks for CI (`require_major`, `require_jdk`, `require_jvm_library`)
- strict JSON envelope with explicit `pass`/`fail`
- environment snapshot (`JAVA_HOME`, `JDK_HOME`, `JRE_HOME`, PATH visibility)
- CSV output for inventory/reporting
- distribution/build-scope inference (Temurin/Zulu/GraalVM/OpenJDK, etc.)
- JavaInfo-style compat mode and exit-code semantics
- optional loader diagnostics (`ldd`/`otool`/`dumpbin`)
- Windows registry source buckets (`javasoft`, `ibm`, `adoptium`, `microsoft`, `zulu`, `bellsoft`)

## Windows Validation

- Smoke checklist: `docs/WINDOWS_SMOKE.md`
- PowerShell harness: `scripts/windows-smoke.ps1`
- GitHub Actions CI: `.github/workflows/ci.yml` (includes Windows smoke run)
