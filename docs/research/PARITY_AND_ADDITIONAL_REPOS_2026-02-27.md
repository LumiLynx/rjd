# Parity Research Backlog (2026-02-27)

## Scope

This file tracks two things:

- what `rjd` still needs for tighter behavior parity
- what external projects are worth mining for next features

## Reference baseline

Local reference set used for parity checks:

- `smallauncher/research/java-discovery/sources/gradle`
- `smallauncher/research/java-discovery/sources/bill-stewart-javainfo`
- `smallauncher/research/java-discovery/sources/jpype`
- `smallauncher/research/java-discovery/sources/locate-java-home`
- `smallauncher/research/java-discovery/sources/node-find-java-home`
- `smallauncher/research/java-discovery/sources/intellij-community`

Upstream docs/repos checked during this pass:

- Gradle toolchains docs:
  - https://docs.gradle.org/current/userguide/toolchains.html
- Coursier JVM provisioning (`java-home`, managed JVMs):
  - https://get-coursier.io/docs/2.1.5-M6-26-gf16363395/cli-java-home
- Foojay Disco API (JDK discovery/download metadata):
  - https://github.com/foojayio/discoapi
- Eclipse Adoptium API surface:
  - https://api.adoptium.net/
- SDKMAN CLI:
  - https://github.com/sdkman/sdkman-cli
- jEnv:
  - https://github.com/jenv/jenv
- Jabba:
  - https://github.com/shyiko/jabba
- Coursier core:
  - https://github.com/coursier/coursier
- Prism Launcher runtime/launcher ecosystem reference:
  - https://github.com/PrismLauncher/PrismLauncher

## Current parity status (rjd)

Covered today:

- env vars (`JAVA_HOME`, `JDK_HOME`, `JRE_HOME`)
- PATH (`java`, `javac`)
- Linux/macOS/Windows common discovery roots
- broad Windows registry vendor coverage
- Gradle and tool-manager roots (`~/.gradle/jdks`, `~/.jdks`, SDKMAN/asdf/jabba/mise)
- Gradle property-backed candidate ingestion:
  - `org.gradle.java.installations.fromEnv`
  - `org.gradle.java.installations.paths`
  - custom IntelliJ JDK dir property
  - Maven toolchains property/file support
- Maven `toolchains.xml` parsing with `${env.*}` substitution
- JavaInfo-style compat precedence for selection in compat mode
- JVM library path probing and optional loader diagnostics

## Remaining parity gaps

1. `org.gradle.java.installations.auto-detect` behavior control
- Current behavior: `rjd` always auto-detects.
- Missing behavior: disable auto-detect but still honor user-defined suppliers.

2. Explicit "Current JVM" supplier semantics
- Gradle includes a dedicated current-JVM supplier.
- `rjd` often finds the same install indirectly, but source attribution is weaker.

3. Maven toolchains parser robustness
- Current parser is intentionally lightweight.
- Gap: full XML/XPath handling for unusual formatting, namespaces, comments, mixed whitespace, and malformed edge cases.

4. Windows registry precedence edge-cases
- JavaInfo has specific behavior around 64-bit preference and registry search details.
- `rjd` covers key families but still needs exact precedence parity verification on real Windows matrices.

## Next implementation pass

1. Add `JavaDoctorOptions::auto_detect_enabled` and enforce supplier gating.
2. Add `source: "tool:current-jvm"` discovery path using process/runtime Java home inference.
3. Replace lightweight Maven parsing with robust XML parser (`quick-xml` or `roxmltree`) plus fixture tests.
4. Add Windows parity integration fixtures and CI runs (registry simulation + native smoke checks).

## Extra repositories worth using

- `coursier/coursier`: strongest candidate for install/resolve flows (`install-java`, `resolve-java`) with pinned JVM coordinates.
- `foojayio/discoapi` + Adoptium API: practical metadata backend for vendor/version/arch filtering and deterministic download selection.
- `sdkman/sdkman-cli`, `jenv/jenv`, `shyiko/jabba`: useful for manager-specific diagnostics and concrete remediation hints in `doctor`.
- `PrismLauncher/PrismLauncher`: good reference for runtime-bundle handling and launcher-facing UX around Java/runtime issues.

## Notes

For parity work, behavior tests matter more than code-porting. The target is identical selection and exit-code outcomes for the same machine state.
