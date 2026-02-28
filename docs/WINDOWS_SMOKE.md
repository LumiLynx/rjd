# rjd Windows Smoke Validation

Use this checklist on a real Windows machine to validate JavaInfo parity behavior and diagnostics.

## 1. Build

```powershell
cargo build --release
```

Binary path:

- `target\release\rjd.exe`

## 2. Baseline doctor report

```powershell
.\target\release\rjd.exe doctor --strict-json --loader-check
```

Check:

- `report.detected_runtime` is present when Java exists.
- `report.environment.java_home_env`, `jdk_home_env`, `jre_home_env` reflect env vars only.
- `report.installations[*].installation.is_64_bit` is populated.
- `report.sources` contains specific registry buckets like `windows:registry:javasoft`, `windows:registry:adoptium`, etc. when applicable.

## 3. JavaInfo-compatible exit-code checks

```powershell
.\target\release\rjd.exe compat --javainstalled --quiet; echo $LASTEXITCODE
.\target\release\rjd.exe compat --javahome --quiet; echo $LASTEXITCODE
.\target\release\rjd.exe compat --javadll --quiet; echo $LASTEXITCODE
.\target\release\rjd.exe compat --javais64bit --quiet; echo $LASTEXITCODE
.\target\release\rjd.exe compat --javaminversion 21 --quiet; echo $LASTEXITCODE
.\target\release\rjd.exe compat --javaminversion bad.version --quiet; echo $LASTEXITCODE
```

Expected semantics:

- `--javainstalled`: `0` installed, `2` not installed
- `--javahome`: `0` when Java installed, `2` otherwise
- `--javadll`: `0` when JVM DLL path exists, `2` otherwise
- `--javais64bit`: `1` if 64-bit, `0` if not 64-bit, `2` if no Java
- `--javaminversion`: `1` if installed version >= required, `0` if lower, `2` if no Java
- invalid version format: `87`

## 4. Optional precedence checks

To verify source precedence, temporarily alter environment:

```powershell
$old = $env:JAVA_HOME
$env:JAVA_HOME = "C:\nonexistent-java-home"
.\target\release\rjd.exe doctor --strict-json
$env:JAVA_HOME = $old
```

You should still see a valid discovered runtime from `PATH`/registry if available.

