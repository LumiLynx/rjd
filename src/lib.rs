use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JavaDoctorError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaInstallation {
    pub path: PathBuf,
    pub java_home: PathBuf,
    pub version: String,
    pub vendor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distribution: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_scope: Option<String>,
    pub arch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_64_bit: Option<bool>,
    pub is_jdk: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jvm_library_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loader_diagnostics: Option<JavaLoaderDiagnostics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaLoaderDiagnostics {
    pub tool: String,
    pub status: String,
    pub exit_code: Option<i32>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaDiscovery {
    pub installation: JavaInstallation,
    pub source: String,
    pub in_use: bool,
    pub active_processes: Vec<JavaProcessUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaProcessUsage {
    pub pid: u32,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaDoctorSource {
    pub source: String,
    pub candidates: usize,
    pub binaries_tested: usize,
    pub installations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaDoctorReport {
    pub os: String,
    pub arch: String,
    pub host_bitness: String,
    pub hostname: Option<String>,
    pub environment: JavaDoctorEnvironment,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected_runtime: Option<JavaDoctorDetectedRuntime>,
    pub active_scan_enabled: bool,
    pub candidate_count: usize,
    pub binary_count: usize,
    pub installation_count: usize,
    pub installations: Vec<JavaDiscovery>,
    pub sources: Vec<JavaDoctorSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaDoctorEnvironment {
    pub java_home_env: Option<PathBuf>,
    pub jdk_home_env: Option<PathBuf>,
    pub jre_home_env: Option<PathBuf>,
    pub path_has_java: bool,
    pub path_has_javac: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaDoctorDetectedRuntime {
    pub path: PathBuf,
    pub java_home: PathBuf,
    pub version: String,
    pub vendor: String,
    pub source: String,
    pub is_jdk: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_64_bit: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jvm_library_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct JavaDoctorOptions {
    pub include_active_processes: bool,
    pub detect_jvm_library: bool,
    pub include_loader_diagnostics: bool,
    pub include_runtime_bundles: bool,
    pub extra_search_roots: Vec<PathBuf>,
    pub command_timeout: Duration,
}

impl Default for JavaDoctorOptions {
    fn default() -> Self {
        Self {
            include_active_processes: false,
            detect_jvm_library: true,
            include_loader_diagnostics: false,
            include_runtime_bundles: true,
            extra_search_roots: Vec::new(),
            command_timeout: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JavaDoctorRequirements {
    pub require_major: Option<u8>,
    pub require_jdk: bool,
    pub require_jvm_library: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaDoctorChecks {
    pub passed: bool,
    pub require_major: Option<u8>,
    pub require_jdk: bool,
    pub require_jvm_library: bool,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JavaDoctorStatus {
    #[serde(rename = "pass")]
    Pass,
    #[serde(rename = "fail")]
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaDoctorEnvelope {
    pub status: JavaDoctorStatus,
    pub report: JavaDoctorReport,
    pub checks: JavaDoctorChecks,
}

#[derive(Debug, Default, Clone)]
struct SourceMetrics {
    candidates: usize,
    binaries_tested: usize,
    installations: usize,
}

#[derive(Debug, Clone)]
struct JavaCandidate {
    path: PathBuf,
    source: String,
}

#[derive(Debug, Clone)]
struct WindowsRegistryQuery {
    subkey: String,
    value_name: &'static str,
    source: &'static str,
}

pub struct JavaDoctor;

impl JavaDoctor {
    pub fn scan_system() -> Vec<JavaInstallation> {
        Self::doctor_report()
            .installations
            .into_iter()
            .map(|entry| entry.installation)
            .collect()
    }

    pub fn scan_system_detailed() -> Vec<JavaDiscovery> {
        Self::doctor_report().installations
    }

    pub fn doctor_report() -> JavaDoctorReport {
        Self::doctor_report_with_options(JavaDoctorOptions::default())
    }

    pub fn run_doctor(
        options: JavaDoctorOptions,
        requirements: JavaDoctorRequirements,
    ) -> JavaDoctorEnvelope {
        let report = Self::doctor_report_with_options(options);
        let checks = Self::evaluate_requirements(&report, &requirements);
        let status = if checks.passed {
            JavaDoctorStatus::Pass
        } else {
            JavaDoctorStatus::Fail
        };

        JavaDoctorEnvelope {
            status,
            report,
            checks,
        }
    }

    pub fn doctor_report_with_options(options: JavaDoctorOptions) -> JavaDoctorReport {
        let mut candidates = Vec::new();
        let mut seen_candidates = HashSet::new();
        let environment = Self::collect_environment_snapshot();
        let hostname = Self::detect_hostname();
        let host_bitness = Self::host_bitness();

        Self::collect_environment_candidates(&mut candidates, &mut seen_candidates);
        Self::collect_path_candidates(&mut candidates, &mut seen_candidates);
        Self::collect_os_candidates(&mut candidates, &mut seen_candidates);
        Self::collect_tool_manager_candidates(&mut candidates, &mut seen_candidates);

        if options.include_runtime_bundles {
            Self::collect_runtime_bundle_candidates(&mut candidates, &mut seen_candidates);
        }

        for root in &options.extra_search_roots {
            Self::collect_root_and_children(
                root,
                "option:search-root",
                &mut candidates,
                &mut seen_candidates,
            );
        }

        let candidate_count = candidates.len();
        let mut discoveries = Vec::new();
        let mut seen_binaries = HashSet::new();
        let mut seen_installations = HashSet::new();
        let mut source_metrics: BTreeMap<String, SourceMetrics> = BTreeMap::new();

        for candidate in &candidates {
            source_metrics
                .entry(candidate.source.clone())
                .or_default()
                .candidates += 1;
        }

        for candidate in candidates {
            for java_bin in Self::java_binary_candidates(&candidate.path) {
                if !java_bin.exists() {
                    continue;
                }

                let key = Self::normalize_path_key(&java_bin);
                if !seen_binaries.insert(key) {
                    continue;
                }

                source_metrics
                    .entry(candidate.source.clone())
                    .or_default()
                    .binaries_tested += 1;

                if let Ok(install) = Self::validate_with_options(
                    &java_bin,
                    options.detect_jvm_library,
                    options.include_loader_diagnostics,
                    options.command_timeout,
                ) {
                    let install_key = Self::normalize_path_key(&install.path);
                    if seen_installations.insert(install_key) {
                        source_metrics
                            .entry(candidate.source.clone())
                            .or_default()
                            .installations += 1;

                        discoveries.push(JavaDiscovery {
                            installation: install,
                            source: candidate.source.clone(),
                            in_use: false,
                            active_processes: Vec::new(),
                        });
                    }
                }
            }
        }

        if options.include_active_processes {
            Self::attach_active_processes(&mut discoveries);
        }

        let detected_runtime = Self::select_detected_runtime(&discoveries);

        let binary_count = seen_binaries.len();
        let sources = source_metrics
            .into_iter()
            .map(|(source, metrics)| JavaDoctorSource {
                source,
                candidates: metrics.candidates,
                binaries_tested: metrics.binaries_tested,
                installations: metrics.installations,
            })
            .collect();

        JavaDoctorReport {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            host_bitness,
            hostname,
            environment,
            detected_runtime,
            active_scan_enabled: options.include_active_processes,
            candidate_count,
            binary_count,
            installation_count: discoveries.len(),
            installations: discoveries,
            sources,
        }
    }

    pub fn evaluate_requirements(
        report: &JavaDoctorReport,
        requirements: &JavaDoctorRequirements,
    ) -> JavaDoctorChecks {
        let mut failures = Vec::new();

        if let Some(required_major) = requirements.require_major {
            let has_major = report
                .installations
                .iter()
                .any(|entry| version_matches_major(&entry.installation.version, required_major));
            if !has_major {
                failures.push(format!(
                    "No Java {} installation was discovered.",
                    required_major
                ));
            }

            if requirements.require_jdk {
                let has_major_jdk = report.installations.iter().any(|entry| {
                    entry.installation.is_jdk
                        && version_matches_major(&entry.installation.version, required_major)
                });
                if !has_major_jdk {
                    failures.push(format!(
                        "No JDK {} installation was discovered.",
                        required_major
                    ));
                }
            }

            if requirements.require_jvm_library {
                let has_major_jvm_lib = report.installations.iter().any(|entry| {
                    entry.installation.jvm_library_path.is_some()
                        && version_matches_major(&entry.installation.version, required_major)
                });
                if !has_major_jvm_lib {
                    failures.push(format!(
                        "No Java {} installation with a JVM shared library was discovered.",
                        required_major
                    ));
                }
            }
        } else {
            if requirements.require_jdk {
                let has_jdk = report
                    .installations
                    .iter()
                    .any(|entry| entry.installation.is_jdk);
                if !has_jdk {
                    failures.push("No JDK installation was discovered.".to_string());
                }
            }

            if requirements.require_jvm_library {
                let has_jvm_lib = report
                    .installations
                    .iter()
                    .any(|entry| entry.installation.jvm_library_path.is_some());
                if !has_jvm_lib {
                    failures.push(
                        "No installation with a JVM shared library was discovered.".to_string(),
                    );
                }
            }
        }

        JavaDoctorChecks {
            passed: failures.is_empty(),
            require_major: requirements.require_major,
            require_jdk: requirements.require_jdk,
            require_jvm_library: requirements.require_jvm_library,
            failures,
        }
    }

    pub fn validate(path: &Path) -> Result<JavaInstallation, JavaDoctorError> {
        Self::validate_with_options(path, true, false, Duration::from_secs(15))
    }

    pub fn validate_with_options(
        path: &Path,
        detect_jvm_library: bool,
        include_loader_diagnostics: bool,
        timeout: Duration,
    ) -> Result<JavaInstallation, JavaDoctorError> {
        if !path.exists() {
            return Err(JavaDoctorError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Java binary not found",
            )));
        }

        let probe_output = {
            let mut probe = Command::new(path);
            probe.args(["-XshowSettings:properties", "-version"]);
            Self::run_command_with_timeout(&mut probe, timeout)
                .map(|output| Self::combine_output(&output))
        };

        if let Ok(output) = probe_output {
            let install = Self::parse_java_output(
                path,
                &output,
                detect_jvm_library,
                include_loader_diagnostics,
                timeout,
            );
            if install.version != "unknown" {
                return Ok(install);
            }
        }

        let mut version_only = Command::new(path);
        version_only.arg("-version");
        let output = Self::run_command_with_timeout(&mut version_only, timeout)?;
        Ok(Self::parse_java_output(
            path,
            &Self::combine_output(&output),
            detect_jvm_library,
            include_loader_diagnostics,
            timeout,
        ))
    }

    fn parse_java_output(
        path: &Path,
        output: &str,
        detect_jvm_library: bool,
        include_loader_diagnostics: bool,
        timeout: Duration,
    ) -> JavaInstallation {
        let version = Self::extract_version(output);
        let vendor = Self::detect_vendor(output);
        let mut arch = Self::detect_arch(output);

        let canonical_path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let java_home = Self::java_home_from_binary(&canonical_path).unwrap_or_else(|| {
            canonical_path
                .parent()
                .and_then(Path::parent)
                .unwrap_or_else(|| Path::new("/"))
                .to_path_buf()
        });
        let is_jdk = Self::is_jdk_installation(&canonical_path);
        let (distribution, build_scope) = Self::infer_distribution(&vendor, output, &java_home);

        let jvm_library_path = if detect_jvm_library {
            Self::detect_jvm_library_path(&java_home)
        } else {
            None
        };
        // Prefer runtime-reported architecture, then fall back to binary header parsing.
        let is_64_bit = Self::arch_to_is_64_bit(&arch)
            .or_else(|| Self::detect_binary_is_64_bit(&canonical_path))
            .or_else(|| {
                jvm_library_path
                    .as_ref()
                    .and_then(|path| Self::detect_binary_is_64_bit(path))
            });
        if arch == "unknown"
            && let Some(value) = is_64_bit
        {
            arch = if value {
                "64-bit".to_string()
            } else {
                "32-bit".to_string()
            };
        }
        let loader_diagnostics = if include_loader_diagnostics {
            jvm_library_path
                .as_ref()
                .map(|jvm_path| Self::collect_loader_diagnostics(jvm_path, timeout))
        } else {
            None
        };

        JavaInstallation {
            path: canonical_path,
            java_home,
            version,
            vendor,
            distribution,
            build_scope,
            arch,
            is_64_bit,
            is_jdk,
            jvm_library_path,
            loader_diagnostics,
        }
    }

    fn run_command_with_timeout(
        command: &mut Command,
        timeout: Duration,
    ) -> Result<Output, JavaDoctorError> {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = command.spawn().map_err(JavaDoctorError::Io)?;
        let start = Instant::now();

        loop {
            match child.try_wait().map_err(JavaDoctorError::Io)? {
                Some(_) => return child.wait_with_output().map_err(JavaDoctorError::Io),
                None => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(JavaDoctorError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "Java probe timed out",
                        )));
                    }
                    thread::sleep(Duration::from_millis(25));
                }
            }
        }
    }

    fn combine_output(output: &Output) -> String {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if stderr.trim().is_empty() {
            stdout.to_string()
        } else if stdout.trim().is_empty() {
            stderr.to_string()
        } else {
            format!("{stderr}\n{stdout}")
        }
    }

    fn java_home_from_binary(java_bin_path: &Path) -> Option<PathBuf> {
        let bin_dir = java_bin_path.parent()?;
        if !Self::path_component_eq(bin_dir.file_name(), "bin") {
            return None;
        }
        let java_home = bin_dir.parent()?;
        Some(java_home.to_path_buf())
    }

    fn is_jdk_installation(java_bin_path: &Path) -> bool {
        let Some(bin_dir) = java_bin_path.parent() else {
            return false;
        };
        let Some(java_home) = bin_dir.parent() else {
            return false;
        };

        let javac = if cfg!(windows) {
            java_home.join("bin").join("javac.exe")
        } else {
            java_home.join("bin").join("javac")
        };
        javac.exists()
    }

    fn detect_jvm_library_path(java_home: &Path) -> Option<PathBuf> {
        let relative_candidates: &[&str] = if cfg!(windows) {
            &[
                "bin/server/jvm.dll",
                "bin/client/jvm.dll",
                "jre/bin/server/jvm.dll",
                "jre/bin/client/jvm.dll",
            ]
        } else if cfg!(target_os = "macos") {
            &[
                "lib/server/libjvm.dylib",
                "jre/lib/server/libjvm.dylib",
                "Contents/Home/lib/server/libjvm.dylib",
            ]
        } else {
            &[
                "lib/server/libjvm.so",
                "lib/amd64/server/libjvm.so",
                "lib/aarch64/server/libjvm.so",
                "jre/lib/server/libjvm.so",
                "jre/lib/amd64/server/libjvm.so",
                "jre/lib/aarch64/server/libjvm.so",
            ]
        };

        for relative in relative_candidates {
            let candidate = java_home.join(relative);
            if candidate.exists() && Self::is_supported_jvm_library_path(&candidate) {
                return Some(fs::canonicalize(&candidate).unwrap_or(candidate));
            }
        }

        let target_name = if cfg!(windows) {
            "jvm.dll"
        } else if cfg!(target_os = "macos") {
            "libjvm.dylib"
        } else {
            "libjvm.so"
        };

        Self::find_file_bounded(java_home, target_name, 4)
    }

    fn find_file_bounded(root: &Path, target_name: &str, max_depth: usize) -> Option<PathBuf> {
        if !root.exists() {
            return None;
        }

        let mut stack = vec![(root.to_path_buf(), 0_usize)];
        let mut seen = HashSet::new();

        while let Some((dir, depth)) = stack.pop() {
            let key = Self::normalize_path_key(&dir);
            if !seen.insert(key) {
                continue;
            }

            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };

            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };

                if file_type.is_file()
                    && path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .map(|name| {
                            if cfg!(windows) {
                                name.eq_ignore_ascii_case(target_name)
                            } else {
                                name == target_name
                            }
                        })
                        .unwrap_or(false)
                {
                    if !Self::is_supported_jvm_library_path(&path) {
                        continue;
                    }
                    return Some(fs::canonicalize(&path).unwrap_or(path));
                }

                if file_type.is_dir() && depth < max_depth {
                    stack.push((path, depth + 1));
                }
            }
        }

        None
    }

    fn is_supported_jvm_library_path(path: &Path) -> bool {
        let unsupported_dirs = ["cacao", "jamvm"];
        let parent_name = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|v| v.to_str())
            .map(|v| v.to_ascii_lowercase());
        match parent_name {
            Some(name) => !unsupported_dirs.iter().any(|u| *u == name),
            None => true,
        }
    }

    fn collect_loader_diagnostics(path: &Path, timeout: Duration) -> JavaLoaderDiagnostics {
        let path_arg = path.display().to_string();
        if cfg!(windows) {
            return Self::run_loader_command(
                "dumpbin",
                &["-headers".to_string(), path_arg],
                timeout,
            );
        }
        if cfg!(target_os = "macos") {
            return Self::run_loader_command("otool", &["-L".to_string(), path_arg], timeout);
        }
        Self::run_loader_command("ldd", &[path_arg], timeout)
    }

    fn run_loader_command(tool: &str, args: &[String], timeout: Duration) -> JavaLoaderDiagnostics {
        let mut command = Command::new(tool);
        command.args(args);

        match Self::run_command_with_timeout(&mut command, timeout) {
            Ok(output) => {
                let text = Self::combine_output(&output);
                let summary = Self::summarize_text_lines(&text, 12);
                if output.status.success() {
                    JavaLoaderDiagnostics {
                        tool: tool.to_string(),
                        status: "ok".to_string(),
                        exit_code: output.status.code(),
                        summary,
                    }
                } else {
                    JavaLoaderDiagnostics {
                        tool: tool.to_string(),
                        status: "error".to_string(),
                        exit_code: output.status.code(),
                        summary,
                    }
                }
            }
            Err(err) => JavaLoaderDiagnostics {
                tool: tool.to_string(),
                status: if matches!(err, JavaDoctorError::Io(_)) {
                    "unavailable".to_string()
                } else {
                    "error".to_string()
                },
                exit_code: None,
                summary: err.to_string(),
            },
        }
    }

    fn summarize_text_lines(text: &str, max_lines: usize) -> String {
        text.lines()
            .take(max_lines)
            .map(str::trim)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn attach_active_processes(discoveries: &mut [JavaDiscovery]) {
        let process_list = Self::collect_process_command_lines();
        if process_list.is_empty() {
            return;
        }

        for discovery in discoveries {
            let java_path = discovery.installation.path.to_string_lossy().to_string();
            let java_key = Self::normalize_path_key(&discovery.installation.path);
            let mut seen = HashSet::new();

            for (pid, command) in &process_list {
                if command.is_empty() {
                    continue;
                }

                let normalized_command = if cfg!(windows) {
                    command.to_lowercase().replace('/', "\\")
                } else {
                    command.clone()
                };

                let direct_match = normalized_command.contains(&java_key);
                let string_match = command.contains(&java_path);

                if direct_match || string_match {
                    let dedupe_key = format!("{pid}:{command}");
                    if seen.insert(dedupe_key) {
                        discovery.active_processes.push(JavaProcessUsage {
                            pid: *pid,
                            command: command.clone(),
                        });
                    }
                }
            }

            discovery.in_use = !discovery.active_processes.is_empty();
        }
    }

    fn collect_process_command_lines() -> Vec<(u32, String)> {
        if cfg!(windows) {
            return Self::collect_windows_process_command_lines();
        }

        let output = Command::new("ps").args(["-eo", "pid=,args="]).output();
        let Ok(output) = output else {
            return Vec::new();
        };
        if !output.status.success() {
            return Vec::new();
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut processes = Vec::new();

        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut parts = trimmed.splitn(2, char::is_whitespace);
            let Some(pid_raw) = parts.next() else {
                continue;
            };
            let Ok(pid) = pid_raw.trim().parse::<u32>() else {
                continue;
            };
            let command = parts.next().unwrap_or("").trim().to_string();
            processes.push((pid, command));
        }

        processes
    }

    fn collect_windows_process_command_lines() -> Vec<(u32, String)> {
        let scripts = [
            r#"[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; Get-CimInstance Win32_Process | ForEach-Object { if ($_.CommandLine) { '{0}`t{1}' -f $_.ProcessId, ($_.CommandLine -replace "`r|`n", " ") } }"#,
            r#"[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; Get-Process | ForEach-Object { if ($_.Path) { '{0}`t{1}' -f $_.Id, $_.Path } }"#,
        ];

        for shell in ["powershell.exe", "powershell"] {
            for script in scripts {
                let output = Command::new(shell)
                    .args(["-NoProfile", "-Command", script])
                    .output();
                let Ok(output) = output else {
                    continue;
                };
                if !output.status.success() {
                    continue;
                }

                let stdout = String::from_utf8_lossy(&output.stdout);
                let parsed = Self::parse_windows_process_tsv_output(&stdout);
                if !parsed.is_empty() {
                    return parsed;
                }
            }
        }

        let output = Command::new("wmic")
            .args(["process", "get", "ProcessId,CommandLine", "/VALUE"])
            .output();
        let Ok(output) = output else {
            return Vec::new();
        };
        if !output.status.success() {
            return Vec::new();
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_windows_wmic_value_output(&stdout)
    }

    fn parse_windows_process_tsv_output(output: &str) -> Vec<(u32, String)> {
        let mut result = Vec::new();
        let mut seen = HashSet::new();

        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let Some((pid_raw, command_raw)) = trimmed.split_once('\t') else {
                continue;
            };
            let Ok(pid) = pid_raw.trim().parse::<u32>() else {
                continue;
            };
            let command = command_raw.trim();
            if command.is_empty() {
                continue;
            }

            let key = format!("{pid}:{command}");
            if seen.insert(key) {
                result.push((pid, command.to_string()));
            }
        }

        result
    }

    fn parse_windows_wmic_value_output(output: &str) -> Vec<(u32, String)> {
        let mut result = Vec::new();
        let mut seen = HashSet::new();
        let mut current_pid: Option<u32> = None;
        let mut current_cmd: Option<String> = None;

        let mut flush = |pid: &mut Option<u32>, cmd: &mut Option<String>| {
            let Some(process_id) = *pid else {
                *cmd = None;
                return;
            };
            let Some(command) = cmd.take() else {
                *pid = None;
                return;
            };
            let command = command.trim().to_string();
            if command.is_empty() {
                *pid = None;
                return;
            }
            let key = format!("{process_id}:{command}");
            if seen.insert(key) {
                result.push((process_id, command));
            }
            *pid = None;
        };

        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                flush(&mut current_pid, &mut current_cmd);
                continue;
            }

            if let Some(value) = trimmed.strip_prefix("ProcessId=") {
                if let Ok(pid) = value.trim().parse::<u32>() {
                    current_pid = Some(pid);
                }
                continue;
            }

            if let Some(value) = trimmed.strip_prefix("CommandLine=") {
                current_cmd = Some(value.trim().to_string());
            }
        }

        flush(&mut current_pid, &mut current_cmd);
        result
    }

    fn collect_environment_snapshot() -> JavaDoctorEnvironment {
        JavaDoctorEnvironment {
            java_home_env: env::var_os("JAVA_HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            jdk_home_env: env::var_os("JDK_HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            jre_home_env: env::var_os("JRE_HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            path_has_java: which::which("java").is_ok(),
            path_has_javac: which::which("javac").is_ok(),
        }
    }

    fn select_detected_runtime(discoveries: &[JavaDiscovery]) -> Option<JavaDoctorDetectedRuntime> {
        let best = discoveries.iter().max_by_key(|entry| {
            (
                Self::source_priority(&entry.source),
                Self::version_sort_key(&entry.installation.version),
                entry.installation.is_jdk,
                entry.installation.jvm_library_path.is_some(),
            )
        })?;

        let install = &best.installation;
        Some(JavaDoctorDetectedRuntime {
            path: install.path.clone(),
            java_home: install.java_home.clone(),
            version: install.version.clone(),
            vendor: install.vendor.clone(),
            source: best.source.clone(),
            is_jdk: install.is_jdk,
            is_64_bit: install.is_64_bit,
            jvm_library_path: install.jvm_library_path.clone(),
        })
    }

    fn source_priority(source: &str) -> u8 {
        if source == "path:java" {
            6
        } else if source.starts_with("env:") {
            5
        } else if [
            "windows:registry:javasoft",
            "windows:registry:ibm",
            "windows:registry:adoptium",
            "windows:registry:microsoft",
            "windows:registry:zulu",
            "windows:registry:bellsoft",
            "windows:registry",
            "macos:java_home",
            "linux:update-java-alternatives",
            "linux:archlinux-java",
        ]
        .iter()
        .any(|prefix| source.starts_with(prefix))
        {
            4
        } else if source.starts_with("tool:") {
            3
        } else if source.starts_with("runtime:") {
            2
        } else {
            1
        }
    }

    fn version_sort_key(version: &str) -> [u16; 4] {
        let mut numbers = version
            .split(|c: char| !c.is_ascii_digit())
            .filter(|part| !part.is_empty())
            .filter_map(|part| part.parse::<u16>().ok());

        let mut result = [0_u16; 4];
        for slot in &mut result {
            if let Some(v) = numbers.next() {
                *slot = v;
            } else {
                break;
            }
        }
        result
    }

    fn detect_hostname() -> Option<String> {
        for key in ["HOSTNAME", "COMPUTERNAME"] {
            if let Some(value) = env::var_os(key).filter(|value| !value.is_empty()) {
                return Some(value.to_string_lossy().to_string());
            }
        }

        if let Ok(output) = Command::new("hostname").output()
            && output.status.success()
        {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }

        None
    }

    fn collect_environment_candidates(
        candidates: &mut Vec<JavaCandidate>,
        seen: &mut HashSet<String>,
    ) {
        for (var, source) in [
            ("JAVA_HOME", "env:JAVA_HOME"),
            ("JDK_HOME", "env:JDK_HOME"),
            ("JRE_HOME", "env:JRE_HOME"),
        ] {
            if let Some(value) = env::var_os(var).filter(|value| !value.is_empty()) {
                Self::push_candidate(candidates, seen, PathBuf::from(value), source);
            }
        }
    }

    fn collect_path_candidates(candidates: &mut Vec<JavaCandidate>, seen: &mut HashSet<String>) {
        for (binary, source) in [("java", "path:java"), ("javac", "path:javac")] {
            if let Ok(path) = which::which(binary) {
                Self::push_candidate(candidates, seen, path, source);
            }
        }
    }

    fn collect_os_candidates(candidates: &mut Vec<JavaCandidate>, seen: &mut HashSet<String>) {
        if cfg!(target_os = "linux") {
            Self::collect_linux_candidates(candidates, seen);
        } else if cfg!(target_os = "macos") {
            Self::collect_macos_candidates(candidates, seen);
        } else if cfg!(windows) {
            Self::collect_windows_candidates(candidates, seen);
        }
    }

    fn collect_linux_candidates(candidates: &mut Vec<JavaCandidate>, seen: &mut HashSet<String>) {
        for root in [
            "/usr/lib/jvm",
            "/usr/lib64/jvm",
            "/usr/lib32/jvm",
            "/usr/java",
            "/usr/local/java",
            "/opt/java",
            "/opt/jdk",
            "/opt/jdks",
            "/opt/ibm",
            "/app/jdk",
        ] {
            Self::collect_root_and_children(Path::new(root), "linux:common", candidates, seen);
        }

        Self::collect_filtered_subdirs(
            Path::new("/usr/lib64"),
            "linux:distro-specific",
            candidates,
            seen,
            |name| name.starts_with("openjdk-") || name.starts_with("openj9-"),
        );
        Self::collect_filtered_subdirs(
            Path::new("/usr/lib"),
            "linux:distro-specific",
            candidates,
            seen,
            |name| name.starts_with("openjdk-") || name.starts_with("openj9-"),
        );
        Self::collect_filtered_subdirs(
            Path::new("/opt"),
            "linux:distro-specific",
            candidates,
            seen,
            |name| name.starts_with("openjdk-") || name.starts_with("openj9-"),
        );
        Self::collect_filtered_subdirs(
            Path::new("/usr/lib"),
            "linux:distro-specific",
            candidates,
            seen,
            |name| name == "java" || name.starts_with("java-"),
        );

        Self::collect_update_java_alternatives_candidates(candidates, seen);
        Self::collect_archlinux_java_candidates(candidates, seen);
    }

    fn collect_macos_candidates(candidates: &mut Vec<JavaCandidate>, seen: &mut HashSet<String>) {
        for output in Self::run_macos_java_home_verbose() {
            for path in Self::parse_macos_java_home_output(&output) {
                Self::push_candidate(candidates, seen, path, "macos:java_home");
            }
        }

        if let Ok(output) = Command::new("/usr/libexec/java_home").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let path = stdout.trim();
            if !path.is_empty() {
                Self::push_candidate(
                    candidates,
                    seen,
                    PathBuf::from(path),
                    "macos:java_home-default",
                );
            }
        }

        for root in [
            PathBuf::from("/Library/Java/JavaVirtualMachines"),
            PathBuf::from("/System/Library/Java/JavaVirtualMachines"),
        ] {
            Self::collect_root_and_children(&root, "macos:system-locations", candidates, seen);
        }

        if let Some(home) = Self::user_home_dir() {
            Self::collect_root_and_children(
                &home
                    .join("Library")
                    .join("Java")
                    .join("JavaVirtualMachines"),
                "macos:user-locations",
                candidates,
                seen,
            );

            for brew_root in [
                PathBuf::from("/opt/homebrew/opt"),
                PathBuf::from("/usr/local/opt"),
            ] {
                Self::collect_homebrew_libexec(&brew_root, candidates, seen);
            }
        }
    }

    fn collect_homebrew_libexec(
        root: &Path,
        candidates: &mut Vec<JavaCandidate>,
        seen: &mut HashSet<String>,
    ) {
        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                let path = entry.path();
                let libexec = path.join("libexec");
                if libexec.is_dir() {
                    Self::collect_root_and_children(&libexec, "homebrew:libexec", candidates, seen);
                }
            }
        }
    }

    fn run_macos_java_home_verbose() -> Vec<String> {
        let mut outputs = Vec::new();
        let mut command = Command::new("/usr/libexec/java_home");
        command.arg("-V").env_remove("JAVA_VERSION");
        if let Ok(output) = command.output() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if !stderr.trim().is_empty() {
                outputs.push(stderr);
            }
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            if !stdout.trim().is_empty() {
                outputs.push(stdout);
            }
        }
        outputs
    }

    fn collect_update_java_alternatives_candidates(
        candidates: &mut Vec<JavaCandidate>,
        seen: &mut HashSet<String>,
    ) {
        let output = Command::new("update-java-alternatives")
            .args(["-l"])
            .output();
        let Ok(output) = output else {
            return;
        };
        if !(output.status.success() || output.status.code() == Some(1)) {
            return;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let mut parts = line.split_whitespace();
            let _name = parts.next();
            let _priority = parts.next();
            let Some(path) = parts.next() else {
                continue;
            };
            Self::push_candidate(
                candidates,
                seen,
                PathBuf::from(path),
                "linux:update-java-alternatives",
            );
        }
    }

    fn collect_archlinux_java_candidates(
        candidates: &mut Vec<JavaCandidate>,
        seen: &mut HashSet<String>,
    ) {
        let output = Command::new("archlinux-java").arg("status").output();
        let Ok(output) = output else {
            return;
        };
        if !output.status.success() {
            return;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let name = trimmed
                .strip_prefix("Available Java environments:")
                .map(str::trim)
                .unwrap_or(trimmed)
                .trim_start_matches('*')
                .trim();

            if name.is_empty()
                || name.eq_ignore_ascii_case("none")
                || name.contains("Default Java environment")
            {
                continue;
            }

            Self::push_candidate(
                candidates,
                seen,
                PathBuf::from("/usr/lib/jvm").join(name),
                "linux:archlinux-java",
            );
        }
    }

    fn collect_windows_candidates(candidates: &mut Vec<JavaCandidate>, seen: &mut HashSet<String>) {
        Self::collect_windows_registry_candidates(candidates, seen);

        for env_var in ["ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(base) = env::var_os(env_var).filter(|value| !value.is_empty()) {
                let root = PathBuf::from(base).join("Java");
                Self::collect_root_and_children(
                    &root,
                    "windows:common-locations",
                    candidates,
                    seen,
                );
            }
        }

        if let Some(system_drive) = env::var_os("SystemDrive").filter(|value| !value.is_empty()) {
            let root = PathBuf::from(system_drive).join("Java");
            Self::collect_root_and_children(&root, "windows:common-locations", candidates, seen);
        }
    }

    fn collect_windows_registry_candidates(
        candidates: &mut Vec<JavaCandidate>,
        seen: &mut HashSet<String>,
    ) {
        for root in ["HKLM", "HKCU"] {
            for query in Self::windows_registry_queries() {
                let key = format!("{root}\\{}", query.subkey);
                for view in ["64", "32"] {
                    let mut command = Command::new("reg");
                    command
                        .arg("query")
                        .arg(&key)
                        .arg("/s")
                        .arg("/v")
                        .arg(query.value_name)
                        .arg(format!("/reg:{view}"));

                    let Ok(output) = command.output() else {
                        continue;
                    };
                    if !output.status.success() {
                        continue;
                    }

                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for path in Self::parse_windows_registry_query_output(&stdout, query.value_name)
                    {
                        Self::push_candidate(candidates, seen, PathBuf::from(path), query.source);
                    }
                }
            }
        }
    }

    fn windows_registry_queries() -> Vec<WindowsRegistryQuery> {
        let mut queries = Vec::new();

        for base in ["SOFTWARE\\JavaSoft", "SOFTWARE\\Wow6432Node\\JavaSoft"] {
            for kind in [
                "JDK",
                "Java Development Kit",
                "Java Runtime Environment",
                "JRE",
            ] {
                queries.push(WindowsRegistryQuery {
                    subkey: format!("{base}\\{kind}"),
                    value_name: "JavaHome",
                    source: "windows:registry:javasoft",
                });
            }
        }

        for base in ["SOFTWARE\\IBM", "SOFTWARE\\Wow6432Node\\IBM"] {
            for kind in [
                "JDK",
                "Java Development Kit",
                "Java Runtime Environment",
                "JRE",
            ] {
                queries.push(WindowsRegistryQuery {
                    subkey: format!("{base}\\{kind}"),
                    value_name: "JavaHome",
                    source: "windows:registry:ibm",
                });
            }
        }

        for base in [
            "SOFTWARE\\AdoptOpenJDK",
            "SOFTWARE\\Eclipse Adoptium",
            "SOFTWARE\\Eclipse Foundation",
            "SOFTWARE\\Semeru",
            "SOFTWARE\\Wow6432Node\\AdoptOpenJDK",
            "SOFTWARE\\Wow6432Node\\Eclipse Adoptium",
            "SOFTWARE\\Wow6432Node\\Eclipse Foundation",
            "SOFTWARE\\Wow6432Node\\Semeru",
        ] {
            for kind in ["JDK", "JRE"] {
                queries.push(WindowsRegistryQuery {
                    subkey: format!("{base}\\{kind}"),
                    value_name: "Path",
                    source: "windows:registry:adoptium",
                });
            }
        }

        for subkey in [
            "SOFTWARE\\Microsoft\\JDK",
            "SOFTWARE\\Wow6432Node\\Microsoft\\JDK",
        ] {
            queries.push(WindowsRegistryQuery {
                subkey: subkey.to_string(),
                value_name: "Path",
                source: "windows:registry:microsoft",
            });
        }

        for subkey in [
            "SOFTWARE\\Azul Systems\\Zulu",
            "SOFTWARE\\Wow6432Node\\Azul Systems\\Zulu",
        ] {
            queries.push(WindowsRegistryQuery {
                subkey: subkey.to_string(),
                value_name: "InstallationPath",
                source: "windows:registry:zulu",
            });
        }

        for subkey in [
            "SOFTWARE\\BellSoft\\Liberica",
            "SOFTWARE\\Wow6432Node\\BellSoft\\Liberica",
        ] {
            queries.push(WindowsRegistryQuery {
                subkey: subkey.to_string(),
                value_name: "InstallationPath",
                source: "windows:registry:bellsoft",
            });
        }

        queries
    }

    fn collect_tool_manager_candidates(
        candidates: &mut Vec<JavaCandidate>,
        seen: &mut HashSet<String>,
    ) {
        if let Some(home) = Self::user_home_dir() {
            Self::collect_root_and_children(
                &home.join(".gradle").join("jdks"),
                "tool:gradle-jdks",
                candidates,
                seen,
            );
            Self::collect_root_and_children(
                &home.join(".jdks"),
                "tool:intellij-jdks",
                candidates,
                seen,
            );
            Self::collect_root_and_children(
                &home.join(".jabba").join("jdk"),
                "tool:jabba",
                candidates,
                seen,
            );
            if let Some(jabba_home) = env::var_os("JABBA_HOME").filter(|value| !value.is_empty()) {
                Self::collect_root_and_children(
                    &PathBuf::from(jabba_home).join("jdk"),
                    "tool:jabba",
                    candidates,
                    seen,
                );
            }

            let sdkman_candidates = env::var_os("SDKMAN_CANDIDATES_DIR")
                .map(PathBuf::from)
                .or_else(|| {
                    env::var_os("SDKMAN_DIR")
                        .filter(|value| !value.is_empty())
                        .map(PathBuf::from)
                        .map(|dir| dir.join("candidates"))
                })
                .unwrap_or_else(|| home.join(".sdkman").join("candidates"));
            Self::collect_root_and_children(
                &sdkman_candidates.join("java"),
                "tool:sdkman",
                candidates,
                seen,
            );

            let asdf_installs = env::var_os("ASDF_DATA_DIR")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .map(|dir| dir.join("installs"))
                .unwrap_or_else(|| home.join(".asdf").join("installs"));
            Self::collect_root_and_children(
                &asdf_installs.join("java"),
                "tool:asdf",
                candidates,
                seen,
            );

            if let Some(mise_installs) = Self::mise_installs_dir(&home) {
                Self::collect_root_and_children(
                    &mise_installs.join("java"),
                    "tool:mise",
                    candidates,
                    seen,
                );
            }
        }
    }

    fn collect_runtime_bundle_candidates(
        candidates: &mut Vec<JavaCandidate>,
        seen: &mut HashSet<String>,
    ) {
        let mut runtime_roots = Vec::new();

        if cfg!(windows) {
            if let Some(app_data) = env::var_os("APPDATA").filter(|value| !value.is_empty()) {
                runtime_roots.push(PathBuf::from(app_data).join(".minecraft").join("runtime"));
            }
            if let Some(local_app_data) =
                env::var_os("LOCALAPPDATA").filter(|value| !value.is_empty())
            {
                let local_app_data = PathBuf::from(local_app_data);
                runtime_roots.push(
                    local_app_data
                        .join("Packages")
                        .join("Microsoft.4297127D64EC6_8wekyb3d8bbwe")
                        .join("LocalCache")
                        .join("Local")
                        .join("runtime"),
                );
                runtime_roots.push(local_app_data.join("Hytale").join("runtime"));
            }
        } else if cfg!(target_os = "macos") {
            if let Some(home) = Self::user_home_dir() {
                runtime_roots.push(
                    home.join("Library")
                        .join("Application Support")
                        .join("minecraft")
                        .join("runtime"),
                );
                runtime_roots.push(
                    home.join("Library")
                        .join("Application Support")
                        .join("Hytale")
                        .join("runtime"),
                );
            }
        } else if let Some(home) = Self::user_home_dir() {
            runtime_roots.push(home.join(".minecraft").join("runtime"));
            runtime_roots.push(home.join(".hytale").join("runtime"));
        }

        for root in runtime_roots {
            Self::collect_runtime_bin_candidates(&root, "runtime:game-managed", candidates, seen);
        }

        if let Some(runtime_home) =
            env::var_os("HYTALE_RUNTIME_HOME").filter(|value| !value.is_empty())
        {
            let root = PathBuf::from(runtime_home);
            Self::collect_runtime_bin_candidates(&root, "runtime:hytale-env", candidates, seen);
        }
    }

    fn collect_runtime_bin_candidates(
        root: &Path,
        source: &str,
        candidates: &mut Vec<JavaCandidate>,
        seen: &mut HashSet<String>,
    ) {
        if !root.exists() {
            return;
        }

        let mut queue = vec![root.to_path_buf()];
        let mut visited = HashSet::new();

        while let Some(current) = queue.pop() {
            let key = Self::normalize_path_key(&current);
            if !visited.insert(key) {
                continue;
            }

            let Ok(entries) = fs::read_dir(&current) else {
                continue;
            };

            let mut bin_found = false;
            let mut subdirs = Vec::new();
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }

                if Self::path_component_eq(path.file_name(), "bin") {
                    bin_found = true;
                    Self::push_candidate(
                        candidates,
                        seen,
                        path.join(if cfg!(windows) { "java.exe" } else { "java" }),
                        source,
                    );
                    if cfg!(windows) {
                        Self::push_candidate(candidates, seen, path.join("javaw.exe"), source);
                    }
                    continue;
                }

                subdirs.push(path);
            }

            if !bin_found {
                queue.extend(subdirs);
            }
        }
    }

    fn mise_installs_dir(home: &Path) -> Option<PathBuf> {
        if let Some(path) = env::var_os("MISE_DATA_DIR").filter(|value| !value.is_empty()) {
            return Some(PathBuf::from(path).join("installs"));
        }
        if let Some(path) = env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
            return Some(PathBuf::from(path).join("mise").join("installs"));
        }
        if cfg!(windows) {
            if let Some(local_app_data) =
                env::var_os("LOCALAPPDATA").filter(|value| !value.is_empty())
            {
                return Some(PathBuf::from(local_app_data).join("mise").join("installs"));
            }
            return Some(
                home.join("AppData")
                    .join("Local")
                    .join("mise")
                    .join("installs"),
            );
        }

        Some(
            home.join(".local")
                .join("share")
                .join("mise")
                .join("installs"),
        )
    }

    fn user_home_dir() -> Option<PathBuf> {
        env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                env::var_os("USERPROFILE")
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
            })
            .or_else(|| {
                let drive = env::var_os("HOMEDRIVE").filter(|value| !value.is_empty())?;
                let path = env::var_os("HOMEPATH").filter(|value| !value.is_empty())?;
                Some(PathBuf::from(drive).join(path))
            })
    }

    fn collect_root_and_children(
        root: &Path,
        source: &str,
        candidates: &mut Vec<JavaCandidate>,
        seen: &mut HashSet<String>,
    ) {
        Self::push_candidate(candidates, seen, root.to_path_buf(), source);
        Self::collect_subdirectories(root, source, candidates, seen);
    }

    fn collect_subdirectories(
        root: &Path,
        source: &str,
        candidates: &mut Vec<JavaCandidate>,
        seen: &mut HashSet<String>,
    ) {
        let Ok(entries) = fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                Self::push_candidate(candidates, seen, path, source);
            }
        }
    }

    fn collect_filtered_subdirs<F>(
        root: &Path,
        source: &str,
        candidates: &mut Vec<JavaCandidate>,
        seen: &mut HashSet<String>,
        predicate: F,
    ) where
        F: Fn(&str) -> bool,
    {
        let Ok(entries) = fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if predicate(name) {
                Self::push_candidate(candidates, seen, path, source);
            }
        }
    }

    fn push_candidate(
        candidates: &mut Vec<JavaCandidate>,
        seen: &mut HashSet<String>,
        path: PathBuf,
        source: &str,
    ) {
        if path.as_os_str().is_empty() || !path.exists() {
            return;
        }
        let key = Self::normalize_path_key(&path);
        if seen.insert(key) {
            candidates.push(JavaCandidate {
                path,
                source: source.to_string(),
            });
        }
    }

    fn push_unique_path(paths: &mut Vec<PathBuf>, seen: &mut HashSet<String>, path: PathBuf) {
        let key = Self::normalize_path_key(&path);
        if seen.insert(key) {
            paths.push(path);
        }
    }

    fn java_binary_candidates(candidate: &Path) -> Vec<PathBuf> {
        let mut homes = Vec::new();
        let mut seen_homes = HashSet::new();

        if candidate.is_file() {
            if let Some(bin_dir) = candidate.parent()
                && Self::path_component_eq(bin_dir.file_name(), "bin")
                && let Some(home) = bin_dir.parent()
            {
                Self::push_unique_path(&mut homes, &mut seen_homes, home.to_path_buf());
            }

            if Self::is_java_binary_name(candidate.file_name())
                && let Some(parent) = candidate.parent().and_then(Path::parent)
            {
                Self::push_unique_path(&mut homes, &mut seen_homes, parent.to_path_buf());
            }
        } else {
            Self::push_unique_path(&mut homes, &mut seen_homes, candidate.to_path_buf());
        }

        let current_homes = homes.clone();
        for home in current_homes {
            Self::push_unique_path(
                &mut homes,
                &mut seen_homes,
                home.join("Contents").join("Home"),
            );
            Self::push_unique_path(&mut homes, &mut seen_homes, home.join("Home"));
            Self::push_unique_path(&mut homes, &mut seen_homes, home.join("jre"));
        }

        let mut binaries = Vec::new();
        let mut seen_binaries = HashSet::new();
        if Self::is_java_binary_name(candidate.file_name()) {
            Self::push_unique_path(&mut binaries, &mut seen_binaries, candidate.to_path_buf());
        }
        for home in homes {
            Self::push_unique_path(
                &mut binaries,
                &mut seen_binaries,
                Self::java_binary_path(&home),
            );
            if cfg!(windows) {
                Self::push_unique_path(
                    &mut binaries,
                    &mut seen_binaries,
                    home.join("bin").join("javaw.exe"),
                );
            }
        }
        binaries
    }

    fn java_binary_path(java_home: &Path) -> PathBuf {
        if cfg!(windows) {
            java_home.join("bin").join("java.exe")
        } else {
            java_home.join("bin").join("java")
        }
    }

    fn path_component_eq(component: Option<&std::ffi::OsStr>, expected: &str) -> bool {
        component
            .and_then(|value| value.to_str())
            .map(|value| value.eq_ignore_ascii_case(expected))
            .unwrap_or(false)
    }

    fn is_java_binary_name(name: Option<&std::ffi::OsStr>) -> bool {
        name.and_then(|value| value.to_str())
            .map(|value| {
                if cfg!(windows) {
                    value.eq_ignore_ascii_case("java.exe")
                        || value.eq_ignore_ascii_case("javaw.exe")
                } else {
                    value == "java"
                }
            })
            .unwrap_or(false)
    }

    fn normalize_path_key(path: &Path) -> String {
        let value = path.to_string_lossy();
        if cfg!(windows) {
            value.replace('/', "\\").to_lowercase()
        } else {
            value.to_string()
        }
    }

    fn parse_macos_java_home_output(output: &str) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        let mut seen = HashSet::new();

        for line in output.lines() {
            let trimmed = line.trim();
            if let Some(index) = trimmed.find('/') {
                let path = trimmed[index..].trim();
                if !path.is_empty() {
                    Self::push_unique_path(&mut paths, &mut seen, PathBuf::from(path));
                }
            }
        }

        paths
    }

    fn parse_windows_registry_query_output(output: &str, value_name: &str) -> Vec<String> {
        let mut values = Vec::new();
        let mut seen = HashSet::new();

        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let mut parts = trimmed.split_whitespace();
            let Some(name) = parts.next() else {
                continue;
            };
            if !name.eq_ignore_ascii_case(value_name) {
                continue;
            }

            let Some(registry_type) = parts.next() else {
                continue;
            };
            if !registry_type.to_ascii_uppercase().starts_with("REG_") {
                continue;
            }

            let value = parts.collect::<Vec<_>>().join(" ");
            let value = value.trim().trim_matches('"');
            if value.is_empty() {
                continue;
            }

            let key = if cfg!(windows) {
                value.to_lowercase()
            } else {
                value.to_string()
            };
            if seen.insert(key) {
                values.push(value.to_string());
            }
        }

        values
    }

    fn extract_version(output: &str) -> String {
        if let Some(version) = Self::read_property(output, "java.version") {
            return version;
        }

        for line in output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            if let Some(start) = line.find('"') {
                let rest = &line[start + 1..];
                if let Some(end) = rest.find('"') {
                    return rest[..end].to_string();
                }
            }

            for token in line.split(|c: char| c.is_whitespace() || [',', '(', ')'].contains(&c)) {
                let trimmed = token.trim_matches('"');
                if trimmed.is_empty() {
                    continue;
                }
                if trimmed.chars().next().is_some_and(|c| c.is_ascii_digit())
                    && trimmed.chars().any(|c| c == '.')
                {
                    return trimmed.to_string();
                }
            }
        }

        "unknown".to_string()
    }

    fn detect_vendor(output: &str) -> String {
        if let Some(vendor) = Self::read_property(output, "java.vendor") {
            return vendor;
        }

        let lower = output.to_lowercase();
        if Self::contains_any(&lower, &["eclipse adoptium", "temurin"]) {
            "Eclipse Adoptium".to_string()
        } else if Self::contains_any(&lower, &["adoptopenjdk"]) {
            "AdoptOpenJDK".to_string()
        } else if Self::contains_any(&lower, &["azul", "zulu", "zulu prime"]) {
            "Azul".to_string()
        } else if Self::contains_any(&lower, &["bellsoft", "liberica"]) {
            "BellSoft".to_string()
        } else if Self::contains_any(&lower, &["amazon", "corretto"]) {
            "Amazon".to_string()
        } else if Self::contains_any(&lower, &["sap machine", "sapmachine"]) {
            "SAP".to_string()
        } else if Self::contains_any(&lower, &["semeru", "ibm"]) {
            "IBM".to_string()
        } else if Self::contains_any(&lower, &["redhat", "red hat"]) {
            "Red Hat".to_string()
        } else if Self::contains_any(&lower, &["jetbrains runtime", "jbr"]) {
            "JetBrains".to_string()
        } else if Self::contains_any(&lower, &["microsoft"]) {
            "Microsoft".to_string()
        } else if Self::contains_any(&lower, &["graalvm"]) {
            "GraalVM".to_string()
        } else if Self::contains_any(&lower, &["openjdk"]) {
            "OpenJDK".to_string()
        } else if Self::contains_any(&lower, &["oracle", "java(tm)"]) {
            "Oracle".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    fn detect_arch(output: &str) -> String {
        if let Some(os_arch) = Self::read_property(output, "os.arch")
            && let Some(arch) = Self::normalize_arch(&os_arch)
        {
            return arch;
        }

        let lower = output.to_lowercase();
        Self::normalize_arch(&lower).unwrap_or_else(|| "unknown".to_string())
    }

    fn arch_to_is_64_bit(arch: &str) -> Option<bool> {
        let lower = arch.to_lowercase();
        if lower.contains("64") {
            Some(true)
        } else if lower.contains("32") {
            Some(false)
        } else {
            None
        }
    }

    fn host_bitness() -> String {
        if cfg!(target_pointer_width = "64") {
            "64-bit".to_string()
        } else if cfg!(target_pointer_width = "32") {
            "32-bit".to_string()
        } else {
            "unknown".to_string()
        }
    }

    fn infer_distribution(
        vendor: &str,
        output: &str,
        java_home: &Path,
    ) -> (Option<String>, Option<String>) {
        let lower = output.to_lowercase();
        let path_lower = java_home.to_string_lossy().to_lowercase();
        let signal = format!("{lower}\n{path_lower}");

        let distribution = if Self::contains_any(&signal, &["gluon", "gluon graalvm"]) {
            Some("Gluon GraalVM".to_string())
        } else if Self::contains_any(&signal, &["graalvm ee"]) {
            Some("GraalVM EE".to_string())
        } else if Self::contains_any(&signal, &["graalvm ce"]) {
            Some("GraalVM CE".to_string())
        } else if Self::contains_any(&signal, &["graalvm community"]) {
            Some("GraalVM Community".to_string())
        } else if Self::contains_any(&signal, &["graalvm"]) {
            Some("GraalVM".to_string())
        } else if Self::contains_any(&signal, &["temurin", "eclipse adoptium"]) {
            Some("Temurin".to_string())
        } else if Self::contains_any(&signal, &["adoptopenjdk j9", "openj9"]) {
            Some("AdoptOpenJDK J9".to_string())
        } else if Self::contains_any(&signal, &["adoptopenjdk"]) {
            Some("AdoptOpenJDK".to_string())
        } else if Self::contains_any(&signal, &["zulu prime"]) {
            Some("Zulu Prime".to_string())
        } else if Self::contains_any(&signal, &["zulu", "azul"]) {
            Some("Zulu".to_string())
        } else if Self::contains_any(&signal, &["liberica native"]) {
            Some("Liberica Native".to_string())
        } else if Self::contains_any(&signal, &["liberica", "bellsoft"]) {
            Some("Liberica".to_string())
        } else if Self::contains_any(&signal, &["semeru certified"]) {
            Some("Semeru Certified".to_string())
        } else if Self::contains_any(&signal, &["semeru"]) {
            Some("Semeru".to_string())
        } else if Self::contains_any(&signal, &["sap machine", "sapmachine"]) {
            Some("SAP Machine".to_string())
        } else if Self::contains_any(&signal, &["corretto"]) {
            Some("Corretto".to_string())
        } else if Self::contains_any(&signal, &["dragonwell"]) {
            Some("Dragonwell".to_string())
        } else if Self::contains_any(&signal, &["bisheng"]) {
            Some("Bi Sheng".to_string())
        } else if Self::contains_any(&signal, &["kona"]) {
            Some("Kona".to_string())
        } else if Self::contains_any(&signal, &["mandrel"]) {
            Some("Mandrel".to_string())
        } else if Self::contains_any(&signal, &["oracle openjdk"]) {
            Some("Oracle OpenJDK".to_string())
        } else if Self::contains_any(&signal, &["microsoft"]) {
            Some("Microsoft Build of OpenJDK".to_string())
        } else if Self::contains_any(&signal, &["jetbrains", "jbr"]) {
            Some("JetBrains Runtime".to_string())
        } else if Self::contains_any(&signal, &["debian"]) {
            Some("Debian OpenJDK".to_string())
        } else if Self::contains_any(&signal, &["ubuntu"]) {
            Some("Ubuntu OpenJDK".to_string())
        } else if Self::contains_any(&signal, &["openlogic", "open logic"]) {
            Some("OpenLogic".to_string())
        } else if Self::contains_any(&signal, &["trava"]) {
            Some("Trava".to_string())
        } else if (signal.contains("oracle") || signal.contains("java(tm)"))
            && !signal.contains("openjdk")
        {
            Some("Oracle JDK".to_string())
        } else if signal.contains("openjdk") {
            Some("OpenJDK".to_string())
        } else if !vendor.eq("Unknown") {
            Some(vendor.to_string())
        } else {
            None
        };

        let build_scope = if distribution
            .as_deref()
            .is_some_and(|d| d.contains("GraalVM"))
        {
            Some("GraalVM".to_string())
        } else if distribution
            .as_deref()
            .is_some_and(|d| d.contains("Oracle JDK"))
        {
            Some("Oracle".to_string())
        } else if signal.contains("openjdk")
            || distribution.as_deref().is_some_and(|d| {
                d.contains("OpenJDK")
                    || d.contains("Temurin")
                    || d.contains("Zulu")
                    || d.contains("Semeru")
                    || d.contains("Liberica")
                    || d.contains("Corretto")
                    || d.contains("Microsoft Build")
                    || d.contains("Dragonwell")
                    || d.contains("AdoptOpenJDK")
                    || d.contains("SAP Machine")
            })
        {
            Some("OpenJDK".to_string())
        } else {
            None
        };

        (distribution, build_scope)
    }

    fn contains_any(text: &str, needles: &[&str]) -> bool {
        needles.iter().any(|needle| text.contains(needle))
    }

    fn read_property(output: &str, key: &str) -> Option<String> {
        for line in output.lines() {
            let trimmed = line.trim();
            let Some((lhs, rhs)) = trimmed.split_once('=') else {
                continue;
            };
            if lhs.trim() != key {
                continue;
            }
            let value = rhs.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
        None
    }

    fn normalize_arch(value: &str) -> Option<String> {
        let lower = value.to_lowercase();

        if lower.contains("64-bit")
            || lower.contains("x86_64")
            || lower.contains("amd64")
            || lower.contains("aarch64")
            || lower.contains("arm64")
            || lower.contains("riscv64")
        {
            Some("64-bit".to_string())
        } else if lower.contains("32-bit")
            || lower == "x86"
            || lower.contains(" x86 ")
            || lower.contains(" i386")
            || lower.contains(" i686")
        {
            Some("32-bit".to_string())
        } else {
            None
        }
    }

    fn detect_binary_is_64_bit(path: &Path) -> Option<bool> {
        let mut file = fs::File::open(path).ok()?;
        let mut header = [0_u8; 4096];
        let read = file.read(&mut header).ok()?;
        if read < 5 {
            return None;
        }
        let bytes = &header[..read];

        // Fast path for native formats on each platform.
        if let Some(value) = Self::detect_elf_is_64_bit(bytes) {
            return Some(value);
        }
        if let Some(value) = Self::detect_macho_is_64_bit(bytes) {
            return Some(value);
        }
        Self::detect_pe_is_64_bit(&mut file, bytes)
    }

    fn detect_elf_is_64_bit(bytes: &[u8]) -> Option<bool> {
        if bytes.len() < 5 || &bytes[0..4] != b"\x7FELF" {
            return None;
        }
        match bytes[4] {
            1 => Some(false),
            2 => Some(true),
            _ => None,
        }
    }

    fn detect_macho_is_64_bit(bytes: &[u8]) -> Option<bool> {
        if bytes.len() < 4 {
            return None;
        }
        let be = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        match be {
            0xFEEDFACF | 0xCFFAEDFE => Some(true),
            0xFEEDFACE | 0xCEFAEDFE => Some(false),
            _ => None,
        }
    }

    fn detect_pe_is_64_bit(file: &mut fs::File, header: &[u8]) -> Option<bool> {
        if header.len() < 0x40 || &header[0..2] != b"MZ" {
            return None;
        }
        let e_lfanew =
            u32::from_le_bytes([header[0x3c], header[0x3d], header[0x3e], header[0x3f]]) as u64;
        let mut sig = [0_u8; 4];
        file.seek(SeekFrom::Start(e_lfanew)).ok()?;
        file.read_exact(&mut sig).ok()?;
        if &sig != b"PE\0\0" {
            return None;
        }
        let mut machine_bytes = [0_u8; 2];
        file.read_exact(&mut machine_bytes).ok()?;
        let machine = u16::from_le_bytes(machine_bytes);
        match machine {
            0x8664 | 0xAA64 | 0x0200 => Some(true),
            0x014c | 0x01c0 | 0x01c4 => Some(false),
            _ => None,
        }
    }
}

pub fn version_matches_major(version: &str, major: u8) -> bool {
    let expected = major.to_string();
    version == expected
        || version.starts_with(&format!("{expected}."))
        || (major == 8 && version.starts_with("1.8."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_discovery(
        source: &str,
        version: &str,
        is_jdk: bool,
        path: &str,
        java_home: &str,
    ) -> JavaDiscovery {
        JavaDiscovery {
            installation: JavaInstallation {
                path: PathBuf::from(path),
                java_home: PathBuf::from(java_home),
                version: version.to_string(),
                vendor: "Test".to_string(),
                distribution: Some("OpenJDK".to_string()),
                build_scope: Some("OpenJDK".to_string()),
                arch: "64-bit".to_string(),
                is_64_bit: Some(true),
                is_jdk,
                jvm_library_path: None,
                loader_diagnostics: None,
            },
            source: source.to_string(),
            in_use: false,
            active_processes: Vec::new(),
        }
    }

    #[test]
    fn parse_java_output_openjdk() {
        let output = r#"openjdk version "17.0.1" 2021-10-19
OpenJDK Runtime Environment (build 17.0.1+12-39)
OpenJDK 64-Bit Server VM (build 17.0.1+12-39, mixed mode, sharing)"#;

        let install = JavaDoctor::parse_java_output(
            &PathBuf::from("/tmp/java"),
            output,
            false,
            false,
            Duration::from_secs(1),
        );
        assert_eq!(install.version, "17.0.1");
        assert_eq!(install.vendor, "OpenJDK");
        assert_eq!(install.arch, "64-bit");
    }

    #[test]
    fn parse_java_output_oracle() {
        let output = r#"java version "1.8.0_202"
Java(TM) SE Runtime Environment (build 1.8.0_202-b08)
Java HotSpot(TM) 64-Bit Server VM (build 25.202-b08, mixed mode)"#;

        let install = JavaDoctor::parse_java_output(
            &PathBuf::from("/tmp/java"),
            output,
            false,
            false,
            Duration::from_secs(1),
        );
        assert_eq!(install.version, "1.8.0_202");
        assert_eq!(install.vendor, "Oracle");
        assert_eq!(install.arch, "64-bit");
    }

    #[test]
    fn parse_macos_java_home_output() {
        let output = r#"Matching Java Virtual Machines (2):
  21.0.2, x86_64:    "OpenJDK 21.0.2"    /Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home
  17.0.10, x86_64:   "OpenJDK 17.0.10"   /Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home"#;

        let parsed = JavaDoctor::parse_macos_java_home_output(output);
        assert_eq!(parsed.len(), 2);
        assert!(
            parsed
                .iter()
                .any(|path| path.ends_with("temurin-21.jdk/Contents/Home"))
        );
        assert!(
            parsed
                .iter()
                .any(|path| path.ends_with("temurin-17.jdk/Contents/Home"))
        );
    }

    #[test]
    fn parse_windows_registry_query_output() {
        let output = r#"
HKEY_LOCAL_MACHINE\SOFTWARE\JavaSoft\JDK\17
    JavaHome    REG_SZ    C:\Program Files\Java\jdk-17

HKEY_LOCAL_MACHINE\SOFTWARE\Eclipse Adoptium\JDK\21.0.2+13\hotspot\MSI
    Path    REG_SZ    C:\Program Files\Eclipse Adoptium\jdk-21.0.2.13-hotspot
"#;

        let java_soft = JavaDoctor::parse_windows_registry_query_output(output, "JavaHome");
        assert_eq!(java_soft, vec!["C:\\Program Files\\Java\\jdk-17"]);

        let adoptium = JavaDoctor::parse_windows_registry_query_output(output, "Path");
        assert_eq!(
            adoptium,
            vec!["C:\\Program Files\\Eclipse Adoptium\\jdk-21.0.2.13-hotspot"]
        );
    }

    #[test]
    fn detect_elf_bitness_from_header() {
        let mut elf64 = [0_u8; 8];
        elf64[0..4].copy_from_slice(b"\x7FELF");
        elf64[4] = 2;
        assert_eq!(JavaDoctor::detect_elf_is_64_bit(&elf64), Some(true));

        let mut elf32 = [0_u8; 8];
        elf32[0..4].copy_from_slice(b"\x7FELF");
        elf32[4] = 1;
        assert_eq!(JavaDoctor::detect_elf_is_64_bit(&elf32), Some(false));
    }

    #[test]
    fn detect_macho_bitness_from_header() {
        let macho64 = 0xFEEDFACF_u32.to_be_bytes();
        assert_eq!(JavaDoctor::detect_macho_is_64_bit(&macho64), Some(true));

        let macho32 = 0xFEEDFACE_u32.to_be_bytes();
        assert_eq!(JavaDoctor::detect_macho_is_64_bit(&macho32), Some(false));
    }

    #[test]
    fn detect_pe_bitness_from_file_header() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("java.exe");

        let mut bytes = vec![0_u8; 512];
        bytes[0..2].copy_from_slice(b"MZ");
        let pe_offset = 0x80_u32;
        bytes[0x3c..0x40].copy_from_slice(&pe_offset.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        fs::write(&path, bytes).expect("write");

        assert_eq!(JavaDoctor::detect_binary_is_64_bit(&path), Some(true));
    }

    #[test]
    fn parse_java_output_uses_binary_bitness_fallback_when_arch_unknown() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin_dir = dir.path().join("jdk").join("bin");
        fs::create_dir_all(&bin_dir).expect("mkdirs");
        let java_path = bin_dir.join("java.exe");

        let mut bytes = vec![0_u8; 512];
        bytes[0..2].copy_from_slice(b"MZ");
        let pe_offset = 0x80_u32;
        bytes[0x3c..0x40].copy_from_slice(&pe_offset.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        fs::write(&java_path, bytes).expect("write");

        let output = r#"java version "21.0.2"
Runtime random text without os.arch property"#;
        let install =
            JavaDoctor::parse_java_output(&java_path, output, false, false, Duration::from_secs(1));

        assert_eq!(install.version, "21.0.2");
        assert_eq!(install.arch, "64-bit");
        assert_eq!(install.is_64_bit, Some(true));
    }

    #[test]
    fn source_priority_windows_registry_types_align() {
        assert_eq!(
            JavaDoctor::source_priority("windows:registry:javasoft"),
            JavaDoctor::source_priority("windows:registry:adoptium")
        );
        assert_eq!(JavaDoctor::source_priority("path:java"), 6);
    }

    #[test]
    fn parse_windows_process_tsv_output() {
        let output =
            "1234\tC:\\Program Files\\Java\\jdk-21\\bin\\javaw.exe -jar launcher.jar\nbad\trow\n";
        let parsed = JavaDoctor::parse_windows_process_tsv_output(output);
        assert_eq!(
            parsed,
            vec![(
                1234,
                "C:\\Program Files\\Java\\jdk-21\\bin\\javaw.exe -jar launcher.jar".to_string()
            )]
        );
    }

    #[test]
    fn parse_windows_wmic_value_output() {
        let output = r#"
CommandLine=C:\Program Files\Java\jdk-17\bin\java.exe -version
ProcessId=4567

CommandLine=
ProcessId=9999

CommandLine=C:\Program Files\Eclipse Adoptium\jdk-21\bin\javaw.exe -jar game.jar
ProcessId=8123
"#;
        let parsed = JavaDoctor::parse_windows_wmic_value_output(output);
        assert_eq!(
            parsed,
            vec![
                (
                    4567,
                    "C:\\Program Files\\Java\\jdk-17\\bin\\java.exe -version".to_string()
                ),
                (
                    8123,
                    "C:\\Program Files\\Eclipse Adoptium\\jdk-21\\bin\\javaw.exe -jar game.jar"
                        .to_string()
                ),
            ]
        );
    }

    #[test]
    fn java_binary_candidates_expand_macos_bundle() {
        let candidate = PathBuf::from("/Library/Java/JavaVirtualMachines/temurin-21.jdk");
        let binaries = JavaDoctor::java_binary_candidates(&candidate);
        assert!(
            binaries
                .iter()
                .any(|path| path.ends_with("Contents/Home/bin/java"))
        );
    }

    #[test]
    fn java_version_major_matching() {
        assert!(version_matches_major("17", 17));
        assert!(version_matches_major("17.0.11", 17));
        assert!(version_matches_major("1.8.0_402", 8));
        assert!(!version_matches_major("21.0.2", 17));
    }

    #[test]
    fn detect_jvm_library_known_layout() {
        let dir = tempfile::tempdir().expect("tempdir");
        let java_home = dir.path().join("jdk");
        let jvm_path = if cfg!(windows) {
            java_home.join("bin").join("server").join("jvm.dll")
        } else if cfg!(target_os = "macos") {
            java_home.join("lib").join("server").join("libjvm.dylib")
        } else {
            java_home.join("lib").join("server").join("libjvm.so")
        };

        fs::create_dir_all(jvm_path.parent().expect("parent")).expect("mkdirs");
        fs::write(&jvm_path, b"dummy").expect("write");

        let detected = JavaDoctor::detect_jvm_library_path(&java_home).expect("detected");
        assert_eq!(
            fs::canonicalize(detected).expect("canonical"),
            fs::canonicalize(jvm_path).expect("canonical")
        );
    }

    #[test]
    fn infer_distribution_temurin() {
        let java_home = PathBuf::from("/usr/lib/jvm/temurin-21");
        let output = "openjdk version \"21.0.2\"\\nEclipse Adoptium Runtime";
        let (distribution, build_scope) =
            JavaDoctor::infer_distribution("Eclipse Adoptium", output, &java_home);
        assert_eq!(distribution.as_deref(), Some("Temurin"));
        assert_eq!(build_scope.as_deref(), Some("OpenJDK"));
    }

    #[test]
    fn infer_distribution_graalvm() {
        let java_home = PathBuf::from("/opt/graalvm-ce-java17");
        let output = "GraalVM CE 22.3.1";
        let (distribution, build_scope) =
            JavaDoctor::infer_distribution("Oracle", output, &java_home);
        assert_eq!(distribution.as_deref(), Some("GraalVM CE"));
        assert_eq!(build_scope.as_deref(), Some("GraalVM"));
    }

    #[test]
    fn infer_distribution_openjdk_with_oracle_mentions() {
        let java_home = PathBuf::from("/usr/lib/jvm/java-21-openjdk");
        let output =
            "openjdk version \"21.0.10\"\\nOpenJDK Runtime Environment\\nhttps://bugs.openjdk.org";
        let (distribution, build_scope) =
            JavaDoctor::infer_distribution("Arch Linux", output, &java_home);
        assert_eq!(distribution.as_deref(), Some("OpenJDK"));
        assert_eq!(build_scope.as_deref(), Some("OpenJDK"));
    }

    #[test]
    fn select_detected_runtime_prefers_path_java_source() {
        let discoveries = vec![
            fake_discovery(
                "env:JAVA_HOME",
                "22.0.1",
                true,
                "/tmp/env-java",
                "/tmp/env-home",
            ),
            fake_discovery(
                "path:java",
                "21.0.10",
                true,
                "/tmp/path-java",
                "/tmp/path-home",
            ),
        ];

        let selected = JavaDoctor::select_detected_runtime(&discoveries).expect("selected");
        assert_eq!(selected.source, "path:java");
        assert_eq!(selected.path, PathBuf::from("/tmp/path-java"));
    }

    #[test]
    fn select_detected_runtime_prefers_higher_version_with_same_source() {
        let discoveries = vec![
            fake_discovery("path:java", "17.0.12", true, "/tmp/java17", "/tmp/home17"),
            fake_discovery("path:java", "21.0.2", true, "/tmp/java21", "/tmp/home21"),
        ];

        let selected = JavaDoctor::select_detected_runtime(&discoveries).expect("selected");
        assert_eq!(selected.version, "21.0.2");
        assert_eq!(selected.path, PathBuf::from("/tmp/java21"));
    }
}
