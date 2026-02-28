use clap::{Args, Parser, Subcommand};
use rjd::{JavaDoctor, JavaDoctorOptions, JavaDoctorRequirements};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "rjd")]
#[command(about = "Rust Java Doctor - Java runtime discovery and diagnostics")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// List discovered Java installations
    List {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        csv: bool,
        /// Add extra search root(s) for discovery
        #[arg(long = "search-root")]
        search_roots: Vec<PathBuf>,
    },
    /// Run full Java diagnostics
    Doctor {
        #[arg(long)]
        json: bool,
        /// Always emit JSON payload and include pass/fail checks
        #[arg(long)]
        strict_json: bool,
        /// Correlate discovered runtimes with running Java processes
        #[arg(long)]
        active: bool,
        /// Run JVM loader dependency checks (`ldd`, `otool`, or `dumpbin`)
        #[arg(long)]
        loader_check: bool,
        /// Suppress plain output and rely on exit code only
        #[arg(long)]
        quiet: bool,
        /// Require at least one Java installation with this major version
        #[arg(long)]
        require_major: Option<u8>,
        /// Require a JDK installation
        #[arg(long)]
        require_jdk: bool,
        /// Require a JVM shared library path to be detected
        #[arg(long)]
        require_jvm_library: bool,
        /// Add extra search root(s) for discovery
        #[arg(long = "search-root")]
        search_roots: Vec<PathBuf>,
    },
    /// JavaInfo-compatible command mode for integration scripts
    Compat(CompatCommand),
}

#[derive(Debug, Args)]
struct CompatCommand {
    /// Tests if Java is installed (exit 0/2)
    #[arg(long = "javainstalled", short = 'i')]
    javainstalled: bool,
    /// Outputs Java home directory
    #[arg(long = "javahome", short = 'H')]
    javahome: bool,
    /// Outputs JVM shared library path
    #[arg(long = "javadll", short = 'd')]
    javadll: bool,
    /// Outputs Java version
    #[arg(long = "javaversion", short = 'V')]
    javaversion: bool,
    /// Tests if Java runtime is 64-bit (exit 1 if true, 0 if false, 2 if not installed)
    #[arg(long = "javais64bit", short = 'b')]
    javais64bit: bool,
    /// Tests minimum Java version (exit 1 if >=, 0 if <, 2 if no Java, 87 invalid version)
    #[arg(long = "javaminversion", short = 'm')]
    javaminversion: Option<String>,
    /// Suppress output and rely on exit code only
    #[arg(long, short = 'q')]
    quiet: bool,
}

fn main() {
    let code = run();
    std::process::exit(code);
}

fn run() -> i32 {
    let cli = Cli::parse();

    match cli.command {
        Commands::List {
            json,
            csv,
            search_roots,
        } => {
            let report = JavaDoctor::doctor_report_with_options(JavaDoctorOptions {
                extra_search_roots: search_roots,
                ..JavaDoctorOptions::default()
            });

            if json {
                let values: Vec<_> = report
                    .installations
                    .into_iter()
                    .map(|entry| entry.installation)
                    .collect();
                print_json(&values);
            } else if csv {
                println!(
                    "vendor,distribution,build_scope,version,arch,is_64_bit,is_jdk,path,java_home,jvm_library_path,loader_tool,loader_status,loader_exit_code,source,in_use"
                );
                for entry in report.installations {
                    let i = entry.installation;
                    println!(
                        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                        csv_field(&i.vendor),
                        csv_field(i.distribution.as_deref().unwrap_or("")),
                        csv_field(i.build_scope.as_deref().unwrap_or("")),
                        csv_field(&i.version),
                        csv_field(&i.arch),
                        csv_field(
                            &i.is_64_bit
                                .map(|value| value.to_string())
                                .unwrap_or_else(String::new)
                        ),
                        csv_field(&i.is_jdk.to_string()),
                        csv_field(&i.path.display().to_string()),
                        csv_field(&i.java_home.display().to_string()),
                        csv_field(
                            &i.jvm_library_path
                                .map(|value| value.display().to_string())
                                .unwrap_or_else(String::new)
                        ),
                        csv_field(
                            &i.loader_diagnostics
                                .as_ref()
                                .map(|value| value.tool.clone())
                                .unwrap_or_default()
                        ),
                        csv_field(
                            &i.loader_diagnostics
                                .as_ref()
                                .map(|value| value.status.clone())
                                .unwrap_or_default()
                        ),
                        csv_field(
                            &i.loader_diagnostics
                                .as_ref()
                                .and_then(|value| value.exit_code)
                                .map(|value| value.to_string())
                                .unwrap_or_default()
                        ),
                        csv_field(&entry.source),
                        csv_field(&entry.in_use.to_string()),
                    );
                }
            } else {
                println!("Discovered Java installations:");
                for entry in report.installations {
                    let i = entry.installation;
                    let jvm = i
                        .jvm_library_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "n/a".to_string());
                    println!(
                        "- {} ({}, {}, dist={:?}, scope={:?}, jdk={}) at {} [source={}] jvm_lib={}",
                        i.version,
                        i.vendor,
                        i.arch,
                        i.distribution,
                        i.build_scope,
                        i.is_jdk,
                        i.path.display(),
                        entry.source,
                        jvm
                    );
                }
            }
            0
        }
        Commands::Doctor {
            json,
            strict_json,
            active,
            loader_check,
            quiet,
            require_major,
            require_jdk,
            require_jvm_library,
            search_roots,
        } => {
            let envelope = JavaDoctor::run_doctor(
                JavaDoctorOptions {
                    include_active_processes: active,
                    include_loader_diagnostics: loader_check,
                    extra_search_roots: search_roots,
                    ..JavaDoctorOptions::default()
                },
                JavaDoctorRequirements {
                    require_major,
                    require_jdk,
                    require_jvm_library,
                },
            );

            if json || strict_json {
                print_json(&envelope);
            } else if !quiet {
                let report = &envelope.report;
                let checks = &envelope.checks;
                println!("Java Discovery Report:");
                println!("System: {} / {}", report.os, report.arch);
                if let Some(hostname) = &report.hostname {
                    println!("Host: {}", hostname);
                }
                println!(
                    "Environment Vars: JAVA_HOME={:?} JDK_HOME={:?} JRE_HOME={:?} path(java={}; javac={})",
                    report.environment.java_home_env,
                    report.environment.jdk_home_env,
                    report.environment.jre_home_env,
                    report.environment.path_has_java,
                    report.environment.path_has_javac
                );
                if let Some(runtime) = &report.detected_runtime {
                    println!(
                        "Detected Runtime: version={} vendor={} source={} java_home={}",
                        runtime.version,
                        runtime.vendor,
                        runtime.source,
                        runtime.java_home.display()
                    );
                }
                println!(
                    "Summary: candidates={} binaries_tested={} installations={} active_scan={}",
                    report.candidate_count,
                    report.binary_count,
                    report.installation_count,
                    report.active_scan_enabled
                );
                println!("Checks:");
                println!(
                    "- require_major={:?} require_jdk={} require_jvm_library={} passed={}",
                    checks.require_major,
                    checks.require_jdk,
                    checks.require_jvm_library,
                    checks.passed
                );
                for failure in &checks.failures {
                    println!("  - {}", failure);
                }

                println!("Sources:");
                for source in &report.sources {
                    println!(
                        "- {}: candidates={} binaries_tested={} installations={}",
                        source.source,
                        source.candidates,
                        source.binaries_tested,
                        source.installations
                    );
                }

                println!("Installations:");
                for entry in &report.installations {
                    let i = &entry.installation;
                    let jvm = i
                        .jvm_library_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "n/a".to_string());
                    println!(
                        "- {} ({}, {}, jdk={}) at {} [source={}] active_processes={} jvm_lib={}",
                        i.version,
                        i.vendor,
                        i.arch,
                        i.is_jdk,
                        i.path.display(),
                        entry.source,
                        entry.active_processes.len(),
                        jvm
                    );
                    if let Some(loader) = &i.loader_diagnostics {
                        println!(
                            "    loader_check: tool={} status={} exit_code={:?}",
                            loader.tool, loader.status, loader.exit_code
                        );
                    }
                    for process in &entry.active_processes {
                        println!("    pid={} {}", process.pid, process.command);
                    }
                }
            }

            if envelope.checks.passed { 0 } else { 3 }
        }
        Commands::Compat(command) => run_compat(command),
    }
}

fn run_compat(command: CompatCommand) -> i32 {
    let selected = [
        command.javainstalled,
        command.javahome,
        command.javadll,
        command.javaversion,
        command.javais64bit,
        command.javaminversion.is_some(),
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();

    if selected != 1 {
        if !command.quiet {
            eprintln!(
                "compat mode requires exactly one operation flag (--javainstalled, --javahome, --javadll, --javaversion, --javais64bit, --javaminversion)"
            );
        }
        return 87;
    }

    let report = JavaDoctor::doctor_report();
    let best = select_best_installation(&report);

    if command.javainstalled {
        if best.is_some() {
            if !command.quiet {
                println!("Java is installed");
            }
            return 0;
        }
        if !command.quiet {
            println!("Java is not installed");
        }
        return 2;
    }

    let Some(install) = best else {
        if !command.quiet {
            println!("Java is not installed");
        }
        return 2;
    };

    if command.javahome {
        if !command.quiet {
            println!("{}", install.java_home.display());
        }
        return 0;
    }

    if command.javadll {
        if let Some(jvm) = &install.jvm_library_path {
            if !command.quiet {
                println!("{}", jvm.display());
            }
            return 0;
        }
        if !command.quiet {
            println!("JVM shared library path not found");
        }
        return 2;
    }

    if command.javaversion {
        if !command.quiet {
            println!("{}", install.version);
        }
        return 0;
    }

    if command.javais64bit {
        return if install.is_64_bit.unwrap_or(false) {
            1
        } else {
            0
        };
    }

    if let Some(required) = command.javaminversion {
        let Some(required_version) = parse_required_version(&required) else {
            if !command.quiet {
                eprintln!("invalid version: {required}");
            }
            return 87;
        };
        let installed_version = parse_installed_version(&install.version);
        return if installed_version >= required_version {
            1
        } else {
            0
        };
    }

    87
}

fn select_best_installation(report: &rjd::JavaDoctorReport) -> Option<&rjd::JavaInstallation> {
    if let Some(runtime) = &report.detected_runtime
        && let Some(entry) = report
            .installations
            .iter()
            .find(|entry| entry.installation.path == runtime.path)
    {
        return Some(&entry.installation);
    }

    report
        .installations
        .iter()
        .map(|entry| &entry.installation)
        .max_by_key(|install| {
            (
                parse_installed_version(&install.version),
                install.is_jdk,
                install.jvm_library_path.is_some(),
            )
        })
}

fn parse_required_version(value: &str) -> Option<[u16; 4]> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }

    let mut result = [0_u16; 4];
    for (idx, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return None;
        }
        result[idx] = part.parse::<u16>().ok()?;
    }
    Some(result)
}

fn parse_installed_version(value: &str) -> [u16; 4] {
    let mut numbers = value
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

fn print_json<T: Serialize>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(text) => println!("{}", text),
        Err(err) => {
            eprintln!("failed to serialize JSON output: {}", err);
            std::process::exit(1);
        }
    }
}

fn csv_field(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    format!("\"{}\"", escaped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn select_best_installation_prefers_detected_runtime_path() {
        let report = rjd::JavaDoctorReport {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            host_bitness: "64-bit".to_string(),
            hostname: None,
            environment: rjd::JavaDoctorEnvironment {
                java_home_env: None,
                jdk_home_env: None,
                jre_home_env: None,
                path_has_java: true,
                path_has_javac: true,
            },
            detected_runtime: Some(rjd::JavaDoctorDetectedRuntime {
                path: PathBuf::from("/tmp/path-java"),
                java_home: PathBuf::from("/tmp/path-home"),
                version: "17.0.12".to_string(),
                vendor: "OpenJDK".to_string(),
                source: "path:java".to_string(),
                is_jdk: true,
                is_64_bit: Some(true),
                jvm_library_path: None,
            }),
            active_scan_enabled: false,
            candidate_count: 2,
            binary_count: 2,
            installation_count: 2,
            installations: vec![
                rjd::JavaDiscovery {
                    installation: rjd::JavaInstallation {
                        path: PathBuf::from("/tmp/path-java"),
                        java_home: PathBuf::from("/tmp/path-home"),
                        version: "17.0.12".to_string(),
                        vendor: "OpenJDK".to_string(),
                        distribution: Some("OpenJDK".to_string()),
                        build_scope: Some("OpenJDK".to_string()),
                        arch: "64-bit".to_string(),
                        is_64_bit: Some(true),
                        is_jdk: true,
                        jvm_library_path: None,
                        loader_diagnostics: None,
                    },
                    source: "path:java".to_string(),
                    in_use: false,
                    active_processes: Vec::new(),
                },
                rjd::JavaDiscovery {
                    installation: rjd::JavaInstallation {
                        path: PathBuf::from("/tmp/newest"),
                        java_home: PathBuf::from("/tmp/newest-home"),
                        version: "21.0.2".to_string(),
                        vendor: "OpenJDK".to_string(),
                        distribution: Some("OpenJDK".to_string()),
                        build_scope: Some("OpenJDK".to_string()),
                        arch: "64-bit".to_string(),
                        is_64_bit: Some(true),
                        is_jdk: true,
                        jvm_library_path: None,
                        loader_diagnostics: None,
                    },
                    source: "windows:registry".to_string(),
                    in_use: false,
                    active_processes: Vec::new(),
                },
            ],
            sources: Vec::new(),
        };

        let selected = select_best_installation(&report).expect("selected");
        assert_eq!(selected.path, PathBuf::from("/tmp/path-java"));
    }
}
