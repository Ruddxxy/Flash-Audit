mod scanner;
mod utils;

use clap::{Parser, ValueEnum};
use rayon::prelude::*;
use ignore::WalkBuilder;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use std::process::Command;
use scanner::Scanner;
use utils::file_loader::FileLoader;
use utils::config::Config;
use utils::sarif::SarifReport;
use tracing::{info, debug, warn, Level};

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Json,
    Sarif,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to scan
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Path to rules.yaml config file
    #[arg(long)]
    rules: Option<PathBuf>,

    /// Output format (json or sarif for GitHub Advanced Security)
    #[arg(long, short, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,

    /// Enable Shannon Entropy scanning for high-randomness strings
    #[arg(long, default_value_t = false)]
    entropy: bool,

    /// Entropy threshold (higher = stricter, less false positives)
    #[arg(long, default_value_t = 4.5)]
    entropy_threshold: f32,

    /// Verbose output (show skipped files, errors)
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Only scan files changed since specified git ref (e.g., HEAD~1, main, origin/main)
    #[arg(long, value_name = "REF")]
    git_diff: Option<String>,

    /// Only scan staged files (for pre-commit hooks)
    #[arg(long, default_value_t = false)]
    staged: bool,
}

/// Get list of files changed since a git ref
fn get_git_diff_files(base_ref: &str, repo_path: &PathBuf) -> Result<Vec<PathBuf>, String> {
    // Validate git ref to prevent command injection
    if !base_ref.chars().all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '/' | '.' | '~' | '^')) {
        return Err(format!("Invalid git ref: {}", base_ref));
    }

    let output = Command::new("git")
        .args(["diff", "--name-only", "--diff-filter=ACMR", "--", base_ref])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to run git: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git diff failed: {}", stderr.trim()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let files: Vec<PathBuf> = stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| repo_path.join(line))
        .filter(|path| path.exists() && path.is_file())
        .collect();

    Ok(files)
}

/// Get list of staged files
fn get_staged_files(repo_path: &PathBuf) -> Result<Vec<PathBuf>, String> {
    let output = Command::new("git")
        .args(["diff", "--name-only", "--cached", "--diff-filter=ACMR"])
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("Failed to run git: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git diff --cached failed: {}", stderr.trim()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let files: Vec<PathBuf> = stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| repo_path.join(line))
        .filter(|path| path.exists() && path.is_file())
        .collect();

    Ok(files)
}

fn main() {
    let args = Args::parse();
    let start = Instant::now();

    // Initialize logging
    let log_level = if args.verbose { Level::DEBUG } else { Level::WARN };
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    // Load configuration
    let config = if let Some(rules_path) = &args.rules {
        Config::load(rules_path).unwrap_or_else(|e| {
            eprintln!("Failed to load rules from {:?}: {}", rules_path, e);
            std::process::exit(1);
        })
    } else {
        // Fallback to embedded default rules if no file provided
        Config::default_rules()
    };

    let scanner = Scanner::new(config.rules);
    let (rule_count, keyword_count) = scanner.stats();
    info!("Loaded {} rules with {} keywords", rule_count, keyword_count);

    // File Discovery Phase
    let files: Vec<PathBuf> = if args.staged {
        // Scan only staged files (pre-commit hook mode)
        info!("Scanning staged files only");
        match get_staged_files(&args.path) {
            Ok(f) => {
                if f.is_empty() {
                    eprintln!("No staged files to scan");
                    println!("[]");
                    return;
                }
                info!("Found {} staged files", f.len());
                f
            }
            Err(e) => {
                eprintln!("Error getting staged files: {}", e);
                std::process::exit(2);
            }
        }
    } else if let Some(ref base_ref) = args.git_diff {
        // Scan only files changed since base ref (CI mode)
        info!("Scanning files changed since {}", base_ref);
        match get_git_diff_files(base_ref, &args.path) {
            Ok(f) => {
                if f.is_empty() {
                    eprintln!("No files changed since {}", base_ref);
                    println!("[]");
                    return;
                }
                info!("Found {} changed files", f.len());
                f
            }
            Err(e) => {
                eprintln!("Error getting git diff: {}", e);
                std::process::exit(2);
            }
        }
    } else {
        // Full scan: Use `ignore` crate for .gitignore support
        let mut files = Vec::new();
        let walker = WalkBuilder::new(&args.path)
            .standard_filters(true)
            .hidden(false) // Allow scanning .env if not ignored by git
            .build();

        for result in walker {
            match result {
                Ok(entry) => {
                    if entry.file_type().map_or(false, |ft| ft.is_file()) {
                        if !entry.path().components().any(|c| c.as_os_str() == ".git") {
                            files.push(entry.path().to_owned());
                        }
                    }
                }
                Err(err) => warn!("Error walking directory: {}", err),
            }
        }

        if files.is_empty() {
            eprintln!("No files found to scan in {:?}", args.path);
            println!("[]");
            return;
        }
        files
    };

    // Parallel Processing Phase
    let results: Mutex<Vec<scanner::Vulnerability>> = Mutex::new(Vec::new());
    let scanned_count = AtomicUsize::new(0);
    let error_count = AtomicUsize::new(0);

    files.par_iter().for_each(|path| {
        match FileLoader::load(path) {
            Ok(content) => {
                scanned_count.fetch_add(1, Ordering::Relaxed);
                debug!("Scanning: {}", path.display());

                let mut vulns = scanner.scan(&content, path.to_string_lossy().as_ref());

                if args.entropy {
                    let entropy_vulns = scanner.scan_entropy(&content, path.to_string_lossy().as_ref(), args.entropy_threshold);
                    vulns.extend(entropy_vulns);
                }

                if !vulns.is_empty() {
                    if let Ok(mut lock) = results.lock() {
                        lock.extend(vulns);
                    }
                }
            },
            Err(e) => {
                error_count.fetch_add(1, Ordering::Relaxed);
                debug!("Skipped {}: {}", path.display(), e);
            }
        }
    });

    let duration = start.elapsed();

    // Output Phase
    let results = results.into_inner().unwrap_or_else(|e| e.into_inner());
    let scanned = scanned_count.load(Ordering::Relaxed);
    let errors = error_count.load(Ordering::Relaxed);

    // Print summary to stderr (doesn't interfere with JSON/SARIF output)
    eprintln!(
        "Scanned {} files in {:.2}s. {} errors. {} secrets found.",
        scanned,
        duration.as_secs_f64(),
        errors,
        results.len()
    );

    // Output in requested format
    let output_result = match args.format {
        OutputFormat::Json => serde_json::to_string_pretty(&results),
        OutputFormat::Sarif => {
            let sarif = SarifReport::from_vulnerabilities(&results);
            sarif.to_json()
        }
    };

    match output_result {
        Ok(output) => {
            println!("{}", output);
            if !results.is_empty() {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Failed to serialize results: {}", e);
            std::process::exit(2);
        }
    }
}
