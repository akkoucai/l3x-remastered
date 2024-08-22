mod error;
mod gpt_validator;
mod report_generator;
mod utils;
mod vulnerability_checks;

use crate::error::MyError;
use crate::vulnerability_checks::VulnerabilityCheck;
use chrono::Local;
use clap::{App, Arg};
use futures::stream::{self, StreamExt};
use gpt_validator::OpenAICreds;
use indicatif::{ProgressBar, ProgressStyle};
use leaky_bucket::RateLimiter;
use log::{info, warn};
use regex::Regex;
use report_generator::{
    FinalReport, SafePatternDetail, SecurityAnalysisSummary, VulnerabilityResult,
};
use std::path::Path;
use std::sync::Arc;
use std::{
    collections::HashMap,
    fs::{self, create_dir_all},
    time::Duration,
};
use walkdir::WalkDir;

#[tokio::main]
async fn main() -> Result<(), MyError> {
    env_logger::init();

    let matches = App::new("AI-driven Smart Contract Static Analyzer")
        .version("0.3")
        .author("YevhSec, akkoucai")
        .about("L3X-remastered detects vulnerabilities in Smart Contracts based on patterns and AI code analysis. Currently supports Solana based on Rust and Ethereum based on Solidity.")
        .arg(Arg::with_name("folder_path")
             .help("The path to the folder to scan")
             .required(true)
             .index(1))
        .arg(Arg::with_name("all_severities")
             .long("all-severities")
             .help("Validate findings of all severities, not just critical and high"))
        .arg(Arg::with_name("model")
             .long("model")
             .value_name("MODEL")
             .help("OpenAI model GPT-3.5 or GPT-4 to use for vulnerability validation (default is chatgpt-4o-latest)")
             .takes_value(true))
        .arg(Arg::with_name("no_validation")
             .long("no-validation")
             .help("Skip vulnerability validation"))
        .get_matches();

    let folder_path = matches.value_of("folder_path").unwrap();
    info!("Scanning folder: {}", folder_path);
    let openai_creds = gpt_validator::OpenAICreds {
        api_key: std::env::var("OPENAI_API_KEY").expect("OPENAI_API_KEY must be set"),
    };
    let validate_all_severities = matches.is_present("all_severities");
    let model = matches.value_of("model").unwrap_or("chatgpt-4o-latest");
    let no_validation = matches.is_present("no_validation");

    info!("Validation model: {}", model);
    if no_validation {
        info!("Skipping validation.");
    }

    let rate_limiter = Arc::new(
        RateLimiter::builder()
            .max(500) // max requests per minute
            .initial(500)
            .refill(500)
            .interval(Duration::from_secs(60))
            .build(),
    );

    let vulnerability_checks = vulnerability_checks::initialize_vulnerability_checks();
    let results_by_language = analyze_folder(
        folder_path,
        &openai_creds,
        &vulnerability_checks[..],
        validate_all_severities,
        model,
        no_validation,
        rate_limiter.clone(),
    )
    .await?;

    // Prepare data for summary generation
    let findings_summary: Vec<(String, Vec<VulnerabilityResult>)> = results_by_language
        .iter()
        .map(|(language, (_, vulnerabilities_details, _))| {
            (language.clone(), vulnerabilities_details.clone())
        })
        .collect();

    // Generate a summary of all findings
    let summary = if no_validation {
        "-".to_string()
    } else {
        gpt_validator::generate_summary(&openai_creds, &findings_summary, model, &rate_limiter)
            .await?
    };

    // Define the reports directory path
    let reports_dir = Path::new("reports");

    // Create the reports directory if it doesn't exist
    create_dir_all(&reports_dir)?;

    for (language, (files_list, vulnerabilities_details, safe_patterns_map)) in results_by_language
    {
        let safe_patterns_overview: Vec<SafePatternDetail> = safe_patterns_map
            .into_iter()
            .map(|(_, detail)| detail)
            .collect();

        let report = FinalReport {
            security_analysis_summary: SecurityAnalysisSummary {
                checked_files: files_list.len(),
                files_list,
                security_issues_found: vulnerabilities_details.len(),
            },
            vulnerabilities_details,
            safe_patterns_overview,
            model: if no_validation {
                "-".to_string()
            } else {
                model.to_string()
            },
            summary: summary.clone(), // Add summary here
        };

        let html_content = report_generator::generate_html_report(&report, &language);
        // Generate a filename with the current date and time
        let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
        let filename = reports_dir.join(format!("{}_L3X_SAST_Report_{}.html", language, timestamp));

        fs::write(&filename, html_content).expect("Unable to write HTML report");

        info!("Generated report for language: {}", language);
    }

    Ok(())
}

async fn analyze_folder(
    folder_path: &str,
    openai_creds: &OpenAICreds,
    checks: &[VulnerabilityCheck],
    validate_all_severities: bool,
    model: &str,
    no_validation: bool,
    rate_limiter: Arc<RateLimiter>,
) -> Result<
    HashMap<
        String,
        (
            Vec<String>,
            Vec<VulnerabilityResult>,
            HashMap<String, SafePatternDetail>,
        ),
    >,
    MyError,
> {
    let mut results_by_language: HashMap<
        String,
        (
            Vec<String>,
            Vec<VulnerabilityResult>,
            HashMap<String, SafePatternDetail>,
        ),
    > = HashMap::new();

    let entries: Vec<_> = WalkDir::new(folder_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let ext = e.path().extension().and_then(|e| e.to_str()).unwrap_or("");
            ext == "rs" || ext == "sol"
        })
        .collect();

    let pb = ProgressBar::new(entries.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .progress_chars("#>-"),
    );

    // Process files in parallel
    let results: Vec<_> = stream::iter(entries)
        .map(|entry| {
            let path = entry.path().to_path_buf();
            let openai_creds = openai_creds.clone();
            let checks = checks.to_vec();
            let model = model.to_string();
            let rate_limiter = rate_limiter.clone();
            let validate_all_severities = validate_all_severities;
            let no_validation = no_validation;
            let pb = pb.clone(); // Clone the progress bar for each task

            tokio::spawn(async move {
                process_file(
                    path,
                    openai_creds,
                    checks,
                    validate_all_severities,
                    model,
                    no_validation,
                    rate_limiter,
                    pb,
                )
                .await
            })
        })
        .buffer_unordered(8) // Adjust the level of concurrency here
        .collect()
        .await;

    for result in results {
        match result {
            Ok(Ok((language, files_list, vulnerabilities_details, safe_patterns_overview))) => {
                let (files_list_ref, vulnerabilities_details_ref, safe_patterns_overview_ref) =
                    results_by_language
                        .entry(language.clone())
                        .or_insert_with(|| (Vec::new(), Vec::new(), HashMap::new()));

                files_list_ref.extend(files_list);
                vulnerabilities_details_ref.extend(vulnerabilities_details);
                for (key, value) in safe_patterns_overview {
                    safe_patterns_overview_ref.insert(key, value);
                }
            }
            Ok(Err(e)) => warn!("Error processing file: {}", e),
            Err(e) => warn!("Task join error: {}", e),
        }
    }

    pb.finish_with_message("Analysis complete");

    Ok(results_by_language)
}

async fn process_file(
    path: std::path::PathBuf,
    openai_creds: OpenAICreds,
    checks: Vec<VulnerabilityCheck>,
    validate_all_severities: bool,
    model: String,
    no_validation: bool,
    rate_limiter: Arc<RateLimiter>,
    pb: ProgressBar,
) -> Result<
    (
        String,
        Vec<String>,
        Vec<VulnerabilityResult>,
        HashMap<String, SafePatternDetail>,
    ),
    MyError,
> {
    let file_content = fs::read_to_string(&path).map_err(MyError::from)?;
    let language = match path.extension().and_then(|e| e.to_str()) {
        Some("rs") => "Rust",
        Some("sol") => "Solidity-Ethereum",
        _ => return Err(MyError::custom("Unsupported language")),
    };

    let mut files_list = Vec::new();
    let mut vulnerabilities_details = Vec::new();
    let mut safe_patterns_overview = HashMap::new();

    files_list.push(path.to_string_lossy().to_string());

    // Group findings per file
    let mut findings_by_file = Vec::new();
    let mut in_block_comment = false;
    let mut struct_block = String::new();
    let mut in_struct_definition = false;

    for (line_number, line) in file_content.lines().enumerate() {
        let trimmed_line = line.trim();

        // Skip single-line comments
        if trimmed_line.starts_with("//") || trimmed_line.starts_with("///") {
            continue;
        }

        // Handle block comments
        if trimmed_line.starts_with("/*") {
            in_block_comment = true;
        }
        if in_block_comment {
            if trimmed_line.ends_with("*/") {
                in_block_comment = false;
            }
            continue;
        }

        // Detect the start of a struct definition
        if trimmed_line.starts_with("struct ") {
            in_struct_definition = true;
            log::info!(
                "Detected start of struct at line {}: {}",
                line_number + 1,
                trimmed_line
            );
        }

        // Accumulate lines if inside a struct definition
        if in_struct_definition {
            struct_block.push_str(trimmed_line);
            struct_block.push_str(" ");

            // Check if the struct definition ends
            if trimmed_line.ends_with("}") {
                in_struct_definition = false;
                log::info!("Struct block: {}", struct_block);
                // Process the entire struct definition
                for check in checks.iter().filter(|c| c.language == language) {
                    let pattern_regex = Regex::new(&check.pattern).map_err(MyError::from)?;
                    let safe_pattern_regex = check
                        .safe_pattern
                        .as_ref()
                        .and_then(|sp| Regex::new(sp).ok());

                    // Check for the presence of the pattern in the accumulated block
                    if pattern_regex.is_match(&struct_block) {
                        findings_by_file.push((
                            line_number + 1,
                            check.id.clone(),
                            check.severity.clone(),
                            check.suggested_fix.clone(),
                        ));
                        log::info!(
                            "Vulnerability found in struct block at line {}: {}",
                            line_number + 1,
                            struct_block
                        );
                    }

                    // Check for the presence of the safe pattern
                    if let Some(safe_regex) = &safe_pattern_regex {
                        if safe_regex.is_match(&struct_block) {
                            log::info!(
                                "Safe pattern found in struct block at line {}: {}",
                                line_number + 1,
                                struct_block
                            );
                            let entry = safe_patterns_overview
                                .entry(check.id.clone())
                                .or_insert_with(|| SafePatternDetail {
                                    pattern_id: check.id.clone(),
                                    title: check.title.clone(),
                                    safe_pattern: check.safe_pattern.clone().unwrap_or_default(),
                                    occurrences: 0,
                                    files: vec![],
                                });

                            entry.occurrences += 1;
                            if !entry.files.contains(&path.to_string_lossy().to_string()) {
                                entry.files.push(path.to_string_lossy().to_string());
                            }
                        }
                    }
                }

                // Reset struct block for the next possible struct
                struct_block.clear();
            }
            continue;
        }

        // Apply the existing logic to other lines as before
        for check in checks.iter().filter(|c| c.language == language) {
            let pattern_regex = Regex::new(&check.pattern).map_err(MyError::from)?;
            let safe_pattern_regex = check
                .safe_pattern
                .as_ref()
                .and_then(|sp| Regex::new(sp).ok());

            // Check for the presence of the pattern
            if pattern_regex.is_match(trimmed_line) {
                findings_by_file.push((
                    line_number + 1,
                    check.id.clone(),
                    check.severity.clone(),
                    check.suggested_fix.clone(),
                ));
            }

            // Check for the presence of the safe pattern
            if let Some(safe_regex) = &safe_pattern_regex {
                if safe_regex.is_match(trimmed_line) {
                    let entry = safe_patterns_overview
                        .entry(check.id.clone())
                        .or_insert_with(|| SafePatternDetail {
                            pattern_id: check.id.clone(),
                            title: check.title.clone(),
                            safe_pattern: check.safe_pattern.clone().unwrap_or_default(),
                            occurrences: 0,
                            files: vec![],
                        });

                    entry.occurrences += 1;
                    if !entry.files.contains(&path.to_string_lossy().to_string()) {
                        entry.files.push(path.to_string_lossy().to_string());
                    }
                }
            }
        }
    }

    let findings_explanations = if no_validation {
        findings_by_file
            .iter()
            .map(|(line, id, severity, _)| {
                (
                    line.clone(),
                    id.clone(),
                    severity.clone(),
                    "".to_string(),
                    "-".to_string(),
                    "".to_string(),
                )
            })
            .collect()
    } else {
        gpt_validator::validate_vulnerabilities_with_gpt(
            &openai_creds,
            &findings_by_file,
            &file_content,
            language,
            validate_all_severities,
            &model,
            &rate_limiter,
        )
        .await?
    };

    for (line_number, vulnerability_id, severity, suggested_fix, assessment, explanation) in
        findings_explanations
    {
        vulnerabilities_details.push(VulnerabilityResult {
            vulnerability_id: vulnerability_id.clone(),
            file: path.to_string_lossy().to_string(),
            line_number,
            title: checks
                .iter()
                .find(|c| c.id == vulnerability_id)
                .unwrap()
                .title
                .clone(),
            severity,
            status: assessment,
            description: checks
                .iter()
                .find(|c| c.id == vulnerability_id)
                .unwrap()
                .description
                .clone(),
            fix: suggested_fix,
            persistence_of_safe_pattern: "No".to_string(),
            safe_pattern: None,
            explanation: Some(explanation),
        });
    }

    pb.inc(1);

    Ok((
        language.to_string(),
        files_list,
        vulnerabilities_details,
        safe_patterns_overview,
    ))
}
