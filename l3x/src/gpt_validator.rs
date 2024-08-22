use crate::error::MyError;
use crate::report_generator::VulnerabilityResult;
use crate::utils::send_request_with_retries;
use leaky_bucket::RateLimiter;
use log::{debug, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
#[derive(Clone)]
pub struct OpenAICreds {
    pub api_key: String,
}

#[derive(Serialize)]
pub struct ChatRequest {
    model: String,
    messages: Vec<Message>,
}

#[derive(Serialize)]
pub struct Message {
    role: String,
    content: String,
}

#[derive(Deserialize)]
pub struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
pub struct Choice {
    message: MessageContent,
}

#[derive(Deserialize)]
pub struct MessageContent {
    content: String,
}

pub async fn validate_vulnerabilities_with_gpt(
    openai_creds: &OpenAICreds,
    findings_by_file: &[(usize, String, String, String)],
    file_content: &str,
    language: &str,
    validate_all_severities: bool,
    model: &str,
    rate_limiter: &RateLimiter,
) -> Result<Vec<(usize, String, String, String, String, String)>, MyError> {
    let client = Client::new();

    let mut findings_list = String::new();
    for (line_number, vulnerability_id, severity, _) in findings_by_file {
        if validate_all_severities || severity == "Critical" || severity == "High" {
            findings_list.push_str(&format!("line {}: {}\n", line_number, vulnerability_id));
        }
    }

    let prompt = match language {
        "Rust" => format!(
            "A Static Application Security Testing (SAST) tool has identified potential vulnerabilities in a Rust code file. This file is part of a Solana smart contract, which often contains code patterns that might not always indicate actual vulnerabilities. Below are the details:\n\nSource code:\n{}\n\nList of detected vulnerabilities:\n{}\n\nFor each finding, carefully assess whether it is a valid vulnerability or a false positive. The goal is to correctly identify true security risks while acknowledging when a pattern is a known safe practice. If the finding is a security risk or could lead to a security issue in specific contexts, mark it as Valid. If the finding follows secure coding practices or is a standard pattern that does not pose a risk considering the context, mark it as a False positive. Provide a clear explanation for your assessment, and suggest any necessary fixes or improvements if applicable. Format your response as follows and do not use markdown formatting:\nFinding: [finding details]\nAssessment: [Valid/False positive]\nExplanation: [detailed explanation]\n\n",
            file_content, findings_list
        ),
        "Solidity-Ethereum" => format!(
            "A Static Application Security Testing (SAST) tool has identified potential vulnerabilities in a Solidity code file. Below are the details:\n\nSource code:\n{}\n\nList of detected vulnerabilities:\n{}\n\nFor each finding, please indicate if it is a valid vulnerability or a false positive. Provide a detailed explanation for your assessment and suggest any necessary fixes or improvements. Format your response as follows and do not use markdown formatting:\nFinding: [finding details]\nAssessment: [Valid/False positive]\nExplanation: [detailed explanation]\n\n",
            file_content, findings_list
        ),
        _ => return Err(MyError::custom("Unsupported language")),
    };

    let chat_request = ChatRequest {
        model: model.to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: prompt,
        }],
    };

    let response = send_request_with_retries(
        &client,
        &openai_creds,
        &chat_request,
        10, // Maximum number of retries
        rate_limiter,
    )
    .await
    .map_err(|e| {
        warn!("Failed to send request to OpenAI: {}", e);
        MyError::custom("Failed to send request to OpenAI")
    })?;

    let text = response
        .choices
        .get(0)
        .map_or_else(|| "", |choice| &choice.message.content);

    // Log the OpenAI response
    log_openai_response(file_content, findings_by_file, &text)?;

    let findings_explanations = analyze_response_text(text);
    let mut result = Vec::new();

    for (findings, assessment, explanation) in findings_explanations {
        for (line_number, vulnerability_id, severity, suggested_fix) in findings_by_file.iter() {
            if findings.contains(&format!("line {}: {}", line_number, vulnerability_id)) {
                result.push((
                    *line_number,
                    vulnerability_id.clone(),
                    severity.clone(),
                    suggested_fix.clone(),
                    assessment.clone(),
                    explanation.clone(),
                ));
            }
        }
    }

    Ok(result)
}

fn log_openai_response(
    file_content: &str,
    findings_by_file: &[(usize, String, String, String)],
    response_text: &str,
) -> Result<(), std::io::Error> {
    let log_file_path = "openai_responses.log";
    let mut log_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_file_path)?;

    writeln!(log_file, "Analyzed file content:\n{}\n", file_content)?;
    writeln!(log_file, "Findings:\n{:?}\n", findings_by_file)?;
    writeln!(log_file, "OpenAI Response:\n{}\n", response_text)?;

    Ok(())
}
fn analyze_response_text(text: &str) -> Vec<(Vec<String>, String, String)> {
    let mut findings_explanations = Vec::new();
    let mut current_findings = Vec::new();
    let mut current_assessment = String::new();
    let mut current_explanation = String::new();
    let mut in_explanation = false;

    for line in text.lines() {
        if line.starts_with("Finding: ") {
            let finding = line.replace("Finding: ", "").trim().to_string();
            current_findings.push(finding);
            in_explanation = false;
        } else if line.starts_with("Assessment: ") {
            current_assessment = line.replace("Assessment: ", "").trim().to_string();
            in_explanation = false;
        } else if line.starts_with("Explanation: ") {
            current_explanation = line.replace("Explanation: ", "").trim().to_string();
            in_explanation = true;
        } else if in_explanation {
            if !current_explanation.is_empty() {
                current_explanation.push('\n');
            }
            current_explanation.push_str(line.trim());
        }
    }

    if !current_findings.is_empty() {
        findings_explanations.push((
            current_findings.clone(),
            current_assessment.clone(),
            current_explanation.clone(),
        ));
    }

    findings_explanations
}

pub async fn generate_summary(
    openai_creds: &OpenAICreds,
    findings: &[(String, Vec<VulnerabilityResult>)],
    model: &str,
    rate_limiter: &RateLimiter,
) -> Result<String, MyError> {
    let client = Client::new();
    let findings_summary = findings
        .iter()
        .flat_map(|(_, v)| v)
        .map(|v| {
            format!(
                "File: {}\nLine: {}\nID: {}\nSeverity: {}\nDescription: {}\n\n",
                v.file, v.line_number, v.vulnerability_id, v.severity, v.description
            )
        })
        .collect::<String>();

    let prompt = format!(
        "Here are the findings from a Static Application Security Testing (SAST) tool:\n\n{}\nPlease provide a concise summary of these findings.",
        findings_summary
    );

    let chat_request = ChatRequest {
        model: model.to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: prompt,
        }],
    };

    let response =
        send_request_with_retries(&client, &openai_creds, &chat_request, 10, rate_limiter)
            .await
            .map_err(|e| {
                warn!("Failed to send request to OpenAI: {}", e);
                MyError::custom("Failed to send request to OpenAI")
            })?;

    let summary = response
        .choices
        .get(0)
        .map_or_else(|| "".to_string(), |choice| choice.message.content.clone());

    Ok(summary)
}
