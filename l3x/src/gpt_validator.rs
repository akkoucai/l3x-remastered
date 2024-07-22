use crate::error::MyError;
use crate::utils::send_request_with_retries;
use leaky_bucket::RateLimiter;
use log::warn;
use reqwest::Client;
use serde::{Deserialize, Serialize};

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
) -> Result<(String, String), MyError> {
    let client = Client::new();

    let mut findings_list = String::new();
    for (line_number, vulnerability_id, severity, _) in findings_by_file {
        if validate_all_severities || severity == "Critical" || severity == "High" {
            findings_list.push_str(&format!("line {}: {}\n", line_number, vulnerability_id));
        }
    }

    let prompt = match language {
        "Rust" => format!(
            "A Static Application Security Testing (SAST) tool has identified potential vulnerabilities in a Rust code file. Below are the details:\n\nSource code:\n{}\n\nList of detected vulnerabilities:\n{}\n\nFor each finding, determine if it is a valid vulnerability or a false positive. Provide a detailed explanation for your assessment and suggest any necessary fixes or improvements. Consider aspects like unsafe code usage, unhandled errors, unchecked arithmetic, and any potential security risks.",
            file_content, findings_list
        ),
        "Solidity-Ethereum" => format!(
            "A Static Application Security Testing (SAST) tool has identified potential vulnerabilities in a Solidity code file. Below are the details:\n\nSource code:\n{}\n\nList of detected vulnerabilities:\n{}\n\nFor each finding, determine if it is a valid vulnerability or a false positive. Provide a detailed explanation for your assessment and suggest any necessary fixes or improvements. Consider aspects like reentrancy attacks, unchecked sends, and any potential security risks.",
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

    let status = analyze_response_text(&text);

    Ok((status.to_string(), text.to_string()))
}

fn analyze_response_text(text: &str) -> &str {
    let lower_text = text.to_lowercase();

    let false_positive_indicators = vec![
        "not a vulnerability",
        "is not a valid vulnerability",
        "false positive",
        "no vulnerability",
        "not valid",
        "does not contain a vulnerability",
        "does not appear to have any obvious vulnerability",
        "no security issue",
        "safe",
    ];

    let valid_vulnerability_indicators = vec![
        "is a valid vulnerability",
        "is indeed a vulnerability",
        "poses a security risk",
        "can be exploited",
        "vulnerable",
        "needs to be addressed",
        "security issue",
        "security risk",
    ];

    if false_positive_indicators
        .iter()
        .any(|&indicator| lower_text.contains(indicator))
    {
        "False positive"
    } else if valid_vulnerability_indicators
        .iter()
        .any(|&indicator| lower_text.contains(indicator))
    {
        "Valid"
    } else {
        "Unknown"
    }
}
