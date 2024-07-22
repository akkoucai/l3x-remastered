use crate::gpt_validator::{self, ChatRequest, ChatResponse};
use leaky_bucket::RateLimiter;
use rand::Rng;
use reqwest::Client;
use std::{error::Error, time::Duration};
use tokio::time::sleep;

pub async fn send_request_with_retries(
    client: &Client,
    openai_creds: &gpt_validator::OpenAICreds,
    chat_request: &ChatRequest,
    max_retries: u32,
    rate_limiter: &RateLimiter,
) -> Result<ChatResponse, Box<dyn Error + Send + Sync>> {
    let mut retries = 0;
    let mut wait_time = Duration::from_secs(1);

    loop {
        // Wait for the rate limiter
        rate_limiter.acquire_one().await;

        match send_openai_request(client, openai_creds, chat_request).await {
            Ok(response) => return Ok(response),
            Err(e) => {
                retries += 1;
                if retries > max_retries {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Exceeded maximum retries due to rate limiting",
                    )));
                }
                println!("Retry {}: {}", retries, e);

                // Exponential backoff with jitter
                let jitter: u64 = rand::thread_rng().gen_range(0..1000);
                wait_time = wait_time * 2 + Duration::from_millis(jitter);

                sleep(wait_time).await;
            }
        }
    }
}

async fn send_openai_request(
    client: &Client,
    openai_creds: &gpt_validator::OpenAICreds,
    chat_request: &ChatRequest,
) -> Result<ChatResponse, Box<dyn Error + Send + Sync>> {
    let response = client
        .post("https://api.openai.com/v1/chat/completions")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", openai_creds.api_key))
        .json(chat_request)
        .send()
        .await?;

    if response.status().is_success() {
        let chat_response = response.json::<ChatResponse>().await?;
        Ok(chat_response)
    } else {
        let error_text = response.text().await?;
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Request failed: {}", error_text),
        )))
    }
}
