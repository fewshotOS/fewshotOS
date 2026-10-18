//! Local model backends for the agent runtime: an [`OllamaPlanner`] and an
//! [`OllamaReader`] talking to Ollama's `/api/chat` (local Qwen by default).
//!
//! Both are untrusted agent components. The planner sees only a
//! [`fewshot_executor::PlannerInput`], so no untrusted bytes reach it; the
//! reader sees untrusted bytes but its output is labeled by the host. The
//! prompts' warnings about injected instructions are defense in depth only.

mod planner;
mod reader;

pub use planner::{OllamaPlanner, PLANNER_SYSTEM, render_input};
pub use reader::{OllamaReader, READER_SYSTEM};

use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

/// Where Ollama is and which models to use.
#[derive(Clone, Debug, PartialEq)]
pub struct OllamaConfig {
    /// Base URL, without a trailing slash.
    pub base_url: String,
    /// Model for planning.
    pub planner_model: String,
    /// Model for reading untrusted content.
    pub reader_model: String,
    /// Sampling temperature.
    pub temperature: f32,
    /// Sampling seed, for reproducible runs.
    pub seed: u64,
}

impl Default for OllamaConfig {
    fn default() -> Self {
        OllamaConfig {
            base_url: "http://localhost:11434".into(),
            planner_model: "qwen3.8-114k".into(),
            reader_model: "qwen3.8-114k".into(),
            temperature: 0.0,
            seed: 0,
        }
    }
}

impl OllamaConfig {
    /// The defaults, overridden by `FEWSHOT_OLLAMA_URL`,
    /// `FEWSHOT_PLANNER_MODEL` and `FEWSHOT_READER_MODEL` when set.
    pub fn from_env() -> Self {
        let mut c = OllamaConfig::default();
        let var = |name| std::env::var(name).ok().filter(|v: &String| !v.is_empty());
        if let Some(url) = var("FEWSHOT_OLLAMA_URL") {
            c.base_url = url.trim_end_matches('/').into();
        }
        if let Some(m) = var("FEWSHOT_PLANNER_MODEL") {
            c.planner_model = m;
        }
        if let Some(m) = var("FEWSHOT_READER_MODEL") {
            c.reader_model = m;
        }
        c
    }
}

/// One non-streaming chat turn.
#[derive(Clone, Copy, Debug)]
pub struct ChatRequest<'a> {
    /// Model name.
    pub model: &'a str,
    /// System prompt.
    pub system: &'a str,
    /// User message.
    pub user: &'a str,
    /// JSON schema the reply must match.
    pub format: &'a Value,
}

/// Sends chat turns to a model. [`HttpChat`] talks to Ollama; tests use fakes.
pub trait Chat {
    /// The model's reply text.
    fn chat(&mut self, req: &ChatRequest<'_>) -> Result<String, String>;
}

/// [`Chat`] over Ollama's HTTP API.
pub struct HttpChat {
    agent: ureq::Agent,
    url: String,
    temperature: f32,
    seed: u64,
}

impl HttpChat {
    /// A client for `config.base_url`.
    pub fn new(config: &OllamaConfig) -> Self {
        // Local models can take minutes on long prompts.
        let agent = ureq::AgentBuilder::new().timeout_read(Duration::from_secs(900)).build();
        HttpChat {
            agent,
            url: format!("{}/api/chat", config.base_url),
            temperature: config.temperature,
            seed: config.seed,
        }
    }
}

#[derive(Deserialize)]
struct ChatResponse {
    message: ChatMessage,
}

#[derive(Deserialize)]
struct ChatMessage {
    content: String,
}

impl Chat for HttpChat {
    fn chat(&mut self, req: &ChatRequest<'_>) -> Result<String, String> {
        let body = json!({
            "model": req.model,
            "stream": false,
            "think": false,
            "format": req.format,
            "options": { "temperature": self.temperature, "seed": self.seed },
            "messages": [
                { "role": "system", "content": req.system },
                { "role": "user", "content": req.user },
            ],
        });
        let resp = self.agent.post(&self.url).send_json(body).map_err(|e| e.to_string())?;
        let resp: ChatResponse = resp.into_json().map_err(|e| e.to_string())?;
        Ok(resp.message.content)
    }
}
