//! `fewshot`: the Fewshot runtime command line.

use clap::{Parser, Subcommand};
use fewshot::{Server, SocketApprovals};
use fewshot_models::{HttpChat, OllamaConfig, OllamaPlanner, OllamaReader};
use fewshot_runtime::{Config, builtin_runtime};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "fewshot", version, about = "Fewshot: labeled data and approvals for AI agents")]
struct Cli {
    /// Config file. Default: `$FEWSHOT_CONFIG`, else `fewshot/fewshot.toml`
    /// in the user's config directory.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve one MCP client over stdio.
    Mcp {
        /// The client's name, as in a `[[client]]` entry of the config.
        #[arg(long)]
        client: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // stdout carries the protocol only.
            eprintln!("fewshot: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let path = cli.config.unwrap_or_else(Config::default_path);
    let config = Config::load(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    match cli.command {
        Command::Mcp { client } => mcp(config, &client),
    }
}

fn mcp(config: Config, client: &str) -> Result<(), String> {
    let key_dir = fewshot_approval::default_dir();
    let key = fewshot_approval::load_public(&key_dir).map_err(|e| {
        format!("no approval key in {} ({e}); run `fewshot-approve` once to create it", key_dir.display())
    })?;
    let ollama = ollama_config(&config);
    let timeout = Duration::from_secs(config.runtime.approval_timeout_s);
    let rt = builtin_runtime(config, key).map_err(|e| e.to_string())?;
    let planner = OllamaPlanner::from_config(&ollama, rt.gate().registry().clone());
    let reader = OllamaReader::new(HttpChat::new(&ollama), ollama.reader_model.clone());
    let approvals = SocketApprovals::new(timeout);
    let mut server =
        Server::new(rt, client, approvals, Box::new(reader), Box::new(planner)).map_err(|e| e.to_string())?;
    eprintln!("fewshot: serving MCP client {client:?} on stdio");
    server.serve(std::io::stdin().lock(), std::io::stdout().lock()).map_err(|e| e.to_string())
}

/// The defaults, then the config file's `[ollama]` values, then the
/// `FEWSHOT_*` environment overrides of [`OllamaConfig::from_env`].
fn ollama_config(config: &Config) -> OllamaConfig {
    let mut c = OllamaConfig::default();
    if let Some(o) = &config.ollama {
        if let Some(u) = &o.base_url {
            c.base_url = u.trim_end_matches('/').into();
        }
        if let Some(m) = &o.planner_model {
            c.planner_model = m.clone();
        }
        if let Some(m) = &o.reader_model {
            c.reader_model = m.clone();
        }
    }
    let (env, default) = (OllamaConfig::from_env(), OllamaConfig::default());
    if env.base_url != default.base_url {
        c.base_url = env.base_url;
    }
    if env.planner_model != default.planner_model {
        c.planner_model = env.planner_model;
    }
    if env.reader_model != default.reader_model {
        c.reader_model = env.reader_model;
    }
    c
}
