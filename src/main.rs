mod app;
mod commands;
mod config;
mod db;
mod domain;
mod jobs;
mod mail;
mod metrics;
mod policy;
mod processing;
mod quota;
mod rate_limit;
mod scanner;
mod storage;
mod templates;
mod util;
mod web;

use std::{
    collections::BTreeSet,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use app::AppState;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use config::AppConfig;
use db::Database;
use serde::{Deserialize, Serialize};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Parser)]
#[command(
    name = "midden",
    version,
    about = "Self-hostable file and paste sharing"
)]
struct Cli {
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve,
    Migrate,
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Owner {
        #[command(subcommand)]
        command: OwnerCommand,
    },
    Storage {
        #[command(subcommand)]
        command: StorageCommand,
    },
    Jobs {
        #[command(subcommand)]
        command: JobCommand,
    },
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Check,
    PrintDefaults,
}

#[derive(Debug, Subcommand)]
enum OwnerCommand {
    Create {
        #[arg(long)]
        email: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: Option<String>,
    },
    ResetPassword {
        #[arg(long)]
        email: String,
        #[arg(long)]
        password: String,
    },
}

#[derive(Debug, Subcommand)]
enum StorageCommand {
    Gc {
        #[arg(long)]
        dry_run: bool,
    },
    Verify,
    Export {
        output: PathBuf,
    },
    Import {
        input: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum JobCommand {
    RunOnce,
}

#[derive(Debug, Subcommand)]
enum UserCommand {
    SetRole {
        #[arg(long)]
        email: String,
        #[arg(long)]
        role: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let config = AppConfig::load(cli.config)?;

    match cli.command {
        Command::Serve => serve(config).await,
        Command::Migrate => {
            let db = Database::connect(&config).await?;
            db.migrate().await?;
            println!("migrations applied");
            Ok(())
        }
        Command::Config { command } => match command {
            ConfigCommand::Check => {
                let _ = AppState::new(config).await?;
                println!("configuration ok");
                Ok(())
            }
            ConfigCommand::PrintDefaults => {
                println!("{}", toml_example(&AppConfig::default())?);
                Ok(())
            }
        },
        Command::Owner { command } => owner_command(config, command).await,
        Command::Storage { command } => storage_command(config, command).await,
        Command::Jobs { command } => jobs_command(config, command).await,
        Command::User { command } => user_command(config, command).await,
    }
}

async fn serve(config: AppConfig) -> anyhow::Result<()> {
    let bind: SocketAddr = config.server.bind.parse()?;
    let state = AppState::new(config).await?;
    state.db.migrate().await?;
    jobs::spawn(state.clone());
    let router = state.router();
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "midden listening");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn owner_command(config: AppConfig, command: OwnerCommand) -> anyhow::Result<()> {
    let db = Database::connect(&config).await?;
    db.migrate().await?;
    match command {
        OwnerCommand::Create {
            email,
            username,
            password,
        } => {
            let password_hash = match password {
                Some(p) => Some(util::hash_password(&p).await?),
                None => None,
            };
            let user = db
                .upsert_owner(&email, &username, password_hash.as_deref())
                .await?;
            println!("owner ready: {} ({})", user.username, user.email);
        }
        OwnerCommand::ResetPassword { email, password } => {
            let current = db.user_by_email(&email).await?;
            let password_hash = util::hash_password(&password).await?;
            let user = db
                .upsert_owner(&email, &current.username, Some(&password_hash))
                .await?;
            println!("owner password reset: {} ({})", user.username, user.email);
        }
    }
    Ok(())
}

async fn storage_command(config: AppConfig, command: StorageCommand) -> anyhow::Result<()> {
    let db = Database::connect(&config).await?;
    db.migrate().await?;
    match command {
        StorageCommand::Gc { dry_run } => {
            let storage = storage::BlobStorage::from_config(&config).await?;
            if !dry_run {
                eprintln!(
                    "warning: storage gc must run while all Midden server and job processes are stopped"
                );
            }
            let expired_files = db.expired_files().await?;
            let expired_file_count = expired_files.len();
            let expired_pastes = if dry_run {
                db.expired_paste_count().await? as u64
            } else {
                db.expire_due_pastes().await?
            };
            let deleted_blobs = if dry_run {
                0
            } else {
                for file in expired_files {
                    db.expire_file_and_release_blob(&file.id).await?;
                }
                commands::cleanup_zero_ref_blobs(&db, &storage).await?
            };
            let expired_auth_state = if dry_run {
                0
            } else {
                db.cleanup_expired_auth_state().await?
            };
            if dry_run {
                println!(
                    "storage reachable; dry-run would expire {} files and {} pastes",
                    expired_file_count, expired_pastes
                );
            } else {
                println!(
                    "storage reachable; expired items processed; deleted {deleted_blobs} blobs and {expired_auth_state} auth rows"
                );
            }
            Ok(())
        }
        StorageCommand::Verify => {
            let storage = storage::BlobStorage::from_config(&config).await?;
            let db_hashes = db.blob_hashes().await?.into_iter().collect::<BTreeSet<_>>();
            let backend_hashes = storage
                .list_hashes()
                .await?
                .into_iter()
                .collect::<BTreeSet<_>>();
            let missing = db_hashes
                .difference(&backend_hashes)
                .cloned()
                .collect::<Vec<_>>();
            let orphaned = backend_hashes
                .difference(&db_hashes)
                .cloned()
                .collect::<Vec<_>>();
            println!(
                "checked {} database blobs and {} backend objects",
                db_hashes.len(),
                backend_hashes.len()
            );
            if !missing.is_empty() {
                println!("missing backend objects:");
                for hash in &missing {
                    println!("{hash}");
                }
            }
            if !orphaned.is_empty() {
                println!("orphaned backend objects:");
                for hash in &orphaned {
                    println!("{hash}");
                }
            }
            if missing.is_empty() && orphaned.is_empty() {
                println!("storage verification ok");
                Ok(())
            } else {
                anyhow::bail!(
                    "storage verification found {} missing and {} orphaned objects",
                    missing.len(),
                    orphaned.len()
                );
            }
        }
        StorageCommand::Export { output } => {
            export_storage(&config, &db, &output).await?;
            Ok(())
        }
        StorageCommand::Import { input } => {
            import_storage(&config, &db, &input).await?;
            Ok(())
        }
    }
}

async fn jobs_command(config: AppConfig, command: JobCommand) -> anyhow::Result<()> {
    let state = AppState::new(config).await?;
    state.db.migrate().await?;
    match command {
        JobCommand::RunOnce => {
            let settings = state.settings().await?;
            let summary = jobs::run_once(&state, &settings).await?;
            println!(
                "jobs complete: expired_files={}, expired_pastes={}, expired_auth_rows={}, deleted_blobs={}, deleted_temp_files={}, scanner_retries={}, metadata_updates={}, missing_blobs={}, orphaned_blobs={}",
                summary.expired_files,
                summary.expired_pastes,
                summary.expired_auth_rows,
                summary.deleted_blobs,
                summary.deleted_temp_files,
                summary.scanner_retries,
                summary.metadata_updates,
                summary.missing_blobs,
                summary.orphaned_blobs
            );
            Ok(())
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StorageExportManifest {
    version: u32,
    created_at: i64,
    blobs: Vec<StorageExportBlob>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StorageExportBlob {
    hash: String,
    size_bytes: u64,
}

async fn export_storage(config: &AppConfig, db: &Database, output: &Path) -> anyhow::Result<()> {
    let storage = storage::BlobStorage::from_config(config).await?;
    let blob_dir = output.join("blobs");
    tokio::fs::create_dir_all(&blob_dir).await?;
    let mut blobs = Vec::new();
    for hash in db.blob_hashes().await? {
        let bytes = storage.get_blob(&hash).await?;
        tokio::fs::write(blob_dir.join(&hash), &bytes).await?;
        blobs.push(StorageExportBlob {
            hash,
            size_bytes: bytes.len() as u64,
        });
    }
    let manifest = StorageExportManifest {
        version: 1,
        created_at: util::now_ts(),
        blobs,
    };
    let encoded = serde_json::to_vec_pretty(&manifest)?;
    tokio::fs::write(output.join("manifest.json"), encoded).await?;
    println!(
        "exported {} blobs to {}",
        manifest.blobs.len(),
        output.display()
    );
    Ok(())
}

async fn import_storage(config: &AppConfig, db: &Database, input: &Path) -> anyhow::Result<()> {
    let storage = storage::BlobStorage::from_config(config).await?;
    let manifest_path = input.join("manifest.json");
    let hashes = if tokio::fs::try_exists(&manifest_path).await? {
        let bytes = tokio::fs::read(&manifest_path).await?;
        let manifest: StorageExportManifest = serde_json::from_slice(&bytes)?;
        manifest
            .blobs
            .into_iter()
            .map(|blob| blob.hash)
            .collect::<Vec<_>>()
    } else {
        let mut hashes = Vec::new();
        let mut entries = tokio::fs::read_dir(input.join("blobs")).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().to_string();
            if is_blob_hash(&name) {
                hashes.push(name);
            }
        }
        hashes.sort();
        hashes
    };
    let blob_dir = input.join("blobs");
    let mut imported = 0_usize;
    for hash in hashes {
        if !is_blob_hash(&hash) {
            anyhow::bail!("invalid blob hash in export: {hash}");
        }
        let bytes = tokio::fs::read(blob_dir.join(&hash)).await?;
        let actual_hash = util::sha256_hex(&bytes);
        if !actual_hash.eq_ignore_ascii_case(&hash) {
            anyhow::bail!("blob contents do not match export hash {hash}: computed {actual_hash}");
        }
        let mutation = db.begin_blob_mutation(&hash).await?;
        storage.put_blob(&hash, Bytes::from(bytes)).await?;
        mutation.commit().await?;
        imported += 1;
    }
    println!("imported {imported} blobs from {}", input.display());
    Ok(())
}

fn is_blob_hash(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("midden=info,tower_http=info")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

fn toml_example(config: &AppConfig) -> anyhow::Result<String> {
    Ok(toml::to_string_pretty(config)?)
}

async fn user_command(config: AppConfig, command: UserCommand) -> anyhow::Result<()> {
    let db = Database::connect(&config).await?;
    db.migrate().await?;
    match command {
        UserCommand::SetRole { email, role } => {
            let user = db.user_by_email(&email).await?;
            let parsed_role = db::Role::parse_form(&role)?;
            db.set_user_role(&user.id, parsed_role).await?;
            println!(
                "user role updated: {} is now {}",
                email,
                parsed_role.as_str()
            );
        }
    }
    Ok(())
}
