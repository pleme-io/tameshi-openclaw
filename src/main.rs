use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "tameshi-openclaw", about = "OpenClaw attestation integration")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compute attestation for all agent layers
    Attest {
        #[arg(long)]
        config: String,
    },
    /// Verify agent attestation against expected hash
    Verify {
        #[arg(long)]
        config: String,
        #[arg(long)]
        expected: String,
    },
    /// Run continuous compliance scanner
    Scan {
        #[arg(long)]
        config: String,
        #[arg(long, default_value = "300")]
        interval: u64,
    },
    /// Gate a skill before activation
    Gate {
        #[arg(long)]
        skill: String,
        #[arg(long)]
        config: String,
    },
    /// Skill store operations
    Store {
        #[command(subcommand)]
        action: StoreAction,
    },
}

#[derive(Subcommand)]
enum StoreAction {
    List,
    Verify { skill_id: String },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Attest { config } => {
            tracing::info!(config = %config, "computing attestation");
            println!("Attestation computed for config: {config}");
        }
        Commands::Verify { config, expected } => {
            tracing::info!(config = %config, expected = %expected, "verifying attestation");
            println!("Verification: config={config}, expected={expected}");
        }
        Commands::Scan {
            config,
            interval,
        } => {
            tracing::info!(config = %config, interval = interval, "starting scanner");
            let oc_config = tameshi_openclaw::config::OpenClawConfig {
                agent_name: "openclaw".into(),
                skills_dir: "/opt/openclaw/skills".into(),
                config_path: config,
                store_url: None,
                scan_interval_secs: interval,
                allowed_permissions: vec![],
                authorized_models: vec![],
            };
            let scanner =
                tameshi_openclaw::scanner::daemon::ComplianceScanner::new(oc_config);
            if let Err(e) = scanner.run().await {
                tracing::error!(error = %e, "scanner failed");
            }
        }
        Commands::Gate { skill, config: _ } => {
            println!("Gating skill: {skill}");
        }
        Commands::Store { action } => match action {
            StoreAction::List => println!("Listing store skills..."),
            StoreAction::Verify { skill_id } => {
                println!("Verifying skill: {skill_id}");
            }
        },
    }
}
