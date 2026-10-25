use clap::{Parser, Subcommand};
use serde_json::Value;

#[derive(Parser)]
#[command(name = "tempus-ddb-core")]
#[command(about = "Tempus DDB Core - INTERNAL DEV CLI (Use the Python `tempus` CLI for production)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the SQLite database schema
    Init {
        #[arg(long, default_value = "tempus.db")]
        db: String,
    },
    /// Generate a new Ed25519 cryptographic keypair
    GenKeys {
        #[arg(long, default_value = "keys.json")]
        output: String,
    },
    /// Record a new decision in the local ledger
    Record {
        #[arg(long, default_value = "tempus.db")]
        db: String,

        /// JSON payload representing inputs/outputs/decisions
        #[arg(long)]
        payload: String,

        /// JSON rules or rule ID representing the logic applied
        #[arg(long)]
        rules: String,

        /// Path to the keys.json file containing the actor's private key
        #[arg(long, default_value = "keys.json")]
        keyfile: String,

        /// Forces recording this as a genesis decision (no parent required)
        #[arg(long)]
        genesis: bool,
    },
    /// Walk the database to verify the integrity and cryptographic authenticity of the chain
    Validate {
        #[arg(long, default_value = "tempus.db")]
        db: String,
    },
    /// Export all decisions as a JSON array for cloud synchronization
    Export {
        #[arg(long, default_value = "tempus.db")]
        db: String,
    },
    /// List decisions with optional pagination
    List {
        #[arg(long, default_value = "tempus.db")]
        db: String,

        /// Maximum number of records to return
        #[arg(long, default_value = "10")]
        limit: u32,

        /// Number of records to skip
        #[arg(long, default_value = "0")]
        offset: u32,
    },
    /// Count the total number of decisions in the ledger
    Count {
        #[arg(long, default_value = "tempus.db")]
        db: String,
    },
    /// Register an agent in the ledger's identity registry
    RegisterAgent {
        #[arg(long, default_value = "tempus.db")]
        db: String,

        /// Path to the gate key that authorizes this registration
        #[arg(long, default_value = "gate.keys.json")]
        keyfile: String,

        /// Ed25519 public key in hex format (64 hex chars)
        #[arg(long, alias = "public-key")]
        public_key: String,

        /// Human-readable alias for the agent
        #[arg(long)]
        alias: String,

        /// Optional JSON metadata for the agent
        #[arg(long, default_value = "{}")]
        metadata: String,
    },
    /// List all registered agents
    ListAgents {
        #[arg(long, default_value = "tempus.db")]
        db: String,
    },
    /// Request a single-use B2A action authorization
    RequestAction {
        #[arg(long, default_value = "tempus.db")]
        db: String,
        #[arg(long, default_value = "gate.keys.json")]
        gate_keyfile: String,
        #[arg(long)]
        agent_keyfile: String,
        /// JSON action intent using tempus.action-intent.v1
        #[arg(long)]
        intent: String,
        #[arg(long, default_value = "60")]
        ttl_seconds: u64,
    },
    /// DEVELOPMENT ONLY: explicitly install a signed allow-all policy
    InstallAllowAllDev {
        #[arg(long, default_value = "tempus.db")]
        db: String,
        #[arg(long, default_value = "gate.keys.json")]
        gate_keyfile: String,
    },
    /// Commit the executor outcome for an allowed action
    CommitOutcome {
        #[arg(long, default_value = "tempus.db")]
        db: String,
        #[arg(long, default_value = "gate.keys.json")]
        gate_keyfile: String,
        #[arg(long)]
        authorization_id: String,
        /// JSON action outcome using tempus.action-outcome.v1
        #[arg(long)]
        outcome: String,
        #[arg(long)]
        executor_keyfile: String,
    },
    /// Return a complete B2A action trace
    Trace {
        #[arg(long, default_value = "tempus.db")]
        db: String,
        #[arg(long, default_value = "gate.keys.json")]
        gate_keyfile: String,
        #[arg(long)]
        action_id: String,
    },
    /// Verify a B2A action trace end to end
    VerifyTrace {
        #[arg(long, default_value = "tempus.db")]
        db: String,
        #[arg(long, default_value = "gate.keys.json")]
        gate_keyfile: String,
        #[arg(long)]
        action_id: String,
        /// Gate public key (64 hex chars) pinned by the verifier. Without it the
        /// result is marked "independent": false (trust root taken from the DB).
        #[arg(long)]
        gate_public_key: Option<String>,
        /// Optional executor public key(s) to pin (requires --gate-public-key)
        #[arg(long = "executor-public-key")]
        executor_public_keys: Vec<String>,
    },
    /// Export one action as a self-contained evidence bundle (no private keys)
    ExportBundle {
        #[arg(long, default_value = "tempus.db")]
        db: String,
        #[arg(long, default_value = "gate.keys.json")]
        gate_keyfile: String,
        #[arg(long)]
        action_id: String,
        /// Output file for the bundle JSON
        #[arg(long)]
        out: String,
    },
    /// Verify an evidence bundle without a database, against a pinned gate key
    VerifyBundle {
        /// Path to the bundle JSON
        #[arg(long)]
        bundle: String,
        /// Gate public key (64 hex chars) pinned by the verifier
        #[arg(long)]
        gate_public_key: String,
        /// Optional executor public key(s) to pin
        #[arg(long = "executor-public-key")]
        executor_public_keys: Vec<String>,
    },
    /// Verify a standalone receipt (trace, permit or outcome JSON) without a database
    VerifyReceipt {
        /// Path to the receipt JSON
        #[arg(long)]
        receipt: String,
        /// Gate public key (64 hex chars) pinned by the verifier
        #[arg(long)]
        gate_public_key: String,
        /// Optional executor public key(s) to pin
        #[arg(long = "executor-public-key")]
        executor_public_keys: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { db } => {
            match _tempus_ddb::SqliteStorage::new(db.clone(), "keys.json".to_string()) {
                Ok(_) => eprintln!("Database initialized successfully: {}", db),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::GenKeys { output } => match _tempus_ddb::generate_keypair(&output) {
            Ok(json_str) => {
                eprintln!("Cryptographic keys generated and saved to: {}", output);
                let val: Value = serde_json::from_str(&json_str).unwrap();
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "public_key": val.get("public_key")
                    }))
                    .unwrap()
                );
            }
            Err(e) => {
                eprintln!("Error generating keys: {}", e);
                std::process::exit(1);
            }
        },
        Commands::Record {
            db,
            payload,
            rules,
            keyfile,
            genesis,
        } => {
            let mut storage = match _tempus_ddb::SqliteStorage::new(db, keyfile) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error opening database: {}", e);
                    std::process::exit(1);
                }
            };

            use _tempus_ddb::StorageLayer;
            if let Err(e) = storage.insert_decision(&payload, &rules, genesis) {
                eprintln!("Error recording decision: {}", e);
                std::process::exit(1);
            }

            let latest = storage.get_latest_hash().unwrap_or_default();
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "status": "success",
                    "action": "recorded",
                    "latest_hash": latest
                }))
                .unwrap()
            );
        }
        Commands::Validate { db } => {
            let storage = match _tempus_ddb::SqliteStorage::new(db, "keys.json".to_string()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error opening database: {}", e);
                    std::process::exit(1);
                }
            };

            match storage.validate_ledger() {
                Ok(json) => println!("{}", json),
                Err(e) => {
                    println!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Export { db } => {
            let storage = match _tempus_ddb::SqliteStorage::new(db, "keys.json".to_string()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error opening database: {}", e);
                    std::process::exit(1);
                }
            };

            use _tempus_ddb::StorageLayer;
            match storage.export_ledger() {
                Ok(json) => println!("{}", json),
                Err(e) => {
                    eprintln!("Error exporting ledger: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::List { db, limit, offset } => {
            let storage = match _tempus_ddb::SqliteStorage::new(db, "keys.json".to_string()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error opening database: {}", e);
                    std::process::exit(1);
                }
            };

            use _tempus_ddb::StorageLayer;
            match storage.list_decisions(limit, offset) {
                Ok(json) => println!("{}", json),
                Err(e) => {
                    eprintln!("Error listing decisions: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Count { db } => {
            let storage = match _tempus_ddb::SqliteStorage::new(db, "keys.json".to_string()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error opening database: {}", e);
                    std::process::exit(1);
                }
            };

            use _tempus_ddb::StorageLayer;
            match storage.count_decisions() {
                Ok(count) => println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "total_decisions": count
                    }))
                    .unwrap()
                ),
                Err(e) => {
                    eprintln!("Error counting decisions: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::RegisterAgent {
            db,
            keyfile,
            public_key,
            alias,
            metadata,
        } => {
            let storage = match _tempus_ddb::SqliteStorage::new(db, keyfile) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error opening database: {}", e);
                    std::process::exit(1);
                }
            };

            match storage.register_agent(&public_key, &alias, &metadata) {
                Ok(json) => println!("{}", json),
                Err(e) => {
                    eprintln!("Error registering agent: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::ListAgents { db } => {
            let storage = match _tempus_ddb::SqliteStorage::new(db, "keys.json".to_string()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error opening database: {}", e);
                    std::process::exit(1);
                }
            };

            match storage.list_agents() {
                Ok(json) => println!("{}", json),
                Err(e) => {
                    eprintln!("Error listing agents: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::RequestAction {
            db,
            gate_keyfile,
            agent_keyfile,
            intent,
            ttl_seconds,
        } => {
            let storage = match _tempus_ddb::SqliteStorage::new(db, gate_keyfile) {
                Ok(storage) => storage,
                Err(error) => {
                    eprintln!("Error opening gate: {error}");
                    std::process::exit(1);
                }
            };
            match storage.request_action(&intent, &agent_keyfile, ttl_seconds) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    eprintln!("Error requesting action: {error}");
                    std::process::exit(1);
                }
            }
        }
        Commands::InstallAllowAllDev { db, gate_keyfile } => {
            let storage = match _tempus_ddb::SqliteStorage::new(db, gate_keyfile) {
                Ok(storage) => storage,
                Err(error) => {
                    eprintln!("Error opening gate: {error}");
                    std::process::exit(1);
                }
            };
            match storage.install_allow_all_dev_policy() {
                Ok(json) => {
                    eprintln!(
                        "WARNING: allow-all development policy installed; every action is \
                         ALLOWED. Do not use in production."
                    );
                    println!("{json}");
                }
                Err(error) => {
                    eprintln!("Error installing allow-all dev policy: {error}");
                    std::process::exit(1);
                }
            }
        }
        Commands::CommitOutcome {
            db,
            gate_keyfile,
            authorization_id,
            outcome,
            executor_keyfile,
        } => {
            let storage = match _tempus_ddb::SqliteStorage::new(db, gate_keyfile) {
                Ok(storage) => storage,
                Err(error) => {
                    eprintln!("Error opening gate: {error}");
                    std::process::exit(1);
                }
            };
            match storage.commit_outcome(&authorization_id, &outcome, &executor_keyfile) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    eprintln!("Error committing outcome: {error}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Trace {
            db,
            gate_keyfile,
            action_id,
        } => {
            let storage = match _tempus_ddb::SqliteStorage::new(db, gate_keyfile) {
                Ok(storage) => storage,
                Err(error) => {
                    eprintln!("Error opening gate: {error}");
                    std::process::exit(1);
                }
            };
            match storage.get_trace(&action_id) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    eprintln!("Error reading trace: {error}");
                    std::process::exit(1);
                }
            }
        }
        Commands::VerifyTrace {
            db,
            gate_keyfile,
            action_id,
            gate_public_key,
            executor_public_keys,
        } => {
            let storage = match _tempus_ddb::SqliteStorage::new(db, gate_keyfile) {
                Ok(storage) => storage,
                Err(error) => {
                    eprintln!("Error opening gate: {error}");
                    std::process::exit(1);
                }
            };
            let result = match gate_public_key {
                Some(gate) => storage.verify_trace_pinned(&action_id, &gate, &executor_public_keys),
                None if !executor_public_keys.is_empty() => {
                    Err("--executor-public-key requires --gate-public-key".to_string())
                }
                None => {
                    eprintln!(
                        "WARNING: no --gate-public-key: NOT INDEPENDENT (trust root comes from \
                         the database being verified)"
                    );
                    storage.verify_trace(&action_id)
                }
            };
            print_verification(result);
        }
        Commands::ExportBundle {
            db,
            gate_keyfile,
            action_id,
            out,
        } => {
            let storage = match _tempus_ddb::SqliteStorage::new(db, gate_keyfile) {
                Ok(storage) => storage,
                Err(error) => {
                    eprintln!("Error opening gate: {error}");
                    std::process::exit(1);
                }
            };
            match storage.export_bundle(&action_id, None) {
                Ok(bundle) => {
                    if let Err(error) = std::fs::write(&out, &bundle) {
                        eprintln!("Error writing bundle '{out}': {error}");
                        std::process::exit(1);
                    }
                    eprintln!("Bundle written to {out}");
                }
                Err(error) => {
                    eprintln!("Error exporting bundle: {error}");
                    std::process::exit(1);
                }
            }
        }
        Commands::VerifyBundle {
            bundle,
            gate_public_key,
            executor_public_keys,
        } => {
            let raw = match std::fs::read_to_string(&bundle) {
                Ok(raw) => raw,
                Err(error) => {
                    eprintln!("Error reading bundle '{bundle}': {error}");
                    std::process::exit(1);
                }
            };
            print_verification(_tempus_ddb::verify_bundle(
                &raw,
                &gate_public_key,
                &executor_public_keys,
            ));
        }
        Commands::VerifyReceipt {
            receipt,
            gate_public_key,
            executor_public_keys,
        } => {
            let raw = match std::fs::read_to_string(&receipt) {
                Ok(raw) => raw,
                Err(error) => {
                    eprintln!("Error reading receipt '{receipt}': {error}");
                    std::process::exit(1);
                }
            };
            print_verification(_tempus_ddb::verify_receipt(
                &raw,
                &gate_public_key,
                &executor_public_keys,
            ));
        }
    }
}

fn print_verification(result: Result<String, String>) {
    match result {
        Ok(json) => {
            println!("{json}");
            if json.contains("\"status\":\"INVALID\"") {
                std::process::exit(2);
            }
        }
        Err(error) => {
            eprintln!("Error verifying: {error}");
            std::process::exit(1);
        }
    }
}
