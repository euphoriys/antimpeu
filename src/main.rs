//! Antimpeu - small encrypted group chat.
//!
//! This binary module is intentionally small: it parses CLI arguments,
//! loads the decrypted data encryption key (DEK) and delegates to the
//! `server` or `client` modules. Helper modules contain encryption,
//! network framing, and the terminal UI.

mod tui;
mod crypto;
mod auth;
mod net;
mod utils;
mod server;
mod client;
mod types;

use clap::{Parser, Subcommand};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::KeyInit;
use std::sync::{Arc, Mutex, mpsc};
use types::{SharedMessages, SharedClients};
use std::collections::HashMap;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the group chat server and wait for incoming connections.
    Server {
    /// Port to listen on
    #[arg(value_parser)]
    port: u16,
    },
    /// Connect to a chat server.
    Client {
    /// Server IP or hostname
    #[arg(value_parser)]
    ip: String,
    /// Server port
    #[arg(value_parser)]
    port: u16,
    },
    /// Generate dek.bin from dek.key (passphrase)
    Enc {},
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Server { port } => {
            // load dek and prepare shared state
            let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
            let dek_path = format!("{}/key/dek.bin", home);
            let dek_arr = match auth::load_dek_from_encrypted(&dek_path) {
                Ok(a) => a,
                Err(e) => { eprintln!("{}", e); return; }
            };
            let cipher = Arc::new(Aes256Gcm::new_from_slice(&dek_arr).expect("Invalid DEK"));
            let messages: SharedMessages<tui::Message> = Arc::new(Mutex::new(Vec::new()));
            let (tx, rx) = mpsc::channel::<String>();
            let clients: SharedClients = Arc::new(Mutex::new(HashMap::new()));
            // spawn server components
            server::run_server_with_tui(port, cipher.clone(), messages.clone(), rx, clients.clone());
            // start TUI in main thread
            let send_fn = move |m: String| { let _ = tx.send(m); };
            let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let _ = tui::run_tui_with_sender(send_fn, messages.clone(), shutdown.clone());
            println!("Antimpeu closed, shutting down server.");
        }
        Commands::Client { ip, port } => {
            let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
            let dek_path = format!("{}/key/dek.bin", home);
            let dek_arr = match auth::load_dek_from_encrypted(&dek_path) {
                Ok(a) => a,
                Err(e) => { eprintln!("{}", e); return; }
            };
            let cipher = Aes256Gcm::new_from_slice(&dek_arr).expect("Invalid DEK");
            client::run_client_with_tui(ip, port, cipher);
        }
    Commands::Enc {} => { cmd_enc(); }
    }
}

fn cmd_enc() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
    let key_in_path = format!("{}/key/dek.key", home);
    let key_out_path = format!("{}/key/dek.bin", home);
    match utils::encrypt_and_write_dek(&key_in_path, &key_out_path) {
        Ok(()) => println!("Wrote encrypted DEK to {}", key_out_path),
        Err(e) => { eprintln!("{}", e); std::process::exit(2); }
    }
}