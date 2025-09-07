//! Shared type aliases used across the project to keep signatures concise.
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

/// A shared, thread-safe message vector used by the TUI and networking code.
pub type SharedMessages<T> = Arc<Mutex<Vec<T>>>;

/// A map of peer address -> writer stream protected by a mutex and shared across threads.
pub type SharedClients = Arc<Mutex<HashMap<String, Arc<Mutex<std::net::TcpStream>>>>>;
