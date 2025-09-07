//! Server responsibilities:
//! - accept TCP connections
//! - run a lightweight handshake (plaintext HELLO, challenge-response)
//! - spawn per-client reader threads
//! - broadcast messages received from the UI via an mpsc Receiver

use std::sync::{Arc, Mutex, mpsc};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;
use aes_gcm::Aes256Gcm;
use rand_core::RngCore;
use crate::types::{SharedMessages, SharedClients};

/// Start the server accept loop and internal worker threads.
///
/// This function returns quickly — the TUI runs in the caller's thread.
pub fn run_server_with_tui(port: u16, cipher: Arc<Aes256Gcm>, messages: SharedMessages<crate::tui::Message>, rx: mpsc::Receiver<String>, clients: SharedClients) {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).expect("Cannot bind");
    println!("Server running on {}", addr);

    // Accept thread: listen for incoming TCP connections and handle handshake
    let clients_accept = clients.clone();
    let messages_accept = messages.clone();
    let cipher_accept = cipher.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let peer = stream.peer_addr().unwrap().to_string();
                    {
                        let mut msgs = messages_accept.lock().unwrap();
                        let sys_text = format!("New connection from {}", peer);
                        msgs.push(crate::tui::Message { sender: "System".to_string(), text: sys_text.clone(), time: chrono::Local::now().format("%H:%M").to_string() });
                        // broadcast to clients
                        let conns = clients_accept.lock().unwrap();
                        for (_addr, client) in conns.iter() {
                            if let Ok(mut s) = client.lock() {
                                let _ = crate::crypto::send_encrypted(&mut s, &sys_text, &cipher_accept, "Server");
                            }
                        }
                    }
                    // Create a separate writer (stored in clients map) and a reader stream used by the reader thread.
                    let mut stream_read = match stream.try_clone() {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    // Expect a plaintext HELLO token first; if missing or incorrect, refuse immediately.
                    stream_read.set_read_timeout(Some(Duration::from_millis(200))).ok();
                    let hello_ok = match crate::net::read_plain(&mut stream_read) {
                        Ok(buf) => {
                            if let Ok(s) = String::from_utf8(buf) {
                                s == "HELLO-ANTIMPEU"
                            } else { false }
                        }
                        Err(_) => false,
                    };
                    if !hello_ok {
                        let mut msgs = messages_accept.lock().unwrap();
                        let sys_text = format!("Refused connection from {}.", peer);
                        msgs.push(crate::tui::Message { sender: "System".to_string(), text: sys_text.clone(), time: chrono::Local::now().format("%H:%M").to_string() });
                        let conns = clients_accept.lock().unwrap();
                        for (_addr, client) in conns.iter() {
                            if let Ok(mut s) = client.lock() {
                                let _ = crate::crypto::send_encrypted(&mut s, &sys_text, &cipher_accept, "Server");
                            }
                        }
                        continue;
                    }
                    // client said HELLO; now send challenge
                    stream_read.set_read_timeout(None).ok();
                    let mut rand_bytes = [0u8; 12];
                    let mut rng = aes_gcm::aead::OsRng;
                    rng.fill_bytes(&mut rand_bytes);
                    let challenge = hex::encode(rand_bytes);
                    let challenge_msg = format!("CHAL:{}", challenge);
                    // send plaintext length-prefixed challenge
                    if crate::net::write_plain(&mut stream, challenge_msg.as_bytes()).is_err() {
                        let mut msgs = messages_accept.lock().unwrap();
                        let sys_text = format!("Refused connection from {} (handshake write failed)", peer);
                        msgs.push(crate::tui::Message { sender: "System".to_string(), text: sys_text.clone(), time: chrono::Local::now().format("%H:%M").to_string() });
                        let conns = clients_accept.lock().unwrap();
                        for (_addr, client) in conns.iter() {
                            if let Ok(mut s) = client.lock() {
                                let _ = crate::crypto::send_encrypted(&mut s, &sys_text, &cipher_accept, "Server");
                            }
                        }
                        continue;
                    }
                    // wait for encrypted reply within timeout
                    stream_read.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    match crate::crypto::read_one_encrypted(&mut stream_read, &cipher_accept) {
                        Some((_username, reply)) => {
                            if reply != challenge {
                                let mut msgs = messages_accept.lock().unwrap();
                                let sys_text = format!("Refused connection from {} (handshake mismatch)", peer);
                                msgs.push(crate::tui::Message { sender: "System".to_string(), text: sys_text.clone(), time: chrono::Local::now().format("%H:%M").to_string() });
                                let conns = clients_accept.lock().unwrap();
                                for (_addr, client) in conns.iter() {
                                    if let Ok(mut s) = client.lock() {
                                        let _ = crate::crypto::send_encrypted(&mut s, &sys_text, &cipher_accept, "Server");
                                    }
                                }
                                continue;
                            }
                            // handshake ok
                            stream_read.set_read_timeout(None).ok();
                        }
                        _ => {
                            let mut msgs = messages_accept.lock().unwrap();
                            let sys_text = format!("Refused connection from {} (no handshake reply)", peer);
                            msgs.push(crate::tui::Message { sender: "System".to_string(), text: sys_text.clone(), time: chrono::Local::now().format("%H:%M").to_string() });
                            let conns = clients_accept.lock().unwrap();
                                for (_addr, client) in conns.iter() {
                                    if let Ok(mut s) = client.lock() {
                                        let _ = crate::crypto::send_encrypted(&mut s, &sys_text, &cipher_accept, "Server");
                                    }
                                }
                            continue;
                        }
                    }

                    let stream_write = Arc::new(Mutex::new(stream));
                    clients_accept.lock().unwrap().insert(peer.clone(), stream_write.clone());

                    // Reader thread for this client uses the dedicated read clone (no mutex) so that
                    // the writer mutex in `clients` is not held while blocking on reads.
                    let messages_in = messages_accept.clone();
                    let clients_in = clients_accept.clone();
                    let cipher_in = cipher_accept.clone();
                    let peer_clone = peer.clone();
                    thread::spawn(move || {
                        let mut reader = stream_read;
                        loop {
                            match crate::crypto::read_one_encrypted(&mut reader, &cipher_in) {
                                        Some((username, msg)) => {
                                    // push into server TUI
                                    let mut msgs = messages_in.lock().unwrap();
                                    msgs.push(crate::tui::Message { sender: username.clone(), text: msg.clone(), time: chrono::Local::now().format("%H:%M").to_string() });
                                    drop(msgs);

                                    // broadcast to all other clients (collect targets while holding lock, then send)
                                    let conns = clients_in.lock().unwrap();
                                    let targets: Vec<_> = conns.iter()
                                        .filter(|(k, _)| *k != &peer_clone)
                                        .map(|(_, v)| v.clone())
                                        .collect();
                                    drop(conns);
                                    for target in targets {
                                        if let Ok(mut s) = target.lock() {
                                            let _ = crate::crypto::send_encrypted(&mut s, &msg, &cipher_in, &username);
                                        }
                                    }
                                }
                                _ => {
                                    clients_in.lock().unwrap().remove(&peer_clone);
                                    let mut msgs = messages_in.lock().unwrap();
                                    let sys_text = format!("Disconnected from {}", peer_clone);
                                    msgs.push(crate::tui::Message { sender: "System".to_string(), text: sys_text.clone(), time: chrono::Local::now().format("%H:%M").to_string() });
                                    let conns = clients_in.lock().unwrap();
                                    for (_addr, client) in conns.iter() {
                                        if let Ok(mut s) = client.lock() {
                                            let _ = crate::crypto::send_encrypted(&mut s, &sys_text, &cipher_in, "Server");
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(e) => eprintln!("Error accepting connection: {}", e),
            }
        }
    });

    // Broadcast thread: take messages from TUI and forward to all clients
    let clients_broadcast = clients.clone();
    let local_username = whoami::username();
    let cipher_broadcast = cipher.clone();
    thread::spawn(move || {
        while let Ok(msg) = rx.recv() {
            let conns = clients_broadcast.lock().unwrap();
            for (_addr, client) in conns.iter() {
                if let Ok(mut s) = client.lock() {
                    let _ = crate::crypto::send_encrypted(&mut s, &msg, &cipher_broadcast, &local_username);
                }
            }
        }
    });

    // Keep this function returning quickly; actual TUI is driven from main which holds handles.
}
