use std::sync::{Arc, Mutex};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use aes_gcm::Aes256Gcm;

/// Start a client connection, run the handshake and launch the TUI.
/// The function blocks and runs the TUI in the current thread.
pub fn run_client_with_tui(ip: String, port: u16, cipher: Aes256Gcm) {
    let addr = format!("{}:{}", ip, port);
    let mut stream = TcpStream::connect(&addr).expect("Could not establish connection");
    println!("Connected to {}", addr);

    // Send HELLO token immediately so server's HELLO-first check succeeds.
    if let Err(e) = crate::net::write_plain(&mut stream, b"HELLO-ANTIMPEU") {
        eprintln!("Failed to send HELLO to server: {}", e);
        return;
    }

    // Client handshake: read plaintext challenge and reply encrypted
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    if let Ok(chal_bytes) = crate::net::read_plain(&mut stream) {
        if let Ok(chal_str) = String::from_utf8(chal_bytes) {
            if chal_str.starts_with("CHAL:") {
                let challenge = chal_str.trim_start_matches("CHAL:").to_string();
                let username = whoami::username();
                let cipher_hand = cipher.clone();
                // send encrypted reply containing the challenge as message
                if let Err(e) = crate::crypto::send_encrypted(&mut stream, &challenge, &cipher_hand, &username) {
                    eprintln!("Handshake reply failed: {}", e);
                    return;
                }
            }
        }
    }
    stream.set_read_timeout(None).ok();

    let messages: Arc<Mutex<Vec<crate::tui::Message>>> = Arc::new(Mutex::new(Vec::new()));
    let messages_clone = messages.clone();
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_reader = shutdown.clone();

    // Reader thread
    let mut stream_reader = stream.try_clone().expect("Could not clone stream for reader thread");
    let cipher_reader = cipher.clone();
    thread::spawn(move || {
        loop {
            match crate::crypto::read_one_encrypted(&mut stream_reader, &cipher_reader) {
                Some((username, msg)) => {
                    let mut msgs = messages_clone.lock().unwrap();
                    msgs.push(crate::tui::Message { sender: username, text: msg, time: chrono::Local::now().format("%H:%M").to_string() });
                }
                None => {
                    // Inform TUI that the server shut down
                    let mut msgs = messages_clone.lock().unwrap();
                    msgs.push(crate::tui::Message { sender: "System".to_string(), text: "Server has shut down".to_string(), time: chrono::Local::now().format("%H:%M").to_string() });
                    shutdown_reader.store(true, std::sync::atomic::Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    // TUI send closure
    let stream_writer = Arc::new(Mutex::new(stream));
    let cipher_writer = cipher.clone();
    let username = whoami::username();
    let send_closure = move |msg: String| {
        if let Ok(mut s) = stream_writer.lock() {
            let _ = crate::crypto::send_encrypted(&mut s, &msg, &cipher_writer, &username);
        }
    };

    let _ = crate::tui::run_tui_with_sender(send_closure, messages, shutdown.clone());
    // After the TUI exits, if the reader signalled a server shutdown, print a single CLI notice.
    if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
        println!("Antimpeu server has been shut down");
    }
}
