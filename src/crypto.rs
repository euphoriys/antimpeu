use aes_gcm::{Aes256Gcm, aead::{Aead, OsRng}};
use rand_core::RngCore;
use serde::{Serialize, Deserialize};
use std::io::{Read, Write};
use std::net::TcpStream;

/// JSON-serializable envelope for encrypted messages sent over TCP.
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedMessage {
    pub username: String,
    pub nonce: String,
    pub ciphertext: String,
    pub tag: String,
}

/// Encrypt and send a message. The serialized JSON is length-prefixed
/// (u32 BE) so the receiver can read one complete frame at a time.
pub fn send_encrypted(stream: &mut TcpStream, message: &str, cipher: &Aes256Gcm, username: &str) -> std::io::Result<()> {
    // Generate random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::aead::generic_array::GenericArray::<u8, typenum::U12>::from_slice(&nonce_bytes);

    // AES-GCM returns ciphertext||tag. We split them to store the tag separately
    let ciphertext_with_tag = cipher.encrypt(nonce, message.as_bytes()).expect("encryption failed");
    let (ciphertext, tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);

    let encrypted_msg = EncryptedMessage {
        username: username.to_string(),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
        tag: hex::encode(tag),
    };

    let serialized_msg = serde_json::to_string(&encrypted_msg).expect("serialization failed");
    let msg_bytes = serialized_msg.as_bytes();
    let len_bytes = (msg_bytes.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes)?;
    stream.write_all(msg_bytes)?;
    stream.flush()?;
    Ok(())
}

/// Read a single encrypted JSON frame, decrypt it with `cipher` and return
/// (username, plaintext) on success. Returns None on any error or EOF.
pub fn read_one_encrypted(stream: &mut TcpStream, cipher: &Aes256Gcm) -> Option<(String, String)> {
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).is_err() { return None; }
    let msg_len = u32::from_be_bytes(len_buf) as usize;
    let mut buffer = vec![0u8; msg_len];
    if stream.read_exact(&mut buffer).is_err() { return None; }

    let encrypted_msg: EncryptedMessage = serde_json::from_slice(&buffer).ok()?;
    let nonce_bytes = hex::decode(&encrypted_msg.nonce).ok()?;
    let nonce = aes_gcm::aead::generic_array::GenericArray::<u8, typenum::U12>::from_slice(&nonce_bytes);

    // reconstruct ciphertext||tag and decrypt
    let mut combined_data = hex::decode(&encrypted_msg.ciphertext).ok()?;
    combined_data.extend_from_slice(&hex::decode(&encrypted_msg.tag).ok()?);
    let decrypted_bytes = cipher.decrypt(nonce, combined_data.as_ref()).ok()?;
    let decrypted_message = String::from_utf8_lossy(&decrypted_bytes).to_string();
    Some((encrypted_msg.username, decrypted_message))
}
