use aes_gcm::{Aes256Gcm, aead::Aead, KeyInit};
use rand_core::RngCore;
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;
use rpassword::read_password;

/// Read a raw DEK from `input_path`, encrypt it with a password (KEK) and
/// write the encrypted blob to `output_path`.
///
/// The output layout is: salt || nonce || ciphertext.
pub fn encrypt_and_write_dek(input_path: &str, output_path: &str) -> Result<(), String> {
    let dek_bytes = std::fs::read(input_path).map_err(|e| format!("Failed to read {}: {}", input_path, e))?;
    if dek_bytes.is_empty() {
        return Err(format!("Input file {} is empty", input_path));
    }
    use std::io::{self, Write};
    print!("Enter KEK (password) to encrypt DEK: ");
    io::stdout().flush().ok();
    let kek = read_password().map_err(|_| "Failed to read KEK".to_string())?;

    let mut salt = [0u8; 16];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut salt);
    let mut kek_derived = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(kek.as_bytes(), &salt, 100_000, &mut kek_derived);

    let kek_cipher = Aes256Gcm::new_from_slice(&kek_derived).map_err(|_| "Invalid KEK-derived key".to_string())?;
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let nonce_ga = aes_gcm::aead::generic_array::GenericArray::<u8, typenum::U12>::from_slice(&nonce);
    let ciphertext = kek_cipher.encrypt(nonce_ga, dek_bytes.as_ref()).map_err(|_| "Encryption failed".to_string())?;

    if let Some(dir) = std::path::Path::new(output_path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    let mut out_blob = Vec::with_capacity(16 + 12 + ciphertext.len());
    out_blob.extend_from_slice(&salt);
    out_blob.extend_from_slice(&nonce);
    out_blob.extend_from_slice(&ciphertext);
    std::fs::write(output_path, &out_blob).map_err(|e| format!("Failed to write {}: {}", output_path, e))?;
    Ok(())
}
