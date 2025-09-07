use aes_gcm::{Aes256Gcm, aead::Aead, KeyInit};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;
use rpassword::read_password;

/// Load and decrypt a 32-byte Data Encryption Key (DEK) saved in the
/// binary format: [16 byte salt][12 byte nonce][ciphertext].
///
/// The function prompts the user for the KEK (password) on stdin.
pub fn load_dek_from_encrypted(path: &str) -> Result<[u8; 32], String> {
    let dek_blob = std::fs::read(path).map_err(|e| format!("Failed to read {}: {}", path, e))?;
    if dek_blob.len() < 16 + 12 + 16 {
    return Err("Encrypted DEK file is too small or malformed".to_string());
    }
    let salt = &dek_blob[0..16];
    let nonce = &dek_blob[16..28];
    let ciphertext = &dek_blob[28..];

    use std::io::{self, Write};
    print!("Enter KEK (password) to decrypt DEK: ");
    io::stdout().flush().ok();
    let kek = read_password().map_err(|_| "Failed to read KEK".to_string())?;
    let mut kek_derived = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(kek.as_bytes(), salt, 100_000, &mut kek_derived);
    let kek_cipher = Aes256Gcm::new_from_slice(&kek_derived).map_err(|_| "Invalid KEK-derived key".to_string())?;
    let nonce_ga = aes_gcm::aead::generic_array::GenericArray::<u8, typenum::U12>::from_slice(nonce);
    let dek_bytes = kek_cipher.decrypt(nonce_ga, ciphertext.as_ref()).map_err(|_| "Failed to decrypt dek.bin: wrong KEK or corrupted file".to_string())?;
    if dek_bytes.len() != 32 { return Err("Decrypted DEK has invalid length".to_string()); }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&dek_bytes);
    Ok(arr)
}
