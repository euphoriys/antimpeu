use std::io::{Read, Write};
use std::net::TcpStream;

/// Write a length-prefixed plaintext message to `stream`.
/// The length is a big-endian u32 followed by the raw bytes.
pub fn write_plain(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    let len_bytes = (data.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes)?;
    stream.write_all(data)?;
    stream.flush()?;
    Ok(())
}

/// Read a length-prefixed plaintext message from `stream`.
pub fn read_plain(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;
    let mut buffer = vec![0u8; msg_len];
    stream.read_exact(&mut buffer)?;
    Ok(buffer)
}
