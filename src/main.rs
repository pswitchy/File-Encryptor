use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use aes_gcm::aead::generic_array::typenum::{U12}; // Only U12 is needed
use anyhow::{anyhow, Context, Result};
use bincode::{deserialize, serialize};
use clap::{Parser, Subcommand};
use hmac::Hmac;   // Only Hmac trait is directly used here
use pbkdf2::pbkdf2;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

const KEY_LENGTH: usize = 32; // 256 bits for AES
const SALT_LENGTH: usize = 16;
const PBKDF2_ITERATIONS: u32 = 100_000; // Adjust as needed
const NONCE_LENGTH: usize = 12;

#[derive(Serialize, Deserialize)]
struct EncryptionMetadata {
    nonce: [u8; NONCE_LENGTH],
    salt: [u8; SALT_LENGTH],
}


#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        #[arg(short, long, value_name = "FILE")]
        input_path: String,
        #[arg(short, long, value_name = "FILE")]
        output_path: String,
        #[arg(short, long, value_name = "PASSWORD")]
        password: String,
    },
    Decrypt {
        #[arg(short, long, value_name = "FILE")]
        input_path: String,
        #[arg(short, long, value_name = "FILE")]
        output_path: String,
        #[arg(short, long, value_name = "PASSWORD")]
        password: String,
    },
}

fn read_file_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path).with_context(|| format!("Could not open file {path:?}"))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .with_context(|| format!("Error reading file at path: {path:?}"))?;
    Ok(buffer)
}

fn write_file_bytes(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = fs::File::create(path).with_context(|| format!("Error creating file {path:?}"))?;
    file.write_all(data)
        .with_context(|| format!("Error writing to file at path: {path:?}"))?;
    Ok(())
}

fn derive_key(password: &str, salt: &[u8]) -> Key<Aes256Gcm> {
    let mut key_bytes = [0u8; KEY_LENGTH];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key_bytes);
    Key::<Aes256Gcm>::from_slice(&key_bytes).to_owned() // Explicit Key type
}


fn generate_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn generate_nonce() -> [u8; NONCE_LENGTH] {
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce_bytes);
    nonce_bytes
}

fn encrypt(key: &Key<Aes256Gcm>, nonce: &[u8; NONCE_LENGTH], data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key);
    let nonce_obj = Nonce::<U12>::from_slice(nonce);
    cipher.encrypt(&nonce_obj, data).map_err(|e| anyhow!(e))  // Use anyhow!
}

fn decrypt(key: &Key<Aes256Gcm>, nonce: &[u8; NONCE_LENGTH], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key);
    let nonce_obj = Nonce::<U12>::from_slice(nonce);
    cipher.decrypt(&nonce_obj, ciphertext).map_err(|e| anyhow!(e))
}


fn encrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<()> {
    // 1. Read input file
    let input_path = Path::new(input_path);
    let plain_text_bytes = read_file_bytes(input_path)?;

    // 2. Generate salt and key
    let salt = generate_salt();
    let key = derive_key(password, &salt);

    // 3. Generate nonce
    let nonce = generate_nonce();

    // 4. Create and serialize metadata
    let metadata = EncryptionMetadata { nonce, salt };
    let metadata_bytes = serialize(&metadata)?;

    // 5. Encrypt data
    let encrypted_data = encrypt(&key, &nonce, &plain_text_bytes)
        .with_context(|| "Error during encryption")?;

    // 6. Combine metadata and encrypted data
    let mut full_encrypted_data = metadata_bytes;
    full_encrypted_data.extend_from_slice(&encrypted_data);

    // 7. Write to output file
    let output_path = Path::new(output_path);
    write_file_bytes(output_path, &full_encrypted_data)?;

    println!("Encryption complete: {}", output_path.display());
    Ok(())
}

fn decrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<()> {
    let input_path = Path::new(input_path);
    let encrypted_data = read_file_bytes(input_path)?;

    let metadata_length = serialize(&EncryptionMetadata {
        nonce: generate_nonce(),
        salt: generate_salt(),
    })
    .unwrap()
    .len();
    let (metadata_bytes, encrypted_data) = encrypted_data.split_at(metadata_length);

    let metadata: EncryptionMetadata = deserialize(metadata_bytes)?;
    let key = derive_key(password, &metadata.salt);


    let decrypted_data = decrypt(&key, &metadata.nonce, encrypted_data)
        .with_context(|| "Error during decryption")?;

    let output_path = Path::new(output_path);
    write_file_bytes(output_path, &decrypted_data)?;

    println!(
        "Decryption complete, decrypted file saved at: {}",
        output_path.display()
    );
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Encrypt {
            input_path,
            output_path,
            password,
        } => encrypt_file(input_path, output_path, password)?,
        Commands::Decrypt {
            input_path,
            output_path,
            password,
        } => decrypt_file(input_path, output_path, password)?,
    };

    Ok(())
}