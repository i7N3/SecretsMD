//! This is a POC for encrypting and decrypting markdown files.
//! Build as an interactive CLI application using the `inquire` crate.
use base64::{engine::general_purpose, Engine as _};
use inquire::{
    error::InquireResult, required, InquireError, Password, PasswordDisplayMode, Select, Text,
};
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::rand::rand_bytes;
use openssl::symm::{decrypt, encrypt, Cipher};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::Command;
use std::{fs, path::Path};

// EncodedFile: Represents the structure for storing encrypted file details.
#[derive(Serialize, Deserialize)]
struct EncodedFile {
    version: String,      // Version of the file format, for future compatibility.
    hint: String,         // Field to store the hint for the password
    encoded_data: String, // Base64-encoded encrypted data.
}

// WARNING: The static SALT and IV are used for demonstration purposes only.
// FOR PROD: Generate a unique values for each encryption and store it securely.
const SALT: &[u8; 32] = b"12345678901234567890123456789012";
const IV: &[u8; 16] = b"1234567890123456";

const CLI_OPTIONS: &[&str; 3] = &["Encrypt a .md file", "Decrypt a .md.enc file", "Exit"];

fn main() -> InquireResult<()> {
    loop {
        clear_screen();
        println!("--- Secrets md POC ---\n");

        let selection = Select::new("Select an option:", CLI_OPTIONS.to_vec()).prompt()?;

        if selection == CLI_OPTIONS[0] {
            encrypt_file_workflow()?;
        } else if selection == CLI_OPTIONS[1] {
            decrypt_file_workflow()?;
        } else if selection == CLI_OPTIONS[2] {
            break;
        }
    }

    Ok(())
}

fn encrypt_aes_256(data: &[u8], password: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let cipher = Cipher::aes_256_cbc();
    let mut key = [0u8; 32];
    pbkdf2_hmac(password, SALT, 1000, MessageDigest::sha256(), &mut key)?;

    encrypt(cipher, &key, Some(IV), data)
}

fn encrypt_file_workflow() -> InquireResult<()> {
    let mut files = get_md_files()?;
    if files.is_empty() {
        println!("No .md files found in the current directory.");
        println!("Press Enter to return to the main menu.");
        let _ = Text::new("").prompt()?;
        return Ok(());
    }

    files.push("Back to main menu".to_string());
    let file_path = Select::new("Choose a .md file to encrypt or go back:", files).prompt()?;

    if file_path == "Back to main menu" {
        return Ok(());
    }

    let password = Password::new("Enter the password for encryption:")
        .with_validator(required!("Password cannot be empty"))
        .with_display_mode(PasswordDisplayMode::Masked)
        .prompt()?;

    let hint = Text::new("Enter a hint for the password (optional):").prompt()?;

    let contents = read_file(&file_path)?;

    let mut salt = [0u8; 32];
    let _ = rand_bytes(&mut salt);

    let encrypted = encrypt_aes_256(contents.as_bytes(), password.as_bytes()).unwrap();
    let base64_encoded = general_purpose::STANDARD.encode(&encrypted);

    let encoded_file = EncodedFile {
        hint,
        version: "1.0.0".to_string(),
        encoded_data: base64_encoded,
    };

    let file_name = Path::new(&file_path).file_name().unwrap().to_str().unwrap();
    let enc_file_path = format!(".{}.enc", file_name);

    write_to_file(&enc_file_path, &encoded_file)?;
    fs::remove_file(&file_path)?;

    Ok(())
}

fn decrypt_aes_256(
    encrypted_data: &[u8],
    password: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let cipher = Cipher::aes_256_cbc();
    let mut key = [0u8; 32];
    pbkdf2_hmac(password, SALT, 1000, MessageDigest::sha256(), &mut key)?;

    decrypt(cipher, &key, Some(IV), encrypted_data)
}

fn decrypt_file_workflow() -> InquireResult<()> {
    let mut files = get_md_enc_files()?;
    if files.is_empty() {
        println!("No .md.enc files found in the current directory.");
        println!("Press Enter to return to the main menu.");
        let _ = Text::new("").prompt()?;
        return Ok(());
    }

    files.push("Back to main menu".to_string());
    let file_path = Select::new("Choose a .md.enc file to decrypt or go back:", files).prompt()?;

    if file_path == "Back to main menu" {
        return Ok(());
    }

    let file_contents = read_file(&file_path).map_err(InquireError::from)?;
    let decoded_file: EncodedFile =
        serde_json::from_str(&file_contents).map_err(|e| InquireError::Custom(Box::new(e)))?;

    if !decoded_file.hint.is_empty() {
        println!("Hint for the password: {}", decoded_file.hint);
    }

    let base64_decoded = general_purpose::STANDARD
        .decode(decoded_file.encoded_data.as_bytes())
        .unwrap();

    loop {
        let password = Password::new("Enter the password for decryption:")
            .with_validator(required!("Password cannot be empty"))
            .with_display_mode(PasswordDisplayMode::Masked)
            .prompt()?;

        match decrypt_aes_256(&base64_decoded, password.as_bytes()) {
            Ok(decrypted_data) => {
                let decrypted_string = String::from_utf8(decrypted_data)
                    .map_err(|e| InquireError::Custom(Box::new(e)))?;

                let decrypted_file_name = Path::new(&file_path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default()
                    .trim_start_matches('.')
                    .trim_end_matches(".enc");

                let decrypted_file_path = format!("./{}", decrypted_file_name);
                write_plain_text_to_file(&decrypted_file_path, &decrypted_string)?;

                fs::remove_file(&file_path)?;
                break; // Exit the loop on successful decryption
            }
            Err(_) => {
                println!("Decryption failed. Incorrect password, try again.");
                // The loop will continue, allowing for another attempt.
            }
        }
    }

    Ok(())
}

fn get_md_files() -> io::Result<Vec<String>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(".")? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "md") {
            files.push(path.to_string_lossy().into_owned());
        }
    }
    Ok(files)
}

fn get_md_enc_files() -> io::Result<Vec<String>> {
    let mut files = Vec::new();
    let entries = fs::read_dir(".")?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        // Checking if the file name (excluding the path) ends with ".md.enc"
        if let Some(filename) = path.file_name().and_then(|s| s.to_str()) {
            if filename.ends_with(".md.enc") {
                files.push(path.to_string_lossy().into_owned());
            }
        }
    }

    Ok(files)
}

fn read_file(file_path: &str) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn write_to_file(file_path: &str, encoded_file: &EncodedFile) -> io::Result<()> {
    let mut file = File::create(file_path)?;
    let json = serde_json::to_string_pretty(encoded_file)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

fn write_plain_text_to_file(file_path: &str, data: &str) -> io::Result<()> {
    let mut file = File::create(file_path)?;
    file.write_all(data.as_bytes())?;
    Ok(())
}

fn clear_screen() {
    let _ = Command::new("clear").status();
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::rand::rand_bytes;

    #[cfg(test)]
    mod file_tests {
        use super::*;
        use std::fs;

        #[test]
        fn test_file_read_write() {
            let test_data = "Test file data";
            let test_file = "test_file.txt";

            write_plain_text_to_file(test_file, test_data).unwrap();
            let read_data = read_file(test_file).unwrap();

            fs::remove_file(test_file).unwrap(); // Clean up

            assert_eq!(test_data, read_data);
        }
    }

    #[test]
    fn test_decrypt_with_incorrect_password() {
        let correct_password = b"correct_password";
        let incorrect_password = b"incorrect_password";
        let data = "Test data".as_bytes();

        let encrypted = encrypt_aes_256(data, correct_password).unwrap();

        // Attempt decryption with the incorrect password
        let decryption_result = decrypt_aes_256(&encrypted, incorrect_password);

        assert!(decryption_result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_in_place() {
        let password = b"password";
        let original = "Hello, world!";

        let mut salt = [0u8; 32];
        rand_bytes(&mut salt).unwrap();

        let encrypted = encrypt_aes_256(original.as_bytes(), password).unwrap();
        let decrypted = decrypt_aes_256(&encrypted, password).unwrap();

        assert_eq!(original.as_bytes(), decrypted.as_slice());
    }

    #[test]
    fn test_full_encode_decode_flow() -> Result<(), Box<dyn std::error::Error>> {
        let original_text = "Hello, world!";
        let password = b"test-password";
        let file_path = "test.md";
        let enc_file_path = ".test.md.enc";

        // Create and write original text to 'test.md'
        write_plain_text_to_file(file_path, original_text)?;

        // Step 1: Read the contents from the file
        let contents = read_file(file_path)?;

        // Generate a random salt for use in the key derivation function.
        let mut salt = [0u8; 32];
        rand_bytes(&mut salt)?;

        // Step 2: Encrypt and encode the original text

        // Encrypt the contents using AES-256.
        let encrypted = encrypt_aes_256(contents.as_bytes(), password)?;
        // Encode the encrypted data to base64.
        let base64_encoded = general_purpose::STANDARD.encode(&encrypted);

        // Create an instance of EncodedFile with the encoded data.
        let encoded_file = EncodedFile {
            version: "1.0.0".to_string(),
            hint: "".to_string(),
            encoded_data: base64_encoded,
        };

        // Step 3: Write encoded data to file
        write_to_file(enc_file_path, &encoded_file)?;

        // Step 4: Read and decode the file

        // Read the contents of the encrypted file.
        let file_contents = read_file(enc_file_path)?;
        // Deserialize the JSON content to EncodedFile.
        let decoded_file: EncodedFile = serde_json::from_str(&file_contents)?;
        // Decode the base64 encoded data.
        let base64_decoded =
            general_purpose::STANDARD.decode(decoded_file.encoded_data.as_bytes())?;

        // Step 5: Decrypt the data
        let decrypted_data = decrypt_aes_256(&base64_decoded, password)?;
        // Convert the decrypted data back to a string.
        let decrypted_string = String::from_utf8(decrypted_data)?;

        // Step 6: Assert that the decrypted data matches the original
        assert_eq!(decrypted_string, original_text);

        // Cleanup: Remove test files
        fs::remove_file(enc_file_path)?;
        fs::remove_file(file_path)?;

        Ok(())
    }
}
