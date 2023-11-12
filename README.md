# Secrets MD 🔑

## Introduction 🌟

Secrets md POC is a command-line application designed for encrypting and decrypting Markdown files. This Proof of Concept (POC) combines advanced security features with an interactive CLI interface, using the Rust programming language. It's built for users who seek a secure way to handle Markdown documents, ensuring confidentiality through robust encryption.

## Key Features 🛠️

-   **Markdown File Encryption/Decryption:** Encrypts .md files into .md.enc format with strong AES-256 encryption. And vise-versa.
-   **Interactive CLI:** Offers a user-friendly, interactive command-line interface for effortless encryption and decryption operations.
-   **Password Protection:** Utilizes a password-based encryption system, complemented by an optional hint feature for password recall.
-   **Security First:** Implements OpenSSL for encryption, ensuring a high level of security.

## Installation 🚀

-   **Prerequisites:** Ensure you have Rust and Cargo installed on your system.
-   **Clone the Repository:** `git clone [repository-url]`
-   **Run the Application:** Navigate to the project directory and run `cargo run`

## Usage 📖

-   **Encrypt a Markdown File:**
    -   Choose 'Encrypt a .md file' from the menu.
    -   Follow the prompts to select a file, enter a password, and an optional hint.
-   **Decrypt a Markdown File:**
    -   Select 'Decrypt a .md.enc file'.
    -   Choose the file and enter the correct password to decrypt.

## Testing 🧪

-   Run `cargo test` to execute the test suite and verify the application's functionality.

## Contributing 💡

Contributions are welcome to refine and expand the capabilities of Secrets md POC. Feel free to suggest improvements, report bugs, or submit pull requests for new features or enhancements.

## Security Disclaimer ⚠️

The static SALT and IV values in the code are for demonstration purposes only. In a production environment, it's crucial to use dynamically generated, unique values for each encryption instance to ensure optimal security.
