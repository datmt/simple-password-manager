# Go Password Manager

A simple, secure, and cross-platform command-line password manager written in Go, inspired by the robustness of a Bash script. It provides essential features for managing your sensitive credentials locally with strong encryption.

-----

## ✨ Features

  * **Secure Storage:** Passwords are encrypted using **AES-256-CFB** mode.
  * **Master Password Protection:** A single master password secures all your stored credentials.
  * **PBKDF2 Key Derivation:** The encryption key is securely derived from your master password and a unique salt using **PBKDF2**, ensuring strong key protection.
  * **Hashed Master Password:** Your master password itself is never stored; only its secure **SHA-256 hash** is kept for authentication.
  * **Persistent Symmetric Key:** A unique symmetric key is generated once and encrypted by your master password, allowing consistent decryption of old passwords even if the master password is changed (as long as you know the *current* master password).
  * **Session Management:** Includes a session timeout to automatically lock the manager after a period of inactivity (15 minutes).
  * **Clipboard Integration:** Easily copy passwords to your clipboard for quick pasting.
  * **Cross-Platform:** Built with Go, it compiles into a single binary for Linux, Windows, and macOS.

-----

## 🚀 Getting Started

These instructions will get you a copy of the project up and running on your local machine.

### Prerequisites

You need [Go](https://golang.org/doc/install) installed on your system (version 1.18 or higher recommended).

### Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/datmt/simple-password-manager.git
    cd simple-password-manager 
    ```


2.  **Download dependencies:**

    ```bash
    go mod download
    ```

### First-Time Setup (Setting Your Master Password)

The first time you use any command that requires authentication (like `add`, `view`, `list`, etc.), the application will prompt you to set up your master password and initialize necessary files.

1.  Run the `add` command with any dummy key/value pair to trigger the setup:

    ```bash
    go run main.go add first-password example123
    ```

2.  The application will prompt:

    ```
    Enter master password:
    Master password and symmetric key not set. Performing initial setup.
    Master password hash set.
    Symmetric key encrypted and saved.
    Password added.
    ```

    Enter a strong, memorable master password when prompted. This master password will be used to protect your symmetric encryption key and authenticate future access.

    **Important:** Three files will be created in your project directory: `.master` (stores the master password hash), `.salt` (stores the salt for PBKDF2), and `.symkey.enc` (stores your encrypted symmetric encryption key). **Do NOT delete these files**, and **do NOT commit them to Git** as they contain critical security information.

-----

## 🛠️ Usage

Once set up, you can use the following commands. Each command that accesses encrypted data will prompt for your master password if the session has timed out (default 15 minutes).

  * **`add <key> <value>`**: Adds a new password entry. If the key already exists, it will not be overwritten.

    ```bash
    go run main.go add github myStrongPassword!
    ```

  * **`view <key>`**: Retrieves and decrypts the password for the given key.

    ```bash
    go run main.go view github
    ```

  * **`update <key> <newValue>`**: Updates the password for an existing key.

    ```bash
    go run main.go update github newUpdatedPassword!
    ```

  * **`delete <key>`**: Deletes the password entry associated with the given key.

    ```bash
    go run main.go delete github
    ```

  * **`list`**: Lists all available keys (password names) stored in the manager.

    ```bash
    go run main.go list
    ```

  * **`copy <key>`**: Decrypts the password for the given key and copies it to your system's clipboard.

    ```bash
    go run main.go copy github
    ```

-----

## 🔒 Security Details

The project employs robust cryptographic practices:

  * **Master Password Hashing:** Your master password is never stored directly. Instead, its SHA-256 hash is stored in the `.master` file for authentication.
  * **Key Derivation Function (PBKDF2):** The actual AES-256 symmetric encryption key is derived from your master password and a unique salt using PBKDF2 with 100,000 iterations. This makes brute-forcing significantly harder. The salt is stored in the `.salt` file.
  * **Encrypted Symmetric Key (`.symkey.enc`):** A randomly generated AES-256 symmetric key is created once and encrypted using a key derived from your master password. This encrypted symmetric key is stored in `.symkey.enc`. This allows the core encryption key for your passwords to remain constant, while the master password serves as the "unlocking mechanism" for this key.
  * **AES-256-CFB Encryption:** Passwords are encrypted using the industry-standard AES-256 algorithm in Cipher Feedback (CFB) mode, ensuring strong confidentiality. A unique Initialization Vector (IV) is used for each encryption.
  * **Session Timeout:** For added security, the manager automatically requires re-authentication after 15 minutes of inactivity.
  * **Secure Password Input:** The master password input uses `golang.org/x/term` to prevent the password from being echoed to the console history.

-----

## 📦 Building for Distribution

Go's cross-compilation features allow you to build a single executable binary for various operating systems (Linux, Windows, macOS) from your development machine.

The project includes a `build.sh` script to automate this process.

1.  **Make the script executable:**
    ```bash
    chmod +x build.sh
    ```
2.  **Run the build script:**
    ```bash
    ./build.sh
    ```
    This will create a `build/` directory containing binaries for different platforms (Linux, Windows, macOS for both AMD64 and ARM64 architectures, and Linux ARMv7).

### Automated Releases with GitHub Actions

This project is configured to automatically build and create GitHub Releases when you push a new Git tag starting with `v` (e.g., `v1.0.0`).

To trigger a release:

1.  Commit all your changes.
2.  Create a new Git tag:
    ```bash
    git tag -a v1.0.0 -m "Release v1.0.0 - Initial stable version"
    ```
3.  Push the tag to your GitHub repository:
    ```bash
    git push origin v1.0.0
    ```
    GitHub Actions will then take over, build binaries for all specified platforms, and attach them to a new release on your repository's "Releases" page.

-----

## 🤝 Contributing

Contributions are welcome\! If you have suggestions for improvements or find a bug, please open an issue or submit a pull request.

-----

## 📄 License

MIT

