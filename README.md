# Advanced Folder Locker

A secure Python application for encrypting and protecting folders with password authentication.

## Features

- **Military-grade encryption**: AES-256 encryption with PBKDF2 key derivation
- **Password protection**: Secure password hashing and verification
- **User-friendly GUI**: Modern tkinter interface
- **Folder compression**: Automatic compression before encryption
- **Password management**: Encrypted password storage for convenience
- **Activity logging**: Real-time operation feedback

## Installation

1. Install Python 3.7 or higher
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   python main.py
   ```

2. **Lock a Folder**:
   - Click "🔐 Lock Folder"
   - Select the folder you want to protect
   - Enter a strong password (minimum 6 characters)
   - Confirm the password
   - The folder will be encrypted and the original deleted

3. **Unlock a Folder**:
   - Click "🔓 Unlock Folder"
   - Select the `.locked` file
   - Enter the correct password
   - The folder will be restored to its original location

4. **View Locked Folders**:
   - Click "📋 View Locked Folders" to see all currently locked folders

5. **Clear Saved Passwords**:
   - Click "🗑️ Clear All Saved Passwords" to remove all stored password hashes

## Security Features

- **AES-256 Encryption**: Industry-standard encryption algorithm
- **PBKDF2 Key Derivation**: 100,000 iterations for password-based key generation
- **Salt-based Hashing**: Unique salt for each password to prevent rainbow table attacks
- **Secure Password Storage**: Passwords are hashed and stored securely
- **Memory Safety**: Sensitive data is handled securely in memory

## File Structure

- `main.py`: Application entry point
- `config.py`: Configuration and password management
- `encryption_manager.py`: Core encryption/decryption functionality
- `gui_manager.py`: User interface components
- `requirements.txt`: Python dependencies

## How It Works

1. **Encryption Process**:
   - Folder contents are compressed into a ZIP archive
   - A random salt is generated for key derivation
   - Password is used with PBKDF2 to generate encryption key
   - ZIP archive is encrypted using AES-256
   - Original folder is securely deleted
   - Encrypted file is saved with `.locked` extension

2. **Decryption Process**:
   - Salt is extracted from the encrypted file
   - Password is verified against stored hash (if available)
   - Encryption key is regenerated using password and salt
   - File is decrypted and extracted as ZIP archive
   - Original folder structure is restored
   - Encrypted file is deleted

## Security Notes

- Always use strong, unique passwords
- Keep your passwords safe - there's no recovery option
- The application stores password hashes locally for convenience
- Original folders are permanently deleted after encryption
- Encrypted files should be backed up safely

## Troubleshooting

- **"Incorrect password" error**: Ensure you're entering the exact password used for encryption
- **"Folder not found" error**: Make sure the selected folder exists and is accessible
- **"Permission denied" error**: Run the application with appropriate permissions
- **Encryption fails**: Ensure the folder is not empty and you have write permissions


