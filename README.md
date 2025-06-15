# File Locker

A secure desktop application for encrypting and decrypting files using password-based AES encryption with a simple, intuitive GUI.

## Overview

File Locker is a Python desktop tool that provides secure file encryption and decryption capabilities. The application features a modern dark mode interface and handles the complete encryption workflow - from securing your original files to safely restoring them when needed.

## Features

- **🌙 Dark Mode UI** - Modern, easy-on-the-eyes interface
- **🔒 Secure Encryption** - Files are encrypted and saved with `.locked` extension
- **🗑️ Automatic Cleanup** - Original files are securely deleted after encryption
- **🔓 Easy Decryption** - Decrypt `.locked` files and restore originals
- **🛡️ Password-Based Security** - AES encryption with user-defined passwords
- **📁 Drag & Drop Support** - Simple file selection interface
- **⚡ Batch Processing** - Handle multiple files at once

## Technologies

- **Python** - Core application language
- **PyQt6** - Modern GUI framework
- **cryptography** - Industry-standard encryption library

## Installation

### Prerequisites

Ensure you have Python 3.7 or higher installed on your system.

### Install Dependencies

```bash
pip install PyQt6 cryptography pyperclip
```

### Download and Run

1. Download all project files to a folder
2. Navigate to the project directory
3. Run the application:

```bash
python "RUN ME.py"
```

## Usage

### Encrypting Files

1. Launch  File Locker
2. Drag and drop files into the application or use "Add Files" button
3. Enter a strong password in the password field
4. Click "Lock Selected Items"
5. Your original files will be encrypted and saved as `.locked` files
6. Original files are automatically deleted for security

### Decrypting Files

1. Select your `.locked` files using drag & drop or file browser
2. Enter the correct password used for encryption
3. Click "Unlock Selected Items"
4. Files are decrypted and restored to their original format
5. `.locked` files are automatically deleted after successful decryption

### Security Tips

- Use strong, unique passwords for encryption
- Remember your passwords - they cannot be recovered if lost
- Keep backups of important files before encryption (optional)
- The application includes password strength indicators to help create secure passwords

## File Behavior

- **Encryption**: `document.pdf` → `document.pdf.locked` (original deleted)
- **Decryption**: `document.pdf.locked` → `document.pdf` (.locked file deleted)

## System Requirements

- **Operating System**: Windows, macOS, or Linux
- **Python**: Version 3.7 or higher
- **RAM**: Minimum 512MB available memory
- **Storage**: Sufficient space for encrypted file copies during processing

## Troubleshooting

### Common Issues

**Missing Dependencies Error**
```bash
pip install --upgrade PyQt6 cryptography pyperclip
```

**Permission Errors**
- Run as administrator (Windows) or with sudo (Linux/macOS) if needed
- Ensure write permissions in the target directory

**Password Issues**
- Passwords are case-sensitive
- Ensure no extra spaces before/after password
- Use the exact same password used for encryption

## Author

**Othman Muhammad**
- Email: othmanmuhammad.personal@gmail.com

## License

This project is released under the MIT License.

```
MIT License

Copyright (c) 2025 Othman Muhammad

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Disclaimer

This software is provided for legitimate file protection purposes. Users are responsible for:
- Remembering their encryption passwords
- Backing up important files before encryption
- Using the software in compliance with local laws and regulations
- Understanding that lost passwords cannot be recovered

---

**STARK File Locker** - Secure, Simple, Reliable File Protection



