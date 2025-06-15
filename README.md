# 🔐 Advanced Folder Locker v3.0.0 - Simplified Version

A comprehensive, easy-to-use file and folder encryption tool with military-grade security and a beautiful blue interface. **No master password required** - just run and use!

## ✨ Key Features

### 🔒 Security Features
- **Military-grade AES-256 encryption** with PBKDF2 key derivation
- **Double Lock** system for extra security on important files
- **Timed Lock** functionality (1 minute to 100 years)
- **Fake Unlock** system after 10 wrong password attempts
- **Stealth Mode** with self-destruct after 20 wrong attempts
- **Clear Evidence** mode - securely deletes original files
- **Emergency Unlock** system via email verification

### 🎨 Beautiful Interface
- **Modern Blue Theme** - Easy on the eyes with professional appearance
- **Multi-language Support**: English, German, French
- **Drag & Drop** interface with visual feedback
- **No Animations** - Fast and responsive
- **Simple Navigation** - Three main tabs: Main, Settings, About
- **Real-time Notifications** with clear feedback

### 🔑 Password Management
- **Simple Password Manager** with masked display
- **Strong Password Generator** with auto-clipboard copy
- **Search and Filter** functionality
- **Export/Import** capabilities
- **No Master Password Required** - Simplified for ease of use

### 📁 File Support
Supports all major file formats including:
- **Documents**: PDF, DOC, DOCX, TXT, RTF, ODT
- **Images**: JPG, PNG, GIF, BMP, SVG, WEBP
- **Videos**: MP4, MKV, AVI, MOV, WMV
- **Audio**: MP3, WAV, AAC, FLAC, OGG
- **Code**: PY, JS, HTML, CSS, PHP, JAVA, C, CPP
- **Archives**: ZIP, RAR, 7Z, TAR, GZ
- **Executables**: EXE, MSI, BAT, SH, APK, APP

## 🚀 Quick Start

### Prerequisites
Install required packages:
```bash
pip install cryptography
pip install tkinterdnd2
pip install pyperclip  # Optional, for clipboard functionality
```

### Installation
1. Download all files to the same directory:
   - `RUN ME.py`
   - `gui_manager.py`
   - `encryption_manager.py`
   - `config.py`

2. Run the application:
```bash
python "RUN ME.py"
```

### First Use
1. Launch the application - no setup required!
2. The beautiful blue interface will appear
3. Start encrypting files immediately

## 📖 How to Use

### Locking Files/Folders

#### Method 1: Drag & Drop (Easiest)
1. Simply **drag and drop** files/folders into the blue drop zone
2. Files will appear in the "Selected Items" list
3. Enter a strong password
4. Click **"🔒 Lock Selected Items"**

#### Method 2: File Selection
1. Click **"📁 Add Files"** or **"📂 Add Folder"**
2. Choose your files/folders
3. Enter a strong password
4. Optional: Enable **Double Lock** for extra security
5. Optional: Enable **Timed Lock** for automatic unlock
6. Click **"🔒 Lock Selected Items"**

### Unlocking Files/Folders
1. Select locked files (they have `.locked` extension)
2. Enter the correct password
3. Click **"🔓 Unlock Selected Items"**

### Advanced Features

#### Password Manager
- Click **"🔑 Password Manager"** to view saved passwords
- Passwords are masked for security: `abc***xyz`
- Select items and click **"👁️ Show Selected"** to reveal passwords
- Search, filter, and export your passwords

#### Security Options
- **🔒 Double Lock**: Applies two layers of encryption
- **⏰ Timed Lock**: Automatically unlock after specified time
- **🎲 Generate Strong Password**: Creates secure 16-character passwords

#### Important File Detection
The tool automatically detects important files containing keywords like:
- bank, banking, password, secret, private
- money, finance, credit, account, crypto, bitcoin
- And suggests using **Double Lock** for extra security

## ⚙️ Settings

### Language Support
- **English** 🇺🇸
- **Deutsch** 🇩🇪 (German)
- **Français** 🇫🇷 (French)

### Security Options
- **🎭 Fake Unlock System**: Creates empty files after 10 wrong attempts
- **👻 Stealth Mode**: Self-destructs after 20 wrong passwords
- **🧹 Clear Evidence**: Securely deletes original files after encryption

### Performance Settings
- **💾 Memory Efficient Mode**: Optimizes for low memory usage
- **🚀 Parallel Operations**: Enables multi-threaded processing

## 🔧 Technical Details

### Encryption Specifications
- **Algorithm**: AES-256 in Fernet mode
- **Key Derivation**: PBKDF2 with SHA-256
- **Iterations**: 100,000 (high security)
- **Salt Length**: 32 bytes (cryptographically secure)
- **Chunk Size**: 64KB for efficient large file handling

### File Structure
```
original_file.txt → original_file.txt.locked + original_file.txt.lockinfo
```

### Metadata Storage
Each encrypted file includes:
- Original filename and size
- Encryption timestamp
- File integrity hash (SHA-256)
- Security settings (double lock status)
- File type classification

## 🛡️ Security Best Practices

### Password Guidelines
1. **Use strong passwords** (16+ characters)
2. **Mix uppercase, lowercase, numbers, and symbols**
3. **Avoid common words or personal information**
4. **Use the built-in password generator**

### Security Recommendations
1. **Enable Double Lock** for sensitive files
2. **Use Timed Lock** for temporary security
3. **Keep backups** of important unencrypted data
4. **Test passwords** before encrypting important files

## 📋 Keyboard Shortcuts

| Shortcut | Action |
|----------|---------|
| `F11` | Toggle fullscreen |
| `Ctrl+O` | Select files |
| `Ctrl+Shift+O` | Select folder |
| `Ctrl+L` | Lock items |
| `Ctrl+U` | Unlock items |
| `Ctrl+G` | Generate password |
| `Ctrl+P` | Password manager |
| `Delete` | Clear selection |
| `F5` | Refresh interface |
| `Ctrl+Q` | Exit application |

## 🐛 Troubleshooting

### Common Issues

**"Missing Dependencies" Error**
```bash
pip install cryptography tkinterdnd2 pyperclip
```

**"Import Error" Message**
- Ensure all files are in the same directory
- Check Python version (3.7+ required)
- Verify all required packages are installed

**Drag & Drop Not Working**
- Install tkinterdnd2: `pip install tkinterdnd2`
- Restart the application
- Try using the file selection buttons instead

**Password Manager Empty**
- Lock some files first to populate the manager
- Passwords are automatically saved when you encrypt files

### File Recovery
If you lose your password:
1. Use the **Emergency Unlock** system
2. Click **"🆘 Emergency Unlock"** button
3. Email: `othmanmuhammad.personal@gmail.com`
4. Include file details and proof of ownership

## 🔄 What's New in v3.0.0

### Major Improvements
- **🎨 Beautiful Blue Theme**: Professional, easy-to-read interface
- **🚀 No Master Password**: Simplified for maximum ease of use
- **🌐 Multi-language**: German and French support added
- **⚡ No Animations**: Faster, more responsive interface
- **🔧 Bug Fixes**: Improved stability and performance

### Simplified Features
- **One-click encryption**: Just drag, drop, and encrypt
- **Clear visual feedback**: Always know what's happening
- **Intuitive interface**: No technical knowledge required
- **Instant access**: No complex setup or authentication

## 📞 Support & Contact

### Developer Contact
- **📧 Email**: othmanmuhammad.personal@gmail.com
- **🆘 Emergency Unlock**: Same email with file details

### Getting Help
When contacting for support, please include:
1. Your operating system and Python version
2. Error message (if any)
3. Steps to reproduce the issue
4. Screenshots (if applicable)

### Reporting Issues
- **Bug reports**: Email with detailed description
- **Feature requests**: Suggestions are welcome
- **Security concerns**: Please report responsibly

## 📄 License & Disclaimer

© 2024 Advanced Folder Locker. All rights reserved.

### Important Notes
- This software is provided "as is" without warranty
- Users are responsible for keeping passwords secure
- Create backups of important data before encryption
- Lost passwords cannot be recovered without emergency unlock process

### Security Notice
The encryption used is **military-grade** and designed to be unbreakable. This means:
- **Forgotten passwords cannot be recovered** without the emergency unlock process
- **Files are permanently protected** until the correct password is provided
- **Your data is safe** even from the developers without the password

## 🌟 Why Choose This Tool?

### ✅ Advantages
- **🔒 Military-grade security** - Your files are truly safe
- **🎨 Beautiful interface** - Professional blue theme
- **🚀 Easy to use** - No complex setup or master passwords
- **🌐 Multi-language** - Works in your preferred language
- **📱 Drag & drop** - Intuitive file management
- **🔑 Password manager** - Never lose passwords again
- **⚡ Fast performance** - No unnecessary animations
- **🛡️ Advanced features** - Double lock, timed lock, stealth mode

### 🎯 Perfect For
- **Personal files** - Photos, documents, videos
- **Business data** - Financial records, contracts, client data
- **Sensitive information** - Passwords, bank details, personal records
- **Temporary security** - Files that need protection for a specific time
- **Multiple users** - Different languages, easy interface

---

**Remember**: Your security is our priority. This tool is designed to be both **highly secure** and **extremely easy to use**. No technical knowledge required - just drag, drop, and encrypt! 🔐✨







