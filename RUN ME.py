#!/usr/bin/env python3
"""
STARK File Locker - Main Entry Point
Enhanced with PyQt6 support and better error handling
"""

import sys
import os
import traceback

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def check_dependencies():
    """Check if all required dependencies are installed"""
    required_packages = {
        'cryptography': 'pip install cryptography',
        'PyQt6': 'pip install PyQt6',
        'pyperclip': 'pip install pyperclip (optional, for clipboard functionality)'
    }

    missing_packages = []

    for package, install_cmd in required_packages.items():
        try:
            __import__(package)
        except ImportError:
            if package != 'pyperclip':  # pyperclip is optional
                missing_packages.append((package, install_cmd))

    if missing_packages:
        error_msg = "Missing required packages:\n\n"
        for package, cmd in missing_packages:
            error_msg += f"• {package}: {cmd}\n"
        error_msg += "\nPlease install the missing packages and try again."

        print(error_msg)

        # Try to show error in GUI if PyQt6 is available
        try:
            from PyQt6.QtWidgets import QApplication, QMessageBox
            app = QApplication([])
            QMessageBox.critical(None, "Missing Dependencies", error_msg)
        except ImportError:
            pass

        return False

    return True


def setup_assets_directory():
    """Create assets directory and check for logo files"""
    assets_dir = os.path.join(os.path.dirname(__file__), 'assets')

    if not os.path.exists(assets_dir):
        try:
            os.makedirs(assets_dir)
            print(f"Created assets directory: {assets_dir}")
            print("Please place your logo files (logo.ico and logo.png) in the assets directory.")
        except Exception as e:
            print(f"Warning: Could not create assets directory: {e}")

    # Check for logo files
    logo_ico = os.path.join(assets_dir, 'logo.ico')
    logo_png = os.path.join(assets_dir, 'logo.png')

    if not os.path.exists(logo_ico):
        print(f"Note: Logo file not found at {logo_ico}")

    if not os.path.exists(logo_png):
        print(f"Note: Logo file not found at {logo_png}")

    return assets_dir


def main():
    """Main function to start the application"""
    try:
        # Check dependencies first
        if not check_dependencies():
            sys.exit(1)

        # Setup assets directory
        assets_dir = setup_assets_directory()

        # Import required modules
        try:
            from ui.gui_manager import main as gui_main
            from core.config import APP_CONFIG

        except ImportError as e:
            error_msg = f"Import Error: {e}\n\nMake sure all required files are in the correct directories:\n"
            error_msg += "• ui/gui_manager.py\n• core/encryption_manager.py\n• core/config.py\n"
            error_msg += "\nAlso ensure required packages are installed:\n"
            error_msg += "• pip install cryptography\n• pip install PyQt6\n• pip install pyperclip"

            print(error_msg)

            try:
                from PyQt6.QtWidgets import QApplication, QMessageBox
                app = QApplication([])
                QMessageBox.critical(None, "Import Error", error_msg)
            except ImportError:
                pass

            sys.exit(1)

        # Start the application
        print("=" * 60)
        print(f"🔐 {APP_CONFIG['APP_NAME']} v{APP_CONFIG['VERSION']}")
        print("=" * 60)
        print("✨ Enhanced Features:")
        print("  • Modern PyQt6 interface with responsive design")
        print("  • Dark theme support")
        print("  • F11 fullscreen toggle functionality")
        print("  • Smart error handling and user feedback")
        print("  • Drag & drop with visual feedback")
        print("  • Multi-language support (EN/DE/FR)")
        print("  • AES-256 encryption with secure deletion")
        print("  • Batch processing with progress indication")
        print("  • Password strength validation")
        print("  • Timed lock and double encryption")
        print("=" * 60)
        print("🚀 Starting enhanced application...")
        print()

        # Run the GUI
        gui_main()

    except Exception as e:
        error_msg = f"Fatal Error: {str(e)}\n\nTraceback:\n{traceback.format_exc()}"
        print(error_msg)

        # Try to show error in messagebox
        try:
            from PyQt6.QtWidgets import QApplication, QMessageBox
            app = QApplication([])
            QMessageBox.critical(None, "Fatal Error",
                                 f"Application failed to start:\n\n{str(e)}\n\nCheck console for details.")
        except ImportError:
            pass

        sys.exit(1)


if __name__ == "__main__":
    print("🔐 STARK FILE LOCKER - ENHANCED VERSION")
    print("Enhanced with responsive UI, dark theme, F11 fullscreen, and smart error handling")
    print()

    main()






