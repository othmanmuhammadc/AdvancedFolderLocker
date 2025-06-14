import sys
import os
import tkinter as tk
from pathlib import Path

# Add code directory to Python path
code_dir = Path(__file__).parent / "code"
sys.path.insert(0, str(code_dir))

try:
    from config import Config
    from encryption_manager import EncryptionManager
    from gui_manager import ModernGUI
    import logging
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure all files are in the 'code' directory")
    input("Press Enter to exit...")
    sys.exit(1)


def setup_logging():
    """Setup application logging"""
    log_dir = Path.home() / ".folder_locker" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / "app.log"),
            logging.StreamHandler()
        ]
    )


def main():
    """Main application entry point"""
    try:
        # Setup logging
        setup_logging()
        logger = logging.getLogger(__name__)
        logger.info("Starting Advanced Folder Locker...")

        # Create application components
        config = Config()
        encryption_manager = EncryptionManager()

        # Launch GUI
        app = ModernGUI(encryption_manager, config)
        app.run()

        logger.info("Application closed successfully")

    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        logging.error(f"Critical application error: {e}")
        print(f"Application error: {e}")
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()





