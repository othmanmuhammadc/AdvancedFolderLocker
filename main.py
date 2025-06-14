import json
from config import Config
from encryption_manager import EncryptionManager
from gui_manager import ModernGUI


def main():
    """Main function"""
    try:
        # Create basic components
        config = Config()
        encryption_manager = EncryptionManager()

        # Create and run GUI
        app = ModernGUI(encryption_manager, config)
        app.run()

    except Exception as e:
        print(f"Application error: {e}")
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()





