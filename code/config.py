import os
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional


class Config:
    """Enhanced configuration manager with better error handling and features"""

    def __init__(self):
        self.app_dir = Path.home() / ".folder_locker"
        self.config_file = self.app_dir / "config.json"
        self.passwords_file = self.app_dir / "passwords.json"
        self.history_file = self.app_dir / "history.json"
        self.logger = logging.getLogger(__name__)

        self.ensure_directories()
        self.load_config()

    def ensure_directories(self):
        """Create required directories with proper permissions"""
        try:
            self.app_dir.mkdir(exist_ok=True, parents=True)

            # Hide directory on Windows
            if os.name == 'nt':
                try:
                    os.system(f'attrib +h "{self.app_dir}"')
                except Exception as e:
                    self.logger.warning(f"Could not hide config directory: {e}")

            self.logger.info(f"Configuration directory: {self.app_dir}")

        except Exception as e:
            self.logger.error(f"Failed to create config directory: {e}")
            raise

    def load_config(self):
        """Load application configuration"""
        default_config = {
            "version": "2.0.0",
            "first_run": True,
            "last_used": None,
            "theme": "dark",
            "auto_hide_files": True,
            "backup_count": 3,
            "log_level": "INFO",
            "animations_enabled": True,
            "blur_effects": True
        }

        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
                # Merge with defaults for missing keys
                for key, value in default_config.items():
                    if key not in self.config:
                        self.config[key] = value
            else:
                self.config = default_config
                self.save_config()

        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            self.config = default_config

    def save_config(self):
        """Save configuration to file"""
        try:
            self.config["last_used"] = datetime.now().isoformat()
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)

            if os.name == 'nt':
                os.system(f'attrib +h "{self.config_file}"')

        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")

    def get_config_value(self, key: str, default=None):
        """Get configuration value"""
        return self.config.get(key, default)

    def set_config_value(self, key: str, value):
        """Set configuration value"""
        self.config[key] = value
        self.save_config()

    def save_password(self, item_name: str, password_hash: str, file_path: str = None, item_type: str = "folder"):
        """Save encrypted password with metadata"""
        try:
            passwords = self.load_passwords()

            passwords[item_name] = {
                "hash": password_hash,
                "created": datetime.now().isoformat(),
                "file_path": file_path,
                "access_count": 0,
                "item_type": item_type  # "folder" or "file"
            }

            with open(self.passwords_file, 'w') as f:
                json.dump(passwords, f, indent=2)

            if os.name == 'nt':
                os.system(f'attrib +h "{self.passwords_file}"')

            self.logger.info(f"Password saved for {item_type}: {item_name}")

        except Exception as e:
            self.logger.error(f"Failed to save password: {e}")
            raise

    def load_passwords(self) -> Dict:
        """Load passwords with error handling"""
        try:
            if self.passwords_file.exists():
                with open(self.passwords_file, 'r') as f:
                    data = json.load(f)

                # Handle old format (just hash strings)
                for item_name, password_data in data.items():
                    if isinstance(password_data, str):
                        data[item_name] = {
                            "hash": password_data,
                            "created": datetime.now().isoformat(),
                            "file_path": None,
                            "access_count": 0,
                            "item_type": "folder"  # Default to folder for legacy entries
                        }

                return data
            return {}

        except Exception as e:
            self.logger.error(f"Failed to load passwords: {e}")
            return {}

    def get_password_hash(self, item_name: str) -> Optional[str]:
        """Get password hash for item"""
        passwords = self.load_passwords()
        password_data = passwords.get(item_name)

        if password_data:
            # Increment access count
            password_data["access_count"] = password_data.get("access_count", 0) + 1
            passwords[item_name] = password_data

            try:
                with open(self.passwords_file, 'w') as f:
                    json.dump(passwords, f, indent=2)
            except Exception as e:
                self.logger.warning(f"Failed to update access count: {e}")

            return password_data.get("hash") if isinstance(password_data, dict) else password_data

        return None

    def remove_password(self, item_name: str):
        """Remove item password"""
        try:
            passwords = self.load_passwords()
            if item_name in passwords:
                del passwords[item_name]
                with open(self.passwords_file, 'w') as f:
                    json.dump(passwords, f, indent=2)
                self.logger.info(f"Password removed for item: {item_name}")

        except Exception as e:
            self.logger.error(f"Failed to remove password: {e}")

    def add_to_history(self, action: str, item_name: str, status: str = "success", item_type: str = "folder"):
        """Add operation to history"""
        try:
            history = self.load_history()

            entry = {
                "timestamp": datetime.now().isoformat(),
                "action": action,
                "item_name": item_name,
                "status": status,
                "item_type": item_type
            }

            history.append(entry)

            # Keep only last 100 entries
            if len(history) > 100:
                history = history[-100:]

            with open(self.history_file, 'w') as f:
                json.dump(history, f, indent=2)

        except Exception as e:
            self.logger.error(f"Failed to add to history: {e}")

    def load_history(self) -> list:
        """Load operation history"""
        try:
            if self.history_file.exists():
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            return []

        except Exception as e:
            self.logger.error(f"Failed to load history: {e}")
            return []

    def clear_all_data(self):
        """Clear all saved data"""
        try:
            files_to_clear = [self.passwords_file, self.history_file]

            for file_path in files_to_clear:
                if file_path.exists():
                    file_path.unlink()

            self.logger.info("All data cleared successfully")

        except Exception as e:
            self.logger.error(f"Failed to clear data: {e}")
            raise

    def get_stats(self) -> Dict:
        """Get application statistics"""
        passwords = self.load_passwords()
        history = self.load_history()

        locked_folders = sum(1 for p in passwords.values() if isinstance(p, dict) and p.get("item_type", "folder") == "folder")
        locked_files = sum(1 for p in passwords.values() if isinstance(p, dict) and p.get("item_type", "folder") == "file")

        return {
            "locked_folders": locked_folders,
            "locked_files": locked_files,
            "total_locked": len(passwords),
            "total_operations": len(history),
            "successful_operations": len([h for h in history if h.get("status") == "success"]),
            "failed_operations": len([h for h in history if h.get("status") == "failed"]),
            "first_run": self.config.get("first_run", True),
            "last_used": self.config.get("last_used")
        }





