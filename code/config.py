# config.py
import os
import json
import configparser
from pathlib import Path


class Config:
    def __init__(self):
        self.app_dir = Path.home() / ".folder_locker"
        self.config_file = self.app_dir / "config.ini"
        self.passwords_file = self.app_dir / "passwords.json"
        self.ensure_directories()

    def ensure_directories(self):
        """Create required directories"""
        self.app_dir.mkdir(exist_ok=True)
        if os.name == 'nt':  # Windows
            os.system(f'attrib +h "{self.app_dir}"')

    def save_password(self, folder_name, password_hash):
        """Save encrypted password"""
        passwords = self.load_passwords()
        passwords[folder_name] = password_hash

        with open(self.passwords_file, 'w') as f:
            json.dump(passwords, f, indent=2)

        if os.name == 'nt':
            os.system(f'attrib +h "{self.passwords_file}"')

    def load_passwords(self):
        """Load passwords"""
        if self.passwords_file.exists():
            with open(self.passwords_file, 'r') as f:
                return json.load(f)
        return {}

    def get_password_hash(self, folder_name):
        """Get password hash"""
        passwords = self.load_passwords()
        return passwords.get(folder_name)

    def remove_password(self, folder_name):
        """Remove folder password"""
        passwords = self.load_passwords()
        if folder_name in passwords:
            del passwords[folder_name]
            with open(self.passwords_file, 'w') as f:
                json.dump(passwords, f, indent=2)









