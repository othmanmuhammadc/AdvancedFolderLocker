# encryption_manager.py
import base64
import hashlib
import shutil
import tempfile
import os
import logging
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptionManager:
    def __init__(self):
        self.logger = self._setup_logger()

    def _setup_logger(self):
        """Setup logging system"""
        logger = logging.getLogger('FolderLocker')
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def generate_key(self, password, salt=None):
        """Generate strong encryption key using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key), salt

    def hash_password(self, password):
        """Create password hash for verification"""
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, password, stored_hash):
        """Verify password correctness"""
        return self.hash_password(password) == stored_hash

    def encrypt_folder(self, folder_path, password):
        """Encrypt folder"""
        try:
            folder_path = Path(folder_path)
            if not folder_path.exists():
                raise FileNotFoundError(f"Folder not found: {folder_path}")

            self.logger.info(f"Starting folder encryption: {folder_path}")

            # Create zip archive
            zip_path = folder_path.with_suffix('.zip')
            shutil.make_archive(str(zip_path.with_suffix('')), 'zip', folder_path)

            # Read data
            with open(zip_path, 'rb') as f:
                data = f.read()

            # Encrypt with random salt
            fernet, salt = self.generate_key(password)
            encrypted_data = fernet.encrypt(data)

            # Save encrypted data with salt
            encrypted_file = folder_path.with_suffix('.locked')
            with open(encrypted_file, 'wb') as f:
                f.write(salt)  # Save salt at the beginning
                f.write(encrypted_data)

            # Remove temporary files and original folder
            os.remove(zip_path)
            shutil.rmtree(folder_path)

            # Hide encrypted file
            if os.name == 'nt':
                os.system(f'attrib +h "{encrypted_file}"')

            self.logger.info(f"Folder encrypted successfully: {encrypted_file}")
            return str(encrypted_file)

        except Exception as e:
            self.logger.error(f"Folder encryption failed: {e}")
            raise

    def decrypt_folder(self, encrypted_file_path, password):
        """Decrypt folder"""
        try:
            encrypted_file_path = Path(encrypted_file_path)
            if not encrypted_file_path.exists():
                raise FileNotFoundError(f"Encrypted file not found: {encrypted_file_path}")

            self.logger.info(f"Starting file decryption: {encrypted_file_path}")

            # Read encrypted data
            with open(encrypted_file_path, 'rb') as f:
                salt = f.read(16)  # Read salt
                encrypted_data = f.read()

            # Decrypt
            fernet, _ = self.generate_key(password, salt)
            decrypted_data = fernet.decrypt(encrypted_data)

            # Create temporary file for decrypted data
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
                temp_file.write(decrypted_data)
                temp_zip_path = temp_file.name

            # Extract folder
            folder_name = encrypted_file_path.stem
            output_folder = encrypted_file_path.parent / folder_name

            # Ensure no folder with same name exists
            counter = 1
            original_folder = output_folder
            while output_folder.exists():
                output_folder = original_folder.with_name(f"{original_folder.name}_{counter}")
                counter += 1

            shutil.unpack_archive(temp_zip_path, output_folder)

            # Remove temporary files and encrypted file
            os.remove(temp_zip_path)
            os.remove(encrypted_file_path)

            self.logger.info(f"Folder decrypted successfully: {output_folder}")
            return str(output_folder)

        except Exception as e:
            self.logger.error(f"Folder decryption failed: {e}")
            raise









