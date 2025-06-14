# encryption_manager.py
import base64
import hashlib
import shutil
import tempfile
import os
import logging
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
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
        """Encrypt folder with improved error handling"""
        folder_path = Path(folder_path)
        zip_path = None

        try:
            if not folder_path.exists():
                raise FileNotFoundError(f"Folder not found: {folder_path}")

            if not folder_path.is_dir():
                raise ValueError(f"Path is not a directory: {folder_path}")

            self.logger.info(f"Starting folder encryption: {folder_path}")

            # Create zip archive
            zip_path = folder_path.with_suffix('.zip')
            self.logger.info(f"Creating archive: {zip_path}")

            shutil.make_archive(str(zip_path.with_suffix('')), 'zip', folder_path)

            if not zip_path.exists():
                raise RuntimeError("Failed to create zip archive")

            # Read data
            with open(zip_path, 'rb') as f:
                data = f.read()

            if not data:
                raise ValueError("Archive is empty")

            # Encrypt with random salt
            fernet, salt = self.generate_key(password)
            encrypted_data = fernet.encrypt(data)

            # Save encrypted data with salt
            encrypted_file = folder_path.with_suffix('.locked')
            with open(encrypted_file, 'wb') as f:
                f.write(salt)  # Save salt at the beginning
                f.write(encrypted_data)

            # Verify encrypted file was created
            if not encrypted_file.exists():
                raise RuntimeError("Failed to create encrypted file")

            # Clean up - remove temporary files and original folder
            try:
                os.remove(zip_path)
            except Exception as e:
                self.logger.warning(f"Failed to remove temporary zip: {e}")

            try:
                shutil.rmtree(folder_path)
            except Exception as e:
                self.logger.warning(f"Failed to remove original folder: {e}")
                # Don't raise here - encryption was successful

            # Hide encrypted file (Windows only)
            if os.name == 'nt':
                try:
                    os.system(f'attrib +h "{encrypted_file}"')
                except Exception as e:
                    self.logger.warning(f"Failed to hide file: {e}")

            self.logger.info(f"Folder encrypted successfully: {encrypted_file}")
            return str(encrypted_file)

        except Exception as e:
            # Clean up on failure
            if zip_path and zip_path.exists():
                try:
                    os.remove(zip_path)
                except:
                    pass

            self.logger.error(f"Folder encryption failed: {e}")
            raise

    def decrypt_folder(self, encrypted_file_path, password):
        """Decrypt folder with improved error handling"""
        encrypted_file_path = Path(encrypted_file_path)
        temp_zip_path = None

        try:
            if not encrypted_file_path.exists():
                raise FileNotFoundError(f"Encrypted file not found: {encrypted_file_path}")

            if not encrypted_file_path.is_file():
                raise ValueError(f"Path is not a file: {encrypted_file_path}")

            self.logger.info(f"Starting file decryption: {encrypted_file_path}")

            # Read encrypted data
            with open(encrypted_file_path, 'rb') as f:
                salt = f.read(16)  # Read salt
                encrypted_data = f.read()

            if len(salt) != 16:
                raise ValueError("Invalid file format: salt missing or corrupted")

            if not encrypted_data:
                raise ValueError("Invalid file format: no encrypted data")

            # Decrypt
            try:
                fernet, _ = self.generate_key(password, salt)
                decrypted_data = fernet.decrypt(encrypted_data)
            except InvalidToken:
                raise ValueError("Invalid password or corrupted file")

            # Create temporary file for decrypted data
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
                temp_file.write(decrypted_data)
                temp_zip_path = temp_file.name

            # Verify temporary file was created
            if not os.path.exists(temp_zip_path):
                raise RuntimeError("Failed to create temporary file")

            # Extract folder
            folder_name = encrypted_file_path.stem
            output_folder = encrypted_file_path.parent / folder_name

            # Ensure no folder with same name exists
            counter = 1
            original_folder = output_folder
            while output_folder.exists():
                output_folder = original_folder.with_name(f"{original_folder.name}_{counter}")
                counter += 1

            try:
                shutil.unpack_archive(temp_zip_path, output_folder)
            except Exception as e:
                raise RuntimeError(f"Failed to extract archive: {e}")

            # Verify extraction was successful
            if not output_folder.exists():
                raise RuntimeError("Extraction failed: output folder not created")

            # Clean up - remove temporary files and encrypted file
            try:
                os.remove(temp_zip_path)
            except Exception as e:
                self.logger.warning(f"Failed to remove temporary file: {e}")

            try:
                os.remove(encrypted_file_path)
            except Exception as e:
                self.logger.warning(f"Failed to remove encrypted file: {e}")
                # Don't raise here - decryption was successful

            self.logger.info(f"Folder decrypted successfully: {output_folder}")
            return str(output_folder)

        except Exception as e:
            # Clean up on failure
            if temp_zip_path and os.path.exists(temp_zip_path):
                try:
                    os.remove(temp_zip_path)
                except:
                    pass

            self.logger.error(f"Folder decryption failed: {e}")
            raise




