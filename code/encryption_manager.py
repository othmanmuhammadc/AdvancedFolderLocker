import base64
import hashlib
import shutil
import tempfile
import os
import logging
import zipfile
from pathlib import Path
from typing import Tuple, Union
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class EncryptionManager:
    """Enhanced encryption manager with improved security and features"""

    SALT_SIZE = 16
    IV_SIZE = 16
    ITERATIONS = 100000
    CHUNK_SIZE = 8192

    def __init__(self):
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """Setup logging system"""
        logger = logging.getLogger('EncryptionManager')
        logger.setLevel(logging.INFO)
        return logger

    def generate_key(self, password: str, salt: bytes = None) -> Tuple[Fernet, bytes]:
        """Generate strong encryption key using PBKDF2 with enhanced security"""
        if salt is None:
            salt = os.urandom(self.SALT_SIZE)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.ITERATIONS,
            backend=default_backend()
        )

        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        return Fernet(key), salt

    def hash_password(self, password: str) -> str:
        """Create secure password hash with salt"""
        salt = os.urandom(32)
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return salt.hex() + pwdhash.hex()

    def verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify password against stored hash"""
        try:
            if len(stored_hash) < 64:
                # Legacy hash format (SHA256 only)
                return hashlib.sha256(password.encode()).hexdigest() == stored_hash

            # New format with salt
            salt = bytes.fromhex(stored_hash[:64])
            stored_pwdhash = stored_hash[64:]
            pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
            return pwdhash.hex() == stored_pwdhash

        except Exception as e:
            self.logger.error(f"Password verification error: {e}")
            return False

    def create_secure_zip(self, folder_path: Path, zip_path: Path) -> bool:
        """Create ZIP archive with better compression and error handling"""
        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as zipf:
                for file_path in folder_path.rglob('*'):
                    if file_path.is_file():
                        # Calculate relative path
                        arc_name = file_path.relative_to(folder_path)
                        zipf.write(file_path, arc_name)
                        self.logger.debug(f"Added to archive: {arc_name}")

            return zip_path.exists() and zip_path.stat().st_size > 0

        except Exception as e:
            self.logger.error(f"Failed to create ZIP archive: {e}")
            return False

    def encrypt_folder(self, folder_path: Union[str, Path], password: str) -> str:
        """Encrypt folder with enhanced security and progress tracking"""
        folder_path = Path(folder_path)
        zip_path = None

        try:
            # Validation
            if not folder_path.exists():
                raise FileNotFoundError(f"Folder not found: {folder_path}")

            if not folder_path.is_dir():
                raise ValueError(f"Path is not a directory: {folder_path}")

            # Check if folder has files
            files = list(folder_path.rglob('*'))
            if not any(f.is_file() for f in files):
                raise ValueError("Folder is empty or contains no files")

            self.logger.info(f"Starting encryption of folder: {folder_path}")

            # Create temporary ZIP archive
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
                zip_path = Path(temp_file.name)

            # Create secure ZIP
            if not self.create_secure_zip(folder_path, zip_path):
                raise RuntimeError("Failed to create ZIP archive")

            # Read ZIP data
            with open(zip_path, 'rb') as f:
                data = f.read()

            if not data:
                raise ValueError("Archive is empty")

            # Generate encryption key with random salt
            fernet, salt = self.generate_key(password)

            # Encrypt data
            encrypted_data = fernet.encrypt(data)

            # Create encrypted file
            encrypted_file = folder_path.with_suffix('.locked')

            # Write encrypted file with metadata
            with open(encrypted_file, 'wb') as f:
                # Write file header
                f.write(b'AFL2')  # Advanced Folder Locker v2 signature
                f.write(len(salt).to_bytes(4, byteorder='big'))
                f.write(salt)
                f.write(len(encrypted_data).to_bytes(8, byteorder='big'))
                f.write(encrypted_data)

            # Verify encrypted file
            if not encrypted_file.exists() or encrypted_file.stat().st_size == 0:
                raise RuntimeError("Failed to create encrypted file")

            # Clean up temporary files
            try:
                if zip_path and zip_path.exists():
                    zip_path.unlink()
            except Exception as e:
                self.logger.warning(f"Failed to remove temporary file: {e}")

            # Remove original folder only after successful encryption
            try:
                shutil.rmtree(folder_path)
                self.logger.info(f"Original folder removed: {folder_path}")
            except Exception as e:
                self.logger.warning(f"Failed to remove original folder: {e}")

            # Hide encrypted file on Windows
            if os.name == 'nt':
                try:
                    os.system(f'attrib +h "{encrypted_file}"')
                except Exception as e:
                    self.logger.warning(f"Failed to hide encrypted file: {e}")

            self.logger.info(f"Folder encrypted successfully: {encrypted_file}")
            return str(encrypted_file)

        except Exception as e:
            # Clean up on failure
            if zip_path and zip_path.exists():
                try:
                    zip_path.unlink()
                except:
                    pass

            self.logger.error(f"Folder encryption failed: {e}")
            raise

    def decrypt_folder(self, encrypted_file_path: Union[str, Path], password: str) -> str:
        """Decrypt folder with enhanced security and validation"""
        encrypted_file_path = Path(encrypted_file_path)
        temp_zip_path = None

        try:
            # Validation
            if not encrypted_file_path.exists():
                raise FileNotFoundError(f"Encrypted file not found: {encrypted_file_path}")

            if not encrypted_file_path.is_file():
                raise ValueError(f"Path is not a file: {encrypted_file_path}")

            self.logger.info(f"Starting decryption of file: {encrypted_file_path}")

            # Read encrypted file
            with open(encrypted_file_path, 'rb') as f:
                # Check file signature
                signature = f.read(4)
                if signature == b'AFL2':
                    # New format with metadata
                    salt_length = int.from_bytes(f.read(4), byteorder='big')
                    salt = f.read(salt_length)
                    data_length = int.from_bytes(f.read(8), byteorder='big')
                    encrypted_data = f.read(data_length)
                else:
                    # Legacy format
                    f.seek(0)
                    salt = f.read(16)
                    encrypted_data = f.read()

            # Validate data
            if len(salt) != self.SALT_SIZE:
                raise ValueError("Invalid file format: corrupted salt")

            if not encrypted_data:
                raise ValueError("Invalid file format: no encrypted data")

            # Decrypt data
            try:
                fernet, _ = self.generate_key(password, salt)
                decrypted_data = fernet.decrypt(encrypted_data)
            except InvalidToken:
                raise ValueError("Invalid password or corrupted file")

            # Create temporary file for decrypted data
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
                temp_file.write(decrypted_data)
                temp_zip_path = Path(temp_file.name)

            # Verify temporary file
            if not temp_zip_path.exists() or temp_zip_path.stat().st_size == 0:
                raise RuntimeError("Failed to create temporary decrypted file")

            # Determine output folder name
            folder_name = encrypted_file_path.stem
            output_folder = encrypted_file_path.parent / folder_name

            # Handle naming conflicts
            counter = 1
            original_folder = output_folder
            while output_folder.exists():
                output_folder = original_folder.with_name(f"{original_folder.name}_{counter}")
                counter += 1

            # Extract archive
            try:
                with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                    zipf.extractall(output_folder)
                    self.logger.info(f"Archive extracted to: {output_folder}")
            except Exception as e:
                raise RuntimeError(f"Failed to extract archive: {e}")

            # Verify extraction
            if not output_folder.exists():
                raise RuntimeError("Extraction failed: output folder not created")

            # Clean up temporary files
            try:
                if temp_zip_path and temp_zip_path.exists():
                    temp_zip_path.unlink()
            except Exception as e:
                self.logger.warning(f"Failed to remove temporary file: {e}")

            # Remove encrypted file only after successful decryption
            try:
                encrypted_file_path.unlink()
                self.logger.info(f"Encrypted file removed: {encrypted_file_path}")
            except Exception as e:
                self.logger.warning(f"Failed to remove encrypted file: {e}")

            self.logger.info(f"Folder decrypted successfully: {output_folder}")
            return str(output_folder)

        except Exception as e:
            # Clean up on failure
            if temp_zip_path and temp_zip_path.exists():
                try:
                    temp_zip_path.unlink()
                except:
                    pass

            self.logger.error(f"Folder decryption failed: {e}")
            raise

    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"

        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"

        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"

        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"

        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return False, "Password must contain at least one special character"

        return True, "Password strength is good"

    def get_file_info(self, encrypted_file_path: Union[str, Path]) -> dict:
        """Get information about encrypted file"""
        encrypted_file_path = Path(encrypted_file_path)

        try:
            if not encrypted_file_path.exists():
                return {"error": "File not found"}

            stat = encrypted_file_path.stat()

            with open(encrypted_file_path, 'rb') as f:
                signature = f.read(4)
                if signature == b'AFL2':
                    version = "2.0"
                else:
                    version = "1.0"

            return {
                "filename": encrypted_file_path.name,
                "size": stat.st_size,
                "created": stat.st_ctime,
                "modified": stat.st_mtime,
                "version": version,
                "folder_name": encrypted_file_path.stem
            }

        except Exception as e:
            return {"error": str(e)}







