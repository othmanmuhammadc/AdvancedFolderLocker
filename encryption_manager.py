#!/usr/bin/env python3
"""
Advanced Folder Locker - Enhanced Encryption Manager
FIXED: Proper .locked file behavior with original file deletion
"""

import os
import json
import hashlib
import secrets
import shutil
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Union
from datetime import datetime, timedelta

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.padding import PKCS7
except ImportError as e:
    print(f"Error importing cryptography: {e}")
    print("Please install: pip install cryptography")
    raise

from config import ENCRYPTION_CONFIG, TIMED_LOCK_CONFIG


class EncryptionManager:
    """Enhanced encryption manager with proper .locked file behavior"""

    def __init__(self):
        self.backend = default_backend()
        self.chunk_size = ENCRYPTION_CONFIG['CHUNK_SIZE']
        self.key_iterations = ENCRYPTION_CONFIG['KEY_ITERATIONS']
        self.salt_length = ENCRYPTION_CONFIG['SALT_LENGTH']
        self.locked_extension = ENCRYPTION_CONFIG['LOCKED_EXTENSION']
        self.metadata_extension = ENCRYPTION_CONFIG['METADATA_EXTENSION']

    def generate_salt(self) -> bytes:
        """Generate a cryptographically secure random salt"""
        return secrets.token_bytes(self.salt_length)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits
                salt=salt,
                iterations=self.key_iterations,
                backend=self.backend
            )
            return kdf.derive(password.encode('utf-8'))
        except Exception as e:
            raise Exception(f"Key derivation failed: {str(e)}")

    def generate_strong_password(self, length: int = 16) -> str:
        """Generate a cryptographically secure password"""
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def validate_password(self, password: str) -> Tuple[bool, str]:
        """Validate password strength"""
        if len(password) < ENCRYPTION_CONFIG['MIN_PASSWORD_LENGTH']:
            return False, f"Password must be at least {ENCRYPTION_CONFIG['MIN_PASSWORD_LENGTH']} characters long"

        if not password.strip():
            return False, "Password cannot be empty or contain only spaces"

        # Check for basic complexity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)

        if len(password) >= 8 and has_upper and has_lower and has_digit:
            return True, "Strong password"
        elif len(password) >= 6:
            return True, "Acceptable password"
        else:
            return False, "Password is too weak"

    def encrypt_file(self, file_path: str, password: str,
                     timed_lock: Optional[int] = None,
                     double_lock: bool = False) -> Tuple[bool, str]:
        """
        Encrypt a single file and replace it with .locked version

        Args:
            file_path: Path to file to encrypt
            password: Encryption password
            timed_lock: Minutes to lock (None for permanent)
            double_lock: Enable double encryption

        Returns:
            Tuple of (success, message)
        """
        try:
            if not os.path.exists(file_path):
                return False, f"File not found: {file_path}"

            if not os.path.isfile(file_path):
                return False, f"Path is not a file: {file_path}"

            # Check if file is already locked
            if file_path.endswith(self.locked_extension):
                return False, f"File is already locked: {file_path}"

            # Validate password
            is_valid, msg = self.validate_password(password)
            if not is_valid:
                return False, f"Password validation failed: {msg}"

            # Generate encryption components
            salt = self.generate_salt()
            iv = secrets.token_bytes(16)  # AES block size
            key = self.derive_key(password, salt)

            # Create metadata
            metadata = {
                'version': '3.0',
                'algorithm': 'AES-256-CBC',
                'created': datetime.now().isoformat(),
                'original_name': os.path.basename(file_path),
                'original_size': os.path.getsize(file_path),
                'checksum': self._calculate_file_checksum(file_path),
                'double_lock': double_lock,
                'timed_lock': None
            }

            # Handle timed lock
            if timed_lock and timed_lock > 0:
                unlock_time = datetime.now() + timedelta(minutes=timed_lock)
                metadata['timed_lock'] = unlock_time.isoformat()

            # Create .locked file path (same directory, same name + .locked)
            locked_path = file_path + self.locked_extension
            if os.path.exists(locked_path):
                return False, f"Locked file already exists: {locked_path}"

            # Encrypt file
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            padder = PKCS7(128).padder()

            # Create temporary file first
            temp_locked_path = locked_path + '.tmp'

            try:
                with open(file_path, 'rb') as infile, open(temp_locked_path, 'wb') as outfile:
                    # Write header: salt + iv + metadata_length + metadata
                    metadata_json = json.dumps(metadata).encode('utf-8')
                    metadata_length = len(metadata_json)

                    outfile.write(salt)
                    outfile.write(iv)
                    outfile.write(metadata_length.to_bytes(4, byteorder='big'))
                    outfile.write(metadata_json)

                    # Encrypt file content
                    while True:
                        chunk = infile.read(self.chunk_size)
                        if not chunk:
                            break

                        if len(chunk) < self.chunk_size:
                            # Last chunk - add padding
                            padded_chunk = padder.update(chunk) + padder.finalize()
                            encrypted_chunk = encryptor.update(padded_chunk) + encryptor.finalize()
                        else:
                            padded_chunk = padder.update(chunk)
                            encrypted_chunk = encryptor.update(padded_chunk)

                        outfile.write(encrypted_chunk)

                # Apply double lock if requested
                if double_lock:
                    success, msg = self._apply_double_lock(temp_locked_path, password)
                    if not success:
                        # Clean up on failure
                        if os.path.exists(temp_locked_path):
                            os.remove(temp_locked_path)
                        return False, f"Double lock failed: {msg}"

                # Move temp file to final location
                shutil.move(temp_locked_path, locked_path)

                # Secure delete original file
                self._secure_delete_file(file_path)

                return True, f"File encrypted and saved as: {os.path.basename(locked_path)}"

            except Exception as e:
                # Clean up temp file on error
                if os.path.exists(temp_locked_path):
                    try:
                        os.remove(temp_locked_path)
                    except:
                        pass
                raise e

        except Exception as e:
            return False, f"Encryption failed: {str(e)}"

    def decrypt_file(self, locked_path: str, password: str) -> Tuple[bool, str]:
        """
        Decrypt a locked file and restore original file

        Args:
            locked_path: Path to locked file
            password: Decryption password

        Returns:
            Tuple of (success, message)
        """
        try:
            if not os.path.exists(locked_path):
                return False, f"Locked file not found: {locked_path}"

            if not locked_path.endswith(self.locked_extension):
                return False, f"File is not a locked file: {locked_path}"

            with open(locked_path, 'rb') as infile:
                # Read header
                salt = infile.read(self.salt_length)
                iv = infile.read(16)
                metadata_length = int.from_bytes(infile.read(4), byteorder='big')
                metadata_json = infile.read(metadata_length)

                try:
                    metadata = json.loads(metadata_json.decode('utf-8'))
                except json.JSONDecodeError:
                    return False, "Invalid file format or corrupted metadata"

                # Check timed lock
                if metadata.get('timed_lock'):
                    try:
                        unlock_time = datetime.fromisoformat(metadata['timed_lock'])
                        if datetime.now() < unlock_time:
                            remaining = unlock_time - datetime.now()
                            return False, f"File is time-locked. Unlocks in: {remaining}"
                    except ValueError:
                        pass  # Invalid date format, proceed with unlock

                # Derive key and decrypt
                key = self.derive_key(password, salt)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
                decryptor = cipher.decryptor()
                unpadder = PKCS7(128).unpadder()

                # Determine output path (remove .locked extension)
                original_path = locked_path[:-len(self.locked_extension)]
                original_name = metadata.get('original_name', os.path.basename(original_path))

                # Use the directory of the locked file and the original filename
                output_dir = os.path.dirname(locked_path)
                output_path = os.path.join(output_dir, original_name)

                # Handle name conflicts
                if os.path.exists(output_path):
                    base_name, ext = os.path.splitext(output_path)
                    counter = 1
                    while os.path.exists(output_path):
                        output_path = f"{base_name}_restored_{counter}{ext}"
                        counter += 1

                # Create temporary file first
                temp_output_path = output_path + '.tmp'

                try:
                    # Decrypt content
                    with open(temp_output_path, 'wb') as outfile:
                        decrypted_data = b''
                        while True:
                            chunk = infile.read(self.chunk_size)
                            if not chunk:
                                break
                            decrypted_data += decryptor.update(chunk)

                        # Finalize and remove padding
                        decrypted_data += decryptor.finalize()
                        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
                        outfile.write(unpadded_data)

                    # Verify checksum if available
                    if 'checksum' in metadata:
                        calculated_checksum = self._calculate_file_checksum(temp_output_path)
                        if calculated_checksum != metadata['checksum']:
                            os.remove(temp_output_path)
                            return False, "File integrity check failed - file may be corrupted"

                    # Move temp file to final location
                    shutil.move(temp_output_path, output_path)

                    # Remove locked file after successful decryption
                    self._secure_delete_file(locked_path)

                    return True, f"File decrypted and restored as: {os.path.basename(output_path)}"

                except Exception as e:
                    # Clean up temp file on error
                    if os.path.exists(temp_output_path):
                        try:
                            os.remove(temp_output_path)
                        except:
                            pass
                    raise e

        except Exception as e:
            return False, f"Decryption failed: {str(e)}"

    def encrypt_folder(self, folder_path: str, password: str,
                       timed_lock: Optional[int] = None,
                       double_lock: bool = False) -> Tuple[bool, str]:
        """
        Encrypt an entire folder by creating a single encrypted archive

        Args:
            folder_path: Path to folder to encrypt
            password: Encryption password
            timed_lock: Minutes to lock (None for permanent)
            double_lock: Enable double encryption

        Returns:
            Tuple of (success, message)
        """
        try:
            if not os.path.exists(folder_path):
                return False, f"Folder not found: {folder_path}"

            if not os.path.isdir(folder_path):
                return False, f"Path is not a folder: {folder_path}"

            # Check if folder is already locked
            locked_path = folder_path + self.locked_extension
            if os.path.exists(locked_path):
                return False, f"Locked folder already exists: {locked_path}"

            # Create temporary archive
            import tempfile
            import zipfile

            temp_dir = tempfile.mkdtemp()
            archive_path = os.path.join(temp_dir, 'folder_archive.zip')

            try:
                # Create zip archive of folder
                with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for root, dirs, files in os.walk(folder_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, folder_path)
                            zipf.write(file_path, arcname)

                # Encrypt the archive using the file encryption method
                success, msg = self.encrypt_file(archive_path, password, timed_lock, double_lock)

                if success:
                    # Move encrypted file to final location
                    encrypted_archive = archive_path + self.locked_extension
                    shutil.move(encrypted_archive, locked_path)

                    # Remove original folder
                    shutil.rmtree(folder_path)

                    return True, f"Folder encrypted and saved as: {os.path.basename(locked_path)}"
                else:
                    return False, f"Failed to encrypt folder archive: {msg}"

            finally:
                # Clean up temporary files
                if os.path.exists(archive_path):
                    try:
                        os.remove(archive_path)
                    except:
                        pass
                if os.path.exists(temp_dir):
                    try:
                        shutil.rmtree(temp_dir)
                    except:
                        pass

        except Exception as e:
            return False, f"Folder encryption failed: {str(e)}"

    def decrypt_folder(self, locked_path: str, password: str) -> Tuple[bool, str]:
        """
        Decrypt a locked folder

        Args:
            locked_path: Path to locked folder file
            password: Decryption password

        Returns:
            Tuple of (success, message)
        """
        try:
            # First decrypt the archive
            success, msg = self.decrypt_file(locked_path, password)
            if not success:
                return False, msg

            # Find the decrypted archive
            # The decrypt_file method should have created a file without .locked extension
            archive_path = locked_path[:-len(self.locked_extension)] + '.zip'

            # If that doesn't exist, look for any zip file in the same directory
            if not os.path.exists(archive_path):
                dir_path = os.path.dirname(locked_path)
                for file in os.listdir(dir_path):
                    if file.endswith('.zip') and 'folder_archive' in file:
                        archive_path = os.path.join(dir_path, file)
                        break

            if not os.path.exists(archive_path):
                return False, "Could not find decrypted archive"

            # Extract the archive
            import zipfile
            output_folder = locked_path[:-len(self.locked_extension)]

            # Handle name conflicts
            if os.path.exists(output_folder):
                base_name = output_folder
                counter = 1
                while os.path.exists(output_folder):
                    output_folder = f"{base_name}_restored_{counter}"
                    counter += 1

            try:
                with zipfile.ZipFile(archive_path, 'r') as zipf:
                    zipf.extractall(output_folder)

                # Remove the archive file
                os.remove(archive_path)

                return True, f"Folder decrypted and restored as: {os.path.basename(output_folder)}"

            except Exception as e:
                return False, f"Failed to extract folder archive: {str(e)}"

        except Exception as e:
            return False, f"Folder decryption failed: {str(e)}"

    def _apply_double_lock(self, file_path: str, password: str) -> Tuple[bool, str]:
        """Apply double encryption to a file"""
        try:
            # Generate new salt and key for second encryption
            salt2 = self.generate_salt()
            key2 = self.derive_key(password + "_double", salt2)
            iv2 = secrets.token_bytes(16)

            # Read current file
            with open(file_path, 'rb') as f:
                data = f.read()

            # Apply second encryption
            cipher = Cipher(algorithms.AES(key2), modes.CBC(iv2), backend=self.backend)
            encryptor = cipher.encryptor()
            padder = PKCS7(128).padder()

            padded_data = padder.update(data) + padder.finalize()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Write back with double lock header
            with open(file_path, 'wb') as f:
                f.write(b'DOUBLE_LOCK')  # 11 bytes marker
                f.write(salt2)
                f.write(iv2)
                f.write(encrypted_data)

            return True, "Double lock applied successfully"

        except Exception as e:
            return False, f"Double lock failed: {str(e)}"

    def _calculate_file_checksum(self, file_path: str) -> str:
        """Calculate SHA-256 checksum of a file"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return ""

    def _secure_delete_file(self, file_path: str) -> None:
        """Securely delete a file by overwriting it multiple times"""
        try:
            if not os.path.exists(file_path):
                return

            file_size = os.path.getsize(file_path)
            passes = ENCRYPTION_CONFIG['SECURE_DELETE_PASSES']

            with open(file_path, 'r+b') as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())

            os.remove(file_path)

        except Exception as e:
            # If secure delete fails, try normal delete
            try:
                os.remove(file_path)
            except:
                pass

    def get_locked_files_info(self, directory: str = None) -> List[Dict]:
        """Get information about locked files in a directory"""
        if directory is None:
            directory = os.getcwd()

        locked_files = []
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.endswith(self.locked_extension):
                        file_path = os.path.join(root, file)
                        try:
                            info = self._get_file_metadata(file_path)
                            if info:
                                locked_files.append(info)
                        except Exception:
                            continue
        except Exception:
            pass

        return locked_files

    def _get_file_metadata(self, locked_path: str) -> Optional[Dict]:
        """Extract metadata from a locked file"""
        try:
            with open(locked_path, 'rb') as f:
                # Skip salt and IV
                f.seek(self.salt_length + 16)
                metadata_length = int.from_bytes(f.read(4), byteorder='big')
                metadata_json = f.read(metadata_length)
                metadata = json.loads(metadata_json.decode('utf-8'))

                return {
                    'path': locked_path,
                    'original_name': metadata.get('original_name', 'Unknown'),
                    'created': metadata.get('created', 'Unknown'),
                    'size': os.path.getsize(locked_path),
                    'original_size': metadata.get('original_size', 0),
                    'timed_lock': metadata.get('timed_lock'),
                    'double_lock': metadata.get('double_lock', False)
                }
        except Exception:
            return None

    def is_file_locked(self, file_path: str) -> bool:
        """Check if a file is locked (encrypted)"""
        return file_path.endswith(self.locked_extension) and os.path.exists(file_path)

    def batch_encrypt(self, file_paths: List[str], password: str,
                      timed_lock: Optional[int] = None,
                      double_lock: bool = False) -> Tuple[int, int, List[str]]:
        """
        Encrypt multiple files in batch

        Returns:
            Tuple of (successful_count, failed_count, error_messages)
        """
        successful = 0
        failed = 0
        errors = []

        for file_path in file_paths:
            try:
                if os.path.isfile(file_path):
                    success, msg = self.encrypt_file(file_path, password, timed_lock, double_lock)
                elif os.path.isdir(file_path):
                    success, msg = self.encrypt_folder(file_path, password, timed_lock, double_lock)
                else:
                    success = False
                    msg = f"Invalid path: {file_path}"

                if success:
                    successful += 1
                else:
                    failed += 1
                    errors.append(f"{os.path.basename(file_path)}: {msg}")

            except Exception as e:
                failed += 1
                errors.append(f"{os.path.basename(file_path)}: {str(e)}")

        return successful, failed, errors

    def batch_decrypt(self, locked_paths: List[str], password: str) -> Tuple[int, int, List[str]]:
        """
        Decrypt multiple locked files in batch

        Returns:
            Tuple of (successful_count, failed_count, error_messages)
        """
        successful = 0
        failed = 0
        errors = []

        for locked_path in locked_paths:
            try:
                # Check if it's a folder or file based on metadata
                metadata = self._get_file_metadata(locked_path)
                if metadata and 'folder_archive' in metadata.get('original_name', ''):
                    success, msg = self.decrypt_folder(locked_path, password)
                else:
                    success, msg = self.decrypt_file(locked_path, password)

                if success:
                    successful += 1
                else:
                    failed += 1
                    errors.append(f"{os.path.basename(locked_path)}: {msg}")

            except Exception as e:
                failed += 1
                errors.append(f"{os.path.basename(locked_path)}: {str(e)}")

        return successful, failed, errors





