"""
Aegis AV - Quarantine Manager
Isolates suspicious files by encrypting and moving them to a quarantine vault.
Files can be restored or permanently deleted.
"""

import os
import shutil
import hashlib
import logging
import struct
import time
from datetime import datetime

from aegis.config import QUARANTINE_DIR, logger

logger = logging.getLogger("Aegis.Quarantine")


class QuarantineManager:
    """Manages quarantined files - isolation, restoration, and deletion."""

    # Simple XOR key for basic obfuscation (prevents accidental execution)
    XOR_KEY = b"AegisAV_Quarantine_2024"
    HEADER_MAGIC = b"SQAV"  # Aegis Quarantine AV

    def __init__(self, database):
        self.db = database
        self.vault_dir = QUARANTINE_DIR
        os.makedirs(self.vault_dir, exist_ok=True)
        logger.info("Quarantine vault: %s", self.vault_dir)

    def quarantine_file(self, file_path, threat_name="Unknown Threat"):
        """
        Quarantine a file by encrypting it and moving it to the vault.
        Returns quarantine record ID or None on failure.
        """
        if not os.path.exists(file_path):
            logger.error("Cannot quarantine - file not found: %s", file_path)
            return None

        try:
            # Read the original file
            with open(file_path, "rb") as f:
                original_data = f.read()

            # Compute hash before quarantine
            file_hash = hashlib.sha256(original_data).hexdigest()
            file_size = len(original_data)

            # Create quarantine filename
            timestamp = int(time.time() * 1000)
            safe_name = os.path.basename(file_path).replace(".", "_")
            quarantine_name = f"{timestamp}_{safe_name}.quarantine"
            quarantine_path = os.path.join(self.vault_dir, quarantine_name)

            # Build quarantine file:
            # [4 bytes: magic] [4 bytes: path length] [path bytes]
            # [4 bytes: data length] [XOR encrypted data]
            original_path_bytes = file_path.encode("utf-8")
            encrypted_data = self._xor_encrypt(original_data)

            with open(quarantine_path, "wb") as f:
                f.write(self.HEADER_MAGIC)
                f.write(struct.pack("<I", len(original_path_bytes)))
                f.write(original_path_bytes)
                f.write(struct.pack("<I", len(encrypted_data)))
                f.write(encrypted_data)

            # Remove the original file
            try:
                os.remove(file_path)
                logger.info("Quarantined: %s -> %s", file_path, quarantine_path)
            except PermissionError:
                # Try to make it removable
                try:
                    os.chmod(file_path, 0o777)
                    os.remove(file_path)
                except Exception as e:
                    logger.warning("Could not remove original file: %s", e)
                    # Still record it as quarantined but note the issue

            # Record in database
            record_id = self.db.add_quarantine(
                original_path=file_path,
                quarantine_path=quarantine_path,
                threat_name=threat_name,
                file_hash=file_hash,
                file_size=file_size
            )

            return record_id

        except Exception as e:
            logger.error("Quarantine failed for %s: %s", file_path, e)
            return None

    def restore_file(self, quarantine_id):
        """
        Restore a quarantined file to its original location.
        Returns True on success.
        """
        records = self.db.get_quarantined()
        record = None
        for r in records:
            if r["id"] == quarantine_id:
                record = r
                break

        if not record:
            logger.error("Quarantine record not found: %d", quarantine_id)
            return False

        quarantine_path = record["quarantine_path"]
        original_path = record["original_path"]

        if not os.path.exists(quarantine_path):
            logger.error("Quarantine file not found: %s", quarantine_path)
            return False

        try:
            # Read quarantine file
            with open(quarantine_path, "rb") as f:
                magic = f.read(4)
                if magic != self.HEADER_MAGIC:
                    logger.error("Invalid quarantine file format")
                    return False

                path_len = struct.unpack("<I", f.read(4))[0]
                stored_path = f.read(path_len).decode("utf-8")
                data_len = struct.unpack("<I", f.read(4))[0]
                encrypted_data = f.read(data_len)

            # Decrypt
            original_data = self._xor_encrypt(encrypted_data)

            # Verify hash
            restored_hash = hashlib.sha256(original_data).hexdigest()
            if record["file_hash"] and restored_hash != record["file_hash"]:
                logger.warning("Hash mismatch during restore - file may be corrupted")

            # Restore to original location
            restore_path = original_path
            os.makedirs(os.path.dirname(restore_path), exist_ok=True)

            with open(restore_path, "wb") as f:
                f.write(original_data)

            # Remove quarantine file
            os.remove(quarantine_path)

            # Update database
            self.db.mark_restored(quarantine_id)

            logger.info("Restored: %s -> %s", quarantine_path, restore_path)
            return True

        except Exception as e:
            logger.error("Restore failed for ID %d: %s", quarantine_id, e)
            return False

    def delete_permanently(self, quarantine_id):
        """
        Permanently delete a quarantined file.
        Returns True on success.
        """
        records = self.db.get_quarantined()
        record = None
        for r in records:
            if r["id"] == quarantine_id:
                record = r
                break

        if not record:
            logger.error("Quarantine record not found: %d", quarantine_id)
            return False

        quarantine_path = record["quarantine_path"]

        try:
            if os.path.exists(quarantine_path):
                # Overwrite with random data before deletion for security
                file_size = os.path.getsize(quarantine_path)
                with open(quarantine_path, "wb") as f:
                    f.write(os.urandom(file_size))
                os.remove(quarantine_path)

            self.db.mark_deleted(quarantine_id)
            logger.info("Permanently deleted quarantine ID: %d", quarantine_id)
            return True

        except Exception as e:
            logger.error("Delete failed for ID %d: %s", quarantine_id, e)
            return False

    def get_quarantined_files(self):
        """Get list of quarantined files."""
        return self.db.get_quarantined()

    def get_vault_size(self):
        """Get total size of quarantine vault in bytes."""
        total = 0
        try:
            for fname in os.listdir(self.vault_dir):
                fpath = os.path.join(self.vault_dir, fname)
                if os.path.isfile(fpath):
                    total += os.path.getsize(fpath)
        except Exception:
            pass
        return total

    def _xor_encrypt(self, data):
        """XOR encrypt/decrypt data (symmetric operation) with optimized list slicing."""
        key = self.XOR_KEY
        key_len = len(key)
        res = bytearray(data)
        for i in range(key_len):
            res[i::key_len] = [b ^ key[i] for b in res[i::key_len]]
        return bytes(res)

    def clean_vault(self, older_than_days=30):
        """Remove quarantine entries older than specified days."""
        records = self.db.get_quarantined()
        removed = 0
        for record in records:
            try:
                q_time = datetime.fromisoformat(record["quarantined_at"])
                age = (datetime.now() - q_time).days
                if age > older_than_days:
                    self.delete_permanently(record["id"])
                    removed += 1
            except Exception:
                pass
        logger.info("Cleaned %d old quarantine entries", removed)
        return removed
