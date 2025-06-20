import os
import hashlib

class AntiTamper:
    """Bảo vệ agent khỏi bị sửa/xóa, phát hiện can thiệp"""
    def __init__(self, files_to_protect):
        self.files_to_protect = files_to_protect
        self.hashes = self._hash_files()

    def _hash_files(self):
        hashes = {}
        for f in self.files_to_protect:
            try:
                with open(f, 'rb') as file:
                    data = file.read()
                    hashes[f] = hashlib.sha256(data).hexdigest()
            except Exception:
                hashes[f] = None
        return hashes

    def check_integrity(self):
        tampered = []
        for f, old_hash in self.hashes.items():
            try:
                with open(f, 'rb') as file:
                    data = file.read()
                    new_hash = hashlib.sha256(data).hexdigest()
                    if old_hash != new_hash:
                        tampered.append(f)
            except Exception:
                tampered.append(f)
        return tampered
