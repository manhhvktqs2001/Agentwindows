import os
import hashlib

class FileUtils:
    @staticmethod
    def read_file(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            return None

    @staticmethod
    def write_file(path, data):
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(data)
                return True
        except Exception:
            return False

    @staticmethod
    def delete_file(path):
        try:
            os.remove(path)
            return True
        except Exception:
            return False

    @staticmethod
    def hash_file(path):
        try:
            with open(path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return None
