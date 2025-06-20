import hashlib
import base64
import os

class CryptoUtils:
    @staticmethod
    def sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def base64_encode(data: bytes) -> str:
        return base64.b64encode(data).decode()

    @staticmethod
    def base64_decode(data: str) -> bytes:
        return base64.b64decode(data)

    @staticmethod
    def random_key(length=32) -> bytes:
        return os.urandom(length)
