from cryptography.fernet import Fernet

class EncryptionUtils:
    """Hỗ trợ mã hóa/giải mã dữ liệu (AES/Fernet)"""
    def __init__(self, key=None):
        self.key = key or Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt(self, data: bytes) -> bytes:
        return self.cipher.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        return self.cipher.decrypt(token)
