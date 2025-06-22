"""
File Utilities for Enhanced File Monitoring
"""

import os
import hashlib
from typing import Dict, Optional
from pathlib import Path

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

def get_file_info(file_path: str) -> Dict:
    """Get detailed file information"""
    try:
        stat = os.stat(file_path)
        return {
            'size': stat.st_size,
            'extension': Path(file_path).suffix,
            'access_time': stat.st_atime,
            'modify_time': stat.st_mtime,
            'create_time': stat.st_ctime,
            'permissions': oct(stat.st_mode)[-3:]
        }
    except Exception:
        return {}

def calculate_file_hash(file_path: str) -> Optional[str]:
    """Calculate MD5 hash of file"""
    try:
        if not os.path.exists(file_path):
            return None
        
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception:
        return None

def is_suspicious_file(file_path: str) -> bool:
    """Check if file is suspicious"""
    suspicious_extensions = {
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
        '.scr', '.pif', '.com', '.hta', '.msi', '.msu', '.msp'
    }
    
    file_lower = file_path.lower()
    
    # Check extension
    if any(ext in file_lower for ext in suspicious_extensions):
        return True
    
    # Check suspicious locations
    suspicious_paths = ['temp', 'downloads', 'desktop', 'recent']
    if any(path in file_lower for path in suspicious_paths):
        return True
    
    return False
