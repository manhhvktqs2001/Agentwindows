"""
Registry Utilities for Enhanced Registry Monitoring
"""

import winreg
from typing import Optional

class RegistryUtils:
    @staticmethod
    def read_value(root, path, name):
        try:
            with winreg.OpenKey(root, path) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return value
        except Exception:
            return None

    @staticmethod
    def write_value(root, path, name, value, regtype=winreg.REG_SZ):
        try:
            with winreg.CreateKey(root, path) as key:
                winreg.SetValueEx(key, name, 0, regtype, value)
                return True
        except Exception:
            return False

    @staticmethod
    def delete_value(root, path, name):
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, name)
                return True
        except Exception:
            return False

def get_registry_value(key_path: str) -> Optional[str]:
    """Get registry value from key path"""
    try:
        # Parse key path
        if key_path.startswith('HKEY_LOCAL_MACHINE\\'):
            root_key = winreg.HKEY_LOCAL_MACHINE
            subkey = key_path.replace('HKEY_LOCAL_MACHINE\\', '')
        elif key_path.startswith('HKEY_CURRENT_USER\\'):
            root_key = winreg.HKEY_CURRENT_USER
            subkey = key_path.replace('HKEY_CURRENT_USER\\', '')
        else:
            return None
        
        # Open key and get default value
        with winreg.OpenKey(root_key, subkey, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, '')
            return str(value)
    except Exception:
        return None

def is_suspicious_registry_key(key_path: str) -> bool:
    """Check if registry key is suspicious"""
    suspicious_patterns = [
        'run', 'runonce', 'policies', 'shell', 'explorer',
        'winlogon', 'services', 'security', 'sam', 'system'
    ]
    
    key_lower = key_path.lower()
    return any(pattern in key_lower for pattern in suspicious_patterns)
