import winreg

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
