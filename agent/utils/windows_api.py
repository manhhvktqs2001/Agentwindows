import platform
import getpass

class WindowsAPIUtils:
    @staticmethod
    def get_os_version():
        return platform.platform()

    @staticmethod
    def get_hostname():
        return platform.node()

    @staticmethod
    def get_current_user():
        return getpass.getuser()
