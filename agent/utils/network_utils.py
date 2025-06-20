import socket
import requests

class NetworkUtils:
    @staticmethod
    def is_connected(host='8.8.8.8', port=53, timeout=3):
        try:
            socket.setdefaulttimeout(timeout)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
            return True
        except Exception:
            return False

    @staticmethod
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None

    @staticmethod
    def get_public_ip():
        try:
            return requests.get('https://api.ipify.org').text
        except Exception:
            return None

    @staticmethod
    def http_get(url, **kwargs):
        try:
            return requests.get(url, **kwargs)
        except Exception:
            return None

    @staticmethod
    def http_post(url, data=None, json=None, **kwargs):
        try:
            return requests.post(url, data=data, json=json, **kwargs)
        except Exception:
            return None
