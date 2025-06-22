"""
Network Utilities for Enhanced Network Monitoring
"""

import socket
import requests
from typing import Dict, Optional

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

def get_connection_info(conn) -> Dict:
    """Get detailed connection information"""
    try:
        return {
            'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
            'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
            'status': conn.status,
            'family': conn.family,
            'type': conn.type,
            'pid': conn.pid
        }
    except Exception:
        return {}

def is_suspicious_connection(conn) -> bool:
    """Check if connection is suspicious"""
    try:
        if not conn.raddr:
            return False
        
        # Check for suspicious ports
        suspicious_ports = {22, 23, 3389, 445, 135, 139, 1433, 3306, 5432}
        if conn.raddr.port in suspicious_ports:
            return True
        
        # Check for private IP ranges
        remote_ip = conn.raddr.ip
        if remote_ip.startswith(('10.', '172.16.', '192.168.')):
            return True
        
        # Check for localhost
        if remote_ip in ('127.0.0.1', 'localhost', '::1'):
            return True
        
        return False
    except Exception:
        return False

def resolve_hostname(ip_address: str) -> Optional[str]:
    """Resolve hostname from IP address"""
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except Exception:
        return None
