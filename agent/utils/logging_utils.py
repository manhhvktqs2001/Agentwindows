# agent/utils/logging_utils.py
"""
Logging Utilities - Setup and configure logging for the agent
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

def setup_logging(config: Optional[dict] = None) -> logging.Logger:
    """Setup logging configuration for the agent"""
    
    # Default configuration
    if config is None:
        config = {
            'level': 'INFO',
            'file_enabled': True,
            'console_enabled': True,
            'log_directory': 'logs',
            'max_file_size': '10MB',
            'backup_count': 5
        }
    
    # Create logs directory
    log_dir = Path(config.get('log_directory', 'logs'))
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, config.get('level', 'INFO').upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    if config.get('console_enabled', True):
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler
    if config.get('file_enabled', True):
        log_file = log_dir / 'edr_agent.log'
        
        # Parse file size
        max_size = config.get('max_file_size', '10MB')
        if isinstance(max_size, str):
            if max_size.upper().endswith('MB'):
                max_bytes = int(max_size[:-2]) * 1024 * 1024
            elif max_size.upper().endswith('KB'):
                max_bytes = int(max_size[:-2]) * 1024
            else:
                max_bytes = int(max_size)
        else:
            max_bytes = max_size
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=config.get('backup_count', 5),
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Create agent-specific logger
    agent_logger = logging.getLogger('EDRAgent')
    agent_logger.info("🛡️ EDR Agent logging initialized")
    
    return agent_logger

# agent/utils/process_utils.py
"""
Process Utilities - Helper functions for process monitoring
"""

import psutil
import hashlib
import platform
from pathlib import Path
from typing import Optional, Dict, Any

def get_process_info(pid: int) -> Optional[Dict[str, Any]]:
    """Get detailed process information"""
    try:
        process = psutil.Process(pid)
        
        info = {
            'pid': pid,
            'name': process.name(),
            'status': process.status(),
            'create_time': process.create_time(),
            'cpu_percent': process.cpu_percent(),
            'memory_percent': process.memory_percent(),
            'num_threads': process.num_threads()
        }
        
        # Additional info with error handling
        try:
            info['exe'] = process.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            info['exe'] = None
        
        try:
            info['cmdline'] = ' '.join(process.cmdline())
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            info['cmdline'] = None
        
        try:
            info['username'] = process.username()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            info['username'] = None
        
        try:
            parent = process.parent()
            if parent:
                info['parent_pid'] = parent.pid
                info['parent_name'] = parent.name()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            info['parent_pid'] = None
            info['parent_name'] = None
        
        return info
        
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def get_process_hash(executable_path: str) -> Optional[str]:
    """Calculate hash of process executable"""
    try:
        if not executable_path or not Path(executable_path).exists():
            return None
        
        hash_sha256 = hashlib.sha256()
        with open(executable_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        
        return hash_sha256.hexdigest()
        
    except Exception:
        return None

def is_system_process(process_name: str) -> bool:
    """Check if process is a system process"""
    if not process_name:
        return False
    
    system_processes = {
        'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
        'services.exe', 'lsass.exe', 'svchost.exe', 'spoolsv.exe', 'explorer.exe'
    }
    
    return process_name.lower() in system_processes

# agent/utils/windows_api.py
"""
Windows API Utilities - Windows-specific API calls
"""

import platform
from typing import Optional, Dict, Any

class WindowsAPI:
    """Windows API wrapper for security monitoring"""
    
    def __init__(self):
        self.is_windows = platform.system().lower() == 'windows'
        self.wmi = None
        self.win32api = None
        
        if self.is_windows:
            self._initialize_windows_modules()
    
    def _initialize_windows_modules(self):
        """Initialize Windows-specific modules"""
        try:
            import wmi
            self.wmi = wmi.WMI()
        except ImportError:
            pass
        
        try:
            import win32api
            self.win32api = win32api
        except ImportError:
            pass
    
    def get_process_details(self, pid: int) -> Optional[Dict[str, Any]]:
        """Get Windows-specific process details"""
        if not self.is_windows or not self.wmi:
            return None
        
        try:
            for process in self.wmi.Win32_Process(ProcessId=pid):
                return {
                    'process_id': process.ProcessId,
                    'name': process.Name,
                    'executable_path': process.ExecutablePath,
                    'command_line': process.CommandLine,
                    'parent_process_id': process.ParentProcessId,
                    'creation_date': process.CreationDate,
                    'session_id': process.SessionId,
                    'priority': process.Priority
                }
        except Exception:
            pass
        
        return None
    
    def get_file_version_info(self, file_path: str) -> Optional[Dict[str, str]]:
        """Get file version information"""
        if not self.is_windows or not self.win32api:
            return None
        
        try:
            import win32api
            info = win32api.GetFileVersionInfo(file_path, "\\")
            ms = info['FileVersionMS']
            ls = info['FileVersionLS']
            version = f"{win32api.HIWORD(ms)}.{win32api.LOWORD(ms)}.{win32api.HIWORD(ls)}.{win32api.LOWORD(ls)}"
            
            return {
                'version': version,
                'company': info.get('CompanyName', ''),
                'description': info.get('FileDescription', ''),
                'product': info.get('ProductName', '')
            }
        except Exception:
            return None
    
    def is_available(self) -> bool:
        """Check if Windows API is available"""
        return self.is_windows and (self.wmi is not None or self.win32api is not None)

# agent/utils/file_utils.py
"""
File Utilities - Helper functions for file operations
"""

import hashlib
import mimetypes
from pathlib import Path
from typing import Optional, Dict, Any

def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
    """Calculate file hash using specified algorithm"""
    try:
        if algorithm == 'md5':
            hasher = hashlib.md5()
        elif algorithm == 'sha1':
            hasher = hashlib.sha1()
        elif algorithm == 'sha256':
            hasher = hashlib.sha256()
        else:
            return None
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        
        return hasher.hexdigest()
        
    except Exception:
        return None

def get_file_metadata(file_path: str) -> Dict[str, Any]:
    """Get file metadata"""
    try:
        path_obj = Path(file_path)
        
        if not path_obj.exists():
            return {}
        
        stat_info = path_obj.stat()
        
        metadata = {
            'name': path_obj.name,
            'extension': path_obj.suffix.lower(),
            'size': stat_info.st_size,
            'created': stat_info.st_ctime,
            'modified': stat_info.st_mtime,
            'accessed': stat_info.st_atime,
            'is_file': path_obj.is_file(),
            'is_directory': path_obj.is_dir(),
            'is_symlink': path_obj.is_symlink()
        }
        
        # MIME type
        mime_type, _ = mimetypes.guess_type(str(path_obj))
        metadata['mime_type'] = mime_type
        
        return metadata
        
    except Exception:
        return {}

def is_executable_file(file_path: str) -> bool:
    """Check if file is executable"""
    try:
        path_obj = Path(file_path)
        
        # Check by extension
        executable_extensions = {'.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.scr', '.com', '.pif'}
        if path_obj.suffix.lower() in executable_extensions:
            return True
        
        # Check MIME type
        mime_type, _ = mimetypes.guess_type(str(path_obj))
        if mime_type and 'executable' in mime_type:
            return True
        
        return False
        
    except Exception:
        return False

# agent/utils/network_utils.py
"""
Network Utilities - Helper functions for network monitoring
"""

import socket
import ipaddress
from typing import Optional, Dict, Any, List

def get_local_ip() -> Optional[str]:
    """Get local IP address"""
    try:
        # Connect to a remote address to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return None

def is_private_ip(ip: str) -> bool:
    """Check if IP address is private"""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def get_network_connections(pid: Optional[int] = None) -> List[Dict[str, Any]]:
    """Get network connections for a process or all processes"""
    try:
        import psutil
        
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if pid is None or conn.pid == pid:
                conn_info = {
                    'pid': conn.pid,
                    'family': conn.family.name if conn.family else None,
                    'type': conn.type.name if conn.type else None,
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status
                }
                connections.append(conn_info)
        
        return connections
        
    except Exception:
        return []

def resolve_hostname(ip: str) -> Optional[str]:
    """Resolve IP address to hostname"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return None