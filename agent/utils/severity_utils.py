# agent/utils/severity_utils.py
"""
Severity Utilities - Helper functions for severity determination and normalization
"""

from typing import Dict, List, Any, Optional

class SeverityCalculator:
    """Calculate event severity based on various indicators"""
    
    # Process severity indicators
    CRITICAL_PROCESSES = {
        'mimikatz', 'procdump', 'pwdump', 'lazagne', 'bloodhound'
    }
    
    HIGH_RISK_PROCESSES = {
        'powershell', 'cmd', 'rundll32', 'regsvr32', 'mshta', 
        'wscript', 'cscript', 'certutil', 'bitsadmin'
    }
    
    SUSPICIOUS_PATHS = {
        'temp', 'appdata', 'programdata', 'users\\public'
    }
    
    # File severity indicators
    EXECUTABLE_EXTENSIONS = {
        '.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.scr', '.com', '.pif'
    }
    
    SCRIPT_EXTENSIONS = {
        '.py', '.js', '.vbs', '.sh', '.pl', '.php', '.rb'
    }
    
    # Network severity indicators
    SUSPICIOUS_PORTS = {
        4444, 5555, 6666, 7777, 8888, 9999,  # Common backdoor ports
        1337, 31337, 12345, 54321,           # RAT ports
        2222, 3333, 10101, 20202,            # Backdoor ports
        8333, 8332, 9332, 9333,              # Bitcoin mining
        9050, 9051, 9150, 9151               # Tor
    }
    
    @classmethod
    def calculate_process_severity(cls, 
                                 process_name: str = None,
                                 process_path: str = None, 
                                 command_line: str = None,
                                 parent_process: str = None) -> str:
        """Calculate severity for process events"""
        try:
            # Normalize inputs
            process_name = (process_name or '').lower()
            process_path = (process_path or '').lower()
            command_line = (command_line or '').lower()
            parent_process = (parent_process or '').lower()
            
            # Critical indicators
            if any(proc in process_name for proc in cls.CRITICAL_PROCESSES):
                return 'CRITICAL'
            
            if any(proc in command_line for proc in cls.CRITICAL_PROCESSES):
                return 'CRITICAL'
            
            # High severity indicators
            high_indicators = [
                # Encoded PowerShell
                'powershell' in process_name and ('-enc' in command_line or '-encoded' in command_line),
                # Suspicious command line tools
                'certutil' in command_line and ('download' in command_line or 'urlcache' in command_line),
                'bitsadmin' in command_line and 'transfer' in command_line,
                # Registry manipulation
                'reg' in process_name and 'add' in command_line,
                # Suspicious paths
                any(path in process_path for path in cls.SUSPICIOUS_PATHS),
                # Process injection indicators
                'rundll32' in process_name and len(command_line) > 50,
                'regsvr32' in process_name and ('scrobj' in command_line or 'http' in command_line)
            ]
            
            if any(high_indicators):
                return 'HIGH'
            
            # Medium severity indicators
            medium_indicators = [
                process_name in cls.HIGH_RISK_PROCESSES,
                process_path.endswith(('.bat', '.cmd', '.vbs', '.js', '.ps1')),
                'powershell' in process_name,
                'cmd' in process_name,
                'wscript' in process_name,
                'cscript' in process_name
            ]
            
            if any(medium_indicators):
                return 'MEDIUM'
            
            # Low severity for unknown processes
            if process_name and not process_path:
                return 'LOW'
            
            return 'INFO'
            
        except Exception:
            return 'INFO'
    
    @classmethod
    def calculate_file_severity(cls,
                              file_name: str = None,
                              file_path: str = None,
                              file_extension: str = None,
                              file_size: int = None,
                              operation: str = None) -> str:
        """Calculate severity for file events"""
        try:
            # Normalize inputs
            file_name = (file_name or '').lower()
            file_path = (file_path or '').lower()
            file_extension = (file_extension or '').lower()
            operation = (operation or '').lower()
            
            # Critical indicators
            critical_indicators = [
                # System file modifications
                'system32' in file_path and operation in ['modify', 'delete'],
                # Boot sector files
                file_name in ['boot.ini', 'bootmgr', 'ntldr'],
                # Ransomware-like behavior
                file_extension in ['.encrypted', '.locked', '.crypto', '.crypt']
            ]
            
            if any(critical_indicators):
                return 'CRITICAL'
            
            # High severity indicators
            high_indicators = [
                # Executable files in suspicious locations
                file_extension in cls.EXECUTABLE_EXTENSIONS and any(path in file_path for path in cls.SUSPICIOUS_PATHS),
                # Large executable files
                file_extension in cls.EXECUTABLE_EXTENSIONS and file_size and file_size > 50 * 1024 * 1024,
                # Script files
                file_extension in cls.SCRIPT_EXTENSIONS,
                # System directory access
                'windows\\system32' in file_path,
                'program files' in file_path
            ]
            
            if any(high_indicators):
                return 'HIGH'
            
            # Medium severity indicators
            medium_indicators = [
                file_extension in cls.EXECUTABLE_EXTENSIONS,
                file_size and file_size > 100 * 1024 * 1024,  # Large files > 100MB
                operation in ['delete', 'move'],
                'startup' in file_path
            ]
            
            if any(medium_indicators):
                return 'MEDIUM'
            
            return 'INFO'
            
        except Exception:
            return 'INFO'
    
    @classmethod
    def calculate_network_severity(cls,
                                 destination_ip: str = None,
                                 destination_port: int = None,
                                 source_port: int = None,
                                 direction: str = None,
                                 protocol: str = None) -> str:
        """Calculate severity for network events"""
        try:
            # Critical indicators
            if destination_port in cls.SUSPICIOUS_PORTS:
                return 'HIGH'
            
            # High severity indicators
            high_indicators = [
                # Outbound connections on suspicious ports
                direction == 'Outbound' and destination_port and destination_port > 49152,
                # High numbered ports
                destination_port and destination_port in range(60000, 65535),
                # Non-standard ports for common protocols
                destination_port in [8080, 8443, 8888] and protocol == 'TCP'
            ]
            
            if any(high_indicators):
                return 'MEDIUM'
            
            # Check for external connections
            if destination_ip and cls._is_external_ip(destination_ip):
                return 'LOW'
            
            return 'INFO'
            
        except Exception:
            return 'INFO'
    
    @classmethod
    def calculate_registry_severity(cls,
                                  registry_key: str = None,
                                  value_name: str = None,
                                  operation: str = None) -> str:
        """Calculate severity for registry events"""
        try:
            registry_key = (registry_key or '').lower()
            value_name = (value_name or '').lower()
            operation = (operation or '').lower()
            
            # Critical indicators
            critical_indicators = [
                # Security feature disabling
                'windows defender' in registry_key and 'disable' in value_name,
                'firewall' in registry_key and operation == 'delete',
                'uac' in registry_key and 'enable' in value_name
            ]
            
            if any(critical_indicators):
                return 'CRITICAL'
            
            # High severity indicators
            high_indicators = [
                # Startup persistence
                '\\run' in registry_key and operation in ['create', 'modify'],
                # Service modifications
                'services' in registry_key,
                # Policy changes
                'policies' in registry_key,
                # File association hijacking
                'shell\\open\\command' in registry_key
            ]
            
            if any(high_indicators):
                return 'HIGH'
            
            # Medium severity for any registry modification
            if operation in ['create', 'modify', 'delete']:
                return 'MEDIUM'
            
            return 'INFO'
            
        except Exception:
            return 'INFO'
    
    @classmethod
    def calculate_authentication_severity(cls,
                                        login_result: str = None,
                                        login_type: str = None,
                                        login_user: str = None) -> str:
        """Calculate severity for authentication events"""
        try:
            login_result = (login_result or '').lower()
            login_type = (login_type or '').lower()
            login_user = (login_user or '').lower()
            
            # High severity indicators
            if login_result == 'failed':
                return 'MEDIUM'
            
            # Administrator logins
            if 'admin' in login_user or login_user == 'administrator':
                return 'MEDIUM'
            
            # Remote logins
            if 'remote' in login_type or 'network' in login_type:
                return 'LOW'
            
            return 'INFO'
            
        except Exception:
            return 'INFO'
    
    @classmethod
    def _is_external_ip(cls, ip: str) -> bool:
        """Check if IP is external (not private)"""
        try:
            import ipaddress
            ip_obj = ipaddress.IPv4Address(ip)
            
            private_ranges = [
                ipaddress.IPv4Network('10.0.0.0/8'),
                ipaddress.IPv4Network('172.16.0.0/12'),
                ipaddress.IPv4Network('192.168.0.0/16'),
                ipaddress.IPv4Network('127.0.0.0/8')
            ]
            
            return not any(ip_obj in private_range for private_range in private_ranges)
        except Exception:
            return False

# Convenience functions
def normalize_severity(severity: str) -> str:
    """Normalize severity to server format"""
    severity_mapping = {
        'Info': 'INFO',
        'Low': 'LOW',
        'Medium': 'MEDIUM', 
        'High': 'HIGH',
        'Critical': 'CRITICAL',
        'INFO': 'INFO',
        'LOW': 'LOW',
        'MEDIUM': 'MEDIUM',
        'HIGH': 'HIGH',
        'CRITICAL': 'CRITICAL'
    }
    return severity_mapping.get(severity, 'INFO')

def calculate_event_severity(event_type: str, **kwargs) -> str:
    """Calculate event severity based on type and parameters"""
    event_type = event_type.lower()
    
    if event_type == 'process':
        return SeverityCalculator.calculate_process_severity(**kwargs)
    elif event_type == 'file':
        return SeverityCalculator.calculate_file_severity(**kwargs)
    elif event_type == 'network':
        return SeverityCalculator.calculate_network_severity(**kwargs)
    elif event_type == 'registry':
        return SeverityCalculator.calculate_registry_severity(**kwargs)
    elif event_type == 'authentication':
        return SeverityCalculator.calculate_authentication_severity(**kwargs)
    else:
        return 'INFO'