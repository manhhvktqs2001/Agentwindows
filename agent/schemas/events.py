# agent/schemas/events.py - COMPLETELY FIXED VERSION
"""
Event Data Schemas - Fixed for server compatibility
Ensures schema compatibility between agent and server
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

class EventType(str, Enum):
    """Event type enumeration"""
    PROCESS = "Process"
    FILE = "File"
    NETWORK = "Network"
    REGISTRY = "Registry"
    AUTHENTICATION = "Authentication"
    SYSTEM = "System"

class EventAction(str, Enum):
    """Event action enumeration - FIXED WITH ALL REQUIRED ACTIONS"""
    # Basic actions
    CREATE = "Create"
    MODIFY = "Modify"
    DELETE = "Delete"
    ACCESS = "Access"
    START = "Start"
    STOP = "Stop"
    CONNECT = "Connect"
    DISCONNECT = "Disconnect"
    
    # Legacy actions (for compatibility)
    CREATED = "Created"
    MODIFIED = "Modified"
    DELETED = "Deleted"
    ACCESSED = "Accessed"
    STARTED = "Started"
    STOPPED = "Stopped"
    CONNECTED = "Connected"
    DISCONNECTED = "Disconnected"
    
    # Authentication actions
    LOGIN = "Login"
    LOGOUT = "Logout"
    SESSION = "Session"  # ADDED: For session events
    FAILED = "Failed"
    SUCCESS = "Success"
    
    # Security actions - FIXED: Added missing actions
    DETECTED = "Detected"
    BLOCKED = "Blocked"
    ALLOWED = "Allowed"
    SUSPICIOUS_ACTIVITY = "SuspiciousActivity"
    SUSPICIOUS = "Suspicious"  # ADDED: For file collector
    
    # Resource monitoring
    RESOURCE_USAGE = "ResourceUsage"
    CPU_SPIKE = "CpuSpike"
    MEMORY_LEAK = "MemoryLeak"
    DISK_IO_HIGH = "DiskIoHigh"
    NETWORK_USAGE = "NetworkUsage"
    
    # Network specific
    CONNECTION = "Connection"
    CONNECTION_CLOSED = "ConnectionClosed"
    DNS_QUERY = "DnsQuery"
    HTTP_REQUEST = "HttpRequest"
    SSL_CONNECTION = "SslConnection"
    PORT_SCAN = "PortScan"
    NETWORK_CONNECTION = "NetworkConnection"
    
    # Process specific
    TERMINATE = "Terminate"
    FILE_ACCESS = "FileAccess"
    
    # Registry specific
    REGISTRY_ACCESS = "RegistryAccess"
    STARTUP_ENTRY = "StartupEntry"
    
    # System specific
    SYSTEM_BOOT = "SystemBoot"
    SYSTEM_LOAD = "SystemLoad"
    ANOMALY_DETECTED = "AnomalyDetected"

class Severity(str, Enum):
    """Event severity enumeration - for agent use"""
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class EventSeverity(str, Enum):
    """Event severity enumeration - matching server schema"""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ThreatLevel(str, Enum):
    """Threat level enumeration"""
    NONE = "None"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"

@dataclass
class EventData:
    """Base event data structure - COMPLETELY FIXED"""
    # Required fields
    event_type: str
    event_action: str
    event_timestamp: datetime
    
    # Core attributes
    severity: str = "Info"
    agent_id: Optional[str] = None
    description: Optional[str] = None
    
    # Process events
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_process_name: Optional[str] = None
    process_user: Optional[str] = None
    process_hash: Optional[str] = None
    
    # File events
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    file_extension: Optional[str] = None
    file_operation: Optional[str] = None
    
    # Network events
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    direction: Optional[str] = None
    
    # ✅ ENHANCED: Network connections array for comprehensive network data
    network_connections: Optional[List[Dict[str, Any]]] = None
    
    # Registry events - FIXED: Use correct field names matching server
    registry_key: Optional[str] = None
    registry_value_name: Optional[str] = None  # Server expects this field
    registry_value_data: Optional[str] = None  # Server expects this field
    registry_operation: Optional[str] = None
    
    # Authentication events
    login_user: Optional[str] = None
    login_type: Optional[str] = None
    login_result: Optional[str] = None
    
    # System events
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    
    # Additional data
    raw_event_data: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Validate data after initialization"""
        # Ensure severity is valid
        valid_severities = ['Info', 'Low', 'Medium', 'High', 'Critical']
        if self.severity not in valid_severities:
            self.severity = 'Info'
        
        # Ensure event_type is valid
        valid_types = ['Process', 'File', 'Network', 'Registry', 'Authentication', 'System']
        if self.event_type not in valid_types:
            raise ValueError(f"Invalid event_type: {self.event_type}")
        
        # Set default description if not provided
        if not self.description:
            self.description = f"{self.event_type} {self.event_action}"
    
    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity to server-compatible format"""
        severity_mapping = {
            # Agent format -> Server format
            'Info': 'INFO',
            'Low': 'LOW',
            'Medium': 'MEDIUM',
            'High': 'HIGH',
            'Critical': 'CRITICAL',
            # Already correct format
            'INFO': 'INFO',
            'LOW': 'LOW',
            'MEDIUM': 'MEDIUM',
            'HIGH': 'HIGH',
            'CRITICAL': 'CRITICAL'
        }
        
        normalized = severity_mapping.get(severity, 'INFO')
        return normalized
    
    @classmethod
    def create_with_severity(cls, severity: str, **kwargs) -> 'EventData':
        """Create EventData with proper severity normalization"""
        # Create instance
        instance = cls(**kwargs)
        # Set and normalize severity
        instance.severity = instance._normalize_severity(severity)
        return instance
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {}
        for key, value in self.__dict__.items():
            if value is not None:
                if isinstance(value, datetime):
                    result[key] = value.isoformat()
                else:
                    result[key] = value
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EventData':
        """Create EventData from dictionary"""
        # Convert timestamp string back to datetime if needed
        if 'event_timestamp' in data and isinstance(data['event_timestamp'], str):
            data['event_timestamp'] = datetime.fromisoformat(data['event_timestamp'])
        
        return cls(**data)
    
    def get_event_summary(self) -> str:
        """Get a brief summary of the event"""
        if self.event_type == 'Process':
            return f"Process {self.event_action}: {self.process_name} (PID: {self.process_id})"
        elif self.event_type == 'File':
            return f"File {self.event_action}: {self.file_name}"
        elif self.event_type == 'Network':
            return f"Network {self.event_action}: {self.destination_ip}:{self.destination_port}"
        elif self.event_type == 'Registry':
            return f"Registry {self.event_action}: {self.registry_key}"
        elif self.event_type == 'Authentication':
            return f"Auth {self.event_action}: {self.login_user}"
        elif self.event_type == 'System':
            return f"System {self.event_action}: CPU {self.cpu_usage}%"
        else:
            return f"{self.event_type} {self.event_action}"
    
    def is_high_severity(self) -> bool:
        """Check if event is high or critical severity"""
        return self.severity in ['High', 'Critical']
    
    def add_context(self, context: Dict[str, Any]):
        """Add additional context to raw_event_data"""
        if self.raw_event_data:
            self.raw_event_data.update(context)
        else:
            self.raw_event_data = context

# Helper functions for creating events
def create_process_event(severity: str = "INFO", **kwargs) -> EventData:
    """Create a process event"""
    return EventData.create_with_severity(severity, event_type="Process", **kwargs)

def create_file_event(severity: str = "INFO", **kwargs) -> EventData:
    """Create a file event"""
    return EventData.create_with_severity(severity, event_type="File", **kwargs)

def create_network_event(severity: str = "INFO", **kwargs) -> EventData:
    """Create a network event"""
    return EventData.create_with_severity(severity, event_type="Network", **kwargs)

def create_registry_event(severity: str = "INFO", **kwargs) -> EventData:
    """Create a registry event"""
    return EventData.create_with_severity(severity, event_type="Registry", **kwargs)

def create_authentication_event(severity: str = "INFO", **kwargs) -> EventData:
    """Create an authentication event"""
    return EventData.create_with_severity(severity, event_type="Authentication", **kwargs)

def create_system_event(severity: str = "INFO", **kwargs) -> EventData:
    """Create a system event"""
    return EventData.create_with_severity(severity, event_type="System", **kwargs)

# Utility functions
def normalize_severity(severity: str) -> str:
    """Normalize severity string to standard format"""
    severity_mapping = {
        'info': 'INFO',
        'low': 'LOW', 
        'medium': 'MEDIUM',
        'high': 'HIGH',
        'critical': 'CRITICAL',
        'Info': 'INFO',
        'Low': 'LOW',
        'Medium': 'MEDIUM', 
        'High': 'HIGH',
        'Critical': 'CRITICAL'
    }
    return severity_mapping.get(severity, 'INFO')

def get_severity_level(severity: str) -> int:
    """Get numeric level for severity comparison"""
    severity_levels = {
        'INFO': 0,
        'LOW': 1,
        'MEDIUM': 2,
        'HIGH': 3,
        'CRITICAL': 4
    }
    return severity_levels.get(severity.upper(), 0)