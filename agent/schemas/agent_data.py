# agent/schemas/agent_data.py
"""
Agent Data Schemas - Data structures for agent communication
"""

from dataclasses import dataclass
from typing import Optional
from datetime import datetime

@dataclass
class AgentRegistrationData:
    """Agent registration data"""
    hostname: str
    ip_address: str
    operating_system: str
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    agent_version: str = "1.0.0"
    mac_address: Optional[str] = None
    domain: Optional[str] = None
    install_path: Optional[str] = None

@dataclass
class AgentHeartbeatData:
    """Agent heartbeat data"""
    hostname: str
    status: str = "Active"
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_latency: int = 0

# agent/schemas/events.py
"""
Event Data Schemas - Data structures for security events
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime

@dataclass
class EventData:
    """Base event data structure"""
    # Required fields
    event_type: str  # Process, File, Network, Registry, Authentication, System
    event_action: str  # Create, Delete, Modify, Access, etc.
    event_timestamp: datetime
    severity: str = "Info"  # Info, Low, Medium, High, Critical
    
    # Agent information
    agent_id: Optional[str] = None
    
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
    
    # Registry events
    registry_key: Optional[str] = None
    registry_value_name: Optional[str] = None
    registry_value_data: Optional[str] = None
    registry_operation: Optional[str] = None
    
    # Authentication events
    login_user: Optional[str] = None
    login_type: Optional[str] = None
    login_result: Optional[str] = None
    
    # Additional data
    raw_event_data: Optional[Dict[str, Any]] = None

# agent/schemas/server_responses.py
"""
Server Response Schemas - Data structures for server responses
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from datetime import datetime

@dataclass
class ServerResponse:
    """Base server response"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

@dataclass
class RegistrationResponse(ServerResponse):
    """Agent registration response"""
    agent_id: Optional[str] = None
    config_version: Optional[str] = None
    heartbeat_interval: Optional[int] = None
    monitoring_enabled: Optional[bool] = None

@dataclass
class HeartbeatResponse(ServerResponse):
    """Heartbeat response"""
    config_version: Optional[str] = None
    monitoring_enabled: Optional[bool] = None
    next_heartbeat: Optional[int] = None

@dataclass
class EventSubmissionResponse(ServerResponse):
    """Event submission response"""
    event_id: Optional[int] = None
    threat_detected: bool = False
    risk_score: int = 0
    alerts_generated: List[int] = None

@dataclass
class ConfigResponse(ServerResponse):
    """Agent configuration response"""
    agent_id: Optional[str] = None
    hostname: Optional[str] = None
    config_version: Optional[str] = None
    monitoring_enabled: Optional[bool] = None
    heartbeat_interval: Optional[int] = None
    event_batch_size: Optional[int] = None
    collection_settings: Optional[Dict[str, Any]] = None
    detection_settings: Optional[Dict[str, Any]] = None