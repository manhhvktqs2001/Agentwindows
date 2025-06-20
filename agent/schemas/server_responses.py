from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

@dataclass
class ServerResponse:
    success: bool
    message: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    alerts: Optional[List[Dict[str, Any]]] = None
    commands: Optional[List[Dict[str, Any]]] = None
