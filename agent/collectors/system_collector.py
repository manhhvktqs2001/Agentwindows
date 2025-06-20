import psutil
from ..schemas.events import EventData
from datetime import datetime

class SystemCollector:
    """Thu thập sự kiện hệ thống cho agent Windows"""
    def __init__(self):
        pass

    def collect(self):
        events = []
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        event = EventData(
            event_type='System',
            event_action='ResourceUsage',
            event_timestamp=datetime.utcnow(),
            cpu_usage=cpu,
            memory_usage=mem.percent,
            disk_usage=disk.percent
        )
        events.append(event)
        return events
