from .base_collector import BaseCollector
from ..schemas.events import EventData
import psutil
from datetime import datetime

class SystemCollector(BaseCollector):
    """Thu thập sự kiện hệ thống cho agent Windows"""
    def __init__(self, config_manager):
        super().__init__(config_manager, "SystemCollector")

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

    def _collect_data(self):
        """Thu thập dữ liệu hệ thống thực tế từ Windows"""
        return self.collect()
