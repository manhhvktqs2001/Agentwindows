from .base_collector import BaseCollector
from ..schemas.events import EventData
import psutil
from datetime import datetime
import asyncio
import json

class SystemCollector(BaseCollector):
    """System event collector for Windows agent"""
    def __init__(self, config_manager):
        super().__init__(config_manager, "System")

    def collect(self):
        events = []
        try:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            event = EventData(
                event_type='System',
                event_action='ResourceUsage',
                event_timestamp=datetime.now(),
                severity='Info',
                description=f'System resource usage - CPU: {cpu}%, Memory: {mem.percent}%, Disk: {disk.percent}%',
                source_ip='127.0.0.1',
                destination_ip='',
                source_port=0,
                destination_port=0,
                protocol='',
                cpu_usage=cpu,
                memory_usage=mem.percent,
                disk_usage=disk.percent,
                raw_event_data=json.dumps({
                    'cpu_percent': cpu,
                    'memory_percent': mem.percent,
                    'disk_percent': disk.percent,
                    'memory_available': mem.available,
                    'memory_total': mem.total,
                    'disk_free': disk.free,
                    'disk_total': disk.total,
                    'timestamp': datetime.now().isoformat()
                })
            )
            events.append(event)
        except Exception:
            pass
        return events

    async def _collect_data(self):
        """Collect system data from Windows (async)"""
        return await asyncio.to_thread(self.collect)
