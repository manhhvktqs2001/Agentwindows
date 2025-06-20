from .base_collector import BaseCollector
from ..schemas.events import EventData
import psutil
import hashlib
from datetime import datetime

class ProcessCollector(BaseCollector):
    """Thu thập sự kiện tiến trình (process) cho agent Windows"""
    def __init__(self, config_manager):
        super().__init__(config_manager, "ProcessCollector")

    def collect(self):
        """Thu thập tất cả process hiện tại trên hệ thống"""
        events = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'ppid', 'cmdline']):
            try:
                info = proc.info
                process_hash = self._hash_process(info.get('exe'))
                event = EventData(
                    event_type='Process',
                    event_action='Running',
                    event_timestamp=datetime.utcnow(),
                    process_id=info.get('pid'),
                    process_name=info.get('name'),
                    process_path=info.get('exe'),
                    command_line=' '.join(info.get('cmdline', [])),
                    parent_pid=info.get('ppid'),
                    process_user=info.get('username'),
                    process_hash=process_hash
                )
                events.append(event)
            except Exception:
                continue
        return events

    def _hash_process(self, exe_path):
        if not exe_path:
            return None
        try:
            with open(exe_path, 'rb') as f:
                data = f.read()
                return hashlib.sha256(data).hexdigest()
        except Exception:
            return None

    def _collect_data(self):
        """Thu thập dữ liệu process thực tế từ Windows"""
        return self.collect()
