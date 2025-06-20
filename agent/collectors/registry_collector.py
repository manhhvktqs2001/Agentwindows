from .base_collector import BaseCollector
from ..schemas.events import EventData
from datetime import datetime
import winreg
import asyncio

class RegistryCollector(BaseCollector):
    """Thu thập sự kiện registry cho agent Windows (khung cơ bản)"""
    def __init__(self, config_manager):
        super().__init__(config_manager, "RegistryCollector")

    def collect(self):
        events = []
        # Thu thập các key phổ biến (ví dụ: Run key)
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") as key:
                i = 0
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(key, i)
                        event = EventData(
                            event_type='Registry',
                            event_action='Read',
                            event_timestamp=datetime.utcnow(),
                            registry_key=r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                            registry_value_name=value_name,
                            registry_value_data=value_data,
                            registry_operation='Read'
                        )
                        events.append(event)
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass
        return events

    async def _collect_data(self):
        """Thu thập dữ liệu registry thực tế từ Windows (async)"""
        return await asyncio.to_thread(self.collect)
