from .base_collector import BaseCollector
from ..schemas.events import EventData
import psutil
from datetime import datetime

class NetworkCollector(BaseCollector):
    """Thu thập sự kiện mạng cho agent Windows"""
    def __init__(self, config_manager):
        super().__init__(config_manager, "NetworkCollector")

    def collect(self):
        events = []
        for conn in psutil.net_connections(kind='inet'):
            try:
                event = EventData(
                    event_type='Network',
                    event_action='Connection',
                    event_timestamp=datetime.utcnow(),
                    source_ip=conn.laddr.ip if conn.laddr else None,
                    source_port=conn.laddr.port if conn.laddr else None,
                    destination_ip=conn.raddr.ip if conn.raddr else None,
                    destination_port=conn.raddr.port if conn.raddr else None,
                    protocol=str(conn.type),
                    direction='Outbound' if conn.status == 'ESTABLISHED' else 'Inbound'
                )
                events.append(event)
            except Exception:
                continue
        return events

    def _collect_data(self):
        """Thu thập dữ liệu network thực tế từ Windows"""
        return self.collect()
