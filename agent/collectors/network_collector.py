import psutil
from ..schemas.events import EventData
from datetime import datetime

class NetworkCollector:
    """Thu thập sự kiện mạng cho agent Windows"""
    def __init__(self):
        pass

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
