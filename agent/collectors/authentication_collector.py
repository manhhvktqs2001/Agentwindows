from .base_collector import BaseCollector
from ..schemas.events import EventData
from datetime import datetime
import getpass
import platform
import asyncio
import json

class AuthenticationCollector(BaseCollector):
    """Authentication event collector for Windows agent"""
    def __init__(self, config_manager):
        super().__init__(config_manager, "Authentication")

    def collect(self):
        events = []
        # Collect current login information
        try:
            user = getpass.getuser()
            event = EventData(
                event_type='Authentication',
                event_action='Logon',
                event_timestamp=datetime.now(),
                severity='Info',
                description=f'User login: {user}',
                source_ip='127.0.0.1',
                destination_ip='',
                source_port=0,
                destination_port=0,
                protocol='',
                login_user=user,
                login_type='Interactive',
                login_result='Success',
                raw_event_data=json.dumps({
                    'user': user,
                    'login_type': 'Interactive',
                    'result': 'Success',
                    'timestamp': datetime.now().isoformat()
                })
            )
            events.append(event)
        except Exception:
            pass
        return events

    async def _collect_data(self):
        """Collect authentication data from Windows (async)"""
        return await asyncio.to_thread(self.collect)
