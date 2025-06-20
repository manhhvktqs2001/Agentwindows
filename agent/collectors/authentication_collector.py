from .base_collector import BaseCollector
from ..schemas.events import EventData
from datetime import datetime
import getpass
import platform
import asyncio

class AuthenticationCollector(BaseCollector):
    """Thu thập sự kiện đăng nhập cho agent Windows (khung cơ bản)"""
    def __init__(self, config_manager):
        super().__init__(config_manager, "AuthenticationCollector")

    def collect(self):
        events = []
        # Thu thập thông tin đăng nhập hiện tại (user, type, result)
        try:
            user = getpass.getuser()
            event = EventData(
                event_type='Authentication',
                event_action='Logon',
                event_timestamp=datetime.utcnow(),
                login_user=user,
                login_type='Interactive',
                login_result='Success'
            )
            events.append(event)
        except Exception:
            pass
        return events

    async def _collect_data(self):
        """Thu thập dữ liệu đăng nhập thực tế từ Windows (async)"""
        return await asyncio.to_thread(self.collect)
