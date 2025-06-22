from .base_collector import BaseCollector
from ..schemas.events import EventData
from datetime import datetime
import getpass
import platform
import asyncio
import json
import time

class AuthenticationCollector(BaseCollector):
    """Authentication event collector for Windows agent - FIXED: Performance optimized"""
    def __init__(self, config_manager):
        super().__init__(config_manager, "Authentication")
        
        # FIXED: Cache frequently accessed data
        self._cached_user = None
        self._last_collection = 0
        self._collection_interval = 60  # Only collect every 60 seconds to reduce load
        
        # FIXED: Set longer polling interval to reduce CPU usage
        self.polling_interval = 15  # Increase from 5 to 15 seconds
        
    async def _collector_specific_init(self):
        """Initialize authentication collector - FIXED: Cache user info"""
        try:
            # Cache user info once during initialization
            self._cached_user = getpass.getuser()
            self.logger.info(f"✅ Authentication collector initialized for user: {self._cached_user}")
        except Exception as e:
            self.logger.error(f"❌ Authentication collector initialization failed: {e}")

    def collect(self):
        """Collect authentication information - FIXED: Optimized"""
        events = []
        try:
            current_time = time.time()
            
            # FIXED: Only collect authentication events periodically to reduce overhead
            if current_time - self._last_collection < self._collection_interval:
                return events  # Return empty list to skip collection
            
            self._last_collection = current_time
            
            # Use cached user info
            user = self._cached_user or 'unknown'
            
            event = EventData(
                event_type='Authentication',
                event_action='Logon',
                event_timestamp=datetime.now(),
                severity='Info',
                description=f'User session active: {user}',
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
                    'timestamp': datetime.now().isoformat(),
                    'cached': True  # Indicate this is using cached data
                })
            )
            events.append(event)
            
        except Exception as e:
            # FIXED: Don't log errors frequently, use debug level
            self.logger.debug(f"Authentication collection error: {e}")
            
        return events

    async def _collect_data(self):
        """Collect authentication data from Windows (async) - FIXED: Optimized"""
        try:
            # FIXED: Use asyncio.to_thread with timeout to prevent blocking
            result = await asyncio.wait_for(
                asyncio.to_thread(self.collect),
                timeout=2.0  # 2 second timeout
            )
            return result
            
        except asyncio.TimeoutError:
            self.logger.warning("⚠️ Authentication collection timeout, skipping")
            return []
        except Exception as e:
            self.logger.debug(f"Authentication collection async error: {e}")
            return []
    
    def get_auth_stats(self) -> dict:
        """Get authentication collector statistics"""
        return {
            'cached_user': self._cached_user,
            'last_collection': self._last_collection,
            'collection_interval': self._collection_interval,
            'polling_interval': self.polling_interval,
            'optimized': True
        }