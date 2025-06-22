from .base_collector import BaseCollector
from ..schemas.events import EventData
import psutil
from datetime import datetime
import asyncio
import json
import time

class SystemCollector(BaseCollector):
    """System event collector for Windows agent - FIXED: Performance optimized"""
    def __init__(self, config_manager):
        super().__init__(config_manager, "System")
        
        # FIXED: Cache system metrics to reduce psutil calls
        self._cached_cpu = 0.0
        self._cached_memory = 0.0
        self._cached_disk = 0.0
        self._last_collection = 0
        self._cache_duration = 30  # Cache for 30 seconds
        
        # FIXED: Set longer polling interval to reduce CPU usage
        self.polling_interval = 15  # Increase from 5 to 15 seconds
        
    async def _collector_specific_init(self):
        """Initialize system collector - FIXED: Pre-warm cache"""
        try:
            # Pre-warm the cache during initialization
            await self._update_cache()
            self.logger.info("✅ System collector initialized with cached metrics")
        except Exception as e:
            self.logger.error(f"❌ System collector initialization failed: {e}")
    
    async def _update_cache(self):
        """Update cached system metrics - FIXED: Optimized psutil calls"""
        try:
            current_time = time.time()
            
            if current_time - self._last_collection < self._cache_duration:
                return  # Use existing cache
            
            # FIXED: Use minimal interval for cpu_percent to reduce blocking time
            self._cached_cpu = psutil.cpu_percent(interval=0.1)  # Reduced from 1.0s to 0.1s
            
            # Get memory info (fast operation)
            mem = psutil.virtual_memory()
            self._cached_memory = mem.percent
            
            # Get disk info (relatively fast)
            try:
                disk = psutil.disk_usage('/')
                self._cached_disk = disk.percent
            except:
                # Fallback if root disk not accessible
                self._cached_disk = 0.0
            
            self._last_collection = current_time
            
        except Exception as e:
            self.logger.debug(f"Cache update error: {e}")

    def collect(self):
        """Collect system information - FIXED: Use cached data"""
        events = []
        try:
            # Use cached values to avoid slow psutil calls
            cpu = self._cached_cpu
            mem_percent = self._cached_memory
            disk_percent = self._cached_disk
            
            event = EventData(
                event_type='System',
                event_action='ResourceUsage',
                event_timestamp=datetime.now(),
                severity='Info',
                description=f'System resource usage - CPU: {cpu}%, Memory: {mem_percent}%, Disk: {disk_percent}%',
                source_ip='127.0.0.1',
                destination_ip='',
                source_port=0,
                destination_port=0,
                protocol='',
                cpu_usage=cpu,
                memory_usage=mem_percent,
                disk_usage=disk_percent,
                raw_event_data=json.dumps({
                    'cpu_percent': cpu,
                    'memory_percent': mem_percent,
                    'disk_percent': disk_percent,
                    'timestamp': datetime.now().isoformat(),
                    'cached': True,  # Indicate this is using cached data
                    'cache_age': time.time() - self._last_collection
                })
            )
            events.append(event)
            
        except Exception as e:
            # FIXED: Don't log errors frequently, use debug level
            self.logger.debug(f"System collection error: {e}")
            
        return events

    async def _collect_data(self):
        """Collect system data from Windows (async) - FIXED: Optimized"""
        try:
            # FIXED: Update cache first (async)
            await self._update_cache()
            
            # FIXED: Use asyncio.to_thread with timeout to prevent blocking
            result = await asyncio.wait_for(
                asyncio.to_thread(self.collect),
                timeout=2.0  # 2 second timeout
            )
            return result
            
        except asyncio.TimeoutError:
            self.logger.warning("⚠️ System collection timeout, skipping")
            return []
        except Exception as e:
            self.logger.debug(f"System collection async error: {e}")
            return []
    
    def get_system_stats(self) -> dict:
        """Get system collector statistics"""
        return {
            'cached_cpu': self._cached_cpu,
            'cached_memory': self._cached_memory,
            'cached_disk': self._cached_disk,
            'last_collection': self._last_collection,
            'cache_duration': self._cache_duration,
            'cache_age': time.time() - self._last_collection,
            'polling_interval': self.polling_interval,
            'optimized': True
        }
    
    def get_current_metrics(self) -> dict:
        """Get current cached metrics without collection"""
        return {
            'cpu_usage': self._cached_cpu,
            'memory_usage': self._cached_memory,
            'disk_usage': self._cached_disk,
            'last_updated': self._last_collection
        }