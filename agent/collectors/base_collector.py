# agent/collectors/base_collector.py
"""
Base Collector - Abstract base class for all data collectors
FIXED: Enhanced performance and error handling
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Dict, Any

from ..core.config_manager import ConfigManager
from ..schemas.events import EventData

class BaseCollector(ABC):
    """Abstract base class for data collectors - FIXED: Performance optimized"""
    
    def __init__(self, config_manager: ConfigManager, collector_name: str):
        self.config_manager = config_manager
        self.collector_name = collector_name
        self.logger = logging.getLogger(f"collector.{collector_name}")
        
        # Configuration
        self.config = self.config_manager.get_config()
        self.collection_config = self.config.get('collection', {})
        
        # Collector state
        self.is_running = False
        self.is_initialized = False
        self.start_time: Optional[datetime] = None
        
        # Collection settings - FIXED: Optimized defaults
        self.polling_interval = self.collection_config.get('polling_interval', 10)  # FIXED: Increase from 5 to 10
        self.max_events_per_interval = self.collection_config.get('max_events_per_interval', 100)  # FIXED: Reduce from 1000 to 100
        self.real_time_monitoring = self.collection_config.get('real_time_monitoring', True)
        
        # Statistics
        self.events_collected = 0
        self.events_sent = 0
        self.collection_errors = 0
        self.last_collection_time: Optional[datetime] = None
        
        # FIXED: Performance optimization flags
        self._collecting = False  # Prevent concurrent collections
        self._last_performance_log = 0
        self._slow_collection_threshold = 0.5  # FIXED: Reduce from 1.0s to 0.5s
        
        # Event processor reference (will be set by parent)
        self.event_processor = None
    
    async def initialize(self):
        """Initialize the collector - FIXED: Enhanced error handling"""
        try:
            self.logger.info(f"🔧 Initializing {self.collector_name}...")
            
            # Validate configuration
            await self._validate_config()
            
            # Perform collector-specific initialization
            await self._collector_specific_init()
            
            self.is_initialized = True
            self.logger.info(f"✅ {self.collector_name} initialized")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} initialization failed: {e}")
            raise Exception(f"Initialization failed: {e}")
    
    async def start(self):
        """Start the collector - FIXED: Enhanced startup"""
        try:
            if not self.is_initialized:
                await self.initialize()
            
            self.is_running = True
            self.start_time = datetime.now()
            
            self.logger.info(f"🚀 Starting collector: {self.collector_name}")
            
            # Start polling loop for polling-based collectors
            # Real-time collectors like FileCollector should override this method
            asyncio.create_task(self._polling_loop())
            
            self.logger.info(f"✅ Collector started: {self.collector_name}")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} start failed: {e}")
            self.is_running = False
            raise Exception(f"Start failed: {e}")
    
    async def stop(self):
        """Stop the collector"""
        try:
            self.logger.info(f"🛑 Stopping {self.collector_name}...")
            self.is_running = False
            
            # Wait for current collection to finish
            max_wait = 5  # seconds
            wait_count = 0
            while self._collecting and wait_count < max_wait:
                await asyncio.sleep(0.1)
                wait_count += 0.1
            
            # Perform collector-specific cleanup
            await self._collector_specific_cleanup()
            
            self.logger.info(f"✅ {self.collector_name} stopped")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} stop error: {e}")
    
    async def _polling_loop(self):
        """Main polling loop for collectors - FIXED: Performance optimized"""
        while self.is_running:
            try:
                # FIXED: Skip collection if previous one is still running
                if self._collecting:
                    await asyncio.sleep(1)
                    continue
                
                collection_start = time.time()
                self._collecting = True
                
                try:
                    # FIXED: Collect data with timeout
                    result = await asyncio.wait_for(
                        self._collect_data(), 
                        timeout=10.0  # 10 second timeout
                    )
                    
                    # Process the result - FIXED: Limit events per collection
                    events_processed = 0
                    max_events = min(self.max_events_per_interval, 50)  # FIXED: Cap at 50 events
                    
                    if isinstance(result, list):
                        # Multiple events returned
                        for event in result[:max_events]:  # FIXED: Limit events
                            await self.add_event(event)
                            events_processed += 1
                    elif isinstance(result, EventData):
                        # Single event returned
                        await self.add_event(result)
                        events_processed += 1
                    # If result is None or empty, continue
                    
                    # Update statistics
                    self.last_collection_time = datetime.now()
                    collection_time = time.time() - collection_start
                    
                    # FIXED: Log performance issues less frequently
                    if collection_time > self._slow_collection_threshold:
                        current_time = time.time()
                        if current_time - self._last_performance_log > 30:  # Log only every 30 seconds
                            self.logger.warning(f"⚠️ Slow collection: {collection_time:.2f}s")
                            self._last_performance_log = current_time
                    
                    # FIXED: Dynamic wait time based on collection performance
                    if collection_time > self.polling_interval:
                        # If collection took longer than interval, skip wait
                        wait_time = 0.1
                    else:
                        wait_time = max(0.1, self.polling_interval - collection_time)
                    
                    await asyncio.sleep(wait_time)
                    
                except asyncio.TimeoutError:
                    self.logger.warning(f"⚠️ Collection timeout: {self.collector_name}")
                    self.collection_errors += 1
                    await asyncio.sleep(self.polling_interval)
                    
                finally:
                    self._collecting = False
                
            except Exception as e:
                self.logger.error(f"❌ Collection error: {e}")
                self.collection_errors += 1
                self._collecting = False
                await asyncio.sleep(self.polling_interval)
    
    @abstractmethod
    async def _collect_data(self):
        """Collect data - must be implemented by subclasses"""
        pass
    
    async def _collector_specific_init(self):
        """Collector-specific initialization - override in subclasses if needed"""
        pass
    
    async def _collector_specific_cleanup(self):
        """Collector-specific cleanup - override in subclasses if needed"""
        pass
    
    async def _validate_config(self):
        """Validate collector configuration - FIXED: Enhanced validation"""
        if self.polling_interval < 1:
            self.logger.warning("⚠️ Polling interval too low, setting to 1 second")
            self.polling_interval = 1
        
        if self.max_events_per_interval < 1:
            self.logger.warning("⚠️ Max events per interval too low, setting to 10")
            self.max_events_per_interval = 10
        elif self.max_events_per_interval > 1000:
            self.logger.warning("⚠️ Max events per interval too high, setting to 1000")
            self.max_events_per_interval = 1000
    
    async def add_event(self, event_data: EventData):
        """Add event to the processing queue - FIXED: Enhanced error handling"""
        try:
            if self.event_processor:
                await self.event_processor.add_event(event_data)
                self.events_collected += 1
                self.logger.debug(f"📤 Event added: {event_data.event_type}")
            else:
                self.logger.warning("⚠️ No event processor available")
                
        except Exception as e:
            self.logger.error(f"❌ Failed to add event: {e}")
            self.collection_errors += 1
    
    def set_event_processor(self, event_processor):
        """Set the event processor reference"""
        self.event_processor = event_processor
        self.logger.debug("🔗 Event processor linked")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics - FIXED: Enhanced stats"""
        uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        
        return {
            'collector_name': self.collector_name,
            'is_running': self.is_running,
            'is_initialized': self.is_initialized,
            'uptime_seconds': uptime,
            'events_collected': self.events_collected,
            'collection_errors': self.collection_errors,
            'last_collection_time': self.last_collection_time.isoformat() if self.last_collection_time else None,
            'polling_interval': self.polling_interval,
            'real_time_monitoring': self.real_time_monitoring,
            'events_per_minute': (self.events_collected / max(uptime / 60, 1)) if uptime > 0 else 0,
            'is_collecting': self._collecting,  # FIXED: Add current collection status
            'slow_collection_threshold': self._slow_collection_threshold,
            'max_events_per_interval': self.max_events_per_interval
        }
    
    def get_config(self) -> Dict[str, Any]:
        """Get collector configuration"""
        return {
            'polling_interval': self.polling_interval,
            'max_events_per_interval': self.max_events_per_interval,
            'real_time_monitoring': self.real_time_monitoring,
            'collection_enabled': self.collection_config.get('enabled', True),
            'slow_collection_threshold': self._slow_collection_threshold
        }
    
    def update_config(self, config_updates: Dict[str, Any]):
        """Update collector configuration - FIXED: Enhanced validation"""
        try:
            if 'polling_interval' in config_updates:
                new_interval = max(1, config_updates['polling_interval'])
                self.polling_interval = new_interval
            
            if 'max_events_per_interval' in config_updates:
                new_max = max(1, min(1000, config_updates['max_events_per_interval']))
                self.max_events_per_interval = new_max
            
            if 'real_time_monitoring' in config_updates:
                self.real_time_monitoring = config_updates['real_time_monitoring']
            
            if 'slow_collection_threshold' in config_updates:
                self._slow_collection_threshold = max(0.1, config_updates['slow_collection_threshold'])
            
            self.logger.info(f"🔧 {self.collector_name} configuration updated")
            
        except Exception as e:
            self.logger.error(f"❌ Configuration update failed: {e}")
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check - FIXED: Enhanced health monitoring"""
        try:
            health_status = {
                'healthy': True,
                'collector_name': self.collector_name,
                'is_running': self.is_running,
                'is_initialized': self.is_initialized,
                'issues': []
            }
            
            # Check if collector is running when it should be
            if self.is_initialized and not self.is_running:
                health_status['healthy'] = False
                health_status['issues'].append('Collector is not running')
            
            # Check for excessive errors
            uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            error_rate = self.collection_errors / max(uptime / 60, 1) if uptime > 60 else 0
            
            if error_rate > 1:  # More than 1 error per minute
                health_status['healthy'] = False
                health_status['issues'].append(f'High error rate: {error_rate:.1f} errors/min')
            
            # Check if collection is happening
            if (self.last_collection_time and 
                (datetime.now() - self.last_collection_time).total_seconds() > self.polling_interval * 3):
                health_status['healthy'] = False
                health_status['issues'].append('Collection appears to be stalled')
            
            # FIXED: Check if collector is stuck in collection
            if self._collecting and uptime > 60:  # Been collecting for more than 1 minute
                health_status['healthy'] = False
                health_status['issues'].append('Collector appears to be stuck in collection')
            
            return health_status
            
        except Exception as e:
            self.logger.error(f"❌ Health check failed: {e}")
            return {
                'healthy': False,
                'collector_name': self.collector_name,
                'issues': [f'Health check failed: {str(e)}']
            }
    
    def clear_stats(self):
        """Clear collector statistics"""
        self.events_collected = 0
        self.events_sent = 0
        self.collection_errors = 0
        self.last_collection_time = None
        self._last_performance_log = 0
        self.logger.info(f"📊 {self.collector_name} statistics cleared")