# agent/collectors/base_collector.py
"""
Base Collector - Abstract base class for all data collectors
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
    """Abstract base class for data collectors"""
    
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
        
        # Collection settings
        self.polling_interval = self.collection_config.get('polling_interval', 5)
        self.max_events_per_interval = self.collection_config.get('max_events_per_interval', 1000)
        self.real_time_monitoring = self.collection_config.get('real_time_monitoring', True)
        
        # Statistics
        self.events_collected = 0
        self.events_sent = 0
        self.collection_errors = 0
        self.last_collection_time: Optional[datetime] = None
        
        # Event processor reference (will be set by parent)
        self.event_processor = None
    
    async def initialize(self):
        """Initialize the collector - override in subclasses"""
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
        """Start the collector"""
        try:
            if not self.is_initialized:
                await self.initialize()
            
            self.is_running = True
            self.start_time = datetime.now()
            
            self.logger.info(f"🚀 Starting {self.collector_name}...")
            
            # Start collection loop
            if self.real_time_monitoring:
                asyncio.create_task(self._collection_loop())
            
            self.logger.info(f"✅ {self.collector_name} started")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} start failed: {e}")
            self.is_running = False
            raise Exception(f"Start failed: {e}")
    
    async def stop(self):
        """Stop the collector"""
        try:
            self.logger.info(f"🛑 Stopping {self.collector_name}...")
            self.is_running = False
            
            # Perform collector-specific cleanup
            await self._collector_specific_cleanup()
            
            self.logger.info(f"✅ {self.collector_name} stopped")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} stop error: {e}")
    
    async def _collection_loop(self):
        """Main collection loop"""
        while self.is_running:
            try:
                collection_start = time.time()
                
                # Collect data
                await self._collect_data()
                
                # Update statistics
                self.last_collection_time = datetime.now()
                collection_time = time.time() - collection_start
                
                # Log performance if collection takes too long
                if collection_time > 1.0:
                    self.logger.warning(f"⚠️ Slow collection: {collection_time:.2f}s")
                
                # Wait for next collection interval
                await asyncio.sleep(max(0, self.polling_interval - collection_time))
                
            except Exception as e:
                self.logger.error(f"❌ Collection error: {e}")
                self.collection_errors += 1
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
        """Validate collector configuration"""
        if self.polling_interval < 1:
            self.logger.warning("⚠️ Polling interval too low, setting to 1 second")
            self.polling_interval = 1
        
        if self.max_events_per_interval < 1:
            self.logger.warning("⚠️ Max events per interval too low, setting to 100")
            self.max_events_per_interval = 100
    
    async def add_event(self, event_data: EventData):
        """Add event to the processing queue"""
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
        """Get collector statistics"""
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
            'events_per_minute': (self.events_collected / max(uptime / 60, 1)) if uptime > 0 else 0
        }
    
    def get_config(self) -> Dict[str, Any]:
        """Get collector configuration"""
        return {
            'polling_interval': self.polling_interval,
            'max_events_per_interval': self.max_events_per_interval,
            'real_time_monitoring': self.real_time_monitoring,
            'collection_enabled': self.collection_config.get('enabled', True)
        }
    
    def update_config(self, config_updates: Dict[str, Any]):
        """Update collector configuration"""
        try:
            if 'polling_interval' in config_updates:
                self.polling_interval = max(1, config_updates['polling_interval'])
            
            if 'max_events_per_interval' in config_updates:
                self.max_events_per_interval = max(1, config_updates['max_events_per_interval'])
            
            if 'real_time_monitoring' in config_updates:
                self.real_time_monitoring = config_updates['real_time_monitoring']
            
            self.logger.info(f"🔧 {self.collector_name} configuration updated")
            
        except Exception as e:
            self.logger.error(f"❌ Configuration update failed: {e}")
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check"""
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
            if uptime > 300 and self.collection_errors > 10:  # More than 10 errors in 5 minutes
                health_status['healthy'] = False
                health_status['issues'].append(f'High error rate: {self.collection_errors} errors')
            
            # Check if collection is happening
            if (self.last_collection_time and 
                (datetime.now() - self.last_collection_time).total_seconds() > self.polling_interval * 2):
                health_status['healthy'] = False
                health_status['issues'].append('Collection appears to be stalled')
            
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
        self.logger.info(f"📊 {self.collector_name} statistics cleared")