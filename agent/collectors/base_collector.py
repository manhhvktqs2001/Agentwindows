# agent/collectors/base_collector.py - MODIFIED FOR ZERO DELAY
"""
Base Collector - ZERO DELAY Support
Immediate event processing and transmission
"""

from abc import ABC, abstractmethod
import asyncio
import logging
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json
import hashlib
import os
import platform
import psutil
from pathlib import Path

from agent.core.config_manager import ConfigManager
from agent.schemas.events import EventData

class BaseCollector(ABC):
    """Abstract base class for data collectors - ZERO DELAY Support"""
    
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
        
        # ZERO DELAY: Immediate processing settings
        self.immediate_processing = True  # NEW: Enable immediate processing
        self.polling_interval = 0.1  # MODIFIED: Minimal polling for immediate detection
        self.max_events_per_interval = 1  # MODIFIED: Process one event immediately
        self.real_time_monitoring = True
        
        # Statistics
        self.events_collected = 0
        self.events_sent = 0
        self.collection_errors = 0
        self.last_collection_time: Optional[datetime] = None
        
        # Event processor reference (will be set by parent)
        self.event_processor = None
        
        # ZERO DELAY: Performance optimization flags
        self._collecting = False
        self._last_performance_log = 0
        self._immediate_send_threshold = 0.001  # Send within 1ms
    
    async def initialize(self):
        """Initialize the collector with ZERO DELAY support"""
        try:
            self.logger.info(f"🚀 Initializing {self.collector_name} with ZERO DELAY...")
            
            # Validate configuration
            await self._validate_config()
            
            # Perform collector-specific initialization
            await self._collector_specific_init()
            
            self.is_initialized = True
            self.logger.info(f"✅ {self.collector_name} initialized with ZERO DELAY support")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} initialization failed: {e}")
            raise Exception(f"Initialization failed: {e}")
    
    async def start(self):
        """Start the collector with ZERO DELAY processing"""
        try:
            if not self.is_initialized:
                await self.initialize()
            
            self.is_running = True
            self.start_time = datetime.now()
            
            self.logger.info(f"🚀 Starting collector with ZERO DELAY: {self.collector_name}")
            
            # Start minimal polling loop for detection
            asyncio.create_task(self._minimal_polling_loop())
            
            self.logger.info(f"✅ ZERO DELAY Collector started: {self.collector_name}")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} start failed: {e}")
            self.is_running = False
            raise Exception(f"Start failed: {e}")
    
    async def stop(self):
        """Stop the collector gracefully"""
        try:
            self.logger.info(f"🛑 Stopping {self.collector_name} gracefully...")
            self.is_running = False
            
            # Wait for current collection to finish (max 5 seconds)
            max_wait = 5
            wait_count = 0
            while self._collecting and wait_count < max_wait:
                await asyncio.sleep(0.1)  # 100ms check interval
                wait_count += 0.1
            
            # Perform collector-specific cleanup
            await self._collector_specific_cleanup()
            
            self.logger.info(f"✅ {self.collector_name} stopped gracefully")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} stop error: {e}")
            # Continue with shutdown even if there are errors
    
    async def stop_monitoring(self):
        """Stop monitoring - alias for stop method"""
        await self.stop()
    
    async def start_monitoring(self):
        """Start monitoring - alias for start method"""
        await self.start()
    
    async def _minimal_polling_loop(self):
        """Minimal polling loop for ZERO DELAY detection"""
        while self.is_running:
            try:
                # Skip collection if previous one is still running
                if self._collecting:
                    await asyncio.sleep(0.001)
                    continue
                
                collection_start = time.time()
                self._collecting = True
                
                try:
                    # Collect data with immediate processing
                    result = await asyncio.wait_for(
                        self._collect_data(), 
                        timeout=1.0  # 1 second timeout for immediate response
                    )
                    
                    # Process the result immediately
                    if isinstance(result, list):
                        for event in result:
                            await self._add_immediate_event(event)
                    elif isinstance(result, EventData):
                        await self._add_immediate_event(result)
                    
                    # Update statistics
                    self.last_collection_time = datetime.now()
                    collection_time = time.time() - collection_start
                    
                    # Log performance issues less frequently
                    if collection_time > self._immediate_send_threshold:
                        current_time = time.time()
                        if current_time - self._last_performance_log > 10:  # Log every 10 seconds
                            self.logger.debug(f"⚡ Collection time: {collection_time*1000:.1f}ms")
                            self._last_performance_log = current_time
                    
                    # Immediate next collection check
                    await asyncio.sleep(0.001)  # 1ms for immediate detection
                    
                except asyncio.TimeoutError:
                    self.logger.warning(f"⚠️ Collection timeout: {self.collector_name}")
                    self.collection_errors += 1
                    await asyncio.sleep(0.01)
                    
                finally:
                    self._collecting = False
                
            except Exception as e:
                self.logger.error(f"❌ Minimal polling error: {e}")
                self.collection_errors += 1
                self._collecting = False
                await asyncio.sleep(0.01)
    
    async def _add_immediate_event(self, event_data: EventData):
        """Add event and send IMMEDIATELY - ZERO DELAY"""
        try:
            # ZERO DELAY: Send immediately to event processor
            if self.event_processor:
                await self.event_processor.add_event(event_data)
                self.events_sent += 1
                self.logger.debug(f"🚀 Event sent immediately: {event_data.event_type}")
            else:
                self.logger.warning("Event processor not available for immediate sending")
                
        except Exception as e:
            self.logger.error(f"Immediate event sending failed: {e}")
            self.collection_errors += 1
    
    async def _send_event_immediately(self, event_data: EventData):
        """Send event immediately through event processor"""
        try:
            if self.event_processor:
                await self.event_processor.add_event(event_data)
                self.events_collected += 1
                self.logger.debug(f"⚡ Event sent immediately: {event_data.event_type}")
            else:
                self.logger.warning("⚠️ No event processor available for immediate send")
                
        except Exception as e:
            self.logger.error(f"❌ Immediate event send failed: {e}")
            self.collection_errors += 1
    
    async def _process_remaining_immediate_events(self):
        """Process any remaining immediate events before shutdown"""
        try:
            while not self._immediate_events.empty():
                try:
                    event = self._immediate_events.get_nowait()
                    await self._send_event_immediately(event)
                except asyncio.QueueEmpty:
                    break
                    
        except Exception as e:
            self.logger.error(f"❌ Failed to process remaining immediate events: {e}")
    
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
        """Validate collector configuration for ZERO DELAY"""
        if self.polling_interval < 0.001:
            self.logger.warning("⚠️ Polling interval too low, setting to 1ms for immediate processing")
            self.polling_interval = 0.001
        
        if self.max_events_per_interval < 1:
            self.logger.warning("⚠️ Max events per interval too low, setting to 1 for immediate processing")
            self.max_events_per_interval = 1
    
    async def add_event(self, event_data: EventData):
        """Add event to the processing queue - ZERO DELAY version"""
        try:
            if self.immediate_processing:
                await self._add_immediate_event(event_data)
            else:
                # Fallback to event processor
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
        self.logger.debug("🔗 Event processor linked for ZERO DELAY")
    
    def enable_immediate_processing(self, enabled: bool = True):
        """Enable/disable immediate processing mode"""
        self.immediate_processing = enabled
        self.logger.info(f"⚡ Immediate processing {'enabled' if enabled else 'disabled'}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics with ZERO DELAY metrics"""
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
            'is_collecting': self._collecting,
            'immediate_processing': self.immediate_processing,
            'zero_delay_enabled': True,
            'immediate_queue_size': self._immediate_events.qsize(),
            'immediate_send_threshold_ms': self._immediate_send_threshold * 1000
        }
    
    def get_config(self) -> Dict[str, Any]:
        """Get collector configuration"""
        return {
            'polling_interval': self.polling_interval,
            'max_events_per_interval': self.max_events_per_interval,
            'real_time_monitoring': self.real_time_monitoring,
            'collection_enabled': self.collection_config.get('enabled', True),
            'immediate_processing': self.immediate_processing,
            'zero_delay_enabled': True
        }
    
    def update_config(self, config_updates: Dict[str, Any]):
        """Update collector configuration for ZERO DELAY"""
        try:
            if 'polling_interval' in config_updates:
                new_interval = max(0.001, config_updates['polling_interval'])  # Minimum 1ms
                self.polling_interval = new_interval
            
            if 'immediate_processing' in config_updates:
                self.immediate_processing = config_updates['immediate_processing']
            
            if 'real_time_monitoring' in config_updates:
                self.real_time_monitoring = config_updates['real_time_monitoring']
            
            self.logger.info(f"🔧 {self.collector_name} ZERO DELAY configuration updated")
            
        except Exception as e:
            self.logger.error(f"❌ Configuration update failed: {e}")
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check with ZERO DELAY metrics"""
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
            
            if error_rate > 0.5:  # More than 0.5 errors per minute for immediate processing
                health_status['healthy'] = False
                health_status['issues'].append(f'High error rate: {error_rate:.1f} errors/min')
            
            # Check if collection is happening
            if (self.last_collection_time and 
                (datetime.now() - self.last_collection_time).total_seconds() > 1):  # 1 second for immediate processing
                health_status['healthy'] = False
                health_status['issues'].append('Collection appears to be stalled')
            
            # Check immediate processing queue
            if self._immediate_events.qsize() > 0 and uptime > 1:
                health_status['issues'].append(f'Immediate queue has {self._immediate_events.qsize()} pending events')
            
            # Add ZERO DELAY specific health info
            health_status['zero_delay_status'] = {
                'immediate_processing': self.immediate_processing,
                'immediate_queue_size': self._immediate_events.qsize(),
                'last_collection_ms_ago': (datetime.now() - self.last_collection_time).total_seconds() * 1000 if self.last_collection_time else None
            }
            
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
        self.logger.info(f"📊 {self.collector_name} ZERO DELAY statistics cleared")