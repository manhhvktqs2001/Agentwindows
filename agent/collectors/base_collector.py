# agent/collectors/base_collector.py - FIXED VERSION
"""
Base Collector - Fixed for Zero Delay Support
"""

from abc import ABC, abstractmethod
import asyncio
import logging
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
import json
import hashlib
import os
import platform
import psutil
from pathlib import Path

from agent.core.config_manager import ConfigManager
from agent.schemas.events import EventData

class BaseCollector(ABC):
    """Abstract base class for data collectors - Fixed Version"""
    
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
        self.immediate_processing = True
        self.polling_interval = 0.1
        self.max_events_per_interval = 1
        self.real_time_monitoring = True
        
        # Statistics
        self.events_collected = 0
        self.events_sent = 0
        self.collection_errors = 0
        self.last_collection_time: Optional[datetime] = None
        
        # Event processor reference (will be set by parent)
        self.event_processor = None
        
        # Fixed: Remove queue initialization that was causing issues
        self._collecting = False
        self._last_performance_log = 0
        self._immediate_send_threshold = 0.001
    
    async def initialize(self):
        """Initialize the collector"""
        try:
            self.logger.info(f"🚀 Initializing {self.collector_name}...")
            
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
            
            self.logger.info(f"🚀 Starting collector: {self.collector_name}")
            
            # Start minimal polling loop for detection
            asyncio.create_task(self._minimal_polling_loop())
            
            self.logger.info(f"✅ Collector started: {self.collector_name}")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} start failed: {e}")
            self.is_running = False
            raise Exception(f"Start failed: {e}")
    
    async def stop(self):
        """Stop the collector gracefully"""
        try:
            self.logger.info(f"🛑 Stopping {self.collector_name}...")
            self.is_running = False
            
            # Wait for current collection to finish
            max_wait = 5
            wait_count = 0
            while self._collecting and wait_count < max_wait:
                await asyncio.sleep(0.1)
                wait_count += 0.1
            
            # Perform collector-specific cleanup
            await self._collector_specific_cleanup()
            
            self.logger.info(f"✅ {self.collector_name} stopped")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} stop error: {e}")
    
    async def stop_monitoring(self):
        """Stop monitoring - alias for stop method"""
        await self.stop()
    
    async def start_monitoring(self):
        """Start monitoring - alias for start method"""
        await self.start()
    
    async def _minimal_polling_loop(self):
        """Minimal polling loop for immediate detection"""
        while self.is_running:
            try:
                if self._collecting:
                    await asyncio.sleep(0.001)
                    continue
                
                collection_start = time.time()
                self._collecting = True
                
                try:
                    # Collect data with timeout
                    result = await asyncio.wait_for(
                        self._collect_data(), 
                        timeout=1.0
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
                        if current_time - self._last_performance_log > 10:
                            self.logger.debug(f"⚡ Collection time: {collection_time*1000:.1f}ms")
                            self._last_performance_log = current_time
                    
                    await asyncio.sleep(self.polling_interval)
                    
                except asyncio.TimeoutError:
                    self.logger.warning(f"⚠️ Collection timeout: {self.collector_name}")
                    self.collection_errors += 1
                    await asyncio.sleep(0.01)
                    
                finally:
                    self._collecting = False
                
            except Exception as e:
                self.logger.error(f"❌ Polling error: {e}")
                self.collection_errors += 1
                self._collecting = False
                await asyncio.sleep(0.01)
    
    async def _add_immediate_event(self, event_data: EventData):
        """Add event and send immediately"""
        try:
            if self.event_processor:
                await self.event_processor.add_event(event_data)
                self.events_sent += 1
                self.logger.debug(f"🚀 Event sent: {event_data.event_type}")
            else:
                self.logger.warning("Event processor not available")
                
        except Exception as e:
            self.logger.error(f"Event sending failed: {e}")
            self.collection_errors += 1
    
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
        if self.polling_interval < 0.001:
            self.logger.warning("⚠️ Polling interval too low, setting to 1ms")
            self.polling_interval = 0.001
        
        if self.max_events_per_interval < 1:
            self.logger.warning("⚠️ Max events per interval too low, setting to 1")
            self.max_events_per_interval = 1
    
    async def add_event(self, event_data: EventData):
        """Add event to the processing queue"""
        try:
            if self.immediate_processing:
                await self._add_immediate_event(event_data)
            else:
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
            'events_sent': self.events_sent,
            'collection_errors': self.collection_errors,
            'last_collection_time': self.last_collection_time.isoformat() if self.last_collection_time else None,
            'polling_interval': self.polling_interval,
            'real_time_monitoring': self.real_time_monitoring,
            'events_per_minute': (self.events_collected / max(uptime / 60, 1)) if uptime > 0 else 0,
            'is_collecting': self._collecting,
            'immediate_processing': self.immediate_processing
        }
    
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
            
            if self.is_initialized and not self.is_running:
                health_status['healthy'] = False
                health_status['issues'].append('Collector is not running')
            
            uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            error_rate = self.collection_errors / max(uptime / 60, 1) if uptime > 60 else 0
            
            if error_rate > 0.5:
                health_status['healthy'] = False
                health_status['issues'].append(f'High error rate: {error_rate:.1f} errors/min')
            
            if (self.last_collection_time and 
                (datetime.now() - self.last_collection_time).total_seconds() > 10):
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