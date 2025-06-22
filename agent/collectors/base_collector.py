# agent/collectors/base_collector.py - FIXED FOR CONTINUOUS DATA COLLECTION
"""
Base Collector - Fixed for Continuous Data Collection and Immediate Sending
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
    """Abstract base class for data collectors - FIXED for continuous collection"""
    
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
        
        # CONTINUOUS COLLECTION: Optimized settings
        self.immediate_processing = True
        self.polling_interval = 0.5  # 500ms default for continuous monitoring
        self.max_events_per_interval = 10  # Allow more events per interval
        self.real_time_monitoring = True
        
        # CONTINUOUS COLLECTION: Enhanced tracking
        self.events_collected = 0
        self.events_sent = 0
        self.collection_errors = 0
        self.last_collection_time: Optional[datetime] = None
        self.collection_duration = 0
        self.average_collection_time = 0
        
        # Event processor reference (will be set by parent)
        self.event_processor = None
        
        # CONTINUOUS COLLECTION: Performance tracking
        self._collecting = False
        self._last_performance_log = 0
        self._immediate_send_threshold = 0.001
        self._collection_times = []
        self._max_collection_history = 100
        
        # CONTINUOUS COLLECTION: Error tracking
        self._consecutive_errors = 0
        self._last_error_time = 0
        self._error_backoff = 1
        
        self.logger.info(f"✅ {collector_name} initialized for CONTINUOUS DATA COLLECTION")
    
    async def initialize(self):
        """Initialize the collector"""
        try:
            self.logger.info(f"🚀 Initializing {self.collector_name} for continuous collection...")
            
            # Validate configuration
            await self._validate_config()
            
            # Perform collector-specific initialization
            await self._collector_specific_init()
            
            self.is_initialized = True
            self.logger.info(f"✅ {self.collector_name} initialized for CONTINUOUS MONITORING")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} initialization failed: {e}")
            raise Exception(f"Initialization failed: {e}")
    
    async def start(self):
        """Start the collector for continuous collection"""
        try:
            if not self.is_initialized:
                await self.initialize()
            
            self.is_running = True
            self.start_time = datetime.now()
            
            self.logger.info(f"🚀 Starting collector: {self.collector_name}")
            
            # Start continuous collection loop
            asyncio.create_task(self._continuous_collection_loop())
            
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
            
            # Log final statistics
            if self.events_collected > 0:
                uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
                rate = self.events_collected / uptime if uptime > 0 else 0
                self.logger.info(f"📊 {self.collector_name} Final Stats: {self.events_collected} events, {rate:.2f}/sec")
            
            self.logger.info(f"✅ {self.collector_name} stopped")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} stop error: {e}")
    
    async def _continuous_collection_loop(self):
        """Continuous collection loop for immediate data sending"""
        self.logger.info(f"🔄 Starting continuous collection loop: {self.collector_name}")
        
        while self.is_running:
            try:
                if self._collecting:
                    await asyncio.sleep(0.001)
                    continue
                
                # Check if we should back off due to errors
                if self._consecutive_errors > 0:
                    if time.time() - self._last_error_time < self._error_backoff:
                        await asyncio.sleep(0.1)
                        continue
                
                collection_start = time.time()
                self._collecting = True
                
                try:
                    # Collect data with timeout
                    result = await asyncio.wait_for(
                        self._collect_data(), 
                        timeout=2.0  # 2 second timeout
                    )
                    
                    # Process the result immediately
                    events_processed = 0
                    if isinstance(result, list):
                        for event in result:
                            if isinstance(event, EventData):
                                await self._send_event_immediately(event)
                                events_processed += 1
                    elif isinstance(result, EventData):
                        await self._send_event_immediately(result)
                        events_processed += 1
                    
                    # Update statistics
                    self.last_collection_time = datetime.now()
                    collection_time = time.time() - collection_start
                    self.collection_duration = collection_time
                    
                    # Track collection times for performance analysis
                    self._collection_times.append(collection_time)
                    if len(self._collection_times) > self._max_collection_history:
                        self._collection_times.pop(0)
                    
                    self.average_collection_time = sum(self._collection_times) / len(self._collection_times)
                    
                    # Reset error tracking on success
                    if events_processed > 0:
                        self._consecutive_errors = 0
                        self._error_backoff = 1
                    
                    # Log performance if collection is slow
                    if collection_time > 0.1:  # 100ms threshold
                        current_time = time.time()
                        if current_time - self._last_performance_log > 30:  # Log every 30 seconds
                            self.logger.warning(f"⚠️ Slow collection: {collection_time*1000:.1f}ms in {self.collector_name}")
                            self._last_performance_log = current_time
                    
                    # Dynamic polling interval based on activity
                    if events_processed > 0:
                        # Fast polling when there's activity
                        await asyncio.sleep(0.1)
                    else:
                        # Normal polling when quiet
                        await asyncio.sleep(self.polling_interval)
                    
                except asyncio.TimeoutError:
                    self.logger.warning(f"⚠️ Collection timeout: {self.collector_name}")
                    self.collection_errors += 1
                    self._consecutive_errors += 1
                    self._last_error_time = time.time()
                    self._error_backoff = min(self._error_backoff * 2, 10)  # Max 10 second backoff
                    await asyncio.sleep(0.1)
                    
                finally:
                    self._collecting = False
                
            except Exception as e:
                self.logger.error(f"❌ Collection loop error in {self.collector_name}: {e}")
                self.collection_errors += 1
                self._consecutive_errors += 1
                self._last_error_time = time.time()
                self._error_backoff = min(self._error_backoff * 2, 10)
                self._collecting = False
                await asyncio.sleep(1)
    
    async def _send_event_immediately(self, event_data: EventData):
        """Send event immediately to event processor"""
        try:
            if self.event_processor:
                await self.event_processor.add_event(event_data)
                self.events_sent += 1
                self.events_collected += 1
                
                # Log significant events
                if event_data.severity in ['High', 'Critical']:
                    self.logger.info(f"🚨 HIGH PRIORITY EVENT: {event_data.event_type} - {event_data.event_action}")
                else:
                    self.logger.debug(f"📤 Event sent: {event_data.event_type} - {event_data.event_action}")
            else:
                self.logger.warning("⚠️ Event processor not available")
                self.collection_errors += 1
                
        except Exception as e:
            self.logger.error(f"❌ Event sending failed: {e}")
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
            await self._send_event_immediately(event_data)
                    
        except Exception as e:
            self.logger.error(f"❌ Failed to add event: {e}")
            self.collection_errors += 1
    
    def set_event_processor(self, event_processor):
        """Set the event processor reference"""
        self.event_processor = event_processor
        self.logger.debug("🔗 Event processor linked for continuous sending")
    
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
            'consecutive_errors': self._consecutive_errors,
            'last_collection_time': self.last_collection_time.isoformat() if self.last_collection_time else None,
            'polling_interval': self.polling_interval,
            'real_time_monitoring': self.real_time_monitoring,
            'events_per_minute': (self.events_collected / max(uptime / 60, 1)) if uptime > 0 else 0,
            'is_collecting': self._collecting,
            'immediate_processing': self.immediate_processing,
            'collection_duration_ms': self.collection_duration * 1000,
            'average_collection_time_ms': self.average_collection_time * 1000,
            'error_backoff_seconds': self._error_backoff,
            'continuous_collection': True
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
            
            if error_rate > 1.0:  # More than 1 error per minute
                health_status['healthy'] = False
                health_status['issues'].append(f'High error rate: {error_rate:.1f} errors/min')
            
            if self._consecutive_errors > 5:
                health_status['healthy'] = False
                health_status['issues'].append(f'Too many consecutive errors: {self._consecutive_errors}')
            
            if (self.last_collection_time and 
                (datetime.now() - self.last_collection_time).total_seconds() > 30):
                health_status['healthy'] = False
                health_status['issues'].append('Collection appears to be stalled')
            
            if self.average_collection_time > 1.0:  # > 1 second average
                health_status['healthy'] = False
                health_status['issues'].append(f'Slow collection performance: {self.average_collection_time:.2f}s avg')
            
            return health_status
            
        except Exception as e:
            self.logger.error(f"❌ Health check failed: {e}")
            return {
                'healthy': False,
                'collector_name': self.collector_name,
                'issues': [f'Health check failed: {str(e)}']
            }
    
    async def force_collection(self):
        """Force an immediate collection cycle"""
        try:
            self.logger.info(f"🔄 Forcing collection cycle: {self.collector_name}")
            
            if not self._collecting:
                result = await self._collect_data()
                
                if isinstance(result, list):
                    for event in result:
                        if isinstance(event, EventData):
                            await self._send_event_immediately(event)
                elif isinstance(result, EventData):
                    await self._send_event_immediately(result)
                
                self.logger.info(f"✅ Forced collection completed: {self.collector_name}")
            else:
                self.logger.warning(f"⚠️ Collection already in progress: {self.collector_name}")
                
        except Exception as e:
            self.logger.error(f"❌ Forced collection failed: {e}")
    
    def get_performance_metrics(self) -> Dict[str, float]:
        """Get detailed performance metrics"""
        try:
            uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            
            return {
                'collection_rate': self.events_collected / max(uptime, 1),
                'error_rate': self.collection_errors / max(uptime, 1),
                'success_rate': (self.events_sent / max(self.events_collected, 1)) * 100,
                'average_collection_time': self.average_collection_time,
                'uptime_hours': uptime / 3600,
                'consecutive_errors': self._consecutive_errors,
                'error_backoff': self._error_backoff,
                'is_healthy': self._consecutive_errors < 5 and self.average_collection_time < 1.0
            }
            
        except Exception as e:
            self.logger.error(f"❌ Performance metrics calculation failed: {e}")
            return {}
    
    # Compatibility methods for existing code
    async def stop_monitoring(self):
        """Stop monitoring - alias for stop method"""
        await self.stop()
    
    async def start_monitoring(self):
        """Start monitoring - alias for start method"""
        await self.start()