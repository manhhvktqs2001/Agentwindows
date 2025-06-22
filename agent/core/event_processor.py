# agent/core/event_processor.py - ENHANCED
"""
Event Processor với Security Alert Notification System - ENHANCED
Tăng cường khả năng xử lý và gửi dữ liệu liên tục
"""

import asyncio
import logging
import time
import threading
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import deque
from dataclasses import dataclass
import uuid
from pathlib import Path

from agent.core.config_manager import ConfigManager
from agent.core.communication import ServerCommunication
from agent.schemas.events import EventData
from agent.utils.security_notifications import SecurityAlertNotifier

@dataclass
class EventStats:
    """Event processing statistics"""
    events_collected: int = 0
    events_sent: int = 0
    events_failed: int = 0
    events_queued: int = 0
    alerts_received: int = 0
    security_notifications_sent: int = 0
    last_batch_sent: Optional[datetime] = None
    batch_count: int = 0
    processing_rate: float = 0.0  # Events per second
    queue_size_history: List[int] = None

class EventProcessor:
    """Event Processor with Security Alert Notifications - ENHANCED for continuous monitoring"""
    
    def __init__(self, config_manager: ConfigManager, communication: ServerCommunication):
        self.config_manager = config_manager
        self.communication = communication
        self.logger = logging.getLogger(__name__)
        
        # Thread lock for logging safety
        self._log_lock = threading.Lock()
        
        # Configuration
        self.config = self.config_manager.get_config()
        self.agent_config = self.config.get('agent', {})
        
        # ENHANCED: Event queue with larger capacity
        self.event_queue: deque = deque()
        self.max_queue_size = self.agent_config.get('event_queue_size', 5000)  # ENHANCED: Increased from 1000
        self.batch_size = self.agent_config.get('event_batch_size', 200)  # ENHANCED: Increased from 100
        
        # ENHANCED: Processing state with continuous monitoring
        self.is_running = False
        self.agent_id: Optional[str] = None
        
        # ENHANCED: Statistics with enhanced tracking
        self.stats = EventStats()
        self.stats.queue_size_history = []
        
        # ENHANCED: Batch processing with higher frequency
        self.batch_interval = 2  # ENHANCED: Reduced from 5 to 2 seconds for continuous monitoring
        self.last_batch_time = time.time()
        
        # ENHANCED: Event filtering with enhanced rules
        self.filters = self.config.get('filters', {})
        
        # ENHANCED: Security Alert Notification System
        self.security_notifier = SecurityAlertNotifier(config_manager)
        self.security_notifier.set_communication(communication)
        
        # ENHANCED: Performance monitoring
        self.processing_start_time = time.time()
        self.last_processing_stats = time.time()
        
        # ENHANCED: Queue monitoring
        self.queue_monitoring_enabled = True
        self.queue_alert_threshold = 0.8  # Alert when queue is 80% full
        
        self._safe_log("info", "Enhanced Event Processor with Security Notifications initialized")
        
        # Performance tracking
        self._last_stats_time = time.time()
        self._last_batch_time = time.time()
        self._batch_count = 0
    
    def _safe_log(self, level: str, message: str):
        """Thread-safe logging to prevent reentrant calls"""
        try:
            with self._log_lock:
                getattr(self.logger, level)(message)
        except:
            # If logging fails, fail silently to prevent cascading errors
            pass
    
    async def start(self):
        """Start event processor with enhanced monitoring"""
        try:
            self.is_running = True
            self.processing_start_time = time.time()
            self._safe_log("info", "Enhanced event processor started with security notifications")
            
            # Start batch processing task with higher frequency
            asyncio.create_task(self._batch_processing_loop())
            
            # Start statistics logging task with enhanced monitoring
            asyncio.create_task(self._stats_logging_loop())
            
            # Start queue monitoring task
            asyncio.create_task(self._queue_monitoring_loop())
            
        except Exception as e:
            self._safe_log("error", f"Event processor start error: {e}")
            raise
    
    async def stop(self):
        """Stop event processor gracefully"""
        try:
            self._safe_log("info", "Stopping enhanced event processor...")
            self.is_running = False
            
            # Wait for current processing to finish
            max_wait = 10  # seconds
            wait_count = 0
            while self._processing and wait_count < max_wait:
                await asyncio.sleep(0.1)
                wait_count += 0.1
            
            # Stop background tasks
            if self._batch_task and not self._batch_task.done():
                self._batch_task.cancel()
            
            if self._alert_task and not self._alert_task.done():
                self._alert_task.cancel()
            
            self._safe_log("info", "Enhanced event processor stopped")
            
        except Exception as e:
            self._safe_log("error", f"Event processor stop error: {e}")
    
    def set_agent_id(self, agent_id: str):
        """Set agent ID for communication"""
        self.agent_id = agent_id
        self._safe_log("info", f"Agent ID set: {agent_id}")
    
    async def add_event(self, event_data: EventData):
        """Add event to processing queue"""
        try:
            # Check queue size limit
            if len(self.event_queue) >= self.max_queue_size:
                # Remove oldest events to make room
                events_to_remove = len(self.event_queue) - self.max_queue_size + 1
                for _ in range(events_to_remove):
                    self.event_queue.popleft()
                
                self._safe_log("warning", f"Event queue full, dropped {events_to_remove} oldest events")
            
            # Add event to queue
            self.event_queue.append(event_data)
            self.stats.events_collected += 1
            
            # Update statistics
            self._update_stats()
            
        except Exception as e:
            self._safe_log("error", f"Failed to add event: {e}")
            self.stats.events_failed += 1
    
    async def _process_batch(self):
        """Process events in batches"""
        while self.is_running:
            try:
                # Wait for events or timeout
                if len(self.event_queue) == 0:
                    await asyncio.sleep(self.batch_interval)
                    continue
                
                # Collect batch of events
                batch_events = []
                batch_start_time = time.time()
                
                while (len(batch_events) < self.batch_size and 
                       len(self.event_queue) > 0 and 
                       time.time() - batch_start_time < self.batch_timeout):
                    
                    event = self.event_queue.popleft()
                    batch_events.append(event)
                
                if not batch_events:
                    continue
                
                # Send batch to server
                self._processing = True
                try:
                    response = await self.communication.submit_event_batch(
                        agent_id=self.agent_id,
                        events=batch_events
                    )
                    
                    if response:
                        self.stats.events_sent += len(batch_events)
                        self.stats.last_batch_sent = datetime.now()
                        self.stats.batch_count += 1
                        
                        self._safe_log("info", f"Batch sent successfully: {len(batch_events)} events")
                        
                        # Process server response for alerts
                        await self._process_server_response(response)
                        
                    else:
                        # Return events to queue on failure
                        for event in batch_events:
                            self.event_queue.appendleft(event)
                        self._safe_log("error", f"Batch send failed: {len(batch_events)} events returned to queue")
                        
                except Exception as e:
                    # Return events to queue on error
                    for event in batch_events:
                        self.event_queue.appendleft(event)
                    self._safe_log("error", f"Batch send error: {e}")
                
                finally:
                    self._processing = False
                
                # Update batch statistics
                self.stats.events_queued = len(self.event_queue)
                
            except Exception as e:
                self._safe_log("error", f"Batch processing error: {e}")
                await asyncio.sleep(self.batch_interval)
    
    async def _process_server_response(self, server_response: Dict[str, Any]):
        """Process server response for alerts and notifications"""
        try:
            # Check for alerts in response
            alerts = []
            if 'alerts_generated' in server_response:
                alerts = server_response['alerts_generated']
            elif 'alerts' in server_response:
                alerts = server_response['alerts']
            
            if alerts:
                self.stats.alerts_received += len(alerts)
                self._safe_log("warning", f"Received {len(alerts)} alerts from server")
                
                # Process alerts through security notifier
                if self.security_notifier:
                    # Get related events for context
                    related_events = []
                    if 'related_events' in server_response:
                        related_events = server_response['related_events']
                    
                    # Process alerts
                    self.security_notifier.process_server_alerts(server_response, related_events)
                    
                    # Log threat detection
                    if server_response.get('threat_detected', False):
                        self._safe_log("warning", f"Threat detected by server - Risk Score: {server_response.get('risk_score', 0)}")
            
            # Update statistics
            self.stats.security_notifications_sent += len(alerts)
            
        except Exception as e:
            self._safe_log("error", f"Security alert handling error: {e}")
    
    async def _check_alerts(self):
        """Check for pending alerts from server"""
        while self.is_running:
            try:
                if not self.agent_id or not self.communication:
                    await asyncio.sleep(self.alert_check_interval)
                    continue
                
                # Get pending alerts from server
                response = await self.communication.get_pending_alerts(self.agent_id)
                
                if response and response.get('alerts'):
                    alerts = response['alerts']
                    self._safe_log("warning", f"Received {len(alerts)} pending alerts from server")
                    
                    # Process alerts through security notifier
                    if self.security_notifier:
                        self.security_notifier.process_server_alerts(response)
                    
                    # Update statistics
                    self.stats.alerts_received += len(alerts)
                
                await asyncio.sleep(self.alert_check_interval)
                
            except Exception as e:
                self._safe_log("error", f"Alert check error: {e}")
                await asyncio.sleep(self.alert_check_interval)
    
    def _update_stats(self):
        """Update processing statistics"""
        current_time = time.time()
        
        # Update processing rate
        if current_time - self.last_processing_stats >= 1.0:  # Every second
            time_diff = current_time - self.last_processing_stats
            self.stats.processing_rate = self.stats.events_collected / time_diff if time_diff > 0 else 0
            self.last_processing_stats = current_time
        
        # Update queue size history
        self.stats.queue_size_history.append(len(self.event_queue))
        if len(self.stats.queue_size_history) > 100:
            self.stats.queue_size_history.pop(0)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        try:
            current_time = time.time()
            
            # Calculate queue utilization
            queue_utilization = len(self.event_queue) / self.max_queue_size if self.max_queue_size > 0 else 0
            
            # Calculate uptime
            uptime = current_time - self.processing_start_time if self.processing_start_time else 0
            
            # Calculate batch processing rate
            batch_rate = self.stats.batch_count / (uptime / 60) if uptime > 0 else 0  # batches per minute
            
            stats = {
                'events_collected': self.stats.events_collected,
                'events_sent': self.stats.events_sent,
                'events_failed': self.stats.events_failed,
                'events_queued': self.stats.events_queued,
                'alerts_received': self.stats.alerts_received,
                'security_notifications_sent': self.stats.security_notifications_sent,
                'batch_count': self.stats.batch_count,
                'processing_rate': self.stats.processing_rate,
                'queue_utilization': queue_utilization,
                'uptime_seconds': uptime,
                'last_batch_sent': self.stats.last_batch_sent.isoformat() if self.stats.last_batch_sent else None,
                'queue_size_history': self.stats.queue_size_history[-20:],  # Last 20 readings
                'is_running': self.is_running,
                'agent_id': self.agent_id
            }
            
            # Log performance warnings
            if queue_utilization > self.queue_alert_threshold:
                self._safe_log("warning", f"Event queue utilization high: {queue_utilization:.1%}")
            
            if self.stats.processing_rate < 1.0:  # Less than 1 event per second
                self._safe_log("warning", f"Low processing rate: {self.stats.processing_rate:.2f} events/sec")
            
            return stats
            
        except Exception as e:
            self._safe_log("error", f"Stats calculation error: {e}")
            return {}
    
    async def _batch_processing_loop(self):
        """ENHANCED: Batch processing loop with higher frequency"""
        try:
            while self.is_running:
                try:
                    # Check if we should send a batch
                    current_time = time.time()
                    queue_size = len(self.event_queue)
                    
                    # Send batch if queue is full or time interval reached
                    if (queue_size >= self.batch_size or 
                        (queue_size > 0 and current_time - self.last_batch_time >= self.batch_interval)):
                        await self._process_batch()
                    
                    # ENHANCED: Shorter sleep interval for more responsive processing
                    await asyncio.sleep(0.5)  # Reduced from 1 second to 0.5 seconds
                    
                except Exception as e:
                    self._safe_log("error", f"Batch processing loop error: {e}")
                    await asyncio.sleep(1)
                    
        except Exception as e:
            self._safe_log("error", f"Batch processing loop failed: {e}")
    
    async def _send_remaining_events(self):
        """Send remaining events in queue"""
        try:
            if self.event_queue:
                self._safe_log("info", f"Sending {len(self.event_queue)} remaining events...")
                await self._process_batch()
                
        except Exception as e:
            self._safe_log("error", f"Failed to send remaining events: {e}")
    
    async def _stats_logging_loop(self):
        """ENHANCED: Statistics logging loop with performance monitoring"""
        try:
            while self.is_running:
                try:
                    # Calculate processing rate
                    current_time = time.time()
                    time_diff = current_time - self.last_processing_stats
                    
                    if time_diff > 0:
                        self.stats.processing_rate = self.stats.events_collected / time_diff
                    
                    # Update queue size history
                    self.stats.queue_size_history.append(len(self.event_queue))
                    if len(self.stats.queue_size_history) > 100:
                        self.stats.queue_size_history.pop(0)
                    
                    # Log enhanced statistics every 30 seconds
                    if int(current_time) % 30 == 0:
                        self._safe_log("info", f"📊 Enhanced Stats - "
                                           f"Collected: {self.stats.events_collected}, "
                                           f"Sent: {self.stats.events_sent}, "
                                           f"Failed: {self.stats.events_failed}, "
                                           f"Queue: {len(self.event_queue)}, "
                                           f"Rate: {self.stats.processing_rate:.2f} events/sec, "
                                           f"Alerts: {self.stats.alerts_received}")
                    
                    self.last_processing_stats = current_time
                    await asyncio.sleep(10)  # Update every 10 seconds
                    
                except Exception as e:
                    self._safe_log("error", f"Stats logging error: {e}")
                    await asyncio.sleep(10)
                    
        except Exception as e:
            self._safe_log("error", f"Stats logging loop failed: {e}")
    
    async def _queue_monitoring_loop(self):
        """ENHANCED: Queue monitoring loop for performance alerts"""
        try:
            while self.is_running:
                try:
                    queue_size = len(self.event_queue)
                    queue_utilization = queue_size / self.max_queue_size
                    
                    # Alert if queue is getting full
                    if queue_utilization > self.queue_alert_threshold:
                        self._safe_log("warning", f"⚠️ Event queue utilization high: "
                                               f"{queue_utilization:.1%} ({queue_size}/{self.max_queue_size})")
                    
                    # Alert if queue is empty for too long (potential issue)
                    if queue_size == 0 and self.is_running:
                        # This could indicate collectors are not working
                        pass
                    
                    await asyncio.sleep(15)  # Check every 15 seconds
                    
                except Exception as e:
                    self._safe_log("error", f"Queue monitoring error: {e}")
                    await asyncio.sleep(15)
                    
        except Exception as e:
            self._safe_log("error", f"Queue monitoring loop failed: {e}")
    
    def get_queue_size(self) -> int:
        """Get current queue size"""
        return len(self.event_queue)
    
    def clear_queue(self):
        """Clear event queue"""
        self.event_queue.clear()
        self._safe_log("info", "Event queue cleared")
    
    def get_performance_metrics(self) -> Dict[str, float]:
        """Get performance metrics"""
        return {
            'queue_utilization': len(self.event_queue) / self.max_queue_size if self.max_queue_size > 0 else 0,
            'processing_rate': self.stats.processing_rate,
            'batch_rate': self.stats.batch_count / ((time.time() - self.processing_start_time) / 60) if self.processing_start_time else 0
        }