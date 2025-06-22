# agent/core/event_processor.py - MODIFIED FOR ZERO DELAY
"""
Event Processor với ZERO DELAY - Gửi dữ liệu ngay lập tức
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
    processing_rate: float = 0.0
    queue_size_history: List[int] = None

class EventProcessor:
    """Event Processor with ZERO DELAY - Immediate transmission"""
    
    def __init__(self, config_manager: ConfigManager, communication: ServerCommunication):
        self.config_manager = config_manager
        self.communication = communication
        self.logger = logging.getLogger(__name__)
        
        # Thread lock for logging safety
        self._log_lock = threading.Lock()
        
        # Configuration
        self.config = self.config_manager.get_config()
        self.agent_config = self.config.get('agent', {})
        
        # ZERO DELAY: Immediate processing
        self.immediate_send = True  # NEW: Send events immediately
        self.batch_size = 1  # MODIFIED: Send one event at a time for zero delay
        self.batch_interval = 0.1  # MODIFIED: Minimal interval for immediate processing
        
        # Event queue with minimal size for immediate processing
        self.event_queue: deque = deque()
        self.max_queue_size = 10  # MODIFIED: Very small queue for immediate processing
        
        # Processing state
        self.is_running = False
        self.agent_id: Optional[str] = None
        
        # Statistics
        self.stats = EventStats()
        self.stats.queue_size_history = []
        
        # Processing tracking
        self.processing_start_time = time.time()
        self.last_processing_stats = time.time()
        
        # Security Alert Notification System
        self.security_notifier = SecurityAlertNotifier(config_manager)
        self.security_notifier.set_communication(communication)
        
        # ZERO DELAY: Immediate processing flags
        self._immediate_processing = True
        self._processing_lock = asyncio.Lock()
        
        self._safe_log("info", "🚀 ZERO DELAY Event Processor initialized - Immediate transmission enabled")
    
    def _safe_log(self, level: str, message: str):
        """Thread-safe logging to prevent reentrant calls"""
        try:
            with self._log_lock:
                getattr(self.logger, level)(message)
        except:
            pass
    
    async def start(self):
        """Start event processor with ZERO DELAY processing"""
        try:
            self.is_running = True
            self.processing_start_time = time.time()
            self._safe_log("info", "🚀 ZERO DELAY Event Processor started - Immediate transmission active")
            
            # Start immediate processing task
            asyncio.create_task(self._immediate_processing_loop())
            
            # Start statistics logging task
            asyncio.create_task(self._stats_logging_loop())
            
        except Exception as e:
            self._safe_log("error", f"Event processor start error: {e}")
            raise
    
    async def stop(self):
        """Stop event processor gracefully"""
        try:
            self._safe_log("info", "Stopping ZERO DELAY Event Processor...")
            self.is_running = False
            
            # Process any remaining events immediately
            await self._process_remaining_events()
            
            self._safe_log("info", "ZERO DELAY Event Processor stopped")
            
        except Exception as e:
            self._safe_log("error", f"Event processor stop error: {e}")
    
    def set_agent_id(self, agent_id: str):
        """Set agent ID for communication"""
        self.agent_id = agent_id
        self._safe_log("info", f"Agent ID set: {agent_id}")
    
    async def add_event(self, event_data: EventData):
        """Add event and process IMMEDIATELY - ZERO DELAY"""
        try:
            # ZERO DELAY: Process event immediately instead of queuing
            if self.immediate_send and self.agent_id and self.communication:
                await self._send_event_immediately(event_data)
            else:
                # Fallback to queue if immediate processing not available
                if len(self.event_queue) >= self.max_queue_size:
                    # Remove oldest event to make room
                    self.event_queue.popleft()
                    self._safe_log("warning", "Queue full, dropped oldest event for immediate processing")
                
                self.event_queue.append(event_data)
            
            self.stats.events_collected += 1
            self._update_stats()
            
        except Exception as e:
            self._safe_log("error", f"Failed to add/process event: {e}")
            self.stats.events_failed += 1
    
    async def _send_event_immediately(self, event_data: EventData):
        """Send single event immediately - ZERO DELAY"""
        try:
            async with self._processing_lock:
                # Set agent ID
                event_data.agent_id = self.agent_id
                
                # Send single event immediately
                response = await self.communication.submit_event(event_data)
                
                if response:
                    self.stats.events_sent += 1
                    self.stats.last_batch_sent = datetime.now()
                    self.stats.batch_count += 1
                    
                    self._safe_log("debug", f"🚀 Event sent immediately: {event_data.event_type}")
                    
                    # Process server response for alerts immediately
                    await self._process_server_response(response)
                else:
                    # If immediate send fails, add to queue for retry
                    if len(self.event_queue) < self.max_queue_size:
                        self.event_queue.append(event_data)
                    self.stats.events_failed += 1
                    self._safe_log("warning", "Immediate send failed, event queued for retry")
        
        except Exception as e:
            self._safe_log("error", f"Immediate event send failed: {e}")
            self.stats.events_failed += 1
            
            # Add to queue for retry if immediate send fails
            if len(self.event_queue) < self.max_queue_size:
                self.event_queue.append(event_data)
    
    async def _immediate_processing_loop(self):
        """Process queued events immediately - ZERO DELAY backup processing"""
        try:
            while self.is_running:
                try:
                    # Process any queued events immediately
                    if self.event_queue:
                        async with self._processing_lock:
                            while self.event_queue and self.is_running:
                                event = self.event_queue.popleft()
                                await self._send_event_immediately(event)
                    
                    # Very short sleep to prevent CPU overload
                    await asyncio.sleep(0.01)  # 10ms check interval for immediate processing
                    
                except Exception as e:
                    self._safe_log("error", f"Immediate processing error: {e}")
                    await asyncio.sleep(0.1)
                    
        except Exception as e:
            self._safe_log("error", f"Immediate processing loop failed: {e}")
    
    async def _process_server_response(self, server_response: Dict[str, Any]):
        """Process server response for alerts and notifications - IMMEDIATE"""
        try:
            # Check for alerts in response
            alerts = []
            if 'alerts_generated' in server_response:
                alerts = server_response['alerts_generated']
            elif 'alerts' in server_response:
                alerts = server_response['alerts']
            
            if alerts:
                self.stats.alerts_received += len(alerts)
                self._safe_log("warning", f"🚨 Received {len(alerts)} alerts from server - Processing immediately")
                
                # Process alerts through security notifier IMMEDIATELY
                if self.security_notifier:
                    # Get related events for context
                    related_events = []
                    if 'related_events' in server_response:
                        related_events = server_response['related_events']
                    
                    # Process alerts immediately
                    self.security_notifier.process_server_alerts(server_response, related_events)
                    
                    # Log threat detection immediately
                    if server_response.get('threat_detected', False):
                        self._safe_log("critical", f"🚨 IMMEDIATE THREAT DETECTED - Risk Score: {server_response.get('risk_score', 0)}")
            
            # Update statistics
            self.stats.security_notifications_sent += len(alerts)
            
        except Exception as e:
            self._safe_log("error", f"Server response processing error: {e}")
    
    async def _process_remaining_events(self):
        """Process any remaining events before shutdown"""
        try:
            if self.event_queue:
                self._safe_log("info", f"Processing {len(self.event_queue)} remaining events immediately...")
                
                while self.event_queue:
                    event = self.event_queue.popleft()
                    await self._send_event_immediately(event)
                    
        except Exception as e:
            self._safe_log("error", f"Failed to process remaining events: {e}")
    
    def _update_stats(self):
        """Update processing statistics"""
        current_time = time.time()
        
        # Update processing rate
        if current_time - self.last_processing_stats >= 1.0:
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
            
            # Calculate processing rate
            processing_rate = self.stats.events_sent / uptime if uptime > 0 else 0
            
            stats = {
                'events_collected': self.stats.events_collected,
                'events_sent': self.stats.events_sent,
                'events_failed': self.stats.events_failed,
                'events_queued': len(self.event_queue),
                'alerts_received': self.stats.alerts_received,
                'security_notifications_sent': self.stats.security_notifications_sent,
                'batch_count': self.stats.batch_count,
                'processing_rate': processing_rate,
                'queue_utilization': queue_utilization,
                'uptime_seconds': uptime,
                'last_batch_sent': self.stats.last_batch_sent.isoformat() if self.stats.last_batch_sent else None,
                'queue_size_history': self.stats.queue_size_history[-20:],
                'is_running': self.is_running,
                'agent_id': self.agent_id,
                'immediate_mode': self.immediate_send,  # NEW: Show immediate mode status
                'zero_delay_enabled': True  # NEW: Confirm zero delay mode
            }
            
            return stats
            
        except Exception as e:
            self._safe_log("error", f"Stats calculation error: {e}")
            return {}
    
    async def _stats_logging_loop(self):
        """Statistics logging loop"""
        try:
            while self.is_running:
                try:
                    # Log enhanced statistics every 30 seconds
                    current_time = time.time()
                    if int(current_time) % 30 == 0:
                        self._safe_log("info", f"🚀 ZERO DELAY Stats - "
                                           f"Collected: {self.stats.events_collected}, "
                                           f"Sent: {self.stats.events_sent}, "
                                           f"Failed: {self.stats.events_failed}, "
                                           f"Queue: {len(self.event_queue)}, "
                                           f"Immediate Mode: {self.immediate_send}, "
                                           f"Alerts: {self.stats.alerts_received}")
                    
                    await asyncio.sleep(10)
                    
                except Exception as e:
                    self._safe_log("error", f"Stats logging error: {e}")
                    await asyncio.sleep(10)
                    
        except Exception as e:
            self._safe_log("error", f"Stats logging loop failed: {e}")
    
    def get_queue_size(self) -> int:
        """Get current queue size"""
        return len(self.event_queue)
    
    def clear_queue(self):
        """Clear event queue"""
        self.event_queue.clear()
        self._safe_log("info", "Event queue cleared")
    
    def enable_immediate_mode(self, enabled: bool = True):
        """Enable/disable immediate processing mode"""
        self.immediate_send = enabled
        self._safe_log("info", f"🚀 Immediate mode {'enabled' if enabled else 'disabled'}")
    
    def get_performance_metrics(self) -> Dict[str, float]:
        """Get performance metrics"""
        return {
            'queue_utilization': len(self.event_queue) / self.max_queue_size if self.max_queue_size > 0 else 0,
            'processing_rate': self.stats.processing_rate,
            'immediate_processing': self.immediate_send,
            'zero_delay_mode': True
        }