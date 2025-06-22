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
            
            # Start statistics logging task
            asyncio.create_task(self._stats_logging_loop())
            
        except Exception as e:
            self._safe_log("error", f"Event processor start error: {e}")
            raise
    
    async def stop(self):
        """Stop event processor gracefully"""
        try:
            self._safe_log("info", "🛑 Stopping ZERO DELAY Event Processor gracefully...")
            self.is_running = False
            
            # Wait a moment for any ongoing operations to complete
            await asyncio.sleep(0.5)
            
            self._safe_log("info", "✅ ZERO DELAY Event Processor stopped gracefully")
            
        except Exception as e:
            self._safe_log("error", f"❌ Event processor stop error: {e}")
            # Continue with shutdown even if there are errors
    
    def set_agent_id(self, agent_id: str):
        """Set agent ID for communication"""
        self.agent_id = agent_id
        self._safe_log("info", f"Agent ID set: {agent_id}")
    
    async def add_event(self, event_data: EventData):
        """Add event and process IMMEDIATELY - ZERO DELAY"""
        try:
            # ZERO DELAY: Always send immediately, never queue
            if self.agent_id and self.communication:
                await self._send_event_immediately(event_data)
            else:
                self._safe_log("error", "Cannot send event - agent_id or communication not available")
            
            self.stats.events_collected += 1
            self._update_stats()
            
        except Exception as e:
            self._safe_log("error", f"Failed to send event immediately: {e}")
            self.stats.events_failed += 1
    
    async def submit_event(self, event_data: EventData):
        """Submit event - alias for add_event for compatibility"""
        await self.add_event(event_data)
    
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
                    self.stats.events_failed += 1
                    self._safe_log("warning", "Immediate send failed")
        
        except Exception as e:
            self._safe_log("error", f"Immediate event send failed: {e}")
            self.stats.events_failed += 1
    
    async def _process_server_response(self, server_response: Dict[str, Any]):
        """Process server response for alerts and notifications - IMMEDIATE"""
        try:
            if not server_response:
                return
            
            # Check for alerts in response
            alerts = server_response.get('alerts', [])
            if alerts:
                self.stats.alerts_received += len(alerts)
                self._safe_log("info", f"🚨 Received {len(alerts)} alerts from server")
                
                # Process alerts immediately
                for alert in alerts:
                    await self._process_alert_immediately(alert)
            
            # Check for notifications
            notifications = server_response.get('notifications', [])
            if notifications:
                self.stats.security_notifications_sent += len(notifications)
                self._safe_log("info", f"📢 Received {len(notifications)} notifications from server")
                
                # Send notifications immediately
                for notification in notifications:
                    await self._send_notification_immediately(notification)
                    
        except Exception as e:
            self._safe_log("error", f"Server response processing failed: {e}")
    
    def _update_stats(self):
        """Update processing statistics"""
        current_time = time.time()
        
        # Update processing rate
        if current_time - self.last_processing_stats >= 1.0:
            time_diff = current_time - self.last_processing_stats
            self.stats.processing_rate = self.stats.events_collected / time_diff if time_diff > 0 else 0
            self.last_processing_stats = current_time
    
    def get_stats(self) -> Dict[str, Any]:
        """Get event processor statistics"""
        try:
            current_time = time.time()
            uptime = current_time - self.processing_start_time if self.processing_start_time else 0
            
            # Calculate processing rate
            processing_rate = 0
            if uptime > 0:
                processing_rate = self.stats.events_sent / uptime
            
            # Calculate queue utilization (always 0 since no queue)
            queue_utilization = 0
            
            return {
                'events_collected': self.stats.events_collected,
                'events_sent': self.stats.events_sent,
                'events_failed': self.stats.events_failed,
                'events_queued': 0,  # Always 0 - no queue
                'alerts_received': self.stats.alerts_received,
                'security_notifications_sent': self.stats.security_notifications_sent,
                'last_batch_sent': self.stats.last_batch_sent.isoformat() if self.stats.last_batch_sent else None,
                'batch_count': self.stats.batch_count,
                'processing_rate': processing_rate,
                'queue_utilization': queue_utilization,
                'uptime': uptime,
                'immediate_requests': getattr(self, 'immediate_requests', 0),
                'failed_immediate_requests': getattr(self, 'failed_immediate_requests', 0)
            }
            
        except Exception as e:
            self._safe_log("error", f"Stats calculation failed: {e}")
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
                                           f"Queue: 0, "
                                           f"Immediate Mode: {self.immediate_send}, "
                                           f"Alerts: {self.stats.alerts_received}")
                    
                    await asyncio.sleep(10)
                    
                except Exception as e:
                    self._safe_log("error", f"Stats logging error: {e}")
                    await asyncio.sleep(10)
                    
        except Exception as e:
            self._safe_log("error", f"Stats logging loop failed: {e}")
    
    def get_queue_size(self) -> int:
        """Get current queue size - Always 0 since no queue"""
        return 0
    
    def clear_queue(self):
        """Clear event queue - No operation since no queue"""
        pass
    
    def enable_immediate_mode(self, enabled: bool = True):
        """Enable immediate mode - Always enabled"""
        self.immediate_send = True
    
    def get_performance_metrics(self) -> Dict[str, float]:
        """Get performance metrics"""
        return {
            'queue_utilization': 0,  # Always 0 - no queue
            'processing_rate': self.stats.processing_rate,
            'immediate_processing': self.immediate_send,
            'zero_delay_mode': True
        }
    
    async def _process_alert_immediately(self, alert: Dict):
        """Process alert immediately"""
        try:
            # Process alert through security notifier
            if self.security_notifier:
                self.security_notifier.process_alert(alert)
        except Exception as e:
            self._safe_log("error", f"Alert processing failed: {e}")
    
    async def _send_notification_immediately(self, notification: Dict):
        """Send notification immediately"""
        try:
            # Send notification through security notifier
            if self.security_notifier:
                await self.security_notifier.send_notification(notification)
        except Exception as e:
            self._safe_log("error", f"Notification sending failed: {e}")