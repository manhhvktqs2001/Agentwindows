# agent/core/event_processor.py - COMPLETE FIXED VERSION WITH ALERT POLLING
"""
Event Processor - FIXED FOR CONTINUOUS DATA SENDING + ALERT POLLING
Đảm bảo gửi dữ liệu liên tục và nhận alerts từ server để hiển thị notifications
"""

import asyncio
import logging
import time
import threading
import requests
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
    """Event Processor - FIXED for continuous data transmission + Alert Polling"""
    
    def __init__(self, config_manager: ConfigManager, communication: ServerCommunication):
        self.config_manager = config_manager
        self.communication = communication
        self.logger = logging.getLogger(__name__)
        
        # Thread lock for logging safety
        self._log_lock = threading.Lock()
        
        # Configuration
        self.config = self.config_manager.get_config()
        self.agent_config = self.config.get('agent', {})
        
        # CONTINUOUS SENDING: Always immediate
        self.immediate_send = True
        self.batch_size = 1
        self.batch_interval = 0.001  # 1ms for immediate response
        
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
        
        # CONTINUOUS SENDING: Enhanced tracking
        self._immediate_processing = True
        self._processing_lock = asyncio.Lock()
        self._send_errors = 0
        self._consecutive_failures = 0
        self._last_successful_send = time.time()
        
        # ADDED: Queue for failed events (retry mechanism)
        self._failed_events_queue = deque(maxlen=1000)
        self._retry_task = None
        
        # REALTIME ALERT POLLING: New functionality
        self.alert_polling_enabled = True
        self.alert_polling_interval = 0.1  # 100ms - REALTIME!
        self.fast_polling_interval = 0.05  # 50ms when alerts expected
        self.last_alert_check = 0
        self.server_base_url = None
        self.alerts_processed = 0
        self.realtime_mode = True
        self.consecutive_empty_checks = 0
        
        # Get server URL from config
        if config_manager:
            server_config = config_manager.get_config().get('server', {})
            host = server_config.get('host', '192.168.20.85')
            port = server_config.get('port', 5000)
            self.server_base_url = f"http://{host}:{port}"
        
        self._safe_log("info", "⚡ Event Processor initialized for REALTIME DATA SENDING + REALTIME ALERT POLLING")
    
    def _safe_log(self, level: str, message: str):
        """Thread-safe logging to prevent reentrant calls"""
        try:
            with self._log_lock:
                getattr(self.logger, level)(message)
        except:
            pass
    
    async def start(self):
        """Start event processor with continuous transmission + alert polling"""
        try:
            self.is_running = True
            self.processing_start_time = time.time()
            self._safe_log("info", "⚡ Event Processor started - REALTIME TRANSMISSION + REALTIME ALERT POLLING ACTIVE")
            
            # Start retry mechanism for failed events
            self._retry_task = asyncio.create_task(self._retry_failed_events_loop())
            
            # Start statistics logging task
            asyncio.create_task(self._stats_logging_loop())
            
            # Start connection health monitoring
            asyncio.create_task(self._connection_health_loop())
            
            # REALTIME ALERT POLLING: Start realtime alert polling task
            if self.alert_polling_enabled and self.server_base_url:
                asyncio.create_task(self._realtime_alert_polling_loop())
                self._safe_log("info", "⚡ REALTIME Alert polling enabled - checking server every 100ms for immediate alerts")
            
        except Exception as e:
            self._safe_log("error", f"Event processor start error: {e}")
            raise
    
    async def stop(self):
        """Stop event processor gracefully"""
        try:
            self._safe_log("info", "🛑 Stopping Event Processor...")
            self.is_running = False
            
            # Cancel retry task
            if self._retry_task:
                self._retry_task.cancel()
            
            # Try to send any remaining failed events
            await self._flush_failed_events()
            
            # Wait a moment for any ongoing operations to complete
            await asyncio.sleep(0.5)
            
            self._safe_log("info", "✅ Event Processor stopped gracefully")
            
        except Exception as e:
            self._safe_log("error", f"❌ Event processor stop error: {e}")
    
    def set_agent_id(self, agent_id: str):
        """Set agent ID for communication"""
        self.agent_id = agent_id
        self._safe_log("info", f"Agent ID set: {agent_id}")
    
    async def add_event(self, event_data: EventData):
        """Add event and send IMMEDIATELY - CONTINUOUS TRANSMISSION"""
        try:
            # CONTINUOUS SENDING: Always try to send immediately
            if self.agent_id and self.communication:
                success = await self._send_event_immediately(event_data)
                
                # If immediate send failed, add to retry queue
                if not success:
                    self._failed_events_queue.append({
                        'event': event_data,
                        'timestamp': time.time(),
                        'retry_count': 0
                    })
                    self._safe_log("warning", f"Event queued for retry: {event_data.event_type}")
            else:
                self._safe_log("error", "Cannot send event - agent_id or communication not available")
            
            self.stats.events_collected += 1
            self._update_stats()
            
        except Exception as e:
            self._safe_log("error", f"Failed to process event: {e}")
            self.stats.events_failed += 1
    
    async def _send_event_immediately(self, event_data: EventData) -> bool:
        """Send single event immediately - CONTINUOUS TRANSMISSION"""
        try:
            async with self._processing_lock:
                # Set agent ID
                event_data.agent_id = self.agent_id
                
                # ENHANCED: Add timestamp if missing
                if not hasattr(event_data, 'event_timestamp') or not event_data.event_timestamp:
                    event_data.event_timestamp = datetime.now()
                
                # Send single event immediately
                start_time = time.time()
                response = await self.communication.submit_event(event_data)
                send_time = (time.time() - start_time) * 1000  # Convert to ms
                
                if response:
                    self.stats.events_sent += 1
                    self.stats.last_batch_sent = datetime.now()
                    self.stats.batch_count += 1
                    self._consecutive_failures = 0
                    self._last_successful_send = time.time()
                    
                    self._safe_log("info", f"📤 EVENT SENT: {event_data.event_type} - {event_data.event_action} ({send_time:.1f}ms)")
                    
                    # Process server response for alerts immediately
                    await self._process_server_response(response)
                    return True
                else:
                    self.stats.events_failed += 1
                    self._send_errors += 1
                    self._consecutive_failures += 1
                    self._safe_log("error", f"❌ Event send failed: {event_data.event_type}")
                    return False
        
        except Exception as e:
            self._safe_log("error", f"❌ Immediate event send failed: {e}")
            self.stats.events_failed += 1
            self._send_errors += 1
            self._consecutive_failures += 1
            return False
    
    async def _retry_failed_events_loop(self):
        """Retry failed events periodically"""
        retry_interval = 5  # Retry every 5 seconds
        max_retries = 3
        
        while self.is_running:
            try:
                if self._failed_events_queue:
                    self._safe_log("info", f"🔄 Retrying {len(self._failed_events_queue)} failed events...")
                    
                    # Process failed events
                    events_to_retry = []
                    while self._failed_events_queue and len(events_to_retry) < 10:  # Max 10 at a time
                        events_to_retry.append(self._failed_events_queue.popleft())
                    
                    for event_info in events_to_retry:
                        event_data = event_info['event']
                        retry_count = event_info['retry_count']
                        
                        if retry_count < max_retries:
                            success = await self._send_event_immediately(event_data)
                            
                            if not success:
                                # Re-queue with incremented retry count
                                event_info['retry_count'] += 1
                                event_info['timestamp'] = time.time()
                                self._failed_events_queue.append(event_info)
                        else:
                            # Max retries reached, log and discard
                            self._safe_log("error", f"❌ Event discarded after {max_retries} retries: {event_data.event_type}")
                
                await asyncio.sleep(retry_interval)
                
            except Exception as e:
                self._safe_log("error", f"❌ Retry loop error: {e}")
                await asyncio.sleep(retry_interval)
    
    async def _flush_failed_events(self):
        """Try to send all remaining failed events"""
        try:
            if self._failed_events_queue:
                self._safe_log("info", f"🔄 Flushing {len(self._failed_events_queue)} remaining events...")
                
                while self._failed_events_queue:
                    event_info = self._failed_events_queue.popleft()
                    event_data = event_info['event']
                    
                    try:
                        await self._send_event_immediately(event_data)
                    except:
                        pass  # Ignore errors during shutdown
        except Exception as e:
            self._safe_log("error", f"❌ Flush failed events error: {e}")
    
    async def _connection_health_loop(self):
        """Monitor connection health and log warnings"""
        check_interval = 30  # Check every 30 seconds
        
        while self.is_running:
            try:
                current_time = time.time()
                
                # Check if we haven't sent successfully for a while
                time_since_last_send = current_time - self._last_successful_send
                
                if time_since_last_send > 60:  # 1 minute without successful send
                    self._safe_log("warning", f"⚠️ No successful sends for {time_since_last_send:.1f} seconds")
                
                # Check consecutive failures
                if self._consecutive_failures > 10:
                    self._safe_log("error", f"🚨 {self._consecutive_failures} consecutive send failures")
                
                # Check failed queue size
                if len(self._failed_events_queue) > 100:
                    self._safe_log("warning", f"⚠️ Large failed events queue: {len(self._failed_events_queue)} events")
                
                await asyncio.sleep(check_interval)
                
            except Exception as e:
                self._safe_log("error", f"❌ Connection health check error: {e}")
                await asyncio.sleep(check_interval)
    
    # REALTIME ALERT POLLING: New realtime functionality
    async def _realtime_alert_polling_loop(self):
        """REALTIME ALERT POLLING: Check for alerts every 100ms for immediate response"""
        while self.is_running:
            try:
                current_time = time.time()
                
                # Dynamic polling interval based on activity
                if self.consecutive_empty_checks > 50:  # 5 seconds without alerts
                    poll_interval = self.alert_polling_interval  # 100ms
                elif self.consecutive_empty_checks > 10:  # 1 second without alerts
                    poll_interval = 0.05  # 50ms
                else:
                    poll_interval = 0.01  # 10ms - SUPER FAST when alerts expected
                
                # Check immediately without waiting for interval
                if current_time - self.last_alert_check >= poll_interval:
                    found_alerts = await self._check_server_alerts_realtime()
                    self.last_alert_check = current_time
                    
                    if found_alerts:
                        self.consecutive_empty_checks = 0  # Reset counter
                        # Speed up polling when alerts are found
                        await asyncio.sleep(0.001)  # 1ms for immediate next check
                    else:
                        self.consecutive_empty_checks += 1
                        await asyncio.sleep(poll_interval)
                else:
                    await asyncio.sleep(0.001)  # 1ms micro-sleep
                
            except Exception as e:
                self._safe_log("error", f"❌ Realtime alert polling error: {e}")
                await asyncio.sleep(0.1)  # Brief pause on error
    
    async def _check_server_alerts_realtime(self) -> bool:
        """REALTIME: Check server for pending alerts with immediate processing"""
        try:
            if not self.server_base_url or not self.agent_id:
                return False
            
            # Optimized endpoints for fastest response
            endpoints_to_try = [
                f"/api/v1/alerts/pending?agent_id={self.agent_id}&limit=50&realtime=true",
                f"/api/v1/alerts/latest?agent_id={self.agent_id}&limit=20&since={int(self.last_alert_check)}",
                f"/api/alerts/pending/{self.agent_id}?realtime=true",
                f"/api/v1/alerts?agent_id={self.agent_id}&status=pending&limit=30"
            ]
            
            for endpoint in endpoints_to_try:
                url = self.server_base_url + endpoint
                
                try:
                    # Ultra-fast request with short timeout
                    response = await self._make_realtime_alert_request(url)
                    
                    if response:
                        alerts = self._extract_alerts_from_response(response)
                        
                        if alerts:
                            self._safe_log("critical", f"⚡ REALTIME: Found {len(alerts)} alerts - Processing IMMEDIATELY")
                            
                            # Process ALL alerts in parallel for maximum speed
                            tasks = []
                            for alert in alerts:
                                task = asyncio.create_task(self._process_server_alert_immediate(alert))
                                tasks.append(task)
                            
                            # Wait for all notifications to be sent
                            if tasks:
                                await asyncio.gather(*tasks, return_exceptions=True)
                            
                            # Immediate acknowledgment
                            asyncio.create_task(self._acknowledge_alerts_received(alerts))
                            
                            return True  # Found alerts
                        
                except Exception as e:
                    self._safe_log("debug", f"Realtime alert check failed for {endpoint}: {e}")
                    continue
            
            return False  # No alerts found
            
        except Exception as e:
            self._safe_log("error", f"❌ Realtime server alert check failed: {e}")
            return False
    
    async def _make_realtime_alert_request(self, url: str):
        """Make ultra-fast HTTP request for realtime alerts"""
        try:
            def make_fast_request():
                try:
                    # Ultra-fast request with minimal timeout
                    response = requests.get(url, timeout=1)  # 1 second timeout
                    if response.status_code == 200:
                        return response.json()
                    elif response.status_code == 404:
                        return None
                    else:
                        return None
                except Exception:
                    return None
            
            # Run in thread with minimal delay
            result = await asyncio.to_thread(make_fast_request)
            return result
            
        except Exception:
            return None
    
    def _extract_alerts_from_response(self, response: Dict) -> List[Dict]:
        """Extract alerts from server response"""
        try:
            alerts = []
            
            # Try different response formats
            if isinstance(response, dict):
                if 'alerts' in response:
                    alerts = response['alerts']
                elif 'data' in response and isinstance(response['data'], list):
                    alerts = response['data']
                elif 'results' in response:
                    alerts = response['results']
                elif response.get('success') and 'alerts_generated' in response:
                    alerts = response['alerts_generated']
            elif isinstance(response, list):
                alerts = response
            
            # Filter out invalid alerts
            valid_alerts = []
            for alert in alerts:
                if isinstance(alert, dict) and alert.get('id'):
                    valid_alerts.append(alert)
            
            return valid_alerts
            
        except Exception as e:
            self._safe_log("error", f"❌ Failed to extract alerts: {e}")
            return []
    
    async def _make_alert_request(self, url: str):
        """Make HTTP request to server for alerts"""
        try:
            def make_request():
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        return response.json()
                    elif response.status_code == 404:
                        return None  # Endpoint not found
                    else:
                        self._safe_log("debug", f"Alert request failed: {response.status_code}")
                        return None
                except Exception as e:
                    self._safe_log("debug", f"Alert request error: {e}")
                    return None
            
            # Run in thread to avoid blocking
            result = await asyncio.to_thread(make_request)
            return result
            
        except Exception as e:
            self._safe_log("error", f"❌ Alert request failed: {e}")
            return None
    
    async def _process_server_alert_immediate(self, alert: Dict[str, Any]):
        """Process server alert and show notification immediately"""
        try:
            self._safe_log("critical", f"🚨 PROCESSING SERVER ALERT: {alert.get('rule_name', 'Unknown')} - {alert.get('severity', 'Unknown')}")
            
            # Update stats
            self.stats.alerts_received += 1
            self.alerts_processed += 1
            
            # Process through security notifier
            if hasattr(self, 'security_notifier') and self.security_notifier:
                # Create server response format
                server_response = {
                    'alerts_generated': [alert]
                }
                
                # Process alert and show notification
                await self.security_notifier.process_server_alerts(server_response)
                
                self._safe_log("info", f"✅ Server alert processed and notification sent: {alert.get('id')}")
                self.stats.security_notifications_sent += 1
            else:
                self._safe_log("error", "❌ Security notifier not available")
                
        except Exception as e:
            self._safe_log("error", f"❌ Server alert processing failed: {e}")
    
    async def _acknowledge_alerts_received(self, alerts: List[Dict]):
        """Acknowledge that alerts were received by agent"""
        try:
            if not self.server_base_url or not alerts:
                return
            
            alert_ids = [alert.get('id') for alert in alerts if alert.get('id')]
            
            if alert_ids:
                # Try different acknowledgment endpoints
                endpoints_to_try = [
                    "/api/v1/alerts/acknowledge-delivery",
                    "/api/v1/alerts/delivered",
                    "/api/alerts/acknowledge"
                ]
                
                data = {
                    'agent_id': self.agent_id,
                    'alert_ids': alert_ids,
                    'delivered_at': datetime.now().isoformat(),
                    'delivery_method': 'polling'
                }
                
                for endpoint in endpoints_to_try:
                    url = self.server_base_url + endpoint
                    
                    def make_ack_request():
                        try:
                            response = requests.post(url, json=data, timeout=3)
                            return response.status_code == 200
                        except:
                            return False
                    
                    success = await asyncio.to_thread(make_ack_request)
                    
                    if success:
                        self._safe_log("info", f"✅ Acknowledged delivery of {len(alert_ids)} alerts via {endpoint}")
                        return
                
                self._safe_log("debug", f"⚠️ Failed to acknowledge alert delivery on all endpoints")
                    
        except Exception as e:
            self._safe_log("error", f"❌ Alert acknowledgment failed: {e}")
    
    async def _process_server_response(self, server_response: Dict[str, Any]):
        """Process server response for alerts and notifications - IMMEDIATE"""
        try:
            if not server_response:
                return
            
            # DEBUG: Log server response occasionally
            if int(time.time()) % 10 == 0:  # Every 10 seconds
                self._safe_log("debug", f"🔍 DEBUG: Server response keys: {list(server_response.keys())}")
            
            # Check for alerts in response
            alerts = server_response.get('alerts', [])
            if alerts:
                self.stats.alerts_received += len(alerts)
                self._safe_log("info", f"🚨 Received {len(alerts)} alerts from server response")
                
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
                    
            # Check for alerts_generated
            if server_response and 'alerts_generated' in server_response and server_response['alerts_generated']:
                self._safe_log("info", f"🚨 Found alerts_generated: {len(server_response['alerts_generated'])} alerts")
                self.stats.alerts_received += len(server_response['alerts_generated'])
                
                # Asynchronously process alerts and show notifications
                await self.security_notifier.process_server_alerts(server_response)
                
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
        """Get event processor statistics including alert polling"""
        try:
            current_time = time.time()
            uptime = current_time - self.processing_start_time if self.processing_start_time else 0
            
            # Calculate processing rate
            processing_rate = 0
            if uptime > 0:
                processing_rate = self.stats.events_sent / uptime
            
            # Calculate success rate
            total_attempts = self.stats.events_sent + self.stats.events_failed
            success_rate = (self.stats.events_sent / total_attempts * 100) if total_attempts > 0 else 0
            
            return {
                'events_collected': self.stats.events_collected,
                'events_sent': self.stats.events_sent,
                'events_failed': self.stats.events_failed,
                'events_queued': len(self._failed_events_queue),
                'alerts_received': self.stats.alerts_received,
                'alerts_processed': self.alerts_processed,
                'security_notifications_sent': self.stats.security_notifications_sent,
                'last_batch_sent': self.stats.last_batch_sent.isoformat() if self.stats.last_batch_sent else None,
                'batch_count': self.stats.batch_count,
                'processing_rate': processing_rate,
                'success_rate': success_rate,
                'uptime': uptime,
                'send_errors': self._send_errors,
                'consecutive_failures': self._consecutive_failures,
                'time_since_last_send': current_time - self._last_successful_send,
                'failed_queue_size': len(self._failed_events_queue),
                'alert_polling_enabled': self.alert_polling_enabled,
                'realtime_mode': self.realtime_mode,
                'alert_polling_interval_ms': self.alert_polling_interval * 1000,
                'consecutive_empty_checks': self.consecutive_empty_checks,
                'last_alert_check': self.last_alert_check,
                'server_base_url': self.server_base_url
            }
            
        except Exception as e:
            self._safe_log("error", f"Stats calculation failed: {e}")
            return {}
    
    async def _stats_logging_loop(self):
        """Statistics logging loop with enhanced details"""
        try:
            while self.is_running:
                try:
                    # Log enhanced statistics every 30 seconds
                    current_time = time.time()
                    if int(current_time) % 30 == 0:
                        stats = self.get_stats()
                        
                        self._safe_log("info", 
                            f"📊 REALTIME SENDING + ALERT POLLING Stats - "
                            f"Sent: {stats['events_sent']}, "
                            f"Failed: {stats['events_failed']}, "
                            f"Queue: {stats['events_queued']}, "
                            f"Rate: {stats['processing_rate']:.2f}/s, "
                            f"Success: {stats['success_rate']:.1f}%, "
                            f"Alerts: {stats['alerts_received']}, "
                            f"Notifications: {stats['security_notifications_sent']}, "
                            f"Empty checks: {self.consecutive_empty_checks}")
                    
                    await asyncio.sleep(10)
                    
                except Exception as e:
                    self._safe_log("error", f"Stats logging error: {e}")
                    await asyncio.sleep(10)
                    
        except Exception as e:
            self._safe_log("error", f"Stats logging loop failed: {e}")
    
    # Compatibility methods
    async def submit_event(self, event_data: EventData):
        """Submit event - alias for add_event for compatibility"""
        await self.add_event(event_data)
    
    def get_queue_size(self) -> int:
        """Get current queue size"""
        return len(self._failed_events_queue)
    
    def clear_queue(self):
        """Clear event queue"""
        self._failed_events_queue.clear()
    
    def enable_immediate_mode(self, enabled: bool = True):
        """Enable immediate mode - Always enabled"""
        self.immediate_send = True
    
    def get_performance_metrics(self) -> Dict[str, float]:
        """Get performance metrics"""
        total_attempts = self.stats.events_sent + self.stats.events_failed
        success_rate = (self.stats.events_sent / total_attempts) if total_attempts > 0 else 0
        
        return {
            'queue_utilization': len(self._failed_events_queue) / 1000,  # Normalized to max queue size
            'processing_rate': self.stats.processing_rate,
            'immediate_processing': self.immediate_send,
            'continuous_sending_mode': True,
            'alert_polling_enabled': self.alert_polling_enabled,
            'success_rate': success_rate,
            'error_rate': self._send_errors / max(total_attempts, 1),
            'alerts_received': self.stats.alerts_received,
            'notifications_sent': self.stats.security_notifications_sent
        }
    
    async def _process_alert_immediately(self, alert: Dict):
        """Process alert immediately"""
        try:
            # Process alert through security notifier
            if self.security_notifier:
                await self.security_notifier.process_alert(alert)
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