# agent/core/event_processor.py - SIMPLE RULE-BASED VERSION
"""
Event Processor - CHỈ HIỂN THỊ CẢNH BÁO KHI SERVER PHÁT HIỆN VI PHẠM RULE
Gửi events lên server và chỉ hiển thị notification khi server trả về rule violation
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
from agent.utils.security_notifications import SimpleRuleBasedAlertNotifier

@dataclass
class EventStats:
    """Event processing statistics"""
    events_collected: int = 0
    events_sent: int = 0
    events_failed: int = 0
    rule_violations_received: int = 0
    rule_alerts_displayed: int = 0
    last_event_sent: Optional[datetime] = None
    last_rule_violation: Optional[datetime] = None
    processing_rate: float = 0.0

class EventProcessor:
    def __init__(self, config_manager, communication):
        self.simple_processor = SimpleEventProcessor(config_manager, communication)
    
    def set_agent_id(self, agent_id):
        self.simple_processor.set_agent_id(agent_id)
    
    async def start(self):
        await self.simple_processor.start()
    
    async def stop(self):
        await self.simple_processor.stop()
    
    async def add_event(self, event_data):
        await self.simple_processor.add_event(event_data)
    
    def get_stats(self):
        return self.simple_processor.get_stats()
    
    def get_queue_size(self):
        return self.simple_processor.get_queue_size()
    
    def clear_queue(self):
        self.simple_processor.clear_queue()
    
    def enable_immediate_mode(self, enabled: bool = True):
        self.simple_processor.enable_immediate_mode(enabled)
    
    def get_performance_metrics(self):
        return self.simple_processor.get_performance_metrics()

class SimpleEventProcessor:
    """Event Processor - CHỈ HIỂN THỊ CẢNH BÁO KHI SERVER PHÁT HIỆN VI PHẠM RULE"""
    
    def __init__(self, config_manager: ConfigManager, communication: ServerCommunication):
        self.config_manager = config_manager
        self.communication = communication
        self.logger = logging.getLogger(__name__)
        
        # Thread lock for logging safety
        self._log_lock = threading.Lock()
        
        # Configuration
        self.config = self.config_manager.get_config()
        self.agent_config = self.config.get('agent', {})
        
        # Event processing settings
        self.immediate_send = True
        self.batch_size = 1
        self.batch_interval = 0.001
        
        # Processing state
        self.is_running = False
        self.agent_id: Optional[str] = None
        
        # Statistics
        self.stats = EventStats()
        
        # Processing tracking
        self.processing_start_time = time.time()
        
        # Simple Rule-Based Alert Notification System
        self.security_notifier = SimpleRuleBasedAlertNotifier(config_manager)
        self.security_notifier.set_communication(communication)
        
        # Event queue for failed sends
        self._failed_events_queue = deque(maxlen=1000)
        self._retry_task = None
        
        # Processing lock
        self._processing_lock = asyncio.Lock()
        self._send_errors = 0
        self._consecutive_failures = 0
        self._last_successful_send = time.time()
        
        # Retry logging control
        self._last_retry_log = 0
        
        self._safe_log("info", "🚀 Simple Event Processor initialized - RULE-BASED ALERTS ONLY")
    
    def _safe_log(self, level: str, message: str):
        """Thread-safe logging"""
        try:
            with self._log_lock:
                getattr(self.logger, level)(message)
        except:
            pass
    
    async def start(self):
        """Start event processor"""
        try:
            self.is_running = True
            self.processing_start_time = time.time()
            self._safe_log("info", "🚀 Simple Event Processor started - RULE-BASED ALERTS ONLY")
            
            # Start retry mechanism for failed events
            self._retry_task = asyncio.create_task(self._retry_failed_events_loop())
            
            # Start statistics logging
            asyncio.create_task(self._stats_logging_loop())
            
        except Exception as e:
            self._safe_log("error", f"Event processor start error: {e}")
            raise
    
    async def stop(self):
        """Stop event processor gracefully"""
        try:
            self._safe_log("info", "🛑 Stopping Simple Event Processor...")
            self.is_running = False
            
            # Cancel retry task
            if self._retry_task:
                self._retry_task.cancel()
            
            # Try to send any remaining failed events
            await self._flush_failed_events()
            
            await asyncio.sleep(0.5)
            
            self._safe_log("info", "✅ Simple Event Processor stopped gracefully")
            
        except Exception as e:
            self._safe_log("error", f"❌ Event processor stop error: {e}")
    
    def set_agent_id(self, agent_id: str):
        """Set agent ID for communication"""
        self.agent_id = agent_id
        self._safe_log("info", f"Agent ID set: {agent_id}")
    
    async def add_event(self, event_data: EventData):
        """
        GỬI EVENT LÊN SERVER - CHỈ KHI KẾT NỐI THÀNH CÔNG
        Chỉ gửi event khi thực sự kết nối được với server
        """
        try:
            # FIXED: Ensure agent_id is set on the event
            if self.agent_id and not event_data.agent_id:
                event_data.agent_id = self.agent_id
            
            # FIXED: Skip events without agent_id
            if not event_data.agent_id:
                self.stats.events_failed += 1
                return
            
            # FIXED: Update stats immediately
            self.stats.events_collected += 1
            
            # FIXED: Check offline_mode first - SILENT when offline
            if not self.communication or self.communication.offline_mode:
                # SILENT: Don't send events when offline
                self.stats.events_failed += 1
                return
            
            # FIXED: Check if server is actually connected before sending
            if not self.communication.is_connected():
                # SILENT: Don't send events when not connected
                self.stats.events_failed += 1
                return
            
            # ADDED: Debug log for Authentication events (only when online)
            if event_data.event_type == 'Authentication' and self.communication and self.communication.is_connected():
                self._safe_log("info", f"🔐 AUTHENTICATION EVENT: {event_data.login_user} - {event_data.event_action}")
            
            if self.agent_id and self.communication:
                # Gửi event lên server ngay lập tức
                success = await self._send_event_to_server(event_data)
                
                if not success:
                    # Nếu gửi thất bại, thêm vào retry queue - SILENT
                    self._failed_events_queue.append({
                        'event': event_data,
                        'timestamp': time.time(),
                        'retry_count': 0
                    })
                    # NO LOGGING - completely silent
            else:
                # SILENT when agent_id or communication not available
                self.stats.events_failed += 1
            
        except Exception as e:
            # SILENT on exceptions
            self.stats.events_failed += 1
    
    async def _send_event_to_server(self, event_data: EventData) -> bool:
        """
        GỬI EVENT LÊN SERVER VÀ CHỜ RULE VIOLATION RESPONSE - SILENT OFFLINE MODE
        """
        try:
            # FIXED: Ensure agent_id is set on the event
            if self.agent_id and not event_data.agent_id:
                event_data.agent_id = self.agent_id
            
            # FIXED: Validate that agent_id is present
            if not event_data.agent_id:
                self._safe_log("error", f"❌ Event missing agent_id: {event_data.event_type}")
                return False
            
            # Gửi event lên server
            success, response, error = await self.communication.submit_event(event_data)
            
            if success:
                self.stats.events_sent += 1
                self.stats.last_event_sent = datetime.now()
                self._consecutive_failures = 0
                self._last_successful_send = time.time()
                
                # Xử lý response từ server để kiểm tra rule violations
                if response and isinstance(response, dict):
                    await self._process_server_response_simple(response, event_data)
                
                return True
            else:
                self.stats.events_failed += 1
                self._send_errors += 1
                self._consecutive_failures += 1
                
                # SILENT: No logging for offline mode
                return False
                
        except Exception as e:
            self.stats.events_failed += 1
            self._send_errors += 1
            self._consecutive_failures += 1
            
            # SILENT: No logging for offline mode
            return False
    
    async def _process_server_response_simple(self, server_response: Dict[str, Any], original_event: EventData):
        """
        XỬ LÝ RESPONSE TỪ SERVER - CHỈ HIỂN THỊ KHI CÓ RULE VIOLATION
        Chỉ hiển thị alert khi server phát hiện vi phạm rule cụ thể
        """
        try:
            if not server_response:
                return
            
            rule_violation_detected = False
            
            # Case 1: Server trả về alerts với rule information
            if 'alerts_generated' in server_response and server_response['alerts_generated']:
                alerts = server_response['alerts_generated']
                # Kiểm tra xem có rule violation không
                rule_alerts = [alert for alert in alerts if self._is_rule_violation_alert(alert)]
                
                if rule_alerts:
                    rule_violation_detected = True
                    self.stats.rule_violations_received += len(rule_alerts)
                    self.stats.last_rule_violation = datetime.now()
                    
                    self._safe_log("warning", f"🚨 SERVER DETECTED {len(rule_alerts)} RULE VIOLATIONS")
                    
                    # Hiển thị rule alerts
                    await self.security_notifier.process_server_alerts(
                        {'alerts_generated': rule_alerts}, 
                        [original_event]
                    )
                    
                    self.stats.rule_alerts_displayed += len(rule_alerts)
            
            # Case 2: Server trả về alerts array
            elif 'alerts' in server_response and server_response['alerts']:
                alerts = server_response['alerts']
                rule_alerts = [alert for alert in alerts if self._is_rule_violation_alert(alert)]
                
                if rule_alerts:
                    rule_violation_detected = True
                    self.stats.rule_violations_received += len(rule_alerts)
                    self.stats.last_rule_violation = datetime.now()
                    
                    self._safe_log("warning", f"🚨 SERVER DETECTED {len(rule_alerts)} RULE VIOLATIONS")
                    
                    await self.security_notifier.process_server_alerts(
                        {'alerts': rule_alerts}, 
                        [original_event]
                    )
                    
                    self.stats.rule_alerts_displayed += len(rule_alerts)
            
            # Case 3: Server phát hiện threat với rule information
            elif (server_response.get('threat_detected', False) and 
                  server_response.get('rule_triggered')):
                
                rule_violation_detected = True
                self.stats.rule_violations_received += 1
                self.stats.last_rule_violation = datetime.now()
                
                self._safe_log("warning", f"🚨 SERVER RULE TRIGGERED: {server_response.get('rule_triggered')}")
                
                # Tạo rule violation alert
                rule_alert = {
                    'id': f'rule_violation_{int(time.time())}',
                    'alert_id': f'rule_violation_{int(time.time())}',
                    'rule_id': server_response.get('rule_id'),
                    'rule_name': server_response.get('rule_triggered'),
                    'rule_description': server_response.get('rule_description', ''),
                    'title': f'Security Rule Violation: {server_response.get("rule_triggered")}',
                    'description': server_response.get('threat_description', 'Security rule violation detected'),
                    'severity': self._map_risk_to_severity(server_response.get('risk_score', 50)),
                    'risk_score': server_response.get('risk_score', 50),
                    'detection_method': 'Server Rule Engine',
                    'mitre_technique': server_response.get('mitre_technique'),
                    'mitre_tactic': server_response.get('mitre_tactic'),
                    'event_id': server_response.get('event_id'),
                    'timestamp': datetime.now().isoformat(),
                    'server_generated': True,
                    'rule_violation': True,
                    'process_name': original_event.process_name,
                    'process_path': original_event.process_path,
                    'file_path': original_event.file_path
                }
                
                await self.security_notifier.process_server_alerts(
                    {'alerts_generated': [rule_alert]}, 
                    [original_event]
                )
                
                self.stats.rule_alerts_displayed += 1
            
            # Case 4: Không có rule violation - KHÔNG HIỂN THỊ GÌ
            if not rule_violation_detected:
                self._safe_log("debug", f"✅ No rule violations detected for {original_event.event_type} - {original_event.process_name}")
            
        except Exception as e:
            self._safe_log("error", f"❌ Server response processing failed: {e}")
    
    def _is_rule_violation_alert(self, alert: Dict[str, Any]) -> bool:
        """Check if alert is a rule violation alert"""
        try:
            # Check for rule-specific fields
            rule_indicators = [
                alert.get('rule_id'),
                alert.get('rule_name'),
                alert.get('rule_triggered'),
                alert.get('rule_violation'),
                'rule' in alert.get('detection_method', '').lower(),
                'rule' in alert.get('title', '').lower(),
                'violation' in alert.get('description', '').lower()
            ]
            
            return any(rule_indicators)
            
        except Exception as e:
            self._safe_log("error", f"❌ Error checking rule violation: {e}")
            return False
    
    def _map_risk_to_severity(self, risk_score: int) -> str:
        """Map risk score to severity level"""
        if risk_score >= 90:
            return "CRITICAL"
        elif risk_score >= 70:
            return "HIGH"
        elif risk_score >= 50:
            return "MEDIUM"
        elif risk_score >= 30:
            return "LOW"
        else:
            return "INFO"
    
    async def _retry_failed_events_loop(self):
        """Retry failed events - SILENT OFFLINE MODE"""
        retry_interval = 5  # Start with 5 seconds
        max_retry_interval = 60  # Max 60 seconds
        consecutive_failures = 0
        was_offline = False  # Track if we were offline
        
        while self.is_running:
            try:
                if not self._failed_events_queue:
                    await asyncio.sleep(1)
                    continue
                
                # Check if server is available - SILENT when offline
                if not self.communication or not self.communication.is_connected():
                    # COMPLETELY SILENT - no logging when offline
                    was_offline = True
                    await asyncio.sleep(retry_interval)
                    consecutive_failures += 1
                    retry_interval = min(retry_interval * 1.5, max_retry_interval)
                    continue
                
                # NOTIFY ONLY when coming back online
                if was_offline:
                    self._safe_log("info", "✅ SERVER CONNECTION RESTORED - Resuming event transmission")
                    was_offline = False
                    consecutive_failures = 0
                    retry_interval = 5
                
                # Process retry queue - SILENT processing
                failed_events = list(self._failed_events_queue)
                self._failed_events_queue.clear()
                
                success_count = 0
                for failed_event in failed_events:
                    if not self.is_running:
                        break
                    
                    event_data = failed_event['event']
                    retry_count = failed_event['retry_count']
                    
                    if retry_count >= 3:  # Max 3 retries - SILENT discard
                        continue
                    
                    # Try to send again
                    success = await self._send_event_to_server(event_data)
                    
                    if success:
                        success_count += 1
                    else:
                        # Re-queue for retry - SILENT
                        failed_event['retry_count'] = retry_count + 1
                        self._failed_events_queue.append(failed_event)
                
                # Only log if we successfully sent some events
                if success_count > 0:
                    self._safe_log("info", f"✅ Resumed: {success_count} events sent")
                
                await asyncio.sleep(retry_interval)
                
            except Exception as e:
                # SILENT on retry loop errors
                await asyncio.sleep(5)
    
    async def _flush_failed_events(self):
        """Try to send all remaining failed events"""
        try:
            if self._failed_events_queue:
                self._safe_log("info", f"🔄 Flushing {len(self._failed_events_queue)} remaining events...")
                
                while self._failed_events_queue:
                    event_info = self._failed_events_queue.popleft()
                    event_data = event_info['event']
                    
                    try:
                        await self._send_event_to_server(event_data)
                    except:
                        pass  # Ignore errors during shutdown
        except Exception as e:
            self._safe_log("error", f"❌ Flush failed events error: {e}")
    
    async def _stats_logging_loop(self):
        """Statistics logging loop - FIXED VERSION"""
        try:
            while self.is_running:
                try:
                    # Log statistics every 60 seconds
                    current_time = time.time()
                    if int(current_time) % 60 == 0:
                        stats = self.get_stats()
                        
                        # FIXED: Better processing rate calculation
                        processing_rate = stats.get('processing_rate', 0)
                        events_sent = stats.get('events_sent', 0)
                        events_failed = stats.get('events_failed', 0)
                        success_rate = stats.get('success_rate', 0)
                        
                        # FIXED: Only show warning if really low rate
                        if processing_rate < 0.01 and events_sent == 0:
                            self._safe_log("warning", f"⚠️ Low processing rate: {processing_rate:.2f} events/sec - No events sent")
                        elif processing_rate < 0.1:
                            self._safe_log("info", f"📊 Low processing rate: {processing_rate:.2f} events/sec - Check server connection")
                        else:
                            self._safe_log("info", 
                                f"📊 Event Processor Stats - "
                                f"Sent: {events_sent}, "
                                f"Failed: {events_failed}, "
                                f"Success Rate: {success_rate:.1f}%, "
                                f"Rate: {processing_rate:.2f}/s")
                    
                    await asyncio.sleep(30)  # Check every 30 seconds
                    
                except Exception as e:
                    self._safe_log("error", f"Stats logging error: {e}")
                    await asyncio.sleep(30)
                    
        except Exception as e:
            self._safe_log("error", f"Stats logging loop failed: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get event processor statistics"""
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
                'rule_violations_received': self.stats.rule_violations_received,
                'rule_alerts_displayed': self.stats.rule_alerts_displayed,
                'last_event_sent': self.stats.last_event_sent.isoformat() if self.stats.last_event_sent else None,
                'last_rule_violation': self.stats.last_rule_violation.isoformat() if self.stats.last_rule_violation else None,
                'processing_rate': processing_rate,
                'success_rate': success_rate,
                'uptime': uptime,
                'send_errors': self._send_errors,
                'consecutive_failures': self._consecutive_failures,
                'time_since_last_send': current_time - self._last_successful_send,
                'failed_queue_size': len(self._failed_events_queue),
                'rule_based_alerts_only': True,
                'simple_mode': True
            }
            
        except Exception as e:
            self._safe_log("error", f"Stats calculation failed: {e}")
            return {}
    
    # Compatibility methods
    async def submit_event(self, event_data: EventData):
        """Submit event - alias for add_event"""
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
            'queue_utilization': len(self._failed_events_queue) / 1000,
            'processing_rate': self.stats.processing_rate,
            'immediate_processing': self.immediate_send,
            'rule_based_mode': True,
            'simple_mode': True,
            'success_rate': success_rate,
            'error_rate': self._send_errors / max(total_attempts, 1),
            'rule_violations_received': self.stats.rule_violations_received,
            'rule_alerts_displayed': self.stats.rule_alerts_displayed
        }

    async def _process_events(self):
        """Process events from queue - RULE-BASED ALERTS ONLY"""
        self.is_processing = True
        
        try:
            while not self.event_queue.empty():
                try:
                    event_data = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                    
                    # Check if server is connected before sending
                    if not self.communication or not self.communication.is_connected():
                        # Server is offline - skip sending but keep event for later
                        self._safe_log("debug", f"📡 Server offline - skipping event: {event_data.event_type}")
                        continue
                    
                    # Send event to server
                    success = await self._send_event_to_server(event_data)
                    
                    if not success:
                        # Only log retry if we haven't logged too many recently
                        current_time = time.time()
                        if current_time - self._last_retry_log > 5.0:  # Log retry every 5 seconds max
                            self._safe_log("warning", f"⚠️ Event queued for retry: {event_data.event_type}")
                            self._last_retry_log = current_time
                        
                        # Add to retry queue with limit
                        if len(self.retry_queue) < 100:  # Limit retry queue size
                            self.retry_queue.append(event_data)
                    
                    self.event_queue.task_done()
                    
                except asyncio.TimeoutError:
                    break
                except Exception as e:
                    self._safe_log("error", f"❌ Event processing error: {e}")
                    if not self.event_queue.empty():
                        self.event_queue.task_done()
        
        finally:
            self.is_processing = False
            
            # Process retry queue if server is back online
            if self.communication and self.communication.is_connected() and self.retry_queue:
                await self._process_retry_queue()

    async def _process_retry_queue(self):
        """Process events in retry queue when server is back online"""
        if not self.retry_queue:
            return
        
        self._safe_log("info", f"🔄 Processing {len(self.retry_queue)} retry events...")
        
        retry_events = self.retry_queue.copy()
        self.retry_queue.clear()
        
        for event_data in retry_events:
            try:
                success = await self._send_event_to_server(event_data)
                if not success:
                    # Put back in retry queue if still failing
                    if len(self.retry_queue) < 50:  # Smaller limit for retry queue
                        self.retry_queue.append(event_data)
            except Exception as e:
                self._safe_log("error", f"❌ Retry event processing failed: {e}")
                # Put back in retry queue
                if len(self.retry_queue) < 50:
                    self.retry_queue.append(event_data)
        
        if self.retry_queue:
            self._safe_log("warning", f"⚠️ {len(self.retry_queue)} events still in retry queue")
        else:
            self._safe_log("info", "✅ All retry events processed successfully")