# agent/core/event_processor.py - CHỈ HIỂN THỊ ALERT TỪ SERVER
"""
Event Processor - CHỈ HIỂN THỊ CẢNH BÁO KHI SERVER GỬI VỀ
Gửi events lên server và chỉ hiển thị notification khi server phát hiện vi phạm
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
    server_alerts_received: int = 0
    security_notifications_displayed: int = 0
    last_event_sent: Optional[datetime] = None
    last_server_alert: Optional[datetime] = None
    processing_rate: float = 0.0

class EventProcessor:
    """Event Processor - CHỈ HIỂN THỊ ALERT KHI SERVER GỬI VỀ"""
    
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
        
        # Security Alert Notification System - CHỈ CHO SERVER ALERTS
        self.security_notifier = SecurityAlertNotifier(config_manager)
        self.security_notifier.set_communication(communication)
        
        # Event queue for failed sends
        self._failed_events_queue = deque(maxlen=1000)
        self._retry_task = None
        
        # Processing lock
        self._processing_lock = asyncio.Lock()
        self._send_errors = 0
        self._consecutive_failures = 0
        self._last_successful_send = time.time()
        
        self._safe_log("info", "🚀 Event Processor initialized - SERVER ALERT DISPLAY ONLY")
    
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
            self._safe_log("info", "🚀 Event Processor started - SERVER ALERT NOTIFICATIONS ENABLED")
            
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
            self._safe_log("info", "🛑 Stopping Event Processor...")
            self.is_running = False
            
            # Cancel retry task
            if self._retry_task:
                self._retry_task.cancel()
            
            # Try to send any remaining failed events
            await self._flush_failed_events()
            
            await asyncio.sleep(0.5)
            
            self._safe_log("info", "✅ Event Processor stopped gracefully")
            
        except Exception as e:
            self._safe_log("error", f"❌ Event processor stop error: {e}")
    
    def set_agent_id(self, agent_id: str):
        """Set agent ID for communication"""
        self.agent_id = agent_id
        self._safe_log("info", f"Agent ID set: {agent_id}")
    
    async def add_event(self, event_data: EventData):
        """
        GỬI EVENT LÊN SERVER VÀ CHỜ PHẢN HỒI
        Chỉ hiển thị alert nếu server phát hiện threat
        """
        try:
            if self.agent_id and self.communication:
                # Gửi event lên server ngay lập tức
                success = await self._send_event_to_server(event_data)
                
                if not success:
                    # Nếu gửi thất bại, thêm vào retry queue
                    self._failed_events_queue.append({
                        'event': event_data,
                        'timestamp': time.time(),
                        'retry_count': 0
                    })
                    self._safe_log("warning", f"Event queued for retry: {event_data.event_type}")
            else:
                self._safe_log("error", "Cannot send event - agent_id or communication not available")
            
            self.stats.events_collected += 1
            
        except Exception as e:
            self._safe_log("error", f"Failed to process event: {e}")
            self.stats.events_failed += 1
    
    async def _send_event_to_server(self, event_data: EventData) -> bool:
        """
        GỬI EVENT LÊN SERVER VÀ XỬ LÝ PHẢN HỒI
        Chỉ hiển thị notification nếu server phát hiện threat
        """
        try:
            async with self._processing_lock:
                # Set agent ID
                event_data.agent_id = self.agent_id
                
                # Add timestamp if missing
                if not hasattr(event_data, 'event_timestamp') or not event_data.event_timestamp:
                    event_data.event_timestamp = datetime.now()
                
                # Send event to server
                start_time = time.time()
                response = await self.communication.submit_event(event_data)
                send_time = (time.time() - start_time) * 1000  # Convert to ms
                
                if response:
                    self.stats.events_sent += 1
                    self.stats.last_event_sent = datetime.now()
                    self._consecutive_failures = 0
                    self._last_successful_send = time.time()
                    
                    self._safe_log("debug", f"📤 Event sent: {event_data.event_type} - {event_data.event_action} ({send_time:.1f}ms)")
                    
                    # XỬ LÝ PHẢN HỒI TỪ SERVER - CHỈ HIỂN THỊ ALERT NẾU CÓ THREAT
                    await self._process_server_response(response, event_data)
                    return True
                else:
                    self.stats.events_failed += 1
                    self._send_errors += 1
                    self._consecutive_failures += 1
                    self._safe_log("debug", f"❌ Event send failed: {event_data.event_type}")
                    return False
        
        except Exception as e:
            self._safe_log("error", f"❌ Event send failed: {e}")
            self.stats.events_failed += 1
            self._send_errors += 1
            self._consecutive_failures += 1
            return False
    
    async def _process_server_response(self, server_response: Dict[str, Any], original_event: EventData):
        """
        XỬ LÝ PHẢN HỒI TỪ SERVER - CHỈ HIỂN THỊ NẾU CÓ THREAT
        Chỉ hiển thị notification khi server phát hiện vi phạm bảo mật
        """
        try:
            if not server_response:
                return
            
            # Kiểm tra xem server có phát hiện threat không
            threat_detected = False
            alerts_to_show = []
            
            # Case 1: Server trả về threat_detected = True
            if server_response.get('threat_detected', False):
                threat_detected = True
                self._safe_log("warning", f"🚨 SERVER DETECTED THREAT - Risk Score: {server_response.get('risk_score', 0)}")
                
                # Tạo alert từ server response
                server_alert = {
                    'id': f'server_threat_{int(time.time())}',
                    'rule_name': server_response.get('rule_triggered', 'Server Threat Detection'),
                    'title': 'Security Threat Detected by Server',
                    'description': server_response.get('threat_description', f'Server detected suspicious {original_event.event_type} activity'),
                    'severity': self._map_risk_to_severity(server_response.get('risk_score', 50)),
                    'risk_score': server_response.get('risk_score', 50),
                    'detection_method': 'Server Analysis',
                    'mitre_technique': server_response.get('mitre_technique'),
                    'mitre_tactic': server_response.get('mitre_tactic'),
                    'event_id': server_response.get('event_id'),
                    'timestamp': datetime.now().isoformat(),
                    'server_generated': True,
                    'original_event_type': original_event.event_type,
                    'original_event_action': original_event.event_action
                }
                alerts_to_show.append(server_alert)
            
            # Case 2: Server trả về alerts_generated
            if 'alerts_generated' in server_response and server_response['alerts_generated']:
                threat_detected = True
                alerts = server_response['alerts_generated']
                self._safe_log("warning", f"🚨 SERVER GENERATED {len(alerts)} SECURITY ALERTS")
                
                for alert in alerts:
                    # Ensure alert has server_generated flag
                    alert['server_generated'] = True
                    alert['original_event_type'] = original_event.event_type
                    alert['original_event_action'] = original_event.event_action
                    alerts_to_show.append(alert)
            
            # Case 3: Server trả về alerts array
            if 'alerts' in server_response and server_response['alerts']:
                threat_detected = True
                alerts = server_response['alerts']
                self._safe_log("warning", f"🚨 SERVER SENT {len(alerts)} SECURITY ALERTS")
                
                for alert in alerts:
                    alert['server_generated'] = True
                    alert['original_event_type'] = original_event.event_type
                    alert['original_event_action'] = original_event.event_action
                    alerts_to_show.append(alert)
            
            # Case 4: Risk score cao (>= 70)
            risk_score = server_response.get('risk_score', 0)
            if risk_score >= 70 and not threat_detected:
                threat_detected = True
                self._safe_log("warning", f"🚨 HIGH RISK SCORE DETECTED: {risk_score}/100")
                
                high_risk_alert = {
                    'id': f'high_risk_{int(time.time())}',
                    'rule_name': 'High Risk Score Detection',
                    'title': f'High Risk Activity Detected (Score: {risk_score})',
                    'description': f'Server assigned high risk score to {original_event.event_type} activity',
                    'severity': self._map_risk_to_severity(risk_score),
                    'risk_score': risk_score,
                    'detection_method': 'Risk Scoring',
                    'timestamp': datetime.now().isoformat(),
                    'server_generated': True,
                    'original_event_type': original_event.event_type,
                    'original_event_action': original_event.event_action
                }
                alerts_to_show.append(high_risk_alert)
            
            # CHỈ HIỂN THỊ NOTIFICATION NẾU CÓ THREAT
            if threat_detected and alerts_to_show:
                self.stats.server_alerts_received += len(alerts_to_show)
                self.stats.last_server_alert = datetime.now()
                
                # Hiển thị alerts qua security notifier
                server_response_for_notifier = {
                    'alerts_generated': alerts_to_show,
                    'threat_detected': True,
                    'risk_score': max(alert.get('risk_score', 0) for alert in alerts_to_show)
                }
                
                await self.security_notifier.process_server_alerts(server_response_for_notifier, [original_event])
                
                self.stats.security_notifications_displayed += len(alerts_to_show)
                
                self._safe_log("critical", f"🚨 DISPLAYED {len(alerts_to_show)} SERVER SECURITY ALERTS")
            else:
                # Không có threat - không hiển thị gì
                self._safe_log("debug", f"✅ Server processed event normally - no threats detected ({original_event.event_type})")
            
        except Exception as e:
            self._safe_log("error", f"❌ Server response processing failed: {e}")
    
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
        """Retry failed events periodically"""
        retry_interval = 10  # Retry every 10 seconds
        max_retries = 3
        
        while self.is_running:
            try:
                if self._failed_events_queue:
                    self._safe_log("info", f"🔄 Retrying {len(self._failed_events_queue)} failed events...")
                    
                    events_to_retry = []
                    while self._failed_events_queue and len(events_to_retry) < 5:  # Max 5 at a time
                        events_to_retry.append(self._failed_events_queue.popleft())
                    
                    for event_info in events_to_retry:
                        event_data = event_info['event']
                        retry_count = event_info['retry_count']
                        
                        if retry_count < max_retries:
                            success = await self._send_event_to_server(event_data)
                            
                            if not success:
                                event_info['retry_count'] += 1
                                event_info['timestamp'] = time.time()
                                self._failed_events_queue.append(event_info)
                        else:
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
                        await self._send_event_to_server(event_data)
                    except:
                        pass  # Ignore errors during shutdown
        except Exception as e:
            self._safe_log("error", f"❌ Flush failed events error: {e}")
    
    async def _stats_logging_loop(self):
        """Statistics logging loop"""
        try:
            while self.is_running:
                try:
                    # Log statistics every 60 seconds
                    current_time = time.time()
                    if int(current_time) % 60 == 0:
                        stats = self.get_stats()
                        
                        self._safe_log("info", 
                            f"📊 Event Processor Stats - "
                            f"Sent: {stats['events_sent']}, "
                            f"Failed: {stats['events_failed']}, "
                            f"Server Alerts: {stats['server_alerts_received']}, "
                            f"Notifications: {stats['security_notifications_displayed']}, "
                            f"Rate: {stats['processing_rate']:.2f}/s")
                    
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
                'server_alerts_received': self.stats.server_alerts_received,
                'security_notifications_displayed': self.stats.security_notifications_displayed,
                'last_event_sent': self.stats.last_event_sent.isoformat() if self.stats.last_event_sent else None,
                'last_server_alert': self.stats.last_server_alert.isoformat() if self.stats.last_server_alert else None,
                'processing_rate': processing_rate,
                'success_rate': success_rate,
                'uptime': uptime,
                'send_errors': self._send_errors,
                'consecutive_failures': self._consecutive_failures,
                'time_since_last_send': current_time - self._last_successful_send,
                'failed_queue_size': len(self._failed_events_queue),
                'server_alert_mode': True
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
            'server_alert_only_mode': True,
            'success_rate': success_rate,
            'error_rate': self._send_errors / max(total_attempts, 1),
            'server_alerts_received': self.stats.server_alerts_received,
            'notifications_displayed': self.stats.security_notifications_displayed
        }