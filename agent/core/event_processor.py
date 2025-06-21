# agent/core/event_processor.py - Updated with Security Notifications
"""
Event Processor với Security Alert Notification System
Hiển thị cảnh báo bảo mật khi server phát hiện threats qua detection rules
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import deque
from dataclasses import dataclass

from .config_manager import ConfigManager
from .communication import ServerCommunication
from ..schemas.events import EventData
from ..utils.security_notifications import SecurityAlertNotifier

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

class EventProcessor:
    """Event Processor with Security Alert Notifications"""
    
    def __init__(self, config_manager: ConfigManager, communication: ServerCommunication):
        self.config_manager = config_manager
        self.communication = communication
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.config = self.config_manager.get_config()
        self.agent_config = self.config.get('agent', {})
        
        # Event queue
        self.event_queue: deque = deque()
        self.max_queue_size = self.agent_config.get('event_queue_size', 1000)
        self.batch_size = self.agent_config.get('event_batch_size', 100)
        
        # Processing state
        self.is_running = False
        self.agent_id: Optional[str] = None
        
        # Statistics
        self.stats = EventStats()
        
        # Batch processing
        self.batch_interval = 5  # seconds
        self.last_batch_time = time.time()
        
        # Event filtering
        self.filters = self.config.get('filters', {})
        
        # Security Alert Notification System
        self.security_notifier = SecurityAlertNotifier(config_manager)
        
        self.logger.info("🔒 Event Processor with Security Notifications initialized")
    
    async def start(self):
        """Start event processor"""
        try:
            self.is_running = True
            self.logger.info("🚀 Event processor started with security notifications")
            
            # Start batch processing task
            asyncio.create_task(self._batch_processing_loop())
            
            # Start statistics logging task
            asyncio.create_task(self._stats_logging_loop())
            
        except Exception as e:
            self.logger.error(f"❌ Event processor start error: {e}")
    
    async def stop(self):
        """Stop event processor"""
        try:
            self.logger.info("🛑 Stopping event processor...")
            self.is_running = False
            
            # Process remaining events
            if self.event_queue:
                await self._send_remaining_events()
            
            self.logger.info("✅ Event processor stopped")
            
        except Exception as e:
            self.logger.error(f"❌ Event processor stop error: {e}")
    
    def set_agent_id(self, agent_id: str):
        """Set agent ID for event processing"""
        self.agent_id = agent_id
        self.logger.info(f"🆔 Agent ID set: {agent_id}")
    
    async def add_event(self, event_data: EventData):
        """Add event to processing queue"""
        try:
            # Set agent ID if not already set
            if self.agent_id:
                event_data.agent_id = self.agent_id
            
            # Apply filters
            if not self._should_process_event(event_data):
                return
            
            # Check queue size
            if len(self.event_queue) >= self.max_queue_size:
                # Remove oldest event to make room
                self.event_queue.popleft()
                self.logger.warning("⚠️ Event queue full, dropped oldest event")
            
            # Add to queue
            self.event_queue.append(event_data)
            self.stats.events_collected += 1
            self.stats.events_queued = len(self.event_queue)
            
            self.logger.debug(f"📥 Event queued: {event_data.event_type} ({len(self.event_queue)} in queue)")
            
            # Check if we should send immediately
            if len(self.event_queue) >= self.batch_size:
                await self._send_batch()
            
        except Exception as e:
            self.logger.error(f"❌ Failed to add event: {e}")
            self.stats.events_failed += 1
    
    async def _send_batch(self):
        """Send batch of events to server and handle security alerts"""
        try:
            if not self.event_queue or not self.agent_id:
                self.logger.warning(f"[SEND_BATCH] Missing agent_id or empty queue. AgentID: {self.agent_id}")
                return
            
            # Extract events for batch
            batch_events = []
            batch_size = min(len(self.event_queue), self.batch_size)
            
            for _ in range(batch_size):
                if self.event_queue:
                    batch_events.append(self.event_queue.popleft())
            
            if not batch_events:
                return
            
            self.logger.info(f"[SEND_BATCH] Sending batch: {len(batch_events)} events | AgentID: {self.agent_id}")
            
            # Send to server
            response = await self.communication.submit_event_batch(self.agent_id, batch_events)
            
            if response and response.get('success'):
                self.stats.events_sent += len(batch_events)
                self.stats.last_batch_sent = datetime.now()
                self.stats.batch_count += 1
                self.logger.info(f"✅ Batch sent successfully: {len(batch_events)} events")
                
                # *** XỬ LÝ SECURITY ALERTS TỪ SERVER ***
                await self._handle_security_alerts_from_server(response, batch_events)
                    
            else:
                # Return events to queue on failure
                for event in reversed(batch_events):
                    self.event_queue.appendleft(event)
                
                self.stats.events_failed += len(batch_events)
                self.logger.error(f"❌ Batch send failed: {len(batch_events)} events returned to queue")
            
            self.last_batch_time = time.time()
            self.stats.events_queued = len(self.event_queue)
            
        except Exception as e:
            self.logger.error(f"❌ Batch send error: {e}")
            # Return events to queue on error
            for event in batch_events:
                self.event_queue.appendleft(event)
    
    async def _handle_security_alerts_from_server(self, server_response: Dict[str, Any], batch_events: List[EventData]):
        """Xử lý security alerts từ server response"""
        try:
            # Kiểm tra các trường có thể chứa alerts
            alerts_found = False
            
            # Check for alerts_generated field (thường dùng)
            if 'alerts_generated' in server_response and server_response['alerts_generated']:
                alerts_found = True
                self.stats.alerts_received += len(server_response['alerts_generated'])
                
                self.logger.warning(
                    f"🚨 SECURITY ALERTS: {len(server_response['alerts_generated'])} threats detected by server!"
                )
                
                # Gửi đến security notifier để hiển thị popup
                self.security_notifier.process_server_alerts(server_response, batch_events)
            
            # Check for threat_detected field
            elif server_response.get('threat_detected', False):
                alerts_found = True
                self.stats.alerts_received += 1
                
                # Create alert data from response
                alert_data = {
                    'alert_id': f"alert_{int(time.time())}",
                    'rule_name': 'Server Detection',
                    'alert_type': 'Security Alert',
                    'title': 'Threat Detected by Server',
                    'description': server_response.get('message', 'Suspicious activity detected'),
                    'severity': 'HIGH' if server_response.get('risk_score', 0) >= 70 else 'MEDIUM',
                    'risk_score': server_response.get('risk_score', 50),
                    'detection_method': 'Server Analysis',
                    'timestamp': datetime.now().isoformat()
                }
                
                self.logger.warning(f"🚨 SERVER THREAT DETECTED: Risk Score {alert_data['risk_score']}")
                
                # Send to security notifier
                self.security_notifier.process_server_alerts(
                    {'alerts_generated': [alert_data]}, 
                    batch_events
                )
            
            # Check for individual alert fields
            elif any(key.startswith('alert_') for key in server_response.keys()):
                alerts_found = True
                self.stats.alerts_received += 1
                
                # Extract alert information from response
                alert_data = {
                    'alert_id': server_response.get('alert_id', f"alert_{int(time.time())}"),
                    'rule_name': server_response.get('rule_name', 'Unknown Rule'),
                    'alert_type': server_response.get('alert_type', 'Security Alert'),
                    'title': server_response.get('title', 'Security Threat Detected'),
                    'description': server_response.get('description', 'Suspicious activity detected'),
                    'severity': server_response.get('severity', 'MEDIUM'),
                    'risk_score': server_response.get('risk_score', 50),
                    'detection_method': server_response.get('detection_method', 'Server Analysis'),
                    'timestamp': server_response.get('timestamp', datetime.now().isoformat())
                }
                
                self.logger.warning(f"🚨 ALERT FROM SERVER: {alert_data['rule_name']} - {alert_data['severity']}")
                
                # Send to security notifier
                self.security_notifier.process_server_alerts(
                    {'alerts_generated': [alert_data]}, 
                    batch_events
                )
            
            if alerts_found:
                self.logger.critical(
                    f"🚨 SECURITY ALERT SUMMARY:"
                    f"\n   Events in batch: {len(batch_events)}"
                    f"\n   Alerts generated: {self.stats.alerts_received}"
                    f"\n   Risk score: {server_response.get('risk_score', 'N/A')}"
                    f"\n   Threat level: {server_response.get('threat_level', 'N/A')}"
                )
                
                # Update statistics
                self.stats.security_notifications_sent += 1
                
            else:
                self.logger.debug("✅ No security alerts in server response")
                
        except Exception as e:
            self.logger.error(f"❌ Error handling security alerts from server: {e}")
    
    def _should_process_event(self, event_data: EventData) -> bool:
        """Apply filters to determine if event should be processed"""
        try:
            # Check if collection is enabled
            if not self.config.get('collection', {}).get('enabled', True):
                return False
            
            # Check event type filters
            collection_config = self.config.get('collection', {})
            
            if event_data.event_type == 'Process':
                if not collection_config.get('collect_processes', True):
                    return False
                
                # Filter system processes
                if (self.filters.get('exclude_system_processes', True) and 
                    self._is_system_process(event_data)):
                    return False
                    
            elif event_data.event_type == 'File':
                if not collection_config.get('collect_files', True):
                    return False
                
                # Filter by file extension
                if (event_data.file_extension and 
                    event_data.file_extension.lower() in self.filters.get('exclude_file_extensions', [])):
                    return False
                
                # Filter Windows directories
                if (event_data.file_path and 
                    any(excluded_dir.lower() in event_data.file_path.lower() 
                        for excluded_dir in self.filters.get('exclude_windows_directories', []))):
                    return False
                    
            elif event_data.event_type == 'Network':
                if not collection_config.get('collect_network', True):
                    return False
                    
            elif event_data.event_type == 'Registry':
                if not collection_config.get('collect_registry', True):
                    return False
                    
            elif event_data.event_type == 'Authentication':
                if not collection_config.get('collect_authentication', True):
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Filter error: {e}")
            return True  # Default to processing if filter fails
    
    def _is_system_process(self, event_data: EventData) -> bool:
        """Check if process is a system process"""
        try:
            if not event_data.process_name:
                return False
            
            system_processes = [
                'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
                'services.exe', 'lsass.exe', 'svchost.exe', 'spoolsv.exe'
            ]
            
            process_name = event_data.process_name.lower()
            return process_name in system_processes
            
        except Exception:
            return False
    
    async def _batch_processing_loop(self):
        """Main batch processing loop"""
        while self.is_running:
            try:
                current_time = time.time()
                
                # Check if batch interval has passed
                if (current_time - self.last_batch_time >= self.batch_interval and 
                    self.event_queue):
                    await self._send_batch()
                
                await asyncio.sleep(1)  # Check every second
                
            except Exception as e:
                self.logger.error(f"❌ Batch processing error: {e}")
                await asyncio.sleep(5)
    
    async def _send_remaining_events(self):
        """Send all remaining events in queue"""
        try:
            while self.event_queue:
                await self._send_batch()
                await asyncio.sleep(0.1)  # Small delay between batches
                
            self.logger.info("✅ All remaining events sent")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to send remaining events: {e}")
    
    async def _stats_logging_loop(self):
        """Log statistics periodically"""
        while self.is_running:
            try:
                await asyncio.sleep(60)  # Log every minute
                
                if self.stats.events_collected > 0:
                    success_rate = (self.stats.events_sent / self.stats.events_collected) * 100
                    
                    self.logger.info(
                        f"📊 Event Stats: Collected={self.stats.events_collected}, "
                        f"Sent={self.stats.events_sent}, Failed={self.stats.events_failed}, "
                        f"Queued={self.stats.events_queued}, "
                        f"Alerts={self.stats.alerts_received}, "
                        f"Security Notifications={self.stats.security_notifications_sent}, "
                        f"Success Rate={success_rate:.1f}%"
                    )
                
            except Exception as e:
                self.logger.error(f"❌ Stats logging error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current processing statistics"""
        base_stats = {
            'events_collected': self.stats.events_collected,
            'events_sent': self.stats.events_sent,
            'events_failed': self.stats.events_failed,
            'events_queued': self.stats.events_queued,
            'alerts_received': self.stats.alerts_received,
            'security_notifications_sent': self.stats.security_notifications_sent,
            'batch_count': self.stats.batch_count,
            'last_batch_sent': self.stats.last_batch_sent.isoformat() if self.stats.last_batch_sent else None,
            'queue_size': len(self.event_queue),
            'max_queue_size': self.max_queue_size,
            'batch_size': self.batch_size,
            'success_rate': (self.stats.events_sent / max(self.stats.events_collected, 1)) * 100
        }
        
        # Add security notification stats
        if self.security_notifier:
            base_stats['security_notifier_stats'] = self.security_notifier.get_security_stats()
        
        return base_stats
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get current queue status"""
        return {
            'current_size': len(self.event_queue),
            'max_size': self.max_queue_size,
            'usage_percent': (len(self.event_queue) / self.max_queue_size) * 100,
            'is_full': len(self.event_queue) >= self.max_queue_size,
            'batch_size': self.batch_size,
            'time_since_last_batch': time.time() - self.last_batch_time
        }
    
    async def flush_queue(self):
        """Force flush all events in queue"""
        try:
            if self.event_queue:
                self.logger.info(f"🔄 Flushing {len(self.event_queue)} events")
                await self._send_remaining_events()
            else:
                self.logger.info("✅ Event queue is empty")
        except Exception as e:
            self.logger.error(f"❌ Error while flushing event queue: {e}")
    
    def clear_stats(self):
        """Clear processing statistics"""
        self.stats = EventStats()
        self.logger.info("📊 Event statistics cleared")
    
    def test_security_notification_system(self):
        """Test the security notification system"""
        try:
            if self.security_notifier:
                self.security_notifier.test_security_alert()
                self.logger.info("✅ Security notification test completed")
            else:
                self.logger.warning("⚠️ Security notifier not available")
        except Exception as e:
            self.logger.error(f"❌ Security notification test failed: {e}")
    
    def configure_security_notifications(self, **kwargs):
        """Configure security notification settings"""
        try:
            if self.security_notifier:
                self.security_notifier.configure_security_notifications(**kwargs)
                self.logger.info(f"🔧 Security notification settings updated: {kwargs}")
            else:
                self.logger.warning("⚠️ Security notifier not available")
        except Exception as e:
            self.logger.error(f"❌ Security notification configuration failed: {e}")
    
    def get_recent_security_alerts(self) -> List[Dict[str, Any]]:
        """Get recent security alerts"""
        try:
            if self.security_notifier:
                stats = self.security_notifier.get_security_stats()
                return stats.get('recent_alerts', [])
            else:
                return []
        except Exception as e:
            self.logger.error(f"❌ Failed to get recent security alerts: {e}")
            return []
    
    def simulate_security_alert(self, rule_name: str = "Test Rule", severity: str = "HIGH"):
        """Simulate a security alert for testing"""
        try:
            # Create mock server response with alert
            mock_response = {
                'success': True,
                'alerts_generated': [{
                    'id': f'sim_{int(time.time())}',
                    'rule_name': rule_name,
                    'title': f'Simulated {severity} Alert',
                    'description': f'This is a simulated {severity} security alert for testing',
                    'severity': severity,
                    'risk_score': 85 if severity == 'HIGH' else 95 if severity == 'CRITICAL' else 60,
                    'detection_method': 'Simulation',
                    'alert_type': 'Test Alert',
                    'timestamp': datetime.now().isoformat()
                }]
            }
            
            # Process the simulated alert
            if self.security_notifier:
                self.security_notifier.process_server_alerts(mock_response, [])
                self.logger.info(f"✅ Simulated {severity} security alert: {rule_name}")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to simulate security alert: {e}")


# For backward compatibility
EnhancedEventProcessor = EventProcessor