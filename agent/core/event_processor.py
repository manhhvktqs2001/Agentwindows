# agent/core/event_processor.py - Final Version with Alert Acknowledgment
"""
Event Processor với Security Alert Notification System và Alert Acknowledgment
Enhanced để gửi acknowledgment ngược lại server để lưu vào bảng Alerts
"""

import asyncio
import logging
import time
import threading
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
    alerts_acknowledged: int = 0
    security_notifications_sent: int = 0
    last_batch_sent: Optional[datetime] = None
    batch_count: int = 0

class EventProcessor:
    """Event Processor with Security Alert Notifications and Server Acknowledgment"""
    
    def __init__(self, config_manager: ConfigManager, communication: ServerCommunication):
        self.config_manager = config_manager
        self.communication = communication
        self.logger = logging.getLogger(__name__)
        
        # Thread lock for logging safety
        self._log_lock = threading.Lock()
        
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
        
        # Security Alert Notification System with Communication Link
        self.security_notifier = SecurityAlertNotifier(config_manager)
        self.security_notifier.set_communication(communication)  # Link communication for acknowledgment
        
        self._safe_log("info", "🔒 Event Processor with Security Notifications and Acknowledgment initialized")
    
    def _safe_log(self, level: str, message: str):
        """Thread-safe logging to prevent reentrant calls"""
        try:
            with self._log_lock:
                getattr(self.logger, level)(message)
        except:
            # If logging fails, fail silently to prevent cascading errors
            pass
    
    async def start(self):
        """Start event processor"""
        try:
            self.is_running = True
            self._safe_log("info", "🚀 Event processor started with security notifications and acknowledgment")
            
            # Start batch processing task
            asyncio.create_task(self._batch_processing_loop())
            
            # Start statistics logging task
            asyncio.create_task(self._stats_logging_loop())
            
        except Exception as e:
            self._safe_log("error", f"❌ Event processor start error: {e}")
    
    async def stop(self):
        """Stop event processor"""
        try:
            self._safe_log("info", "🛑 Stopping event processor...")
            self.is_running = False
            
            # Process remaining events
            if self.event_queue:
                await self._send_remaining_events()
            
            self._safe_log("info", "✅ Event processor stopped")
            
        except Exception as e:
            self._safe_log("error", f"❌ Event processor stop error: {e}")
    
    def set_agent_id(self, agent_id: str):
        """Set agent ID for event processing"""
        self.agent_id = agent_id
        self._safe_log("info", f"🆔 Agent ID set: {agent_id}")
    
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
                self._safe_log("warning", "⚠️ Event queue full, dropped oldest event")
            
            # Add to queue
            self.event_queue.append(event_data)
            self.stats.events_collected += 1
            self.stats.events_queued = len(self.event_queue)
            
            # Check if we should send immediately
            if len(self.event_queue) >= self.batch_size:
                await self._send_batch()
            
        except Exception as e:
            self._safe_log("error", f"❌ Failed to add event: {e}")
            self.stats.events_failed += 1
    
    async def _send_batch(self):
        """Send batch of events to server and handle security alerts with acknowledgment"""
        try:
            if not self.event_queue or not self.agent_id:
                return
            
            # Extract events for batch
            batch_events = []
            batch_size = min(len(self.event_queue), self.batch_size)
            
            for _ in range(batch_size):
                if self.event_queue:
                    batch_events.append(self.event_queue.popleft())
            
            if not batch_events:
                return
            
            # Use safe logging for batch send
            self._safe_log("info", f"[SEND_BATCH] Sending batch: {len(batch_events)} events | AgentID: {self.agent_id}")
            
            # Send to server
            response = await self.communication.submit_event_batch(self.agent_id, batch_events)
            
            if response and response.get('success'):
                self.stats.events_sent += len(batch_events)
                self.stats.last_batch_sent = datetime.now()
                self.stats.batch_count += 1
                
                # Safe logging for successful batch
                self._safe_log("info", f"✅ Batch sent successfully: {len(batch_events)} events")
                
                # Handle security alerts from server with acknowledgment
                await self._handle_security_alerts_from_server_with_ack(response, batch_events)
                    
            else:
                # Return events to queue on failure
                for event in reversed(batch_events):
                    self.event_queue.appendleft(event)
                
                self.stats.events_failed += len(batch_events)
                self._safe_log("error", f"❌ Batch send failed: {len(batch_events)} events returned to queue")
            
            self.last_batch_time = time.time()
            self.stats.events_queued = len(self.event_queue)
            
        except Exception as e:
            # Use safe logging for errors
            self._safe_log("error", f"❌ Batch send error: {e}")
            # Return events to queue on error
            if 'batch_events' in locals():
                for event in batch_events:
                    self.event_queue.appendleft(event)
    
    async def _handle_security_alerts_from_server_with_ack(self, server_response: Dict[str, Any], batch_events: List[EventData]):
        """Handle security alerts from server response with enhanced acknowledgment"""
        try:
            alerts_found = False
            alerts_to_process = []
            alert_ids_to_mark_retrieved = []
            
            # Method 1: Check for alerts_generated field (standard format)
            if 'alerts_generated' in server_response and server_response['alerts_generated']:
                alerts_found = True
                alerts_to_process.extend(server_response['alerts_generated'])
                self._safe_log("warning", f"🚨 ALERTS_GENERATED: {len(server_response['alerts_generated'])} alerts from server")
                
                # Collect alert IDs for marking as retrieved
                for alert in server_response['alerts_generated']:
                    alert_id = alert.get('server_alert_id') or alert.get('id') or alert.get('alert_id')
                    if alert_id:
                        alert_ids_to_mark_retrieved.append(str(alert_id))
            
            # Method 2: Check for alerts field (alternative format)
            elif 'alerts' in server_response and server_response['alerts']:
                alerts_found = True
                alerts_to_process.extend(server_response['alerts'])
                self._safe_log("warning", f"🚨 ALERTS: {len(server_response['alerts'])} alerts from server")
                
                # Collect alert IDs
                for alert in server_response['alerts']:
                    alert_id = alert.get('server_alert_id') or alert.get('id') or alert.get('alert_id')
                    if alert_id:
                        alert_ids_to_mark_retrieved.append(str(alert_id))
            
            # Method 3: Check for threat_detected field
            elif server_response.get('threat_detected', False):
                alerts_found = True
                alert_data = {
                    'alert_id': f"threat_{int(time.time())}",
                    'server_alert_id': server_response.get('alert_id'),  # From server DB
                    'rule_name': 'Server Threat Detection',
                    'alert_type': 'Security Alert',
                    'title': 'Threat Detected by Server',
                    'description': server_response.get('message', 'Suspicious activity detected'),
                    'severity': 'HIGH' if server_response.get('risk_score', 0) >= 70 else 'MEDIUM',
                    'risk_score': server_response.get('risk_score', 50),
                    'detection_method': 'Server Analysis',
                    'timestamp': datetime.now().isoformat()
                }
                alerts_to_process.append(alert_data)
                
                alert_id = alert_data.get('server_alert_id')
                if alert_id:
                    alert_ids_to_mark_retrieved.append(str(alert_id))
                
                self._safe_log("warning", f"🚨 THREAT_DETECTED: Risk Score {alert_data['risk_score']}")
            
            # Method 4: Check for success=true with risk_score > threshold (inferred threat)
            elif (server_response.get('success', False) and 
                  server_response.get('risk_score', 0) > 50):
                alerts_found = True
                alert_data = {
                    'alert_id': f"inferred_{int(time.time())}",
                    'server_alert_id': server_response.get('alert_id'),
                    'rule_name': 'High Risk Activity',
                    'alert_type': 'Risk Alert',
                    'title': 'High Risk Activity Detected',
                    'description': f"Activity with risk score {server_response['risk_score']} detected",
                    'severity': 'HIGH' if server_response['risk_score'] >= 70 else 'MEDIUM',
                    'risk_score': server_response['risk_score'],
                    'detection_method': 'Risk Scoring',
                    'timestamp': datetime.now().isoformat()
                }
                alerts_to_process.append(alert_data)
                
                alert_id = alert_data.get('server_alert_id')
                if alert_id:
                    alert_ids_to_mark_retrieved.append(str(alert_id))
                
                self._safe_log("warning", f"🚨 HIGH_RISK: Score {alert_data['risk_score']}")
            
            # Method 5: Check if there are any fields containing "alert" or "threat"
            else:
                for key, value in server_response.items():
                    if ('alert' in key.lower() or 'threat' in key.lower()) and value:
                        alerts_found = True
                        alert_data = {
                            'alert_id': f"field_{int(time.time())}",
                            'server_alert_id': server_response.get('alert_id'),
                            'rule_name': f'Server Alert ({key})',
                            'alert_type': 'Security Alert',
                            'title': f'Security Alert: {key}',
                            'description': f'{key}: {str(value)}',
                            'severity': 'MEDIUM',
                            'risk_score': 60,
                            'detection_method': 'Field Detection',
                            'timestamp': datetime.now().isoformat()
                        }
                        alerts_to_process.append(alert_data)
                        
                        alert_id = alert_data.get('server_alert_id')
                        if alert_id:
                            alert_ids_to_mark_retrieved.append(str(alert_id))
                        
                        self._safe_log("warning", f"🚨 FIELD_ALERT: {key} = {value}")
                        break  # Only process first alert field found
            
            # Process all found alerts with acknowledgment
            if alerts_found and alerts_to_process:
                self.stats.alerts_received += len(alerts_to_process)
                
                # Log comprehensive alert summary
                self._safe_log("critical", 
                    f"🚨 SECURITY ALERT SUMMARY: {len(alerts_to_process)} alerts detected\n"
                    f"   Response keys: {list(server_response.keys())}\n"
                    f"   Alert types: {[alert.get('alert_type', 'Unknown') for alert in alerts_to_process]}\n"
                    f"   Severities: {[alert.get('severity', 'Unknown') for alert in alerts_to_process]}"
                )
                
                # Mark alerts as retrieved on server (if we have alert IDs)
                if alert_ids_to_mark_retrieved:
                    try:
                        await self.communication.mark_alerts_as_retrieved(alert_ids_to_mark_retrieved)
                        self._safe_log("info", f"✅ Marked {len(alert_ids_to_mark_retrieved)} alerts as retrieved")
                        self.stats.alerts_acknowledged += len(alert_ids_to_mark_retrieved)
                    except Exception as e:
                        self._safe_log("error", f"❌ Failed to mark alerts as retrieved: {e}")
                
                # Send to security notifier for display and acknowledgment
                mock_response = {'alerts_generated': alerts_to_process}
                self.security_notifier.process_server_alerts(mock_response, batch_events)
                self.stats.security_notifications_sent += 1
                
                # Log each individual alert
                for alert in alerts_to_process:
                    self._safe_log("error", 
                        f"🚨 ALERT: {alert.get('rule_name', 'Unknown')} | "
                        f"Severity: {alert.get('severity', 'Unknown')} | "
                        f"Risk: {alert.get('risk_score', 0)}/100 | "
                        f"Server ID: {alert.get('server_alert_id', 'N/A')}"
                    )
            else:
                # Debug: Log server response for analysis if no alerts found
                self._safe_log("debug", f"📋 Server response keys: {list(server_response.keys())}")
                
        except Exception as e:
            self._safe_log("error", f"❌ Error handling security alerts from server: {e}")
            # Also log the problematic response for debugging
            self._safe_log("debug", f"Problematic response: {server_response}")
    
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
            self._safe_log("error", f"❌ Filter error: {e}")
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
                self._safe_log("error", f"❌ Batch processing error: {e}")
                await asyncio.sleep(5)
    
    async def _send_remaining_events(self):
        """Send all remaining events in queue"""
        try:
            while self.event_queue:
                await self._send_batch()
                await asyncio.sleep(0.1)  # Small delay between batches
                
            self._safe_log("info", "✅ All remaining events sent")
            
        except Exception as e:
            self._safe_log("error", f"❌ Failed to send remaining events: {e}")
    
    async def _stats_logging_loop(self):
        """Log statistics periodically"""
        while self.is_running:
            try:
                await asyncio.sleep(60)  # Log every minute
                
                if self.stats.events_collected > 0:
                    success_rate = (self.stats.events_sent / self.stats.events_collected) * 100
                    acknowledgment_rate = (self.stats.alerts_acknowledged / max(self.stats.alerts_received, 1)) * 100
                    
                    stats_message = (
                        f"📊 Event Stats: Collected={self.stats.events_collected}, "
                        f"Sent={self.stats.events_sent}, Failed={self.stats.events_failed}, "
                        f"Queued={self.stats.events_queued}, "
                        f"Alerts={self.stats.alerts_received}, "
                        f"Acknowledged={self.stats.alerts_acknowledged}, "
                        f"Success Rate={success_rate:.1f}%, "
                        f"Acknowledgment Rate={acknowledgment_rate:.1f}%"
                    )
                    
                    self._safe_log("info", stats_message)
                
            except Exception as e:
                self._safe_log("error", f"❌ Stats logging error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current processing statistics"""
        base_stats = {
            'events_collected': self.stats.events_collected,
            'events_sent': self.stats.events_sent,
            'events_failed': self.stats.events_failed,
            'events_queued': self.stats.events_queued,
            'alerts_received': self.stats.alerts_received,
            'alerts_acknowledged': self.stats.alerts_acknowledged,
            'security_notifications_sent': self.stats.security_notifications_sent,
            'batch_count': self.stats.batch_count,
            'last_batch_sent': self.stats.last_batch_sent.isoformat() if self.stats.last_batch_sent else None,
            'queue_size': len(self.event_queue),
            'max_queue_size': self.max_queue_size,
            'batch_size': self.batch_size,
            'success_rate': (self.stats.events_sent / max(self.stats.events_collected, 1)) * 100,
            'acknowledgment_rate': (self.stats.alerts_acknowledged / max(self.stats.alerts_received, 1)) * 100
        }
        
        # Add security notification stats
        if self.security_notifier:
            base_stats['security_notifier_stats'] = self.security_notifier.get_security_stats()
        
        # Add communication info
        if self.communication:
            base_stats['communication_info'] = {
                'server_host': self.communication.server_host,
                'server_port': self.communication.server_port,
                'agent_id': getattr(self.communication, 'agent_id', None),
                'alert_acknowledgment_enabled': True
            }
        
        return base_stats