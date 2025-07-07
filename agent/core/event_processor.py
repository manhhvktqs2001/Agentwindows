# agent/core/event_processor.py - FIXED RULE-BASED VERSION
"""
Event Processor - FIXED TO DISPLAY ALERTS FROM SERVER AND LOCAL RULES
Hiển thị cảnh báo khi server hoặc local rules phát hiện vi phạm
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
    local_rules_triggered: int = 0
    server_rules_triggered: int = 0
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
    """Event Processor - FIXED TO DISPLAY ALL RULE-BASED ALERTS"""
    
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
        
        # FIXED: Enhanced Rule-Based Alert Notification System
        self.security_notifier = SimpleRuleBasedAlertNotifier(config_manager)
        self.security_notifier.set_communication(communication)
        # CHỈ HIỂN THỊ CẢNH BÁO TỪ SERVER
        self.security_notifier.enabled = True
        self.security_notifier.show_server_rules = True
        self.security_notifier.show_local_rules = False
        self.security_notifier.show_risk_based_alerts = False
        
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
        
        # FIXED: Enhanced rule processing
        self.rule_processing_enabled = True
        self.local_rule_processing = True
        self.server_rule_processing = True
        
        self._safe_log("info", "🚀 FIXED Event Processor initialized - ENHANCED RULE-BASED ALERTS")
    
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
            self._safe_log("info", "🚀 FIXED Event Processor started - ENHANCED RULE PROCESSING")
            
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
            self._safe_log("info", "🛑 Stopping FIXED Event Processor...")
            self.is_running = False
            
            # Cancel retry task
            if self._retry_task:
                self._retry_task.cancel()
            
            # Try to send any remaining failed events
            await self._flush_failed_events()
            
            await asyncio.sleep(0.5)
            
            self._safe_log("info", "✅ FIXED Event Processor stopped gracefully")
            
        except Exception as e:
            self._safe_log("error", f"❌ Event processor stop error: {e}")
    
    def set_agent_id(self, agent_id: str):
        """Set agent ID for communication"""
        self.agent_id = agent_id
        self._safe_log("info", f"Agent ID set: {agent_id}")
    
    async def add_event(self, event_data: EventData):
        """
        FIXED: GỬI EVENT VÀ XỬ LÝ RULE-BASED ALERTS
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
            # FIXED: Always try to send event and process rules
            if self.agent_id and self.communication:
                # Gửi event lên server và nhận response (có thể chứa rule violations)
                success, response, error = await self.communication.submit_event(event_data)
                # Thêm debug log chi tiết response server trả về
                self._safe_log("warning", f"[DEBUG] Server response for event: {event_data.event_type} - {event_data.process_name} => {response}")
                if success and response:
                    # FIXED: Process response for rule violations (server OR local)
                    await self._process_enhanced_server_response(response, event_data)
                    self.stats.events_sent += 1
                    self.stats.last_event_sent = datetime.now()
                    self._consecutive_failures = 0
                    self._last_successful_send = time.time()
                else:
                    # FIXED: Event sending failed, add to retry queue
                    self._failed_events_queue.append({
                        'event': event_data,
                        'timestamp': time.time(),
                        'retry_count': 0
                    })
                    self.stats.events_failed += 1
                    self._consecutive_failures += 1
            else:
                # FIXED: No communication available
                self.stats.events_failed += 1
            
        except Exception as e:
            # FIXED: Handle exceptions gracefully
            self.stats.events_failed += 1
            self._safe_log("error", f"❌ Event processing error: {e}")
    
    async def _process_enhanced_server_response(self, server_response: Dict[str, Any], original_event: EventData):
        """Process enhanced server response (alerts + action)"""
        try:
            # IN CHI TIẾT JSON DATA NHẬN TỪ SERVER
            import json
            self._safe_log("warning", "🚨 ========== JSON DATA RECEIVED FROM SERVER ==========")
            self._safe_log("warning", f"📦 Agent ID: {original_event.agent_id}")
            self._safe_log("warning", f"📋 Event Type: {original_event.event_type}")
            self._safe_log("warning", f"🔧 Event Action: {original_event.event_action}")
            self._safe_log("warning", f"📝 Process Name: {original_event.process_name}")
            
            # In response keys
            response_keys = list(server_response.keys())
            self._safe_log("warning", f"📋 Response Keys: {response_keys}")
            
            # In threat detection info
            threat_detected = server_response.get('threat_detected', False)
            risk_score = server_response.get('risk_score', 0)
            self._safe_log("warning", f"🚨 THREAT DETECTED: {threat_detected}")
            self._safe_log("warning", f"📈 Risk Score: {risk_score}")
            
            # In alerts info
            alerts_generated = server_response.get('alerts_generated', [])
            if alerts_generated:
                self._safe_log("warning", f"📊 Alerts generated: {alerts_generated}")
            
            # In action info
            if 'type' in server_response and server_response['type'] == 'alert_and_action':
                self._safe_log("warning", "⚡ ALERT AND ACTION MODE DETECTED")
                if 'action' in server_response:
                    action_data = server_response['action']
                    self._safe_log("warning", "⚡ ACTION DATA RECEIVED:")
                    self._safe_log("warning", f"   🔧 Action Type: {action_data.get('action_type')}")
                    self._safe_log("warning", f"   📋 Event Type: {action_data.get('event_type')}")
                    self._safe_log("warning", f"   ⚙️ Config: {action_data.get('config')}")
                    
                    if action_data.get('action_type') == 'kill_process':
                        self._safe_log("warning", f"   🎯 Target PID: {action_data.get('target_pid')}")
                        self._safe_log("warning", f"   📝 Process Name: {action_data.get('process_name')}")
                        self._safe_log("warning", f"   💻 Command Line: {action_data.get('command_line')}")
            
            # In raw JSON
            json_str = json.dumps(server_response, indent=2, default=str)
            self._safe_log("warning", "📄 RAW JSON DATA RECEIVED:")
            self._safe_log("warning", json_str)
            self._safe_log("warning", "🚨 ==============================================")
            
            # Xử lý cảnh báo
            if alerts_generated:
                self.stats.rule_violations_received += len(alerts_generated)
                self.stats.last_rule_violation = datetime.now()
                notification_response = {
                    'alerts_generated': alerts_generated
                }
                await self.security_notifier.process_server_alerts(
                    notification_response, 
                    [original_event]
                )
                self.stats.rule_alerts_displayed += len(alerts_generated)
                total_local = sum(1 for alert in alerts_generated if alert.get('local_rule'))
                total_server = len(alerts_generated) - total_local
                self._safe_log("warning", f"🔔 DISPLAYED {len(alerts_generated)} ALERTS:")
                if total_local > 0:
                    self._safe_log("warning", f"   🔍 Local Rules: {total_local}")
                if total_server > 0:
                    self._safe_log("warning", f"   🚨 Server Rules: {total_server}")
            else:
                self._safe_log("debug", f"✅ No rule violations for {original_event.event_type} - {original_event.process_name}")
            
            # NEW: Handle action from server (format mới)
            if 'type' in server_response and server_response['type'] == 'alert_and_action' and 'action' in server_response:
                self._safe_log("warning", f"⚡ RECEIVED ACTION: {server_response['action']}")
                self.execute_action(server_response['action'], original_event)
            elif action_command:
                self._safe_log("warning", f"⚡ RECEIVED ACTION COMMAND: {action_command}")
                self.execute_action_command(action_command, original_event)
        except Exception as e:
            self._safe_log("error", f"❌ Enhanced server response processing failed: {e}")

    def execute_action(self, action: dict, original_event: EventData = None):
        """Thực thi action từ server (format mới)"""
        try:
            action_type = action.get("action_type")
            event_type = action.get("event_type")
            config = action.get("config", {})
            if action_type == "kill_process":
                pid = action.get("target_pid")
                if pid:
                    self.kill_process(pid, config.get("force_kill", False))
                else:
                    self._safe_log("error", "[ERROR] Không có PID để kill process.")
            elif action_type == "block_network":
                ip = action.get("target_ip")
                if ip:
                    self.block_network(ip, config)
                else:
                    self._safe_log("error", "[ERROR] Không có IP để block.")
            elif action_type == "quarantine_file":
                file_path = action.get("file_path")
                if file_path:
                    self.quarantine_file(file_path, config)
                else:
                    self._safe_log("error", "[ERROR] Không có file_path để quarantine.")
            else:
                self._safe_log("warning", f"[WARN] Không nhận diện được action: {action_type} cho event_type: {event_type}")
        except Exception as e:
            self._safe_log("error", f"❌ Failed to execute action: {e}")

    def kill_process(self, process_id, force=False):
        """Kill a process by PID (Windows)"""
        import psutil
        try:
            p = psutil.Process(int(process_id))
            if force:
                p.kill()
            else:
                p.terminate()
            self._safe_log("warning", f"✅ Process {process_id} killed (force={force})")
        except Exception as e:
            self._safe_log("error", f"❌ Failed to kill process {process_id}: {e}")

    def block_network(self, ip, config=None):
        # TODO: Thực thi block network trên Windows
        self._safe_log("warning", f"[ACTION] Blocked network IP: {ip} with config: {config}")

    def quarantine_file(self, file_path, config=None):
        # TODO: Thực thi quarantine file trên Windows
        self._safe_log("warning", f"[ACTION] Quarantined file: {file_path} with config: {config}")

    def execute_action_command(self, action_command: dict, original_event: EventData):
        """Thực thi action từ server (ví dụ: Kill Process)"""
        try:
            action_type = action_command.get("type")
            config = action_command.get("config", {})
            target = action_command.get("target")
            if action_type == "Kill Process" and target:
                force = config.get("force_kill", False)
                self._safe_log("warning", f"⚡ Executing Kill Process: PID={target}, force={force}")
                self.kill_process(target, force)
            else:
                self._safe_log("warning", f"⚡ Unsupported or missing action/target: {action_command}")
        except Exception as e:
            self._safe_log("error", f"❌ Failed to execute action command: {e}")
    
    def _is_valid_alert(self, alert: Dict[str, Any]) -> bool:
        """FIXED: Check if alert is valid for display"""
        try:
            # Must have basic alert structure
            if not isinstance(alert, dict):
                return False
            
            # Must have at least an ID or rule information
            has_id = alert.get('id') or alert.get('alert_id')
            has_rule = alert.get('rule_id') or alert.get('rule_name') or alert.get('rule_triggered')
            has_title = alert.get('title')
            has_description = alert.get('description')
            
            # FIXED: Accept alerts with rule info OR basic alert structure
            return bool(has_id or has_rule or has_title or has_description)
            
        except Exception as e:
            self._safe_log("error", f"❌ Error validating alert: {e}")
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
        """Retry failed events - ENHANCED"""
        retry_interval = 5  # Start with 5 seconds
        max_retry_interval = 60  # Max 60 seconds
        consecutive_failures = 0
        was_offline = False  # Track if we were offline
        
        while self.is_running:
            try:
                if not self._failed_events_queue:
                    await asyncio.sleep(1)
                    continue
                
                # Check if server is available
                if not self.communication or not self.communication.is_connected():
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
                
                # Process retry queue
                failed_events = list(self._failed_events_queue)
                self._failed_events_queue.clear()
                
                success_count = 0
                for failed_event in failed_events:
                    if not self.is_running:
                        break
                    
                    event_data = failed_event['event']
                    retry_count = failed_event['retry_count']
                    
                    if retry_count >= 3:  # Max 3 retries
                        continue
                    
                    # Try to send again
                    try:
                        success, response, error = await self.communication.submit_event(event_data)
                        
                        if success:
                            success_count += 1
                            # FIXED: Process response for retried events too
                            if response:
                                await self._process_enhanced_server_response(response, event_data)
                        else:
                            # Re-queue for retry
                            failed_event['retry_count'] = retry_count + 1
                            self._failed_events_queue.append(failed_event)
                    except Exception as e:
                        # Re-queue for retry
                        failed_event['retry_count'] = retry_count + 1
                        self._failed_events_queue.append(failed_event)
                
                # Only log if we successfully sent some events
                if success_count > 0:
                    self._safe_log("info", f"✅ Resumed: {success_count} events sent")
                
                await asyncio.sleep(retry_interval)
                
            except Exception as e:
                await asyncio.sleep(5)
    
    async def _flush_failed_events(self):
        """Try to send all remaining failed events, keep those not sent for next retry"""
        try:
            if self._failed_events_queue:
                self._safe_log("info", f"🔄 Flushing {len(self._failed_events_queue)} remaining events...")
                still_failed = deque()
                while self._failed_events_queue:
                    event_info = self._failed_events_queue.popleft()
                    event_data = event_info['event']
                    try:
                        # Nếu mất kết nối, dừng flush và giữ lại event
                        if not self.communication or not self.communication.is_connected():
                            still_failed.append(event_info)
                            self._safe_log("warning", "❌ Lost connection during flush, will retry later")
                            break
                        success, response, error = await self.communication.submit_event(event_data)
                        if success and response:
                            await self._process_enhanced_server_response(response, event_data)
                        else:
                            still_failed.append(event_info)
                    except Exception as e:
                        still_failed.append(event_info)
                # Đưa lại các event chưa gửi được vào queue
                self._failed_events_queue = still_failed
        except Exception as e:
            self._safe_log("error", f"❌ Flush failed events error: {e}")
    
    async def _stats_logging_loop(self):
        """Statistics logging loop - ENHANCED"""
        try:
            while self.is_running:
                try:
                    # Log statistics every 60 seconds
                    current_time = time.time()
                    if int(current_time) % 60 == 0:
                        stats = self.get_stats()
                        
                        processing_rate = stats.get('processing_rate', 0)
                        events_sent = stats.get('events_sent', 0)
                        events_failed = stats.get('events_failed', 0)
                        success_rate = stats.get('success_rate', 0)
                        
                        # FIXED: Enhanced logging with rule stats
                        local_rules = stats.get('local_rules_triggered', 0)
                        server_rules = stats.get('server_rules_triggered', 0)
                        total_alerts = stats.get('rule_alerts_displayed', 0)
                        
                        if processing_rate < 0.01 and events_sent == 0:
                            self._safe_log("warning", f"⚠️ Low processing rate: {processing_rate:.2f} events/sec - No events sent")
                        else:
                            self._safe_log("info", 
                                f"📊 ENHANCED Event Processor Stats - "
                                f"Sent: {events_sent}, "
                                f"Failed: {events_failed}, "
                                f"Success: {success_rate:.1f}%, "
                                f"Rate: {processing_rate:.2f}/s, "
                                f"Alerts: {total_alerts} "
                                f"(Local: {local_rules}, Server: {server_rules})")
                    
                    await asyncio.sleep(30)  # Check every 30 seconds
                    
                except Exception as e:
                    self._safe_log("error", f"Stats logging error: {e}")
                    await asyncio.sleep(30)
                    
        except Exception as e:
            self._safe_log("error", f"Stats logging loop failed: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get enhanced event processor statistics"""
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
                'local_rules_triggered': self.stats.local_rules_triggered,
                'server_rules_triggered': self.stats.server_rules_triggered,
                'last_event_sent': self.stats.last_event_sent.isoformat() if self.stats.last_event_sent else None,
                'last_rule_violation': self.stats.last_rule_violation.isoformat() if self.stats.last_rule_violation else None,
                'processing_rate': processing_rate,
                'success_rate': success_rate,
                'uptime': uptime,
                'send_errors': self._send_errors,
                'consecutive_failures': self._consecutive_failures,
                'time_since_last_send': current_time - self._last_successful_send,
                'failed_queue_size': len(self._failed_events_queue),
                'enhanced_rule_processing': True,
                'local_and_server_rules': True
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
        """Get enhanced performance metrics"""
        total_attempts = self.stats.events_sent + self.stats.events_failed
        success_rate = (self.stats.events_sent / total_attempts) if total_attempts > 0 else 0
        
        return {
            'queue_utilization': len(self._failed_events_queue) / 1000,
            'processing_rate': self.stats.processing_rate,
            'immediate_processing': self.immediate_send,
            'enhanced_rule_processing': True,
            'local_and_server_rules': True,
            'success_rate': success_rate,
            'error_rate': self._send_errors / max(total_attempts, 1),
            'rule_violations_received': self.stats.rule_violations_received,
            'rule_alerts_displayed': self.stats.rule_alerts_displayed,
            'local_rules_triggered': self.stats.local_rules_triggered,
            'server_rules_triggered': self.stats.server_rules_triggered
        }