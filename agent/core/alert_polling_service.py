"""
Alert Polling Service - Nhận dữ liệu từ server bằng polling
Không ảnh hưởng đến các chức năng khác của agent
"""

import asyncio
import logging
import time
import ctypes
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

# Sửa circular import
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .communication import ServerCommunication

from ..utils.security_notifications import SimpleRuleBasedAlertNotifier

logger = logging.getLogger('alert_polling')

@dataclass
class AlertPollingStats:
    """Thống kê polling alerts"""
    polls_performed: int = 0
    alerts_received: int = 0
    alerts_displayed: int = 0
    actions_executed: int = 0
    last_poll_time: Optional[datetime] = None
    last_alert_time: Optional[datetime] = None
    consecutive_failures: int = 0
    total_polling_time: float = 0.0

class AlertPollingService:
    """Service để polling alerts từ server"""
    
    def __init__(self, communication: 'ServerCommunication', config_manager=None):
        self.communication = communication
        self.config_manager = config_manager
        self.agent_id = None
        
        # Polling configuration
        self.polling_interval = 2  # seconds
        self.max_consecutive_failures = 5
        self.is_running = False
        self.is_paused = False
        
        # Security notifier để hiển thị alerts
        self.security_notifier = SimpleRuleBasedAlertNotifier(config_manager)
        
        # Statistics
        self.stats = AlertPollingStats()
        
        # Alert deduplication
        self.recent_alerts = {}  # alert_id -> timestamp
        self.alert_cooldown = 60  # seconds
        
        self.agent_start_time = datetime.now()  # Thời điểm agent khởi động
        
        self.logger = logging.getLogger(__name__)
        
        logger.info("📡 Alert Polling Service initialized")
    
    def set_agent_id(self, agent_id: str):
        """Set agent ID cho polling service"""
        self.agent_id = agent_id
        self.security_notifier.set_communication(self.communication)
        logger.info(f"🎯 Alert Polling Service - Agent ID set: {agent_id}")
    
    async def start(self):
        """Bắt đầu polling service"""
        if self.is_running:
            logger.warning("⚠️ Alert Polling Service already running")
            return
        
        self.is_running = True
        self.is_paused = False
        logger.info("🚀 Starting Alert Polling Service")
        
        # Bắt đầu polling loop
        asyncio.create_task(self._polling_loop())
    
    async def stop(self):
        """Dừng polling service"""
        self.is_running = False
        logger.info("🛑 Alert Polling Service stopped")
    
    async def pause(self):
        """Tạm dừng polling"""
        self.is_paused = True
        logger.info("⏸️ Alert Polling Service paused")
    
    async def resume(self):
        """Tiếp tục polling"""
        self.is_paused = False
        logger.info("▶️ Alert Polling Service resumed")
    
    async def _polling_loop(self):
        """Main polling loop"""
        while self.is_running:
            try:
                if not self.is_paused and self.agent_id:
                    await self._poll_alerts()
                
                # Chờ đến lần polling tiếp theo
                await asyncio.sleep(self.polling_interval)
                
            except Exception as e:
                logger.error(f"❌ Polling loop error: {e}")
                self.stats.consecutive_failures += 1
                
                # Nếu có quá nhiều lỗi liên tiếp, tăng thời gian chờ
                if self.stats.consecutive_failures >= self.max_consecutive_failures:
                    logger.warning(f"⚠️ Too many consecutive failures ({self.stats.consecutive_failures}), increasing polling interval")
                    await asyncio.sleep(self.polling_interval * 2)
                else:
                    await asyncio.sleep(self.polling_interval)
    
    async def _poll_alerts(self):
        """Poll alerts từ server"""
        start_time = time.time()
        
        try:
            if not self.communication or not self.communication.is_connected():
                logger.debug("📡 Server not connected, skipping poll")
                return
            
            # Kiểm tra agent_id trước khi gọi API
            if not self.agent_id:
                logger.debug("📡 Agent ID not set, skipping poll")
                return
            
            # Lấy pending alerts từ server
            response = await self.communication.get_pending_alerts(self.agent_id)
            
            if response and response.get('alerts'):
                alerts = response['alerts']
                self.stats.alerts_received += len(alerts)
                self.stats.last_alert_time = datetime.now()
                
                logger.info(f"📥 Polled {len(alerts)} alerts from server")
                logger.debug(f"📋 Response data: {response}")
                
                # Xử lý từng alert
                for alert_data in alerts:
                    logger.debug(f"📋 Processing alert: {alert_data.get('alert_id', 'unknown')} - {alert_data.get('title', 'Unknown')}")
                    await self._process_alert(alert_data)
            else:
                logger.debug("📭 No pending alerts from server")
                if response:
                    logger.debug(f"📋 Response structure: {list(response.keys()) if isinstance(response, dict) else 'Not a dict'}")
            
            # Reset consecutive failures nếu thành công
            self.stats.consecutive_failures = 0
            self.stats.polls_performed += 1
            self.stats.last_poll_time = datetime.now()
            
        except Exception as e:
            logger.error(f"❌ Polling failed: {e}")
            self.stats.consecutive_failures += 1
        
        finally:
            self.stats.total_polling_time += time.time() - start_time
    
    async def _process_alert(self, alert_data: Dict[str, Any]):
        """
        Nhận alert từ server: hiển thị từng cảnh báo trong alerts_generated (popup góc phải màn hình)
        và thực hiện action nếu có.
        """
        try:
            # Lọc chỉ hiển thị alert mới sau khi agent khởi động
            alert_time_str = alert_data.get('first_detected') or alert_data.get('timestamp')
            alert_time = None
            if alert_time_str:
                try:
                    alert_time = datetime.fromisoformat(alert_time_str)
                except Exception:
                    alert_time = None
            if alert_time and alert_time < self.agent_start_time:
                logger.debug(f"⏩ Alert {alert_data.get('alert_id')} is old (before agent start), skipping")
                return
            # Kiểm tra deduplication
            alert_id = alert_data.get('alert_id')
            if alert_id and self._is_alert_in_cooldown(alert_id):
                logger.debug(f"⏰ Alert {alert_id} in cooldown, skipping")
                return
            # 1. Hiển thị từng cảnh báo trong alerts_generated
            alerts = alert_data.get('alerts_generated') or []
            if alerts:
                for alert in alerts:
                    await self.security_notifier.process_server_alerts({'alerts': [alert]})
                    self.stats.alerts_displayed += 1
            else:
                # Nếu không có alerts_generated, fallback về alert tổng thể
                alert = self._convert_notification_to_alert(alert_data)
                if alert:
                    await self.security_notifier.process_server_alerts({'alerts': [alert]})
                    self.stats.alerts_displayed += 1
            # 2. Thực hiện action nếu có
            await self._handle_alert_action(alert_data)
            # Mark alert as processed
            if alert_id:
                self.recent_alerts[alert_id] = time.time()
        except Exception as e:
            logger.error(f"❌ Failed to process alert: {e}")
    
    async def _handle_alert_notification(self, alert_data: Dict[str, Any]):
        """Xử lý thông báo alert"""
        try:
            # Convert alert data to notification format
            alert = self._convert_notification_to_alert(alert_data)
            if alert:
                await self.security_notifier.process_server_alerts({'alerts': [alert]})
                self.stats.alerts_displayed += 1
        except Exception as e:
            logger.error(f"❌ Failed to handle alert notification: {e}")
    
    async def _handle_alert_action(self, alert_data: Dict[str, Any]):
        """Xử lý action từ alert"""
        try:
            action = alert_data.get('action')
            if action:
                success = await self._execute_action(action)
                if success:
                    self.stats.actions_executed += 1
        except Exception as e:
            logger.error(f"❌ Failed to handle alert action: {e}")
    
    def _convert_notification_to_alert(self, alert_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Convert alert data to notification format"""
        try:
            alert = {
                'id': alert_data.get('alert_id'),
                'title': alert_data.get('title', 'Unknown Alert'),
                'description': alert_data.get('description'),
                'severity': alert_data.get('severity', 'Medium'),
                'risk_score': alert_data.get('risk_score', 50),
                'detection_method': alert_data.get('detection_method', 'Unknown'),
                'first_detected': alert_data.get('first_detected'),
                'mitre_tactic': alert_data.get('mitre_tactic'),
                'mitre_technique': alert_data.get('mitre_technique'),
                'event_count': alert_data.get('event_count', 1),
                'age_minutes': alert_data.get('age_minutes', 0),
                'status': alert_data.get('status', 'Open'),
                'event_id': alert_data.get('event_id'),
                'rule_id': alert_data.get('rule_id'),
                'threat_id': alert_data.get('threat_id'),
                'server_generated': alert_data.get('server_generated', True),
                'rule_violation': alert_data.get('rule_violation', True),
                # Additional metadata
                'polling_source': True,
                'status': alert_data.get('status', 'Open')
            }
            
            return alert
            
        except Exception as e:
            logger.error(f"❌ Failed to convert alert data to alert: {e}")
            return None
    
    async def _execute_action(self, action: Dict[str, Any]) -> bool:
        """Thực thi action từ server"""
        try:
            action_type = action.get('action_type')
            
            if action_type == 'kill_process':
                return await self._execute_kill_process(action)
            elif action_type == 'block_network':
                return await self._execute_block_network(action)
            elif action_type == 'quarantine_file':
                return await self._execute_quarantine_file(action)
            else:
                logger.warning(f"⚠️ Unknown action type: {action_type}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Action execution failed: {e}")
            return False
    
    async def _execute_kill_process(self, action: Dict[str, Any]) -> bool:
        """Thực thi kill process bằng taskkill hoặc psutil, log rõ nguồn gốc (AI/rule) nếu có."""
        try:
            pid = action.get('process_id') or action.get('target_pid')
            process_name = action.get('process_name', 'Unknown')
            source = action.get('source', 'Unknown')  # 'AI', 'Rule', ...
            if not pid:
                logger.error("❌ No PID provided for kill_process")
                return False
            # Log nguồn gốc action nếu có
            logger.info(f"[AGENT] Nhận lệnh kill_process từ nguồn: {source}. PID={pid}, Name={process_name}")
            import psutil
            try:
                p = psutil.Process(int(pid))
                p.kill()
                logger.info(f"✅ Đã kill process {process_name} (PID: {pid}) thành công (psutil)")
                return True
            except Exception as e:
                logger.warning(f"psutil kill failed: {e}, fallback to taskkill")
                import subprocess
                cmd = ["taskkill", "/PID", str(pid), "/F"]
                logger.info(f"[AGENT] Executing: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    message = f"✅ Đã kill process {process_name} (PID: {pid}) thành công (taskkill)"
                    logger.info(f"✅ {message}")
                    return True
                else:
                    error_message = f"❌ Không thể kill process {process_name} (PID: {pid}): {result.stderr}"
                    logger.error(f"❌ {error_message}")
                    return False
        except Exception as e:
            error_message = f"❌ Lỗi khi kill process {process_name} (PID: {pid}): {e}"
            logger.error(f"❌ {error_message}")
            return False
    
    async def _execute_block_network(self, action: Dict[str, Any]) -> bool:
        """Thực thi block network bằng Windows Firewall (netsh), kiểm tra trùng rule trước khi tạo"""
        try:
            target_ip = action.get('target_ip') or action.get('ip')
            target_port = action.get('target_port') or action.get('port')
            if not target_ip:
                logger.error("❌ No IP provided for block_network")
                try:
                    ctypes.windll.user32.MessageBoxW(0, "No IP provided for block_network", "Agent thông báo", 1)
                except Exception as e:
                    logger.warning(f"⚠️ Failed to show popup: {e}")
                return False
            rule_name = f"Block_{target_ip}_{target_port or 'all'}"
            # Kiểm tra rule đã tồn tại chưa
            check_cmd = [
                "netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"
            ]
            check_result = subprocess.run(check_cmd, capture_output=True, text=True)
            if "No rules match the specified criteria" not in check_result.stdout:
                logger.info(f"⚠️ Rule {rule_name} đã tồn tại, không tạo lại.")
                try:
                    ctypes.windll.user32.MessageBoxW(0, f"Rule {rule_name} đã tồn tại, không tạo lại.", "Agent thông báo", 1)
                except Exception as e:
                    logger.warning(f"⚠️ Failed to show popup: {e}")
                return True  # Đã tồn tại, coi như thành công
            if target_port:
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=out",
                    "action=block",
                    f"remoteip={target_ip}",
                    "protocol=TCP",
                    f"remoteport={target_port}"
                ]
            else:
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=out",
                    "action=block",
                    f"remoteip={target_ip}"
                ]
            logger.info(f"[AGENT] Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                message = f"Đã chặn kết nối mạng đến IP: {target_ip} port: {target_port or 'all'}"
                logger.info(f"✅ {message}")
                try:
                    ctypes.windll.user32.MessageBoxW(0, message, "Agent thông báo", 1)
                except Exception as e:
                    logger.warning(f"⚠️ Failed to show popup: {e}")
                return True
            else:
                error_message = f"Không thể chặn kết nối mạng đến IP {target_ip} port {target_port or 'all'}: {result.stderr}"
                logger.error(f"❌ {error_message}")
                try:
                    ctypes.windll.user32.MessageBoxW(0, error_message, "Agent thông báo", 1)
                except Exception as e:
                    logger.warning(f"⚠️ Failed to show error popup: {e}")
                return False
        except Exception as e:
            error_message = f"Không thể chặn kết nối mạng đến IP {target_ip}: {e}"
            logger.error(f"❌ {error_message}")
            try:
                ctypes.windll.user32.MessageBoxW(0, error_message, "Agent thông báo", 1)
            except Exception as popup_error:
                logger.warning(f"⚠️ Failed to show error popup: {popup_error}")
            return False
    
    async def _execute_quarantine_file(self, action: Dict[str, Any]) -> bool:
        """Thực thi quarantine file: backup_file true thì vào thùng rác, false thì xóa luôn"""
        try:
            import os
            try:
                from send2trash import send2trash
                SEND2TRASH_AVAILABLE = True
            except ImportError:
                SEND2TRASH_AVAILABLE = False

            file_path = action.get('file_path')
            backup = action.get('backup_file', False)
            if not file_path:
                logger.error("❌ No file path provided for quarantine_file")
                return False

            if not os.path.exists(file_path):
                logger.error(f"❌ File does not exist: {file_path}")
                return False

            if backup:
                if SEND2TRASH_AVAILABLE:
                    try:
                        send2trash(file_path)
                        logger.info(f"✅ File sent to Windows Recycle Bin: {file_path}")
                    except Exception as e:
                        logger.error(f"❌ Failed to send file to Recycle Bin: {e}")
                        return False
                else:
                    logger.error("❌ send2trash library not available. Cannot move file to Recycle Bin.")
                    return False
            else:
                try:
                    os.remove(file_path)
                    logger.info(f"🗑️ File deleted permanently: {file_path}")
                except Exception as e:
                    logger.error(f"❌ Failed to delete file: {e}")
                    return False

            return True
        except Exception as e:
            logger.error(f"❌ Error executing quarantine file action: {e}")
            return False
    
    def _is_alert_in_cooldown(self, alert_id: str) -> bool:
        """Kiểm tra alert có trong cooldown không"""
        if alert_id not in self.recent_alerts:
            return False
        
        time_since = time.time() - self.recent_alerts[alert_id]
        return time_since < self.alert_cooldown
    
    def get_stats(self) -> Dict[str, Any]:
        """Lấy thống kê polling"""
        try:
            total_time = max(self.stats.total_polling_time, 0.001)
            total_polls = max(self.stats.polls_performed, 1)
            
            return {
                'polls_performed': self.stats.polls_performed,
                'alerts_received': self.stats.alerts_received,
                'alerts_displayed': self.stats.alerts_displayed,
                'actions_executed': self.stats.actions_executed,
                'consecutive_failures': self.stats.consecutive_failures,
                'last_poll_time': self.stats.last_poll_time.isoformat() if self.stats.last_poll_time else None,
                'last_alert_time': self.stats.last_alert_time.isoformat() if self.stats.last_alert_time else None,
                'average_polling_time_ms': round((total_time / total_polls) * 1000, 2),
                'success_rate': round(
                    ((total_polls - self.stats.consecutive_failures) / total_polls) * 100, 2
                ),
                'is_running': self.is_running,
                'is_paused': self.is_paused,
                'polling_interval': self.polling_interval
            }
        except Exception as e:
            logger.error(f"Stats calculation failed: {e}")
            return {
                'polls_performed': 0,
                'alerts_received': 0,
                'alerts_displayed': 0,
                'actions_executed': 0,
                'is_running': self.is_running,
                'is_paused': self.is_paused
            } 