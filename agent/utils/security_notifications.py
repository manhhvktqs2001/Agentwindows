# agent/utils/security_notifications.py
"""
Security Alert Notification System
Hiển thị cảnh báo bảo mật ở góc phải màn hình khi server phát hiện threats
"""

import logging
import threading
import time
from datetime import datetime
from typing import Dict, Any, List
import json

# Import plyer for notifications
try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False

# Fallback imports
try:
    import ctypes
    from ctypes import wintypes
    CTYPES_AVAILABLE = True
except ImportError:
    CTYPES_AVAILABLE = False


class SecurityAlertNotifier:
    """Chuyên xử lý thông báo cảnh báo bảo mật từ detection rules"""
    
    def __init__(self, config_manager=None):
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager
        
        # Security notification settings
        self.enabled = True
        self.show_on_screen = True
        self.play_sound = True
        self.auto_dismiss_timeout = 30  # seconds
        
        # Alert categorization
        self.critical_rules = [
            'Mimikatz Credential Dumping',
            'Mass File Encryption Detection',
            'Ransomware Activity'
        ]
        
        self.high_priority_rules = [
            'Suspicious PowerShell Encoded',
            'Linux Reverse Shell Detection',
            'Registry Run Key Persistence'
        ]
        
        # Notification tracking
        self.active_alerts = []
        self.alert_history = []
        
        # Rate limiting cho security alerts
        self.max_security_alerts_per_minute = 10
        self.recent_alerts = []
        
        self.logger.info("🔒 Security Alert Notifier initialized")
    
    def process_server_alerts(self, server_response: Dict[str, Any], related_events: List = None):
        """Xử lý alerts từ server response khi gửi events"""
        try:
            # Kiểm tra xem có alerts trong response không
            alerts = []
            
            if 'alerts_generated' in server_response:
                alerts = server_response['alerts_generated']
            elif 'alerts' in server_response:
                alerts = server_response['alerts']
            
            if not alerts:
                return
            
            self.logger.warning(f"🚨 Received {len(alerts)} security alerts from server")
            
            for alert in alerts:
                self._process_single_alert(alert, related_events)
                
        except Exception as e:
            self.logger.error(f"❌ Error processing server alerts: {e}")
    
    def _process_single_alert(self, alert: Dict[str, Any], related_events: List = None):
        """Xử lý một alert riêng lẻ"""
        try:
            # Parse alert information
            alert_info = {
                'alert_id': alert.get('id', f"alert_{int(time.time())}"),
                'rule_name': alert.get('rule_name', 'Unknown Rule'),
                'alert_type': alert.get('alert_type', 'Security Alert'),
                'title': alert.get('title', alert.get('alert_title', 'Security Threat Detected')),
                'description': alert.get('description', alert.get('alert_description', 'Suspicious activity detected')),
                'severity': alert.get('severity', alert.get('alert_severity', 'MEDIUM')),
                'risk_score': alert.get('risk_score', 50),
                'timestamp': alert.get('timestamp', datetime.now().isoformat()),
                'mitre_tactic': alert.get('mitre_tactic'),
                'mitre_technique': alert.get('mitre_technique'),
                'detection_method': alert.get('detection_method', 'Rule-based'),
                'event_id': alert.get('event_id'),
                'related_event': None
            }
            
            # Tìm event liên quan
            if related_events and alert_info['event_id'] is not None:
                try:
                    event_index = int(alert_info['event_id'])
                    if 0 <= event_index < len(related_events):
                        alert_info['related_event'] = related_events[event_index]
                except (ValueError, IndexError):
                    pass
            
            # Xác định mức độ ưu tiên
            priority = self._determine_alert_priority(alert_info)
            alert_info['priority'] = priority
            
            # Rate limiting check
            if not self._check_security_rate_limit():
                self.logger.warning("⚠️ Security alert rate limit exceeded")
                return
            
            # Log alert details
            self.logger.critical(
                f"🚨 SECURITY ALERT: {alert_info['rule_name']} | "
                f"Severity: {alert_info['severity']} | "
                f"Risk: {alert_info['risk_score']}/100"
            )
            
            # Show notification
            self._show_security_notification(alert_info)
            
            # Track alert
            self._track_security_alert(alert_info)
            
        except Exception as e:
            self.logger.error(f"❌ Error processing single alert: {e}")
    
    def _determine_alert_priority(self, alert_info: Dict[str, Any]) -> str:
        """Xác định mức độ ưu tiên của alert"""
        rule_name = alert_info.get('rule_name', '')
        severity = alert_info.get('severity', 'MEDIUM').upper()
        risk_score = alert_info.get('risk_score', 50)
        
        # Critical priority
        if (rule_name in self.critical_rules or 
            severity == 'CRITICAL' or 
            risk_score >= 90):
            return 'CRITICAL'
        
        # High priority
        if (rule_name in self.high_priority_rules or 
            severity == 'HIGH' or 
            risk_score >= 70):
            return 'HIGH'
        
        # Medium priority
        if severity == 'MEDIUM' or risk_score >= 50:
            return 'MEDIUM'
        
        return 'LOW'
    
    def _show_security_notification(self, alert_info: Dict[str, Any]):
        """Hiển thị thông báo bảo mật ở góc phải màn hình"""
        try:
            # Prepare notification content
            title, message = self._prepare_security_notification_content(alert_info)
            
            # Determine notification duration based on priority
            timeout = self._get_notification_timeout(alert_info['priority'])
            
            if PLYER_AVAILABLE:
                self._show_plyer_security_notification(title, message, alert_info, timeout)
            elif CTYPES_AVAILABLE:
                self._show_messagebox_security_notification(title, message, alert_info)
            else:
                # Fallback to logging
                self.logger.critical(f"🚨 SECURITY ALERT: {title}\n{message}")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to show security notification: {e}")
    
    def _prepare_security_notification_content(self, alert_info: Dict[str, Any]):
        """Chuẩn bị nội dung thông báo bảo mật"""
        priority = alert_info['priority']
        rule_name = alert_info['rule_name']
        title_text = alert_info['title']
        description = alert_info['description']
        
        # Priority icons và prefixes
        priority_info = {
            'CRITICAL': ('🚨', 'CRITICAL THREAT'),
            'HIGH': ('⚠️', 'HIGH RISK DETECTED'),
            'MEDIUM': ('⚡', 'SECURITY ALERT'),
            'LOW': ('ℹ️', 'SECURITY NOTICE')
        }
        
        icon, prefix = priority_info.get(priority, ('⚠️', 'SECURITY ALERT'))
        
        # Create notification title
        title = f"{icon} {prefix}"
        
        # Create detailed message
        message_parts = [
            f"Rule: {rule_name}",
            f"Alert: {title_text}",
            f"Description: {description}"
        ]
        
        # Add event details if available
        if alert_info.get('related_event'):
            event = alert_info['related_event']
            if hasattr(event, 'process_name') and event.process_name:
                message_parts.append(f"Process: {event.process_name}")
            elif hasattr(event, 'file_name') and event.file_name:
                message_parts.append(f"File: {event.file_name}")
            elif hasattr(event, 'destination_ip') and event.destination_ip:
                message_parts.append(f"Connection: {event.destination_ip}")
        
        # Add MITRE information if available
        if alert_info.get('mitre_tactic'):
            message_parts.append(f"MITRE: {alert_info['mitre_tactic']}")
        
        # Add risk score
        message_parts.append(f"Risk Score: {alert_info['risk_score']}/100")
        
        message = "\n".join(message_parts)
        
        return title, message
    
    def _get_notification_timeout(self, priority: str) -> int:
        """Xác định thời gian hiển thị notification"""
        timeout_map = {
            'CRITICAL': 60,  # 1 minute for critical
            'HIGH': 30,      # 30 seconds for high
            'MEDIUM': 15,    # 15 seconds for medium
            'LOW': 10        # 10 seconds for low
        }
        return timeout_map.get(priority, 15)
    
    def _show_plyer_security_notification(self, title: str, message: str, alert_info: Dict[str, Any], timeout: int):
        """Hiển thị security notification bằng Plyer"""
        def show():
            try:
                notification.notify(
                    title=title,
                    message=message,
                    app_name="EDR Security Agent",
                    timeout=timeout,
                    toast=True
                )
                
                self.logger.info(f"🔔 Security notification displayed: {alert_info['rule_name']}")
                
                # Play sound for critical alerts
                if alert_info['priority'] == 'CRITICAL' and self.play_sound:
                    self._play_alert_sound()
                
            except Exception as e:
                self.logger.error(f"❌ Plyer security notification failed: {e}")
        
        # Run in background thread
        thread = threading.Thread(target=show, daemon=True)
        thread.start()
    
    def _show_messagebox_security_notification(self, title: str, message: str, alert_info: Dict[str, Any]):
        """Hiển thị security notification bằng MessageBox (fallback)"""
        def show():
            try:
                # MessageBox types
                MB_OK = 0x0
                MB_ICONERROR = 0x10
                MB_ICONWARNING = 0x30
                MB_TOPMOST = 0x40000
                MB_SYSTEMMODAL = 0x1000
                
                # Icon based on priority
                if alert_info['priority'] in ['CRITICAL', 'HIGH']:
                    icon = MB_ICONERROR
                else:
                    icon = MB_ICONWARNING
                
                # Show as topmost and system modal for critical alerts
                flags = MB_OK | icon | MB_TOPMOST
                if alert_info['priority'] == 'CRITICAL':
                    flags |= MB_SYSTEMMODAL
                
                ctypes.windll.user32.MessageBoxW(0, message, title, flags)
                
                self.logger.info(f"🔔 Security MessageBox displayed: {alert_info['rule_name']}")
                
            except Exception as e:
                self.logger.error(f"❌ MessageBox security notification failed: {e}")
        
        # Run in background thread
        thread = threading.Thread(target=show, daemon=True)
        thread.start()
    
    def _play_alert_sound(self):
        """Phát âm thanh cảnh báo cho critical alerts"""
        try:
            # Play Windows system sound
            ctypes.windll.user32.MessageBeep(0x10)  # MB_ICONHAND sound
        except Exception as e:
            self.logger.debug(f"Could not play alert sound: {e}")
    
    def _check_security_rate_limit(self) -> bool:
        """Kiểm tra rate limit cho security alerts"""
        current_time = time.time()
        
        # Remove alerts older than 1 minute
        self.recent_alerts = [
            t for t in self.recent_alerts 
            if current_time - t < 60
        ]
        
        return len(self.recent_alerts) < self.max_security_alerts_per_minute
    
    def _track_security_alert(self, alert_info: Dict[str, Any]):
        """Theo dõi security alert"""
        current_time = time.time()
        self.recent_alerts.append(current_time)
        
        # Add to history
        self.alert_history.append({
            'alert_id': alert_info['alert_id'],
            'rule_name': alert_info['rule_name'],
            'priority': alert_info['priority'],
            'timestamp': current_time,
            'notified': True
        })
        
        # Keep only recent history (last 100 alerts)
        if len(self.alert_history) > 100:
            self.alert_history = self.alert_history[-100:]
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Lấy thống kê security alerts"""
        return {
            'enabled': self.enabled,
            'plyer_available': PLYER_AVAILABLE,
            'ctypes_available': CTYPES_AVAILABLE,
            'recent_alerts_count': len(self.recent_alerts),
            'total_alerts_processed': len(self.alert_history),
            'rate_limit': self.max_security_alerts_per_minute,
            'auto_dismiss_timeout': self.auto_dismiss_timeout,
            'play_sound': self.play_sound,
            'recent_alerts': [
                {
                    'rule_name': alert['rule_name'],
                    'priority': alert['priority'],
                    'timestamp': datetime.fromtimestamp(alert['timestamp']).isoformat()
                }
                for alert in self.alert_history[-10:]  # Last 10 alerts
            ]
        }
    
    def configure_security_notifications(self, **kwargs):
        """Cấu hình security notifications"""
        if 'enabled' in kwargs:
            self.enabled = kwargs['enabled']
        if 'show_on_screen' in kwargs:
            self.show_on_screen = kwargs['show_on_screen']
        if 'play_sound' in kwargs:
            self.play_sound = kwargs['play_sound']
        if 'auto_dismiss_timeout' in kwargs:
            self.auto_dismiss_timeout = kwargs['auto_dismiss_timeout']
        if 'max_security_alerts_per_minute' in kwargs:
            self.max_security_alerts_per_minute = kwargs['max_security_alerts_per_minute']
        
        self.logger.info(f"🔧 Security notification settings updated: {kwargs}")
    
    def test_security_alert(self):
        """Test security alert notification"""
        try:
            test_alert = {
                'id': 'test_001',
                'rule_name': 'Test Security Rule',
                'title': 'Test Security Alert',
                'description': 'This is a test security alert notification',
                'severity': 'HIGH',
                'risk_score': 85,
                'alert_type': 'Test Alert',
                'detection_method': 'Rule-based',
                'mitre_tactic': 'Defense Evasion',
                'mitre_technique': 'T1055'
            }
            
            self._process_single_alert(test_alert)
            self.logger.info("✅ Test security alert sent")
            
        except Exception as e:
            self.logger.error(f"❌ Test security alert failed: {e}")


# Convenience functions
def create_security_notifier(config_manager=None):
    """Tạo security alert notifier"""
    return SecurityAlertNotifier(config_manager)

def process_detection_alerts(server_response: Dict[str, Any], related_events: List = None, notifier=None):
    """Xử lý detection alerts từ server"""
    if notifier is None:
        notifier = SecurityAlertNotifier()
    
    notifier.process_server_alerts(server_response, related_events)

def test_security_notification():
    """Test nhanh security notification"""
    notifier = SecurityAlertNotifier()
    notifier.test_security_alert()