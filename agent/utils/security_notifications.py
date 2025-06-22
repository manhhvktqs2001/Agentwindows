# agent/utils/security_notifications.py - FIXED FOR PLYER NOTIFICATIONS
"""
Security Alert Notification System - Fixed with Plyer for Windows Toast
Hiển thị toast notifications ở góc phải màn hình khi server phát hiện threats
"""

import logging
import threading
import time
import json
import os
import sys
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

# Import for notifications - Priority order
NOTIFICATION_METHOD = None

# Try plyer first (best for Windows toast)
try:
    from plyer import notification
    PLYER_AVAILABLE = True
    NOTIFICATION_METHOD = "plyer"
    print("🔔 Plyer notification system loaded")
except ImportError:
    PLYER_AVAILABLE = False
    print("⚠️ Plyer not available")

# Try win10toast as backup
try:
    import warnings
    warnings.filterwarnings("ignore", category=UserWarning, module="pkg_resources")
    from win10toast import ToastNotifier
    WIN10_TOAST_AVAILABLE = True
    if not NOTIFICATION_METHOD:
        NOTIFICATION_METHOD = "win10toast"
        print("🔔 Win10Toast notification system loaded")
except ImportError:
    WIN10_TOAST_AVAILABLE = False
    if not NOTIFICATION_METHOD:
        print("⚠️ Win10Toast not available")

# Windows API as final fallback
try:
    import ctypes
    from ctypes import wintypes
    WINDOWS_API_AVAILABLE = True
    if not NOTIFICATION_METHOD:
        NOTIFICATION_METHOD = "windows_api"
        print("🔔 Windows API notification system loaded")
except ImportError:
    WINDOWS_API_AVAILABLE = False
    if not NOTIFICATION_METHOD:
        NOTIFICATION_METHOD = "console"
        print("⚠️ Using console notifications as fallback")

class SecurityAlertNotifier:
    """Enhanced Security Alert Notifier with Plyer Toast Notifications"""
    
    def __init__(self, config_manager=None):
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager
        
        # Server communication reference
        self.communication = None
        
        # Notification settings
        self.enabled = True
        self.show_on_screen = True
        self.play_sound = True
        self.auto_dismiss_timeout = 15
        
        # Alert acknowledgment settings
        self.auto_acknowledge = True
        self.send_feedback = True
        self.track_user_interactions = True
        
        # Toast notification settings
        self.toast_duration = 15  # seconds
        self.app_name = "EDR Security Agent"
        self.app_icon = self._get_app_icon_path()
        
        # Alert categorization
        self.critical_rules = [
            'Mimikatz Credential Dumping',
            'Mass File Encryption Detection', 
            'Ransomware Activity',
            'Kernel Driver Loading',
            'System File Modification'
        ]
        
        self.high_priority_rules = [
            'Suspicious PowerShell Encoded',
            'Linux Reverse Shell Detection',
            'Code Injection Detected',
            'Privilege Escalation',
            'Remote Admin Tools'
        ]
        
        # Notification tracking
        self.active_alerts = []
        self.alert_history = []
        self.recent_alerts = []
        
        # Rate limiting
        self.max_security_alerts_per_minute = 10
        
        # Initialize notification system
        self.notification_system = NOTIFICATION_METHOD
        
        if PLYER_AVAILABLE:
            self.logger.info("🔔 Plyer notification system initialized")
        elif WIN10_TOAST_AVAILABLE:
            self.toast_notifier = ToastNotifier()
            self.logger.info("🔔 Win10Toast notification system initialized")
        
        self.logger.info(f"Enhanced Security Alert Notifier initialized with {self.notification_system}")
    
    def set_communication(self, communication):
        """Set communication reference for alert acknowledgment"""
        self.communication = communication
        self.logger.info("Communication linked for alert acknowledgment")
    
    def _get_app_icon_path(self) -> str:
        """Get path to application icon"""
        try:
            # Look for icon in various locations
            icon_paths = [
                Path(__file__).parent.parent.parent / "assets" / "edr_icon.ico",
                Path(__file__).parent.parent.parent / "edr_icon.ico",
                Path(sys.executable).parent / "edr_icon.ico"
            ]
            
            for icon_path in icon_paths:
                if icon_path.exists():
                    return str(icon_path)
            
            # Use default Windows security icon if available
            return str(Path(os.environ.get('WINDIR', 'C:\\Windows')) / "System32" / "imageres.dll")
            
        except Exception:
            return None
    
    def process_server_alerts(self, server_response: Dict[str, Any], related_events: List = None):
        """Process alerts from server response - Enhanced for immediate display"""
        try:
            alerts = []
            
            # Extract alerts from various response formats
            if 'alerts_generated' in server_response:
                alerts = server_response['alerts_generated']
            elif 'alerts' in server_response:
                alerts = server_response['alerts']
            elif server_response.get('threat_detected', False):
                # Create alert from threat detection
                alerts = [{
                    'id': f'threat_{int(time.time())}',
                    'rule_name': 'Server Threat Detection',
                    'title': 'Security Threat Detected',
                    'description': server_response.get('message', 'Suspicious activity detected by server'),
                    'severity': 'HIGH' if server_response.get('risk_score', 0) >= 70 else 'MEDIUM',
                    'risk_score': server_response.get('risk_score', 50),
                    'detection_method': 'Server Analysis'
                }]
            
            if not alerts:
                return
            
            self.logger.warning(f"🚨 Processing {len(alerts)} security alerts from server")
            
            # Process each alert immediately
            for alert in alerts:
                # Show notification immediately (synchronous)
                self._show_immediate_notification(alert, related_events)
                
        except Exception as e:
            self.logger.error(f"❌ Error processing server alerts: {e}")
    
    def _show_immediate_notification(self, alert: Dict[str, Any], related_events: List = None):
        """Show notification immediately without async"""
        try:
            # Parse alert information
            alert_info = {
                'alert_id': alert.get('id', alert.get('alert_id', f"alert_{int(time.time())}")),
                'server_alert_id': alert.get('server_alert_id'),
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
            
            # Determine priority
            priority = self._determine_alert_priority(alert_info)
            alert_info['priority'] = priority
            
            # Rate limiting check
            if not self._check_security_rate_limit():
                self.logger.warning("⚠️ Security alert rate limit exceeded")
                return
            
            # Log alert
            self.logger.critical(
                f"🚨 SECURITY ALERT: {alert_info['rule_name']} | "
                f"Severity: {alert_info['severity']} | "
                f"Risk: {alert_info['risk_score']}/100"
            )
            
            # Show notification immediately
            self._display_toast_notification(alert_info)
            
            # Track alert locally
            self._track_security_alert(alert_info)
            
        except Exception as e:
            self.logger.error(f"❌ Error showing immediate notification: {e}")
    
    def _display_toast_notification(self, alert_info: Dict[str, Any]):
        """Display toast notification using best available method"""
        try:
            # Prepare notification content
            title, message = self._prepare_notification_content(alert_info)
            
            # Method 1: Plyer (preferred for Windows)
            if PLYER_AVAILABLE:
                try:
                    self.logger.info("🔔 Showing Plyer toast notification...")
                    
                    # Enhanced notification with icon
                    notification.notify(
                        title=title,
                        message=message,
                        timeout=self.toast_duration,
                        app_icon=self.app_icon,
                        app_name=self.app_name,
                        toast=True  # Force Windows toast
                    )
                    
                    self.logger.info(f"✅ Plyer notification displayed: {alert_info['rule_name']}")
                    
                    # Play sound if enabled
                    if self.play_sound:
                        self._play_alert_sound()
                    
                    return True
                    
                except Exception as e:
                    self.logger.warning(f"⚠️ Plyer notification failed: {e}")
            
            # Method 2: Win10Toast (backup)
            if WIN10_TOAST_AVAILABLE and hasattr(self, 'toast_notifier'):
                try:
                    self.logger.info("🔔 Showing Win10Toast notification...")
                    
                    self.toast_notifier.show_toast(
                        title=title,
                        msg=message,
                        duration=self.toast_duration,
                        threaded=True,
                        icon_path=self.app_icon
                    )
                    
                    self.logger.info(f"✅ Win10Toast notification displayed: {alert_info['rule_name']}")
                    
                    if self.play_sound:
                        self._play_alert_sound()
                    
                    return True
                    
                except Exception as e:
                    self.logger.warning(f"⚠️ Win10Toast notification failed: {e}")
            
            # Method 3: Windows MessageBox (fallback)
            if WINDOWS_API_AVAILABLE:
                try:
                    self.logger.info("🔔 Showing Windows MessageBox...")
                    
                    # Show in separate thread to avoid blocking
                    def show_messagebox():
                        try:
                            ctypes.windll.user32.MessageBoxW(
                                0,
                                message,
                                title,
                                0x30 | 0x40000  # MB_ICONWARNING | MB_TOPMOST
                            )
                        except Exception as e:
                            self.logger.debug(f"MessageBox error: {e}")
                    
                    import threading
                    threading.Thread(target=show_messagebox, daemon=True).start()
                    
                    self.logger.info(f"✅ MessageBox notification displayed: {alert_info['rule_name']}")
                    
                    if self.play_sound:
                        self._play_alert_sound()
                    
                    return True
                    
                except Exception as e:
                    self.logger.warning(f"⚠️ MessageBox notification failed: {e}")
            
            # Method 4: Console notification (final fallback)
            self._show_console_notification(title, message, alert_info)
            return True
            
        except Exception as e:
            self.logger.error(f"❌ All notification methods failed: {e}")
            return False
    
    def _determine_alert_priority(self, alert_info: Dict[str, Any]) -> str:
        """Determine alert priority"""
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
        
        # Low priority
        return 'LOW'
    
    def _prepare_notification_content(self, alert_info: Dict[str, Any]) -> tuple:
        """Prepare notification title and message"""
        try:
            rule_name = alert_info.get('rule_name', 'Security Alert')
            severity = alert_info.get('severity', 'MEDIUM')
            risk_score = alert_info.get('risk_score', 50)
            description = alert_info.get('description', 'Suspicious activity detected')
            
            # Create title with emoji
            severity_icons = {
                'CRITICAL': '🚨',
                'HIGH': '⚠️',
                'MEDIUM': '🔍',
                'LOW': 'ℹ️'
            }
            
            icon = severity_icons.get(severity, '🔔')
            title = f"{icon} EDR Alert - {severity}"
            
            # Create detailed message
            message_parts = [
                f"Rule: {rule_name}",
                f"Risk Score: {risk_score}/100"
            ]
            
            if description and len(description) < 100:
                message_parts.insert(1, f"Details: {description}")
            
            # Add MITRE info if available
            if alert_info.get('mitre_tactic'):
                message_parts.append(f"Tactic: {alert_info['mitre_tactic']}")
            
            # Add timestamp
            try:
                timestamp = alert_info.get('timestamp', datetime.now().isoformat())
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_str = dt.strftime('%H:%M:%S')
                message_parts.append(f"Time: {time_str}")
            except:
                pass
            
            message = "\n".join(message_parts)
            
            return title, message
            
        except Exception as e:
            self.logger.error(f"❌ Error preparing notification content: {e}")
            return "EDR Security Alert", "Suspicious activity detected"
    
    def _show_console_notification(self, title: str, message: str, alert_info: Dict[str, Any]):
        """Show console notification as fallback"""
        try:
            priority = alert_info.get('priority', 'MEDIUM')
            rule_name = alert_info.get('rule_name', 'Unknown')
            severity = alert_info.get('severity', 'MEDIUM')
            risk_score = alert_info.get('risk_score', 50)
            
            # Create visual separator
            separator = "=" * 80
            
            print(f"\n{separator}")
            print(f"🚨 SECURITY ALERT - {priority}")
            print(f"Rule: {rule_name}")
            print(f"Severity: {severity}")
            print(f"Risk Score: {risk_score}/100")
            print(f"Title: {title}")
            print(f"Message: {message}")
            print(f"{separator}\n")
            
        except Exception as e:
            self.logger.error(f"❌ Console notification error: {e}")
    
    def _play_alert_sound(self):
        """Play alert sound"""
        try:
            if WINDOWS_API_AVAILABLE:
                # Play Windows notification sound
                try:
                    import winsound
                    winsound.PlaySound("SystemExclamation", winsound.SND_ALIAS | winsound.SND_ASYNC)
                except:
                    # Fallback beep
                    frequency = 1000  # Hz
                    duration = 500   # ms
                    winsound.Beep(frequency, duration)
        except Exception as e:
            self.logger.debug(f"Sound play error: {e}")
    
    def _check_security_rate_limit(self) -> bool:
        """Check if we're within rate limits for security alerts"""
        try:
            current_time = time.time()
            
            # Remove old alerts from tracking
            self.recent_alerts = [
                alert for alert in self.recent_alerts 
                if current_time - alert['timestamp'] < 60
            ]
            
            # Check if we're over the limit
            if len(self.recent_alerts) >= self.max_security_alerts_per_minute:
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Rate limit check error: {e}")
            return True  # Allow if check fails
    
    def _track_security_alert(self, alert_info: Dict[str, Any]):
        """Track security alert for statistics"""
        try:
            current_time = time.time()
            
            # Add to recent alerts
            self.recent_alerts.append({
                'timestamp': current_time,
                'alert_id': alert_info['alert_id'],
                'rule_name': alert_info['rule_name'],
                'severity': alert_info['severity'],
                'notification_shown': True
            })
            
            # Add to history
            self.alert_history.append({
                'timestamp': current_time,
                'alert_info': alert_info.copy()
            })
            
            # Keep only last 1000 alerts in history
            if len(self.alert_history) > 1000:
                self.alert_history = self.alert_history[-1000:]
            
        except Exception as e:
            self.logger.error(f"❌ Alert tracking error: {e}")
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security notification statistics"""
        try:
            current_time = time.time()
            
            # Calculate recent alerts
            recent_alerts = [
                alert for alert in self.recent_alerts 
                if current_time - alert['timestamp'] < 3600  # Last hour
            ]
            
            # Count by severity
            severity_counts = {}
            for alert in recent_alerts:
                severity = alert['severity']
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            return {
                'total_alerts_today': len([a for a in self.alert_history if current_time - a['timestamp'] < 86400]),
                'recent_alerts_1h': len(recent_alerts),
                'severity_distribution': severity_counts,
                'notifications_enabled': self.enabled,
                'notification_system': self.notification_system,
                'plyer_available': PLYER_AVAILABLE,
                'win10toast_available': WIN10_TOAST_AVAILABLE,
                'windows_api_available': WINDOWS_API_AVAILABLE
            }
            
        except Exception as e:
            self.logger.error(f"❌ Stats error: {e}")
            return {}
    
    def test_security_alert(self):
        """Test security alert notification system"""
        try:
            test_alert = {
                'id': 'test_alert',
                'server_alert_id': 'server_test_123',
                'rule_name': 'Test Security Rule',
                'title': 'Test Security Alert',
                'description': 'This is a test security alert to verify notification system',
                'severity': 'HIGH',
                'risk_score': 85,
                'timestamp': datetime.now().isoformat(),
                'detection_method': 'Test'
            }
            
            self.logger.info("🧪 Testing security alert notification system...")
            
            # Show test notification
            self._show_immediate_notification(test_alert)
            
            self.logger.info("✅ Security alert test completed")
            
        except Exception as e:
            self.logger.error(f"❌ Security alert test failed: {e}")

def create_security_notifier(config_manager=None):
    """Factory function to create security notifier"""
    return SecurityAlertNotifier(config_manager)

def test_notification_system():
    """Test the entire notification system"""
    try:
        notifier = SecurityAlertNotifier()
        notifier.test_security_alert()
        return True
    except Exception as e:
        print(f"❌ Notification system test failed: {e}")
        return False

# Test if running directly
if __name__ == "__main__":
    print("🧪 Testing Security Notification System with Plyer...")
    test_notification_system()
    print("✅ Test completed - Check for toast notification in bottom-right corner!")