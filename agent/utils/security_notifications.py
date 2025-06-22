# agent/utils/security_notifications.py - Enhanced with Alert Acknowledgment
"""
Security Alert Notification System - Enhanced Version with Server Acknowledgment
Hiển thị toast notifications ở góc phải màn hình khi server phát hiện threats
Gửi acknowledgment ngược lại server để tracking alert lifecycle
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

# Import for Windows Toast Notifications
try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False

# Fallback Windows API imports
try:
    import ctypes
    from ctypes import wintypes
    import win32api
    import win32con
    import win32gui
    WINDOWS_API_AVAILABLE = True
except ImportError:
    WINDOWS_API_AVAILABLE = False

# Try to import win10toast for better Windows 10/11 notifications
try:
    from win10toast import ToastNotifier
    WIN10_TOAST_AVAILABLE = True
except ImportError:
    WIN10_TOAST_AVAILABLE = False


class SecurityAlertNotifier:
    """Enhanced Security Alert Notifier with Toast Notifications and Server Acknowledgment"""
    
    def __init__(self, config_manager=None):
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager
        
        # Server communication reference (will be set by EventProcessor)
        self.communication = None
        
        # Notification settings
        self.enabled = True
        self.show_on_screen = True
        self.play_sound = True
        self.auto_dismiss_timeout = 30
        
        # Alert acknowledgment settings
        self.auto_acknowledge = True
        self.send_feedback = True
        self.track_user_interactions = True
        
        # Toast notification settings
        self.toast_duration = 10  # seconds
        self.toast_threaded = True
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
        
        # Initialize toast notifier
        self.toast_notifier = None
        if WIN10_TOAST_AVAILABLE:
            try:
                self.toast_notifier = ToastNotifier()
                self.logger.info("✅ Win10Toast notifier initialized")
            except Exception as e:
                self.logger.debug(f"Win10Toast init failed: {e}")
        
        self.logger.info("🔒 Enhanced Security Alert Notifier with Acknowledgment initialized")
    
    def set_communication(self, communication):
        """Set communication reference for alert acknowledgment"""
        self.communication = communication
        self.logger.info("🔗 Communication linked for alert acknowledgment")
    
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
        """Process alerts from server response - Enhanced version with acknowledgment"""
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
            
            # Process each alert with acknowledgment
            for alert in alerts:
                # Create task for async processing
                asyncio.create_task(self._process_single_alert_async(alert, related_events))
                
        except Exception as e:
            self.logger.error(f"❌ Error processing server alerts: {e}")
    
    async def _process_single_alert_async(self, alert: Dict[str, Any], related_events: List = None):
        """Process a single security alert asynchronously with server acknowledgment"""
        try:
            # Parse alert information
            alert_info = {
                'alert_id': alert.get('id', alert.get('alert_id', f"alert_{int(time.time())}")),
                'server_alert_id': alert.get('server_alert_id'),  # ID from server database
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
            
            # Find related event
            if related_events and alert_info['event_id'] is not None:
                try:
                    event_index = int(alert_info['event_id'])
                    if 0 <= event_index < len(related_events):
                        alert_info['related_event'] = related_events[event_index]
                except (ValueError, IndexError):
                    pass
            
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
            
            # Show enhanced notification
            await self._show_enhanced_security_notification_async(alert_info)
            
            # Send acknowledgment to server
            if self.auto_acknowledge and self.communication:
                await self._acknowledge_alert_to_server(alert_info)
            
            # Track alert locally
            self._track_security_alert(alert_info)
            
        except Exception as e:
            self.logger.error(f"❌ Error processing single alert: {e}")
    
    async def _acknowledge_alert_to_server(self, alert_info: Dict[str, Any]):
        """Send alert acknowledgment to server"""
        try:
            alert_id = alert_info.get('server_alert_id') or alert_info.get('alert_id')
            
            if not alert_id:
                self.logger.warning("⚠️ No alert ID for acknowledgment")
                return
            
            # Send acknowledgment
            acknowledgment_details = {
                'notification_displayed': True,
                'display_method': 'toast_notification',
                'severity': alert_info.get('severity'),
                'rule_name': alert_info.get('rule_name'),
                'agent_version': '2.0.0',
                'display_timestamp': datetime.now().isoformat(),
                'priority': alert_info.get('priority')
            }
            
            response = await self.communication.acknowledge_alert(
                alert_id=alert_id,
                status="acknowledged",
                details=acknowledgment_details
            )
            
            if response and response.get('success'):
                self.logger.info(f"✅ Alert acknowledged to server: {alert_id}")
                
                # Send additional feedback about notification display
                await self.communication.send_alert_feedback(
                    alert_id=alert_id,
                    feedback_type="notification_displayed",
                    feedback_data={
                        'display_method': 'plyer_toast' if PLYER_AVAILABLE else 'fallback',
                        'notification_timeout': self._get_notification_timeout(alert_info.get('priority', 'MEDIUM')),
                        'user_interaction_tracking': self.track_user_interactions,
                        'sound_played': self.play_sound
                    }
                )
                
            else:
                self.logger.warning(f"⚠️ Failed to acknowledge alert: {alert_id}")
                
        except Exception as e:
            self.logger.error(f"❌ Alert acknowledgment failed: {e}")
    
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
    
    async def _show_enhanced_security_notification_async(self, alert_info: Dict[str, Any]):
        """Show enhanced security notification with multiple methods - Async version"""
        try:
            if not self.enabled:
                return
            
            # Prepare notification content
            title, message = self._prepare_notification_content(alert_info)
            priority = alert_info.get('priority', 'MEDIUM')
            timeout = self._get_notification_timeout(priority)
            
            # Try different notification methods in order of preference
            notification_shown = False
            
            # Method 1: Windows 10/11 Toast
            if WIN10_TOAST_AVAILABLE and self.toast_notifier:
                notification_shown = await self._show_win10_toast_async(title, message, alert_info, timeout)
            
            # Method 2: Plyer notification
            if not notification_shown and PLYER_AVAILABLE:
                notification_shown = await self._show_plyer_notification_async(title, message, alert_info, timeout)
            
            # Method 3: Windows MessageBox
            if not notification_shown and WINDOWS_API_AVAILABLE:
                notification_shown = await self._show_messagebox_notification_async(title, message, alert_info)
            
            # Method 4: Console notification (fallback)
            if not notification_shown:
                self._show_console_notification(title, message, alert_info)
            
            # Play sound if enabled
            if self.play_sound:
                self._play_alert_sound()
            
            self.logger.info(f"🔔 Security notification displayed: {alert_info['rule_name']}")
            
            # Send notification display feedback to server
            if self.communication and alert_info.get('server_alert_id'):
                await self.communication.send_alert_feedback(
                    alert_id=alert_info['server_alert_id'],
                    feedback_type="notification_displayed_successfully",
                    feedback_data={
                        'display_method': 'plyer' if notification_shown and PLYER_AVAILABLE else 'fallback',
                        'display_success': notification_shown,
                        'title': title,
                        'timeout': timeout
                    }
                )
            
        except Exception as e:
            self.logger.error(f"❌ Error showing security notification: {e}")
    
    async def _show_win10_toast_async(self, title: str, message: str, alert_info: Dict[str, Any], timeout: int) -> bool:
        """Show Windows 10/11 toast notification - Async version"""
        try:
            def show_toast():
                try:
                    self.toast_notifier.show_toast(
                        title=title,
                        msg=message,
                        duration=timeout,
                        threaded=self.toast_threaded,
                        icon_path=self.app_icon,
                        callback_on_click=lambda: asyncio.create_task(self._on_notification_click(alert_info))
                    )
                except Exception as e:
                    self.logger.debug(f"Win10Toast error: {e}")
            
            if self.toast_threaded:
                await asyncio.get_event_loop().run_in_executor(None, show_toast)
            else:
                show_toast()
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Win10Toast failed: {e}")
            return False
    
    async def _show_plyer_notification_async(self, title: str, message: str, alert_info: Dict[str, Any], timeout: int) -> bool:
        """Show notification using Plyer - Async version"""
        try:
            def show():
                try:
                    notification.notify(
                        title=title,
                        message=message,
                        timeout=timeout,
                        app_icon=self.app_icon
                    )
                except Exception as e:
                    self.logger.debug(f"Plyer notification error: {e}")
            
            await asyncio.get_event_loop().run_in_executor(None, show)
            return True
            
        except Exception as e:
            self.logger.debug(f"Plyer notification failed: {e}")
            return False
    
    async def _show_messagebox_notification_async(self, title: str, message: str, alert_info: Dict[str, Any]) -> bool:
        """Show Windows MessageBox notification - Async version"""
        try:
            def show():
                try:
                    ctypes.windll.user32.MessageBoxW(
                        0, 
                        message, 
                        title, 
                        win32con.MB_OK | win32con.MB_ICONWARNING
                    )
                except Exception as e:
                    self.logger.debug(f"MessageBox error: {e}")
            
            await asyncio.get_event_loop().run_in_executor(None, show)
            return True
            
        except Exception as e:
            self.logger.debug(f"MessageBox failed: {e}")
            return False
    
    def _show_console_notification(self, title: str, message: str, alert_info: Dict[str, Any]):
        """Show console notification as fallback"""
        try:
            priority = alert_info.get('priority', 'MEDIUM')
            rule_name = alert_info.get('rule_name', 'Unknown')
            severity = alert_info.get('severity', 'MEDIUM')
            risk_score = alert_info.get('risk_score', 50)
            
            # Create visual separator
            separator = "=" * 80
            
            # Color codes for console (if supported)
            colors = {
                'CRITICAL': '\033[91m',  # Red
                'HIGH': '\033[93m',      # Yellow
                'MEDIUM': '\033[94m',    # Blue
                'LOW': '\033[92m'        # Green
            }
            
            color = colors.get(priority, '')
            reset = '\033[0m'
            
            print(f"\n{separator}")
            print(f"{color}🚨 SECURITY ALERT - {priority}{reset}")
            print(f"{color}Rule: {rule_name}{reset}")
            print(f"{color}Severity: {severity}{reset}")
            print(f"{color}Risk Score: {risk_score}/100{reset}")
            print(f"{color}Title: {title}{reset}")
            print(f"{color}Message: {message}{reset}")
            print(f"{separator}\n")
            
        except Exception as e:
            self.logger.error(f"❌ Console notification error: {e}")
    
    def _prepare_notification_content(self, alert_info: Dict[str, Any]) -> tuple:
        """Prepare notification title and message"""
        try:
            rule_name = alert_info.get('rule_name', 'Security Alert')
            severity = alert_info.get('severity', 'MEDIUM')
            risk_score = alert_info.get('risk_score', 50)
            description = alert_info.get('description', 'Suspicious activity detected')
            
            # Create title
            if severity == 'CRITICAL':
                title = f"🚨 CRITICAL: {rule_name}"
            elif severity == 'HIGH':
                title = f"⚠️ HIGH: {rule_name}"
            elif severity == 'MEDIUM':
                title = f"🔍 MEDIUM: {rule_name}"
            else:
                title = f"ℹ️ LOW: {rule_name}"
            
            # Create message
            message_parts = []
            
            # Add description
            if description:
                message_parts.append(description)
            
            # Add risk score
            if risk_score > 0:
                message_parts.append(f"Risk Score: {risk_score}/100")
            
            # Add MITRE info if available
            if alert_info.get('mitre_tactic'):
                message_parts.append(f"Tactic: {alert_info['mitre_tactic']}")
            
            if alert_info.get('mitre_technique'):
                message_parts.append(f"Technique: {alert_info['mitre_technique']}")
            
            # Add timestamp
            timestamp = alert_info.get('timestamp', datetime.now().isoformat())
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_str = dt.strftime('%H:%M:%S')
                message_parts.append(f"Time: {time_str}")
            except:
                pass
            
            message = " | ".join(message_parts)
            
            return title, message
            
        except Exception as e:
            self.logger.error(f"❌ Error preparing notification content: {e}")
            return "Security Alert", "Suspicious activity detected"
    
    def _get_notification_timeout(self, priority: str) -> int:
        """Get notification timeout based on priority"""
        timeouts = {
            'CRITICAL': 15,
            'HIGH': 12,
            'MEDIUM': 8,
            'LOW': 5
        }
        return timeouts.get(priority, 8)
    
    async def _on_notification_click(self, alert_info: Dict[str, Any]):
        """Handle notification click event with server feedback"""
        try:
            self.logger.info("🔔 Security notification clicked")
            
            # Send click feedback to server
            if self.communication and alert_info.get('server_alert_id'):
                await self.communication.update_alert_status(
                    alert_id=alert_info['server_alert_id'],
                    new_status="investigating",
                    details={
                        'action': 'user_clicked_notification',
                        'timestamp': datetime.now().isoformat(),
                        'user_interaction': True
                    }
                )
                
                await self.communication.send_alert_feedback(
                    alert_id=alert_info['server_alert_id'],
                    feedback_type="user_clicked",
                    feedback_data={
                        'click_timestamp': datetime.now().isoformat(),
                        'alert_priority': alert_info.get('priority'),
                        'rule_name': alert_info.get('rule_name')
                    }
                )
                
        except Exception as e:
            self.logger.error(f"❌ Notification click handling error: {e}")
    
    async def _on_notification_dismiss(self, alert_info: Dict[str, Any]):
        """Handle notification dismissal with server feedback"""
        try:
            self.logger.info("🔔 Security notification dismissed")
            
            # Send dismissal feedback to server
            if self.communication and alert_info.get('server_alert_id'):
                await self.communication.update_alert_status(
                    alert_id=alert_info['server_alert_id'],
                    new_status="dismissed",
                    details={
                        'action': 'user_dismissed_notification',
                        'timestamp': datetime.now().isoformat(),
                        'auto_dismiss': False
                    }
                )
                
                await self.communication.send_alert_feedback(
                    alert_id=alert_info['server_alert_id'],
                    feedback_type="user_dismissed",
                    feedback_data={
                        'dismiss_timestamp': datetime.now().isoformat(),
                        'dismiss_method': 'manual'
                    }
                )
                
        except Exception as e:
            self.logger.error(f"❌ Notification dismiss handling error: {e}")
    
    def _play_alert_sound(self):
        """Play alert sound"""
        try:
            # Simple beep for now - could be enhanced with custom sounds
            if WINDOWS_API_AVAILABLE:
                import winsound
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
                'acknowledged_to_server': bool(self.communication and alert_info.get('server_alert_id'))
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
            acknowledged_count = 0
            for alert in recent_alerts:
                severity = alert['severity']
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                if alert.get('acknowledged_to_server'):
                    acknowledged_count += 1
            
            return {
                'total_alerts_today': len([a for a in self.alert_history if current_time - a['timestamp'] < 86400]),
                'recent_alerts_1h': len(recent_alerts),
                'acknowledged_alerts_1h': acknowledged_count,
                'acknowledgment_rate': (acknowledged_count / max(len(recent_alerts), 1)) * 100,
                'severity_distribution': severity_counts,
                'notifications_enabled': self.enabled,
                'auto_acknowledge_enabled': self.auto_acknowledge,
                'communication_linked': self.communication is not None,
                'toast_available': WIN10_TOAST_AVAILABLE,
                'plyer_available': PLYER_AVAILABLE
            }
            
        except Exception as e:
            self.logger.error(f"❌ Stats error: {e}")
            return {}
    
    def test_security_alert(self):
        """Test security alert notification system with acknowledgment"""
        try:
            test_alert = {
                'id': 'test_alert',
                'server_alert_id': 'server_test_123',
                'rule_name': 'Test Security Rule',
                'title': 'Test Security Alert',
                'description': 'This is a test security alert to verify notification and acknowledgment system',
                'severity': 'MEDIUM',
                'risk_score': 60,
                'timestamp': datetime.now().isoformat(),
                'detection_method': 'Test'
            }
            
            self.logger.info("🧪 Testing security alert notification and acknowledgment system...")
            
            # Create async task for testing
            asyncio.create_task(self._process_single_alert_async(test_alert))
            
            self.logger.info("✅ Security alert test initiated")
            
        except Exception as e:
            self.logger.error(f"❌ Security alert test failed: {e}")
    
    def configure_security_notifications(self, **kwargs):
        """Configure security notification settings"""
        try:
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, value)
                    self.logger.info(f"🔧 Security notification setting updated: {key} = {value}")
                else:
                    self.logger.warning(f"⚠️ Unknown security notification setting: {key}")
                    
        except Exception as e:
            self.logger.error(f"❌ Configuration error: {e}")


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
    print("🧪 Testing Security Notification System with Acknowledgment...")
    test_notification_system()
    print("✅ Test completed")