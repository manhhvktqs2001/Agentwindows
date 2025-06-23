# agent/utils/security_notifications.py - FIXED NOTIFICATION SYSTEM
"""
Security Alert Notification System - FIXED VERSION
Hiển thị toast notifications với nhiều phương pháp fallback để đảm bảo luôn hiển thị được
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
import traceback
import subprocess

# --- PLYER NOTIFICATION SETUP - PRIMARY METHOD ---
PLYER_AVAILABLE = False
try:
    from plyer import notification
    PLYER_AVAILABLE = True
    print("🔔 Plyer notification system loaded successfully.")
except ImportError:
    try:
        # Try installing plyer if not available
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "plyer"], 
                            capture_output=True, timeout=30)
        from plyer import notification
        PLYER_AVAILABLE = True
        print("🔔 Plyer installed and loaded successfully.")
    except:
        print("⚠️ Plyer not available. Notifications will appear in console only.")

# --- WINDOWS TOAST FALLBACK ---
WIN10TOAST_AVAILABLE = False
try:
    from win10toast import ToastNotifier
    WIN10TOAST_AVAILABLE = True
except ImportError:
    try:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "win10toast"], 
                            capture_output=True, timeout=30)
        from win10toast import ToastNotifier
        WIN10TOAST_AVAILABLE = True
    except:
        pass

class SecurityAlertNotifier:
    """Security Alert Notifier - FIXED VERSION with guaranteed notifications"""
    
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
        
        # Initialize notification systems - PLYER FIRST
        self.plyer_available = PLYER_AVAILABLE
        self.toast_available = WIN10TOAST_AVAILABLE
        self.toast_notifier = None
        
        if self.toast_available:
            try:
                self.toast_notifier = ToastNotifier()
                self.logger.info("✅ Windows Toast Notifier initialized as fallback")
            except Exception as e:
                self.logger.error(f"❌ Failed to initialize Toast Notifier: {e}")
                self.toast_available = False
        
        # Toast notification settings
        self.toast_duration = 10  # seconds - increased for better visibility
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
        self.notifications_sent = 0
        self.notifications_failed = 0
        self.last_notification_time = None
        
        self.logger.info(f"🔔 Security Alert Notifier initialized - Plyer: {self.plyer_available}, Toast: {self.toast_available}")
    
    def set_communication(self, communication):
        """Set communication reference for alert acknowledgment"""
        self.communication = communication
        self.logger.info("Communication linked for alert acknowledgment")
    
    def _get_app_icon_path(self) -> Optional[str]:
        """Get path to application icon"""
        try:
            # Look for icon in various locations
            base_dir = Path(__file__).resolve().parent.parent.parent
            icon_paths = [
                base_dir / "assets" / "edr_icon.ico",
                base_dir / "edr_icon.ico",
                Path("C:/Windows/System32/SecurityHealthSystray.exe"),  # Use Windows security icon as fallback
            ]
            
            for icon_path in icon_paths:
                if icon_path.exists():
                    self.logger.info(f"Found app icon at: {icon_path}")
                    return str(icon_path)
            
            self.logger.warning("Custom EDR icon not found. Using default system icon.")
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting app icon path: {e}")
            return None
    
    async def process_server_alerts(self, server_response: Dict[str, Any], related_events: List = None):
        """Process alerts from server response - FIXED VERSION"""
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
                # Show notification immediately
                await self._show_notification_fixed(alert, related_events)
                
        except Exception as e:
            self.logger.error(f"❌ Error processing server alerts: {e}")
            traceback.print_exc()
    
    async def _show_notification_fixed(self, alert: Dict[str, Any], related_events: List = None):
        """Show notification - FIXED VERSION with multiple fallbacks"""
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
            
            # Show notification with multiple methods - PLYER FIRST
            success = await self._display_notification_with_fallbacks(alert_info)
            
            if success:
                self.notifications_sent += 1
                self.last_notification_time = datetime.now()
            else:
                self.notifications_failed += 1
            
            # Track alert locally
            self._track_security_alert(alert_info)
            
        except Exception as e:
            self.logger.error(f"❌ Error showing notification: {e}")
            traceback.print_exc()
            self.notifications_failed += 1
    
    async def _display_notification_with_fallbacks(self, alert_info: Dict[str, Any]) -> bool:
        """Display notification using multiple fallback methods - PLYER FIRST"""
        try:
            title, message = self._prepare_notification_content(alert_info)
            
            # METHOD 1: Try Plyer notification FIRST (cross-platform, better)
            if self.plyer_available:
                success = await self._show_plyer_notification(title, message, alert_info)
                if success:
                    self.logger.info("✅ Plyer notification shown successfully")
                    return True
            
            # METHOD 2: Try Windows 10 Toast (fallback)
            if self.toast_available and self.toast_notifier:
                success = await self._show_windows_toast(title, message, alert_info)
                if success:
                    self.logger.info("✅ Windows Toast notification shown successfully")
                    return True
            
            # METHOD 3: Try PowerShell balloon tip
            success = await self._show_powershell_balloon(title, message, alert_info)
            if success:
                self.logger.info("✅ PowerShell balloon notification shown successfully")
                return True
            
            # METHOD 4: Console notification as final fallback
            self._show_console_notification(title, message, alert_info)
            self.logger.warning("⚠️ All GUI notifications failed, using console fallback")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ All notification methods failed: {e}")
            return False
    
    async def _show_plyer_notification(self, title: str, message: str, alert_info: Dict[str, Any]) -> bool:
        """Show Plyer notification - PRIMARY METHOD"""
        try:
            if not self.plyer_available:
                return False
            
            def show_plyer():
                try:
                    notification.notify(
                        title=title,
                        message=message,
                        timeout=self.toast_duration,
                        app_name=self.app_name,
                        app_icon=self.app_icon
                    )
                    return True
                except Exception as e:
                    self.logger.error(f"Plyer notification error: {e}")
                    return False
            
            # Run in thread to avoid blocking
            result = await asyncio.to_thread(show_plyer)
            
            if result and self.play_sound:
                await asyncio.to_thread(self._play_alert_sound)
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Plyer notification failed: {e}")
            return False
    
    async def _show_windows_toast(self, title: str, message: str, alert_info: Dict[str, Any]) -> bool:
        """Show Windows 10 Toast notification - FALLBACK METHOD"""
        try:
            if not self.toast_available or not self.toast_notifier:
                return False
            
            def show_toast():
                try:
                    self.toast_notifier.show_toast(
                        title=title,
                        msg=message,
                        icon_path=self.app_icon,
                        duration=self.toast_duration,
                        threaded=True
                    )
                    return True
                except Exception as e:
                    self.logger.error(f"Windows Toast error: {e}")
                    return False
            
            # Run in thread to avoid blocking
            result = await asyncio.to_thread(show_toast)
            
            if result and self.play_sound:
                await asyncio.to_thread(self._play_alert_sound)
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Windows Toast notification failed: {e}")
            return False
    
    async def _show_powershell_balloon(self, title: str, message: str, alert_info: Dict[str, Any]) -> bool:
        """Show PowerShell balloon tip"""
        try:
            # PowerShell script for balloon tip
            ps_script = f'''
Add-Type -AssemblyName System.Windows.Forms
$balloon = New-Object System.Windows.Forms.NotifyIcon
$balloon.Icon = [System.Drawing.SystemIcons]::Warning
$balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
$balloon.BalloonTipText = "{message.replace('"', '""')}"
$balloon.BalloonTipTitle = "{title.replace('"', '""')}"
$balloon.Visible = $true
$balloon.ShowBalloonTip({self.toast_duration * 1000})
Start-Sleep -Seconds 2
$balloon.Dispose()
'''
            
            def run_powershell():
                try:
                    result = subprocess.run(
                        ["powershell", "-Command", ps_script],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    return result.returncode == 0
                except Exception as e:
                    self.logger.error(f"PowerShell balloon error: {e}")
                    return False
            
            result = await asyncio.to_thread(run_powershell)
            
            if result and self.play_sound:
                await asyncio.to_thread(self._play_alert_sound)
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ PowerShell balloon notification failed: {e}")
            return False
    
    def _determine_alert_priority(self, alert_info: Dict[str, Any]) -> str:
        """Determine alert priority based on rule and severity"""
        rule_name = alert_info.get('rule_name', '').lower()
        severity = alert_info.get('severity', 'MEDIUM').upper()
        risk_score = alert_info.get('risk_score', 50)
        
        # Critical priority
        if (rule_name in [rule.lower() for rule in self.critical_rules] or 
            severity == 'CRITICAL' or 
            risk_score >= 90):
            return 'CRITICAL'
        
        # High priority
        if (rule_name in [rule.lower() for rule in self.high_priority_rules] or 
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
            title = f"{icon} EDR Security Alert - {severity}"
            
            # Create detailed message - keep it concise for better display
            message_parts = [
                f"Rule: {rule_name}",
                f"Risk: {risk_score}/100"
            ]
            
            # Add description if short enough
            if description and len(description) < 80:
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
            
            # Flash console window to get attention
            try:
                import ctypes
                ctypes.windll.kernel32.SetConsoleTextAttribute(
                    ctypes.windll.kernel32.GetStdHandle(-11), 12)  # Red text
                print("🚨🚨🚨 SECURITY ALERT DETECTED 🚨🚨🚨")
                ctypes.windll.kernel32.SetConsoleTextAttribute(
                    ctypes.windll.kernel32.GetStdHandle(-11), 7)   # Reset to white
            except:
                pass
            
        except Exception as e:
            self.logger.error(f"❌ Console notification error: {e}")
    
    def _play_alert_sound(self):
        """Play alert sound"""
        try:
            # Try multiple sound methods
            try:
                import winsound
                # Play Windows notification sound
                winsound.PlaySound("SystemExclamation", winsound.SND_ALIAS | winsound.SND_ASYNC)
            except:
                try:
                    # Fallback beep
                    import winsound
                    frequency = 1000  # Hz
                    duration = 500   # ms
                    winsound.Beep(frequency, duration)
                except:
                    # Final fallback - system beep
                    print("\a")  # ASCII bell character
                    
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
            return {
                'notifications_sent': self.notifications_sent,
                'notifications_failed': self.notifications_failed,
                'last_notification_time': self.last_notification_time.isoformat() if self.last_notification_time else None,
                'plyer_available': self.plyer_available,
                'toast_available': self.toast_available,
                'recent_alerts_count': len(self.recent_alerts),
                'alert_history_count': len(self.alert_history),
                'success_rate': (self.notifications_sent / max(self.notifications_sent + self.notifications_failed, 1)) * 100
            }
        except Exception as e:
            self.logger.error(f"❌ Stats calculation error: {e}")
            return {}

    # Legacy methods for compatibility
    async def process_alert(self, alert: Dict):
        """Process alert - legacy method"""
        await self._show_notification_fixed(alert)
    
    async def send_notification(self, notification: Dict):
        """Send notification - legacy method"""
        await self._show_notification_fixed(notification)

def create_security_notifier(config_manager=None):
    """Factory function to create security notifier"""
    return SecurityAlertNotifier(config_manager)