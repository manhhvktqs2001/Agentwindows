# agent/utils/security_notifications.py - CHỈ HIỂN THỊ ALERT TỪ SERVER
"""
Security Alert Notification System - CHỈ HIỂN THỊ KHI SERVER GỬI CẢNH BÁO
Chỉ hiển thị notification khi server phát hiện vi phạm luật bảo mật
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

# PLYER NOTIFICATION SETUP
PLYER_AVAILABLE = False
try:
    from plyer import notification
    PLYER_AVAILABLE = True
    print("🔔 Plyer notification system loaded successfully.")
except ImportError:
    try:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "plyer"], 
                            capture_output=True, timeout=30)
        from plyer import notification
        PLYER_AVAILABLE = True
        print("🔔 Plyer installed and loaded successfully.")
    except:
        print("⚠️ Plyer not available. Notifications will appear in console only.")

# WINDOWS TOAST FALLBACK
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
    """Security Alert Notifier - CHỈ HIỂN THỊ ALERT TỪ SERVER"""
    
    def __init__(self, config_manager=None):
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager
        
        # Server communication reference
        self.communication = None
        
        # Notification settings - 3 SECONDS AUTO-DISMISS
        self.enabled = True
        self.show_server_alerts_only = True  # CHỈ HIỂN THỊ ALERT TỪ SERVER
        self.show_on_screen = True
        self.play_sound = True
        self.auto_dismiss_timeout = 3  # TỰ ĐỘNG TẮT SAU 3 GIÂY
        
        # Initialize notification systems - SIMPLE MODE (NO ICON)
        self.plyer_available = False
        self.toast_available = False
        self.toast_notifier = None
        
        # Initialize Plyer - NO ICON MODE
        try:
            from plyer import notification
            self.plyer_notification = notification
            self.plyer_available = True
            self.logger.info("✅ Plyer notification initialized (simple mode)")
        except ImportError:
            self.logger.info("⚠️ Plyer not available")
        
        # Initialize Windows Toast - NO ICON MODE
        try:
            from win10toast import ToastNotifier
            self.toast_notifier = ToastNotifier()
            self.toast_available = True
            self.logger.info("✅ Windows Toast initialized (simple mode)")
        except ImportError:
            self.logger.info("⚠️ Windows Toast not available")
        
        # Toast notification settings - 3 SECONDS DURATION
        self.toast_duration = 3  # CHỈ HIỂN THỊ 3 GIÂY
        self.app_name = "EDR Security Agent"
        self.app_icon = None  # FIXED: NO ICON TO AVOID ERRORS
        
        # Server alert tracking
        self.server_alerts_received = 0
        self.server_alerts_displayed = 0
        self.last_server_alert_time = None
        
        # Alert deduplication
        self.displayed_alerts = set()
        self.alert_cooldown = {}
        
        self.logger.info(f"🔔 Security Alert Notifier initialized - SERVER ALERTS ONLY (3s duration, no icon issues)")
        self.logger.info(f"   Plyer: {self.plyer_available}, Toast: {self.toast_available}")
    
    def set_communication(self, communication):
        """Set communication reference"""
        self.communication = communication
        self.logger.info("Communication linked for server alert processing")
    
    def _icon_path(self) -> Optional[str]:
        """Get path to application icon - FIXED VERSION"""
        try:
            base_dir = Path(__file__).resolve().parent.parent.parent
            icon_paths = [
                base_dir / "assets" / "edr_icon.ico",
                base_dir / "edr_icon.ico",
                base_dir / "icon.ico",
                Path("C:/Windows/System32/shell32.dll"),  # Windows default icons
            ]
            
            for icon_path in icon_paths:
                if icon_path.exists():
                    self.logger.info(f"Found app icon at: {icon_path}")
                    return str(icon_path)
            
            # Return None để sử dụng default icon
            self.logger.info("No custom icon found, using default system icon")
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting app icon path: {e}")
            return None
    
    async def process_server_alerts(self, server_response: Dict[str, Any], related_events: List = None):
        """
        CHỈ XỬ LÝ VÀ HIỂN THỊ ALERTS TỪ SERVER
        Chỉ hiển thị khi server phát hiện vi phạm luật bảo mật
        """
        try:
            # Kiểm tra xem có alert từ server không
            alerts = []
            
            # Trích xuất alerts từ server response
            if 'alerts_generated' in server_response and server_response['alerts_generated']:
                alerts = server_response['alerts_generated']
                self.logger.warning(f"📨 SERVER SENT {len(alerts)} SECURITY ALERTS")
            
            elif 'alerts' in server_response and server_response['alerts']:
                alerts = server_response['alerts']
                self.logger.warning(f"📨 SERVER SENT {len(alerts)} SECURITY ALERTS")
            
            elif server_response.get('threat_detected', False):
                # Tạo alert từ threat detection của server
                alerts = [{
                    'id': f'server_threat_{int(time.time())}',
                    'rule_name': server_response.get('rule_triggered', 'Server Threat Detection'),
                    'title': 'Security Threat Detected by Server',
                    'description': server_response.get('threat_description', 'Suspicious activity detected by server analysis'),
                    'severity': self._map_risk_to_severity(server_response.get('risk_score', 50)),
                    'risk_score': server_response.get('risk_score', 50),
                    'detection_method': 'Server Analysis',
                    'mitre_technique': server_response.get('mitre_technique'),
                    'mitre_tactic': server_response.get('mitre_tactic'),
                    'event_id': server_response.get('event_id'),
                    'timestamp': datetime.now().isoformat(),
                    'server_generated': True
                }]
                self.logger.warning(f"📨 SERVER DETECTED THREAT - Risk Score: {server_response.get('risk_score', 50)}")
            
            # Chỉ xử lý nếu có alerts từ server
            if not alerts:
                self.logger.debug("✅ No security alerts from server - normal operation")
                return
            
            self.server_alerts_received += len(alerts)
            self.last_server_alert_time = datetime.now()
            
            # Hiển thị từng alert từ server
            for alert in alerts:
                await self._display_server_alert(alert)
                
        except Exception as e:
            self.logger.error(f"❌ Error processing server alerts: {e}")
            traceback.print_exc()
    
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
    
    async def _display_server_alert(self, alert: Dict[str, Any]):
        """
        HIỂN THỊ ALERT TỪ SERVER
        Chỉ hiển thị alert mà server gửi về
        """
        try:
            # Parse alert information từ server
            alert_info = {
                'alert_id': alert.get('id', alert.get('alert_id', f"server_alert_{int(time.time())}")),
                'rule_name': alert.get('rule_name', alert.get('rule_triggered', 'Server Security Rule')),
                'title': alert.get('title', alert.get('alert_title', 'Security Threat Detected by Server')),
                'description': alert.get('description', alert.get('alert_description', 'Server detected suspicious activity')),
                'severity': alert.get('severity', alert.get('alert_severity', 'MEDIUM')),
                'risk_score': alert.get('risk_score', 50),
                'timestamp': alert.get('timestamp', datetime.now().isoformat()),
                'mitre_technique': alert.get('mitre_technique'),
                'mitre_tactic': alert.get('mitre_tactic'),
                'detection_method': alert.get('detection_method', 'Server Rule Engine'),
                'event_id': alert.get('event_id'),
                'server_generated': True
            }
            
            # Kiểm tra deduplication
            alert_signature = f"{alert_info['rule_name']}_{alert_info['alert_id']}"
            if alert_signature in self.displayed_alerts:
                self.logger.debug(f"🔄 Duplicate server alert suppressed: {alert_info['rule_name']}")
                return
            
            # Kiểm tra cooldown
            if self._is_in_cooldown(alert_signature):
                self.logger.debug(f"⏰ Server alert in cooldown: {alert_info['rule_name']}")
                return
            
            # Log server alert
            self.logger.critical("=" * 80)
            self.logger.critical(f"🚨 SERVER SECURITY ALERT RECEIVED:")
            self.logger.critical(f"   Rule: {alert_info['rule_name']}")
            self.logger.critical(f"   Severity: {alert_info['severity']}")
            self.logger.critical(f"   Risk Score: {alert_info['risk_score']}/100")
            self.logger.critical(f"   Description: {alert_info['description']}")
            if alert_info['mitre_technique']:
                self.logger.critical(f"   MITRE Technique: {alert_info['mitre_technique']}")
            if alert_info['mitre_tactic']:
                self.logger.critical(f"   MITRE Tactic: {alert_info['mitre_tactic']}")
            self.logger.critical("=" * 80)
            
            # Hiển thị notification trên màn hình
            success = await self._show_server_alert_notification(alert_info)
            
            if success:
                self.server_alerts_displayed += 1
                self.displayed_alerts.add(alert_signature)
                self.alert_cooldown[alert_signature] = time.time()
                self.logger.info(f"✅ Server alert displayed successfully: {alert_info['rule_name']}")
            else:
                self.logger.error(f"❌ Failed to display server alert: {alert_info['rule_name']}")
            
        except Exception as e:
            self.logger.error(f"❌ Error displaying server alert: {e}")
            traceback.print_exc()
    
    def _is_in_cooldown(self, alert_signature: str, cooldown_minutes: int = 5) -> bool:
        """Check if alert is in cooldown period"""
        if alert_signature not in self.alert_cooldown:
            return False
        
        time_since = time.time() - self.alert_cooldown[alert_signature]
        return time_since < (cooldown_minutes * 60)
    
    async def _show_server_alert_notification(self, alert_info: Dict[str, Any]) -> bool:
        """
        HIỂN THỊ NOTIFICATION CHO ALERT TỪ SERVER - 3 GIÂY TỰ ĐỘNG TẮT
        Sử dụng multiple fallback methods với 3 giây duration
        """
        try:
            title, message = self._prepare_server_alert_content(alert_info)
            
            # METHOD 1: Plyer notification (3 giây)
            if self.plyer_available:
                success = await self._show_plyer_notification(title, message, alert_info)
                if success:
                    self.logger.info("✅ Server alert shown via Plyer (3s duration)")
                    # Tự động dismiss sau 3 giây
                    asyncio.create_task(self._auto_dismiss_notification(3))
                    return True
            
            # METHOD 2: Windows Toast notification (3 giây)
            if self.toast_available and self.toast_notifier:
                success = await self._show_windows_toast(title, message, alert_info)
                if success:
                    self.logger.info("✅ Server alert shown via Windows Toast (3s duration)")
                    asyncio.create_task(self._auto_dismiss_notification(3))
                    return True
            
            # METHOD 3: PowerShell balloon tip (3 giây)
            success = await self._show_powershell_balloon(title, message, alert_info)
            if success:
                self.logger.info("✅ Server alert shown via PowerShell balloon (3s duration)")
                return True
            
            # METHOD 4: Console notification (hiển thị và tự clear sau 3 giây)
            self._show_console_notification(title, message, alert_info)
            asyncio.create_task(self._auto_clear_console_notification(3))
            self.logger.info("✅ Server alert shown in console (3s duration)")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ All notification methods failed: {e}")
            return False
    
    async def _auto_dismiss_notification(self, duration: int):
        """Tự động dismiss notification sau duration giây"""
        try:
            await asyncio.sleep(duration)
            self.logger.debug(f"🔕 Auto-dismissed notification after {duration} seconds")
        except Exception as e:
            self.logger.debug(f"Auto-dismiss error: {e}")
    
    async def _auto_clear_console_notification(self, duration: int):
        """Tự động clear console notification sau duration giây"""
        try:
            await asyncio.sleep(duration)
            # Clear console với empty lines
            print("\n" * 5)
            print("🔕 Alert dismissed after 3 seconds")
            self.logger.debug(f"🔕 Console notification cleared after {duration} seconds")
        except Exception as e:
            self.logger.debug(f"Console clear error: {e}")
    
    def _prepare_server_alert_content(self, alert_info: Dict[str, Any]) -> tuple:
        """Prepare notification content for server alert"""
        try:
            rule_name = alert_info.get('rule_name', 'Server Security Rule')
            severity = alert_info.get('severity', 'MEDIUM')
            risk_score = alert_info.get('risk_score', 50)
            description = alert_info.get('description', 'Server detected security threat')
            
            # Create title với emoji
            severity_icons = {
                'CRITICAL': '🚨',
                'HIGH': '⚠️',
                'MEDIUM': '🔍',
                'LOW': 'ℹ️'
            }
            
            icon = severity_icons.get(severity, '🔔')
            title = f"{icon} SERVER SECURITY ALERT - {severity}"
            
            # Create detailed message
            message_parts = [
                f"🛡️ EDR Server detected a security threat:",
                f"Rule: {rule_name}",
                f"Risk Score: {risk_score}/100"
            ]
            
            # Add description if available
            if description and len(description) < 100:
                message_parts.append(f"Details: {description}")
            
            # Add MITRE info if available
            if alert_info.get('mitre_technique'):
                message_parts.append(f"MITRE: {alert_info['mitre_technique']}")
            
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
            self.logger.error(f"❌ Error preparing server alert content: {e}")
            return "EDR Server Security Alert", "Server detected security threat"
    
    async def _show_plyer_notification(self, title: str, message: str, alert_info: Dict[str, Any]) -> bool:
        """Show Plyer notification - 3 SECONDS DURATION - SIMPLE MODE NO ICON"""
        try:
            if not self.plyer_available:
                return False
            
            def show_plyer():
                try:
                    # SIMPLE MODE: No icon parameter to avoid errors
                    self.plyer_notification.notify(
                        title=title,
                        message=message,
                        timeout=3,  # 3 GIÂY TỰ ĐỘNG TẮT
                        app_name=self.app_name
                        # NO app_icon parameter - this was causing the error
                    )
                    return True
                except Exception as e:
                    self.logger.debug(f"Plyer notification error: {e}")
                    return False
            
            result = await asyncio.to_thread(show_plyer)
            
            if result and self.play_sound:
                await asyncio.to_thread(self._play_alert_sound)
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Plyer notification failed: {e}")
            return False
    
    async def _show_windows_toast(self, title: str, message: str, alert_info: Dict[str, Any]) -> bool:
        """Show Windows Toast notification - 3 SECONDS DURATION - SIMPLE MODE NO ICON"""
        try:
            if not self.toast_available or not self.toast_notifier:
                return False
            
            def show_toast():
                try:
                    # SIMPLE MODE: No icon parameter to avoid errors
                    self.toast_notifier.show_toast(
                        title=title,
                        msg=message,
                        duration=3,  # 3 GIÂY TỰ ĐỘNG TẮT
                        threaded=True
                        # NO icon_path parameter - this can cause errors
                    )
                    return True
                except Exception as e:
                    self.logger.debug(f"Windows Toast error: {e}")
                    return False
            
            result = await asyncio.to_thread(show_toast)
            
            if result and self.play_sound:
                await asyncio.to_thread(self._play_alert_sound)
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Windows Toast notification failed: {e}")
            return False
    
    async def _show_powershell_balloon(self, title: str, message: str, alert_info: Dict[str, Any]) -> bool:
        """Show PowerShell balloon tip - 3 SECONDS DURATION"""
        try:
            # PowerShell script với 3 giây hiển thị
            ps_script = f'''
Add-Type -AssemblyName System.Windows.Forms
$balloon = New-Object System.Windows.Forms.NotifyIcon
$balloon.Icon = [System.Drawing.SystemIcons]::Warning
$balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
$balloon.BalloonTipText = "{message.replace('"', '""')}"
$balloon.BalloonTipTitle = "{title.replace('"', '""')}"
$balloon.Visible = $true
$balloon.ShowBalloonTip(3000)
Start-Sleep -Seconds 3
$balloon.Dispose()
'''
            
            def run_powershell():
                try:
                    result = subprocess.run(
                        ["powershell", "-Command", ps_script],
                        capture_output=True,
                        text=True,
                        timeout=5  # Giảm timeout xuống 5 giây
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
    
    def _show_console_notification(self, title: str, message: str, alert_info: Dict[str, Any]):
        """Show console notification với 3 giây countdown"""
        try:
            rule_name = alert_info.get('rule_name', 'Unknown')
            severity = alert_info.get('severity', 'MEDIUM')
            risk_score = alert_info.get('risk_score', 50)
            
            # Create visual separator
            separator = "=" * 100
            
            print(f"\n{separator}")
            print(f"🚨 SERVER SECURITY ALERT - {severity}")
            print(f"🛡️ Rule Triggered: {rule_name}")
            print(f"📊 Risk Score: {risk_score}/100")
            print(f"📋 Title: {title}")
            print(f"📝 Message: {message}")
            print(f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"⏱️  Auto-dismiss in 3 seconds...")
            print(f"{separator}")
            
            # Flash console để thu hút sự chú ý
            try:
                import ctypes
                ctypes.windll.kernel32.SetConsoleTextAttribute(
                    ctypes.windll.kernel32.GetStdHandle(-11), 12)  # Red text
                print("🚨🚨🚨 SERVER DETECTED SECURITY THREAT 🚨🚨🚨")
                print("🔕 This alert will auto-dismiss in 3 seconds")
                ctypes.windll.kernel32.SetConsoleTextAttribute(
                    ctypes.windll.kernel32.GetStdHandle(-11), 7)   # Reset to white
            except:
                print("🚨🚨🚨 SERVER DETECTED SECURITY THREAT 🚨🚨🚨")
                print("🔕 This alert will auto-dismiss in 3 seconds")
            
        except Exception as e:
            self.logger.error(f"❌ Console notification error: {e}")
    
    def _play_alert_sound(self):
        """Play alert sound for server alerts"""
        try:
            try:
                import winsound
                # Play critical system sound
                winsound.PlaySound("SystemHand", winsound.SND_ALIAS | winsound.SND_ASYNC)
            except:
                try:
                    import winsound
                    # Critical alert beep pattern
                    for _ in range(3):
                        winsound.Beep(1000, 300)  # 1000Hz for 300ms
                        time.sleep(0.1)
                except:
                    # Fallback beep
                    for _ in range(3):
                        print("\a", end="", flush=True)
                        time.sleep(0.2)
                    
        except Exception as e:
            self.logger.debug(f"Sound play error: {e}")
    
    def get_server_alert_stats(self) -> Dict[str, Any]:
        """Get server alert statistics"""
        try:
            return {
                'server_alerts_received': self.server_alerts_received,
                'server_alerts_displayed': self.server_alerts_displayed,
                'last_server_alert_time': self.last_server_alert_time.isoformat() if self.last_server_alert_time else None,
                'plyer_available': self.plyer_available,
                'toast_available': self.toast_available,
                'displayed_alerts_count': len(self.displayed_alerts),
                'display_success_rate': (self.server_alerts_displayed / max(self.server_alerts_received, 1)) * 100,
                'server_alerts_only_mode': True
            }
        except Exception as e:
            self.logger.error(f"❌ Stats calculation error: {e}")
            return {}
    
    # Legacy methods for compatibility - CHỈ XỬ LÝ ALERT TỪ SERVER
    async def process_alert(self, alert: Dict):
        """Legacy method - chỉ xử lý nếu là server alert"""
        if alert.get('server_generated') or alert.get('from_server'):
            await self._display_server_alert(alert)
        else:
            self.logger.debug("🔒 Non-server alert ignored - server alerts only mode")
    
    async def send_notification(self, notification: Dict):
        """Legacy method - chỉ xử lý nếu là server notification"""
        if notification.get('server_generated') or notification.get('from_server'):
            await self._display_server_alert(notification)
        else:
            self.logger.debug("🔒 Non-server notification ignored - server alerts only mode")

def create_security_notifier(config_manager=None):
    """Factory function to create security notifier"""
    return SecurityAlertNotifier(config_manager)