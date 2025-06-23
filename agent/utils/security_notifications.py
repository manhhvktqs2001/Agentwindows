# agent/utils/security_notifications.py - SIMPLE RULE-BASED ALERT SYSTEM
"""
Security Alert Notification System - CHỈ HIỂN THỊ KHI SERVER PHÁT HIỆN VI PHẠM RULE
Chỉ hiển thị cảnh báo khi server gửi về và acknowledgment về database
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

# NOTIFICATION LIBRARIES
PLYER_AVAILABLE = False
try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    pass

WIN10TOAST_AVAILABLE = False
try:
    from win10toast import ToastNotifier
    WIN10TOAST_AVAILABLE = True
except ImportError:
    pass

class SimpleRuleBasedAlertNotifier:
    """Simple Alert Notifier - CHỈ HIỂN THỊ CẢNH BÁO TỪ SERVER RULE VIOLATIONS"""
    
    def __init__(self, config_manager=None):
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager
        
        # Server communication reference
        self.communication = None
        
        # Notification settings - SIMPLE MODE
        self.enabled = True
        self.server_rule_alerts_only = True  # CHỈ CẢNH BÁO TỪ SERVER RULES
        self.show_on_screen = True
        self.play_sound = True
        self.alert_duration = 8  # 8 giây hiển thị
        
        # Initialize notification systems
        self.plyer_available = PLYER_AVAILABLE
        self.toast_available = WIN10TOAST_AVAILABLE
        self.toast_notifier = None
        
        if self.plyer_available:
            self.plyer_notification = notification
            self.logger.info("✅ Plyer notification available")
        
        if self.toast_available:
            try:
                self.toast_notifier = ToastNotifier()
                self.logger.info("✅ Windows Toast notification available")
            except:
                self.toast_available = False
        
        # Alert tracking
        self.rule_alerts_received = 0
        self.rule_alerts_displayed = 0
        self.last_rule_alert_time = None
        self.acknowledged_alerts = set()
        
        # Alert deduplication - short window for rule alerts
        self.recent_rule_alerts = {}
        self.rule_alert_cooldown = 30  # 30 seconds cooldown for same rule
        
        self.logger.info(f"🔔 Simple Rule-Based Alert Notifier initialized")
        self.logger.info(f"   Mode: SERVER RULE ALERTS ONLY")
        self.logger.info(f"   Plyer: {self.plyer_available}, Toast: {self.toast_available}")
    
    def set_communication(self, communication):
        """Set communication reference for acknowledgments"""
        self.communication = communication
        self.logger.info("Communication linked for rule alert acknowledgments")
    
    async def process_server_alerts(self, server_response: Dict[str, Any], related_events: List = None):
        """
        XỬ LÝ VÀ HIỂN THỊ CHỈ RULE-BASED ALERTS TỪ SERVER
        Chỉ hiển thị khi server phát hiện vi phạm rule cụ thể
        """
        try:
            # CHỈ XỬ LÝ KHI SERVER GỬI ALERTS
            rule_alerts = []
            
            # Case 1: Server gửi alerts_generated
            if 'alerts_generated' in server_response and server_response['alerts_generated']:
                rule_alerts = server_response['alerts_generated']
                self.logger.warning(f"🚨 SERVER RULE VIOLATION: {len(rule_alerts)} alerts received")
            
            # Case 2: Server gửi alerts array
            elif 'alerts' in server_response and server_response['alerts']:
                rule_alerts = server_response['alerts']
                self.logger.warning(f"🚨 SERVER RULE VIOLATION: {len(rule_alerts)} alerts received")
            
            # Case 3: Server phát hiện threat với rule
            elif server_response.get('threat_detected', False) and server_response.get('rule_triggered'):
                rule_alert = {
                    'id': f'rule_alert_{int(time.time())}',
                    'alert_id': f'rule_alert_{int(time.time())}',
                    'rule_id': server_response.get('rule_id'),
                    'rule_name': server_response.get('rule_triggered'),
                    'rule_description': server_response.get('rule_description', ''),
                    'title': f'Security Rule Violation: {server_response.get("rule_triggered")}',
                    'description': server_response.get('threat_description', 'Security rule violation detected'),
                    'severity': self._map_risk_to_severity(server_response.get('risk_score', 50)),
                    'risk_score': server_response.get('risk_score', 50),
                    'detection_method': 'Server Rule Engine',
                    'mitre_technique': server_response.get('mitre_technique'),
                    'mitre_tactic': server_response.get('mitre_tactic'),
                    'event_id': server_response.get('event_id'),
                    'timestamp': datetime.now().isoformat(),
                    'server_generated': True,
                    'rule_violation': True
                }
                rule_alerts = [rule_alert]
                self.logger.warning(f"🚨 SERVER RULE TRIGGERED: {server_response.get('rule_triggered')}")
            
            # CHỈ XỬ LÝ NẾU CÓ RULE ALERTS TỪ SERVER
            if rule_alerts:
                self.rule_alerts_received += len(rule_alerts)
                self.last_rule_alert_time = datetime.now()
                
                # Hiển thị từng rule alert
                for alert in rule_alerts:
                    success = await self._display_rule_alert(alert)
                    if success:
                        await self._send_rule_alert_acknowledgment(alert)
                        self.rule_alerts_displayed += 1
            else:
                # KHÔNG CÓ RULE VIOLATION - KHÔNG HIỂN THỊ GÌ
                self.logger.debug("✅ No rule violations detected by server - no alerts to display")
                
        except Exception as e:
            self.logger.error(f"❌ Error processing server rule alerts: {e}")
            traceback.print_exc()
    
    async def _display_rule_alert(self, alert: Dict[str, Any]) -> bool:
        """
        HIỂN THỊ RULE ALERT TỪ SERVER
        Chỉ hiển thị khi có vi phạm rule cụ thể
        """
        try:
            # Parse alert information từ server
            rule_info = {
                'alert_id': alert.get('id', alert.get('alert_id', f"rule_alert_{int(time.time())}")),
                'rule_id': alert.get('rule_id'),
                'rule_name': alert.get('rule_name', alert.get('rule_triggered', 'Security Rule')),
                'rule_description': alert.get('rule_description', ''),
                'title': alert.get('title', 'Security Rule Violation'),
                'description': alert.get('description', 'Security rule violation detected'),
                'severity': alert.get('severity', 'MEDIUM'),
                'risk_score': alert.get('risk_score', 50),
                'timestamp': alert.get('timestamp', datetime.now().isoformat()),
                'mitre_technique': alert.get('mitre_technique'),
                'mitre_tactic': alert.get('mitre_tactic'),
                'detection_method': alert.get('detection_method', 'Server Rule Engine'),
                'event_id': alert.get('event_id'),
                'process_name': alert.get('process_name'),
                'file_path': alert.get('file_path'),
                'network_info': alert.get('network_info'),
                'server_generated': True,
                'rule_violation': True
            }
            
            # Kiểm tra deduplication cho rule alerts
            rule_signature = f"{rule_info['rule_name']}_{rule_info.get('rule_id', 'unknown')}"
            if self._is_rule_in_cooldown(rule_signature):
                self.logger.debug(f"🔄 Rule alert in cooldown: {rule_info['rule_name']}")
                return False
            
            # Log rule violation
            self.logger.critical("=" * 100)
            self.logger.critical(f"🚨 SERVER RULE VIOLATION DETECTED:")
            self.logger.critical(f"   Alert ID: {rule_info['alert_id']}")
            self.logger.critical(f"   Rule ID: {rule_info.get('rule_id', 'N/A')}")
            self.logger.critical(f"   Rule Name: {rule_info['rule_name']}")
            self.logger.critical(f"   Rule Description: {rule_info['rule_description']}")
            self.logger.critical(f"   Severity: {rule_info['severity']}")
            self.logger.critical(f"   Risk Score: {rule_info['risk_score']}/100")
            self.logger.critical(f"   Description: {rule_info['description']}")
            if rule_info['process_name']:
                self.logger.critical(f"   Process: {rule_info['process_name']}")
            if rule_info['file_path']:
                self.logger.critical(f"   File: {rule_info['file_path']}")
            if rule_info['mitre_technique']:
                self.logger.critical(f"   MITRE Technique: {rule_info['mitre_technique']}")
            if rule_info['mitre_tactic']:
                self.logger.critical(f"   MITRE Tactic: {rule_info['mitre_tactic']}")
            self.logger.critical(f"   Detection Method: {rule_info['detection_method']}")
            self.logger.critical("=" * 100)
            
            # Hiển thị notification trên màn hình
            success = await self._show_rule_alert_notification(rule_info)
            
            if success:
                self.recent_rule_alerts[rule_signature] = time.time()
                self.logger.info(f"✅ Rule alert displayed successfully: {rule_info['rule_name']}")
                return True
            else:
                self.logger.error(f"❌ Failed to display rule alert: {rule_info['rule_name']}")
                return False
            
        except Exception as e:
            self.logger.error(f"❌ Error displaying rule alert: {e}")
            traceback.print_exc()
            return False
    
    def _is_rule_in_cooldown(self, rule_signature: str) -> bool:
        """Check if rule alert is in cooldown period"""
        if rule_signature not in self.recent_rule_alerts:
            return False
        
        time_since = time.time() - self.recent_rule_alerts[rule_signature]
        return time_since < self.rule_alert_cooldown
    
    async def _show_rule_alert_notification(self, rule_info: Dict[str, Any]) -> bool:
        """
        HIỂN THỊ NOTIFICATION CHO RULE VIOLATION
        """
        try:
            title, message = self._prepare_rule_alert_content(rule_info)
            
            # METHOD 1: Plyer notification
            if self.plyer_available:
                success = await self._show_plyer_notification(title, message, rule_info)
                if success:
                    self.logger.info("✅ Rule alert shown via Plyer")
                    return True
            
            # METHOD 2: Windows Toast notification
            if self.toast_available and self.toast_notifier:
                success = await self._show_windows_toast(title, message, rule_info)
                if success:
                    self.logger.info("✅ Rule alert shown via Windows Toast")
                    return True
            
            # METHOD 3: PowerShell balloon tip
            success = await self._show_powershell_balloon(title, message, rule_info)
            if success:
                self.logger.info("✅ Rule alert shown via PowerShell balloon")
                return True
            
            # METHOD 4: Console notification
            self._show_console_notification(title, message, rule_info)
            self.logger.info("✅ Rule alert shown in console")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ All notification methods failed: {e}")
            return False
    
    async def _send_rule_alert_acknowledgment(self, alert: Dict[str, Any]):
        """Send rule alert acknowledgment back to server for database insert"""
        try:
            if not self.communication:
                self.logger.warning("⚠️ No communication available for rule alert acknowledgment")
                return
            
            alert_id = alert.get('id', alert.get('alert_id'))
            if not alert_id:
                self.logger.warning("⚠️ No alert ID for rule acknowledgment")
                return
            
            # Check if already acknowledged
            if alert_id in self.acknowledged_alerts:
                return
            
            # Prepare acknowledgment data for database insert
            ack_data = {
                'alert_id': alert_id,
                'rule_id': alert.get('rule_id'),
                'rule_name': alert.get('rule_name', alert.get('rule_triggered')),
                'agent_id': getattr(self.communication, 'agent_id', None),
                'status': 'acknowledged',
                'acknowledged_at': datetime.now().isoformat(),
                'display_status': 'displayed',
                'notification_method': 'desktop_notification',
                'rule_violation': True,
                'severity': alert.get('severity'),
                'risk_score': alert.get('risk_score'),
                'detection_method': alert.get('detection_method'),
                'mitre_technique': alert.get('mitre_technique'),
                'mitre_tactic': alert.get('mitre_tactic'),
                'event_id': alert.get('event_id'),
                'process_name': alert.get('process_name'),
                'file_path': alert.get('file_path'),
                'user_action': 'auto_acknowledged_by_agent',
                'acknowledgment_type': 'rule_violation_display'
            }
            
            # Send acknowledgment to server for database insert
            if hasattr(self.communication, 'send_alert_acknowledgment'):
                success = await self.communication.send_alert_acknowledgment(ack_data)
                if success:
                    self.acknowledged_alerts.add(alert_id)
                    self.logger.info(f"✅ Rule alert acknowledgment sent to database: {alert_id}")
                else:
                    self.logger.warning(f"⚠️ Failed to send rule alert acknowledgment: {alert_id}")
            else:
                self.logger.warning("⚠️ Alert acknowledgment method not available")
            
        except Exception as e:
            self.logger.error(f"❌ Error sending rule alert acknowledgment: {e}")
    
    def _prepare_rule_alert_content(self, rule_info: Dict[str, Any]) -> tuple:
        """Prepare notification content for rule violation alert"""
        try:
            rule_name = rule_info.get('rule_name', 'Security Rule')
            severity = rule_info.get('severity', 'MEDIUM')
            risk_score = rule_info.get('risk_score', 50)
            description = rule_info.get('description', 'Security rule violation detected')
            
            # Create title với emoji cho rule violation
            severity_icons = {
                'CRITICAL': '🚨',
                'HIGH': '⚠️',
                'MEDIUM': '🔍',
                'LOW': 'ℹ️'
            }
            
            icon = severity_icons.get(severity, '🔔')
            title = f"{icon} SECURITY RULE VIOLATION - {severity}"
            
            # Create detailed message for rule violation
            message_parts = [
                f"🛡️ Security Rule Triggered:",
                f"Rule: {rule_name}",
                f"Risk Score: {risk_score}/100"
            ]
            
            # Add rule description if available
            rule_description = rule_info.get('rule_description')
            if rule_description and len(rule_description) < 100:
                message_parts.append(f"Rule: {rule_description}")
            
            # Add violation details
            if description and len(description) < 150:
                message_parts.append(f"Violation: {description}")
            
            # Add process info if available
            process_name = rule_info.get('process_name')
            if process_name:
                message_parts.append(f"Process: {process_name}")
            
            # Add MITRE info if available
            if rule_info.get('mitre_technique'):
                message_parts.append(f"MITRE: {rule_info['mitre_technique']}")
            
            # Add timestamp
            try:
                timestamp = rule_info.get('timestamp', datetime.now().isoformat())
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_str = dt.strftime('%H:%M:%S')
                message_parts.append(f"Time: {time_str}")
            except:
                pass
            
            message = "\n".join(message_parts)
            
            return title, message
            
        except Exception as e:
            self.logger.error(f"❌ Error preparing rule alert content: {e}")
            return "Security Rule Violation", "Security rule violation detected"
    
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
    
    async def _show_plyer_notification(self, title: str, message: str, rule_info: Dict[str, Any]) -> bool:
        """Show Plyer notification for rule violation"""
        try:
            if not self.plyer_available:
                return False
            
            def show_plyer():
                try:
                    self.plyer_notification.notify(
                        title=title,
                        message=message,
                        timeout=self.alert_duration,
                        app_name="EDR Security Agent"
                    )
                    return True
                except Exception as e:
                    self.logger.debug(f"Plyer notification error: {e}")
                    return False
            
            result = await asyncio.to_thread(show_plyer)
            
            if result and self.play_sound:
                await asyncio.to_thread(self._play_rule_violation_sound)
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Plyer notification failed: {e}")
            return False
    
    async def _show_windows_toast(self, title: str, message: str, rule_info: Dict[str, Any]) -> bool:
        """Show Windows Toast notification for rule violation"""
        try:
            if not self.toast_available or not self.toast_notifier:
                return False
            
            def show_toast():
                try:
                    self.toast_notifier.show_toast(
                        title=title,
                        msg=message,
                        duration=self.alert_duration,
                        threaded=True
                    )
                    return True
                except Exception as e:
                    self.logger.debug(f"Windows Toast error: {e}")
                    return False
            
            result = await asyncio.to_thread(show_toast)
            
            if result and self.play_sound:
                await asyncio.to_thread(self._play_rule_violation_sound)
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Windows Toast notification failed: {e}")
            return False
    
    async def _show_powershell_balloon(self, title: str, message: str, rule_info: Dict[str, Any]) -> bool:
        """Show PowerShell balloon tip for rule violation"""
        try:
            ps_script = f'''
Add-Type -AssemblyName System.Windows.Forms
$balloon = New-Object System.Windows.Forms.NotifyIcon
$balloon.Icon = [System.Drawing.SystemIcons]::Error
$balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Error
$balloon.BalloonTipText = "{message.replace('"', '""')}"
$balloon.BalloonTipTitle = "{title.replace('"', '""')}"
$balloon.Visible = $true
$balloon.ShowBalloonTip({self.alert_duration * 1000})
Start-Sleep -Seconds {self.alert_duration}
$balloon.Dispose()
'''
            
            def run_powershell():
                try:
                    result = subprocess.run(
                        ["powershell", "-Command", ps_script],
                        capture_output=True,
                        text=True,
                        timeout=self.alert_duration + 2
                    )
                    return result.returncode == 0
                except Exception as e:
                    self.logger.error(f"PowerShell balloon error: {e}")
                    return False
            
            result = await asyncio.to_thread(run_powershell)
            
            if result and self.play_sound:
                await asyncio.to_thread(self._play_rule_violation_sound)
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ PowerShell balloon notification failed: {e}")
            return False
    
    def _show_console_notification(self, title: str, message: str, rule_info: Dict[str, Any]):
        """Show console notification for rule violation"""
        try:
            rule_name = rule_info.get('rule_name', 'Unknown Rule')
            severity = rule_info.get('severity', 'MEDIUM')
            risk_score = rule_info.get('risk_score', 50)
            
            # Create visual separator
            separator = "=" * 120
            
            print(f"\n{separator}")
            print(f"🚨 SECURITY RULE VIOLATION DETECTED - {severity}")
            print(f"🛡️ Rule Name: {rule_name}")
            print(f"📊 Risk Score: {risk_score}/100")
            print(f"📋 Title: {title}")
            print(f"📝 Details: {message}")
            print(f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"⏱️  Alert Duration: {self.alert_duration} seconds")
            print(f"{separator}")
            
            # Flash console để thu hút sự chú ý
            try:
                import ctypes
                ctypes.windll.kernel32.SetConsoleTextAttribute(
                    ctypes.windll.kernel32.GetStdHandle(-11), 12)  # Red text
                print("🚨🚨🚨 SECURITY RULE VIOLATION DETECTED 🚨🚨🚨")
                print("🔔 Rule-based security alert from server")
                ctypes.windll.kernel32.SetConsoleTextAttribute(
                    ctypes.windll.kernel32.GetStdHandle(-11), 7)   # Reset to white
            except:
                print("🚨🚨🚨 SECURITY RULE VIOLATION DETECTED 🚨🚨🚨")
                print("🔔 Rule-based security alert from server")
            
        except Exception as e:
            self.logger.error(f"❌ Console notification error: {e}")
    
    def _play_rule_violation_sound(self):
        """Play alert sound for rule violations"""
        try:
            try:
                import winsound
                # Play critical system sound for rule violations
                winsound.PlaySound("SystemExclamation", winsound.SND_ALIAS | winsound.SND_ASYNC)
            except:
                try:
                    import winsound
                    # Rule violation beep pattern - more urgent
                    for _ in range(2):
                        winsound.Beep(1200, 400)  # 1200Hz for 400ms
                        time.sleep(0.1)
                        winsound.Beep(800, 200)   # 800Hz for 200ms
                        time.sleep(0.1)
                except:
                    # Fallback beep for rule violations
                    for _ in range(4):
                        print("\a", end="", flush=True)
                        time.sleep(0.15)
                    
        except Exception as e:
            self.logger.debug(f"Sound play error: {e}")
    
    def get_rule_alert_stats(self) -> Dict[str, Any]:
        """Get rule alert statistics"""
        try:
            return {
                'rule_alerts_received': self.rule_alerts_received,
                'rule_alerts_displayed': self.rule_alerts_displayed,
                'acknowledged_rule_alerts': len(self.acknowledged_alerts),
                'last_rule_alert_time': self.last_rule_alert_time.isoformat() if self.last_rule_alert_time else None,
                'plyer_available': self.plyer_available,
                'toast_available': self.toast_available,
                'recent_rule_alerts': len(self.recent_rule_alerts),
                'display_success_rate': (self.rule_alerts_displayed / max(self.rule_alerts_received, 1)) * 100,
                'server_rule_alerts_only_mode': True,
                'rule_alert_cooldown_seconds': self.rule_alert_cooldown
            }
        except Exception as e:
            self.logger.error(f"❌ Stats calculation error: {e}")
            return {}
    
    # Legacy methods for compatibility
    async def process_alert(self, alert: Dict):
        """Legacy method - only process if it's a server rule alert"""
        if alert.get('server_generated') and alert.get('rule_violation'):
            await self._display_rule_alert(alert)
        else:
            self.logger.debug("🔒 Non-rule alert ignored - server rule alerts only mode")
    
    async def send_notification(self, notification: Dict):
        """Legacy method - only process if it's a server rule notification"""
        if notification.get('server_generated') and notification.get('rule_violation'):
            await self._display_rule_alert(notification)
        else:
            self.logger.debug("🔒 Non-rule notification ignored - server rule alerts only mode")

def create_security_notifier(config_manager=None):
    """Factory function to create simple rule-based security notifier"""
    return SimpleRuleBasedAlertNotifier(config_manager)