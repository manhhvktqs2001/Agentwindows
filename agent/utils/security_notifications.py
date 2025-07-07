# agent/utils/security_notifications.py - FIXED ENHANCED ALERT SYSTEM
"""
Security Alert Notification System - FIXED TO DISPLAY ALL RULE-BASED ALERTS
Hiển thị cảnh báo từ server rules VÀ local rules
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
import platform

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
    """FIXED Alert Notifier - Hiển thị TẤT CẢ rule-based alerts"""
    
    def __init__(self, config_manager=None):
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager
        
        # Server communication reference
        self.communication = None
        
        # FIXED: Enhanced notification settings
        self.enabled = True
        self.show_server_rules = True
        self.show_local_rules = True
        self.show_risk_based_alerts = True
        self.show_on_screen = True
        self.play_sound = True
        self.alert_duration = 10  # Increase to 10 seconds
        
        # Initialize notification systems
        self.toast_available = WIN10TOAST_AVAILABLE
        self.toast_notifier = None
        self.toast_init_failed = False
        if self.toast_available:
            try:
                self.toast_notifier = ToastNotifier()
                self.logger.info("✅ Win10Toast notification available")
            except Exception as e:
                self.toast_available = False
                self.toast_init_failed = True
                self.logger.error(f"Win10Toast init error: {e}")
        
        # FIXED: Enhanced alert tracking
        self.total_alerts_received = 0
        self.total_alerts_displayed = 0
        self.server_rule_alerts = 0
        self.local_rule_alerts = 0
        self.risk_based_alerts = 0
        self.last_alert_time = None
        self.acknowledged_alerts = set()
        
        # Alert deduplication with longer window
        self.recent_alerts = {}
        self.alert_cooldown = 15  # 15 seconds cooldown
        
        # FIXED: Alert type tracking
        self.alert_types_displayed = {
            'server_rules': 0,
            'local_rules': 0,
            'risk_based': 0,
            'other': 0
        }
        
        self.logger.info(f"🔔 FIXED Alert Notifier initialized")
        self.logger.info(f"   Mode: ALL RULE-BASED ALERTS")
        self.logger.info(f"   Server Rules: {self.show_server_rules}")
        self.logger.info(f"   Local Rules: {self.show_local_rules}")
        self.logger.info(f"   Risk-Based: {self.show_risk_based_alerts}")
        self.logger.info(f"   Plyer: {PLYER_AVAILABLE}, Toast: {self.toast_available}")
    
    def set_communication(self, communication):
        """Set communication reference for acknowledgments"""
        self.communication = communication
        self.logger.info("Communication linked for alert acknowledgments")
    
    async def process_server_alerts(self, server_response: Dict[str, Any], related_events: Optional[List[Any]] = None):
        """
        FIXED: XỬ LÝ VÀ HIỂN THỊ CHỈ KHI CÓ RULE VIOLATIONS
        """
        try:
            alerts_to_display = []
            if related_events is None:
                related_events = []
            
            # FIXED: Check if there are actual rule violations
            threat_detected = server_response.get('threat_detected', False)
            risk_score = server_response.get('risk_score', 0)
            alerts_generated = server_response.get('alerts_generated', [])
            rule_triggered = server_response.get('rule_triggered')
            
            # FIXED: Only process if there's actual threat detection
            if not threat_detected and not alerts_generated and not rule_triggered and risk_score < 50:
                self.logger.debug("ℹ️ No rule violations detected - silent processing")
                return
            
            # CASE 1: Server gửi alerts_generated array
            if alerts_generated:
                self.logger.info(f"🔔 PROCESSING {len(alerts_generated)} RULE VIOLATIONS from server")
                for alert in alerts_generated:
                    if self._should_display_alert(alert):
                        alerts_to_display.append(alert)
                        self._classify_alert_type(alert)
            # CASE 2: Server gửi alerts array (alternative format)
            elif 'alerts' in server_response and server_response['alerts']:
                alerts = server_response['alerts']
                self.logger.info(f"🔔 PROCESSING {len(alerts)} RULE VIOLATIONS from alerts array")
                for alert in alerts:
                    if self._should_display_alert(alert):
                        alerts_to_display.append(alert)
                        self._classify_alert_type(alert)
            
            # FIXED: DISPLAY ONLY IF RULE VIOLATIONS DETECTED
            if alerts_to_display:
                self.total_alerts_received += len(alerts_to_display)
                self.last_alert_time = datetime.now()
                
                self.logger.critical("=" * 120)
                self.logger.critical(f"🚨 DISPLAYING {len(alerts_to_display)} RULE VIOLATIONS:")
                
                # Display each alert
                displayed_count = 0
                for alert in alerts_to_display:
                    try:
                        success = await self._display_enhanced_alert(alert)
                        if success:
                            await self._send_alert_acknowledgment(alert)
                            displayed_count += 1
                            self.total_alerts_displayed += 1
                    except Exception as e:
                        self.logger.error(f"❌ Failed to display alert: {e}")
                
                self.logger.critical(f"✅ SUCCESSFULLY DISPLAYED {displayed_count}/{len(alerts_to_display)} RULE VIOLATIONS")
                self.logger.critical("=" * 120)
                
                # Log alert type summary
                self._log_alert_summary()
            else:
                self.logger.debug("ℹ️ No rule violations to display")
                
        except Exception as e:
            self.logger.error(f"❌ Error processing server alerts: {e}")
            traceback.print_exc()
    
    def _should_display_alert(self, alert: Dict[str, Any]) -> bool:
        """FIXED: Check if alert should be displayed"""
        try:
            if not isinstance(alert, dict):
                return False
            
            # Check for basic alert structure
            has_id = alert.get('id') or alert.get('alert_id')
            has_rule = alert.get('rule_id') or alert.get('rule_name') or alert.get('rule_triggered')
            has_title = alert.get('title')
            has_description = alert.get('description')
            has_severity = alert.get('severity')
            
            # FIXED: Accept alerts with ANY of these fields
            if not (has_id or has_rule or has_title or has_description or has_severity):
                self.logger.debug("❌ Alert rejected: missing basic fields")
                return False
            
            # Check alert type preferences
            is_local_rule = alert.get('local_rule', False)
            is_server_rule = not is_local_rule and (has_rule or alert.get('server_generated', False))
            is_risk_based = alert.get('detection_method') == 'Risk Score Analysis'
            
            # FIXED: Check type preferences
            if is_local_rule and not self.show_local_rules:
                self.logger.debug("❌ Alert rejected: local rules disabled")
                return False
            
            if is_server_rule and not self.show_server_rules:
                self.logger.debug("❌ Alert rejected: server rules disabled")
                return False
            
            if is_risk_based and not self.show_risk_based_alerts:
                self.logger.debug("❌ Alert rejected: risk-based alerts disabled")
                return False
            
            # Check deduplication
            alert_signature = self._get_alert_signature(alert)
            if self._is_alert_in_cooldown(alert_signature):
                self.logger.debug(f"❌ Alert rejected: in cooldown - {alert_signature}")
                return False
            
            self.logger.debug(f"✅ Alert accepted for display: {alert.get('title', 'No title')}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error checking alert display: {e}")
            return False
    
    def _classify_alert_type(self, alert: Dict[str, Any]):
        """Classify and count alert types"""
        try:
            if alert.get('local_rule', False):
                self.alert_types_displayed['local_rules'] += 1
                self.local_rule_alerts += 1
            elif alert.get('detection_method') == 'Risk Score Analysis':
                self.alert_types_displayed['risk_based'] += 1
                self.risk_based_alerts += 1
            elif alert.get('server_generated', False) or alert.get('rule_id'):
                self.alert_types_displayed['server_rules'] += 1
                self.server_rule_alerts += 1
            else:
                self.alert_types_displayed['other'] += 1
        except Exception as e:
            self.logger.error(f"❌ Error classifying alert: {e}")
    
    def _convert_response_to_alert(self, server_response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Convert server response to alert format"""
        try:
            alert = {
                'id': f'response_alert_{int(time.time())}',
                'alert_id': f'response_alert_{int(time.time())}',
                'rule_id': server_response.get('rule_id'),
                'rule_name': server_response.get('rule_name', server_response.get('rule_triggered')),
                'rule_description': server_response.get('rule_description', ''),
                'title': f"Rule Triggered: {server_response.get('rule_triggered', 'Unknown Rule')}",
                'description': server_response.get('threat_description', 'Rule violation detected'),
                'severity': self._map_risk_to_severity(server_response.get('risk_score', 50)),
                'risk_score': server_response.get('risk_score', 50),
                'detection_method': server_response.get('detection_method', 'Rule Engine'),
                'mitre_technique': server_response.get('mitre_technique'),
                'mitre_tactic': server_response.get('mitre_tactic'),
                'event_id': server_response.get('event_id'),
                'timestamp': datetime.now().isoformat(),
                'server_generated': server_response.get('server_generated', True),
                'rule_violation': True,
                'local_rule': server_response.get('local_rule_triggered', False),
                'process_name': server_response.get('process_name'),
                'process_path': server_response.get('process_path'),
                'file_path': server_response.get('file_path')
            }
            
            return alert
            
        except Exception as e:
            self.logger.error(f"❌ Error converting response to alert: {e}")
            return None
    
    def _get_alert_signature(self, alert: Dict[str, Any]) -> str:
        """Get unique signature for alert deduplication"""
        try:
            rule_name = alert.get('rule_name', alert.get('title', 'unknown'))
            process_name = alert.get('process_name', 'unknown')
            return f"{rule_name}_{process_name}"
        except:
            return f"alert_{int(time.time())}"
    
    def _is_alert_in_cooldown(self, alert_signature: str) -> bool:
        """Check if alert is in cooldown period"""
        if alert_signature not in self.recent_alerts:
            return False
        
        time_since = time.time() - self.recent_alerts[alert_signature]
        return time_since < self.alert_cooldown
    
    async def _display_enhanced_alert(self, alert: Dict[str, Any]) -> bool:
        """
        FIXED: HIỂN THỊ ALERT VỚI ENHANCED NOTIFICATIONS
        """
        try:
            title, message = self._prepare_enhanced_alert_content(alert)
            # METHOD 1: Win10Toast notification
            if self.toast_available and self.toast_notifier is not None and not self.toast_init_failed:
                try:
                    if self.toast_notifier is None:
                        return False
                    self.toast_notifier.show_toast(
                        title=title,
                        msg=message,
                        duration=self.alert_duration,
                        threaded=True,
                        icon_path=None
                    )
                    self.logger.info("✅ Alert shown via Win10Toast")
                    self._mark_alert_displayed(alert)
                    return True
                except Exception as e:
                    self.logger.error(f"Win10Toast notification error: {e}")
                    self.toast_available = False  # Disable further attempts
                    self.toast_init_failed = True
            # METHOD 2: PowerShell balloon tip
            success = await self._show_enhanced_powershell_balloon(title, message, alert)
            if success:
                self.logger.info("✅ Alert shown via PowerShell balloon")
                self._mark_alert_displayed(alert)
                return True
            # METHOD 3: Enhanced console notification
            self._show_enhanced_console_notification(title, message, alert)
            self.logger.info("✅ Alert shown in console")
            self._mark_alert_displayed(alert)
            return False
        except Exception as e:
            self.logger.error(f"❌ All notification methods failed: {e}")
            return False
    
    def _prepare_enhanced_alert_content(self, alert: Dict[str, Any]) -> tuple:
        """Prepare enhanced notification content"""
        try:
            rule_name = alert.get('rule_name', alert.get('title', 'Security Alert'))
            severity = alert.get('severity', 'MEDIUM')
            risk_score = alert.get('risk_score', 50)
            description = alert.get('description', 'Security rule violation detected')
            
            # Determine alert type for display
            alert_type = "🔍 LOCAL RULE" if alert.get('local_rule') else "🚨 SERVER RULE"
            if alert.get('detection_method') == 'Risk Score Analysis':
                alert_type = "📊 RISK ANALYSIS"
            
            # Create title with type and severity
            severity_icons = {
                'CRITICAL': '🚨',
                'HIGH': '⚠️',
                'MEDIUM': '🔍',
                'LOW': 'ℹ️',
                'INFO': 'ℹ️'
            }
            
            icon = severity_icons.get(severity, '🔔')
            title = f"{icon} {alert_type} - {severity}"
            
            # Create detailed message
            message_parts = [
                f"🛡️ Rule: {rule_name}",
                f"📊 Risk Score: {risk_score}/100"
            ]
            
            # Add rule description if available
            rule_description = alert.get('rule_description')
            if rule_description and len(rule_description) < 100:
                message_parts.append(f"📋 Description: {rule_description}")
            
            # Add violation details
            if description and len(description) < 150:
                message_parts.append(f"⚠️ Details: {description}")
            
            # Add process info if available
            process_name = alert.get('process_name')
            if process_name:
                message_parts.append(f"🔧 Process: {process_name}")
            
            # Add detection method
            detection_method = alert.get('detection_method')
            if detection_method:
                message_parts.append(f"🔍 Method: {detection_method}")
            
            # Add MITRE info if available
            if alert.get('mitre_technique'):
                message_parts.append(f"🎯 MITRE: {alert['mitre_technique']}")
            
            # Add timestamp
            try:
                timestamp = alert.get('timestamp', datetime.now().isoformat())
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_str = dt.strftime('%H:%M:%S')
                message_parts.append(f"⏰ Time: {time_str}")
            except:
                pass
            
            message = "\n".join(message_parts)
            
            return title, message
            
        except Exception as e:
            self.logger.error(f"❌ Error preparing alert content: {e}")
            return "Security Alert", "Security rule violation detected"
    
    def _log_alert_details(self, alert: Dict[str, Any]):
        """Log detailed alert information"""
        try:
            alert_type = "LOCAL" if alert.get('local_rule') else "SERVER"
            rule_name = alert.get('rule_name', 'Unknown Rule')
            severity = alert.get('severity', 'MEDIUM')
            risk_score = alert.get('risk_score', 50)
            
            self.logger.critical(f"🔔 {alert_type} RULE ALERT:")
            self.logger.critical(f"   📋 Rule: {rule_name}")
            self.logger.critical(f"   📊 Severity: {severity}")
            self.logger.critical(f"   🎯 Risk Score: {risk_score}/100")
            
            if alert.get('process_name'):
                self.logger.critical(f"   🔧 Process: {alert['process_name']}")
            
            if alert.get('rule_description'):
                self.logger.critical(f"   📝 Description: {alert['rule_description']}")
            
            if alert.get('detection_method'):
                self.logger.critical(f"   🔍 Detection: {alert['detection_method']}")
            
        except Exception as e:
            self.logger.error(f"❌ Error logging alert details: {e}")
    
    def _mark_alert_displayed(self, alert: Dict[str, Any]):
        """Mark alert as displayed"""
        try:
            alert_signature = self._get_alert_signature(alert)
            self.recent_alerts[alert_signature] = time.time()
        except Exception as e:
            self.logger.error(f"❌ Error marking alert as displayed: {e}")
    
    async def _show_enhanced_windows_toast(self, title: str, message: str, alert: Dict[str, Any]) -> bool:
        """Show enhanced Windows Toast notification"""
        try:
            if not self.toast_available or self.toast_notifier is None or self.toast_init_failed:
                return False
            def show_toast():
                if self.toast_notifier is None:
                    return False
                try:
                    self.toast_notifier.show_toast(
                        title=title,
                        msg=message,
                        duration=self.alert_duration,
                        threaded=True,
                        icon_path=None
                    )
                    return True
                except Exception as e:
                    self.logger.debug(f"Windows Toast error: {e}")
                    self.toast_available = False
                    self.toast_init_failed = True
                    return False
            result = await asyncio.to_thread(show_toast)
            if result and self.play_sound:
                await asyncio.to_thread(self._play_alert_sound, alert)
            return result
        except Exception as e:
            self.logger.error(f"❌ Windows Toast notification failed: {e}")
            self.toast_available = False
            self.toast_init_failed = True
            return False
    
    async def _show_enhanced_powershell_balloon(self, title: str, message: str, alert: Dict[str, Any]) -> bool:
        """Show enhanced PowerShell balloon tip"""
        try:
            # Determine balloon icon based on severity
            severity = alert.get('severity', 'MEDIUM')
            if severity in ['CRITICAL', 'HIGH']:
                icon_type = 'Error'
            elif severity == 'MEDIUM':
                icon_type = 'Warning'
            else:
                icon_type = 'Info'
            
            ps_script = f'''
Add-Type -AssemblyName System.Windows.Forms
$balloon = New-Object System.Windows.Forms.NotifyIcon
$balloon.Icon = [System.Drawing.SystemIcons]::{icon_type}
$balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::{icon_type}
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
                await asyncio.to_thread(self._play_alert_sound, alert)
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ PowerShell balloon notification failed: {e}")
            return False
    
    def _show_enhanced_console_notification(self, title: str, message: str, alert: Dict[str, Any]):
        """Show enhanced console notification"""
        try:
            rule_name = alert.get('rule_name', 'Unknown Rule')
            severity = alert.get('severity', 'MEDIUM')
            risk_score = alert.get('risk_score', 50)
            alert_type = "LOCAL RULE" if alert.get('local_rule') else "SERVER RULE"
            
            # Create visual separator
            separator = "=" * 120
            
            print(f"\n{separator}")
            print(f"🚨 {alert_type} ALERT DETECTED - {severity}")
            print(f"🛡️ Rule Name: {rule_name}")
            print(f"📊 Risk Score: {risk_score}/100")
            print(f"📋 Title: {title}")
            print(f"📝 Details: {message}")
            print(f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"⏱️  Alert Duration: {self.alert_duration} seconds")
            print(f"{separator}")
            
            # Flash console based on severity
            try:
                import ctypes
                if severity in ['CRITICAL', 'HIGH']:
                    color = 12  # Red text
                    flash_text = "🚨🚨🚨 HIGH SEVERITY ALERT 🚨🚨🚨"
                elif severity == 'MEDIUM':
                    color = 14  # Yellow text
                    flash_text = "⚠️⚠️⚠️ MEDIUM SEVERITY ALERT ⚠️⚠️⚠️"
                else:
                    color = 11  # Cyan text
                    flash_text = "ℹ️ℹ️ℹ️ SECURITY ALERT ℹ️ℹ️ℹ️"
                
                ctypes.windll.kernel32.SetConsoleTextAttribute(
                    ctypes.windll.kernel32.GetStdHandle(-11), color)
                print(flash_text)
                print(f"🔔 {alert_type} - Rule-based security alert")
                ctypes.windll.kernel32.SetConsoleTextAttribute(
                    ctypes.windll.kernel32.GetStdHandle(-11), 7)   # Reset to white
            except:
                print(f"🚨🚨🚨 {alert_type} ALERT 🚨🚨🚨")
                print("🔔 Rule-based security alert")
            
        except Exception as e:
            self.logger.error(f"❌ Console notification error: {e}")
    
    def _play_alert_sound(self, alert: Dict[str, Any]):
        """Play alert sound based on severity"""
        try:
            severity = alert.get('severity', 'MEDIUM')
            
            try:
                import winsound
                if severity in ['CRITICAL', 'HIGH']:
                    # Critical/High severity - urgent sound
                    winsound.PlaySound("SystemExclamation", winsound.SND_ALIAS | winsound.SND_ASYNC)
                    for _ in range(3):
                        winsound.Beep(1200, 300)  # 1200Hz for 300ms
                        time.sleep(0.1)
                elif severity == 'MEDIUM':
                    # Medium severity - warning sound
                    winsound.PlaySound("SystemAsterisk", winsound.SND_ALIAS | winsound.SND_ASYNC)
                    for _ in range(2):
                        winsound.Beep(800, 200)   # 800Hz for 200ms
                        time.sleep(0.1)
                else:
                    # Low/Info severity - gentle sound
                    winsound.PlaySound("SystemQuestion", winsound.SND_ALIAS | winsound.SND_ASYNC)
                    winsound.Beep(600, 100)     # 600Hz for 100ms
            except:
                # Fallback beep pattern based on severity
                beep_count = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}
                for _ in range(beep_count.get(severity, 2)):
                    print("\a", end="", flush=True)
                    time.sleep(0.15)
                    
        except Exception as e:
            self.logger.debug(f"Sound play error: {e}")
    
    async def _send_alert_acknowledgment(self, alert: Dict[str, Any]):
        """Send alert acknowledgment to server"""
        try:
            if not self.communication:
                self.logger.warning("⚠️ No communication available for acknowledgment")
                return
            
            alert_id = alert.get('id', alert.get('alert_id'))
            if not alert_id:
                self.logger.warning("⚠️ No alert ID for acknowledgment")
                return
            
            # Check if already acknowledged
            if alert_id in self.acknowledged_alerts:
                return
            
            # Prepare acknowledgment data
            ack_data = {
                'alert_id': alert_id,
                'rule_id': alert.get('rule_id'),
                'rule_name': alert.get('rule_name'),
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
                'acknowledgment_type': 'rule_violation_display',
                'alert_type': 'local_rule' if alert.get('local_rule') else 'server_rule'
            }
            
            # Send acknowledgment
            if hasattr(self.communication, 'send_alert_acknowledgment'):
                success = await self.communication.send_alert_acknowledgment(ack_data)
                if success:
                    self.acknowledged_alerts.add(alert_id)
                    self.logger.info(f"✅ Alert acknowledgment sent: {alert_id}")
                else:
                    self.logger.warning(f"⚠️ Failed to send acknowledgment: {alert_id}")
            else:
                self.logger.warning("⚠️ Alert acknowledgment method not available")
            
        except Exception as e:
            self.logger.error(f"❌ Error sending acknowledgment: {e}")
    
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
    
    def _log_alert_summary(self):
        """Log summary of alert types displayed"""
        try:
            self.logger.info("📊 ALERT SUMMARY:")
            self.logger.info(f"   🔍 Local Rules: {self.alert_types_displayed['local_rules']}")
            self.logger.info(f"   🚨 Server Rules: {self.alert_types_displayed['server_rules']}")
            self.logger.info(f"   📊 Risk-Based: {self.alert_types_displayed['risk_based']}")
            self.logger.info(f"   📋 Other: {self.alert_types_displayed['other']}")
            self.logger.info(f"   📈 Total Displayed: {self.total_alerts_displayed}")
        except Exception as e:
            self.logger.error(f"❌ Error logging alert summary: {e}")
    
    def get_enhanced_stats(self) -> Dict[str, Any]:
        """Get enhanced alert statistics"""
        try:
            return {
                'total_alerts_received': self.total_alerts_received,
                'total_alerts_displayed': self.total_alerts_displayed,
                'server_rule_alerts': self.server_rule_alerts,
                'local_rule_alerts': self.local_rule_alerts,
                'risk_based_alerts': self.risk_based_alerts,
                'acknowledged_alerts': len(self.acknowledged_alerts),
                'last_alert_time': self.last_alert_time.isoformat() if self.last_alert_time else None,
                'alert_types_displayed': self.alert_types_displayed.copy(),
                'toast_available': self.toast_available,
                'recent_alerts': len(self.recent_alerts),
                'display_success_rate': (self.total_alerts_displayed / max(self.total_alerts_received, 1)) * 100,
                'enhanced_alert_system': True,
                'all_rule_types_supported': True,
                'alert_cooldown_seconds': self.alert_cooldown
            }
        except Exception as e:
            self.logger.error(f"❌ Stats calculation error: {e}")
            return {}

def create_security_notifier(config_manager=None):
    """Factory function to create enhanced security notifier"""
    return SimpleRuleBasedAlertNotifier(config_manager)