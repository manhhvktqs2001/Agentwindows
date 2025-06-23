# agent/utils/security_notifications.py - PLYER-ONLY NOTIFICATIONS
"""
Security Alert Notification System - Using Plyer Exclusively for Windows Toast
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
import traceback

# --- PLYER-ONLY NOTIFICATION SETUP ---
# We will only attempt to import and use plyer for GUI notifications.
PLYER_AVAILABLE = False
try:
    from plyer import notification
    PLYER_AVAILABLE = True
    print("🔔 Plyer notification system loaded and ready.")
except ImportError:
    print("⚠️ Plyer not found. GUI notifications are disabled. Alerts will appear in the console.")
    # No other libraries will be attempted.

class SecurityAlertNotifier:
    """Security Alert Notifier using Plyer exclusively for toast notifications."""
    
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
        self.toast_duration = 2  # seconds
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
        
        if PLYER_AVAILABLE:
            self.logger.info("Security Alert Notifier initialized to use Plyer.")
        else:
            self.logger.warning("Security Alert Notifier: Plyer not available, will fall back to console logging for alerts.")
    
    def set_communication(self, communication):
        """Set communication reference for alert acknowledgment"""
        self.communication = communication
        self.logger.info("Communication linked for alert acknowledgment")
    
    def _get_app_icon_path(self) -> Optional[str]:
        """Get path to application icon. Returns None if not found."""
        try:
            # Look for icon in various locations
            base_dir = Path(__file__).resolve().parent.parent.parent
            icon_paths = [
                base_dir / "assets" / "edr_icon.ico",
                base_dir / "edr_icon.ico",
            ]
            
            for icon_path in icon_paths:
                if icon_path.exists():
                    self.logger.info(f"Found app icon at: {icon_path}")
                    return str(icon_path)
            
            self.logger.warning("Custom EDR icon not found. Notifications will use a default icon.")
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting app icon path: {e}")
            return None
    
    async def process_server_alerts(self, server_response: Dict[str, Any], related_events: List = None):
        """Process alerts from server response - made async for proper threading"""
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
                # Show notification asynchronously
                await self._show_immediate_notification(alert, related_events)
                
        except Exception as e:
            self.logger.error(f"❌ Error processing server alerts: {e}")
    
    async def _show_immediate_notification(self, alert: Dict[str, Any], related_events: List = None):
        """Show notification - made async for proper threading"""
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
            
            # Show toast notification on screen
            await self._display_toast_notification(alert_info)
            
            # Track alert locally
            self._track_security_alert(alert_info)
            
        except Exception as e:
            self.logger.error(f"❌ Error showing immediate notification: {e}")
    
    async def _display_toast_notification(self, alert_info: Dict[str, Any]):
        """
        Displays a toast notification using Plyer by running it in a separate thread
        to avoid blocking the main asyncio event loop.
        """
        try:
            title, message = self._prepare_notification_content(alert_info)
            
            if PLYER_AVAILABLE:
                self.logger.info(f"🔔 Scheduling Plyer notification in a separate thread. Title: {title}")
                
                def blocking_notify():
                    """The actual blocking call to Plyer."""
                    try:
                        notification.notify(
                            title=title,
                            message=message,
                            timeout=self.toast_duration,
                            app_icon=self.app_icon,
                            app_name=self.app_name,
                            toast=True
                        )
                        self.logger.info("✅ Plyer notification call completed successfully in thread.")
                    except Exception as e:
                        self.logger.error(f"❌ Error inside Plyer notification thread: {e}", exc_info=True)

                try:
                    # Run the blocking function in a separate thread
                    await asyncio.to_thread(blocking_notify)
                    
                    if self.play_sound:
                        # Sound can also be blocking, run in thread too
                        await asyncio.to_thread(self._play_alert_sound)

                    return
                except Exception as e:
                    self.logger.error(f"❌ Failed to run notification in thread: {e}", exc_info=True)
            
            # Fallback for when Plyer is not available or fails
            self.logger.warning("Plyer not available or failed, showing alert in console as fallback.")
            self._show_console_notification(title, message, alert_info)
            
        except Exception as e:
            self.logger.error(f"❌ Failed to display any notification: {e}", exc_info=True)
    
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
            if PLYER_AVAILABLE:
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
        """Returns current security statistics."""
        return {
            "notifications_sent": self.notifications_sent,
            "notifications_failed": self.notifications_failed,
            "last_notification_time": self.last_notification_time.isoformat() if self.last_notification_time else None,
        }

def create_security_notifier(config_manager=None):
    """Factory function to create security notifier"""
    return SecurityAlertNotifier(config_manager)