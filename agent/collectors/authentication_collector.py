# agent/collectors/authentication_collector.py - ADMIN-ENHANCED USER SCANNING
"""
Admin-Enhanced Authentication Collector - Scans ALL users with admin privileges
Thu thập đầy đủ thông tin authentication: LoginUser, LoginType, LoginResult
Quét tất cả user trong máy bằng quyền Administrator
"""

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventAction, Severity
from datetime import datetime, timedelta
import getpass
import platform
import asyncio
import json
import time
import os
import subprocess
import re
from typing import List, Dict, Any, Optional
from collections import defaultdict
import uuid
import socket

# Windows-specific imports with graceful fallback
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32security
    import win32api
    import win32net
    import win32netcon
    import win32com.client
    import winreg
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

class AuthenticationCollector(BaseCollector):
    """Admin-Enhanced Authentication Collector - Scans ALL users with admin privileges"""
    def __init__(self, config_manager):
        super().__init__(config_manager, "AuthenticationCollector")
        self.polling_interval = 300  # 5 minutes
        self.logger.info("🔐 Admin-Enhanced Authentication Collector initialized - FULL USER SCANNING WITH ADMIN PRIVILEGES")
        self.scanned_users = set()  # Track scanned users to avoid duplicates
    
    async def _collect_data(self):
        """Collect authentication data from ALL users on the machine with admin privileges"""
        events = []
        try:
            self.logger.info("🔍 Starting comprehensive user scan with admin privileges...")
            
            # Method 1: Get current user
            current_user = self._get_current_user()
            if current_user:
                events.extend(self._create_user_events(current_user, "Current User"))
            
            # Method 2: Scan via WMI (Windows Management Instrumentation)
            wmi_users = self._scan_users_via_wmi()
            for user in wmi_users:
                if user not in self.scanned_users:
                    events.extend(self._create_user_events(user, "WMI User"))
                    self.scanned_users.add(user)
            
            # Method 3: Scan registry for users
            registry_users = self._scan_users_via_registry()
            for user in registry_users:
                if user not in self.scanned_users:
                    events.extend(self._create_user_events(user, "Registry User"))
                    self.scanned_users.add(user)
            
            # Method 4: Scan via net command (admin required)
            net_users = self._scan_users_via_net_command()
            for user in net_users:
                if user not in self.scanned_users:
                    events.extend(self._create_user_events(user, "Net User"))
                    self.scanned_users.add(user)
            
            # Method 5: Scan via PowerShell with bypass execution policy
            ps_users = self._scan_users_via_powershell_admin()
            for user in ps_users:
                if user not in self.scanned_users:
                    events.extend(self._create_user_events(user, "PowerShell User"))
                    self.scanned_users.add(user)
            
            # Method 6: Scan via Windows API with admin privileges
            api_users = self._scan_users_via_windows_api()
            for user in api_users:
                if user not in self.scanned_users:
                    events.extend(self._create_user_events(user, "Windows API User"))
                    self.scanned_users.add(user)
            
            # Method 7: Scan active sessions and processes
            session_users = self._scan_active_sessions_admin()
            for user in session_users:
                if user not in self.scanned_users:
                    events.extend(self._create_user_events(user, "Active Session User"))
                    self.scanned_users.add(user)
            
            # Method 8: Scan via wmic command
            wmic_users = self._scan_users_via_wmic()
            for user in wmic_users:
                if user not in self.scanned_users:
                    events.extend(self._create_user_events(user, "WMIC User"))
                    self.scanned_users.add(user)
            
            if events:
                self.logger.info(f"📤 Found {len(events)} authentication events from {len(self.scanned_users)} unique users")
                self.logger.info(f"🔍 Users found: {', '.join(list(self.scanned_users)[:10])}{'...' if len(self.scanned_users) > 10 else ''}")
                # DEBUG: Log each event being returned
                for i, event in enumerate(events):
                    self.logger.info(f"🔐 [DEBUG] Returning event {i+1}: {event.event_action} - {event.login_user}")
            else:
                self.logger.warning("⚠️ No authentication events found - check admin privileges")
            
        except Exception as e:
            self.logger.error(f"❌ Admin-enhanced authentication collection failed: {e}")
        
        return events
    
    def _get_current_user(self) -> Optional[str]:
        """Get current user via multiple methods"""
        try:
            # Method 1: getpass
            user = getpass.getuser()
            if user:
                return user
            
            # Method 2: os.environ
            user = os.environ.get('USERNAME') or os.environ.get('USER')
            if user:
                return user
            
            # Method 3: Windows API
            if WIN32_AVAILABLE:
                try:
                    user = win32api.GetUserName()
                    if user:
                        return user
                except:
                    pass
            
            return None
        except Exception as e:
            self.logger.debug(f"Current user detection failed: {e}")
            return None
    
    def _scan_users_via_wmi(self) -> List[str]:
        """Scan users via WMI (Windows Management Instrumentation)"""
        users = []
        try:
            if WIN32_AVAILABLE:
                # Use WMI to get all local users
                wmi = win32com.client.GetObject("winmgmts:")
                user_accounts = wmi.InstancesOf("Win32_UserAccount")
                
                for user_account in user_accounts:
                    username = user_account.Name
                    if username and username not in users:
                        users.append(username)
                        self.logger.debug(f"Found WMI user: {username}")
            
        except Exception as e:
            self.logger.debug(f"WMI user scan failed: {e}")
        
        return users
    
    def _scan_users_via_registry(self) -> List[str]:
        """Scan users via Windows Registry"""
        users = []
        try:
            # Scan SAM registry for users
            sam_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sam_key, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            if subkey_name.startswith('S-1-5-'):
                                try:
                                    with winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ) as subkey:
                                        try:
                                            profile_path = winreg.QueryValueEx(subkey, "ProfileImagePath")[0]
                                            if profile_path and "Users\\" in profile_path:
                                                username = profile_path.split("\\")[-1]
                                                if username and username not in users:
                                                    users.append(username)
                                                    self.logger.debug(f"Found registry user: {username}")
                                        except:
                                            pass
                                except:
                                    pass
                            i += 1
                        except WindowsError:
                            break
            except:
                pass
                
        except Exception as e:
            self.logger.debug(f"Registry user scan failed: {e}")
        
        return users
    
    def _scan_users_via_net_command(self) -> List[str]:
        """Scan users via net user command (requires admin)"""
        users = []
        try:
            # Use net user command to list all users
            cmd = ['net', 'user']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    # Parse net user output
                    if line.strip() and not line.startswith('The command completed'):
                        # Extract usernames from the output
                        parts = line.strip().split()
                        for part in parts:
                            if part and not part.startswith('\\') and part not in ['User', 'accounts', 'for']:
                                # Filter out invalid usernames (only dashes, too short, etc.)
                                if (part not in users and 
                                    len(part) > 1 and 
                                    not part.startswith('-') and 
                                    not part.endswith('-') and
                                    not all(c == '-' for c in part) and
                                    part.isprintable()):
                                    users.append(part)
                                    self.logger.debug(f"Found net user: {part}")
            
        except Exception as e:
            self.logger.debug(f"Net user command failed: {e}")
        
        return users
    
    def _scan_users_via_powershell_admin(self) -> List[str]:
        """Scan users via PowerShell with admin privileges"""
        users = []
        try:
            # PowerShell command with execution policy bypass
            cmd = [
                'powershell', '-ExecutionPolicy', 'Bypass', '-Command',
                'Get-LocalUser | Select-Object -ExpandProperty Name'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                user_lines = result.stdout.strip().split('\n')
                for line in user_lines:
                    user = line.strip()
                    if user and user not in ['', 'Name']:
                        users.append(user)
                        self.logger.debug(f"Found PowerShell user: {user}")
            
        except Exception as e:
            self.logger.debug(f"PowerShell admin user scan failed: {e}")
        
        return users
    
    def _scan_users_via_windows_api(self) -> List[str]:
        """Scan users via Windows API with admin privileges"""
        users = []
        try:
            if WIN32_AVAILABLE:
                # Use Windows API to enumerate users
                try:
                    # Get all local users via Windows API
                    users_info = win32net.NetUserEnum(None, 0)
                    for user_info in users_info[0]:
                        username = user_info['name']
                        if username and username not in users:
                            users.append(username)
                            self.logger.debug(f"Found Windows API user: {username}")
                except:
                    pass
                
        except Exception as e:
            self.logger.debug(f"Windows API user scan failed: {e}")
        
        return users
    
    def _scan_active_sessions_admin(self) -> List[str]:
        """Scan active user sessions with admin privileges"""
        users = []
        try:
            if WIN32_AVAILABLE:
                try:
                    # Get active sessions via Windows API
                    sessions = win32net.NetSessionEnum(None, None, None, 0)
                    for session in sessions:
                        if session.get('sesi10_username'):
                            user = session['sesi10_username']
                            if user not in users:
                                users.append(user)
                                self.logger.debug(f"Found active session user: {user}")
                except:
                    pass
                    
                # Also scan for logged-on users
                try:
                    logon_sessions = win32net.NetWkstaUserEnum(None, 0)
                    for session in logon_sessions[0]:
                        if session.get('wkui1_username'):
                            user = session['wkui1_username']
                            if user not in users:
                                users.append(user)
                                self.logger.debug(f"Found logged-on user: {user}")
                except:
                    pass
                    
        except Exception as e:
            self.logger.debug(f"Active session admin scan failed: {e}")
        
        return users
    
    def _scan_users_via_wmic(self) -> List[str]:
        """Scan users via WMIC command"""
        users = []
        try:
            # Use WMIC to get user accounts
            cmd = ['wmic', 'useraccount', 'get', 'name']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    user = line.strip()
                    if user and user not in ['', 'Name']:
                        users.append(user)
                        self.logger.debug(f"Found WMIC user: {user}")
            
        except Exception as e:
            self.logger.debug(f"WMIC user scan failed: {e}")
        
        return users
    
    def _create_user_events(self, username: str, user_type: str) -> List[EventData]:
        """Create authentication events for a user"""
        events = []
        try:
            # Get IP address
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip_address = s.getsockname()[0]
                s.close()
            except Exception:
                ip_address = '127.0.0.1'
            
            # Create login event
            login_event = EventData(
                event_type="Authentication",
                event_action=EventAction.LOGIN,
                event_timestamp=datetime.now(),
                severity="Info",
                login_user=username,
                login_type="Interactive",
                login_result="Success",
                source_ip=ip_address,
                description=f"🔐 USER LOGIN: {username} ({user_type})",
                raw_event_data={
                    'event_subtype': 'user_authentication',
                    'login_method': 'Interactive',
                    'login_source': 'Interactive',
                    'user_domain': username.split('\\')[0] if '\\' in username else None,
                    'user_name': username.split('\\')[-1] if '\\' in username else username,
                    'login_time': time.time(),
                    'is_current_user': username == self._get_current_user(),
                    'authentication_successful': True
                }
            )
            events.append(login_event)
            
            # Create session event
            session_event = EventData(
                event_type="Authentication",
                event_action=EventAction.SESSION,
                event_timestamp=datetime.now(),
                severity="Info",
                login_user=username,
                login_type="Session",
                login_result="Active",
                source_ip=ip_address,
                raw_event_data={
                    'username': username,
                    'user_type': user_type,
                    'session_type': 'Active',
                    'ip_address': ip_address,
                    'timestamp': datetime.now().isoformat(),
                    'detection_method': 'Admin-Enhanced User Scanner'
                }
            )
            events.append(session_event)
            
            self.logger.info(f"📤 Created authentication events for {user_type}: {username}")
            
        except Exception as e:
            self.logger.error(f"Failed to create events for user {username}: {e}")
        
        return events

def create_authentication_collector(config_manager):
    return AuthenticationCollector(config_manager)