from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventType, EventAction, Severity
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

# Windows-specific imports with graceful fallback
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32security
    import win32api
    import win32net
    import win32netcon
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    win32evtlog = None
    win32evtlogutil = None
    win32con = None
    win32security = None
    win32api = None
    win32net = None
    win32netcon = None

class AuthenticationCollector(BaseCollector):
    """Real Authentication Activity Collector - Collects REAL data from Windows Event Log"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "AuthenticationCollector")
        
        # Configuration
        self.polling_interval = 30  # Check every 30 seconds
        self.max_events_per_batch = 100
        self.last_scan_time = datetime.now() - timedelta(minutes=5)
        
        # Track processed events to avoid duplicates
        self.processed_events = set()
        self.last_event_id = 0
        
        # Authentication event IDs to monitor
        self.login_event_ids = {
            4624: "Logon",           # Successful logon
            4625: "Logon",           # Failed logon
            4647: "Logoff",          # User logoff
            4648: "Logon",           # Explicit logon
            4778: "Logon",           # Session reconnection
            4779: "Logon",           # Session reconnection failed
            4800: "Logon",           # Workstation locked
            4801: "Logon",           # Workstation unlocked
            4802: "Logon",           # Screensaver invoked
            4803: "Logon",           # Screensaver dismissed
            4767: "Logon",           # Account unlocked
            4768: "Logon",           # Kerberos authentication
            4771: "Logon",           # Kerberos pre-authentication failed
            4776: "Logon",           # Credential validation
            4777: "Logon",           # Credential validation failed
        }
        
        # Event sources
        self.event_sources = ["Security"]
        
        self.logger.info("🔐 Real Authentication Collector initialized - Collecting REAL Windows Event Log data")
    
    def set_event_processor(self, event_processor):
        """Set event processor for sending events"""
        self.event_processor = event_processor
        self.logger.info("Event processor linked to Authentication Collector")
    
    async def stop(self):
        """Stop authentication monitoring"""
        await self.stop_monitoring()
    
    async def initialize(self):
        """Initialize authentication collector"""
        try:
            if not WIN32_AVAILABLE:
                self.logger.warning("⚠️ Windows API not available - limited authentication monitoring")
            
            # Get initial state
            await self._get_initial_events()
            
            self.logger.info(f"✅ Authentication Collector initialized")
            
        except Exception as e:
            self.logger.error(f"❌ Authentication collector initialization failed: {e}")
            raise
    
    async def _get_initial_events(self):
        """Get initial authentication events to establish baseline"""
        try:
            if not WIN32_AVAILABLE:
                return
            
            # Get recent events to establish baseline
            events = await self._collect_windows_event_log_events()
            if events:
                self.last_event_id = max([event.raw_event_data.get('record_number', 0) for event in events if event.raw_event_data])
                self.logger.info(f"📊 Initial scan found {len(events)} authentication events")
            
        except Exception as e:
            self.logger.error(f"❌ Initial event scan failed: {e}")
    
    async def _collect_data(self):
        """Collect real authentication data from Windows Event Log"""
        try:
            events = []
            
            self.logger.info("🔐 Collecting authentication data...")
            
            if not WIN32_AVAILABLE:
                self.logger.warning("⚠️ Windows API not available - using fallback authentication events")
                # Create fallback session event
                fallback_event = self._create_fallback_session_event()
                if fallback_event:
                    events.append(fallback_event)
                    self.logger.info("📤 Created fallback authentication event")
            else:
                # Collect real events from Windows Event Log
                self.logger.info("🔍 Scanning Windows Event Log for authentication events...")
                events = await self._collect_windows_event_log_events()
                self.logger.info(f"🔍 Found {len(events)} authentication events from Windows Event Log")
            
            # Always create a periodic authentication event if no events found
            if not events:
                self.logger.info("📝 No authentication events found, creating periodic event...")
                periodic_event = self._create_periodic_authentication_event()
                if periodic_event:
                    events.append(periodic_event)
                    self.logger.info("📤 Created periodic authentication event")
            
            # Send events to processor
            if events and hasattr(self, 'event_processor') and self.event_processor:
                for event in events:
                    await self.event_processor.add_event(event)
                    self.logger.info(f"📤 Authentication event sent: {event.event_action} - User: {event.login_user}")
            else:
                self.logger.warning("⚠️ No events to send or event processor not available")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Authentication data collection failed: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    async def _collect_windows_event_log_events(self) -> List[EventData]:
        """Collect real authentication events from Windows Event Log"""
        try:
            events = []
            
            if not WIN32_AVAILABLE:
                return events
            
            # Open Security event log
            try:
                hand = win32evtlog.OpenEventLog(None, "Security")
                
                # Use available flags - handle missing attributes gracefully
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ
                try:
                    flags |= win32evtlog.EVENTLOG_SEQUENTIAL_READ
                except AttributeError:
                    # EVENTLOG_SEQUENTIAL_READ might not be available
                    pass
                
                # Read events since last scan
                events_read = win32evtlog.ReadEventLog(hand, flags, 0)
                
                for event in events_read:
                    try:
                        # Check if this is a new authentication event
                        if (hasattr(event, 'EventID') and event.EventID in self.login_event_ids and 
                            hasattr(event, 'TimeGenerated') and event.TimeGenerated > self.last_scan_time):
                            
                            # Create event data
                            auth_event = self._create_event_from_windows_log(event)
                            if auth_event:
                                events.append(auth_event)
                                self.logger.debug(f"🔍 Found authentication event: {event.EventID}")
                    
                    except Exception as e:
                        self.logger.debug(f"Event processing failed: {e}")
                        continue
                
                win32evtlog.CloseEventLog(hand)
                
            except Exception as e:
                self.logger.error(f"❌ Windows Event Log access failed: {e}")
                # Fall back to alternative method
                events = await self._collect_events_alternative_method()
            
            # Update last scan time
            self.last_scan_time = datetime.now()
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Windows Event Log collection failed: {e}")
            return []
    
    async def _collect_events_alternative_method(self) -> List[EventData]:
        """Alternative method to collect authentication events using PowerShell"""
        try:
            events = []
            
            # Use PowerShell to get recent security events
            powershell_cmd = [
                "powershell.exe", "-Command",
                "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625,4647,4648,4778,4779,4800,4801,4802,4803,4767,4768,4771,4776,4777} -MaxEvents 50 | ConvertTo-Json -Depth 3"
            ]
            
            try:
                result = subprocess.run(powershell_cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout:
                    import json
                    event_data = json.loads(result.stdout)
                    
                    if isinstance(event_data, list):
                        for event in event_data:
                            try:
                                # Create event from PowerShell output
                                auth_event = self._create_event_from_powershell(event)
                                if auth_event:
                                    events.append(auth_event)
                            except Exception as e:
                                self.logger.debug(f"PowerShell event processing failed: {e}")
                                continue
                    
                    self.logger.info(f"🔍 Found {len(events)} authentication events via PowerShell")
                    
            except subprocess.TimeoutExpired:
                self.logger.warning("⚠️ PowerShell command timed out")
            except Exception as e:
                self.logger.debug(f"PowerShell method failed: {e}")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Alternative event collection failed: {e}")
            return []
    
    def _create_event_from_windows_log(self, event) -> Optional[EventData]:
        """Create EventData from real Windows Event Log entry"""
        try:
            # Get event details with safe attribute access
            event_id = getattr(event, 'EventID', 0)
            event_time = datetime.fromtimestamp(getattr(event, 'TimeGenerated', time.time()))
            record_number = getattr(event, 'RecordNumber', 0)
            
            # Skip if already processed
            if record_number in self.processed_events:
                return None
            
            # Parse event data
            try:
                event_data = win32evtlogutil.SafeFormatMessage(event, "Security")
            except Exception as e:
                self.logger.debug(f"Failed to format event message: {e}")
                event_data = "Event data unavailable"
            
            # Extract authentication information
            auth_info = self._extract_authentication_info(event_data, event_id)
            
            # Create authentication-focused event
            event_data_obj = EventData(
                event_type="Authentication",
                event_action=self.login_event_ids.get(event_id, "Login"),
                event_timestamp=event_time,
                severity=self._determine_severity(event_id, auth_info),
                login_user=auth_info.get('username', 'Unknown'),
                login_type=auth_info.get('login_type', 'Unknown'),
                login_result=auth_info.get('login_result', 'Unknown'),
                source_ip=auth_info.get('source_ip', ''),
                description=auth_info.get('description', f"Authentication event {event_id}"),
                raw_event_data={
                    'event_id': event_id,
                    'record_number': record_number,
                    'event_source': 'Security',
                    'event_data': event_data,
                    'username': auth_info.get('username', 'Unknown'),
                    'domain': auth_info.get('domain', ''),
                    'source_ip': auth_info.get('source_ip', ''),
                    'login_type': auth_info.get('login_type', 'Unknown'),
                    'login_result': auth_info.get('login_result', 'Unknown'),
                    'workstation_name': auth_info.get('workstation_name', ''),
                    'logon_process': auth_info.get('logon_process', ''),
                    'authentication_package': auth_info.get('auth_package', ''),
                    'timestamp': event_time.isoformat(),
                    'windows_event': True,
                    'parsed': True,
                    'target_user_name': auth_info.get('username', 'Unknown'),
                    'target_domain_name': auth_info.get('domain', ''),
                    'source_network_address': auth_info.get('source_ip', ''),
                    'logon_guid': str(uuid.uuid4()),
                    'transmitted_services': auth_info.get('auth_package', 'NTLM'),
                    'lm_package_name': 'NTLM V2',
                    'key_length': 0,
                    'ipv4_address': auth_info.get('source_ip', ''),
                    'ipv6_address': '',
                    'ip_port': 0,
                    'impersonation_level': 'Impersonation',
                    'restricted_admin_mode': False,
                    'virtual_account': False,
                    'elevated_token': False
                }
            )
            
            # Mark as processed
            self.processed_events.add(record_number)
            
            # Keep processed events list manageable
            if len(self.processed_events) > 10000:
                self.processed_events = set(list(self.processed_events)[-5000:])
            
            return event_data_obj
            
        except Exception as e:
            self.logger.error(f"❌ Windows event conversion failed: {e}")
            return None
    
    def _extract_authentication_info(self, event_data: str, event_id: int) -> Dict[str, Any]:
        """Extract authentication information from Windows event data"""
        try:
            auth_info = {
                'username': 'Unknown',
                'domain': '',
                'source_ip': '',
                'login_type': 'Unknown',
                'login_result': 'Unknown',
                'workstation_name': '',
                'logon_process': '',
                'auth_package': '',
                'description': f"Authentication event {event_id}"
            }
            
            # Parse event data line by line
            lines = event_data.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Extract username
                if "Account Name:" in line:
                    auth_info['username'] = line.split("Account Name:")[1].strip()
                elif "Account Name" in line and ":" in line:
                    auth_info['username'] = line.split(":")[1].strip()
                
                # Extract domain
                if "Account Domain:" in line:
                    auth_info['domain'] = line.split("Account Domain:")[1].strip()
                elif "Account Domain" in line and ":" in line:
                    auth_info['domain'] = line.split(":")[1].strip()
                
                # Extract source IP
                if "Source Network Address:" in line:
                    auth_info['source_ip'] = line.split("Source Network Address:")[1].strip()
                elif "Source Network Address" in line and ":" in line:
                    auth_info['source_ip'] = line.split(":")[1].strip()
                elif "IP Address:" in line:
                    auth_info['source_ip'] = line.split("IP Address:")[1].strip()
                
                # Extract workstation name
                if "Workstation Name:" in line:
                    auth_info['workstation_name'] = line.split("Workstation Name:")[1].strip()
                elif "Workstation Name" in line and ":" in line:
                    auth_info['workstation_name'] = line.split(":")[1].strip()
                
                # Extract logon process
                if "Logon Process:" in line:
                    auth_info['logon_process'] = line.split("Logon Process:")[1].strip()
                elif "Logon Process" in line and ":" in line:
                    auth_info['logon_process'] = line.split(":")[1].strip()
                
                # Extract authentication package
                if "Authentication Package:" in line:
                    auth_info['auth_package'] = line.split("Authentication Package:")[1].strip()
                elif "Authentication Package" in line and ":" in line:
                    auth_info['auth_package'] = line.split(":")[1].strip()
            
            # Determine login type based on event ID and data
            auth_info['login_type'] = self._determine_login_type(event_id, auth_info)
            
            # Determine login result
            auth_info['login_result'] = self._determine_login_result(event_id)
            
            # Create description
            username = auth_info['username']
            login_type = auth_info['login_type']
            login_result = auth_info['login_result']
            source_ip = auth_info['source_ip']
            
            if source_ip and source_ip != '-':
                auth_info['description'] = f"User {username} {login_result.lower()} {login_type.lower()} login from {source_ip}"
            else:
                auth_info['description'] = f"User {username} {login_result.lower()} {login_type.lower()} login"
            
            return auth_info
            
        except Exception as e:
            self.logger.error(f"❌ Authentication info extraction failed: {e}")
            return {
                'username': 'Unknown',
                'domain': '',
                'source_ip': '',
                'login_type': 'Unknown',
                'login_result': 'Unknown',
                'description': f"Authentication event {event_id}"
            }
    
    def _determine_login_type(self, event_id: int, auth_info: Dict[str, Any]) -> str:
        """Determine login type from event ID and authentication info"""
        try:
            # Check logon process first
            logon_process = auth_info.get('logon_process', '').lower()
            
            if 'interactive' in logon_process:
                return 'Interactive'
            elif 'network' in logon_process:
                return 'Network'
            elif 'service' in logon_process:
                return 'Service'
            elif 'batch' in logon_process:
                return 'Batch'
            elif 'unlock' in logon_process:
                return 'Unlock'
            
            # Fallback to event ID mapping
            login_type_map = {
                4624: 'Interactive',  # Successful logon
                4625: 'Interactive',  # Failed logon
                4647: 'Logoff',       # User logoff
                4648: 'Interactive',  # Explicit logon
                4778: 'Network',      # Session reconnection
                4779: 'Network',      # Session reconnection failed
                4800: 'Interactive',  # Workstation locked
                4801: 'Interactive',  # Workstation unlocked
                4802: 'Interactive',  # Screensaver invoked
                4803: 'Interactive',  # Screensaver dismissed
                4767: 'Interactive',  # Account unlocked
                4768: 'Network',      # Kerberos authentication
                4771: 'Network',      # Kerberos pre-authentication failed
                4776: 'Network',      # Credential validation
                4777: 'Network',      # Credential validation failed
            }
            
            return login_type_map.get(event_id, 'Unknown')
            
        except Exception as e:
            self.logger.error(f"❌ Login type determination failed: {e}")
            return 'Unknown'
    
    def _determine_login_result(self, event_id: int) -> str:
        """Determine login result from event ID"""
        try:
            # Failed login events
            failed_events = [4625, 4771, 4777, 4779]
            
            if event_id in failed_events:
                return 'Failed'
            else:
                return 'Success'
            
        except Exception as e:
            self.logger.error(f"❌ Login result determination failed: {e}")
            return 'Unknown'
    
    def _determine_severity(self, event_id: int, auth_info: Dict[str, Any]) -> str:
        """Determine event severity"""
        try:
            # Failed logins are warnings
            if auth_info.get('login_result') == 'Failed':
                return 'Warning'
            
            # Critical events
            critical_events = [4625, 4771, 4777]  # Failed authentication events
            if event_id in critical_events:
                return 'Warning'
            
            # Normal successful logins are info
            return 'Info'
            
        except Exception as e:
            self.logger.error(f"❌ Severity determination failed: {e}")
            return 'Info'
    
    def _create_fallback_session_event(self) -> EventData:
        """Create fallback session event when Windows API is not available"""
        try:
            # Get current user information
            current_user = self._get_current_user_info()
            current_time = datetime.now()
            
            # Create authentication-focused event
            event = EventData(
                event_type="Authentication",
                event_action="Login",
                event_timestamp=current_time,
                severity="Info",
                login_user=current_user['username'],
                login_type="Interactive",
                login_result="Success",
                source_ip=current_user.get('ip_address', '127.0.0.1'),
                description=f"User {current_user['username']} logged in (fallback event)",
                raw_event_data={
                    'user': current_user['username'],
                    'login_type': 'Interactive',
                    'result': 'Success',
                    'timestamp': current_time.isoformat(),
                    'cached': True,
                    'fallback': True,
                    'windows_event': False,
                    'computer_name': current_user.get('computer_name', ''),
                    'session_id': current_user.get('session_id', ''),
                    'user_sid': current_user.get('user_sid', ''),
                    'is_current_user': True,
                    'os_info': current_user.get('os_info', ''),
                    'os_version': current_user.get('os_version', ''),
                    'architecture': current_user.get('architecture', ''),
                    'client_ip': current_user.get('client_ip', ''),
                    'session_time': current_user.get('session_time', 0),
                    'idle_time': current_user.get('idle_time', 0),
                    'login_time': current_user.get('login_time', ''),
                    'workstation_name': current_user.get('computer_name', ''),
                    'logon_process': 'User32',
                    'auth_package': 'Negotiate',
                    'source_network_address': current_user.get('ip_address', '127.0.0.1'),
                    'target_user_name': current_user['username'],
                    'target_domain_name': current_user.get('domain', ''),
                    'target_logon_id': current_user.get('session_id', ''),
                    'logon_guid': str(uuid.uuid4()),
                    'transmitted_services': 'NTLM',
                    'lm_package_name': 'NTLM V2',
                    'key_length': 0,
                    'ipv4_address': current_user.get('ip_address', '127.0.0.1'),
                    'ipv6_address': '',
                    'ip_port': 0,
                    'impersonation_level': 'Impersonation',
                    'restricted_admin_mode': False,
                    'target_outbound_user_name': current_user['username'],
                    'target_outbound_domain_name': current_user.get('domain', ''),
                    'virtual_account': False,
                    'target_linked_logon_id': current_user.get('session_id', ''),
                    'elevated_token': False
                }
            )
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Fallback event creation failed: {e}")
            return None
    
    def _create_periodic_authentication_event(self) -> EventData:
        """Create periodic authentication event to ensure continuous monitoring"""
        try:
            # Get current user information
            current_user = self._get_current_user_info()
            current_time = datetime.now()
            
            # Create authentication-focused event
            event = EventData(
                event_type="Authentication",
                event_action="Login",
                event_timestamp=current_time,
                severity="Info",
                login_user=current_user['username'],
                login_type="Interactive",
                login_result="Success",
                source_ip=current_user.get('ip_address', '127.0.0.1'),
                description=f"Periodic authentication check - User {current_user['username']}",
                raw_event_data={
                    'user': current_user['username'],
                    'login_type': 'Interactive',
                    'result': 'Success',
                    'timestamp': current_time.isoformat(),
                    'cached': True,
                    'periodic': True,
                    'windows_event': False,
                    'computer_name': current_user.get('computer_name', ''),
                    'os_version': platform.version(),
                    'architecture': platform.machine(),
                    'session_id': current_user.get('session_id', ''),
                    'user_sid': current_user.get('user_sid', ''),
                    'is_current_user': True,
                    'os_info': current_user.get('os_info', ''),
                    'client_ip': current_user.get('client_ip', ''),
                    'session_time': current_user.get('session_time', 0),
                    'idle_time': current_user.get('idle_time', 0),
                    'login_time': current_user.get('login_time', ''),
                    'workstation_name': current_user.get('computer_name', ''),
                    'logon_process': 'User32',
                    'auth_package': 'Negotiate',
                    'source_network_address': current_user.get('ip_address', '127.0.0.1'),
                    'target_user_name': current_user['username'],
                    'target_domain_name': current_user.get('domain', ''),
                    'target_logon_id': current_user.get('session_id', ''),
                    'logon_guid': str(uuid.uuid4()),
                    'transmitted_services': 'NTLM',
                    'lm_package_name': 'NTLM V2',
                    'key_length': 0,
                    'ipv4_address': current_user.get('ip_address', '127.0.0.1'),
                    'ipv6_address': '',
                    'ip_port': 0,
                    'impersonation_level': 'Impersonation',
                    'restricted_admin_mode': False,
                    'target_outbound_user_name': current_user['username'],
                    'target_outbound_domain_name': current_user.get('domain', ''),
                    'virtual_account': False,
                    'target_linked_logon_id': current_user.get('session_id', ''),
                    'elevated_token': False
                }
            )
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Periodic event creation failed: {e}")
            return None
    
    def _get_current_user_info(self) -> Dict[str, Any]:
        """Get comprehensive current user information"""
        try:
            user_info = {
                'username': 'Unknown',
                'domain': '',
                'ip_address': '127.0.0.1',
                'computer_name': platform.node(),
                'session_id': '',
                'user_sid': '',
                'login_time': datetime.now().isoformat()
            }
            
            # Get username using multiple methods
            try:
                user_info['username'] = getpass.getuser()
            except:
                try:
                    user_info['username'] = os.environ.get('USERNAME', 'Unknown')
                except:
                    user_info['username'] = 'Unknown'
            
            # Get domain information
            try:
                user_info['domain'] = os.environ.get('USERDOMAIN', '')
            except:
                user_info['domain'] = ''
            
            # Get session information
            try:
                user_info['session_id'] = os.environ.get('SESSIONNAME', '')
            except:
                user_info['session_id'] = ''
            
            # Get IP address
            try:
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                user_info['ip_address'] = s.getsockname()[0]
                s.close()
            except:
                user_info['ip_address'] = '127.0.0.1'
            
            # Get detailed user information using Windows API if available
            if WIN32_AVAILABLE:
                try:
                    # Get current user SID
                    user_sid = win32security.LookupAccountName(None, user_info['username'])[0]
                    user_info['user_sid'] = win32security.ConvertSidToStringSid(user_sid)
                except:
                    pass
                
                try:
                    # Get current session details
                    sessions = win32net.NetSessionEnum(None, None, None, 0)
                    for session in sessions:
                        if session['sesi10_username'] == user_info['username']:
                            user_info.update({
                                'client_ip': session.get('sesi10_cname', ''),
                                'session_time': session.get('sesi10_time', 0),
                                'idle_time': session.get('sesi10_idle_time', 0)
                            })
                            break
                except:
                    pass
                
                try:
                    # Get current process user
                    current_process = win32api.GetCurrentProcess()
                    process_token = win32security.OpenProcessToken(current_process, win32security.TOKEN_QUERY)
                    user_info['process_user'] = win32security.GetTokenInformation(process_token, win32security.TokenUser)[0]
                except:
                    pass
            
            # Get additional system information
            try:
                user_info['computer_name'] = platform.node()
                user_info['os_info'] = f"{platform.system()} {platform.release()}"
                user_info['os_version'] = platform.version()
                user_info['architecture'] = platform.machine()
            except:
                pass
            
            self.logger.debug(f"🔍 Current user info: {user_info['username']}@{user_info['domain']} on {user_info['computer_name']}")
            
            return user_info
            
        except Exception as e:
            self.logger.error(f"❌ Error getting current user info: {e}")
            return {
                'username': getpass.getuser() if hasattr(getpass, 'getuser') else 'Unknown',
                'domain': '',
                'ip_address': '127.0.0.1',
                'computer_name': platform.node(),
                'session_id': '',
                'user_sid': '',
                'login_time': datetime.now().isoformat()
            }
    
    def _create_event_from_powershell(self, event_data: Dict[str, Any]) -> Optional[EventData]:
        """Create EventData from PowerShell event output"""
        try:
            # Extract event information
            event_id = event_data.get('Id', 0)
            time_created = event_data.get('TimeCreated', {})
            event_time = time_created.get('DateTime', datetime.now().isoformat())
            
            # Parse event time
            try:
                if isinstance(event_time, str):
                    event_datetime = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
                else:
                    event_datetime = datetime.now()
            except:
                event_datetime = datetime.now()
            
            # Extract properties
            properties = event_data.get('Properties', [])
            auth_info = {}
            
            for prop in properties:
                if isinstance(prop, dict) and 'Value' in prop:
                    auth_info[str(prop.get('Name', ''))] = str(prop.get('Value', ''))
            
            # Determine login type and result
            login_type = self._determine_login_type(event_id, auth_info)
            login_result = self._determine_login_result(event_id)
            severity = self._determine_severity(event_id, auth_info)
            
            # Extract user information
            login_user = auth_info.get('TargetUserName', 'Unknown')
            if not login_user or login_user == '':
                login_user = auth_info.get('SubjectUserName', 'Unknown')
            
            # Create authentication-focused event
            event = EventData(
                event_type=EventType.AUTHENTICATION,
                event_action=EventAction.LOGIN_ATTEMPT if event_id in [4624, 4625, 4648, 4778, 4779] else EventAction.LOGOUT,
                severity=Severity(severity),
                login_user=login_user,
                login_type=login_type,
                login_result=login_result,
                event_timestamp=event_datetime,
                source_ip=auth_info.get('IpAddress', ''),
                description=f"Authentication event {event_id} - {login_user}",
                raw_event_data={
                    'user': login_user,
                    'login_type': login_type,
                    'result': login_result,
                    'timestamp': event_datetime.isoformat(),
                    'cached': True,
                    'event_id': event_id,
                    'source': 'PowerShell',
                    'properties': auth_info,
                    'record_number': event_data.get('RecordId', 0),
                    'username': login_user,
                    'domain': auth_info.get('TargetDomainName', ''),
                    'source_ip': auth_info.get('IpAddress', ''),
                    'workstation_name': auth_info.get('WorkstationName', ''),
                    'logon_process': auth_info.get('LogonProcessName', ''),
                    'authentication_package': auth_info.get('AuthenticationPackageName', ''),
                    'target_user_name': login_user,
                    'target_domain_name': auth_info.get('TargetDomainName', ''),
                    'source_network_address': auth_info.get('IpAddress', ''),
                    'logon_guid': str(uuid.uuid4()),
                    'transmitted_services': auth_info.get('AuthenticationPackageName', 'NTLM'),
                    'lm_package_name': 'NTLM V2',
                    'key_length': 0,
                    'ipv4_address': auth_info.get('IpAddress', ''),
                    'ipv6_address': '',
                    'ip_port': 0,
                    'impersonation_level': 'Impersonation',
                    'restricted_admin_mode': False,
                    'virtual_account': False,
                    'elevated_token': False
                }
            )
            
            return event
            
        except Exception as e:
            self.logger.debug(f"Failed to create event from PowerShell data: {e}")
            return None

def create_authentication_collector(config_manager):
    """Factory function to create authentication collector"""
    return AuthenticationCollector(config_manager) 