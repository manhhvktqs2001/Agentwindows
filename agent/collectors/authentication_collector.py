from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, Severity, EventAction
from datetime import datetime
import getpass
import platform
import asyncio
import json
import time
import win32evtlog
import win32evtlogutil
import win32con
import win32security
from typing import List, Dict, Any, Optional
from collections import defaultdict

class AuthenticationCollector(BaseCollector):
    """Enhanced Authentication Activity Collector"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "AuthenticationCollector")
        
        # Enhanced configuration
        self.polling_interval = 15  # ENHANCED: Reduced from 30 to 15 seconds for continuous monitoring
        self.max_events_per_batch = 20  # ENHANCED: Increased batch size
        self.track_authentication_events = True
        self.monitor_failed_attempts = True
        
        # Authentication tracking
        self.known_events = set()
        self.failed_attempts = defaultdict(int)
        self.successful_logins = defaultdict(list)
        self.suspicious_activities = set()
        
        # Enhanced monitoring
        self.monitor_logins = True
        self.monitor_logouts = True
        self.monitor_failed_attempts = True
        self.monitor_privilege_changes = True
        self.monitor_account_changes = True
        self.monitor_password_changes = True
        
        # Event sources to monitor
        self.event_sources = [
            'Security',
            'Microsoft-Windows-Security-Auditing',
            'Microsoft-Windows-Winlogon',
            'Microsoft-Windows-Authentication'
        ]
        
        # Event IDs to monitor
        self.login_event_ids = [4624, 4625, 4647, 4648, 4778, 4779]
        self.logout_event_ids = [4634, 4647, 4778]
        self.failed_login_event_ids = [4625, 4648, 4779]
        self.privilege_event_ids = [4672, 4673, 4674, 4688]
        self.account_event_ids = [4720, 4722, 4724, 4728, 4732, 4738, 4740]
        self.password_event_ids = [4723, 4724, 4738]
        
        # Suspicious patterns
        self.suspicious_usernames = [
            'admin', 'administrator', 'root', 'system', 'guest',
            'test', 'demo', 'temp', 'user', 'default'
        ]
        
        self.suspicious_ips = set()
        self.failed_attempt_threshold = 5  # Alert after 5 failed attempts
        
        self.logger.info("🔐 Enhanced Authentication Collector initialized")
    
    async def initialize(self):
        """Initialize authentication collector with enhanced monitoring"""
        try:
            # Get initial authentication state
            await self._scan_recent_events()
            
            # Set up enhanced monitoring
            self._setup_authentication_monitoring()
            
            # Load suspicious IPs
            await self._load_suspicious_ips()
            
            self.logger.info(f"✅ Enhanced Authentication Collector initialized - Monitoring {len(self.known_events)} events")
            
        except Exception as e:
            self.logger.error(f"❌ Authentication collector initialization failed: {e}")
            raise
    
    def _setup_authentication_monitoring(self):
        """Set up enhanced authentication monitoring"""
        try:
            # Set up authentication event callbacks
            self._setup_authentication_callbacks()
            
        except Exception as e:
            self.logger.error(f"Authentication monitoring setup failed: {e}")
    
    def _setup_authentication_callbacks(self):
        """Set up authentication event callbacks for real-time monitoring"""
        try:
            # This would integrate with Windows Event Log API for real-time events
            # For now, we use polling with enhanced frequency
            pass
        except Exception as e:
            self.logger.debug(f"Authentication callbacks setup failed: {e}")
    
    async def collect_data(self) -> List[EventData]:
        """Collect authentication data with enhanced monitoring"""
        try:
            events = []
            
            # ENHANCED: Collect new authentication events
            new_events = await self._detect_new_authentication_events()
            events.extend(new_events)
            
            # ENHANCED: Monitor failed login attempts
            failed_events = await self._monitor_failed_attempts()
            events.extend(failed_events)
            
            # ENHANCED: Monitor successful logins
            login_events = await self._monitor_successful_logins()
            events.extend(login_events)
            
            # ENHANCED: Monitor privilege changes
            privilege_events = await self._monitor_privilege_changes()
            events.extend(privilege_events)
            
            # ENHANCED: Monitor account changes
            account_events = await self._monitor_account_changes()
            events.extend(account_events)
            
            # ENHANCED: Monitor suspicious activities
            suspicious_events = await self._monitor_suspicious_activities()
            events.extend(suspicious_events)
            
            if events:
                self.logger.debug(f"📊 Collected {len(events)} authentication events")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Authentication data collection failed: {e}")
            return []
    
    async def _scan_recent_events(self):
        """Scan recent authentication events for baseline"""
        try:
            # Scan events from the last hour
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=1)
            
            for source in self.event_sources:
                await self._scan_event_source(source, start_time, end_time)
            
            self.logger.info(f"📋 Baseline scan: {len(self.known_events)} authentication events")
            
        except Exception as e:
            self.logger.error(f"Authentication scan failed: {e}")
    
    async def _scan_event_source(self, source: str, start_time: datetime, end_time: datetime):
        """Scan events from a specific source"""
        try:
            hand = win32evtlog.OpenEventLog(None, source)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            for event in events:
                try:
                    event_time = datetime.fromtimestamp(event.TimeGenerated)
                    
                    if start_time <= event_time <= end_time:
                        event_id = event.EventID & 0xFFFF
                        
                        # Check if this is an authentication event
                        if self._is_authentication_event(event_id):
                            event_key = f"{source}_{event_id}_{event_time.timestamp()}"
                            self.known_events.add(event_key)
                            
                            # Check if suspicious
                            if self._is_suspicious_authentication_event(event):
                                self.suspicious_activities.add(event_key)
                
                except Exception as e:
                    self.logger.debug(f"Event processing failed: {e}")
                    continue
            
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            self.logger.debug(f"Event source scan failed for {source}: {e}")
    
    async def _detect_new_authentication_events(self) -> List[EventData]:
        """Detect new authentication events"""
        try:
            events = []
            current_events = set()
            
            # Scan recent events (last 30 seconds)
            end_time = datetime.now()
            start_time = end_time - timedelta(seconds=30)
            
            for source in self.event_sources:
                await self._scan_event_source_for_new_events(source, start_time, end_time, current_events, events)
            
            # Update known events
            self.known_events = current_events
            
            return events
            
        except Exception as e:
            self.logger.error(f"New authentication event detection failed: {e}")
            return []
    
    async def _scan_event_source_for_new_events(self, source: str, start_time: datetime, end_time: datetime,
                                              current_events: set, events: List[EventData]):
        """Scan event source for new events"""
        try:
            hand = win32evtlog.OpenEventLog(None, source)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events_list = win32evtlog.ReadEventLog(hand, flags, 0)
            
            for event in events_list:
                try:
                    event_time = datetime.fromtimestamp(event.TimeGenerated)
                    
                    if start_time <= event_time <= end_time:
                        event_id = event.EventID & 0xFFFF
                        
                        # Check if this is an authentication event
                        if self._is_authentication_event(event_id):
                            event_key = f"{source}_{event_id}_{event_time.timestamp()}"
                            current_events.add(event_key)
                            
                            # Check if this is a new event
                            if event_key not in self.known_events:
                                # New authentication event detected
                                auth_event = self._create_authentication_event(event, source, event_id, event_time)
                                if auth_event:
                                    events.append(auth_event)
                                    
                                    # Update tracking
                                    if self._is_suspicious_authentication_event(event):
                                        self.suspicious_activities.add(event_key)
                                        self.logger.warning(f"🚨 Suspicious authentication event detected: {event_id}")
                
                except Exception as e:
                    self.logger.debug(f"Event processing failed: {e}")
                    continue
            
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            self.logger.debug(f"New event scan failed for {source}: {e}")
    
    async def _monitor_failed_attempts(self) -> List[EventData]:
        """Monitor failed login attempts"""
        try:
            events = []
            
            # Scan for failed login events
            end_time = datetime.now()
            start_time = end_time - timedelta(minutes=5)
            
            for source in self.event_sources:
                try:
                    hand = win32evtlog.OpenEventLog(None, source)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    
                    events_list = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    for event in events_list:
                        try:
                            event_time = datetime.fromtimestamp(event.TimeGenerated)
                            event_id = event.EventID & 0xFFFF
                            
                            if (start_time <= event_time <= end_time and 
                                event_id in self.failed_login_event_ids):
                                
                                # Extract username and IP from event
                                username, ip_address = self._extract_login_info(event)
                                
                                if username and ip_address:
                                    # Track failed attempts
                                    key = f"{username}_{ip_address}"
                                    self.failed_attempts[key] += 1
                                    
                                    # Check if threshold exceeded
                                    if self.failed_attempts[key] >= self.failed_attempt_threshold:
                                        event_data = self._create_authentication_event(
                                            event, source, event_id, event_time,
                                            additional_data={
                                                'failed_attempts': self.failed_attempts[key],
                                                'username': username,
                                                'ip_address': ip_address,
                                                'threshold_exceeded': True
                                            }
                                        )
                                        if event_data:
                                            events.append(event_data)
                                            self.logger.warning(f"🚨 Multiple failed login attempts: {username} from {ip_address}")
                        
                        except Exception as e:
                            self.logger.debug(f"Failed attempt event processing failed: {e}")
                            continue
                    
                    win32evtlog.CloseEventLog(hand)
                
                except Exception as e:
                    self.logger.debug(f"Failed attempt monitoring failed for {source}: {e}")
            
            return events
            
        except Exception as e:
            self.logger.error(f"Failed attempt monitoring failed: {e}")
            return []
    
    async def _monitor_successful_logins(self) -> List[EventData]:
        """Monitor successful logins"""
        try:
            events = []
            
            # Scan for successful login events
            end_time = datetime.now()
            start_time = end_time - timedelta(minutes=5)
            
            for source in self.event_sources:
                try:
                    hand = win32evtlog.OpenEventLog(None, source)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    
                    events_list = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    for event in events_list:
                        try:
                            event_time = datetime.fromtimestamp(event.TimeGenerated)
                            event_id = event.EventID & 0xFFFF
                            
                            if (start_time <= event_time <= end_time and 
                                event_id in self.login_event_ids):
                                
                                # Extract login info
                                username, ip_address = self._extract_login_info(event)
                                
                                if username and ip_address:
                                    # Track successful logins
                                    key = f"{username}_{ip_address}"
                                    self.successful_logins[key].append({
                                        'timestamp': event_time,
                                        'ip_address': ip_address,
                                        'event_id': event_id
                                    })
                                    
                                    # Check if suspicious
                                    if self._is_suspicious_login(username, ip_address):
                                        event_data = self._create_authentication_event(
                                            event, source, event_id, event_time,
                                            additional_data={
                                                'suspicious_login': True,
                                                'username': username,
                                                'ip_address': ip_address
                                            }
                                        )
                                        if event_data:
                                            events.append(event_data)
                                            self.logger.warning(f"🚨 Suspicious login detected: {username} from {ip_address}")
                        
                        except Exception as e:
                            self.logger.debug(f"Successful login event processing failed: {e}")
                            continue
                    
                    win32evtlog.CloseEventLog(hand)
                
                except Exception as e:
                    self.logger.debug(f"Successful login monitoring failed for {source}: {e}")
            
            return events
            
        except Exception as e:
            self.logger.error(f"Successful login monitoring failed: {e}")
            return []
    
    async def _monitor_privilege_changes(self) -> List[EventData]:
        """Monitor privilege changes"""
        try:
            events = []
            
            # Scan for privilege change events
            end_time = datetime.now()
            start_time = end_time - timedelta(minutes=10)
            
            for source in self.event_sources:
                try:
                    hand = win32evtlog.OpenEventLog(None, source)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    
                    events_list = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    for event in events_list:
                        try:
                            event_time = datetime.fromtimestamp(event.TimeGenerated)
                            event_id = event.EventID & 0xFFFF
                            
                            if (start_time <= event_time <= end_time and 
                                event_id in self.privilege_event_ids):
                                
                                event_data = self._create_authentication_event(
                                    event, source, event_id, event_time,
                                    additional_data={
                                        'privilege_change': True,
                                        'event_type': 'privilege_change'
                                    }
                                )
                                if event_data:
                                    events.append(event_data)
                                    self.logger.warning(f"🚨 Privilege change detected: Event ID {event_id}")
                        
                        except Exception as e:
                            self.logger.debug(f"Privilege change event processing failed: {e}")
                            continue
                    
                    win32evtlog.CloseEventLog(hand)
                
                except Exception as e:
                    self.logger.debug(f"Privilege change monitoring failed for {source}: {e}")
            
            return events
            
        except Exception as e:
            self.logger.error(f"Privilege change monitoring failed: {e}")
            return []
    
    async def _monitor_account_changes(self) -> List[EventData]:
        """Monitor account changes"""
        try:
            events = []
            
            # Scan for account change events
            end_time = datetime.now()
            start_time = end_time - timedelta(minutes=10)
            
            for source in self.event_sources:
                try:
                    hand = win32evtlog.OpenEventLog(None, source)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    
                    events_list = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    for event in events_list:
                        try:
                            event_time = datetime.fromtimestamp(event.TimeGenerated)
                            event_id = event.EventID & 0xFFFF
                            
                            if (start_time <= event_time <= end_time and 
                                event_id in self.account_event_ids):
                                
                                event_data = self._create_authentication_event(
                                    event, source, event_id, event_time,
                                    additional_data={
                                        'account_change': True,
                                        'event_type': 'account_change'
                                    }
                                )
                                if event_data:
                                    events.append(event_data)
                                    self.logger.warning(f"🚨 Account change detected: Event ID {event_id}")
                        
                        except Exception as e:
                            self.logger.debug(f"Account change event processing failed: {e}")
                            continue
                    
                    win32evtlog.CloseEventLog(hand)
                
                except Exception as e:
                    self.logger.debug(f"Account change monitoring failed for {source}: {e}")
            
            return events
            
        except Exception as e:
            self.logger.error(f"Account change monitoring failed: {e}")
            return []
    
    async def _monitor_suspicious_activities(self) -> List[EventData]:
        """Monitor suspicious authentication activities"""
        try:
            events = []
            
            # Check for suspicious patterns in recent events
            for event_key in list(self.suspicious_activities):
                try:
                    # Parse event key
                    parts = event_key.split('_')
                    if len(parts) >= 3:
                        source = parts[0]
                        event_id = int(parts[1])
                        timestamp = float(parts[2])
                        
                        event_time = datetime.fromtimestamp(timestamp)
                        
                        # Check if event is recent
                        if datetime.now() - event_time < timedelta(minutes=5):
                            event_data = self._create_authentication_event(
                                None, source, event_id, event_time,
                                additional_data={
                                    'suspicious_activity': True,
                                    'activity_type': 'suspicious_pattern'
                                }
                            )
                            if event_data:
                                events.append(event_data)
                
                except Exception:
                    continue
            
            return events
            
        except Exception as e:
            self.logger.error(f"Suspicious activity monitoring failed: {e}")
            return []
    
    async def _load_suspicious_ips(self):
        """Load suspicious IP addresses"""
        try:
            # This would load from threat intelligence feeds
            # For now, we'll use a basic list
            self.suspicious_ips = {
                '192.168.1.100',  # Example suspicious IP
                '10.0.0.50'       # Example suspicious IP
            }
            
        except Exception as e:
            self.logger.debug(f"Suspicious IP loading failed: {e}")
    
    def _is_authentication_event(self, event_id: int) -> bool:
        """Check if event ID is an authentication event"""
        return (event_id in self.login_event_ids or 
                event_id in self.logout_event_ids or 
                event_id in self.failed_login_event_ids or
                event_id in self.privilege_event_ids or
                event_id in self.account_event_ids or
                event_id in self.password_event_ids)
    
    def _is_suspicious_authentication_event(self, event) -> bool:
        """Check if authentication event is suspicious"""
        try:
            # This would implement suspicious pattern detection
            # For now, return False
            return False
        except:
            return False
    
    def _is_suspicious_login(self, username: str, ip_address: str) -> bool:
        """Check if login is suspicious"""
        try:
            # Check suspicious username
            if username.lower() in self.suspicious_usernames:
                return True
            
            # Check suspicious IP
            if ip_address in self.suspicious_ips:
                return True
            
            return False
            
        except:
            return False
    
    def _extract_login_info(self, event) -> tuple:
        """Extract username and IP address from event"""
        try:
            # This would parse event data to extract login information
            # For now, return placeholder values
            return "unknown_user", "unknown_ip"
        except:
            return None, None
    
    def _determine_authentication_severity(self, event_id: int, username: str = None, ip_address: str = None) -> Severity:
        """Determine severity based on authentication event"""
        # Failed login attempts
        if event_id in self.failed_login_event_ids:
            return Severity.HIGH
        
        # Privilege changes
        if event_id in self.privilege_event_ids:
            return Severity.HIGH
        
        # Account changes
        if event_id in self.account_event_ids:
            return Severity.MEDIUM
        
        # Successful logins
        if event_id in self.login_event_ids:
            if username and username.lower() in self.suspicious_usernames:
                return Severity.MEDIUM
            return Severity.LOW
        
        return Severity.LOW
    
    def _create_authentication_event(self, event, source: str, event_id: int, event_time: datetime,
                                   additional_data: Dict = None) -> EventData:
        """Create authentication event data"""
        try:
            return EventData(
                event_type=EventType.AUTHENTICATION,
                event_action=self._get_event_action(event_id),
                event_timestamp=event_time,
                severity=self._determine_authentication_severity(event_id),
                username=additional_data.get('username') if additional_data else None,
                source_ip=additional_data.get('ip_address') if additional_data else None,
                raw_event_data={
                    'event_source': source,
                    'event_id': event_id,
                    'event_time': event_time.isoformat(),
                    **(additional_data or {})
                }
            )
            
        except Exception as e:
            self.logger.error(f"Authentication event creation failed: {e}")
            return None
    
    def _get_event_action(self, event_id: int) -> EventAction:
        """Get event action from event ID"""
        if event_id in self.login_event_ids:
            return EventAction.LOGON
        elif event_id in self.logout_event_ids:
            return EventAction.LOGOFF
        elif event_id in self.failed_login_event_ids:
            return EventAction.FAILED_LOGIN
        elif event_id in self.privilege_event_ids:
            return EventAction.PRIVILEGE_CHANGE
        elif event_id in self.account_event_ids:
            return EventAction.ACCOUNT_CHANGE
        elif event_id in self.password_event_ids:
            return EventAction.PASSWORD_CHANGE
        else:
            return EventAction.OTHER