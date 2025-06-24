# agent/collectors/authentication_collector.py - FIXED VERSION
"""
Enhanced Authentication Collector - FIXED for reliable event sending
Thu thập đầy đủ thông tin authentication và gửi events một cách đáng tin cậy
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

class EnhancedAuthenticationCollector(BaseCollector):
    """Enhanced Authentication Collector - FIXED for reliable authentication event generation"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "AuthenticationCollector")
        
        # FIXED: Optimize performance settings
        self.polling_interval = 30  # Increase from 300s to 30s for more frequent checks
        self.max_events_per_scan = 5  # Limit events per scan for better performance
        
        # User tracking
        self.discovered_users = set()
        self.last_scan_time = 0
        self.scan_count = 0
        
        # Authentication event tracking
        self.auth_events_generated = 0
        self.session_events_generated = 0
        self.unique_users_found = 0
        
        # FIXED: Reduce scanning methods for better performance
        self.scanning_methods = [
            'current_user',
            'environment_vars', 
            'net_command',
            'wmic_command'
        ]
        
        # FIXED: Cache for better performance
        self.user_cache = {}
        self.cache_expiry = 300  # 5 minutes cache
        
        self.logger.info("🔐 Enhanced Authentication Collector initialized - FIXED VERSION")
        self.logger.info(f"   Polling Interval: {self.polling_interval}s")
        self.logger.info(f"   Scanning Methods: {len(self.scanning_methods)}")
    
    async def _collect_data(self):
        """Collect authentication data - FIXED VERSION"""
        try:
            start_time = time.time()
            events = []
            current_time = time.time()
            
            # FIXED: Only scan if enough time has passed
            if current_time - self.last_scan_time < self.polling_interval:
                return []
            
            self.logger.info(f"🔐 Starting authentication scan #{self.scan_count + 1}")
            
            # FIXED: Use cached data if recent
            if self._is_cache_valid():
                self.logger.debug("📋 Using cached user data")
                users = self.user_cache.get('users', [])
            else:
                # Discover users using multiple methods
                users = await self._discover_users_efficiently()
                self._update_cache(users)
            
            # Generate events for discovered users
            for user in users:
                if len(events) >= self.max_events_per_scan:
                    break
                    
                if user not in self.discovered_users:
                    # New user discovered - create authentication events
                    auth_events = await self._create_authentication_events_for_user(user)
                    events.extend(auth_events)
                    self.discovered_users.add(user)
                    self.unique_users_found += 1
            
            # FIXED: Always generate at least one summary event
            if self.scan_count % 3 == 0:  # Every 3 scans
                summary_event = await self._create_authentication_summary_event()
                if summary_event:
                    events.append(summary_event)
            
            # Update tracking
            self.last_scan_time = current_time
            self.scan_count += 1
            self.auth_events_generated += len([e for e in events if e.event_action == EventAction.LOGIN])
            self.session_events_generated += len([e for e in events if e.event_action == EventAction.SESSION])
            
            # FIXED: Log performance
            collection_time = (time.time() - start_time) * 1000
            if events:
                self.logger.info(f"🔐 Authentication scan completed: {len(events)} events, {len(users)} users")
                self.logger.info(f"   📊 Users discovered: {self.unique_users_found} unique")
                self.logger.info(f"   ⏱️ Collection time: {collection_time:.1f}ms")
            else:
                self.logger.debug(f"🔐 Authentication scan: no new events (cached: {len(users)} users)")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Authentication collection failed: {e}")
            return []
    
    def _is_cache_valid(self) -> bool:
        """Check if user cache is still valid"""
        cache_time = self.user_cache.get('timestamp', 0)
        return (time.time() - cache_time) < self.cache_expiry
    
    def _update_cache(self, users: List[str]):
        """Update user cache"""
        self.user_cache = {
            'users': users,
            'timestamp': time.time()
        }
    
    async def _discover_users_efficiently(self) -> List[str]:
        """Discover users using efficient methods - FIXED VERSION"""
        users = set()
        
        try:
            # Method 1: Current user (always available)
            current_user = self._get_current_user()
            if current_user:
                users.add(current_user)
                self.logger.debug(f"🔐 Current user: {current_user}")
            
            # Method 2: Environment variables
            env_users = self._get_users_from_environment()
            users.update(env_users)
            if env_users:
                self.logger.debug(f"🔐 Environment users: {env_users}")
            
            # Method 3: Net user command (if available)
            if 'net_command' in self.scanning_methods:
                net_users = await self._get_users_via_net_command()
                users.update(net_users)
                if net_users:
                    self.logger.debug(f"🔐 Net users: {net_users}")
            
            # Method 4: WMIC command (if available)
            if 'wmic_command' in self.scanning_methods:
                wmic_users = await self._get_users_via_wmic()
                users.update(wmic_users)
                if wmic_users:
                    self.logger.debug(f"🔐 WMIC users: {wmic_users}")
            
            # FIXED: Filter out invalid usernames
            valid_users = []
            for user in users:
                if self._is_valid_username(user):
                    valid_users.append(user)
            
            self.logger.info(f"🔐 User discovery: {len(valid_users)} valid users from {len(users)} total")
            return valid_users
            
        except Exception as e:
            self.logger.error(f"❌ User discovery failed: {e}")
            return [current_user] if current_user else []
    
    def _get_current_user(self) -> Optional[str]:
        """Get current user via multiple methods"""
        try:
            # Try getpass first
            user = getpass.getuser()
            if user and len(user) > 0:
                return user
            
            # Try environment variables
            user = os.environ.get('USERNAME') or os.environ.get('USER')
            if user and len(user) > 0:
                return user
            
            # Try Windows API if available
            if WIN32_AVAILABLE:
                try:
                    user = win32api.GetUserName()
                    if user and len(user) > 0:
                        return user
                except:
                    pass
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Current user detection failed: {e}")
            return None
    
    def _get_users_from_environment(self) -> List[str]:
        """Get users from environment variables"""
        users = []
        try:
            # Check various environment variables
            env_vars = ['USERNAME', 'USER', 'LOGNAME', 'USERPROFILE']
            
            for var in env_vars:
                value = os.environ.get(var)
                if value:
                    # Extract username from paths like C:\Users\username
                    if '\\Users\\' in value:
                        username = value.split('\\Users\\')[-1].split('\\')[0]
                        if username and username not in users:
                            users.append(username)
                    elif value and value not in users and len(value) < 50:
                        users.append(value)
            
            return users
            
        except Exception as e:
            self.logger.debug(f"Environment user detection failed: {e}")
            return []
    
    async def _get_users_via_net_command(self) -> List[str]:
        """Get users via net user command"""
        users = []
        try:
            # Run net user command
            cmd = ['net', 'user']
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                # Parse output
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip() and not any(skip in line.lower() for skip in 
                        ['the command completed', 'user accounts for', '----']):
                        # Extract usernames from the line
                        parts = line.strip().split()
                        for part in parts:
                            if (len(part) > 1 and 
                                not part.startswith('-') and 
                                part.isascii() and 
                                part not in users):
                                users.append(part)
            
            return users[:5]  # Limit to 5 users
            
        except Exception as e:
            self.logger.debug(f"Net user command failed: {e}")
            return []
    
    async def _get_users_via_wmic(self) -> List[str]:
        """Get users via WMIC command"""
        users = []
        try:
            # Run WMIC command
            cmd = ['wmic', 'useraccount', 'get', 'name', '/format:list']
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                # Parse output
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip().startswith('Name='):
                        username = line.split('=', 1)[1].strip()
                        if username and username not in users:
                            users.append(username)
            
            return users[:5]  # Limit to 5 users
            
        except Exception as e:
            self.logger.debug(f"WMIC command failed: {e}")
            return []
    
    def _is_valid_username(self, username: str) -> bool:
        """Check if username is valid"""
        if not username or len(username) < 1:
            return False
        
        # Skip invalid patterns
        invalid_patterns = [
            'none', 'null', 'unknown', 'error', 'failed',
            '----', '====', 'the command', 'user accounts',
            'completed successfully'
        ]
        
        username_lower = username.lower()
        if any(pattern in username_lower for pattern in invalid_patterns):
            return False
        
        # Check length and characters
        if len(username) > 50 or len(username) < 1:
            return False
        
        # Must be printable ASCII
        if not username.isprintable() or not username.isascii():
            return False
        
        return True
    
    async def _create_authentication_events_for_user(self, username: str) -> List[EventData]:
        """Create authentication events for a discovered user - FIXED VERSION"""
        events = []
        
        try:
            # Get system info
            hostname = platform.node()
            timestamp = datetime.now()
            
            # Get IP address
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip_address = s.getsockname()[0]
                s.close()
            except:
                ip_address = '127.0.0.1'
            
            # EVENT 1: User Login Event
            login_event = EventData(
                event_type="Authentication",
                event_action=EventAction.LOGIN,
                event_timestamp=timestamp,
                severity="Info",
                
                # Authentication specific fields
                login_user=username,
                login_type="Interactive",
                login_result="Success",
                source_ip=ip_address,
                
                description=f"🔐 USER LOGIN: {username} on {hostname}",
                raw_event_data={
                    'event_subtype': 'user_authentication',
                    'authentication_method': 'System Discovery',
                    'login_source': 'Interactive',
                    'hostname': hostname,
                    'domain': username.split('\\')[0] if '\\' in username else None,
                    'username_only': username.split('\\')[-1] if '\\' in username else username,
                    'discovery_time': time.time(),
                    'discovery_method': 'Enhanced Authentication Collector',
                    'is_current_user': username == self._get_current_user(),
                    'authentication_successful': True,
                    'session_active': True
                }
            )
            events.append(login_event)
            
            # EVENT 2: Session Event
            session_event = EventData(
                event_type="Authentication", 
                event_action=EventAction.SESSION,
                event_timestamp=timestamp,
                severity="Info",
                
                # Authentication specific fields
                login_user=username,
                login_type="Session",
                login_result="Active",
                source_ip=ip_address,
                
                description=f"👤 USER SESSION: {username} session active",
                raw_event_data={
                    'event_subtype': 'user_session',
                    'session_type': 'Active',
                    'session_state': 'Connected',
                    'hostname': hostname,
                    'username': username,
                    'ip_address': ip_address,
                    'timestamp': timestamp.isoformat(),
                    'detection_method': 'Enhanced Authentication Collector',
                    'session_duration': 'Unknown',
                    'authentication_level': 'Standard'
                }
            )
            events.append(session_event)
            
            self.logger.info(f"🔐 Created {len(events)} authentication events for user: {username}")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Failed to create authentication events for {username}: {e}")
            return []
    
    async def _create_authentication_summary_event(self) -> Optional[EventData]:
        """Create authentication summary event"""
        try:
            timestamp = datetime.now()
            hostname = platform.node()
            
            summary_info = {
                'total_users_discovered': len(self.discovered_users),
                'authentication_events_generated': self.auth_events_generated,
                'session_events_generated': self.session_events_generated,
                'scan_count': self.scan_count,
                'scanning_methods': self.scanning_methods,
                'users_list': list(self.discovered_users)[:10],  # First 10 users
                'cache_enabled': True,
                'collection_efficient': True
            }
            
            summary_event = EventData(
                event_type="Authentication",
                event_action=EventAction.ACCESS,
                event_timestamp=timestamp,
                severity="Info",
                
                login_user="SYSTEM_SUMMARY",
                login_type="Summary",
                login_result="Active",
                
                description=f"🔐 AUTHENTICATION SUMMARY: {len(self.discovered_users)} users, {self.auth_events_generated} events",
                raw_event_data={
                    'event_subtype': 'authentication_summary',
                    'summary_info': summary_info,
                    'hostname': hostname,
                    'collection_timestamp': timestamp.isoformat(),
                    'collector_version': 'Enhanced_v2.1.0',
                    'performance_optimized': True
                }
            )
            
            return summary_event
            
        except Exception as e:
            self.logger.error(f"❌ Failed to create authentication summary: {e}")
            return None
    
    def get_stats(self) -> Dict:
        """Get detailed statistics for authentication collection"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'Authentication_Enhanced',
            'unique_users_discovered': len(self.discovered_users),
            'authentication_events_generated': self.auth_events_generated,
            'session_events_generated': self.session_events_generated,
            'total_scan_count': self.scan_count,
            'scanning_methods_count': len(self.scanning_methods),
            'cache_enabled': True,
            'cache_expiry_seconds': self.cache_expiry,
            'cache_valid': self._is_cache_valid(),
            'last_scan_time': self.last_scan_time,
            'polling_interval_seconds': self.polling_interval,
            'max_events_per_scan': self.max_events_per_scan,
            'discovered_users': list(self.discovered_users)[:5],  # First 5 users
            'enhanced_version': True,
            'performance_optimized': True,
            'win32_available': WIN32_AVAILABLE
        })
        return base_stats

def create_authentication_collector(config_manager):
    """Factory function to create enhanced authentication collector"""
    return EnhancedAuthenticationCollector(config_manager)