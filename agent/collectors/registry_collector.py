# agent/collectors/registry_collector.py
"""
Windows Registry Collector - Fixed for missing dependencies
Gracefully handles missing Windows API modules
"""

import asyncio
import logging
import platform
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any
import threading
import json
import winreg
import os
from pathlib import Path
import subprocess
from collections import defaultdict

# Windows-specific imports with graceful fallback
try:
    import win32api
    import win32con
    import win32event
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    win32api = None
    win32con = None
    win32event = None

try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False
    wmi = None

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, Severity, EventAction
from agent.utils.registry_utils import RegistryUtils

WINDOWS_AVAILABLE = WIN32_AVAILABLE

class RegistryMonitor:
    """Windows Registry monitoring - graceful fallback for missing APIs"""
    
    def __init__(self, registry_collector):
        self.registry_collector = registry_collector
        self.logger = logging.getLogger(__name__)
        self.monitoring_threads = []
        self.is_monitoring = False
        
        # Only setup if Windows APIs are available
        if not WINDOWS_AVAILABLE:
            self.logger.warning("⚠️ Windows API modules not available, registry monitoring disabled")
            return
        
        # Keys to monitor (only if APIs available)
        self.monitored_keys = [
            # Startup and persistence
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            
            # Services
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
            
            # Windows Defender
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender"),
            
            # UAC Settings
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
        ]
    
    def start_monitoring(self):
        """Start monitoring registry keys"""
        if not WINDOWS_AVAILABLE:
            self.logger.info("📋 Registry monitoring unavailable - Windows API modules missing")
            return
        
        self.is_monitoring = True
        
        try:
            for root_key, subkey_path in self.monitored_keys:
                thread = threading.Thread(
                    target=self._monitor_key,
                    args=(root_key, subkey_path),
                    daemon=True
                )
                thread.start()
                self.monitoring_threads.append(thread)
            
            self.logger.info(f"🔍 Started monitoring {len(self.monitored_keys)} registry keys")
        except Exception as e:
            self.logger.error(f"❌ Failed to start registry monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop monitoring registry keys"""
        self.is_monitoring = False
        
        # Wait for threads to finish
        for thread in self.monitoring_threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        self.monitoring_threads.clear()
        self.logger.info("🛑 Registry monitoring stopped")
    
    def _monitor_key(self, root_key, subkey_path):
        """Monitor a specific registry key for changes"""
        if not WINDOWS_AVAILABLE:
            return
            
        try:
            key_handle = None
            event_handle = None
            
            while self.is_monitoring:
                try:
                    # Open the registry key
                    key_handle = winreg.OpenKey(
                        root_key,
                        subkey_path,
                        0,
                        winreg.KEY_NOTIFY | winreg.KEY_READ
                    )
                    
                    # Create event for notification
                    event_handle = win32event.CreateEvent(None, False, False, None)
                    
                    # Request notification
                    win32api.RegNotifyChangeKeyValue(
                        key_handle,
                        True,  # Watch subtree
                        win32con.REG_NOTIFY_CHANGE_NAME |
                        win32con.REG_NOTIFY_CHANGE_ATTRIBUTES |
                        win32con.REG_NOTIFY_CHANGE_LAST_SET |
                        win32con.REG_NOTIFY_CHANGE_SECURITY,
                        event_handle,
                        True  # Asynchronous
                    )
                    
                    # Wait for notification
                    result = win32event.WaitForSingleObject(event_handle, 5000)  # 5 second timeout
                    
                    if result == win32event.WAIT_OBJECT_0:
                        # Registry change detected
                        asyncio.run_coroutine_threadsafe(
                            self._handle_registry_change(root_key, subkey_path),
                            self.registry_collector.event_loop
                        )
                    
                except Exception as e:
                    self.logger.debug(f"Registry monitoring error for {subkey_path}: {e}")
                    time.sleep(1)  # Brief pause before retry
                
                finally:
                    # Cleanup
                    if event_handle:
                        try:
                            win32api.CloseHandle(event_handle)
                        except:
                            pass
                    if key_handle:
                        try:
                            winreg.CloseKey(key_handle)
                        except:
                            pass
                
                # Brief pause between monitoring cycles
                time.sleep(0.1)
                
        except Exception as e:
            self.logger.error(f"❌ Registry monitoring thread failed for {subkey_path}: {e}")
    
    async def _handle_registry_change(self, root_key, subkey_path):
        """Handle registry change event"""
        try:
            # Read current registry values
            current_values = self._read_registry_values(root_key, subkey_path)
            
            # Create registry event
            event_data = EventData(
                event_type='Registry',
                event_action='Change',
                event_timestamp=datetime.now(),
                registry_key=f"{self._get_root_key_name(root_key)}\\{subkey_path}",
                registry_operation='Modify',
                raw_event_data=json.dumps(current_values) if current_values else None
            )
            
            # Add to event queue
            await self.registry_collector.add_event(event_data)
            
        except Exception as e:
            self.logger.error(f"❌ Registry change handling error: {e}")
    
    def _read_registry_values(self, root_key, subkey_path):
        """Read all values from a registry key"""
        if not WINDOWS_AVAILABLE:
            return None
            
        try:
            values = {}
            
            with winreg.OpenKey(root_key, subkey_path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(key, i)
                        values[value_name] = {
                            'data': str(value_data),
                            'type': value_type
                        }
                        i += 1
                    except WindowsError:
                        break
            
            return values
            
        except Exception as e:
            self.logger.debug(f"Failed to read registry values from {subkey_path}: {e}")
            return None
    
    def _get_root_key_name(self, root_key):
        """Get readable name for root key"""
        if not WINDOWS_AVAILABLE:
            return "UNKNOWN"
            
        key_names = {
            winreg.HKEY_CLASSES_ROOT: "HKEY_CLASSES_ROOT",
            winreg.HKEY_CURRENT_USER: "HKEY_CURRENT_USER",
            winreg.HKEY_LOCAL_MACHINE: "HKEY_LOCAL_MACHINE",
            winreg.HKEY_USERS: "HKEY_USERS",
            winreg.HKEY_CURRENT_CONFIG: "HKEY_CURRENT_CONFIG"
        }
        return key_names.get(root_key, f"UNKNOWN_{root_key}")

class RegistryCollector(BaseCollector):
    """Enhanced Registry Activity Collector"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "RegistryCollector")
        
        # Enhanced configuration
        self.polling_interval = 5  # ENHANCED: Reduced from 15 to 5 seconds for continuous monitoring
        self.max_keys_per_batch = 50  # ENHANCED: Increased batch size
        self.track_registry_changes = True
        self.monitor_suspicious_keys = True
        
        # Registry tracking
        self.known_keys = set()
        self.registry_values = {}
        self.suspicious_keys = set()
        self.registry_changes = defaultdict(list)
        
        # Enhanced monitoring
        self.monitor_startup_keys = True
        self.monitor_persistence_keys = True
        self.monitor_security_keys = True
        self.monitor_software_keys = True
        self.monitor_system_keys = True
        
        # Suspicious registry patterns
        self.suspicious_key_patterns = [
            'Run', 'RunOnce', 'RunServices', 'RunServicesOnce',
            'Winlogon', 'Shell', 'Explorer', 'Policies',
            'Security', 'SAM', 'System', 'Software'
        ]
        
        self.suspicious_value_patterns = [
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
            'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe',
            'bitsadmin.exe', 'wmic.exe', 'schtasks.exe', 'at.exe'
        ]
        
        # Registry monitoring paths
        self.monitor_paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies"),
            (winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Services"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Explorer"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer")
        ]
        
        self.logger.info("🔧 Enhanced Registry Collector initialized")
    
    async def initialize(self):
        """Initialize registry collector with enhanced monitoring"""
        try:
            # Get initial registry state
            await self._scan_all_registry()
            
            # Set up enhanced monitoring
            self._setup_registry_monitoring()
            
            self.logger.info(f"✅ Enhanced Registry Collector initialized - Monitoring {len(self.known_keys)} keys")
            
        except Exception as e:
            self.logger.error(f"❌ Registry collector initialization failed: {e}")
            raise
    
    def _setup_registry_monitoring(self):
        """Set up enhanced registry monitoring"""
        try:
            # Set up registry event callbacks
            self._setup_registry_callbacks()
            
            # Initialize registry utilities
            self.registry_utils = RegistryUtils()
            
        except Exception as e:
            self.logger.error(f"Registry monitoring setup failed: {e}")
    
    def _setup_registry_callbacks(self):
        """Set up registry event callbacks for real-time monitoring"""
        try:
            # This would integrate with Windows API for real-time registry events
            # For now, we use polling with enhanced frequency
            pass
        except Exception as e:
            self.logger.debug(f"Registry callbacks setup failed: {e}")
    
    async def collect_data(self) -> List[EventData]:
        """Collect registry data with enhanced monitoring"""
        try:
            events = []
            
            # ENHANCED: Collect new registry keys
            new_keys = await self._detect_new_registry_keys()
            events.extend(new_keys)
            
            # ENHANCED: Collect modified registry keys
            modified_keys = await self._detect_modified_registry_keys()
            events.extend(modified_keys)
            
            # ENHANCED: Collect deleted registry keys
            deleted_keys = await self._detect_deleted_registry_keys()
            events.extend(deleted_keys)
            
            # ENHANCED: Monitor suspicious registry keys
            suspicious_events = await self._monitor_suspicious_registry_keys()
            events.extend(suspicious_events)
            
            # ENHANCED: Monitor registry value changes
            value_events = await self._monitor_registry_values()
            events.extend(value_events)
            
            # ENHANCED: Monitor startup keys
            startup_events = await self._monitor_startup_keys()
            events.extend(startup_events)
            
            if events:
                self.logger.debug(f"📊 Collected {len(events)} registry events")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Registry data collection failed: {e}")
            return []
    
    async def _scan_all_registry(self):
        """Scan all registry keys in monitored paths for baseline"""
        try:
            for hkey, subkey in self.monitor_paths:
                await self._scan_registry_key(hkey, subkey)
            
            self.logger.info(f"📋 Baseline scan: {len(self.known_keys)} registry keys")
            
        except Exception as e:
            self.logger.error(f"Registry scan failed: {e}")
    
    async def _scan_registry_key(self, hkey, subkey):
        """Scan registry key for values"""
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, type_ = winreg.EnumValue(key, i)
                        key_path = f"{self._get_hkey_name(hkey)}\\{subkey}"
                        key_identifier = f"{key_path}\\{name}"
                        
                        self.known_keys.add(key_identifier)
                        self.registry_values[key_identifier] = {
                            'value': value,
                            'type': type_,
                            'timestamp': time.time()
                        }
                        
                        # Check if suspicious
                        if self._is_suspicious_registry_key(key_path, name, value):
                            self.suspicious_keys.add(key_identifier)
                        
                        i += 1
                    except WindowsError:
                        break
                        
        except Exception as e:
            self.logger.debug(f"Registry key scan failed for {subkey}: {e}")
    
    async def _detect_new_registry_keys(self) -> List[EventData]:
        """Detect newly created registry keys"""
        try:
            events = []
            current_keys = set()
            
            for hkey, subkey in self.monitor_paths:
                await self._scan_registry_key_for_new_values(hkey, subkey, current_keys, events)
            
            # Update known keys
            self.known_keys = current_keys
            
            return events
            
        except Exception as e:
            self.logger.error(f"New registry key detection failed: {e}")
            return []
    
    async def _scan_registry_key_for_new_values(self, hkey, subkey, current_keys: set, events: List[EventData]):
        """Scan registry key for new values"""
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, type_ = winreg.EnumValue(key, i)
                        key_path = f"{self._get_hkey_name(hkey)}\\{subkey}"
                        key_identifier = f"{key_path}\\{name}"
                        
                        current_keys.add(key_identifier)
                        
                        # Check if this is a new key
                        if key_identifier not in self.known_keys:
                            # New registry key detected
                            event = self._create_registry_event(
                                action=EventAction.CREATE,
                                registry_key=key_path,
                                registry_name=name,
                                registry_value=str(value),
                                registry_type=type_,
                                severity=self._determine_registry_severity(key_path, name, value)
                            )
                            events.append(event)
                            
                            # Update tracking
                            self.registry_values[key_identifier] = {
                                'value': value,
                                'type': type_,
                                'timestamp': time.time()
                            }
                            
                            # Check if suspicious
                            if self._is_suspicious_registry_key(key_path, name, value):
                                self.suspicious_keys.add(key_identifier)
                                self.logger.warning(f"🚨 Suspicious registry key detected: {key_identifier}")
                        
                        i += 1
                    except WindowsError:
                        break
                        
        except Exception as e:
            self.logger.debug(f"New registry key scan failed for {subkey}: {e}")
    
    async def _detect_modified_registry_keys(self) -> List[EventData]:
        """Detect modified registry keys"""
        try:
            events = []
            
            for key_identifier in list(self.known_keys):
                try:
                    # Parse key identifier
                    parts = key_identifier.split('\\')
                    if len(parts) < 3:
                        continue
                    
                    hkey_name = parts[0]
                    subkey = '\\'.join(parts[1:-1])
                    name = parts[-1]
                    
                    hkey = self._get_hkey_from_name(hkey_name)
                    if hkey is None:
                        continue
                    
                    # Check current value
                    with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                        try:
                            current_value, current_type = winreg.QueryValueEx(key, name)
                            original_data = self.registry_values.get(key_identifier)
                            
                            if original_data and (current_value != original_data['value'] or current_type != original_data['type']):
                                # Registry key modified
                                event = self._create_registry_event(
                                    action=EventAction.MODIFY,
                                    registry_key=f"{hkey_name}\\{subkey}",
                                    registry_name=name,
                                    registry_value=str(current_value),
                                    registry_type=current_type,
                                    severity=Severity.MEDIUM,
                                    additional_data={
                                        'original_value': str(original_data['value']),
                                        'new_value': str(current_value),
                                        'original_type': original_data['type'],
                                        'new_type': current_type
                                    }
                                )
                                events.append(event)
                                
                                # Update tracking
                                self.registry_values[key_identifier] = {
                                    'value': current_value,
                                    'type': current_type,
                                    'timestamp': time.time()
                                }
                                
                                # Check if suspicious
                                if self._is_suspicious_registry_key(f"{hkey_name}\\{subkey}", name, current_value):
                                    self.suspicious_keys.add(key_identifier)
                        
                        except WindowsError:
                            # Key might have been deleted
                            continue
                
                except Exception:
                    continue
            
            return events
            
        except Exception as e:
            self.logger.error(f"Modified registry key detection failed: {e}")
            return []
    
    async def _detect_deleted_registry_keys(self) -> List[EventData]:
        """Detect deleted registry keys"""
        try:
            events = []
            
            for key_identifier in list(self.known_keys):
                try:
                    # Parse key identifier
                    parts = key_identifier.split('\\')
                    if len(parts) < 3:
                        continue
                    
                    hkey_name = parts[0]
                    subkey = '\\'.join(parts[1:-1])
                    name = parts[-1]
                    
                    hkey = self._get_hkey_from_name(hkey_name)
                    if hkey is None:
                        continue
                    
                    # Check if key still exists
                    with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                        try:
                            winreg.QueryValueEx(key, name)
                        except WindowsError:
                            # Key deleted
                            event = self._create_registry_event(
                                action=EventAction.DELETE,
                                registry_key=f"{hkey_name}\\{subkey}",
                                registry_name=name,
                                registry_value="",
                                registry_type=0,
                                severity=Severity.LOW
                            )
                            events.append(event)
                            
                            # Clean up tracking
                            self.registry_values.pop(key_identifier, None)
                            self.suspicious_keys.discard(key_identifier)
                
                except Exception:
                    continue
            
            return events
            
        except Exception as e:
            self.logger.error(f"Deleted registry key detection failed: {e}")
            return []
    
    async def _monitor_suspicious_registry_keys(self) -> List[EventData]:
        """Monitor activities of suspicious registry keys"""
        try:
            events = []
            
            for key_identifier in list(self.suspicious_keys):
                try:
                    # Parse key identifier
                    parts = key_identifier.split('\\')
                    if len(parts) < 3:
                        continue
                    
                    hkey_name = parts[0]
                    subkey = '\\'.join(parts[1:-1])
                    name = parts[-1]
                    
                    hkey = self._get_hkey_from_name(hkey_name)
                    if hkey is None:
                        continue
                    
                    # Check if key still exists
                    with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                        try:
                            current_value, current_type = winreg.QueryValueEx(key, name)
                            
                            # Monitor suspicious activities
                            event = await self._check_suspicious_registry_activity(
                                f"{hkey_name}\\{subkey}", name, current_value
                            )
                            if event:
                                events.append(event)
                        
                        except WindowsError:
                            self.suspicious_keys.discard(key_identifier)
                            continue
                
                except Exception:
                    continue
            
            return events
            
        except Exception as e:
            self.logger.error(f"Suspicious registry key monitoring failed: {e}")
            return []
    
    async def _check_suspicious_registry_activity(self, key_path: str, name: str, value: Any) -> Optional[EventData]:
        """Check for suspicious activities in a registry key"""
        try:
            value_str = str(value).lower()
            
            # Check for suspicious patterns in value
            for pattern in self.suspicious_value_patterns:
                if pattern.lower() in value_str:
                    return self._create_registry_event(
                        action=EventAction.SUSPICIOUS_ACTIVITY,
                        registry_key=key_path,
                        registry_name=name,
                        registry_value=str(value),
                        registry_type=1,  # REG_SZ
                        severity=Severity.HIGH,
                        additional_data={
                            'suspicious_pattern': pattern,
                            'suspicious_activity': 'suspicious_value'
                        }
                    )
            
            # Check for suspicious key patterns
            for pattern in self.suspicious_key_patterns:
                if pattern.lower() in key_path.lower():
                    return self._create_registry_event(
                        action=EventAction.SUSPICIOUS_ACTIVITY,
                        registry_key=key_path,
                        registry_name=name,
                        registry_value=str(value),
                        registry_type=1,  # REG_SZ
                        severity=Severity.MEDIUM,
                        additional_data={
                            'suspicious_pattern': pattern,
                            'suspicious_activity': 'suspicious_key'
                        }
                    )
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Suspicious registry activity check failed: {e}")
            return None
    
    async def _monitor_registry_values(self) -> List[EventData]:
        """Monitor registry value changes"""
        try:
            events = []
            
            # This would require integration with Windows API for real-time registry monitoring
            # For now, we'll monitor specific high-value keys more frequently
            
            high_value_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\System"),
                (winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Services")
            ]
            
            for hkey, subkey in high_value_keys:
                try:
                    with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                        i = 0
                        while True:
                            try:
                                name, value, type_ = winreg.EnumValue(key, i)
                                key_path = f"{self._get_hkey_name(hkey)}\\{subkey}"
                                
                                # Check for unusual values
                                if self._is_unusual_registry_value(value):
                                    event = self._create_registry_event(
                                        action=EventAction.REGISTRY_ACCESS,
                                        registry_key=key_path,
                                        registry_name=name,
                                        registry_value=str(value),
                                        registry_type=type_,
                                        severity=Severity.MEDIUM,
                                        additional_data={
                                            'unusual_value': True,
                                            'value_length': len(str(value))
                                        }
                                    )
                                    events.append(event)
                                
                                i += 1
                            except WindowsError:
                                break
                
                except Exception as e:
                    self.logger.debug(f"Registry value monitoring failed for {subkey}: {e}")
            
            return events
            
        except Exception as e:
            self.logger.error(f"Registry value monitoring failed: {e}")
            return []
    
    async def _monitor_startup_keys(self) -> List[EventData]:
        """Monitor startup registry keys"""
        try:
            events = []
            
            startup_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
            ]
            
            for hkey, subkey in startup_keys:
                try:
                    with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                        i = 0
                        while True:
                            try:
                                name, value, type_ = winreg.EnumValue(key, i)
                                key_path = f"{self._get_hkey_name(hkey)}\\{subkey}"
                                
                                # Monitor startup entries
                                event = self._create_registry_event(
                                    action=EventAction.STARTUP_ENTRY,
                                    registry_key=key_path,
                                    registry_name=name,
                                    registry_value=str(value),
                                    registry_type=type_,
                                    severity=Severity.MEDIUM,
                                    additional_data={
                                        'startup_type': 'registry',
                                        'startup_location': key_path
                                    }
                                )
                                events.append(event)
                                
                                i += 1
                            except WindowsError:
                                break
                
                except Exception as e:
                    self.logger.debug(f"Startup key monitoring failed for {subkey}: {e}")
            
            return events
            
        except Exception as e:
            self.logger.error(f"Startup key monitoring failed: {e}")
            return []
    
    def _get_hkey_name(self, hkey) -> str:
        """Get HKEY name from handle"""
        hkey_names = {
            winreg.HKEY_CLASSES_ROOT: "HKEY_CLASSES_ROOT",
            winreg.HKEY_CURRENT_USER: "HKEY_CURRENT_USER",
            winreg.HKEY_LOCAL_MACHINE: "HKEY_LOCAL_MACHINE",
            winreg.HKEY_USERS: "HKEY_USERS",
            winreg.HKEY_CURRENT_CONFIG: "HKEY_CURRENT_CONFIG"
        }
        return hkey_names.get(hkey, "UNKNOWN")
    
    def _get_hkey_from_name(self, hkey_name: str):
        """Get HKEY handle from name"""
        hkey_handles = {
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_USERS": winreg.HKEY_USERS,
            "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG
        }
        return hkey_handles.get(hkey_name)
    
    def _is_suspicious_registry_key(self, key_path: str, name: str, value: Any) -> bool:
        """Check if registry key is suspicious"""
        try:
            key_path_lower = key_path.lower()
            name_lower = name.lower()
            value_str = str(value).lower()
            
            # Check for suspicious patterns in key path
            if any(pattern.lower() in key_path_lower for pattern in self.suspicious_key_patterns):
                return True
            
            # Check for suspicious patterns in value
            if any(pattern.lower() in value_str for pattern in self.suspicious_value_patterns):
                return True
            
            return False
            
        except:
            return False
    
    def _is_unusual_registry_value(self, value: Any) -> bool:
        """Check if registry value is unusual"""
        try:
            value_str = str(value)
            
            # Check for long values
            if len(value_str) > 1000:
                return True
            
            # Check for encoded values
            if any(encoding in value_str.lower() for encoding in ['base64', 'hex', 'encoded']):
                return True
            
            # Check for suspicious patterns
            if any(pattern in value_str.lower() for pattern in ['http://', 'https://', 'ftp://']):
                return True
            
            return False
            
        except:
            return False
    
    def _determine_registry_severity(self, key_path: str, name: str, value: Any) -> Severity:
        """Determine severity based on registry key characteristics"""
        if self._is_suspicious_registry_key(key_path, name, value):
            return Severity.HIGH
        elif any(pattern.lower() in key_path.lower() for pattern in ['run', 'startup', 'services']):
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _create_registry_event(self, action: EventAction, registry_key: str, registry_name: str,
                             registry_value: str, registry_type: int, severity: Severity,
                             additional_data: Dict = None) -> EventData:
        """Create registry event data"""
        try:
            return EventData(
                event_type=EventType.REGISTRY,
                event_action=action,
                event_timestamp=datetime.now(),
                severity=severity,
                registry_key=registry_key,
                registry_name=registry_name,
                registry_value=registry_value,
                registry_type=registry_type,
                raw_event_data=additional_data or {}
            )
            
        except Exception as e:
            self.logger.error(f"Registry event creation failed: {e}")
            return None