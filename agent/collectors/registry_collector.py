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
from typing import Dict, List, Optional, Set
import threading
import json

# Windows-specific imports with graceful fallback
try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False
    winreg = None

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

from .base_collector import BaseCollector
from ..schemas.events import EventData

WINDOWS_AVAILABLE = WINREG_AVAILABLE and WIN32_AVAILABLE

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
    """Registry events collector for Windows - with graceful fallback"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "RegistryCollector")
        
        # Platform check
        self.is_windows = platform.system().lower() == 'windows'
        
        # Registry monitoring
        self.registry_monitor = None
        self.event_loop = None
        
        # Feature availability
        self.monitoring_available = WINDOWS_AVAILABLE and self.is_windows
        
        # Configuration
        self.monitor_critical_keys = True
        self.monitor_startup_keys = True
        self.monitor_security_keys = True
        self.monitor_network_keys = True
        
        # FIX: Initialize monitored_keys attribute
        self.monitored_keys = []
        if WINDOWS_AVAILABLE:
            self.monitored_keys = [
                r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
                r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",
            ]
        
        # Known critical registry values (only if APIs available)
        self.critical_values = {}
        if WINDOWS_AVAILABLE:
            self.critical_values = {
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run": "startup_programs",
                r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection": "defender_settings",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System": "uac_settings",
            }
        
        # Value tracking for change detection
        self.previous_values = {}
        
        # Cache for registry changes
        self.registry_cache = {}
        self.registry_timestamps = {}
        
    async def _collector_specific_init(self):
        """Initialize Windows registry collector"""
        try:
            if not self.is_windows:
                self.logger.warning("⚠️ Registry collector only supports Windows")
                return
            
            if not self.monitoring_available:
                self.logger.warning("⚠️ Registry monitoring disabled - Windows API modules not available")
                self.logger.info("💡 To enable registry monitoring, install: pip install pywin32 wmi")
                return
            
            # Get current event loop for async operations
            self.event_loop = asyncio.get_event_loop()
            
            # Initialize registry monitor
            self.registry_monitor = RegistryMonitor(self)
            
            # Read initial registry state
            await self._read_initial_state()
            
            self.logger.info("✅ Registry collector initialized")
            
        except Exception as e:
            self.logger.error(f"❌ Registry collector initialization failed: {e}")
            # Don't raise exception - allow agent to continue without registry monitoring
            self.monitoring_available = False
    
    async def start(self):
        """Start registry monitoring"""
        try:
            await super().start()
            
            if self.monitoring_available and self.registry_monitor:
                self.registry_monitor.start_monitoring()
                self.logger.info("✅ Registry monitoring started")
            else:
                self.logger.info("📋 Registry monitoring disabled - Windows APIs not available")
            
        except Exception as e:
            self.logger.error(f"❌ Registry collector start failed: {e}")
            # Don't raise - continue without registry monitoring
    
    async def stop(self):
        """Stop registry monitoring"""
        try:
            if self.monitoring_available and self.registry_monitor:
                self.registry_monitor.stop_monitoring()
            
            await super().stop()
            
        except Exception as e:
            self.logger.error(f"❌ Registry collector stop error: {e}")
    
    async def _collect_data(self):
        """Monitor registry for changes"""
        try:
            current_time = datetime.now()
            
            # Monitor critical registry keys for changes
            for key_path in self.monitored_keys:
                try:
                    current_value = self._get_registry_value(key_path)
                    key_hash = hash(str(current_value))
                    
                    if key_path not in self.registry_cache:
                        # First time seeing this key
                        self.registry_cache[key_path] = key_hash
                        self.logger.debug(f"📝 Initial registry key: {key_path}")
                    elif self.registry_cache[key_path] != key_hash:
                        # Registry key changed
                        event_data = EventData(
                            event_type='Registry',
                            event_action='Modify',
                            event_timestamp=current_time,
                            severity='Medium',
                            description=f'Registry key modified: {key_path}',
                            registry_key=key_path,
                            registry_value_data=str(current_value),
                            registry_operation='Modify',
                            raw_event_data=json.dumps({
                                'key_path': key_path,
                                'new_value': current_value,
                                'action': 'modified'
                            })
                        )
                        await self.add_event(event_data)
                        self.registry_cache[key_path] = key_hash
                        self.logger.debug(f"🔧 Registry key changed: {key_path}")
                        
                except Exception as e:
                    self.logger.debug(f"⚠️ Cannot monitor registry key {key_path}: {e}")
                    continue
            
            # Clean up old cache entries (older than 1 hour)
            cutoff_time = current_time - timedelta(hours=1)
            old_keys = [key for key, time in self.registry_timestamps.items() if time < cutoff_time]
            for key in old_keys:
                if key in self.registry_cache:
                    del self.registry_cache[key]
                if key in self.registry_timestamps:
                    del self.registry_timestamps[key]
            
            return []
            
        except Exception as e:
            self.logger.error(f"❌ Registry collection error: {e}")
            return []
    
    def _get_registry_value(self, key_path):
        """Get registry value for a given key path"""
        try:
            if not WINDOWS_AVAILABLE:
                return None
            
            # Parse key path
            if key_path.startswith("HKEY_LOCAL_MACHINE\\"):
                root_key = winreg.HKEY_LOCAL_MACHINE
                subkey = key_path[19:]  # Remove "HKEY_LOCAL_MACHINE\\"
            elif key_path.startswith("HKEY_CURRENT_USER\\"):
                root_key = winreg.HKEY_CURRENT_USER
                subkey = key_path[18:]  # Remove "HKEY_CURRENT_USER\\"
            else:
                # Assume HKEY_LOCAL_MACHINE for relative paths
                root_key = winreg.HKEY_LOCAL_MACHINE
                subkey = key_path
            
            # Open registry key
            with winreg.OpenKey(root_key, subkey, 0, winreg.KEY_READ) as key:
                # Read default value
                try:
                    value, _ = winreg.QueryValueEx(key, "")
                    return str(value)
                except FileNotFoundError:
                    # No default value, return empty string
                    return ""
                    
        except Exception as e:
            self.logger.debug(f"Error reading registry key {key_path}: {e}")
            return None
    
    def _read_key_values(self, key_path):
        """Read values from a registry key"""
        if not WINDOWS_AVAILABLE:
            return None
            
        try:
            values = {}
            
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(key, i)
                        values[value_name] = {
                            'data': value_data,
                            'type': value_type
                        }
                        i += 1
                    except WindowsError:
                        break
            
            return values
            
        except Exception as e:
            self.logger.debug(f"Failed to read registry key {key_path}: {e}")
            return None
    
    def _detect_changes(self, old_values, new_values):
        """Detect changes between registry value sets"""
        changes = []
        
        # Check for new or modified values
        for value_name, value_info in new_values.items():
            if value_name not in old_values:
                # New value
                changes.append({
                    'action': 'Create',
                    'value_name': value_name,
                    'new_data': value_info['data']
                })
            elif old_values[value_name]['data'] != value_info['data']:
                # Modified value
                changes.append({
                    'action': 'Modify',
                    'value_name': value_name,
                    'old_data': old_values[value_name]['data'],
                    'new_data': value_info['data']
                })
        
        # Check for deleted values
        for value_name in old_values:
            if value_name not in new_values:
                changes.append({
                    'action': 'Delete',
                    'value_name': value_name,
                    'old_data': old_values[value_name]['data']
                })
        
        return changes
    
    async def _read_initial_state(self):
        """Read initial state of critical registry keys"""
        try:
            if not self.monitoring_available:
                return
                
            for key_path in self.critical_values.keys():
                values = self._read_key_values(key_path)
                if values is not None:
                    self.previous_values[key_path] = values
            
            self.logger.info(f"📊 Initial registry state read for {len(self.previous_values)} keys")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to read initial registry state: {e}")
    
    def get_registry_stats(self) -> Dict:
        """Get registry monitoring statistics"""
        return {
            'is_windows': self.is_windows,
            'windows_api_available': WINDOWS_AVAILABLE,
            'winreg_available': WINREG_AVAILABLE,
            'win32_available': WIN32_AVAILABLE,
            'wmi_available': WMI_AVAILABLE,
            'monitoring_available': self.monitoring_available,
            'monitoring_enabled': self.registry_monitor is not None,
            'monitored_keys_count': len(self.registry_monitor.monitored_keys) if self.registry_monitor else 0,
            'critical_keys_tracked': len(self.previous_values),
            'monitor_critical_keys': self.monitor_critical_keys,
            'monitor_startup_keys': self.monitor_startup_keys,
            'monitor_security_keys': self.monitor_security_keys,
            'monitor_network_keys': self.monitor_network_keys
        }
    
    def configure_monitoring(self, **kwargs):
        """Configure registry monitoring options"""
        if 'monitor_critical_keys' in kwargs:
            self.monitor_critical_keys = kwargs['monitor_critical_keys']
        if 'monitor_startup_keys' in kwargs:
            self.monitor_startup_keys = kwargs['monitor_startup_keys']
        if 'monitor_security_keys' in kwargs:
            self.monitor_security_keys = kwargs['monitor_security_keys']
        if 'monitor_network_keys' in kwargs:
            self.monitor_network_keys = kwargs['monitor_network_keys']
        
        self.logger.info(f"🔧 Registry monitoring configured: {kwargs}")

    def _get_severity(self, key_path):
        """Get severity for a registry key"""
        if not WINDOWS_AVAILABLE:
            return 'INFO'
            
        # High severity for critical registry changes
        if any([
            'run' in key_path.lower(),
            'startup' in key_path.lower(),
            'services' in key_path.lower(),
            'autorun' in key_path.lower()
        ]):
            return 'High'
        
        # Medium severity for system registry changes
        if any([
            'software' in key_path.lower(),
            'system' in key_path.lower(),
            'currentversion' in key_path.lower()
        ]):
            return 'Medium'
        
        # Default to info
        return 'Info'