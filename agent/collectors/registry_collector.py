# agent/collectors/registry_collector.py - COMPLETELY FIXED VERSION
"""
Enhanced Registry Collector - Continuous Registry Monitoring
Thu thập thông tin registry liên tục và gửi cho server
"""

try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False
    winreg = None

import asyncio
import logging
import time
from typing import Dict, List, Optional, Set
from datetime import datetime
import subprocess

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventAction
from agent.utils.registry_utils import RegistryUtils, get_registry_value, is_suspicious_registry_key

logger = logging.getLogger('RegistryCollector')

class EnhancedRegistryCollector(BaseCollector):
    """Enhanced Registry Collector with continuous monitoring - COMPLETELY FIXED"""
    
    def __init__(self, config_manager=None):
        super().__init__(config_manager, "RegistryCollector")
        self.config_manager = config_manager
        self.logger = logging.getLogger('RegistryCollector')
        self.monitored_keys = set()
        
        # FIXED: Reduce suspicious keys to improve performance
        self.suspicious_keys = {
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        }
        
        # Performance tracking
        self.stats = {
            'keys_scanned': 0,
            'new_keys_detected': 0,
            'suspicious_keys_detected': 0,
            'events_generated': 0,
            'last_scan_time': None
        }
        
        # FIXED: Add caching to improve performance
        self.key_cache = {}
        self.cache_timeout = 300  # 5 minutes
        self.last_cache_clear = time.time()
        
        self.logger.info("Enhanced Registry Collector initialized - PERFORMANCE OPTIMIZED")
    
    async def initialize(self):
        """Initialize the registry collector"""
        try:
            self.logger.info("🚀 Initializing RegistryCollector...")
            await super().initialize()
            
            if not WINREG_AVAILABLE:
                self.logger.warning("⚠️ Windows Registry API not available, limited functionality")
            
            self.logger.info("✅ RegistryCollector initialized")
        except Exception as e:
            self.logger.error(f"❌ RegistryCollector initialization failed: {e}")
            raise
    
    async def _collect_data(self):
        if self._paused:
            self.logger.info("⏸️  RegistryCollector paused - exiting _collect_data")
            return
        """Collect registry data - Required by BaseCollector"""
        try:
            start_time = time.time()
            if not WINREG_AVAILABLE:
                return []
            
            events = []
            current_keys = set()
            new_keys = []
            suspicious_keys = []
            
            # Scan HKEY_LOCAL_MACHINE
            hklm_keys = await self._scan_hive(winreg.HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE")
            current_keys.update(hklm_keys)
            
            # Scan HKEY_CURRENT_USER
            hkcu_keys = await self._scan_hive(winreg.HKEY_CURRENT_USER, "HKEY_CURRENT_USER")
            current_keys.update(hkcu_keys)
            
            # Check for new keys
            for key in current_keys:
                if key not in self.monitored_keys:
                    new_keys.append(key)
                    self.monitored_keys.add(key)
                
                # Check for suspicious keys
                if is_suspicious_registry_key(key):
                    suspicious_keys.append(key)
            
            # Generate events for new keys
            for key in new_keys:
                event = await self._generate_registry_event(key, EventAction.CREATE)
                if event:
                    events.append(event)
                    self.stats['new_keys_detected'] += 1
            
            # Generate events for suspicious keys
            for key in suspicious_keys:
                event = await self._generate_registry_event(key, EventAction.SUSPICIOUS_ACTIVITY, severity="High")
                if event:
                    events.append(event)
                    self.stats['suspicious_keys_detected'] += 1
            
            self.stats['keys_scanned'] += len(current_keys)
            self.stats['last_scan_time'] = datetime.now()
            
            # FIXED: Log performance metrics with better thresholds
            collection_time = (time.time() - start_time) * 1000
            if collection_time > 8000:  # Increase threshold for registry scanning
                self.logger.warning(f"⚠️ Slow collection: {collection_time:.1f}ms in RegistryCollector")
            elif collection_time > 3000:
                self.logger.info(f"📊 Registry scan time: {collection_time:.1f}ms")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Registry scan failed: {e}")
            return []
    
    async def _scan_hive(self, hive, hive_name: str) -> Set[str]:
        """Scan a registry hive for keys - PERFORMANCE OPTIMIZED"""
        keys = set()
        
        if not WINREG_AVAILABLE:
            return keys
        
        try:
            # FIXED: Only scan critical startup keys for better performance
            startup_keys = [
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            ]
            
            for key_path in startup_keys:
                try:
                    key_handle = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                    keys.add(f"{hive_name}\\{key_path}")
                    winreg.CloseKey(key_handle)
                except WindowsError:
                    continue
            
        except Exception as e:
            self.logger.debug(f"Registry hive scan error: {e}")
        
        return keys
    
    async def _generate_registry_event(self, key_path: str, action: str, severity: str = "Info"):
        """Generate registry event for server - COMPLETELY FIXED"""
        try:
            # Get registry value if possible
            registry_value = None
            try:
                registry_value = get_registry_value(key_path)
            except Exception:
                pass
            
            # Parse key path to get components
            key_parts = key_path.split('\\')
            registry_name = key_parts[-1] if key_parts else key_path
            
            event = EventData(
                event_type="Registry",
                event_action=action,
                event_timestamp=datetime.now(),
                severity=severity,
                
                registry_key=key_path,
                registry_value_name=registry_name,
                registry_value_data=str(registry_value) if registry_value else None,
                registry_operation="read",
                
                description=f"🔧 REGISTRY ACCESS: {key_path}\\{registry_name}",
                raw_event_data={
                    'event_subtype': 'registry_access',
                    'registry_hive': key_path.split('\\')[0] if '\\' in key_path else None,
                    'value_type': type(registry_value).__name__ if registry_value else None,
                    'value_size': len(str(registry_value)) if registry_value else 0,
                    'is_system_key': is_suspicious_registry_key(key_path),
                    'access_time': time.time()
                }
            )
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Registry event generation failed: {e}")
            return None
    
    def get_stats(self) -> Dict:
        """Get collector statistics"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'Registry',
            'keys_scanned': self.stats['keys_scanned'],
            'new_keys_detected': self.stats['new_keys_detected'],
            'suspicious_keys_detected': self.stats['suspicious_keys_detected'],
            'events_generated': self.stats['events_generated'],
            'last_scan_time': self.stats['last_scan_time'].isoformat() if self.stats['last_scan_time'] else None,
            'monitored_keys': len(self.monitored_keys),
            'winreg_available': WINREG_AVAILABLE
        })
        return base_stats