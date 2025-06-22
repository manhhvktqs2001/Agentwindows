# agent/collectors/registry_collector.py
"""
Enhanced Registry Collector - Continuous Registry Monitoring
Thu thập thông tin registry liên tục và gửi cho server
"""

import winreg
import asyncio
import logging
import time
from typing import Dict, List, Optional, Set
from datetime import datetime
import subprocess

from ..schemas.events import EventData, EventType, EventAction
from ..utils.registry_utils import get_registry_value, is_suspicious_registry_key

logger = logging.getLogger('RegistryCollector')

class EnhancedRegistryCollector:
    """Enhanced Registry Collector with continuous monitoring"""
    
    def __init__(self, config_manager=None):
        self.config_manager = config_manager
        self.logger = logging.getLogger('RegistryCollector')
        self.is_running = False
        self.monitored_keys = set()
        self.suspicious_keys = {
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\SuperHidden',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideDrivesNoViewer',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowRun',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowControlPanel',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowMyComputer',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowMyDocs',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowMyPics',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowMyMusic',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowNetConn',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowPrinters',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowSetProgramAccessAndDefaults',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowHelp',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowSearch',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowRecentDocs',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowUser',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowNetPlaces',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowMyGames',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowMyVideos',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowMyPics',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowMyMusic',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowNetConn',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowPrinters',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowSetProgramAccessAndDefaults',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowHelp',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowSearch',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowRecentDocs',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowUser',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowNetPlaces',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowMyGames',
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_ShowMyVideos'
        }
        
        # Performance tracking
        self.stats = {
            'keys_scanned': 0,
            'new_keys_detected': 0,
            'suspicious_keys_detected': 0,
            'events_generated': 0,
            'last_scan_time': None
        }
        
        self.logger.info("Enhanced Registry Collector initialized")
    
    async def initialize(self):
        """Initialize the registry collector"""
        try:
            self.logger.info("🔧 Initializing Enhanced Registry Collector...")
            # No specific initialization needed for registry collector
            self.logger.info("✅ Enhanced Registry Collector initialized successfully")
        except Exception as e:
            self.logger.error(f"❌ Enhanced Registry Collector initialization failed: {e}")
            raise
    
    async def start_monitoring(self):
        """Start continuous registry monitoring"""
        self.is_running = True
        self.logger.info("🚀 Starting continuous registry monitoring...")
        
        # Start monitoring loop
        asyncio.create_task(self._monitoring_loop())
        
        self.logger.info("✅ Registry monitoring started")
    
    async def stop_monitoring(self):
        """Stop registry monitoring"""
        self.is_running = False
        self.logger.info("🛑 Registry monitoring stopped")
    
    async def _monitoring_loop(self):
        """Continuous monitoring loop"""
        while self.is_running:
            try:
                await self._scan_registry_keys()
                await asyncio.sleep(10)  # Scan every 10 seconds (registry changes less frequently)
                
            except Exception as e:
                self.logger.error(f"❌ Registry monitoring error: {e}")
                await asyncio.sleep(30)  # Wait longer on error
    
    async def _scan_registry_keys(self):
        """Scan registry keys for changes"""
        try:
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
                await self._generate_registry_event(key, EventAction.CREATE)
                self.stats['new_keys_detected'] += 1
            
            # Generate events for suspicious keys
            for key in suspicious_keys:
                await self._generate_registry_event(key, EventAction.SUSPICIOUS_ACTIVITY, severity="High")
                self.stats['suspicious_keys_detected'] += 1
            
            self.stats['keys_scanned'] += len(current_keys)
            self.stats['last_scan_time'] = datetime.now()
            
        except Exception as e:
            self.logger.error(f"❌ Registry scan failed: {e}")
    
    async def _scan_hive(self, hive, hive_name: str) -> Set[str]:
        """Scan a registry hive for keys"""
        keys = set()
        
        try:
            # Scan specific suspicious keys
            for key_path in self.suspicious_keys:
                if key_path.startswith(hive_name.replace('HKEY_', '')):
                    try:
                        key_handle = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                        keys.add(f"{hive_name}\\{key_path}")
                        winreg.CloseKey(key_handle)
                    except WindowsError:
                        continue
            
            # Scan startup keys
            startup_keys = [
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce'
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
        """Generate registry event for server"""
        try:
            # Get registry value if possible
            registry_value = None
            try:
                registry_value = get_registry_value(key_path)
            except Exception:
                pass
            
            event = EventData(
                event_type=EventType.REGISTRY,
                event_action=action,
                event_timestamp=datetime.now(),
                severity=severity,
                
                # Registry details
                registry_key=key_path,
                registry_value=registry_value,
                
                # Additional context
                description=f"Registry {action.lower()}: {key_path}"
            )
            
            # Add raw event data
            event.raw_event_data = {
                'key_path': key_path,
                'value': registry_value,
                'is_suspicious': is_suspicious_registry_key(key_path),
                'hive': key_path.split('\\')[0] if '\\' in key_path else None
            }
            
            # Send event to event processor
            if hasattr(self, 'event_processor') and self.event_processor:
                await self.event_processor.submit_event(event)
                self.stats['events_generated'] += 1
            
            self.logger.debug(f"📝 Registry event generated: {key_path}")
            
        except Exception as e:
            self.logger.error(f"❌ Registry event generation failed: {e}")
    
    def get_stats(self) -> Dict:
        """Get collector statistics"""
        return {
            'collector_type': 'Registry',
            'is_running': self.is_running,
            'keys_scanned': self.stats['keys_scanned'],
            'new_keys_detected': self.stats['new_keys_detected'],
            'suspicious_keys_detected': self.stats['suspicious_keys_detected'],
            'events_generated': self.stats['events_generated'],
            'last_scan_time': self.stats['last_scan_time'].isoformat() if self.stats['last_scan_time'] else None,
            'monitored_keys': len(self.monitored_keys)
        }
    
    def set_event_processor(self, event_processor):
        """Set event processor for sending events"""
        self.event_processor = event_processor
        self.logger.info("Event processor linked to Registry Collector")
    
    async def stop(self):
        """Stop registry monitoring"""
        await self.stop_monitoring()