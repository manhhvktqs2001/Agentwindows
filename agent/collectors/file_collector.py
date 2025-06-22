# agent/collectors/file_collector.py - FIXED VERSION
"""
Enhanced File Collector - Continuous File System Monitoring
Thu thập thông tin file liên tục và gửi cho server
"""

import asyncio
import logging
import os
import time
import hashlib
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
from collections import defaultdict
import shutil
import stat

try:
    import win32file
    import win32con
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventType, EventAction, Severity
from agent.utils.file_utils import FileUtils, get_file_info, calculate_file_hash, is_suspicious_file

logger = logging.getLogger('FileCollector')

class EnhancedFileCollector(BaseCollector):
    """Enhanced File Collector with continuous monitoring - FIXED"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "FileCollector")
        
        self.monitored_files = set()
        self.suspicious_extensions = {
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
            '.scr', '.pif', '.com', '.hta', '.msi', '.msu', '.msp'
        }
        
        # Performance tracking
        self.stats = {
            'files_scanned': 0,
            'new_files_detected': 0,
            'suspicious_files_detected': 0,
            'events_generated': 0,
            'last_scan_time': None
        }
        
        # Monitor directories
        self.monitor_directories = [
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/AppData/Local/Temp"),
            os.path.expanduser("~/AppData/Roaming"),
            "C:/Windows/Temp",
            "C:/ProgramData"
        ]
        
        self.logger.info("Enhanced File Collector initialized")
    
    async def initialize(self):
        """Initialize the file collector"""
        try:
            self.logger.info("🚀 Initializing FileCollector...")
            await super().initialize()
            self.logger.info("✅ FileCollector initialized")
        except Exception as e:
            self.logger.error(f"❌ FileCollector initialization failed: {e}")
            raise
    
    async def _collect_data(self):
        """Scan files for changes - Required by BaseCollector"""
        try:
            events = []
            current_files = set()
            new_files = []
            suspicious_files = []
            
            # Scan each monitored directory
            for directory in self.monitor_directories:
                if os.path.exists(directory):
                    try:
                        dir_files = await self._scan_directory(directory)
                        current_files.update(dir_files)
                        
                        # Check for new files
                        for file_path in dir_files:
                            if file_path not in self.monitored_files:
                                new_files.append(file_path)
                                self.monitored_files.add(file_path)
                        
                            # Check for suspicious files
                            if is_suspicious_file(file_path):
                                suspicious_files.append(file_path)
                    except Exception as e:
                        self.logger.debug(f"Error scanning directory {directory}: {e}")
                        continue
            
            # Generate events for new files
            for file_path in new_files:
                event = await self._generate_file_event(file_path, EventAction.CREATE)
                if event:
                    events.append(event)
                    self.stats['new_files_detected'] += 1
            
            # Generate events for suspicious files - FIXED: Use correct action
            for file_path in suspicious_files:
                event = await self._generate_file_event(file_path, EventAction.SUSPICIOUS_ACTIVITY, severity="High")
                if event:
                    events.append(event)
                    self.stats['suspicious_files_detected'] += 1
            
            self.stats['files_scanned'] += len(current_files)
            self.stats['last_scan_time'] = datetime.now()
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ File scan failed: {e}")
            return []
    
    async def _scan_directory(self, directory: str) -> Set[str]:
        """Scan a directory for files"""
        files = set()
        
        try:
            for root, dirs, filenames in os.walk(directory):
                # Skip system directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['$Recycle.Bin', 'System Volume Information']]
                
                for filename in filenames:
                    try:
                        file_path = os.path.join(root, filename)
                        
                        # Skip system files and temporary files
                        if self._should_skip_file(file_path):
                            continue
                        
                        files.add(file_path)
                    
                    except (OSError, PermissionError):
                        continue
                        
        except Exception as e:
            self.logger.debug(f"Directory scan error for {directory}: {e}")
        
        return files
    
    def _should_skip_file(self, file_path: str) -> bool:
        """Check if file should be skipped"""
        try:
            # Skip system files
            if any(skip in file_path.lower() for skip in [
                'pagefile.sys', 'hiberfil.sys', 'swapfile.sys',
                'ntuser.dat', 'ntuser.ini', 'desktop.ini',
                'thumbs.db', '.tmp', '.temp', '.log'
            ]):
                return True
            
            # Skip files that are too large (> 100MB)
            try:
                if os.path.getsize(file_path) > 100 * 1024 * 1024:
                    return True
            except (OSError, PermissionError):
                return True
            
            return False
            
        except Exception:
            return True
    
    async def _generate_file_event(self, file_path: str, action: str, severity: str = "Info"):
        """Generate file event for server - FIXED"""
        try:
            # Get file information
            file_info = get_file_info(file_path)
            
            # Calculate file hash if possible
            file_hash = None
            try:
                file_hash = calculate_file_hash(file_path)
            except Exception:
                pass
            
            event = EventData(
                event_type=EventType.FILE,
                event_action=action,
                event_timestamp=datetime.now(),
                severity=severity,
                
                # File details
                file_path=file_path,
                file_name=os.path.basename(file_path),
                file_size=file_info.get('size', 0),
                file_hash=file_hash,
                file_extension=file_info.get('extension', ''),
                
                # Additional context
                description=f"File {action.lower()}: {os.path.basename(file_path)}"
            )
            
            # Add raw event data
            event.raw_event_data = {
                'file_info': file_info,
                'is_suspicious': is_suspicious_file(file_path),
                'directory': os.path.dirname(file_path),
                'access_time': file_info.get('access_time'),
                'modify_time': file_info.get('modify_time'),
                'create_time': file_info.get('create_time')
            }
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ File event generation failed: {e}")
            return None
    
    def get_stats(self) -> Dict:
        """Get collector statistics"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'File',
            'files_scanned': self.stats['files_scanned'],
            'new_files_detected': self.stats['new_files_detected'],
            'suspicious_files_detected': self.stats['suspicious_files_detected'],
            'events_generated': self.stats['events_generated'],
            'last_scan_time': self.stats['last_scan_time'].isoformat() if self.stats['last_scan_time'] else None,
            'monitored_files': len(self.monitored_files),
            'monitor_directories': len(self.monitor_directories)
        })
        return base_stats