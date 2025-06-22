# agent/collectors/file_collector.py - ENHANCED
"""
File Activity Collector - ENHANCED
Thu thập thông tin về hoạt động file liên tục với tần suất cao
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
from agent.utils.file_utils import FileUtils

class FileCollector(BaseCollector):
    """Enhanced File Activity Collector"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "FileCollector")
        
        # Enhanced configuration
        self.polling_interval = 3  # ENHANCED: Reduced from 10 to 3 seconds for continuous monitoring
        self.max_files_per_batch = 100  # ENHANCED: Increased batch size
        self.track_file_changes = True
        self.monitor_suspicious_files = True
        
        # File tracking
        self.known_files = set()
        self.file_hashes = {}
        self.suspicious_files = set()
        self.file_changes = defaultdict(list)
        
        # Enhanced monitoring
        self.monitor_executables = True
        self.monitor_documents = True
        self.monitor_scripts = True
        self.monitor_temp_files = True
        self.monitor_downloads = True
        
        # Suspicious file patterns
        self.suspicious_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
            '.msi', '.scr', '.pif', '.com', '.hta', '.wsf', '.wsh'
        ]
        
        self.suspicious_paths = [
            'temp', 'downloads', 'desktop', 'recent', 'startup',
            'appdata', 'local', 'roaming', 'system32', 'windows'
        ]
        
        # File monitoring paths
        self.monitor_paths = [
            os.path.expanduser('~/Desktop'),
            os.path.expanduser('~/Downloads'),
            os.path.expanduser('~/Documents'),
            os.path.expanduser('~/AppData/Local/Temp'),
            os.path.expanduser('~/AppData/Roaming'),
            'C:/Windows/Temp',
            'C:/ProgramData'
        ]
        
        self.logger.info("Enhanced File Collector initialized")
    
    async def initialize(self):
        """Initialize file collector with enhanced monitoring"""
        try:
            # Get initial file state
            await self._scan_all_files()
            
            # Set up enhanced monitoring
            self._setup_file_monitoring()
            
            self.logger.info(f"Enhanced File Collector initialized - Monitoring {len(self.known_files)} files")
            
        except Exception as e:
            self.logger.error(f"File collector initialization failed: {e}")
            raise
    
    def _setup_file_monitoring(self):
        """Set up enhanced file monitoring"""
        try:
            # Set up file event callbacks
            self._setup_file_callbacks()
            
            # Initialize file utilities
            self.file_utils = FileUtils()
            
        except Exception as e:
            self.logger.error(f"File monitoring setup failed: {e}")
    
    def _setup_file_callbacks(self):
        """Set up file event callbacks for real-time monitoring"""
        try:
            # This would integrate with Windows API for real-time file events
            # For now, we use polling with enhanced frequency
            pass
        except Exception as e:
            self.logger.debug(f"File callbacks setup failed: {e}")
    
    async def _collect_data(self):
        """Collect file data with enhanced monitoring - REQUIRED ABSTRACT METHOD"""
        try:
            events = []
            
            # ENHANCED: Collect new files
            new_files = await self._detect_new_files()
            events.extend(new_files)
            
            # ENHANCED: Collect modified files
            modified_files = await self._detect_modified_files()
            events.extend(modified_files)
            
            # ENHANCED: Collect deleted files
            deleted_files = await self._detect_deleted_files()
            events.extend(deleted_files)
            
            # ENHANCED: Monitor suspicious files
            suspicious_events = await self._monitor_suspicious_files()
            events.extend(suspicious_events)
            
            # ENHANCED: Monitor file access patterns
            access_events = await self._monitor_file_access()
            events.extend(access_events)
            
            # ENHANCED: Monitor file size changes
            size_events = await self._monitor_file_sizes()
            events.extend(size_events)
            
            if events:
                self.logger.debug(f"Collected {len(events)} file events")
            
            return events
            
        except Exception as e:
            self.logger.error(f"File data collection failed: {e}")
            return []
    
    async def collect_data(self) -> List[EventData]:
        """Collect file data with enhanced monitoring"""
        try:
            events = []
            
            # ENHANCED: Collect new files
            new_files = await self._detect_new_files()
            events.extend(new_files)
            
            # ENHANCED: Collect modified files
            modified_files = await self._detect_modified_files()
            events.extend(modified_files)
            
            # ENHANCED: Collect deleted files
            deleted_files = await self._detect_deleted_files()
            events.extend(deleted_files)
            
            # ENHANCED: Monitor suspicious files
            suspicious_events = await self._monitor_suspicious_files()
            events.extend(suspicious_events)
            
            # ENHANCED: Monitor file access patterns
            access_events = await self._monitor_file_access()
            events.extend(access_events)
            
            # ENHANCED: Monitor file size changes
            size_events = await self._monitor_file_sizes()
            events.extend(size_events)
            
            if events:
                self.logger.debug(f"📊 Collected {len(events)} file events")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ File data collection failed: {e}")
            return []
    
    async def _scan_all_files(self):
        """Scan all files in monitored paths for baseline"""
        try:
            for path in self.monitor_paths:
                if os.path.exists(path):
                    await self._scan_directory(path)
            
            self.logger.info(f"Baseline scan: {len(self.known_files)} files")
            
        except Exception as e:
            self.logger.error(f"File scan failed: {e}")
    
    async def _scan_directory(self, directory_path: str):
        """Scan directory for files"""
        try:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        file_key = self._create_file_key(file_path)
                        self.known_files.add(file_key)
                        
                        # Get file hash if possible
                        if os.path.exists(file_path):
                            try:
                                file_hash = await self._get_file_hash(file_path)
                                self.file_hashes[file_key] = file_hash
                            except:
                                pass
                        
                        # Check if suspicious
                        if self._is_suspicious_file(file_path):
                            self.suspicious_files.add(file_key)
                    
                    except (OSError, PermissionError):
                        continue
                        
        except Exception as e:
            self.logger.debug(f"Directory scan failed for {directory_path}: {e}")
    
    async def _detect_new_files(self) -> List[EventData]:
        """Detect newly created files"""
        try:
            events = []
            current_files = set()
            
            for path in self.monitor_paths:
                if os.path.exists(path):
                    await self._scan_directory_for_new_files(path, current_files, events)
            
            # Update known files
            self.known_files = current_files
            
            return events
            
        except Exception as e:
            self.logger.error(f"New file detection failed: {e}")
            return []
    
    async def _scan_directory_for_new_files(self, directory_path: str, current_files: set, events: List[EventData]):
        """Scan directory for new files"""
        try:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        file_key = self._create_file_key(file_path)
                        current_files.add(file_key)
                        
                        # Check if this is a new file
                        if file_key not in self.known_files:
                            # New file detected
                            event = self._create_file_event(
                                action=EventAction.CREATE,
                                file_path=file_path,
                                file_name=file,
                                file_size=os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                                file_hash=await self._get_file_hash(file_path) if os.path.exists(file_path) else None,
                                severity=self._determine_file_severity(file_path)
                            )
                            events.append(event)
                            
                            # Update tracking
                            if os.path.exists(file_path):
                                try:
                                    file_hash = await self._get_file_hash(file_path)
                                    self.file_hashes[file_key] = file_hash
                                except:
                                    pass
                            
                            # Check if suspicious
                            if self._is_suspicious_file(file_path):
                                self.suspicious_files.add(file_key)
                                self.logger.warning(f"🚨 Suspicious file detected: {file_path}")
                    
                    except (OSError, PermissionError):
                        continue
                        
        except Exception as e:
            self.logger.debug(f"New file scan failed for {directory_path}: {e}")
    
    async def _detect_modified_files(self) -> List[EventData]:
        """Detect modified files"""
        try:
            events = []
            
            for file_key in list(self.known_files):
                try:
                    file_path = self._get_file_path_from_key(file_key)
                    if not file_path or not os.path.exists(file_path):
                        continue
                    
                    # Check if file was modified
                    current_hash = await self._get_file_hash(file_path)
                    original_hash = self.file_hashes.get(file_key)
                    
                    if original_hash and current_hash != original_hash:
                        # File modified
                        event = self._create_file_event(
                            action=EventAction.MODIFY,
                            file_path=file_path,
                            file_name=os.path.basename(file_path),
                            file_size=os.path.getsize(file_path),
                            file_hash=current_hash,
                            severity=Severity.MEDIUM,
                            additional_data={
                                'original_hash': original_hash,
                                'new_hash': current_hash
                            }
                        )
                        events.append(event)
                        
                        # Update hash
                        self.file_hashes[file_key] = current_hash
                        
                        # Check if suspicious
                        if self._is_suspicious_file(file_path):
                            self.suspicious_files.add(file_key)
                
                except (OSError, PermissionError):
                    continue
            
            return events
            
        except Exception as e:
            self.logger.error(f"Modified file detection failed: {e}")
            return []
    
    async def _detect_deleted_files(self) -> List[EventData]:
        """Detect deleted files"""
        try:
            events = []
            
            for file_key in list(self.known_files):
                try:
                    file_path = self._get_file_path_from_key(file_key)
                    if file_path and not os.path.exists(file_path):
                        # File deleted
                        event = self._create_file_event(
                            action=EventAction.DELETE,
                            file_path=file_path,
                            file_name=os.path.basename(file_path),
                            file_size=0,
                            file_hash=None,
                            severity=Severity.LOW
                        )
                        events.append(event)
                        
                        # Clean up tracking
                        self.file_hashes.pop(file_key, None)
                        self.suspicious_files.discard(file_key)
                
                except Exception:
                    continue
            
            return events
            
        except Exception as e:
            self.logger.error(f"Deleted file detection failed: {e}")
            return []
    
    async def _monitor_suspicious_files(self) -> List[EventData]:
        """Monitor activities of suspicious files"""
        try:
            events = []
            
            for file_key in list(self.suspicious_files):
                try:
                    file_path = self._get_file_path_from_key(file_key)
                    if not file_path or not os.path.exists(file_path):
                        self.suspicious_files.discard(file_key)
                        continue
                    
                    # Monitor suspicious activities
                    event = await self._check_suspicious_file_activity(file_path)
                    if event:
                        events.append(event)
                
                except Exception:
                    continue
            
            return events
            
        except Exception as e:
            self.logger.error(f"Suspicious file monitoring failed: {e}")
            return []
    
    async def _check_suspicious_file_activity(self, file_path: str) -> Optional[EventData]:
        """Check for suspicious activities in a file"""
        try:
            # Check file attributes
            if os.path.exists(file_path):
                stat = os.stat(file_path)
                
                # Check if file is executable
                if os.access(file_path, os.X_OK):
                    return self._create_file_event(
                        action=EventAction.SUSPICIOUS_ACTIVITY,
                        file_path=file_path,
                        file_name=os.path.basename(file_path),
                        file_size=stat.st_size,
                        file_hash=await self._get_file_hash(file_path),
                        severity=Severity.HIGH,
                        additional_data={
                            'suspicious_activity': 'executable_file',
                            'file_permissions': oct(stat.st_mode)[-3:]
                        }
                    )
                
                # Check if file is in suspicious location
                if self._is_suspicious_location(file_path):
                    return self._create_file_event(
                        action=EventAction.SUSPICIOUS_ACTIVITY,
                        file_path=file_path,
                        file_name=os.path.basename(file_path),
                        file_size=stat.st_size,
                        file_hash=await self._get_file_hash(file_path),
                        severity=Severity.MEDIUM,
                        additional_data={
                            'suspicious_activity': 'suspicious_location',
                            'location': file_path
                        }
                    )
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Suspicious file activity check failed: {e}")
            return None
    
    async def _monitor_file_access(self) -> List[EventData]:
        """Monitor file access patterns"""
        try:
            events = []
            
            # This would require integration with Windows API for real-time file access monitoring
            # For now, we'll monitor file timestamps
            for file_key in list(self.known_files):
                try:
                    file_path = self._get_file_path_from_key(file_key)
                    if not file_path or not os.path.exists(file_path):
                        continue
                    
                    stat = os.stat(file_path)
                    current_time = time.time()
                    
                    # Check if file was accessed recently
                    if current_time - stat.st_atime < 60:  # Accessed within last minute
                        event = self._create_file_event(
                            action=EventAction.ACCESS,
                            file_path=file_path,
                            file_name=os.path.basename(file_path),
                            file_size=stat.st_size,
                            file_hash=await self._get_file_hash(file_path),
                            severity=Severity.LOW,
                            additional_data={
                                'access_time': stat.st_atime,
                                'modification_time': stat.st_mtime
                            }
                        )
                        events.append(event)
                
                except (OSError, PermissionError):
                    continue
            
            return events
            
        except Exception as e:
            self.logger.error(f"File access monitoring failed: {e}")
            return []
    
    async def _monitor_file_sizes(self) -> List[EventData]:
        """Monitor file size changes"""
        try:
            events = []
            
            for file_key in list(self.known_files):
                try:
                    file_path = self._get_file_path_from_key(file_key)
                    if not file_path or not os.path.exists(file_path):
                        continue
                    
                    current_size = os.path.getsize(file_path)
                    
                    # Check for significant size changes
                    if current_size > 10 * 1024 * 1024:  # Files larger than 10MB
                        event = self._create_file_event(
                            action=EventAction.RESOURCE_USAGE,
                            file_path=file_path,
                            file_name=os.path.basename(file_path),
                            file_size=current_size,
                            file_hash=await self._get_file_hash(file_path),
                            severity=Severity.MEDIUM,
                            additional_data={
                                'file_size_mb': current_size / (1024 * 1024)
                            }
                        )
                        events.append(event)
                
                except (OSError, PermissionError):
                    continue
            
            return events
            
        except Exception as e:
            self.logger.error(f"File size monitoring failed: {e}")
            return []
    
    def _create_file_key(self, file_path: str) -> str:
        """Create unique key for file tracking"""
        return file_path.lower()
    
    def _get_file_path_from_key(self, file_key: str) -> Optional[str]:
        """Get file path from key"""
        try:
            # This is a simple implementation - in practice, you'd want a more robust mapping
            return file_key
        except:
            return None
    
    async def _get_file_hash(self, file_path: str) -> Optional[str]:
        """Get file hash"""
        try:
            if not os.path.exists(file_path):
                return None
            
            # Use file utils for hash calculation
            if hasattr(self, 'file_utils'):
                return self.file_utils.calculate_file_hash(file_path)
            else:
                # Fallback hash calculation
                hash_md5 = hashlib.md5()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_md5.update(chunk)
                return hash_md5.hexdigest()
                
        except Exception:
            return None
    
    def _is_suspicious_file(self, file_path: str) -> bool:
        """Check if file is suspicious"""
        try:
            file_path_lower = file_path.lower()
            
            # Check extension
            if any(ext in file_path_lower for ext in self.suspicious_extensions):
                return True
            
            # Check location
            if self._is_suspicious_location(file_path):
                return True
            
            return False
            
        except:
            return False
    
    def _is_suspicious_location(self, file_path: str) -> bool:
        """Check if file is in suspicious location"""
        try:
            file_path_lower = file_path.lower()
            return any(path in file_path_lower for path in self.suspicious_paths)
        except:
            return False
    
    def _determine_file_severity(self, file_path: str) -> Severity:
        """Determine severity based on file characteristics"""
        if self._is_suspicious_file(file_path):
            return Severity.HIGH
        elif any(ext in file_path.lower() for ext in ['.exe', '.dll', '.bat', '.cmd']):
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _create_file_event(self, action: EventAction, file_path: str, file_name: str,
                          file_size: int, file_hash: Optional[str], severity: Severity,
                          additional_data: Dict = None) -> EventData:
        """Create file event data"""
        try:
            return EventData(
                event_type=EventType.FILE,
                event_action=action,
                event_timestamp=datetime.now(),
                severity=severity,
                file_path=file_path,
                file_name=file_name,
                file_size=file_size,
                file_hash=file_hash,
                file_extension=Path(file_path).suffix if file_path else None,
                raw_event_data=additional_data or {}
            )
            
        except Exception as e:
            self.logger.error(f"File event creation failed: {e}")
            return None