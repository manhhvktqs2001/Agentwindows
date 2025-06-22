# agent/collectors/file_collector.py - MULTIPLE FILE EVENT TYPES
"""
Enhanced File Collector - Gửi nhiều loại file events liên tục
Thu thập nhiều loại thông tin file và gửi events khác nhau cho server
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

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventType, EventAction, Severity
from agent.utils.file_utils import FileUtils, get_file_info, calculate_file_hash, is_suspicious_file

logger = logging.getLogger('FileCollector')

class EnhancedFileCollector(BaseCollector):
    """Enhanced File Collector - Multiple file event types for continuous sending"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "FileCollector")
        
        # MULTIPLE EVENTS: File tracking
        self.monitored_files = {}  # file_path -> file_info
        self.file_access_count = defaultdict(int)
        self.large_files = {}  # Track large file operations
        self.recent_downloads = set()
        
        # MULTIPLE EVENTS: File categories for different events
        self.suspicious_extensions = {
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
            '.scr', '.pif', '.com', '.hta', '.msi', '.msu', '.msp'
        }
        
        self.document_extensions = {
            '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx', '.txt'
        }
        
        self.image_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg'
        }
        
        self.archive_extensions = {
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'
        }
        
        # MULTIPLE EVENTS: Thresholds for different event types
        self.large_file_threshold = 50 * 1024 * 1024  # 50MB
        self.frequent_access_threshold = 5  # 5 accesses in scan period
        self.polling_interval = 1.0  # 1 second for file monitoring
        
        # Monitor directories for different event types
        self.monitor_directories = {
            'critical': [
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Downloads"),
                "C:/Windows/System32",
                "C:/Program Files",
                "C:/Program Files (x86)"
            ],
            'documents': [
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/Pictures"),
                os.path.expanduser("~/Videos")
            ],
            'temp': [
                os.path.expanduser("~/AppData/Local/Temp"),
                os.path.expanduser("~/AppData/Roaming"),
                "C:/Windows/Temp",
                "C:/ProgramData"
            ]
        }
        
        # MULTIPLE EVENTS: Statistics
        self.stats = {
            'file_creation_events': 0,
            'file_modification_events': 0,
            'file_deletion_events': 0,
            'file_access_events': 0,
            'suspicious_file_events': 0,
            'large_file_events': 0,
            'document_events': 0,
            'executable_events': 0,
            'archive_events': 0,
            'total_file_events': 0
        }
        
        self.logger.info("Enhanced File Collector initialized for MULTIPLE FILE EVENT TYPES")
    
    async def _collect_data(self):
        """Collect multiple types of file events"""
        try:
            events = []
            current_files = {}
            
            # MULTIPLE EVENTS: Scan all monitored directories
            for category, directories in self.monitor_directories.items():
                for directory in directories:
                    if os.path.exists(directory):
                        try:
                            dir_events = await self._scan_directory_for_multiple_events(directory, category)
                            events.extend(dir_events)
                        except Exception as e:
                            self.logger.debug(f"Error scanning directory {directory}: {e}")
                            continue
            
            # EVENT TYPE 1: File System Summary Event (every 10 scans)
            if self.stats['total_file_events'] % 10 == 0:
                summary_event = await self._create_file_system_summary_event()
                if summary_event:
                    events.append(summary_event)
            
            # EVENT TYPE 2: Disk Usage Event (if high)
            disk_event = await self._check_disk_usage_event()
            if disk_event:
                events.append(disk_event)
            
            self.stats['total_file_events'] += len(events)
            
            if events:
                self.logger.info(f"📤 Generated {len(events)} MULTIPLE FILE EVENTS for continuous sending")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Multiple file events collection failed: {e}")
            return []
    
    async def _scan_directory_for_multiple_events(self, directory: str, category: str) -> List[EventData]:
        """Scan directory and generate multiple event types"""
        events = []
        
        try:
            for root, dirs, filenames in os.walk(directory):
                # Skip system directories to avoid permission issues
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['$Recycle.Bin', 'System Volume Information']]
                
                for filename in filenames:
                    try:
                        file_path = os.path.join(root, filename)
                        
                        if self._should_skip_file(file_path):
                            continue
                        
                        # Get file info
                        file_info = get_file_info(file_path)
                        if not file_info:
                            continue
                        
                        file_key = file_path
                        current_time = time.time()
                        
                        # EVENT TYPE 1: New File Creation Event
                        if file_key not in self.monitored_files:
                            event = await self._create_file_creation_event(file_path, file_info, category)
                            if event:
                                events.append(event)
                                self.stats['file_creation_events'] += 1
                        
                        # EVENT TYPE 2: File Modification Event
                        elif (file_key in self.monitored_files and 
                              file_info.get('modify_time', 0) > self.monitored_files[file_key].get('modify_time', 0)):
                            event = await self._create_file_modification_event(file_path, file_info, category)
                            if event:
                                events.append(event)
                                self.stats['file_modification_events'] += 1
                        
                        # EVENT TYPE 3: Large File Event
                        if file_info.get('size', 0) > self.large_file_threshold:
                            event = await self._create_large_file_event(file_path, file_info)
                            if event:
                                events.append(event)
                                self.stats['large_file_events'] += 1
                        
                        # EVENT TYPE 4: Suspicious File Event
                        if is_suspicious_file(file_path):
                            event = await self._create_suspicious_file_event(file_path, file_info)
                            if event:
                                events.append(event)
                                self.stats['suspicious_file_events'] += 1
                        
                        # EVENT TYPE 5: File Type Specific Events
                        ext = file_info.get('extension', '').lower()
                        if ext in self.document_extensions:
                            event = await self._create_document_file_event(file_path, file_info)
                            if event:
                                events.append(event)
                                self.stats['document_events'] += 1
                        
                        elif ext in self.suspicious_extensions:
                            event = await self._create_executable_file_event(file_path, file_info)
                            if event:
                                events.append(event)
                                self.stats['executable_events'] += 1
                        
                        elif ext in self.archive_extensions:
                            event = await self._create_archive_file_event(file_path, file_info)
                            if event:
                                events.append(event)
                                self.stats['archive_events'] += 1
                        
                        # EVENT TYPE 6: File Access Pattern Event
                        self.file_access_count[file_key] += 1
                        if self.file_access_count[file_key] >= self.frequent_access_threshold:
                            event = await self._create_frequent_access_event(file_path, file_info)
                            if event:
                                events.append(event)
                                self.stats['file_access_events'] += 1
                            self.file_access_count[file_key] = 0  # Reset counter
                        
                        # Update tracked file info
                        self.monitored_files[file_key] = {
                            'size': file_info.get('size', 0),
                            'modify_time': file_info.get('modify_time', 0),
                            'access_time': file_info.get('access_time', 0),
                            'last_seen': current_time,
                            'extension': ext,
                            'category': category
                        }
                        
                    except (OSError, PermissionError):
                        continue
                        
        except Exception as e:
            self.logger.debug(f"Directory scan error for {directory}: {e}")
        
        return events
    
    async def _create_file_creation_event(self, file_path: str, file_info: Dict, category: str):
        """EVENT TYPE 1: File Creation Event"""
        try:
            severity = "High" if is_suspicious_file(file_path) else "Info"
            
            return EventData(
                event_type=EventType.FILE,
                event_action=EventAction.CREATE,
                event_timestamp=datetime.now(),
                severity=severity,
                
                file_path=file_path,
                file_name=os.path.basename(file_path),
                file_size=file_info.get('size', 0),
                file_extension=file_info.get('extension', ''),
                
                description=f"📄 FILE CREATED: {os.path.basename(file_path)} in {category} directory",
                raw_event_data={
                    'event_subtype': 'file_creation',
                    'directory_category': category,
                    'file_info': file_info,
                    'is_suspicious': is_suspicious_file(file_path),
                    'creation_time': time.time()
                }
            )
        except Exception as e:
            self.logger.error(f"❌ File creation event failed: {e}")
            return None
    
    async def _create_file_modification_event(self, file_path: str, file_info: Dict, category: str):
        """EVENT TYPE 2: File Modification Event"""
        try:
            return EventData(
                event_type=EventType.FILE,
                event_action=EventAction.MODIFY,
                event_timestamp=datetime.now(),
                severity="Medium" if is_suspicious_file(file_path) else "Info",
                
                file_path=file_path,
                file_name=os.path.basename(file_path),
                file_size=file_info.get('size', 0),
                file_extension=file_info.get('extension', ''),
                
                description=f"✏️ FILE MODIFIED: {os.path.basename(file_path)}",
                raw_event_data={
                    'event_subtype': 'file_modification',
                    'directory_category': category,
                    'modify_time': file_info.get('modify_time'),
                    'previous_info': self.monitored_files.get(file_path, {}),
                    'size_change': file_info.get('size', 0) - self.monitored_files.get(file_path, {}).get('size', 0)
                }
            )
        except Exception as e:
            self.logger.error(f"❌ File modification event failed: {e}")
            return None
    
    async def _create_large_file_event(self, file_path: str, file_info: Dict):
        """EVENT TYPE 3: Large File Event"""
        try:
            size_mb = file_info.get('size', 0) / (1024 * 1024)
            
            return EventData(
                event_type=EventType.FILE,
                event_action=EventAction.CREATE,
                event_timestamp=datetime.now(),
                severity="Medium",
                
                file_path=file_path,
                file_name=os.path.basename(file_path),
                file_size=file_info.get('size', 0),
                file_extension=file_info.get('extension', ''),
                
                description=f"📦 LARGE FILE: {os.path.basename(file_path)} ({size_mb:.1f}MB)",
                raw_event_data={
                    'event_subtype': 'large_file_detected',
                    'size_mb': size_mb,
                    'threshold_mb': self.large_file_threshold / (1024 * 1024),
                    'file_category': 'large_file'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Large file event failed: {e}")
            return None
    
    async def _create_suspicious_file_event(self, file_path: str, file_info: Dict):
        """EVENT TYPE 4: Suspicious File Event"""
        try:
            return EventData(
                event_type=EventType.FILE,
                event_action=EventAction.SUSPICIOUS_ACTIVITY,
                event_timestamp=datetime.now(),
                severity="High",
                
                file_path=file_path,
                file_name=os.path.basename(file_path),
                file_size=file_info.get('size', 0),
                file_extension=file_info.get('extension', ''),
                
                description=f"🚨 SUSPICIOUS FILE: {os.path.basename(file_path)} detected",
                raw_event_data={
                    'event_subtype': 'suspicious_file_detected',
                    'suspicion_reason': 'suspicious_extension_or_location',
                    'risk_level': 'high',
                    'file_category': 'suspicious'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Suspicious file event failed: {e}")
            return None
    
    async def _create_document_file_event(self, file_path: str, file_info: Dict):
        """EVENT TYPE 5: Document File Event"""
        try:
            return EventData(
                event_type=EventType.FILE,
                event_action=EventAction.ACCESS,
                event_timestamp=datetime.now(),
                severity="Info",
                
                file_path=file_path,
                file_name=os.path.basename(file_path),
                file_size=file_info.get('size', 0),
                file_extension=file_info.get('extension', ''),
                
                description=f"📄 DOCUMENT FILE: {os.path.basename(file_path)} accessed",
                raw_event_data={
                    'event_subtype': 'document_file_activity',
                    'file_category': 'document',
                    'document_type': file_info.get('extension', '').replace('.', '')
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Document file event failed: {e}")
            return None
    
    async def _create_executable_file_event(self, file_path: str, file_info: Dict):
        """EVENT TYPE 6: Executable File Event"""
        try:
            return EventData(
                event_type=EventType.FILE,
                event_action=EventAction.CREATE,
                event_timestamp=datetime.now(),
                severity="High",
                
                file_path=file_path,
                file_name=os.path.basename(file_path),
                file_size=file_info.get('size', 0),
                file_extension=file_info.get('extension', ''),
                
                description=f"⚡ EXECUTABLE FILE: {os.path.basename(file_path)} detected",
                raw_event_data={
                    'event_subtype': 'executable_file_detected',
                    'file_category': 'executable',
                    'executable_type': file_info.get('extension', '').replace('.', ''),
                    'requires_analysis': True
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Executable file event failed: {e}")
            return None
    
    async def _create_archive_file_event(self, file_path: str, file_info: Dict):
        """EVENT TYPE 7: Archive File Event"""
        try:
            return EventData(
                event_type=EventType.FILE,
                event_action=EventAction.CREATE,
                event_timestamp=datetime.now(),
                severity="Medium",
                
                file_path=file_path,
                file_name=os.path.basename(file_path),
                file_size=file_info.get('size', 0),
                file_extension=file_info.get('extension', ''),
                
                description=f"🗜️ ARCHIVE FILE: {os.path.basename(file_path)} detected",
                raw_event_data={
                    'event_subtype': 'archive_file_detected',
                    'file_category': 'archive',
                    'archive_type': file_info.get('extension', '').replace('.', ''),
                    'needs_scanning': True
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Archive file event failed: {e}")
            return None
    
    async def _create_frequent_access_event(self, file_path: str, file_info: Dict):
        """EVENT TYPE 8: Frequent File Access Event"""
        try:
            return EventData(
                event_type=EventType.FILE,
                event_action=EventAction.ACCESS,
                event_timestamp=datetime.now(),
                severity="Medium",
                
                file_path=file_path,
                file_name=os.path.basename(file_path),
                file_size=file_info.get('size', 0),
                
                description=f"🔄 FREQUENT ACCESS: {os.path.basename(file_path)} accessed multiple times",
                raw_event_data={
                    'event_subtype': 'frequent_file_access',
                    'access_count': self.file_access_count[file_path],
                    'access_threshold': self.frequent_access_threshold,
                    'file_category': 'frequently_accessed'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Frequent access event failed: {e}")
            return None
    
    async def _create_file_system_summary_event(self):
        """EVENT TYPE 9: File System Summary Event"""
        try:
            total_files = len(self.monitored_files)
            
            return EventData(
                event_type=EventType.FILE,
                event_action=EventAction.RESOURCE_USAGE,
                event_timestamp=datetime.now(),
                severity="Info",
                
                description=f"📊 FILE SYSTEM SUMMARY: {total_files} files monitored",
                raw_event_data={
                    'event_subtype': 'file_system_summary',
                    'total_monitored_files': total_files,
                    'file_statistics': self.stats.copy(),
                    'directory_counts': {
                        'critical': len([f for f in self.monitored_files.values() if f.get('category') == 'critical']),
                        'documents': len([f for f in self.monitored_files.values() if f.get('category') == 'documents']),
                        'temp': len([f for f in self.monitored_files.values() if f.get('category') == 'temp'])
                    }
                }
            )
        except Exception as e:
            self.logger.error(f"❌ File system summary event failed: {e}")
            return None
    
    async def _check_disk_usage_event(self):
        """EVENT TYPE 10: Disk Usage Event"""
        try:
            for root in ['C:/', 'D:/', 'E:/']:
                if os.path.exists(root):
                    disk_usage = shutil.disk_usage(root)
                    total_gb = disk_usage.total / (1024**3)
                    free_gb = disk_usage.free / (1024**3)
                    used_percent = (disk_usage.used / disk_usage.total) * 100
                    
                    if used_percent > 85:  # High disk usage
                        return EventData(
                            event_type=EventType.FILE,
                            event_action=EventAction.RESOURCE_USAGE,
                            event_timestamp=datetime.now(),
                            severity="High" if used_percent > 95 else "Medium",
                            
                            description=f"💾 HIGH DISK USAGE: Drive {root} is {used_percent:.1f}% full",
                            raw_event_data={
                                'event_subtype': 'high_disk_usage',
                                'drive': root,
                                'used_percent': used_percent,
                                'total_gb': total_gb,
                                'free_gb': free_gb,
                                'threshold_percent': 85
                            }
                        )
        except Exception as e:
            self.logger.error(f"❌ Disk usage event failed: {e}")
        return None
    
    def _should_skip_file(self, file_path: str) -> bool:
        """Check if file should be skipped"""
        try:
            # Skip system files and very large files
            if any(skip in file_path.lower() for skip in [
                'pagefile.sys', 'hiberfil.sys', 'swapfile.sys',
                'ntuser.dat', 'ntuser.ini', 'desktop.ini',
                'thumbs.db', '.tmp', '.temp', '.log'
            ]):
                return True
            
            # Skip files that are too large (> 200MB) for performance
            try:
                if os.path.getsize(file_path) > 200 * 1024 * 1024:
                    return True
            except (OSError, PermissionError):
                return True
            
            return False
            
        except Exception:
            return True
    
    def get_stats(self) -> Dict:
        """Get detailed statistics for multiple file event types"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'File_MultipleEvents',
            'file_creation_events': self.stats['file_creation_events'],
            'file_modification_events': self.stats['file_modification_events'],
            'file_deletion_events': self.stats['file_deletion_events'],
            'file_access_events': self.stats['file_access_events'],
            'suspicious_file_events': self.stats['suspicious_file_events'],
            'large_file_events': self.stats['large_file_events'],
            'document_events': self.stats['document_events'],
            'executable_events': self.stats['executable_events'],
            'archive_events': self.stats['archive_events'],
            'total_file_events': self.stats['total_file_events'],
            'monitored_files_count': len(self.monitored_files),
            'multiple_event_types': True,
            'file_event_types_generated': [
                'file_creation', 'file_modification', 'large_file_detected',
                'suspicious_file_detected', 'document_file_activity', 
                'executable_file_detected', 'archive_file_detected',
                'frequent_file_access', 'file_system_summary', 'high_disk_usage'
            ]
        })
        return base_stats