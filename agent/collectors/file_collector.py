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
from agent.schemas.events import EventData, EventAction, Severity
from agent.utils.file_utils import FileUtils, get_file_info, calculate_file_hash, is_suspicious_file

logger = logging.getLogger('FileCollector')

class EnhancedFileCollector(BaseCollector):
    """Enhanced File Collector - Multiple file event types for continuous sending"""
    
    def __init__(self, config_manager=None):
        super().__init__(config_manager, "FileCollector")
        
        # FIXED: Optimize performance settings
        self.polling_interval = 30  # Increase from default to 30 seconds
        self.max_events_per_batch = 50  # Reduce from default
        self.large_file_threshold = 100 * 1024 * 1024  # 100MB
        self.frequent_access_threshold = 10
        
        # FIXED: Reduce scanning directories for better performance
        self.scan_directories = {
            'system': ['C:\\Windows\\System32'],
            'temp': ['C:\\Temp', 'C:\\Windows\\Temp'],
            'user': ['C:\\Users\\Public\\Desktop']
        }
        
        # FIXED: Reduce file extensions to monitor
        self.document_extensions = {'.doc', '.docx', '.pdf', '.txt'}
        self.suspicious_extensions = {'.exe', '.bat', '.cmd', '.ps1', '.vbs'}
        self.archive_extensions = {'.zip', '.rar', '.7z'}
        
        # Tracking
        self.monitored_files = {}
        self.file_access_count = defaultdict(int)
        
        # Statistics
        self.stats = {
            'file_creation_events': 0,
            'file_modification_events': 0,
            'large_file_events': 0,
            'suspicious_file_events': 0,
            'document_events': 0,
            'executable_events': 0,
            'archive_events': 0,
            'file_access_events': 0,
            'total_file_events': 0
        }
        
        self.logger.info("Enhanced File Collector initialized - PERFORMANCE OPTIMIZED")
    
    async def _collect_data(self):
        """Collect multiple types of file events - OPTIMIZED VERSION"""
        start_time = time.time()
        try:
            events = []
            
            # FIXED: Only scan critical directories for better performance
            for category, directories in self.scan_directories.items():
                for directory in directories:
                    if os.path.exists(directory):
                        try:
                            # FIXED: Limit directory depth for better performance
                            dir_events = await self._scan_directory_for_multiple_events(directory, category, max_depth=2)
                            events.extend(dir_events)
                        except Exception as e:
                            self.logger.debug(f"Error scanning directory {directory}: {e}")
                            continue
            
            # FIXED: Reduce summary event frequency
            if self.stats['total_file_events'] % 50 == 0:  # Every 50 scans instead of 10
                summary_event = await self._create_file_system_summary_event()
                if summary_event:
                    events.append(summary_event)
            
            # FIXED: Only check disk usage occasionally
            if self.stats['total_file_events'] % 100 == 0:  # Every 100 scans
                disk_event = await self._check_disk_usage_event()
                if disk_event:
                    events.append(disk_event)
            
            self.stats['total_file_events'] += len(events)
            
            if events:
                self.logger.info(f"📤 Generated {len(events)} OPTIMIZED FILE EVENTS")
            
            # FIXED: Log performance metrics with better thresholds
            collection_time = (time.time() - start_time) * 1000
            if collection_time > 5000:  # Reduce threshold from 10000ms to 5000ms
                self.logger.warning(f"⚠️ Slow collection: {collection_time:.1f}ms in FileCollector")
            elif collection_time > 2000:
                self.logger.info(f"📊 File scan time: {collection_time:.1f}ms")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Multiple file events collection failed: {e}")
            return []
    
    async def _scan_directory_for_multiple_events(self, directory: str, category: str, max_depth: int = 2) -> List[EventData]:
        """Scan directory and generate events for NEW/MODIFIED files only - OPTIMIZED"""
        events = []
        
        try:
            # FIXED: Limit scan depth and file count for better performance
            file_count = 0
            max_files_per_directory = 100  # Limit files per directory
            
            for root, dirs, filenames in os.walk(directory):
                # FIXED: Limit directory depth
                current_depth = root[len(directory):].count(os.sep)
                if current_depth > max_depth:
                    continue
                
                # Skip system directories to avoid permission issues
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['$Recycle.Bin', 'System Volume Information']]
                
                for filename in filenames:
                    # FIXED: Limit file count per directory
                    if file_count >= max_files_per_directory:
                        break
                    
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
                        
                        # FIXED: Only create events for interesting files
                        ext = file_info.get('extension', '').lower()
                        is_interesting = (ext in self.suspicious_extensions or 
                                        ext in self.document_extensions or 
                                        ext in self.archive_extensions or
                                        file_info.get('size', 0) > self.large_file_threshold)
                        
                        if not is_interesting:
                            continue
                        
                        # FIXED: Only create events for NEW or MODIFIED files
                        file_modified = False
                        if file_key in self.monitored_files:
                            old_modify_time = self.monitored_files[file_key].get('modify_time', 0)
                            new_modify_time = file_info.get('modify_time', 0)
                            file_modified = new_modify_time > old_modify_time
                        
                        # EVENT TYPE 1: New File Creation Event
                        if file_key not in self.monitored_files:
                            event = await self._create_file_creation_event(file_path, file_info, category)
                            if event:
                                events.append(event)
                                self.stats['file_creation_events'] += 1
                        
                        # EVENT TYPE 2: File Modification Event (only if actually modified)
                        elif file_modified:
                            event = await self._create_file_modification_event(file_path, file_info, category)
                            if event:
                                events.append(event)
                                self.stats['file_modification_events'] += 1
                        
                        # EVENT TYPE 3: Large File Event (only for new or modified files)
                        if (file_key not in self.monitored_files or file_modified) and file_info.get('size', 0) > self.large_file_threshold:
                            event = await self._create_large_file_event(file_path, file_info)
                            if event:
                                events.append(event)
                                self.stats['large_file_events'] += 1
                        
                        # EVENT TYPE 4: Suspicious File Event (only for new or modified files)
                        if (file_key not in self.monitored_files or file_modified) and ext in self.suspicious_extensions:
                            event = await self._create_suspicious_file_event(file_path, file_info)
                            if event:
                                events.append(event)
                                self.stats['suspicious_file_events'] += 1
                        
                        # Update tracked file info
                        self.monitored_files[file_key] = {
                            'size': file_info.get('size', 0),
                            'modify_time': file_info.get('modify_time', 0),
                            'access_time': file_info.get('access_time', 0),
                            'last_seen': current_time,
                            'extension': ext,
                            'category': category
                        }
                        
                        file_count += 1
                        
                    except (OSError, PermissionError):
                        continue
                    except Exception as e:
                        self.logger.debug(f"Error processing file {filename}: {e}")
                        continue
                
                # FIXED: Break if we've reached the file limit
                if file_count >= max_files_per_directory:
                    break
            
            return events
            
        except Exception as e:
            self.logger.error(f"Error scanning directory {directory}: {e}")
            return []
    
    async def _create_file_creation_event(self, file_path: str, file_info: Dict, category: str):
        """EVENT TYPE 1: File Creation Event"""
        try:
            severity = "High" if is_suspicious_file(file_path) else "Info"
            
            return EventData(
                event_type="File",
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
                event_type="File",
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
                event_type="File",
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
                event_type="File",
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
                event_type="File",
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
                event_type="File",
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
                event_type="File",
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
                event_type="File",
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
                event_type="File",
                event_action=EventAction.RESOURCE_USAGE,
                event_timestamp=datetime.now(),
                severity="Info",
                
                description=f"📊 FILE SYSTEM SUMMARY: {total_files} files monitored",
                raw_event_data={
                    'event_subtype': 'file_system_summary',
                    'total_monitored_files': total_files,
                    'file_statistics': self.stats.copy(),
                    'directory_counts': {
                        'system': len([f for f in self.monitored_files.values() if f.get('category') == 'system']),
                        'temp': len([f for f in self.monitored_files.values() if f.get('category') == 'temp']),
                        'user': len([f for f in self.monitored_files.values() if f.get('category') == 'user'])
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
                            event_type="File",
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