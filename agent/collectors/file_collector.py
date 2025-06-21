# agent/collectors/file_collector.py - Completely Fixed
"""
File Collector - Fixed all access issues and attribute errors
"""

import asyncio
import logging
import hashlib
import os
import platform
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set
import json

from .base_collector import BaseCollector
from ..schemas.events import EventData

class FileCollector(BaseCollector):
    """File system monitoring collector - Completely Fixed"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "FileCollector")
        
        # IMPORTANT: Initialize ALL attributes FIRST
        self.restricted_paths = []
        self.accessible_paths = []
        self.excluded_extensions = {'.tmp', '.log', '.bak', '.swp', '.lock'}
        self.excluded_directories = set()
        self.max_file_size = 100 * 1024 * 1024  # 100MB
        
        # File monitoring settings
        self.observer = None
        self.event_handler = None
        self.observer_started = False
        
        # Configuration
        self.collect_hashes = True
        self.monitor_creation = True
        self.monitor_modification = True
        self.monitor_deletion = True
        self.monitor_moves = True
        
        # Event tracking
        self.recent_events = {}
        self.event_deduplication_window = 1.0  # seconds
        
        # Now get monitor paths (after all attributes are initialized)
        self.monitor_paths = self._get_monitor_paths()
        
        # Setup filters
        self._setup_filters()
    
    def _get_monitor_paths(self) -> List[str]:
        """Get paths to monitor with access checking"""
        try:
            # Start with empty lists (already initialized)
            self.accessible_paths = []
            self.restricted_paths = []
            
            # User-accessible paths (most likely to work)
            user_home = str(Path.home())
            potential_paths = [
                user_home,
                os.path.join(user_home, 'Desktop'),
                os.path.join(user_home, 'Documents'),
                os.path.join(user_home, 'Downloads'),
                'C:\\Temp',
                'C:\\Users\\Public'
            ]
            
            # Test each path
            for path in potential_paths:
                if self._test_path_access(path):
                    self.accessible_paths.append(path)
                    self.logger.debug(f"✅ Accessible path: {path}")
                else:
                    self.restricted_paths.append(path)
                    self.logger.debug(f"❌ Restricted path: {path}")
            
            if not self.accessible_paths:
                self.logger.warning("⚠️ No accessible paths found for file monitoring")
            else:
                self.logger.info(f"📁 Found {len(self.accessible_paths)} accessible paths")
            
            return self.accessible_paths
            
        except Exception as e:
            self.logger.error(f"❌ Error getting monitor paths: {e}")
            return []
    
    def _test_path_access(self, path: str) -> bool:
        """Test if path is accessible for monitoring"""
        try:
            path_obj = Path(path)
            
            # Check if path exists
            if not path_obj.exists():
                return False
            
            # Check if we can read the directory
            if path_obj.is_dir():
                try:
                    # Try to list directory contents
                    list(path_obj.iterdir())
                    return True
                except (PermissionError, OSError):
                    return False
            
            return False
                
        except Exception:
            return False
    
    def _setup_filters(self):
        """Setup file filters from configuration"""
        try:
            filters_config = self.config.get('filters', {})
            
            # File extensions to exclude
            exclude_extensions = filters_config.get('exclude_file_extensions', [])
            self.excluded_extensions.update(ext.lower() for ext in exclude_extensions)
            
            # File size limit
            self.max_file_size = filters_config.get('max_file_size_mb', 100) * 1024 * 1024
            
            self.logger.debug(f"🔧 File filters configured: {len(self.excluded_extensions)} excluded extensions")
            
        except Exception as e:
            self.logger.error(f"❌ Error setting up filters: {e}")
    
    async def _collector_specific_init(self):
        """Initialize file collector"""
        try:
            # Only setup watchdog if we have accessible paths
            if self.accessible_paths:
                try:
                    from watchdog.observers import Observer
                    from watchdog.events import FileSystemEventHandler
                    
                    # Create observer
                    self.observer = Observer()
                    
                    # Create simple event handler
                    self.event_handler = SimpleFileEventHandler(self)
                    
                    # Schedule monitoring for accessible paths
                    for path in self.accessible_paths:
                        try:
                            self.observer.schedule(
                                self.event_handler,
                                path,
                                recursive=False  # Start with non-recursive to reduce load
                            )
                            self.logger.debug(f"📁 Scheduled monitoring for: {path}")
                        except Exception as e:
                            self.logger.warning(f"⚠️ Cannot monitor path {path}: {e}")
                    
                    self.logger.info(f"✅ File monitoring setup for {len(self.accessible_paths)} paths")
                    
                except ImportError:
                    self.logger.warning("⚠️ Watchdog not available - file monitoring disabled")
                except Exception as e:
                    self.logger.warning(f"⚠️ File monitoring setup failed: {e}")
            else:
                self.logger.warning("⚠️ No accessible paths - file monitoring disabled")
            
        except Exception as e:
            self.logger.error(f"❌ File collector initialization failed: {e}")
    
    async def start(self):
        """Start file monitoring"""
        try:
            await super().start()
            
            if self.observer and self.accessible_paths:
                try:
                    self.observer.start()
                    self.observer_started = True
                    self.logger.info("✅ File system monitoring started")
                except Exception as e:
                    self.logger.warning(f"⚠️ File monitoring failed to start: {e}")
            else:
                self.logger.info("📁 File monitoring disabled - no accessible paths")
            
        except Exception as e:
            self.logger.error(f"❌ File collector start failed: {e}")
    
    async def stop(self):
        """Stop file monitoring"""
        try:
            if self.observer and self.observer_started:
                try:
                    self.observer.stop()
                    self.observer.join(timeout=5)
                    self.observer_started = False
                    self.logger.info("🛑 File system monitoring stopped")
                except Exception as e:
                    self.logger.error(f"❌ Error stopping file observer: {e}")
            
            await super().stop()
            
        except Exception as e:
            self.logger.error(f"❌ File collector stop error: {e}")
    
    async def _collect_data(self):
        """File collector uses event-driven approach, no polling needed"""
        # Clean up old event tracking data
        await self._cleanup_recent_events()
        
        return []  # Return empty list as events come through file system events
    
    async def _cleanup_recent_events(self):
        """Clean up old event tracking data"""
        try:
            current_time = datetime.now()
            cutoff_time = current_time - timedelta(minutes=5)
            
            # Remove old events from tracking
            old_events = [
                event_id for event_id, timestamp in self.recent_events.items()
                if timestamp < cutoff_time
            ]
            
            for event_id in old_events:
                del self.recent_events[event_id]
                
        except Exception as e:
            self.logger.error(f"❌ Recent events cleanup error: {e}")
    
    async def handle_file_event(self, file_path: str, action: str):
        """Handle file system event (called by event handler)"""
        try:
            # Basic validation
            if not self._should_monitor_file(file_path):
                return
            
            # Deduplication check
            if self._is_duplicate_event(file_path, action):
                return
            
            # Get file information
            file_info = await self._get_file_info(file_path, action)
            if not file_info:
                return
            
            # Create event data
            event_data = EventData(
                event_type='File',
                event_action=action,
                event_timestamp=datetime.now(),
                severity='Info',
                description=f'File {action.lower()}: {file_info["name"]}',
                file_path=file_info['path'],
                file_name=file_info['name'],
                file_size=file_info['size'],
                file_hash=file_info['hash'],
                file_extension=file_info['extension'],
                file_operation=action,
                raw_event_data=json.dumps(file_info)
            )
            
            # Add to event queue
            await self.add_event(event_data)
            
            self.logger.debug(f"📄 File {action.lower()}: {file_info['name']}")
            
        except Exception as e:
            self.logger.error(f"❌ File event handling error: {e}")
    
    def _should_monitor_file(self, file_path: str) -> bool:
        """Check if file should be monitored"""
        try:
            path_obj = Path(file_path)
            
            # Check file extension
            if path_obj.suffix.lower() in self.excluded_extensions:
                return False
            
            # Check file size (if file exists)
            try:
                if path_obj.exists() and path_obj.stat().st_size > self.max_file_size:
                    return False
            except (OSError, PermissionError):
                pass
            
            return True
            
        except Exception:
            return False
    
    def _is_duplicate_event(self, file_path: str, action: str) -> bool:
        """Check if this is a duplicate event"""
        try:
            event_key = f"{file_path}:{action}"
            now = datetime.now()
            
            if event_key in self.recent_events:
                time_diff = (now - self.recent_events[event_key]).total_seconds()
                if time_diff < self.event_deduplication_window:
                    return True
            
            # Update recent events
            self.recent_events[event_key] = now
            return False
            
        except Exception:
            return False
    
    async def _get_file_info(self, file_path: str, action: str) -> Optional[Dict]:
        """Get detailed file information"""
        try:
            path_obj = Path(file_path)
            
            file_info = {
                'path': str(path_obj),
                'name': path_obj.name,
                'extension': path_obj.suffix.lower() if path_obj.suffix else None,
                'size': None,
                'hash': None,
                'exists': False,
                'action': action
            }
            
            # For delete events, file won't exist
            if action == 'Delete':
                return file_info
            
            # Get file details if file exists
            try:
                if path_obj.exists() and path_obj.is_file():
                    file_info['exists'] = True
                    stat_info = path_obj.stat()
                    file_info['size'] = stat_info.st_size
                    
                    # Calculate hash for small files only
                    if (self.collect_hashes and 
                        file_info['size'] and 
                        file_info['size'] < 10 * 1024 * 1024):  # 10MB limit
                        file_info['hash'] = await self._calculate_file_hash(file_path)
                    
            except (OSError, PermissionError) as e:
                self.logger.debug(f"Cannot access file {file_path}: {e}")
            
            return file_info
            
        except Exception as e:
            self.logger.error(f"❌ Error getting file info for {file_path}: {e}")
            return None
    
    async def _calculate_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate SHA256 hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            
            return hash_sha256.hexdigest()
            
        except Exception as e:
            self.logger.debug(f"Hash calculation failed for {file_path}: {e}")
            return None
    
    def get_file_stats(self) -> Dict:
        """Get file monitoring statistics"""
        return {
            'accessible_paths': self.accessible_paths,
            'restricted_paths': self.restricted_paths,
            'excluded_extensions': list(self.excluded_extensions),
            'max_file_size_mb': self.max_file_size / (1024 * 1024),
            'collect_hashes': self.collect_hashes,
            'recent_events_count': len(self.recent_events),
            'observer_running': self.observer_started,
            'monitor_paths_count': len(self.accessible_paths)
        }


class SimpleFileEventHandler:
    """Simple file event handler to avoid complex watchdog integration"""
    
    def __init__(self, file_collector):
        self.file_collector = file_collector
        self.logger = logging.getLogger(__name__)
    
    def on_created(self, event):
        """Handle file creation"""
        if not event.is_directory:
            asyncio.create_task(
                self.file_collector.handle_file_event(event.src_path, 'Create')
            )
    
    def on_modified(self, event):
        """Handle file modification"""
        if not event.is_directory:
            asyncio.create_task(
                self.file_collector.handle_file_event(event.src_path, 'Modify')
            )
    
    def on_deleted(self, event):
        """Handle file deletion"""
        if not event.is_directory:
            asyncio.create_task(
                self.file_collector.handle_file_event(event.src_path, 'Delete')
            )
    
    def on_moved(self, event):
        """Handle file move/rename"""
        if not event.is_directory:
            dest_path = getattr(event, 'dest_path', event.src_path)
            asyncio.create_task(
                self.file_collector.handle_file_event(dest_path, 'Move')
            )