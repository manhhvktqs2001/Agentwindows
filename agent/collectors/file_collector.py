# agent/collectors/file_collector.py
"""
File Collector - Fixed Access Denied and permission issues
Graceful handling of restricted paths
"""

import asyncio
import logging
import hashlib
import os
import platform
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from .base_collector import BaseCollector
from ..schemas.events import EventData

class FileEventHandler(FileSystemEventHandler):
    """Handle file system events"""
    
    def __init__(self, file_collector):
        self.file_collector = file_collector
        self.logger = logging.getLogger(__name__)
        try:
            self.loop = asyncio.get_running_loop()
        except RuntimeError:
            self.loop = asyncio.get_event_loop()
    
    def on_created(self, event: FileSystemEvent):
        """Handle file creation"""
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self.file_collector._handle_file_event(event.src_path, 'Create', event),
                self.loop
            )
    
    def on_modified(self, event: FileSystemEvent):
        """Handle file modification"""
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self.file_collector._handle_file_event(event.src_path, 'Modify', event),
                self.loop
            )
    
    def on_deleted(self, event: FileSystemEvent):
        """Handle file deletion"""
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self.file_collector._handle_file_event(event.src_path, 'Delete', event),
                self.loop
            )
    
    def on_moved(self, event: FileSystemEvent):
        """Handle file move/rename"""
        if not event.is_directory:
            asyncio.run_coroutine_threadsafe(
                self.file_collector._handle_file_event(
                    event.dest_path if hasattr(event, 'dest_path') else event.src_path, 
                    'Move', event
                ),
                self.loop
            )

class FileCollector(BaseCollector):
    """Collect file system events - Fixed access issues"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "FileCollector")
        
        # File monitoring
        self.observer: Optional[Observer] = None
        self.event_handler: Optional[FileEventHandler] = None
        self.observer_started = False
        
        # Configuration
        self.monitor_paths = self._get_monitor_paths()
        self.collect_hashes = True
        self.monitor_creation = True
        self.monitor_modification = True
        self.monitor_deletion = True
        self.monitor_moves = True
        
        # File filters
        self.excluded_extensions = {'.tmp', '.log', '.bak', '.swp', '.lock'}
        self.excluded_directories = set()
        self.max_file_size = 100 * 1024 * 1024  # 100MB
        
        # Event tracking
        self.recent_events: Dict[str, datetime] = {}
        self.event_deduplication_window = 1.0  # seconds
        
        # Access control
        self.accessible_paths = []
        self.restricted_paths = []
        
        self._setup_filters()
    
    def _get_monitor_paths(self) -> List[str]:
        """Get paths to monitor - with access checking"""
        try:
            # Default paths based on platform and user permissions
            if platform.system().lower() == 'windows':
                # User-accessible paths first
                user_paths = [
                    str(Path.home()),  # User's home directory
                    str(Path.home() / 'Desktop'),
                    str(Path.home() / 'Documents'),
                    str(Path.home() / 'Downloads'),
                    'C:\\Users\\Public',
                    'C:\\Temp'
                ]
                
                # System paths (may require admin)
                system_paths = [
                    'C:\\Users',
                    'C:\\Program Files',
                    'C:\\Program Files (x86)',
                    'C:\\ProgramData',
                    'C:\\Windows\\Temp'
                ]
                
                default_paths = user_paths + system_paths
            else:
                default_paths = [
                    str(Path.home()),
                    '/tmp',
                    '/var/tmp',
                    '/home',
                    '/usr/bin',
                    '/usr/local/bin',
                    '/etc',
                    '/var/log',
                    '/opt'
                ]
            
            # Get from configuration or use defaults
            config_paths = self.collection_config.get('monitor_paths', default_paths)
            
            # Test access to each path
            accessible_paths = []
            for path in config_paths:
                if self._test_path_access(path):
                    accessible_paths.append(str(Path(path).resolve()))
                else:
                    self.logger.warning(f"⚠️ Cannot access path: {path}")
                    self.restricted_paths.append(path)
            
            self.accessible_paths = accessible_paths
            return accessible_paths
            
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
                except PermissionError:
                    return False
                except OSError:
                    return False
            else:
                # For files, check if readable
                return path_obj.is_file() and os.access(str(path_obj), os.R_OK)
                
        except Exception:
            return False
    
    def _setup_filters(self):
        """Setup file filters from configuration"""
        try:
            filters_config = self.config.get('filters', {})
            
            # File extensions to exclude
            exclude_extensions = filters_config.get('exclude_file_extensions', [])
            self.excluded_extensions.update(ext.lower() for ext in exclude_extensions)
            
            # Directories to exclude
            exclude_dirs = filters_config.get('exclude_windows_directories', [])
            for exclude_dir in exclude_dirs:
                try:
                    if Path(exclude_dir).exists():
                        self.excluded_directories.add(Path(exclude_dir).resolve())
                except Exception:
                    pass
            
            # File size limit
            self.max_file_size = filters_config.get('max_file_size_mb', 100) * 1024 * 1024
            
        except Exception as e:
            self.logger.error(f"❌ Error setting up filters: {e}")
    
    async def _collector_specific_init(self):
        """Initialize file collector with access checking"""
        try:
            # Create event handler
            self.event_handler = FileEventHandler(self)
            
            # Create observer
            self.observer = Observer()
            
            # Setup monitoring for accessible paths only
            monitored_count = 0
            for path in self.accessible_paths:
                try:
                    self.observer.schedule(
                        self.event_handler,
                        path,
                        recursive=True
                    )
                    monitored_count += 1
                    self.logger.info(f"📁 Monitoring path: {path}")
                except Exception as e:
                    self.logger.warning(f"⚠️ Cannot monitor path {path}: {e}")
                    self.restricted_paths.append(path)
            
            if monitored_count == 0:
                self.logger.warning("⚠️ No accessible paths to monitor")
            else:
                self.logger.info(f"✅ Setup monitoring for {monitored_count} accessible paths")
            
            if self.restricted_paths:
                self.logger.info(f"ℹ️ {len(self.restricted_paths)} paths require admin privileges")
            
        except Exception as e:
            self.logger.error(f"❌ File collector initialization failed: {e}")
            # Don't raise exception - allow agent to continue
    
    async def start(self):
        """Start file monitoring"""
        try:
            await super().start()
            
            if self.observer and self.accessible_paths and not self.observer_started:
                try:
                    self.observer.start()
                    self.observer_started = True
                    self.logger.info("✅ File system monitoring started")
                except Exception as e:
                    self.logger.warning(f"⚠️ File monitoring limited: {e}")
                    self.observer_started = False
            else:
                self.logger.info("📁 File monitoring disabled - no accessible paths")
            
        except Exception as e:
            self.logger.error(f"❌ File collector start failed: {e}")
            # Don't raise - continue without file monitoring
    
    async def stop(self):
        """Stop file monitoring"""
        try:
            if self.observer and self.observer_started:
                try:
                    self.observer.stop()
                    self.observer.join(timeout=5)  # Wait max 5 seconds
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
    
    async def _handle_file_event(self, file_path: str, action: str, event: FileSystemEvent):
        """Handle file system event"""
        try:
            # Basic validation
            if not self._should_monitor_file(file_path):
                return
            
            # Deduplication check
            if self._is_duplicate_event(file_path, action):
                return
            
            # Get file information
            file_info = await self._get_file_info(file_path, action, event)
            
            if not file_info:
                return
            
            # Create event data with severity
            event_data = EventData(
                event_type='File',
                event_action=action,
                event_timestamp=datetime.now(),
                severity=self._determine_severity(file_info),
                # File details
                file_path=file_info['path'],
                file_name=file_info['name'],
                file_size=file_info['size'],
                file_hash=file_info['hash'],
                file_extension=file_info['extension'],
                file_operation=action
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
            
            # Check if in excluded directory
            try:
                resolved_path = path_obj.resolve()
                for excluded_dir in self.excluded_directories:
                    try:
                        if resolved_path.is_relative_to(excluded_dir):
                            return False
                    except (ValueError, AttributeError):
                        # is_relative_to might not be available in older Python versions
                        if str(resolved_path).startswith(str(excluded_dir)):
                            return False
            except (OSError, ValueError):
                # Path might not exist or be invalid
                pass
            
            # Check file size (if file exists)
            try:
                if path_obj.exists() and path_obj.stat().st_size > self.max_file_size:
                    return False
            except (OSError, PermissionError):
                pass
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Error checking file {file_path}: {e}")
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
    
    async def _get_file_info(self, file_path: str, action: str, event: FileSystemEvent) -> Optional[Dict]:
        """Get detailed file information"""
        try:
            path_obj = Path(file_path)
            
            file_info = {
                'path': str(path_obj),
                'name': path_obj.name,
                'extension': path_obj.suffix.lower() if path_obj.suffix else None,
                'size': None,
                'hash': None,
                'exists': False
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
                        file_info['size'] < 10 * 1024 * 1024):  # 10MB limit for hashing
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
    
    def _determine_severity(self, file_info: Dict) -> str:
        """Determine event severity based on file characteristics"""
        try:
            # High severity for executable files
            if file_info.get('extension') in {'.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.scr'}:
                return 'High'
            
            # Medium severity for script files
            if file_info.get('extension') in {'.py', '.js', '.vbs', '.sh', '.pl'}:
                return 'Medium'
            
            # Medium severity for large files
            if file_info.get('size', 0) > 50 * 1024 * 1024:  # 50MB
                return 'Medium'
            
            # Default to info
            return 'Info'
            
        except Exception:
            return 'Info'
    
    async def _cleanup_recent_events(self):
        """Clean up old event tracking data"""
        try:
            now = datetime.now()
            cleanup_threshold = 300  # 5 minutes
            
            events_to_remove = []
            for event_key, event_time in self.recent_events.items():
                if (now - event_time).total_seconds() > cleanup_threshold:
                    events_to_remove.append(event_key)
            
            for event_key in events_to_remove:
                self.recent_events.pop(event_key, None)
            
            if events_to_remove:
                self.logger.debug(f"🧹 Cleaned {len(events_to_remove)} old file event entries")
                
        except Exception as e:
            self.logger.error(f"❌ Recent events cleanup error: {e}")
    
    def get_file_stats(self) -> Dict:
        """Get file monitoring statistics"""
        return {
            'accessible_paths': self.accessible_paths,
            'restricted_paths': self.restricted_paths,
            'excluded_extensions': list(self.excluded_extensions),
            'excluded_directories': [str(d) for d in self.excluded_directories],
            'max_file_size_mb': self.max_file_size / (1024 * 1024),
            'collect_hashes': self.collect_hashes,
            'recent_events_count': len(self.recent_events),
            'observer_running': self.observer_started,
            'observer_alive': self.observer.is_alive() if self.observer and self.observer_started else False
        }
    
    def configure_monitoring(self, **kwargs):
        """Configure file monitoring options"""
        if 'collect_hashes' in kwargs:
            self.collect_hashes = kwargs['collect_hashes']
        if 'max_file_size_mb' in kwargs:
            self.max_file_size = kwargs['max_file_size_mb'] * 1024 * 1024
        
        self.logger.info(f"🔧 File monitoring configured: {kwargs}")