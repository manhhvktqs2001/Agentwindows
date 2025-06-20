# agent/collectors/process_collector.py - ENHANCED WINDOWS VERSION
"""
Windows Process Collector - Enhanced process monitoring with real-time events
Compatible with EDR Server database schema
"""

import asyncio
import logging
import hashlib
import platform
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
import psutil
import threading

# Windows-specific imports
try:
    import wmi
    import win32api
    import win32con
    import win32event
    import win32process
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False

from .base_collector import BaseCollector
from ..schemas.events import EventData

class WindowsProcessEventHandler:
    """Windows-specific process event handler using WMI"""
    
    def __init__(self, process_collector):
        self.process_collector = process_collector
        self.logger = logging.getLogger(__name__)
        self.wmi_connection = None
        self.is_monitoring = False
        
    def start_monitoring(self):
        """Start WMI process monitoring"""
        if not WINDOWS_AVAILABLE:
            self.logger.warning("⚠️ Windows WMI not available")
            return False
        
        try:
            self.wmi_connection = wmi.WMI()
            self.is_monitoring = True
            
            # Start monitoring thread
            monitor_thread = threading.Thread(target=self._wmi_monitor_loop, daemon=True)
            monitor_thread.start()
            
            self.logger.info("✅ Windows WMI process monitoring started")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ WMI monitoring setup failed: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop WMI process monitoring"""
        self.is_monitoring = False
        if self.wmi_connection:
            try:
                self.wmi_connection = None
            except:
                pass
    
    def _wmi_monitor_loop(self):
        """WMI monitoring loop for process events"""
        try:
            self.logger.info("🔍 WMI process monitor loop started")
            
            # Monitor process creation
            process_watcher = self.wmi_connection.Win32_Process.watch_for("creation")
            
            while self.is_monitoring:
                try:
                    # Wait for process creation event (timeout 1 second)
                    new_process = process_watcher(timeout_ms=1000)
                    if new_process:
                        asyncio.run_coroutine_threadsafe(
                            self._handle_process_creation(new_process),
                            self.process_collector.loop
                        )
                except Exception as e:
                    if self.is_monitoring:  # Only log if we're still supposed to be monitoring
                        self.logger.debug(f"WMI monitoring error: {e}")
                    time.sleep(1)
                    
        except Exception as e:
            self.logger.error(f"❌ WMI monitoring loop failed: {e}")
    
    async def _handle_process_creation(self, wmi_process):
        """Handle WMI process creation event"""
        try:
            # Get detailed process information
            process_info = {
                'pid': wmi_process.ProcessId,
                'name': wmi_process.Name,
                'executable_path': wmi_process.ExecutablePath,
                'command_line': wmi_process.CommandLine,
                'parent_pid': wmi_process.ParentProcessId,
                'creation_date': wmi_process.CreationDate,
                'session_id': wmi_process.SessionId
            }
            
            # Create event
            await self.process_collector._create_process_event(
                process_info, 'ProcessCreate'
            )
            
        except Exception as e:
            self.logger.error(f"❌ Process creation handling failed: {e}")

class ProcessCollector(BaseCollector):
    """Enhanced Windows Process Collector with real-time monitoring"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "ProcessCollector")
        
        # Windows-specific handler
        self.windows_handler = None
        if platform.system().lower() == 'windows':
            self.windows_handler = WindowsProcessEventHandler(self)
        
        # Process tracking
        self.known_processes: Set[int] = set()
        self.process_cache: Dict[int, Dict] = {}
        self.last_scan_time = None
        
        # Collection settings
        self.collect_command_lines = True
        self.collect_hashes = True
        self.collect_modules = False  # Heavy operation
        self.max_command_line_length = 8192
        
        # Filters
        self.exclude_system_processes = True
        self.exclude_short_lived = True  # Exclude processes that die quickly
        self.min_process_lifetime = 2  # seconds
        
        # Event loop reference for WMI
        self.loop = None
        
        self._setup_filters()
    
    def _setup_filters(self):
        """Setup process filters from configuration"""
        try:
            filters_config = self.config.get('filters', {})
            
            self.exclude_system_processes = filters_config.get('exclude_system_processes', True)
            self.collect_command_lines = self.config.get('advanced', {}).get('collect_command_lines', True)
            self.collect_hashes = self.config.get('advanced', {}).get('calculate_file_hashes', True)
            
        except Exception as e:
            self.logger.error(f"❌ Error setting up process filters: {e}")
    
    async def _collector_specific_init(self):
        """Initialize process collector"""
        try:
            # Store event loop reference
            self.loop = asyncio.get_event_loop()
            
            # Initialize known processes with current running processes
            await self._initialize_baseline()
            
            # Start Windows-specific monitoring if available
            if self.windows_handler:
                self.windows_handler.start_monitoring()
            
            self.logger.info(f"✅ Process collector initialized with {len(self.known_processes)} known processes")
            
        except Exception as e:
            self.logger.error(f"❌ Process collector initialization failed: {e}")
            raise
    
    async def start(self):
        """Start process collection"""
        try:
            await super().start()
            
            # Start polling loop for process scanning
            asyncio.create_task(self._polling_loop())
            
        except Exception as e:
            self.logger.error(f"❌ Process collector start failed: {e}")
            raise
    
    async def stop(self):
        """Stop process collection"""
        try:
            if self.windows_handler:
                self.windows_handler.stop_monitoring()
            
            await super().stop()
            
        except Exception as e:
            self.logger.error(f"❌ Process collector stop error: {e}")
    
    async def _polling_loop(self):
        """Polling loop for process changes"""
        while self.is_running:
            try:
                await self._scan_for_process_changes()
                await asyncio.sleep(self.polling_interval)
                
            except Exception as e:
                self.logger.error(f"❌ Process polling error: {e}")
                await asyncio.sleep(5)
    
    async def _collect_data(self):
        """Collect process data (called by polling if no real-time monitoring)"""
        if not self.windows_handler:
            # Fallback to polling-based collection
            await self._scan_for_process_changes()
        
        return []  # Events are sent via add_event
    
    async def _initialize_baseline(self):
        """Initialize baseline of currently running processes"""
        try:
            current_processes = psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid', 'create_time'])
            
            for proc in current_processes:
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    
                    self.known_processes.add(pid)
                    self.process_cache[pid] = {
                        'pid': pid,
                        'name': proc_info['name'],
                        'exe': proc_info['exe'],
                        'cmdline': proc_info['cmdline'],
                        'ppid': proc_info['ppid'],
                        'create_time': proc_info['create_time'],
                        'seen_time': time.time()
                    }
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            self.last_scan_time = time.time()
            self.logger.info(f"📊 Baseline initialized: {len(self.known_processes)} processes")
            
        except Exception as e:
            self.logger.error(f"❌ Baseline initialization failed: {e}")
    
    async def _scan_for_process_changes(self):
        """Scan for process changes (new/terminated processes)"""
        try:
            current_time = time.time()
            current_pids = set()
            new_processes = []
            
            # Get current processes
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid', 'create_time']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    current_pids.add(pid)
                    
                    # Check for new processes
                    if pid not in self.known_processes:
                        self.known_processes.add(pid)
                        
                        # Get detailed process information
                        detailed_info = await self._get_detailed_process_info(proc, proc_info)
                        if detailed_info:
                            self.process_cache[pid] = detailed_info
                            new_processes.append(detailed_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check for terminated processes
            terminated_pids = self.known_processes - current_pids
            
            # Process new processes
            for proc_info in new_processes:
                if self._should_report_process(proc_info):
                    await self._create_process_event(proc_info, 'ProcessCreate')
            
            # Process terminated processes
            for pid in terminated_pids:
                if pid in self.process_cache:
                    proc_info = self.process_cache[pid]
                    
                    # Check if process lived long enough to be interesting
                    lifetime = current_time - proc_info.get('seen_time', 0)
                    if not self.exclude_short_lived or lifetime >= self.min_process_lifetime:
                        await self._create_process_event(proc_info, 'ProcessTerminate')
                    
                    # Clean up cache
                    del self.process_cache[pid]
            
            # Update known processes
            self.known_processes = current_pids
            self.last_scan_time = current_time
            
            if new_processes or terminated_pids:
                self.logger.debug(f"📊 Process changes: +{len(new_processes)} -{len(terminated_pids)}")
            
        except Exception as e:
            self.logger.error(f"❌ Process scanning error: {e}")
    
    async def _get_detailed_process_info(self, proc, basic_info):
        """Get detailed process information"""
        try:
            detailed_info = {
                'pid': basic_info['pid'],
                'name': basic_info['name'],
                'exe': basic_info['exe'],
                'cmdline': basic_info['cmdline'],
                'ppid': basic_info['ppid'],
                'create_time': basic_info['create_time'],
                'seen_time': time.time()
            }
            
            # Get additional information
            try:
                # Process user
                detailed_info['username'] = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                detailed_info['username'] = None
            
            # Parent process name
            try:
                if detailed_info['ppid']:
                    parent = psutil.Process(detailed_info['ppid'])
                    detailed_info['parent_name'] = parent.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                detailed_info['parent_name'] = None
            
            # Process hash (if enabled and executable exists)
            if self.collect_hashes and detailed_info['exe']:
                detailed_info['hash'] = await self._calculate_process_hash(detailed_info['exe'])
            
            return detailed_info
            
        except Exception as e:
            self.logger.debug(f"Error getting detailed process info: {e}")
            return basic_info
    
    async def _calculate_process_hash(self, exe_path):
        """Calculate hash of process executable"""
        try:
            if not exe_path or not Path(exe_path).exists():
                return None
            
            # Read file in chunks to avoid memory issues
            hash_sha256 = hashlib.sha256()
            with open(exe_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            
            return hash_sha256.hexdigest()
            
        except Exception as e:
            self.logger.debug(f"Hash calculation failed for {exe_path}: {e}")
            return None
    
    def _should_report_process(self, proc_info):
        """Check if process should be reported"""
        try:
            # Filter system processes if configured
            if self.exclude_system_processes:
                if self._is_system_process(proc_info):
                    return False
            
            # Filter by name
            process_name = proc_info.get('name', '').lower()
            if not process_name:
                return False
            
            # Skip very common system processes
            common_system_processes = {
                'system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
                'winlogon.exe', 'services.exe', 'lsass.exe', 'svchost.exe',
                'spoolsv.exe', 'explorer.exe', 'dwm.exe', 'audiodg.exe'
            }
            
            if process_name in common_system_processes:
                return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Error checking process filter: {e}")
            return True
    
    def _is_system_process(self, proc_info):
        """Check if process is a system process"""
        try:
            # Check by PID (system processes typically have low PIDs)
            pid = proc_info.get('pid', 0)
            if pid <= 4:  # System, Idle processes
                return True
            
            # Check by executable path
            exe_path = proc_info.get('exe', '')
            if exe_path:
                exe_path = exe_path.lower()
                system_paths = [
                    'c:\\windows\\system32',
                    'c:\\windows\\syswow64',
                    'c:\\windows\\winsxs'
                ]
                
                if any(exe_path.startswith(path) for path in system_paths):
                    return True
            
            # Check by username
            username = proc_info.get('username', '')
            if username and username.lower() in ['nt authority\\system', 'nt authority\\local service', 'nt authority\\network service']:
                return True
            
            return False
            
        except Exception:
            return False
    
    async def _create_process_event(self, proc_info, action):
        """Create process event"""
        try:
            # Prepare command line
            cmdline = proc_info.get('cmdline')
            if isinstance(cmdline, list):
                cmdline = ' '.join(cmdline) if cmdline else None
            
            # Truncate command line if too long
            if cmdline and len(cmdline) > self.max_command_line_length:
                cmdline = cmdline[:self.max_command_line_length] + "..."
            
            # Create event data
            event_data = EventData(
                event_type='Process',
                event_action=action,
                event_timestamp=datetime.now(),
                severity='Info',
                
                # Process details
                process_id=proc_info.get('pid'),
                process_name=proc_info.get('name'),
                process_path=proc_info.get('exe'),
                command_line=cmdline,
                parent_pid=proc_info.get('ppid'),
                parent_process_name=proc_info.get('parent_name'),
                process_user=proc_info.get('username'),
                process_hash=proc_info.get('hash')
            )
            
            # Add to event queue
            await self.add_event(event_data)
            
            self.logger.debug(f"📊 Process {action}: {proc_info.get('name')} (PID: {proc_info.get('pid')})")
            
        except Exception as e:
            self.logger.error(f"❌ Process event creation failed: {e}")
    
    def get_process_stats(self) -> Dict:
        """Get process monitoring statistics"""
        return {
            'known_processes': len(self.known_processes),
            'cached_processes': len(self.process_cache),
            'windows_monitoring': self.windows_handler is not None and self.windows_handler.is_monitoring,
            'collect_hashes': self.collect_hashes,
            'collect_command_lines': self.collect_command_lines,
            'exclude_system_processes': self.exclude_system_processes,
            'last_scan_time': self.last_scan_time
        }