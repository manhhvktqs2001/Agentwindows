# agent/collectors/process_collector.py
"""
Process Collector - Windows process monitoring and analysis
Real-time process creation, termination, and behavior analysis
"""

import asyncio
import logging
import hashlib
import os
import platform
import psutil
try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False
    wmi = None
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from pathlib import Path
import json

from .base_collector import BaseCollector
from ..schemas.events import EventData

# Try to import severity utilities, fallback to local implementation if not available
try:
    from ..utils.severity_utils import SeverityCalculator, normalize_severity
    SEVERITY_UTILS_AVAILABLE = True
except ImportError:
    SEVERITY_UTILS_AVAILABLE = False
    # Fallback severity calculator
    class SeverityCalculator:
        @classmethod
        def calculate_process_severity(cls, process_name=None, process_path=None, 
                                     command_line=None, parent_process=None):
            # Simple fallback implementation
            if process_name:
                process_name = process_name.lower()
                if any(proc in process_name for proc in ['mimikatz', 'procdump', 'pwdump']):
                    return 'Critical'
                if any(proc in process_name for proc in ['powershell', 'cmd', 'rundll32']):
                    return 'High'
                if process_name.endswith(('.bat', '.cmd', '.ps1', '.vbs', '.js')):
                    return 'Medium'
            return 'Info'
    
    def normalize_severity(severity: str) -> str:
        """Normalize severity to standard format"""
        severity_map = {
            'critical': 'Critical',
            'high': 'High', 
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Info'
        }
        return severity_map.get(severity.lower(), 'Info')


class ProcessMonitor:
    """Real-time process monitoring using WMI"""
    
    def __init__(self, process_collector):
        self.collector = process_collector
        self.logger = logging.getLogger(__name__)
        self.monitoring = False
        self.wmi_connection = None
        
    def start_monitoring(self):
        """Start WMI process monitoring"""
        try:
            if not WMI_AVAILABLE:
                self.logger.warning("⚠️ WMI not available, using polling-based monitoring")
                return
                
            self.wmi_connection = wmi.WMI()
            self.monitoring = True
            self.logger.info("🔍 Process monitoring started")
        except Exception as e:
            self.logger.error(f"❌ Failed to start process monitoring: {e}")
            self.logger.info("🔄 Falling back to polling-based monitoring")
            
    def stop_monitoring(self):
        """Stop process monitoring"""
        self.monitoring = False
        self.logger.info("🛑 Process monitoring stopped")
        
    def _monitor_processes(self):
        """Monitor process creation events"""
        try:
            if not self.monitoring or not WMI_AVAILABLE:
                return
                
            # Monitor process creation events
            process_watcher = self.wmi_connection.Win32_Process.watch_for(
                raw_wql="SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
            )
            
            while self.monitoring:
                try:
                    process_event = process_watcher(timeout_ms=1000)
                    if process_event:
                        asyncio.create_task(self._handle_process_creation(process_event.TargetInstance))
                except wmi.x_wmi_timed_out:
                    continue
                except Exception as e:
                    self.logger.error(f"❌ Process monitoring error: {e}")
                    break
                    
        except Exception as e:
            self.logger.error(f"❌ Failed to monitor processes: {e}")


class ProcessCollector(BaseCollector):
    """Process monitoring and analysis collector"""
    
    def __init__(self, config_manager):
        """Initialize process collector"""
        super().__init__(config_manager, collector_name="Process")
        
        # Process tracking
        self.known_processes = set()  # Use set instead of dict
        self.process_stats = {
            'total_events': 0,
            'high_severity_events': 0,
            'processes_tracked': 0
        }
        
        # Configuration
        self.collect_hashes = True
        self.monitor_new_processes = True
        self.monitor_terminated_processes = True
        self.monitor_suspicious_processes = True
        
        self.process_monitor = ProcessMonitor(self)
        
        # Suspicious process patterns
        self.suspicious_processes = {
            'mimikatz', 'procdump', 'pwdump', 'wce', 'gsecdump',
            'psexec', 'wmic', 'rundll32', 'regsvr32', 'mshta',
            'powershell', 'cmd', 'certutil', 'bitsadmin', 'wget',
            'curl', 'nc', 'netcat', 'telnet', 'ftp', 'tftp'
        }
        
        # System processes to ignore
        self.system_processes = {
            'svchost.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe',
            'wininit.exe', 'services.exe', 'spoolsv.exe', 'explorer.exe',
            'dwm.exe', 'taskmgr.exe', 'conhost.exe', 'dllhost.exe'
        }
        
    async def _collector_specific_init(self):
        """Initialize process-specific components"""
        try:
            # Get initial process snapshot
            await self._get_initial_process_snapshot()
            
            # Start process monitoring if enabled
            if self.monitor_new_processes:
                self.process_monitor.start_monitoring()
                
            self.logger.info("✅ Process collector initialized")
            
        except Exception as e:
            self.logger.error(f"❌ Process collector initialization failed: {e}")
            
    async def start(self):
        """Start process monitoring"""
        try:
            await super().start()
            self.logger.info("🚀 Process collector started")
        except Exception as e:
            self.logger.error(f"❌ Failed to start process collector: {e}")
            
    async def stop(self):
        """Stop process monitoring"""
        try:
            self.process_monitor.stop_monitoring()
            await super().stop()
            self.logger.info("🛑 Process collector stopped")
        except Exception as e:
            self.logger.error(f"❌ Failed to stop process collector: {e}")
            
    async def _collect_data(self):
        """Collect process information and detect new/terminated processes"""
        try:
            current_processes = set()
            current_time = datetime.now()
            
            # Get current running processes
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent', 'create_time']):
                try:
                    proc_info = proc.info
                    process_key = f"{proc_info['pid']}_{proc_info['name']}"
                    current_processes.add(process_key)
                    
                    # Check if this is a new process
                    if process_key not in self.known_processes:
                        # New process detected - FIX: use command_line instead of process_command_line
                        event_data = EventData(
                            event_type='Process',
                            event_action='Create',
                            event_timestamp=current_time,
                            severity='Info',
                            description=f'New process started: {proc_info["name"]} (PID: {proc_info["pid"]})',
                            process_id=proc_info['pid'],
                            process_name=proc_info['name'],
                            process_path=proc_info.get('exe', ''),
                            command_line=' '.join(proc_info.get('cmdline', [])),  # FIX: Changed from process_command_line
                            cpu_usage=proc_info.get('cpu_percent', 0),
                            memory_usage=proc_info.get('memory_percent', 0),
                            raw_event_data=json.dumps(proc_info)
                        )
                        await self.add_event(event_data)
                        self.known_processes.add(process_key)
                        self.logger.debug(f"🆕 New process detected: {proc_info['name']} (PID: {proc_info['pid']})")
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Check for terminated processes
            terminated_processes = self.known_processes - current_processes
            for process_key in terminated_processes:
                pid, name = process_key.split('_', 1)
                event_data = EventData(
                    event_type='Process',
                    event_action='Terminate',
                    event_timestamp=current_time,
                    severity='Info',
                    description=f'Process terminated: {name} (PID: {pid})',
                    process_id=int(pid),
                    process_name=name,
                    raw_event_data=json.dumps({'pid': pid, 'name': name, 'action': 'terminated'})
                )
                await self.add_event(event_data)
                self.known_processes.discard(process_key)  # FIX: Use discard instead of del
                self.logger.debug(f"💀 Process terminated: {name} (PID: {pid})")
            
            # Clean up old process tracking (older than 1 hour)
            # Note: This needs to be fixed to track timestamps properly
            # For now, we'll just clean up if we have too many processes
            if len(self.known_processes) > 10000:
                # Keep only the most recent half
                processes_list = list(self.known_processes)
                self.known_processes = set(processes_list[-5000:])
            
            return []
            
        except Exception as e:
            self.logger.error(f"❌ Process collection error: {e}")
            return []
            
    async def _get_process_hash(self, exe_path):
        """Calculate file hash for process executable"""
        if not self.collect_hashes or not exe_path:
            return None
            
        try:
            # Check file size limit
            if os.path.exists(exe_path):
                file_size = os.path.getsize(exe_path)
                if file_size > 50 * 1024 * 1024:  # 50MB
                    return None
                    
            def _calculate_hash():
                """Calculate SHA256 hash of file"""
                hash_sha256 = hashlib.sha256()
                with open(exe_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_sha256.update(chunk)
                return hash_sha256.hexdigest()
                
            # Run hash calculation in thread pool
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _calculate_hash)
            
        except Exception as e:
            self.logger.debug(f"Failed to calculate process hash: {e}")
            return None
            
    def _is_system_process(self, process_name):
        """Check if process is a system process"""
        return process_name.lower() in {p.lower() for p in self.system_processes}
        
    def _determine_severity(self, proc_info):
        """Determine process event severity"""
        try:
            process_name = proc_info.get('name', '').lower()
            
            # Critical severity for known malicious processes
            if any(proc in process_name for proc in ['mimikatz', 'procdump', 'pwdump']):
                return 'Critical'
            
            # High severity for suspicious processes
            if any(proc in process_name for proc in ['powershell', 'cmd', 'rundll32']):
                return 'High'
            
            # Medium severity for processes with unusual characteristics
            if (proc_info.get('cpu_percent', 0) > 80 or 
                proc_info.get('memory_percent', 0) > 500 or
                proc_info.get('thread_count', 0) > 100):
                return 'Medium'
            
            # Default to info
            return 'Info'
            
        except Exception:
            return 'Info'
            
    async def _get_initial_process_snapshot(self):
        """Get initial snapshot of running processes"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_info = proc.info
                    process_key = f"{proc_info['pid']}_{proc_info['name']}"
                    self.known_processes.add(process_key)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            self.logger.info(f"📸 Initial process snapshot: {len(self.known_processes)} processes")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to get initial process snapshot: {e}")
            
    def get_process_stats(self) -> Dict:
        """Get process collection statistics"""
        return {
            **self.process_stats,
            'known_processes': len(self.known_processes),
            'processes_tracked': self.process_stats['processes_tracked']
        }
        
    def configure_monitoring(self, **kwargs):
        """Configure process monitoring options"""
        if 'monitor_new_processes' in kwargs:
            self.monitor_new_processes = kwargs['monitor_new_processes']
        if 'monitor_terminated_processes' in kwargs:
            self.monitor_terminated_processes = kwargs['monitor_terminated_processes']
        if 'monitor_suspicious_processes' in kwargs:
            self.monitor_suspicious_processes = kwargs['monitor_suspicious_processes']
        if 'collect_hashes' in kwargs:
            self.collect_hashes = kwargs['collect_hashes']