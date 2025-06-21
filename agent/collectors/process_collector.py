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
import wmi
from datetime import datetime
from typing import Dict, List, Optional, Set
from pathlib import Path
import json

from .base_collector import BaseCollector
from ..schemas.events import EventData

# Try to import severity utilities, fallback to local implementation if not available
try:
    from ..utils.severity_utils import SeverityCalculator
    from ..schemas.events import normalize_severity
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
            self.wmi_connection = wmi.WMI()
            self.monitoring = True
            self.logger.info("🔍 Process monitoring started")
        except Exception as e:
            self.logger.error(f"❌ Failed to start process monitoring: {e}")
            
    def stop_monitoring(self):
        """Stop process monitoring"""
        self.monitoring = False
        self.logger.info("🛑 Process monitoring stopped")
        
    def _monitor_processes(self):
        """Monitor process creation events"""
        try:
            if not self.monitoring:
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
        super().__init__(config_manager, "Process")
        self.process_monitor = ProcessMonitor(self)
        self.known_processes: Set[int] = set()
        self.process_stats = {
            'total_events': 0,
            'suspicious_processes': 0,
            'high_severity_events': 0
        }
        
        # Configuration
        self.monitor_process_creation = True
        self.monitor_process_termination = True
        self.collect_process_details = True
        self.collect_hashes = True
        self.hash_file_size_limit = 50 * 1024 * 1024  # 50MB
        
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
            if self.monitor_process_creation:
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
        """Collect process data"""
        try:
            start_time = datetime.now()
            
            # Get current processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    proc_info['pid'] = proc.pid
                    proc_info['ppid'] = proc.ppid()
                    proc_info['create_time'] = datetime.fromtimestamp(proc.create_time())
                    proc_info['status'] = proc.status()
                    
                    # Check if this is a new process
                    if proc.pid not in self.known_processes:
                        await self._create_process_event(proc_info, 'Create')
                        self.known_processes.add(proc.pid)
                        
                    processes.append(proc_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                    
            # Check for terminated processes
            current_pids = {proc['pid'] for proc in processes}
            terminated_pids = self.known_processes - current_pids
            
            for pid in terminated_pids:
                await self._create_process_event({'pid': pid}, 'Terminate')
                self.known_processes.discard(pid)
                
            # Update stats
            self.process_stats['total_events'] += len(processes)
            
            collection_time = (datetime.now() - start_time).total_seconds()
            if collection_time > 1.0:
                self.logger.warning(f"⚠️ Slow collection: {collection_time:.2f}s")
                
        except Exception as e:
            self.logger.error(f"❌ Process data collection failed: {e}")
            
    async def _create_process_event(self, proc_info, action):
        """Create process event"""
        try:
            # Determine severity
            severity = self._determine_severity(proc_info)
            
            # Create event data
            event_data = EventData(
                event_type="Process",
                event_action=action,
                event_timestamp=datetime.now(),
                severity=severity,
                description=f"Process {action}: {proc_info.get('name', 'Unknown')} (PID: {proc_info.get('pid', 'N/A')})",
                source_ip="127.0.0.1",
                destination_ip="",
                source_port=0,
                destination_port=0,
                protocol="",
                process_name=proc_info.get('name', ''),
                process_id=proc_info.get('pid', 0),
                parent_pid=proc_info.get('ppid', 0),
                command_line=' '.join(proc_info.get('cmdline', [])) if proc_info.get('cmdline') else None,
                process_path=proc_info.get('exe', ''),
                raw_event_data=json.dumps({
                    'action': action,
                    'process_info': proc_info,
                    'cpu_usage': proc_info.get('cpu_percent', 0),
                    'memory_usage': proc_info.get('memory_percent', 0),
                    'status': proc_info.get('status', ''),
                    'create_time': proc_info.get('create_time', '').isoformat() if proc_info.get('create_time') else None
                })
            )
            
            # Add event to queue
            self.add_event(event_data)
            
            # Update stats
            if severity in ['High', 'Critical']:
                self.process_stats['high_severity_events'] += 1
                
        except Exception as e:
            self.logger.error(f"❌ Failed to create process event: {e}")
            
    async def _get_process_hash(self, exe_path):
        """Calculate file hash for process executable"""
        if not self.collect_hashes or not exe_path:
            return None
            
        try:
            # Check file size limit
            if os.path.exists(exe_path):
                file_size = os.path.getsize(exe_path)
                if file_size > self.hash_file_size_limit:
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
            for proc in psutil.process_iter(['pid']):
                try:
                    self.known_processes.add(proc.pid)
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
            'suspicious_processes': self.process_stats['suspicious_processes'],
            'high_severity_events': self.process_stats['high_severity_events']
        }
        
    def configure_monitoring(self, **kwargs):
        """Configure process monitoring options"""
        if 'monitor_process_creation' in kwargs:
            self.monitor_process_creation = kwargs['monitor_process_creation']
        if 'monitor_process_termination' in kwargs:
            self.monitor_process_termination = kwargs['monitor_process_termination']
        if 'collect_process_details' in kwargs:
            self.collect_process_details = kwargs['collect_process_details']
        if 'collect_hashes' in kwargs:
            self.collect_hashes = kwargs['collect_hashes']