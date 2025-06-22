# agent/collectors/process_collector.py
"""
Process Activity Collector - ENHANCED
Thu thập thông tin về hoạt động process liên tục với tần suất cao
"""

import asyncio
import logging
import hashlib
import os
import platform
import psutil
import time
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

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventType, EventAction, Severity
from agent.utils.process_utils import ProcessUtils

class ProcessCollector(BaseCollector):
    """Enhanced Process Activity Collector"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "ProcessCollector")
        
        # Enhanced configuration
        self.polling_interval = 2  # ENHANCED: Reduced from 5 to 2 seconds for continuous monitoring
        self.max_processes_per_batch = 50  # ENHANCED: Increased batch size
        self.track_process_tree = True
        self.monitor_suspicious_processes = True
        
        # Process tracking
        self.known_processes = set()
        self.process_start_times = {}
        self.suspicious_processes = set()
        
        # Enhanced monitoring
        self.monitor_cpu_usage = True
        self.monitor_memory_usage = True
        self.monitor_network_connections = True
        self.monitor_file_operations = True
        
        # Suspicious process patterns
        self.suspicious_patterns = [
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
            'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe',
            'bitsadmin.exe', 'wmic.exe', 'schtasks.exe', 'at.exe',
            'net.exe', 'netstat.exe', 'ipconfig.exe', 'route.exe',
            'arp.exe', 'nslookup.exe', 'ping.exe', 'tracert.exe'
        ]
        
        self.logger.info("Enhanced Process Collector initialized")
    
    async def initialize(self):
        """Initialize process collector with enhanced monitoring"""
        try:
            # Get initial process list
            await self._scan_all_processes()
            
            # Set up enhanced monitoring
            self._setup_process_monitoring()
            
            self.logger.info(f"Enhanced Process Collector initialized - Monitoring {len(self.known_processes)} processes")
            
        except Exception as e:
            self.logger.error(f"Process collector initialization failed: {e}")
            raise
    
    def _setup_process_monitoring(self):
        """Set up enhanced process monitoring"""
        try:
            # Monitor process creation and termination
            psutil.Popen = self._monitored_popen
            
            # Set up process event callbacks
            self._setup_process_callbacks()
            
        except Exception as e:
            self.logger.error(f"Process monitoring setup failed: {e}")
    
    def _setup_process_callbacks(self):
        """Set up process event callbacks for real-time monitoring"""
        try:
            # This would integrate with Windows API for real-time process events
            # For now, we use polling with enhanced frequency
            pass
        except Exception as e:
            self.logger.debug(f"Process callbacks setup failed: {e}")
    
    async def _collect_data(self):
        """Collect process data with enhanced monitoring - REQUIRED ABSTRACT METHOD"""
        try:
            events = []
            
            # ENHANCED: Collect process creation events
            new_processes = await self._detect_new_processes()
            events.extend(new_processes)
            
            # ENHANCED: Collect process termination events
            terminated_processes = await self._detect_terminated_processes()
            events.extend(terminated_processes)
            
            # ENHANCED: Monitor suspicious process activities
            suspicious_events = await self._monitor_suspicious_processes()
            events.extend(suspicious_events)
            
            # ENHANCED: Collect process performance data
            performance_events = await self._collect_performance_data()
            events.extend(performance_events)
            
            # ENHANCED: Monitor process network connections
            network_events = await self._monitor_process_networks()
            events.extend(network_events)
            
            # ENHANCED: Monitor process file operations
            file_events = await self._monitor_process_files()
            events.extend(file_events)
            
            if events:
                self.logger.debug(f"Collected {len(events)} process events")
            
            return events
            
        except Exception as e:
            self.logger.error(f"Process data collection failed: {e}")
            return []
    
    async def collect_data(self) -> List[EventData]:
        """Collect process data with enhanced monitoring"""
        try:
            events = []
            
            # ENHANCED: Collect process creation events
            new_processes = await self._detect_new_processes()
            events.extend(new_processes)
            
            # ENHANCED: Collect process termination events
            terminated_processes = await self._detect_terminated_processes()
            events.extend(terminated_processes)
            
            # ENHANCED: Monitor suspicious process activities
            suspicious_events = await self._monitor_suspicious_processes()
            events.extend(suspicious_events)
            
            # ENHANCED: Collect process performance data
            performance_events = await self._collect_performance_data()
            events.extend(performance_events)
            
            # ENHANCED: Monitor process network connections
            network_events = await self._monitor_process_networks()
            events.extend(network_events)
            
            # ENHANCED: Monitor process file operations
            file_events = await self._monitor_process_files()
            events.extend(file_events)
            
            if events:
                self.logger.debug(f"Collected {len(events)} process events")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Process data collection failed: {e}")
            return []
    
    async def _scan_all_processes(self):
        """Scan all current processes for baseline"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'create_time', 'cmdline']):
                try:
                    proc_info = proc.info
                    self.known_processes.add(proc_info['pid'])
                    self.process_start_times[proc_info['pid']] = proc_info['create_time']
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            self.logger.info(f"Baseline scan: {len(self.known_processes)} processes")
            
        except Exception as e:
            self.logger.error(f"Process scan failed: {e}")
    
    async def _detect_new_processes(self) -> List[EventData]:
        """Detect newly created processes"""
        try:
            events = []
            current_processes = set()
            
            for proc in psutil.process_iter(['pid', 'name', 'create_time', 'cmdline', 'ppid', 'username']):
                try:
                    proc_info = proc.info
                    current_processes.add(proc_info['pid'])
                    
                    # Check if this is a new process
                    if proc_info['pid'] not in self.known_processes:
                        # New process detected
                        event = self._create_process_event(
                            action=EventAction.CREATE,
                            process_id=proc_info['pid'],
                            process_name=proc_info['name'],
                            command_line=' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                            parent_pid=proc_info['ppid'],
                            process_user=proc_info['username'],
                            severity=self._determine_process_severity(proc_info['name'])
                        )
                        events.append(event)
                        
                        # Update tracking
                        self.known_processes.add(proc_info['pid'])
                        self.process_start_times[proc_info['pid']] = proc_info['create_time']
                        
                        # Check if suspicious
                        if self._is_suspicious_process(proc_info['name']):
                            self.suspicious_processes.add(proc_info['pid'])
                            self.logger.warning(f"Suspicious process detected: {proc_info['name']} (PID: {proc_info['pid']})")
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Update known processes
            self.known_processes = current_processes
            
            return events
            
        except Exception as e:
            self.logger.error(f"New process detection failed: {e}")
            return []
    
    async def _detect_terminated_processes(self) -> List[EventData]:
        """Detect terminated processes"""
        try:
            events = []
            current_processes = set()
            
            for proc in psutil.process_iter(['pid']):
                try:
                    current_processes.add(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Find terminated processes
            terminated_pids = self.known_processes - current_processes
            
            for pid in terminated_pids:
                # Create termination event
                event = self._create_process_event(
                    action=EventAction.TERMINATE,
                    process_id=pid,
                    process_name="Unknown",  # Process already terminated
                    command_line="",
                    parent_pid=None,
                    process_user="Unknown",
                    severity=Severity.LOW
                )
                events.append(event)
                
                # Clean up tracking
                self.process_start_times.pop(pid, None)
                self.suspicious_processes.discard(pid)
            
            return events
            
        except Exception as e:
            self.logger.error(f"Terminated process detection failed: {e}")
            return []
    
    async def _monitor_suspicious_processes(self) -> List[EventData]:
        """Monitor activities of suspicious processes"""
        try:
            events = []
            
            for pid in list(self.suspicious_processes):
                try:
                    proc = psutil.Process(pid)
                    
                    # Check if process still exists
                    if not proc.is_running():
                        self.suspicious_processes.discard(pid)
                        continue
                    
                    # Monitor suspicious activities
                    event = await self._check_suspicious_activity(proc)
                    if event:
                        events.append(event)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    self.suspicious_processes.discard(pid)
                    continue
            
            return events
            
        except Exception as e:
            self.logger.error(f"Suspicious process monitoring failed: {e}")
            return []
    
    async def _check_suspicious_activity(self, proc) -> Optional[EventData]:
        """Check for suspicious activities in a process"""
        try:
            # Check command line for suspicious patterns
            cmdline = ' '.join(proc.cmdline()) if proc.cmdline() else ''
            
            suspicious_patterns = [
                'powershell -enc', 'cmd /c', 'wscript', 'cscript',
                'rundll32', 'regsvr32', 'mshta', 'certutil',
                'bitsadmin', 'wmic', 'schtasks', 'at ',
                'net user', 'net group', 'net localgroup'
            ]
            
            for pattern in suspicious_patterns:
                if pattern.lower() in cmdline.lower():
                    return self._create_process_event(
                        action=EventAction.SUSPICIOUS_ACTIVITY,
                        process_id=proc.pid,
                        process_name=proc.name(),
                        command_line=cmdline,
                        parent_pid=proc.ppid(),
                        process_user=proc.username(),
                        severity=Severity.HIGH,
                        additional_data={'suspicious_pattern': pattern}
                    )
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Suspicious activity check failed: {e}")
            return None
    
    async def _collect_performance_data(self) -> List[EventData]:
        """Collect process performance data"""
        try:
            events = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    
                    # Only collect for processes with significant resource usage
                    if proc_info['cpu_percent'] > 10 or proc_info['memory_percent'] > 5:
                        event = self._create_process_event(
                            action=EventAction.RESOURCE_USAGE,
                            process_id=proc_info['pid'],
                            process_name=proc_info['name'],
                            command_line="",
                            parent_pid=None,
                            process_user="",
                            severity=Severity.MEDIUM,
                            additional_data={
                                'cpu_percent': proc_info['cpu_percent'],
                                'memory_percent': proc_info['memory_percent']
                            }
                        )
                        events.append(event)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return events
            
        except Exception as e:
            self.logger.error(f"Performance data collection failed: {e}")
            return []
    
    async def _monitor_process_networks(self) -> List[EventData]:
        """Monitor process network connections"""
        try:
            events = []
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    connections = proc.connections()
                    
                    for conn in connections:
                        if conn.status == 'ESTABLISHED':
                            event = self._create_process_event(
                                action=EventAction.NETWORK_CONNECTION,
                                process_id=proc.info['pid'],
                                process_name=proc.info['name'],
                                command_line="",
                                parent_pid=None,
                                process_user="",
                                severity=Severity.LOW,
                                additional_data={
                                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                                    'status': conn.status
                                }
                            )
                            events.append(event)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return events
            
        except Exception as e:
            self.logger.error(f"Process network monitoring failed: {e}")
            return []
    
    async def _monitor_process_files(self) -> List[EventData]:
        """Monitor process file operations"""
        try:
            events = []
            
            # This would require integration with Windows API for real-time file monitoring
            # For now, we'll monitor file handles
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    open_files = proc.open_files()
                    
                    for file in open_files:
                        if self._is_suspicious_file(file.path):
                            event = self._create_process_event(
                                action=EventAction.FILE_ACCESS,
                                process_id=proc.info['pid'],
                                process_name=proc.info['name'],
                                command_line="",
                                parent_pid=None,
                                process_user="",
                                severity=Severity.MEDIUM,
                                additional_data={
                                    'file_path': file.path,
                                    'file_access': 'read'
                                }
                            )
                            events.append(event)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return events
            
        except Exception as e:
            self.logger.error(f"Process file monitoring failed: {e}")
            return []
    
    def _is_suspicious_process(self, process_name: str) -> bool:
        """Check if process name matches suspicious patterns"""
        return any(pattern.lower() in process_name.lower() for pattern in self.suspicious_patterns)
    
    def _is_suspicious_file(self, file_path: str) -> bool:
        """Check if file path is suspicious"""
        suspicious_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js']
        suspicious_paths = ['temp', 'downloads', 'desktop', 'recent']
        
        file_path_lower = file_path.lower()
        
        # Check extension
        if any(ext in file_path_lower for ext in suspicious_extensions):
            # Check if in suspicious location
            if any(path in file_path_lower for path in suspicious_paths):
                return True
        
        return False
    
    def _determine_process_severity(self, process_name: str) -> Severity:
        """Determine severity based on process name"""
        if self._is_suspicious_process(process_name):
            return Severity.HIGH
        elif process_name.lower() in ['svchost.exe', 'lsass.exe', 'winlogon.exe']:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _create_process_event(self, action: EventAction, process_id: int, process_name: str,
                            command_line: str, parent_pid: Optional[int], process_user: str,
                            severity: Severity, additional_data: Dict = None) -> EventData:
        """Create process event data"""
        try:
            # Get process hash if available
            process_hash = None
            try:
                proc = psutil.Process(process_id)
                process_path = proc.exe()
                if process_path and Path(process_path).exists():
                    process_hash = ProcessUtils.calculate_file_hash(process_path)
            except:
                pass
            
            return EventData(
                event_type=EventType.PROCESS,
                event_action=action,
                event_timestamp=datetime.now(),
                severity=severity,
                process_id=process_id,
                process_name=process_name,
                process_path=proc.exe() if 'proc' in locals() else None,
                command_line=command_line,
                parent_pid=parent_pid,
                parent_process_name=None,  # Would need to look up
                process_user=process_user,
                process_hash=process_hash,
                raw_event_data=additional_data or {}
            )
            
        except Exception as e:
            self.logger.error(f"Process event creation failed: {e}")
            return None
    
    def _monitored_popen(self, *args, **kwargs):
        """Monitored version of Popen to track process creation"""
        try:
            # This would integrate with Windows API for real-time process creation events
            return psutil.Popen(*args, **kwargs)
        except Exception as e:
            self.logger.debug(f"Monitored Popen failed: {e}")
            return psutil.Popen(*args, **kwargs)

    async def stop(self):
        """Stop process collector gracefully"""
        try:
            self.logger.info("Stopping ProcessCollector...")
            self.is_running = False
            
            # Clean up process tracking
            self.known_processes.clear()
            self.process_start_times.clear()
            self.suspicious_processes.clear()
            
            self.logger.info("ProcessCollector stopped")
            
        except Exception as e:
            self.logger.error(f"Process collector stop error: {e}")