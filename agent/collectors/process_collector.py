# agent/collectors/process_collector.py - FIXED MEMORY ERROR
"""
Enhanced Process Collector - FIXED memory_info access error
Thu thập nhiều loại process events và sửa lỗi memory_info object
"""

import psutil
import time
import asyncio
import logging
from typing import Dict, List, Optional, Set
from datetime import datetime
from pathlib import Path

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventType, EventAction
from agent.utils.process_utils import get_process_info, get_process_hash, is_system_process

logger = logging.getLogger('ProcessCollector')

class EnhancedProcessCollector(BaseCollector):
    """Enhanced Process Collector - FIXED memory access error"""
    
    def __init__(self, config_manager=None):
        super().__init__(config_manager, "ProcessCollector")
        
        # MULTIPLE EVENTS: Tracking data
        self.monitored_processes = {}
        self.baseline_processes = set()
        self.last_scan_pids = set()
        self.process_cpu_history = {}
        self.process_memory_history = {}
        
        # MULTIPLE EVENTS: Categories for different event types
        self.suspicious_processes = {
            'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
            'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe'
        }
        
        self.high_cpu_threshold = 80  # CPU > 80%
        self.high_memory_threshold = 500 * 1024 * 1024  # Memory > 500MB
        self.polling_interval = 0.5  # 500ms for continuous monitoring
        
        # MULTIPLE EVENTS: Statistics
        self.stats = {
            'process_create_events': 0,
            'process_terminate_events': 0,
            'process_cpu_events': 0,
            'process_memory_events': 0,
            'process_suspicious_events': 0,
            'process_child_events': 0,
            'process_performance_events': 0,
            'total_events_sent': 0
        }
        
        self.logger.info("Enhanced Process Collector initialized for MULTIPLE EVENT TYPES")
    
    async def _collect_data(self):
        """Collect multiple types of process events - FIXED VERSION"""
        try:
            scan_start = time.time()
            events = []
            current_pids = set()
            
            # MULTIPLE EVENTS: Scan all processes for various event types
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'username', 'ppid']):
                try:
                    proc_info = proc.info
                    if not proc_info['pid'] or not proc_info['name']:
                        continue
                    
                    pid = proc_info['pid']
                    current_pids.add(pid)
                    
                    # FIXED: Get CPU and memory info safely
                    try:
                        # Get actual process object for CPU/memory info
                        actual_proc = psutil.Process(pid)
                        cpu_percent = actual_proc.cpu_percent()
                        memory_info = actual_proc.memory_info()
                        proc_info['cpu_percent'] = cpu_percent
                        proc_info['memory_rss'] = memory_info.rss if memory_info else 0
                        proc_info['memory_vms'] = memory_info.vms if memory_info else 0
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_info['cpu_percent'] = 0
                        proc_info['memory_rss'] = 0
                        proc_info['memory_vms'] = 0
                    
                    # EVENT TYPE 1: Process Creation Events
                    if pid not in self.last_scan_pids:
                        event = await self._create_process_creation_event(proc_info)
                        if event:
                            events.append(event)
                            self.stats['process_create_events'] += 1
                    
                    # EVENT TYPE 2: CPU Usage Events (for high CPU processes)
                    cpu_event = await self._check_process_cpu_event(proc_info)
                    if cpu_event:
                        events.append(cpu_event)
                        self.stats['process_cpu_events'] += 1
                    
                    # EVENT TYPE 3: Memory Usage Events (for high memory processes)
                    memory_event = await self._check_process_memory_event(proc_info)
                    if memory_event:
                        events.append(memory_event)
                        self.stats['process_memory_events'] += 1
                    
                    # EVENT TYPE 4: Suspicious Process Events
                    if proc_info['name'] and proc_info['name'].lower() in self.suspicious_processes:
                        event = await self._create_suspicious_process_event(proc_info)
                        if event:
                            events.append(event)
                            self.stats['process_suspicious_events'] += 1
                    
                    # EVENT TYPE 5: Child Process Events
                    if proc_info.get('ppid'):
                        child_event = await self._create_child_process_event(proc_info)
                        if child_event:
                            events.append(child_event)
                            self.stats['process_child_events'] += 1
                    
                    # EVENT TYPE 6: Process Performance Events (every 5 scans)
                    if self.stats['total_events_sent'] % 5 == 0:
                        perf_event = await self._create_process_performance_event(proc_info)
                        if perf_event:
                            events.append(perf_event)
                            self.stats['process_performance_events'] += 1
                    
                    # Update tracking
                    self.monitored_processes[pid] = {
                        'name': proc_info['name'],
                        'exe': proc_info['exe'],
                        'last_seen': time.time(),
                        'cpu_percent': proc_info.get('cpu_percent', 0),
                        'memory_rss': proc_info.get('memory_rss', 0)
                    }
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # EVENT TYPE 7: Process Termination Events
            terminated_pids = self.last_scan_pids - current_pids
            for pid in terminated_pids:
                if pid in self.monitored_processes:
                    event = await self._create_process_termination_event(pid, self.monitored_processes[pid])
                    if event:
                        events.append(event)
                        self.stats['process_terminate_events'] += 1
                    del self.monitored_processes[pid]
            
            # Update tracking
            self.last_scan_pids = current_pids
            self.stats['total_events_sent'] += len(events)
            
            if events:
                self.logger.info(f"📤 Generated {len(events)} MULTIPLE PROCESS EVENTS for continuous sending")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Multiple process events collection failed: {e}")
            return []
    
    async def _create_process_creation_event(self, proc_info: Dict):
        """EVENT TYPE 1: Process Creation Event - FIXED"""
        try:
            return EventData(
                event_type=EventType.PROCESS,
                event_action=EventAction.CREATE,
                event_timestamp=datetime.now(),
                severity="Medium" if proc_info['name'].lower() in self.suspicious_processes else "Info",
                
                process_id=proc_info.get('pid'),
                process_name=proc_info.get('name'),
                process_path=proc_info.get('exe'),
                command_line=' '.join(proc_info['cmdline']) if proc_info.get('cmdline') else None,
                process_user=proc_info.get('username'),
                parent_pid=proc_info.get('ppid'),
                
                description=f"🆕 PROCESS CREATED: {proc_info.get('name')} (PID: {proc_info.get('pid')})",
                raw_event_data={
                    'event_subtype': 'process_creation',
                    'create_time': proc_info.get('create_time'),
                    'detection_time': time.time(),
                    'is_suspicious': proc_info['name'].lower() in self.suspicious_processes
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Process creation event failed: {e}")
            return None
    
    async def _create_process_termination_event(self, pid: int, proc_info: Dict):
        """EVENT TYPE 2: Process Termination Event - FIXED"""
        try:
            return EventData(
                event_type=EventType.PROCESS,
                event_action=EventAction.STOP,
                event_timestamp=datetime.now(),
                severity="Info",
                
                process_id=pid,
                process_name=proc_info.get('name'),
                process_path=proc_info.get('exe'),
                
                description=f"❌ PROCESS TERMINATED: {proc_info.get('name')} (PID: {pid})",
                raw_event_data={
                    'event_subtype': 'process_termination',
                    'termination_time': time.time(),
                    'process_lifetime': time.time() - proc_info.get('last_seen', time.time())
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Process termination event failed: {e}")
            return None
    
    async def _check_process_cpu_event(self, proc_info: Dict):
        """EVENT TYPE 3: High CPU Usage Event - FIXED"""
        try:
            cpu_percent = proc_info.get('cpu_percent', 0)
            if cpu_percent > self.high_cpu_threshold:
                return EventData(
                    event_type=EventType.PROCESS,
                    event_action=EventAction.RESOURCE_USAGE,
                    event_timestamp=datetime.now(),
                    severity="High",
                    
                    process_id=proc_info.get('pid'),
                    process_name=proc_info.get('name'),
                    cpu_usage=cpu_percent,
                    
                    description=f"🔥 HIGH CPU PROCESS: {proc_info.get('name')} using {cpu_percent}% CPU",
                    raw_event_data={
                        'event_subtype': 'high_cpu_usage',
                        'cpu_percent': cpu_percent,
                        'threshold': self.high_cpu_threshold,
                        'detection_time': time.time()
                    }
                )
        except Exception as e:
            self.logger.error(f"❌ CPU event check failed: {e}")
        return None
    
    async def _check_process_memory_event(self, proc_info: Dict):
        """EVENT TYPE 4: High Memory Usage Event - FIXED"""
        try:
            memory_rss = proc_info.get('memory_rss', 0)
            if memory_rss > self.high_memory_threshold:
                memory_mb = memory_rss / (1024 * 1024)
                return EventData(
                    event_type=EventType.PROCESS,
                    event_action=EventAction.RESOURCE_USAGE,
                    event_timestamp=datetime.now(),
                    severity="Medium",
                    
                    process_id=proc_info.get('pid'),
                    process_name=proc_info.get('name'),
                    memory_usage=memory_mb,
                    
                    description=f"💾 HIGH MEMORY PROCESS: {proc_info.get('name')} using {memory_mb:.1f}MB",
                    raw_event_data={
                        'event_subtype': 'high_memory_usage',
                        'memory_rss': memory_rss,
                        'memory_vms': proc_info.get('memory_vms', 0),
                        'memory_mb': memory_mb,
                        'threshold_mb': self.high_memory_threshold / (1024 * 1024)
                    }
                )
        except Exception as e:
            self.logger.error(f"❌ Memory event check failed: {e}")
        return None
    
    async def _create_suspicious_process_event(self, proc_info: Dict):
        """EVENT TYPE 5: Suspicious Process Event - FIXED"""
        try:
            return EventData(
                event_type=EventType.PROCESS,
                event_action=EventAction.SUSPICIOUS_ACTIVITY,
                event_timestamp=datetime.now(),
                severity="High",
                
                process_id=proc_info.get('pid'),
                process_name=proc_info.get('name'),
                process_path=proc_info.get('exe'),
                command_line=' '.join(proc_info['cmdline']) if proc_info.get('cmdline') else None,
                
                description=f"🚨 SUSPICIOUS PROCESS: {proc_info.get('name')} detected",
                raw_event_data={
                    'event_subtype': 'suspicious_process',
                    'process_category': 'suspicious',
                    'risk_level': 'high',
                    'detection_reason': 'known_suspicious_process_name'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Suspicious process event failed: {e}")
            return None
    
    async def _create_child_process_event(self, proc_info: Dict):
        """EVENT TYPE 6: Child Process Event - FIXED"""
        try:
            # Only create events for interesting parent-child relationships
            if proc_info.get('ppid') and proc_info.get('ppid') in self.monitored_processes:
                parent_info = self.monitored_processes[proc_info['ppid']]
                
                return EventData(
                    event_type=EventType.PROCESS,
                    event_action=EventAction.CREATE,
                    event_timestamp=datetime.now(),
                    severity="Info",
                    
                    process_id=proc_info.get('pid'),
                    process_name=proc_info.get('name'),
                    parent_pid=proc_info.get('ppid'),
                    parent_process_name=parent_info.get('name'),
                    
                    description=f"👶 CHILD PROCESS: {proc_info.get('name')} spawned by {parent_info.get('name')}",
                    raw_event_data={
                        'event_subtype': 'child_process_creation',
                        'parent_name': parent_info.get('name'),
                        'parent_exe': parent_info.get('exe'),
                        'child_name': proc_info.get('name'),
                        'process_tree_depth': 1
                    }
                )
        except Exception as e:
            self.logger.error(f"❌ Child process event failed: {e}")
        return None
    
    async def _create_process_performance_event(self, proc_info: Dict):
        """EVENT TYPE 7: Process Performance Summary Event - FIXED"""
        try:
            memory_rss = proc_info.get('memory_rss', 0)
            memory_mb = memory_rss / (1024 * 1024) if memory_rss > 0 else 0
            
            return EventData(
                event_type=EventType.PROCESS,
                event_action=EventAction.RESOURCE_USAGE,
                event_timestamp=datetime.now(),
                severity="Info",
                
                process_id=proc_info.get('pid'),
                process_name=proc_info.get('name'),
                cpu_usage=proc_info.get('cpu_percent', 0),
                memory_usage=memory_mb,
                
                description=f"📊 PROCESS PERFORMANCE: {proc_info.get('name')} stats",
                raw_event_data={
                    'event_subtype': 'process_performance_summary',
                    'cpu_percent': proc_info.get('cpu_percent', 0),
                    'memory_rss_mb': memory_mb,
                    'memory_vms_mb': proc_info.get('memory_vms', 0) / (1024 * 1024) if proc_info.get('memory_vms', 0) > 0 else 0,
                    'create_time': proc_info.get('create_time'),
                    'username': proc_info.get('username')
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Process performance event failed: {e}")
            return None
    
    def get_stats(self) -> Dict:
        """Get detailed statistics for multiple event types"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'Process_MultipleEvents_Fixed',
            'process_create_events': self.stats['process_create_events'],
            'process_terminate_events': self.stats['process_terminate_events'],
            'process_cpu_events': self.stats['process_cpu_events'],
            'process_memory_events': self.stats['process_memory_events'],
            'process_suspicious_events': self.stats['process_suspicious_events'],
            'process_child_events': self.stats['process_child_events'],
            'process_performance_events': self.stats['process_performance_events'],
            'total_events_sent': self.stats['total_events_sent'],
            'multiple_event_types': True,
            'memory_error_fixed': True,
            'event_types_generated': [
                'process_creation', 'process_termination', 'high_cpu_usage',
                'high_memory_usage', 'suspicious_process', 'child_process_creation',
                'process_performance_summary'
            ]
        })
        return base_stats