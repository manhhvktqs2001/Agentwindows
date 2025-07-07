# agent/collectors/process_collector.py - ENHANCED VERSION FOR ALL PROCESSES
"""
Enhanced Process Collector - Tạo alert cho TẤT CẢ processes
Thu thập và báo cáo mọi process activity, không chỉ suspicious processes
"""

import psutil
import time
import asyncio
import logging
from typing import Dict, List, Optional, Set
from datetime import datetime
from pathlib import Path

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventAction
from agent.utils.process_utils import get_process_info, get_process_hash, is_system_process

logger = logging.getLogger('ProcessCollector')

class EnhancedProcessCollector(BaseCollector):
    """Enhanced Process Collector - Alert cho TẤT CẢ process activities"""
    
    def __init__(self, config_manager=None):
        if config_manager is None:
            from agent.core.config_manager import ConfigManager
            config_manager = ConfigManager()
        super().__init__(config_manager, "ProcessCollector")
        
        # ENHANCED: Tracking tất cả processes
        self.monitored_processes = {}
        self.baseline_processes = set()
        self.last_scan_pids = set()
        self.process_cpu_history = {}
        self.process_memory_history = {}
        
        # ENHANCED: Categories for ALL processes (không chỉ suspicious)
        self.all_executables = {
            'powershell.exe', 'cmd.exe', 'notepad.exe', 'calc.exe', 'explorer.exe',
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'code.exe', 'winword.exe',
            'excel.exe', 'outlook.exe', 'teams.exe', 'skype.exe', 'zoom.exe',
            'discord.exe', 'steam.exe', 'vlc.exe', 'winrar.exe', '7z.exe',
            'python.exe', 'java.exe', 'node.exe', 'git.exe', 'putty.exe',
            'wscript.exe', 'cscript.exe', 'rundll32.exe', 'regsvr32.exe',
            'mshta.exe', 'certutil.exe', 'bitsadmin.exe', 'svchost.exe',
            'lsass.exe', 'winlogon.exe', 'csrss.exe', 'dwm.exe', 'taskhost.exe'
        }
        
        # ENHANCED: Alert for ALL process types
        self.interesting_processes = {
            'editors': ['notepad.exe', 'notepad++.exe', 'code.exe', 'sublime_text.exe'],
            'calculators': ['calc.exe', 'calculator.exe'],
            'browsers': ['chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe'],
            'system_tools': ['cmd.exe', 'powershell.exe', 'powershell_ise.exe'],
            'office': ['winword.exe', 'excel.exe', 'powerpoint.exe', 'outlook.exe'],
            'media': ['vlc.exe', 'wmplayer.exe', 'spotify.exe'],
            'development': ['python.exe', 'java.exe', 'node.exe', 'dotnet.exe'],
            'communication': ['teams.exe', 'skype.exe', 'discord.exe', 'zoom.exe'],
            'security': ['defender.exe', 'ccleaner.exe', 'malwarebytes.exe'],
            'utilities': ['winrar.exe', '7z.exe', 'putty.exe', 'filezilla.exe']
        }
        
        # FIXED: Optimize thresholds for better performance
        self.high_cpu_threshold = 80  # Increase from 70% to 80%
        self.high_memory_threshold = 500 * 1024 * 1024  # Increase from 300MB to 500MB
        self.polling_interval = 0.5  # Decrease from 2.0s to 0.5s for more frequent scanning
        
        # FIXED: Reduce event generation for better performance
        self.generate_alerts_for_all_processes = False  # Only alert on interesting processes
        self.alert_on_process_creation = True
        self.alert_on_process_termination = False  # Disable termination alerts
        self.alert_on_interesting_processes = True
        
        # ENHANCED: Statistics for ALL processes
        self.stats = {
            'total_process_create_events': 0,
            'total_process_terminate_events': 0,
            'notepad_events': 0,
            'calc_events': 0,
            'browser_events': 0,
            'office_events': 0,
            'system_tool_events': 0,
            'suspicious_events': 0,
            'high_cpu_events': 0,
            'high_memory_events': 0,
            'total_events_generated': 0
        }
        
        # FIXED: Add counter for existing process events
        self.existing_process_counter = 0
        self.last_existing_process_log = 0
        
        self.logger.info("Enhanced Process Collector initialized - PERFORMANCE OPTIMIZED")
    
    async def _collect_data(self):
        """Collect process events - ENHANCED to include ALL running processes"""
        try:
            start_time = time.time()
            events = []
            current_pids = set()
            
            # ENHANCED: Scan ALL processes (không lọc theo tên)
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'username', 'ppid']):
                try:
                    proc_info = proc.info
                    if not proc_info['pid'] or not proc_info['name']:
                        continue
                    
                    pid = proc_info['pid']
                    current_pids.add(pid)
                    process_name = proc_info['name'].lower()
                    
                    # Lấy CPU và memory info an toàn
                    try:
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
                    
                    # Tạo event cho mọi process mới
                    if pid not in self.monitored_processes:
                        event = await self._create_enhanced_process_creation_event(proc_info)
                        if event:
                            events.append(event)
                            self.stats['total_process_create_events'] += 1
                        
                        # Count specific process types
                        self._update_process_type_stats(proc_info['name'], 'create')
                        
                        # Check high CPU/Memory for NEW interesting processes
                        if proc_info.get('cpu_percent', 0) > self.high_cpu_threshold:
                            cpu_event = await self._create_high_cpu_event(proc_info)
                            if cpu_event:
                                events.append(cpu_event)
                                self.stats['high_cpu_events'] += 1
                        
                        if proc_info.get('memory_rss', 0) > self.high_memory_threshold:
                            memory_event = await self._create_high_memory_event(proc_info)
                            if memory_event:
                                events.append(memory_event)
                                self.stats['high_memory_events'] += 1
                    
                    elif pid in self.monitored_processes:
                        self.existing_process_counter += 1
                        
                        # Log existing processes every 10 scans to show they're being monitored
                        if self.existing_process_counter % 10 == 0:
                            existing_event = await self._create_existing_process_activity_event(proc_info)
                            if existing_event:
                                events.append(existing_event)
                        
                        # Check high CPU/Memory for existing interesting processes
                        if proc_info.get('cpu_percent', 0) > self.high_cpu_threshold:
                            cpu_event = await self._create_high_cpu_event(proc_info)
                            if cpu_event:
                                events.append(cpu_event)
                                self.stats['high_cpu_events'] += 1
                        
                        if proc_info.get('memory_rss', 0) > self.high_memory_threshold:
                            memory_event = await self._create_high_memory_event(proc_info)
                            if memory_event:
                                events.append(memory_event)
                                self.stats['high_memory_events'] += 1
                    
                    # Update tracking
                    self.monitored_processes[pid] = {
                        'name': proc_info['name'],
                        'exe': proc_info['exe'],
                        'last_seen': time.time(),
                        'cpu_percent': proc_info.get('cpu_percent', 0),
                        'memory_rss': proc_info.get('memory_rss', 0),
                        'create_time': proc_info.get('create_time', 0)
                    }
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # FIXED: Disable termination events for better performance
            # terminated_pids = self.last_scan_pids - current_pids
            # for pid in terminated_pids:
            #     if pid in self.monitored_processes:
            #         event = await self._create_enhanced_process_termination_event(pid, self.monitored_processes[pid])
            #         if event:
            #             events.append(event)
            #             self.stats['total_process_terminate_events'] += 1
            #         del self.monitored_processes[pid]
            
            # Update tracking
            self.last_scan_pids = current_pids
            self.stats['total_events_generated'] += len(events)
            
            # FIXED: Log events when connected to server OR when we have events to show
            if events:
                self.logger.info(f"📤 Generated {len(events)} PROCESS EVENTS")
                
                # Log interesting events
                for event in events[:3]:  # Log first 3 events
                    if hasattr(event, 'process_name'):
                        self.logger.info(f"   📱 {event.event_action}: {event.process_name}")
            
            # FIXED: Log performance metrics with better thresholds
            collection_time = (time.time() - start_time) * 1000
            if collection_time > 1000:  # Reduce threshold from 6000ms to 1000ms
                self.logger.warning(f"⚠️ Slow collection: {collection_time:.1f}ms in ProcessCollector")
            elif collection_time > 500:
                self.logger.info(f"📊 Process scan time: {collection_time:.1f}ms")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Enhanced process events collection failed: {e}")
            return []
    
    def _is_interesting_process(self, process_name: str) -> bool:
        """Check if process is interesting enough for alerts"""
        if not process_name:
            return False
        
        process_lower = process_name.lower()
        
        # Check all interesting process categories
        for category, processes in self.interesting_processes.items():
            if any(proc.lower() in process_lower for proc in processes):
                return True
        
        # Check if it's in our general list
        if process_lower in self.all_executables:
            return True
        
        return False
    
    def _update_process_type_stats(self, process_name: str, action: str):
        """Update statistics for specific process types"""
        if not process_name:
            return
        
        process_lower = process_name.lower()
        
        # Update specific counters
        if 'notepad' in process_lower:
            self.stats['notepad_events'] += 1
        elif 'calc' in process_lower:
            self.stats['calc_events'] += 1
        elif any(browser in process_lower for browser in ['chrome', 'firefox', 'edge', 'browser']):
            self.stats['browser_events'] += 1
        elif any(office in process_lower for office in ['word', 'excel', 'powerpoint', 'outlook']):
            self.stats['office_events'] += 1
        elif any(tool in process_lower for tool in ['cmd', 'powershell', 'wscript', 'cscript']):
            self.stats['system_tool_events'] += 1
        elif any(sus in process_lower for sus in ['rundll32', 'regsvr32', 'mshta', 'certutil']):
            self.stats['suspicious_events'] += 1
    
    async def _create_enhanced_process_creation_event(self, proc_info: Dict):
        """ENHANCED EVENT TYPE 1: Process Creation Event for ALL processes"""
        try:
            process_name = proc_info.get('name', 'Unknown')
            severity = self._determine_enhanced_severity(process_name, proc_info)
            
            # Create enhanced description
            description = f"🆕 PROCESS STARTED: {process_name}"
            if proc_info.get('exe'):
                description += f" from {proc_info['exe']}"
            if proc_info.get('username'):
                description += f" by {proc_info['username']}"
            
            parent_pid = proc_info.get('ppid')
            if parent_pid is None:
                parent_pid = 0
            
            return EventData(
                event_type="Process",
                event_action=EventAction.START,
                event_timestamp=datetime.now(),
                severity=severity,
                
                process_id=proc_info.get('pid'),
                process_name=proc_info.get('name'),
                process_path=proc_info.get('exe'),
                command_line=' '.join(proc_info.get('cmdline', [])),
                parent_pid=int(parent_pid),
                process_user=proc_info.get('username'),
                
                description=f"🆕 PROCESS STARTED: {proc_info.get('name')} (PID: {proc_info.get('pid')})",
                raw_event_data={
                    'event_subtype': 'process_creation',
                    'process_category': self._get_process_category(proc_info.get('name', '')),
                    'cpu_percent': proc_info.get('cpu_percent', 0),
                    'memory_rss': proc_info.get('memory_rss', 0),
                    'create_time': proc_info.get('create_time'),
                    'is_interesting': self._is_interesting_process(proc_info.get('name', '')),
                    'parent_process': self._get_parent_process_name(int(parent_pid))
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Enhanced process creation event failed: {e}")
            return None
    
    async def _create_enhanced_process_termination_event(self, pid: int, proc_info: Dict):
        """ENHANCED EVENT TYPE 2: Process Termination Event for ALL processes"""
        try:
            process_name = proc_info.get('name', 'Unknown')
            
            # Calculate process lifetime
            lifetime = time.time() - proc_info.get('last_seen', time.time())
            
            description = f"❌ PROCESS ENDED: {process_name} (ran for {lifetime:.1f}s)"
            
            return EventData(
                event_type="Process",
                event_action=EventAction.STOP,
                event_timestamp=datetime.now(),
                severity="Info",
                
                process_id=pid,
                process_name=process_name,
                process_path=proc_info.get('exe'),
                
                description=description,
                raw_event_data={
                    'event_subtype': 'enhanced_process_termination',
                    'process_category': self._get_process_category(process_name),
                    'termination_time': time.time(),
                    'process_lifetime': lifetime,
                    'last_cpu_percent': proc_info.get('cpu_percent', 0),
                    'last_memory_mb': proc_info.get('memory_rss', 0) / (1024 * 1024) if proc_info.get('memory_rss') else 0,
                    'was_interesting': self._is_interesting_process(process_name),
                    'enhanced_monitoring': True
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Enhanced process termination event failed: {e}")
            return None
    
    async def _create_interesting_process_activity_event(self, proc_info: Dict):
        """ENHANCED EVENT TYPE 3: Interesting Process Activity Event"""
        try:
            process_name = proc_info.get('name', 'Unknown')
            category = self._get_process_category(process_name)
            
            return EventData(
                event_type="Process",
                event_action=EventAction.ACCESS,
                event_timestamp=datetime.now(),
                severity="Medium" if category in ['system_tools', 'security'] else "Info",
                
                process_id=proc_info.get('pid'),
                process_name=process_name,
                process_path=proc_info.get('exe'),
                command_line=' '.join(proc_info['cmdline']) if proc_info.get('cmdline') else None,
                
                description=f"⭐ INTERESTING PROCESS ACTIVITY: {process_name} ({category})",
                raw_event_data={
                    'event_subtype': 'interesting_process_activity',
                    'process_category': category,
                    'activity_type': 'execution',
                    'interest_level': 'high' if category in ['system_tools', 'security'] else 'medium',
                    'cpu_percent': proc_info.get('cpu_percent', 0),
                    'memory_mb': proc_info.get('memory_rss', 0) / (1024 * 1024) if proc_info.get('memory_rss') else 0,
                    'enhanced_monitoring': True
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Interesting process activity event failed: {e}")
            return None
    
    async def _create_high_cpu_event(self, proc_info: Dict):
        """ENHANCED EVENT TYPE 4: High CPU Usage Event"""
        try:
            cpu_percent = proc_info.get('cpu_percent', 0)
            
            return EventData(
                event_type="Process",
                event_action=EventAction.RESOURCE_USAGE,
                event_timestamp=datetime.now(),
                severity="High" if cpu_percent > 90 else "Medium",
                
                process_id=proc_info.get('pid'),
                process_name=proc_info.get('name'),
                cpu_usage=cpu_percent,
                
                description=f"🔥 HIGH CPU USAGE: {proc_info.get('name')} using {cpu_percent:.1f}% CPU",
                raw_event_data={
                    'event_subtype': 'high_cpu_usage',
                    'cpu_percent': cpu_percent,
                    'threshold': self.high_cpu_threshold,
                    'performance_impact': 'high' if cpu_percent > 90 else 'medium',
                    'enhanced_monitoring': True
                }
            )
        except Exception as e:
            self.logger.error(f"❌ High CPU event failed: {e}")
            return None
    
    async def _create_high_memory_event(self, proc_info: Dict):
        """ENHANCED EVENT TYPE 5: High Memory Usage Event"""
        try:
            memory_rss = proc_info.get('memory_rss', 0)
            memory_mb = memory_rss / (1024 * 1024)
            
            return EventData(
                event_type="Process",
                event_action=EventAction.RESOURCE_USAGE,
                event_timestamp=datetime.now(),
                severity="Medium",
                
                process_id=proc_info.get('pid'),
                process_name=proc_info.get('name'),
                memory_usage=memory_mb,
                
                description=f"💾 HIGH MEMORY USAGE: {proc_info.get('name')} using {memory_mb:.1f}MB",
                raw_event_data={
                    'event_subtype': 'high_memory_usage',
                    'memory_rss': memory_rss,
                    'memory_mb': memory_mb,
                    'threshold_mb': self.high_memory_threshold / (1024 * 1024),
                    'enhanced_monitoring': True
                }
            )
        except Exception as e:
            self.logger.error(f"❌ High memory event failed: {e}")
            return None
    
    def _determine_enhanced_severity(self, process_name: str, proc_info: Dict) -> str:
        """Determine enhanced severity for ALL processes"""
        if not process_name:
            return "Info"
        
        process_lower = process_name.lower()
        
        # High severity for security tools and system utilities
        if any(tool in process_lower for tool in ['powershell', 'cmd', 'rundll32', 'regsvr32', 'certutil']):
            return "High"
        
        # Medium severity for interesting applications
        if any(app in process_lower for app in ['notepad', 'calc', 'chrome', 'firefox']):
            return "Medium"
        
        # High CPU or memory
        if proc_info.get('cpu_percent', 0) > 80 or proc_info.get('memory_rss', 0) > 500 * 1024 * 1024:
            return "High"
        
        return "Info"
    
    def _get_process_category(self, process_name: str) -> str:
        """Get process category for classification"""
        if not process_name:
            return 'unknown'
        
        process_lower = process_name.lower()
        
        for category, processes in self.interesting_processes.items():
            if any(proc.lower() in process_lower for proc in processes):
                return category
        
        return 'other'
    
    def _get_parent_process_name(self, parent_pid: int) -> str:
        """Get parent process name from PID"""
        try:
            if parent_pid and parent_pid > 0:
                parent_process = psutil.Process(parent_pid)
                return parent_process.name()
            return "Unknown"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "Unknown"
        except Exception:
            return "Unknown"
    
    async def _create_existing_process_activity_event(self, proc_info: Dict):
        """EVENT TYPE 6: Existing Process Activity Event - to show monitoring is working"""
        try:
            process_name = proc_info.get('name', 'Unknown')
            
            parent_pid = proc_info.get('ppid')
            if parent_pid is None:
                parent_pid = 0
            
            return EventData(
                event_type="Process",
                event_action=EventAction.ACCESS,
                event_timestamp=datetime.now(),
                severity="Info",
                
                process_id=proc_info.get('pid'),
                process_name=process_name,
                process_path=proc_info.get('exe'),
                command_line=' '.join(proc_info.get('cmdline', [])),
                parent_pid=int(parent_pid),
                process_user=proc_info.get('username'),
                
                description=f"📱 PROCESS MONITORING: {process_name} (PID: {proc_info.get('pid')}) - Active",
                raw_event_data={
                    'event_subtype': 'existing_process_activity',
                    'process_category': self._get_process_category(process_name),
                    'cpu_percent': proc_info.get('cpu_percent', 0),
                    'memory_rss': proc_info.get('memory_rss', 0),
                    'is_interesting': self._is_interesting_process(process_name),
                    'monitoring_type': 'existing_process',
                    'parent_process': self._get_parent_process_name(int(parent_pid))
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Existing process activity event failed: {e}")
            return None
    
    def get_stats(self) -> Dict:
        """Get detailed statistics for enhanced process monitoring"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'Process_Enhanced_AllProcesses',
            'total_process_create_events': self.stats['total_process_create_events'],
            'total_process_terminate_events': self.stats['total_process_terminate_events'],
            'notepad_events': self.stats['notepad_events'],
            'calc_events': self.stats['calc_events'],
            'browser_events': self.stats['browser_events'],
            'office_events': self.stats['office_events'],
            'system_tool_events': self.stats['system_tool_events'],
            'suspicious_events': self.stats['suspicious_events'],
            'high_cpu_events': self.stats['high_cpu_events'],
            'high_memory_events': self.stats['high_memory_events'],
            'total_events_generated': self.stats['total_events_generated'],
            'monitored_processes_count': len(self.monitored_processes),
            'enhanced_monitoring': True,
            'alert_all_processes': True,
            'process_categories_monitored': list(self.interesting_processes.keys()),
            'interesting_processes_count': len(self.all_executables)
        })
        return base_stats

def collect_all_processes():
    """Thu thập tất cả tiến trình đang chạy trên hệ thống (không lọc)"""
    all_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'status']):
        try:
            proc_info = proc.info
            if not proc_info['pid'] or not proc_info['name']:
                continue
            all_processes.append(proc_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return all_processes

if __name__ == "__main__":
    processes = collect_all_processes()
    print(f"Total processes: {len(processes)}")
    for p in processes:
        print(p)