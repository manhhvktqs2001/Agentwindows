# agent/collectors/process_collector.py
"""
Process Collector - Fixed "can only join an iterable" error
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

class FileCollector(BaseCollector):
    """File system monitoring collector - Fixed restricted_paths error"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "FileCollector")
        
        # Initialize restricted_paths BEFORE any path checking
        self.restricted_paths = []
        self.accessible_paths = []
        
        # Get monitor paths with access checking
        self.monitor_paths = self._get_monitor_paths()
        
        # Other initialization...
        self.collect_hashes = True
        self.max_file_size = 100 * 1024 * 1024  # 100MB
        
    def _get_monitor_paths(self) -> List[str]:
        """Get paths to monitor with access checking"""
        try:
            # User accessible paths
            user_paths = [
                str(Path.home()),
                str(Path.home() / 'Desktop'),
                str(Path.home() / 'Documents'), 
                str(Path.home() / 'Downloads')
            ]
            
            accessible = []
            for path in user_paths:
                if self._test_path_access(path):
                    accessible.append(path)
                else:
                    self.restricted_paths.append(path)
            
            self.accessible_paths = accessible
            return accessible
            
        except Exception as e:
            self.logger.error(f"❌ Error getting monitor paths: {e}")
            return []
    
    def _test_path_access(self, path: str) -> bool:
        """Test if path is accessible"""
        try:
            path_obj = Path(path)
            if path_obj.exists() and path_obj.is_dir():
                list(path_obj.iterdir())
                return True
        except:
            pass
        return False
    
    async def _collect_data(self):
        """File collector uses event-driven approach"""
        return []

class ProcessCollector(BaseCollector):
    """Process monitoring and analysis collector - Fixed errors"""
    
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
            await super().stop()
            self.logger.info("🛑 Process collector stopped")
        except Exception as e:
            self.logger.error(f"❌ Failed to stop process collector: {e}")
            
    async def _collect_data(self):
        """Collect process information and detect new/terminated processes"""
        try:
            current_processes = set()
            current_time = datetime.now()
            events = []
            
            # Get current running processes
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent', 'create_time']):
                try:
                    proc_info = proc.info
                    if proc_info['pid'] is None or proc_info['name'] is None:
                        continue
                        
                    process_key = f"{proc_info['pid']}_{proc_info['name']}"
                    current_processes.add(process_key)
                    
                    # Check if this is a new process
                    if process_key not in self.known_processes:
                        # NEW PROCESS DETECTED
                        self.known_processes.add(process_key)
                        
                        # Fix: Handle cmdline properly - it can be None or a list
                        cmdline_str = ""
                        if proc_info.get('cmdline'):
                            if isinstance(proc_info['cmdline'], list):
                                # Filter out None values and join
                                clean_cmdline = [str(arg) for arg in proc_info['cmdline'] if arg is not None]
                                cmdline_str = ' '.join(clean_cmdline)
                            else:
                                cmdline_str = str(proc_info['cmdline'])
                        
                        # Create event data
                        event_data = EventData(
                            event_type='Process',
                            event_action='Create',
                            event_timestamp=current_time,
                            severity='Info',
                            description=f'New process started: {proc_info["name"]} (PID: {proc_info["pid"]})',
                            process_id=proc_info['pid'],
                            process_name=proc_info['name'],
                            process_path=proc_info.get('exe', ''),
                            command_line=cmdline_str,  # Fixed: use proper string
                            cpu_usage=proc_info.get('cpu_percent', 0),
                            memory_usage=proc_info.get('memory_percent', 0),
                            raw_event_data=json.dumps({
                                'pid': proc_info['pid'],
                                'name': proc_info['name'],
                                'exe': proc_info.get('exe', ''),
                                'cmdline': cmdline_str,
                                'cpu_percent': proc_info.get('cpu_percent', 0),
                                'memory_percent': proc_info.get('memory_percent', 0),
                                'create_time': proc_info.get('create_time'),
                                'action': 'created'
                            })
                        )
                        
                        events.append(event_data)
                        self.logger.debug(f"🆕 New process detected: {proc_info['name']} (PID: {proc_info['pid']})")
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    self.logger.debug(f"Error processing process info: {e}")
                    continue
            
            # Check for terminated processes
            terminated_processes = self.known_processes - current_processes
            for process_key in terminated_processes:
                try:
                    # Fix: Handle process_key parsing safely
                    parts = process_key.split('_', 1)
                    if len(parts) >= 2:
                        pid_str, name = parts[0], parts[1]
                        try:
                            pid = int(pid_str)
                        except ValueError:
                            continue
                            
                        event_data = EventData(
                            event_type='Process',
                            event_action='Terminate',
                            event_timestamp=current_time,
                            severity='Info',
                            description=f'Process terminated: {name} (PID: {pid})',
                            process_id=pid,
                            process_name=name,
                            raw_event_data=json.dumps({
                                'pid': pid, 
                                'name': name, 
                                'action': 'terminated'
                            })
                        )
                        
                        events.append(event_data)
                        self.known_processes.discard(process_key)
                        self.logger.debug(f"💀 Process terminated: {name} (PID: {pid})")
                        
                except Exception as e:
                    self.logger.debug(f"Error processing terminated process {process_key}: {e}")
                    # Remove invalid process key
                    self.known_processes.discard(process_key)
                    continue
            
            # Clean up old process tracking (keep only reasonable amount)
            if len(self.known_processes) > 10000:
                # Keep only the most recent processes
                processes_list = list(self.known_processes)
                self.known_processes = set(processes_list[-5000:])
                self.logger.debug(f"🧹 Cleaned up process tracking: kept {len(self.known_processes)} processes")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Process collection error: {e}")
            return []
            
    async def _get_initial_process_snapshot(self):
        """Get initial snapshot of running processes"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_info = proc.info
                    if proc_info['pid'] is not None and proc_info['name'] is not None:
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