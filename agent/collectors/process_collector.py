# agent/collectors/process_collector.py - FIXED VERSION
"""
Enhanced Process Collector - Continuous Process Monitoring
Thu thập thông tin process liên tục và gửi cho server
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
    """Enhanced Process Collector with continuous monitoring - FIXED"""
    
    def __init__(self, config_manager=None):
        super().__init__(config_manager, "ProcessCollector")
        self.config_manager = config_manager
        self.logger = logging.getLogger('ProcessCollector')
        self.monitored_processes = set()
        self.baseline_processes = set()
        self.suspicious_processes = {
            'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
            'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe',
            'bitsadmin.exe', 'wmic.exe', 'schtasks.exe', 'at.exe'
        }
        
        # Performance tracking
        self.stats = {
            'processes_scanned': 0,
            'new_processes_detected': 0,
            'suspicious_processes_detected': 0,
            'events_generated': 0,
            'last_scan_time': None
        }
        
        self.logger.info("Enhanced Process Collector initialized")
    
    async def initialize(self):
        """Initialize the process collector"""
        try:
            self.logger.info("🔧 Initializing Enhanced Process Collector...")
            await super().initialize()
            await self._create_baseline()
            self.logger.info("✅ Enhanced Process Collector initialized successfully")
        except Exception as e:
            self.logger.error(f"❌ Enhanced Process Collector initialization failed: {e}")
            raise
    
    async def _create_baseline(self):
        """Create baseline of current processes"""
        try:
            self.logger.info("📋 Creating process baseline...")
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    proc_info = proc.info
                    process_key = f"{proc_info['name']}_{proc_info['exe']}"
                    self.baseline_processes.add(process_key)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            self.logger.info(f"✅ Baseline created: {len(self.baseline_processes)} processes")
            
        except Exception as e:
            self.logger.error(f"❌ Baseline creation failed: {e}")
    
    async def _collect_data(self):
        """Collect process data - Required by BaseCollector"""
        try:
            events = []
            current_processes = set()
            new_processes = []
            suspicious_events = []
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'username']):
                try:
                    proc_info = proc.info
                    if not proc_info['name']:
                        continue
                        
                    process_key = f"{proc_info['name']}_{proc_info['exe']}"
                    current_processes.add(process_key)
                    
                    # Check for new processes
                    if process_key not in self.baseline_processes and process_key not in self.monitored_processes:
                        new_processes.append(proc_info)
                        self.monitored_processes.add(process_key)
                    
                    # Check for suspicious processes
                    if proc_info['name'] and proc_info['name'].lower() in self.suspicious_processes:
                        suspicious_events.append(proc_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Generate events for new processes
            for proc_info in new_processes:
                event = await self._generate_process_event(proc_info, EventAction.CREATE)
                if event:
                    events.append(event)
                    self.stats['new_processes_detected'] += 1
            
            # Generate events for suspicious processes
            for proc_info in suspicious_events:
                event = await self._generate_process_event(proc_info, EventAction.START, severity="High")
                if event:
                    events.append(event)
                    self.stats['suspicious_processes_detected'] += 1
            
            self.stats['processes_scanned'] += len(current_processes)
            self.stats['last_scan_time'] = datetime.now()
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Process scan failed: {e}")
            return []
    
    async def _generate_process_event(self, proc_info: Dict, action: str, severity: str = "Info"):
        """Generate process event for server"""
        try:
            # Get additional process details
            process_details = None
            try:
                if proc_info.get('pid'):
                    process_details = get_process_info(proc_info['pid'])
            except:
                pass
            
            event = EventData(
                event_type=EventType.PROCESS,
                event_action=action,
                event_timestamp=datetime.now(),
                severity=severity,
                
                # Process details
                process_id=proc_info.get('pid'),
                process_name=proc_info.get('name'),
                process_path=proc_info.get('exe'),
                command_line=' '.join(proc_info['cmdline']) if proc_info.get('cmdline') else None,
                process_user=proc_info.get('username'),
                
                # Additional context
                description=f"Process {action.lower()}: {proc_info.get('name', 'Unknown')} (PID: {proc_info.get('pid', 'Unknown')})"
            )
            
            # Add process hash if available
            if proc_info.get('exe') and Path(str(proc_info['exe'])).exists():
                try:
                    event.process_hash = get_process_hash(proc_info['exe'])
                except:
                    pass
            
            # Add parent process info
            if process_details and process_details.get('parent_pid'):
                event.parent_pid = process_details['parent_pid']
                event.parent_process_name = process_details.get('parent_name')
            
            # Add raw event data
            event.raw_event_data = {
                'create_time': proc_info.get('create_time'),
                'cpu_percent': process_details.get('cpu_percent') if process_details else None,
                'memory_percent': process_details.get('memory_percent') if process_details else None,
                'num_threads': process_details.get('num_threads') if process_details else None,
                'is_suspicious': proc_info.get('name', '').lower() in self.suspicious_processes
            }
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Process event generation failed: {e}")
            return None
    
    def get_stats(self) -> Dict:
        """Get collector statistics"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'Process',
            'processes_scanned': self.stats['processes_scanned'],
            'new_processes_detected': self.stats['new_processes_detected'],
            'suspicious_processes_detected': self.stats['suspicious_processes_detected'],
            'events_generated': self.stats['events_generated'],
            'last_scan_time': self.stats['last_scan_time'].isoformat() if self.stats['last_scan_time'] else None,
            'baseline_processes': len(self.baseline_processes),
            'monitored_processes': len(self.monitored_processes)
        })
        return base_stats