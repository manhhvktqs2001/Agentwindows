# agent/collectors/system_collector.py - MULTIPLE SYSTEM EVENT TYPES
"""
Enhanced System Collector - Gửi nhiều loại system events liên tục
Thu thập nhiều loại thông tin system và gửi events khác nhau cho server
"""

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventAction
import psutil
from datetime import datetime
import asyncio
import json
import time
import platform
from typing import List, Dict, Any, Optional
from collections import deque

class SystemCollector(BaseCollector):
    """Enhanced System Collector - Multiple system event types for continuous sending"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "SystemCollector")
        
        # FIXED: Optimize performance settings
        self.cpu_history = deque(maxlen=30)  # Reduce from 60
        self.memory_history = deque(maxlen=30)
        self.disk_history = deque(maxlen=30)
        self.network_history = deque(maxlen=30)
        self.process_count_history = deque(maxlen=30)
        
        # FIXED: Optimize performance thresholds
        self.cpu_high_threshold = 80  # Increase from 75
        self.cpu_critical_threshold = 95  # Increase from 90
        self.memory_high_threshold = 85  # Increase from 80
        self.memory_critical_threshold = 95  # Increase from 90
        self.disk_high_threshold = 90  # Increase from 85
        self.disk_critical_threshold = 98  # Increase from 95
        
        # FIXED: Optimize polling intervals
        self.polling_interval = 10  # Increase from 2 seconds
        self.send_regular_metrics = True
        self.metrics_send_interval = 30  # Increase from 8 seconds
        self.last_metrics_send = 0
        
        # FIXED: Reduce event frequency
        self.boot_events_sent = False
        self.system_alerts = []
        
        # Statistics
        self.stats = {
            'cpu_usage_events': 0,
            'memory_usage_events': 0,
            'disk_usage_events': 0,
            'process_count_events': 0,
            'system_performance_events': 0,
            'system_health_events': 0,
            'boot_events': 0,
            'service_events': 0,
            'hardware_events': 0,
            'total_system_events': 0
        }
        
        self.logger.info("Enhanced System Collector initialized - PERFORMANCE OPTIMIZED")
    
    async def _collect_data(self):
        if self._paused:
            self.logger.info("⏸️  SystemCollector paused - exiting _collect_data")
            return
        """Collect system events - ENHANCED for better performance"""
        try:
            start_time = time.time()
            events = []
            
            # FIXED: Check server connectivity before processing
            is_connected = False
            if hasattr(self, 'event_processor') and self.event_processor:
                if hasattr(self.event_processor, 'communication') and self.event_processor.communication:
                    is_connected = not self.event_processor.communication.offline_mode
            
            # ENHANCED: Get system information efficiently
            try:
                # CPU Usage Event
                cpu_percent = psutil.cpu_percent(interval=0.1)
                if cpu_percent > self.high_cpu_threshold:
                    cpu_event = await self._create_high_cpu_event(cpu_percent)
                    if cpu_event:
                        events.append(cpu_event)
                        self.stats['high_cpu_events'] += 1
                
                # Memory Usage Event
                memory = psutil.virtual_memory()
                if memory.percent > self.high_memory_threshold:
                    memory_event = await self._create_high_memory_event(memory)
                    if memory_event:
                        events.append(memory_event)
                        self.stats['high_memory_events'] += 1
                
                # Disk Usage Event
                disk = psutil.disk_usage('/')
                if disk.percent > self.high_disk_threshold:
                    disk_event = await self._create_high_disk_event(disk)
                    if disk_event:
                        events.append(disk_event)
                        self.stats['high_disk_events'] += 1
                
                # System Summary Event (every 10 scans)
                if self.stats['total_system_events'] % 10 == 0:
                    summary_event = await self._create_system_summary_event(cpu_percent, memory, disk)
                    if summary_event:
                        events.append(summary_event)
                        self.stats['system_summary_events'] += 1
                
            except Exception as e:
                self.logger.debug(f"System information collection failed: {e}")
                return []
            
            # Update stats
            self.stats['total_system_events'] += len(events)
            
            # FIXED: Only log events when connected to server
            if events and is_connected:
                self.logger.info(f"📤 Generated {len(events)} MULTIPLE SYSTEM EVENTS for continuous sending")
            
            # FIXED: Log performance metrics
            collection_time = (time.time() - start_time) * 1000
            if collection_time > 1000:
                self.logger.warning(f"⚠️ Slow system collection: {collection_time:.1f}ms")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ System events collection failed: {e}")
            return []
    
    async def _collect_current_system_metrics(self):
        """Collect current system metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            
            # Network metrics
            net_io = psutil.net_io_counters()
            
            # Process metrics
            process_count = len(psutil.pids())
            
            # System uptime
            boot_time = psutil.boot_time()
            uptime = time.time() - boot_time
            
            # Load average (if available)
            load_avg = None
            try:
                if hasattr(psutil, 'getloadavg'):
                    load_avg = psutil.getloadavg()
            except:
                pass
            
            return {
                'timestamp': time.time(),
                'cpu_percent': cpu_percent,
                'cpu_count': cpu_count,
                'memory_percent': memory.percent,
                'memory_total': memory.total,
                'memory_available': memory.available,
                'memory_used': memory.used,
                'disk_percent': disk.percent,
                'disk_total': disk.total,
                'disk_used': disk.used,
                'disk_free': disk.free,
                'network_bytes_sent': net_io.bytes_sent,
                'network_bytes_recv': net_io.bytes_recv,
                'process_count': process_count,
                'uptime_seconds': uptime,
                'boot_time': boot_time,
                'load_average': load_avg
            }
        except Exception as e:
            self.logger.error(f"❌ System metrics collection failed: {e}")
            return {}
    
    async def _create_system_metrics_event(self, metrics: Dict):
        """EVENT TYPE 1: Regular System Metrics Event"""
        try:
            severity = self._calculate_system_severity(metrics)
            
            return EventData(
                event_type="System",
                event_action=EventAction.RESOURCE_USAGE,
                event_timestamp=datetime.now(),
                severity=severity,
                
                cpu_usage=metrics.get('cpu_percent'),
                memory_usage=metrics.get('memory_percent'),
                disk_usage=metrics.get('disk_percent'),
                
                description=f"💻 SYSTEM RESOURCES: CPU {metrics.get('cpu_percent', 0):.1f}%, RAM {metrics.get('memory_percent', 0):.1f}%, Disk {metrics.get('disk_percent', 0):.1f}%",
                raw_event_data={
                    'event_subtype': 'system_resource_usage',
                    'cpu_count': psutil.cpu_count(),
                    'memory_total_gb': metrics.get('memory_total', 0) / (1024**3),
                    'memory_available_gb': metrics.get('memory_available', 0) / (1024**3),
                    'disk_total_gb': metrics.get('disk_total', 0) / (1024**3),
                    'disk_free_gb': metrics.get('disk_free', 0) / (1024**3),
                    'system_load': metrics.get('load_average') if hasattr(psutil, 'getloadavg') else None,
                    'boot_time': metrics.get('boot_time'),
                    'collection_time': time.time()
                }
            )
        except Exception as e:
            self.logger.error(f"❌ System metrics event failed: {e}")
            return None
    
    async def _check_cpu_usage_events(self, metrics: Dict) -> List[EventData]:
        """EVENT TYPE 2: CPU Usage Events"""
        events = []
        try:
            cpu_percent = metrics.get('cpu_percent', 0)
            
            if cpu_percent > self.cpu_critical_threshold:
                event = EventData(
                    event_type="System",
                    event_action=EventAction.CPU_SPIKE,
                    event_timestamp=datetime.now(),
                    severity="Critical",
                    
                    cpu_usage=cpu_percent,
                    description=f"🚨 CRITICAL CPU USAGE: {cpu_percent:.1f}% (Critical threshold: {self.cpu_critical_threshold}%)",
                    raw_event_data={
                        'event_subtype': 'critical_cpu_usage',
                        'cpu_percent': cpu_percent,
                        'threshold': self.cpu_critical_threshold,
                        'severity_level': 'critical'
                    }
                )
                events.append(event)
                self.stats['cpu_usage_events'] += 1
                
            elif cpu_percent > self.cpu_high_threshold:
                event = EventData(
                    event_type="System",
                    event_action=EventAction.RESOURCE_USAGE,
                    event_timestamp=datetime.now(),
                    severity="High",
                    
                    cpu_usage=cpu_percent,
                    description=f"⚠️ HIGH CPU USAGE: {cpu_percent:.1f}% (High threshold: {self.cpu_high_threshold}%)",
                    raw_event_data={
                        'event_subtype': 'high_cpu_usage',
                        'cpu_percent': cpu_percent,
                        'threshold': self.cpu_high_threshold,
                        'severity_level': 'high'
                    }
                )
                events.append(event)
                self.stats['cpu_usage_events'] += 1
                
        except Exception as e:
            self.logger.error(f"❌ CPU usage events check failed: {e}")
        
        return events
    
    async def _check_memory_usage_events(self, metrics: Dict) -> List[EventData]:
        """EVENT TYPE 3: Memory Usage Events"""
        events = []
        try:
            memory_percent = metrics.get('memory_percent', 0)
            
            if memory_percent > self.memory_critical_threshold:
                event = EventData(
                    event_type="System",
                    event_action=EventAction.MEMORY_LEAK,
                    event_timestamp=datetime.now(),
                    severity="Critical",
                    
                    memory_usage=memory_percent,
                    description=f"💾 CRITICAL MEMORY USAGE: {memory_percent:.1f}% (Critical threshold: {self.memory_critical_threshold}%)",
                    raw_event_data={
                        'event_subtype': 'critical_memory_usage',
                        'memory_percent': memory_percent,
                        'memory_total_gb': metrics.get('memory_total', 0) / (1024**3),
                        'memory_available_gb': metrics.get('memory_available', 0) / (1024**3),
                        'threshold': self.memory_critical_threshold
                    }
                )
                events.append(event)
                self.stats['memory_usage_events'] += 1
                
            elif memory_percent > self.memory_high_threshold:
                event = EventData(
                    event_type="System",
                    event_action=EventAction.RESOURCE_USAGE,
                    event_timestamp=datetime.now(),
                    severity="High",
                    
                    memory_usage=memory_percent,
                    description=f"⚠️ HIGH MEMORY USAGE: {memory_percent:.1f}% (High threshold: {self.memory_high_threshold}%)",
                    raw_event_data={
                        'event_subtype': 'high_memory_usage',
                        'memory_percent': memory_percent,
                        'threshold': self.memory_high_threshold
                    }
                )
                events.append(event)
                self.stats['memory_usage_events'] += 1
                
        except Exception as e:
            self.logger.error(f"❌ Memory usage events check failed: {e}")
        
        return events
    
    async def _check_disk_usage_events(self, metrics: Dict) -> List[EventData]:
        """EVENT TYPE 4: Disk Usage Events"""
        events = []
        try:
            disk_percent = metrics.get('disk_percent', 0)
            
            if disk_percent > self.disk_critical_threshold:
                event = EventData(
                    event_type="System",
                    event_action=EventAction.RESOURCE_USAGE,
                    event_timestamp=datetime.now(),
                    severity="Critical",
                    
                    disk_usage=disk_percent,
                    description=f"💿 CRITICAL DISK USAGE: {disk_percent:.1f}% (Critical threshold: {self.disk_critical_threshold}%)",
                    raw_event_data={
                        'event_subtype': 'critical_disk_usage',
                        'disk_percent': disk_percent,
                        'disk_total_gb': metrics.get('disk_total', 0) / (1024**3),
                        'disk_free_gb': metrics.get('disk_free', 0) / (1024**3),
                        'threshold': self.disk_critical_threshold
                    }
                )
                events.append(event)
                self.stats['disk_usage_events'] += 1
                
            elif disk_percent > self.disk_high_threshold:
                event = EventData(
                    event_type="System",
                    event_action=EventAction.RESOURCE_USAGE,
                    event_timestamp=datetime.now(),
                    severity="High",
                    
                    disk_usage=disk_percent,
                    description=f"⚠️ HIGH DISK USAGE: {disk_percent:.1f}% (High threshold: {self.disk_high_threshold}%)",
                    raw_event_data={
                        'event_subtype': 'high_disk_usage',
                        'disk_percent': disk_percent,
                        'threshold': self.disk_high_threshold
                    }
                )
                events.append(event)
                self.stats['disk_usage_events'] += 1
                
        except Exception as e:
            self.logger.error(f"❌ Disk usage events check failed: {e}")
        
        return events
    
    async def _check_process_count_events(self, metrics: Dict) -> List[EventData]:
        """EVENT TYPE 5: Process Count Events"""
        events = []
        try:
            process_count = metrics.get('process_count', 0)
            
            # Alert if process count is unusually high (> 300 processes)
            if process_count > 300:
                event = EventData(
                    event_type="System",
                    event_action=EventAction.RESOURCE_USAGE,
                    event_timestamp=datetime.now(),
                    severity="Medium",
                    
                    description=f"🔢 HIGH PROCESS COUNT: {process_count} processes running",
                    raw_event_data={
                        'event_subtype': 'high_process_count',
                        'process_count': process_count,
                        'threshold': 300,
                        'system_load_indicator': 'high_process_activity'
                    }
                )
                events.append(event)
                self.stats['process_count_events'] += 1
                
        except Exception as e:
            self.logger.error(f"❌ Process count events check failed: {e}")
        
        return events
    
    async def _check_system_health_events(self, metrics: Dict) -> List[EventData]:
        """EVENT TYPE 6: System Health Events"""
        events = []
        try:
            health_score = self._calculate_health_score(metrics)
            
            if health_score < 30:  # Poor system health
                event = EventData(
                    event_type="System",
                    event_action=EventAction.ANOMALY_DETECTED,
                    event_timestamp=datetime.now(),
                    severity="High",
                    
                    description=f"🚨 POOR SYSTEM HEALTH: Health score {health_score}/100",
                    raw_event_data={
                        'event_subtype': 'poor_system_health',
                        'health_score': health_score,
                        'health_factors': {
                            'cpu_factor': 100 - metrics.get('cpu_percent', 0),
                            'memory_factor': 100 - metrics.get('memory_percent', 0),
                            'disk_factor': 100 - metrics.get('disk_percent', 0)
                        }
                    }
                )
                events.append(event)
                self.stats['system_health_events'] += 1
                
        except Exception as e:
            self.logger.error(f"❌ System health events check failed: {e}")
        
        return events
    
    async def _create_system_boot_event(self, metrics: Dict):
        """EVENT TYPE 7: System Boot Event"""
        try:
            uptime = metrics.get('uptime_seconds', 0)
            
            return EventData(
                event_type="System",
                event_action=EventAction.SYSTEM_BOOT,
                event_timestamp=datetime.now(),
                severity="Info",
                
                description=f"🔄 SYSTEM BOOT DETECTED: Uptime {uptime/3600:.1f} hours",
                raw_event_data={
                    'event_subtype': 'system_boot',
                    'boot_time': metrics.get('boot_time'),
                    'uptime_seconds': uptime,
                    'uptime_hours': uptime / 3600,
                    'system_info': {
                        'platform': platform.platform(),
                        'system': platform.system(),
                        'release': platform.release(),
                        'version': platform.version()
                    }
                }
            )
        except Exception as e:
            self.logger.error(f"❌ System boot event failed: {e}")
            return None
    
    async def _check_service_status_events(self) -> List[EventData]:
        """EVENT TYPE 8: Service Status Events"""
        events = []
        try:
            # Simple service check - check if important Windows services are running
            important_services = ['winlogon', 'lsass', 'services', 'svchost']
            
            running_services = []
            for proc in psutil.process_iter(['name']):
                try:
                    if proc.info['name'] and proc.info['name'].lower().replace('.exe', '') in important_services:
                        running_services.append(proc.info['name'])
                except:
                    continue
            
            if len(running_services) > 0:
                event = EventData(
                    event_type="System",
                    event_action=EventAction.ACCESS,
                    event_timestamp=datetime.now(),
                    severity="Info",
                    
                    description=f"🔧 SYSTEM SERVICES: {len(running_services)} critical services running",
                    raw_event_data={
                        'event_subtype': 'service_status_check',
                        'running_services': running_services,
                        'service_count': len(running_services),
                        'service_health': 'healthy' if len(running_services) >= 3 else 'degraded'
                    }
                )
                events.append(event)
                self.stats['service_events'] += 1
                
        except Exception as e:
            self.logger.error(f"❌ Service status events check failed: {e}")
        
        return events
    
    async def _check_temperature_events(self) -> List[EventData]:
        """EVENT TYPE 9: Hardware Temperature Events"""
        events = []
        try:
            # Try to get temperature info (not always available)
            if hasattr(psutil, 'sensors_temperatures'):
                temps = psutil.sensors_temperatures()
                
                for sensor_name, sensor_list in temps.items():
                    for sensor in sensor_list:
                        if sensor.current and sensor.current > 75:  # High temperature
                            event = EventData(
                                event_type="System",
                                event_action=EventAction.RESOURCE_USAGE,
                                event_timestamp=datetime.now(),
                                severity="High" if sensor.current > 85 else "Medium",
                                
                                description=f"🌡️ HIGH TEMPERATURE: {sensor_name} at {sensor.current}°C",
                                raw_event_data={
                                    'event_subtype': 'high_temperature',
                                    'sensor_name': sensor_name,
                                    'temperature_celsius': sensor.current,
                                    'temperature_threshold': 75,
                                    'critical_threshold': 85
                                }
                            )
                            events.append(event)
                            self.stats['hardware_events'] += 1
                            
        except Exception as e:
            self.logger.debug(f"Temperature monitoring not available: {e}")
        
        return events
    
    async def _check_system_load_events(self, metrics: Dict) -> List[EventData]:
        """EVENT TYPE 10: System Load Events"""
        events = []
        try:
            load_avg = metrics.get('load_average')
            if load_avg and len(load_avg) >= 1:
                load_1min = load_avg[0]
                cpu_count = metrics.get('cpu_count', 1)
                
                # Load average per CPU core
                load_per_core = load_1min / cpu_count
                
                if load_per_core > 2.0:  # High load (> 2.0 per core)
                    event = EventData(
                        event_type="System",
                        event_action=EventAction.SYSTEM_LOAD,
                        event_timestamp=datetime.now(),
                        severity="High" if load_per_core > 3.0 else "Medium",
                        
                        description=f"📈 HIGH SYSTEM LOAD: {load_1min:.2f} load average ({load_per_core:.2f} per core)",
                        raw_event_data={
                            'event_subtype': 'high_system_load',
                            'load_average_1min': load_1min,
                            'load_average_5min': load_avg[1] if len(load_avg) > 1 else None,
                            'load_average_15min': load_avg[2] if len(load_avg) > 2 else None,
                            'load_per_core': load_per_core,
                            'cpu_count': cpu_count
                        }
                    )
                    events.append(event)
                    
        except Exception as e:
            self.logger.debug(f"Load average monitoring not available: {e}")
        
        return events
    
    def _update_system_history(self, metrics: Dict):
        """Update system metrics history"""
        try:
            self.cpu_history.append(metrics.get('cpu_percent', 0))
            self.memory_history.append(metrics.get('memory_percent', 0))
            self.disk_history.append(metrics.get('disk_percent', 0))
            self.process_count_history.append(metrics.get('process_count', 0))
        except Exception as e:
            self.logger.error(f"❌ History update failed: {e}")
    
    def _calculate_system_severity(self, metrics: Dict) -> str:
        """Calculate overall system severity"""
        try:
            cpu = metrics.get('cpu_percent', 0)
            memory = metrics.get('memory_percent', 0)
            disk = metrics.get('disk_percent', 0)
            
            if cpu > 90 or memory > 90 or disk > 95:
                return "Critical"
            elif cpu > 75 or memory > 80 or disk > 85:
                return "High"
            elif cpu > 60 or memory > 65 or disk > 70:
                return "Medium"
            else:
                return "Info"
        except Exception:
            return "Info"
    
    def _calculate_health_score(self, metrics: Dict) -> int:
        """Calculate system health score (0-100)"""
        try:
            cpu_score = max(0, 100 - metrics.get('cpu_percent', 0))
            memory_score = max(0, 100 - metrics.get('memory_percent', 0))
            disk_score = max(0, 100 - metrics.get('disk_percent', 0))
            
            # Weighted average
            health_score = int((cpu_score * 0.4 + memory_score * 0.4 + disk_score * 0.2))
            return max(0, min(100, health_score))
        except Exception:
            return 50  # Default neutral score
    
    def get_stats(self) -> Dict:
        """Get detailed statistics for multiple system event types"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'System_MultipleEvents',
            'cpu_usage_events': self.stats['cpu_usage_events'],
            'memory_usage_events': self.stats['memory_usage_events'],
            'disk_usage_events': self.stats['disk_usage_events'],
            'process_count_events': self.stats['process_count_events'],
            'system_performance_events': self.stats['system_performance_events'],
            'system_health_events': self.stats['system_health_events'],
            'boot_events': self.stats['boot_events'],
            'service_events': self.stats['service_events'],
            'hardware_events': self.stats['hardware_events'],
            'total_system_events': self.stats['total_system_events'],
            'history_length': len(self.cpu_history),
            'current_health_score': self._calculate_health_score(self._get_current_metrics_summary()),
            'multiple_event_types': True,
            'system_event_types_generated': [
                'system_resource_usage', 'critical_cpu_usage', 'high_cpu_usage',
                'critical_memory_usage', 'high_memory_usage', 'critical_disk_usage',
                'high_disk_usage', 'high_process_count', 'poor_system_health',
                'system_boot', 'service_status_check', 'high_temperature', 'high_system_load'
            ]
        })
        return base_stats
    
    def _get_current_metrics_summary(self) -> Dict:
        """Get current metrics summary for health calculation"""
        try:
            if self.cpu_history and self.memory_history and self.disk_history:
                return {
                    'cpu_percent': self.cpu_history[-1],
                    'memory_percent': self.memory_history[-1],
                    'disk_percent': self.disk_history[-1]
                }
        except:
            pass
        return {'cpu_percent': 0, 'memory_percent': 0, 'disk_percent': 0}