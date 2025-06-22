# agent/collectors/system_collector.py - FIXED IMPORTS
from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventType, EventAction, Severity  # FIXED: Added missing imports
import psutil
from datetime import datetime
import asyncio
import json
import time
import platform
from typing import List, Dict, Any, Optional

class SystemCollector(BaseCollector):
    """Enhanced System Resource Collector - FIXED IMPORTS"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "SystemCollector")
        
        # Enhanced configuration
        self.polling_interval = 3
        self.monitor_cpu_threshold = 80
        self.monitor_memory_threshold = 85
        self.monitor_disk_threshold = 90
        
        # System tracking
        self.last_cpu_usage = 0
        self.last_memory_usage = 0
        self.last_disk_usage = 0
        self.system_alerts = []
        
        # Enhanced monitoring
        self.monitor_cpu_spikes = True
        self.monitor_memory_leaks = True
        self.monitor_disk_activity = True
        self.monitor_network_usage = True
        self.monitor_system_events = True
        
        # Performance tracking
        self.cpu_history = []
        self.memory_history = []
        self.disk_history = []
        self.network_history = []
        
        # Alert thresholds
        self.cpu_spike_threshold = 20
        self.memory_leak_threshold = 10
        self.disk_io_threshold = 1000
        
        self.logger.info("🖥️ Enhanced System Collector initialized")
    
    async def _collect_data(self):
        """Implement abstract method from BaseCollector - collect system data"""
        try:
            events = await self.collect_data()
            return events
        except Exception as e:
            self.logger.error(f"❌ System data collection failed: {e}")
            return []
    
    async def initialize(self):
        """Initialize system collector with enhanced monitoring"""
        try:
            await super().initialize()
            await self._get_initial_system_state()
            self._setup_system_monitoring()
            self.logger.info("✅ Enhanced System Collector initialized")
        except Exception as e:
            self.logger.error(f"❌ System collector initialization failed: {e}")
            raise
    
    def _setup_system_monitoring(self):
        """Set up enhanced system monitoring"""
        try:
            self._setup_system_callbacks()
            self._initialize_performance_tracking()
        except Exception as e:
            self.logger.error(f"System monitoring setup failed: {e}")
    
    def _setup_system_callbacks(self):
        """Set up system event callbacks for real-time monitoring"""
        try:
            pass
        except Exception as e:
            self.logger.debug(f"System callbacks setup failed: {e}")
    
    def _initialize_performance_tracking(self):
        """Initialize performance tracking arrays"""
        try:
            current_cpu = psutil.cpu_percent(interval=1)
            current_memory = psutil.virtual_memory().percent
            current_disk = psutil.disk_usage('/').percent
            
            self.cpu_history = [current_cpu] * 20
            self.memory_history = [current_memory] * 20
            self.disk_history = [current_disk] * 20
            
        except Exception as e:
            self.logger.error(f"Performance tracking initialization failed: {e}")
    
    async def collect_data(self) -> List[EventData]:
        """Collect system data with enhanced monitoring"""
        try:
            events = []
            
            cpu_events = await self._collect_cpu_data()
            events.extend(cpu_events)
            
            memory_events = await self._collect_memory_data()
            events.extend(memory_events)
            
            disk_events = await self._collect_disk_data()
            events.extend(disk_events)
            
            network_events = await self._collect_network_data()
            events.extend(network_events)
            
            system_events = await self._monitor_system_events()
            events.extend(system_events)
            
            anomaly_events = await self._detect_anomalies()
            events.extend(anomaly_events)
            
            if events:
                self.logger.debug(f"📊 Collected {len(events)} system events")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ System data collection failed: {e}")
            return []
    
    async def _get_initial_system_state(self):
        """Get initial system state for baseline"""
        try:
            self.last_cpu_usage = psutil.cpu_percent(interval=1)
            self.last_memory_usage = psutil.virtual_memory().percent
            self.last_disk_usage = psutil.disk_usage('/').percent
            
            self.logger.info(f"📋 Initial system state - CPU: {self.last_cpu_usage}%, "
                           f"Memory: {self.last_memory_usage}%, Disk: {self.last_disk_usage}%")
            
        except Exception as e:
            self.logger.error(f"Initial system state failed: {e}")

    async def _collect_cpu_data(self) -> List[EventData]:
        """Collect CPU usage data"""
        try:
            events = []
            current_cpu = psutil.cpu_percent(interval=1)
            
            self.cpu_history.append(current_cpu)
            if len(self.cpu_history) > 20:
                self.cpu_history.pop(0)
            
            if current_cpu > self.monitor_cpu_threshold:
                event = self._create_system_event(
                    action=EventAction.RESOURCE_USAGE,
                    resource_type='CPU',
                    current_value=current_cpu,
                    threshold=self.monitor_cpu_threshold,
                    severity=Severity.HIGH,
                    additional_data={
                        'cpu_percent': current_cpu,
                        'cpu_count': psutil.cpu_count(),
                        'cpu_freq': psutil.cpu_freq().current if psutil.cpu_freq() else 0
                    }
                )
                if event:
                    events.append(event)
                    self.logger.warning(f"🚨 High CPU usage detected: {current_cpu}%")
            
            if self.monitor_cpu_spikes and len(self.cpu_history) >= 2:
                cpu_change = current_cpu - self.cpu_history[-2]
                if cpu_change > self.cpu_spike_threshold:
                    event = self._create_system_event(
                        action=EventAction.CPU_SPIKE,
                        resource_type='CPU',
                        current_value=current_cpu,
                        threshold=self.cpu_spike_threshold,
                        severity=Severity.MEDIUM,
                        additional_data={
                            'cpu_change': cpu_change,
                            'cpu_history': self.cpu_history[-5:]
                        }
                    )
                    if event:
                        events.append(event)
                        self.logger.warning(f"⚠️ CPU spike detected: +{cpu_change}%")
            
            self.last_cpu_usage = current_cpu
            return events
            
        except Exception as e:
            self.logger.error(f"CPU data collection failed: {e}")
            return []
    
    async def _collect_memory_data(self) -> List[EventData]:
        """Collect memory usage data"""
        try:
            events = []
            memory = psutil.virtual_memory()
            current_memory = memory.percent
            
            self.memory_history.append(current_memory)
            if len(self.memory_history) > 20:
                self.memory_history.pop(0)
            
            if current_memory > self.monitor_memory_threshold:
                event = self._create_system_event(
                    action=EventAction.RESOURCE_USAGE,
                    resource_type='Memory',
                    current_value=current_memory,
                    threshold=self.monitor_memory_threshold,
                    severity=Severity.HIGH,
                    additional_data={
                        'memory_percent': current_memory,
                        'memory_total': memory.total,
                        'memory_available': memory.available,
                        'memory_used': memory.used
                    }
                )
                if event:
                    events.append(event)
                    self.logger.warning(f"🚨 High memory usage detected: {current_memory}%")
            
            if self.monitor_memory_leaks and len(self.memory_history) >= 10:
                recent_avg = sum(self.memory_history[-10:]) / 10
                older_avg = sum(self.memory_history[-20:-10]) / 10
                memory_increase = recent_avg - older_avg
                
                if memory_increase > self.memory_leak_threshold:
                    event = self._create_system_event(
                        action=EventAction.MEMORY_LEAK,
                        resource_type='Memory',
                        current_value=current_memory,
                        threshold=self.memory_leak_threshold,
                        severity=Severity.MEDIUM,
                        additional_data={
                            'memory_increase': memory_increase,
                            'memory_history': self.memory_history[-10:]
                        }
                    )
                    if event:
                        events.append(event)
                        self.logger.warning(f"⚠️ Potential memory leak detected: +{memory_increase}%")
            
            self.last_memory_usage = current_memory
            return events
            
        except Exception as e:
            self.logger.error(f"Memory data collection failed: {e}")
            return []
    
    async def _collect_disk_data(self) -> List[EventData]:
        """Collect disk usage data"""
        try:
            events = []
            disk = psutil.disk_usage('/')
            current_disk = disk.percent
            
            self.disk_history.append(current_disk)
            if len(self.disk_history) > 20:
                self.disk_history.pop(0)
            
            if current_disk > self.monitor_disk_threshold:
                event = self._create_system_event(
                    action=EventAction.RESOURCE_USAGE,
                    resource_type='Disk',
                    current_value=current_disk,
                    threshold=self.monitor_disk_threshold,
                    severity=Severity.HIGH,
                    additional_data={
                        'disk_percent': current_disk,
                        'disk_total': disk.total,
                        'disk_used': disk.used,
                        'disk_free': disk.free
                    }
                )
                if event:
                    events.append(event)
                    self.logger.warning(f"🚨 High disk usage detected: {current_disk}%")
            
            if self.monitor_disk_activity:
                disk_io = psutil.disk_io_counters()
                if disk_io:
                    total_io = (disk_io.read_bytes + disk_io.write_bytes) / (1024 * 1024)
                    
                    if total_io > self.disk_io_threshold:
                        event = self._create_system_event(
                            action=EventAction.DISK_IO_HIGH,
                            resource_type='Disk',
                            current_value=total_io,
                            threshold=self.disk_io_threshold,
                            severity=Severity.MEDIUM,
                            additional_data={
                                'disk_io_mb': total_io,
                                'read_bytes': disk_io.read_bytes,
                                'write_bytes': disk_io.write_bytes,
                                'read_count': disk_io.read_count,
                                'write_count': disk_io.write_count
                            }
                        )
                        if event:
                            events.append(event)
                            self.logger.warning(f"⚠️ High disk I/O detected: {total_io:.2f} MB")
            
            self.last_disk_usage = current_disk
            return events

        except Exception as e:
            self.logger.error(f"Disk data collection failed: {e}")
            return []
    
    async def _collect_network_data(self) -> List[EventData]:
        """Collect network usage data"""
        try:
            events = []
            net_io = psutil.net_io_counters()
            
            bytes_sent = net_io.bytes_sent
            bytes_recv = net_io.bytes_recv
            total_network = (bytes_sent + bytes_recv) / (1024 * 1024)
            
            self.network_history.append(total_network)
            if len(self.network_history) > 20:
                self.network_history.pop(0)
            
            if total_network > 100:
                event = self._create_system_event(
                    action=EventAction.NETWORK_USAGE,
                    resource_type='Network',
                    current_value=total_network,
                    threshold=100,
                    severity=Severity.MEDIUM,
                    additional_data={
                        'network_mb': total_network,
                        'bytes_sent': bytes_sent,
                        'bytes_recv': bytes_recv,
                        'packets_sent': net_io.packets_sent,
                        'packets_recv': net_io.packets_recv
                    }
                )
                if event:
                    events.append(event)
                    self.logger.warning(f"⚠️ High network usage detected: {total_network:.2f} MB")
            
            return events
            
        except Exception as e:
            self.logger.error(f"Network data collection failed: {e}")
            return []
    
    async def _monitor_system_events(self) -> List[EventData]:
        """Monitor system events"""
        try:
            events = []
            
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            
            if uptime.total_seconds() < 300:
                event = self._create_system_event(
                    action=EventAction.SYSTEM_BOOT,
                    resource_type='System',
                    current_value=uptime.total_seconds(),
                    threshold=300,
                    severity=Severity.MEDIUM,
                    additional_data={
                        'boot_time': boot_time.isoformat(),
                        'uptime_seconds': uptime.total_seconds(),
                        'system_info': {
                            'platform': platform.platform(),
                            'system': platform.system(),
                            'release': platform.release(),
                            'version': platform.version()
                        }
                    }
                )
                if event:
                    events.append(event)
                    self.logger.info(f"🔄 System boot detected - Uptime: {uptime}")
            
            if hasattr(psutil, 'getloadavg'):
                try:
                    load_avg = psutil.getloadavg()
                    if load_avg[0] > 5.0:
                        event = self._create_system_event(
                            action=EventAction.SYSTEM_LOAD,
                            resource_type='System',
                            current_value=load_avg[0],
                            threshold=5.0,
                            severity=Severity.MEDIUM,
                            additional_data={
                                'load_average_1min': load_avg[0],
                                'load_average_5min': load_avg[1],
                                'load_average_15min': load_avg[2]
                            }
                        )
                        if event:
                            events.append(event)
                            self.logger.warning(f"⚠️ High system load detected: {load_avg[0]}")
                except:
                    pass
            
            return events
            
        except Exception as e:
            self.logger.error(f"System events monitoring failed: {e}")
            return []
    
    async def _detect_anomalies(self) -> List[EventData]:
        """Detect system anomalies"""
        try:
            events = []
            
            if len(self.cpu_history) >= 10:
                cpu_variance = self._calculate_variance(self.cpu_history[-10:])
                if cpu_variance > 50:
                    event = self._create_system_event(
                        action=EventAction.ANOMALY_DETECTED,
                        resource_type='CPU',
                        current_value=cpu_variance,
                        threshold=50,
                        severity=Severity.HIGH,
                        additional_data={
                            'anomaly_type': 'cpu_variance',
                            'cpu_variance': cpu_variance,
                            'cpu_history': self.cpu_history[-10:]
                        }
                    )
                    if event:
                        events.append(event)
                        self.logger.warning(f"🚨 CPU anomaly detected - Variance: {cpu_variance}")
            
            if len(self.memory_history) >= 10:
                memory_variance = self._calculate_variance(self.memory_history[-10:])
                if memory_variance > 30:
                    event = self._create_system_event(
                        action=EventAction.ANOMALY_DETECTED,
                        resource_type='Memory',
                        current_value=memory_variance,
                        threshold=30,
                        severity=Severity.HIGH,
                        additional_data={
                            'anomaly_type': 'memory_variance',
                            'memory_variance': memory_variance,
                            'memory_history': self.memory_history[-10:]
                        }
                    )
                    if event:
                        events.append(event)
                        self.logger.warning(f"🚨 Memory anomaly detected - Variance: {memory_variance}")
            
            return events
            
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
            return []
    
    def _calculate_variance(self, values: List[float]) -> float:
        """Calculate variance of a list of values"""
        try:
            if not values:
                return 0
            
            mean = sum(values) / len(values)
            variance = sum((x - mean) ** 2 for x in values) / len(values)
            return variance
            
        except Exception:
            return 0
    
    def _create_system_event(self, action: EventAction, resource_type: str, current_value: float,
                           threshold: float, severity: Severity, additional_data: Dict = None) -> EventData:
        """Create system event data - FIXED"""
        try:
            return EventData(
                event_type=EventType.SYSTEM,  # FIXED: Now imports work
                event_action=action,
                event_timestamp=datetime.now(),
                severity=severity,
                raw_event_data={
                    'resource_type': resource_type,
                    'current_value': current_value,
                    'threshold': threshold,
                    'system_info': {
                        'platform': platform.platform(),
                        'system': platform.system(),
                        'release': platform.release(),
                        'version': platform.version(),
                        'machine': platform.machine(),
                        'processor': platform.processor()
                    },
                    **(additional_data or {})
                }
            )
            
        except Exception as e:
            self.logger.error(f"System event creation failed: {e}")
            return None