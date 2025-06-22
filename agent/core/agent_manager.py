# agent/core/agent_manager.py
"""
Agent Manager - Core agent management and coordination
Fixed to disable pending alerts until server endpoints are ready
"""

import asyncio
import logging
import time
import uuid
import platform
import psutil
from datetime import datetime
from typing import Optional, Dict, List, Any
from pathlib import Path

from agent.core.communication import ServerCommunication
from agent.core.config_manager import ConfigManager
from agent.core.event_processor import EventProcessor
from agent.collectors.process_collector import ProcessCollector
from agent.collectors.file_collector import FileCollector
from agent.collectors.network_collector import NetworkCollector
from agent.collectors.registry_collector import RegistryCollector
from agent.collectors.authentication_collector import AuthenticationCollector
from agent.collectors.system_collector import SystemCollector
from agent.schemas.agent_data import AgentRegistrationData, AgentHeartbeatData

class AgentManager:
    """Main agent management class"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        # Core components
        self.communication: Optional[ServerCommunication] = None
        self.event_processor: Optional[EventProcessor] = None
        
        # Data collectors
        self.collectors: Dict[str, Any] = {}
        
        # Agent state
        self.agent_id: Optional[str] = None
        self.is_registered = False
        self.is_monitoring = False
        self.last_heartbeat = None
        self.start_time = datetime.now()
        
        # Configuration
        self.config = self.config_manager.get_config()
        
        # Alert system settings
        self.alert_endpoints_available = False  # FIXED: Track server endpoint availability
        
    async def initialize(self):
        """Initialize agent manager and components"""
        try:
            self.logger.info("Agent manager initialized")
            
            # Initialize server communication
            self.communication = ServerCommunication(self.config_manager)
            await self.communication.initialize()
            
            # Initialize event processor
            self.event_processor = EventProcessor(self.config_manager, self.communication)
            
            # Initialize collectors
            await self._initialize_collectors()
            
            self.logger.info("Agent manager initialized")
            
        except Exception as e:
            self.logger.error(f"Agent manager initialization failed: {e}")
            raise Exception(f"Initialization failed: {e}")
    
    async def _initialize_collectors(self):
        """Initialize data collectors"""
        try:
            config = self.config_manager.get_config()
            collection_config = config.get('collection', {})
            
            # Process collector
            if collection_config.get('collect_processes', True):
                self.collectors['process'] = ProcessCollector(self.config_manager)
                await self.collectors['process'].initialize()
                self.logger.info("Process collector initialized")
            
            # File collector
            if collection_config.get('collect_files', True):
                self.collectors['file'] = FileCollector(self.config_manager)
                await self.collectors['file'].initialize()
                self.logger.info("File collector initialized")
            
            # Network collector
            if collection_config.get('collect_network', True):
                self.collectors['network'] = NetworkCollector(self.config_manager)
                await self.collectors['network'].initialize()
                self.logger.info("Network collector initialized")
            
            # Registry collector (Windows only)
            if (collection_config.get('collect_registry', True) and 
                platform.system().lower() == 'windows'):
                self.collectors['registry'] = RegistryCollector(self.config_manager)
                await self.collectors['registry'].initialize()
                self.logger.info("Registry collector initialized")
            
            # Authentication collector - FIXED: Optimized
            if collection_config.get('collect_authentication', True):
                self.collectors['authentication'] = AuthenticationCollector(self.config_manager)
                await self.collectors['authentication'].initialize()
                # FIXED: Increase polling interval for slow collectors
                self.collectors['authentication'].polling_interval = 15  # Increase from 5 to 15 seconds
                self.logger.info("Authentication collector initialized (optimized)")
            
            # System collector - FIXED: Optimized
            self.collectors['system'] = SystemCollector(self.config_manager)
            await self.collectors['system'].initialize()
            # FIXED: Increase polling interval for slow collectors
            self.collectors['system'].polling_interval = 15  # Increase from 5 to 15 seconds
            self.logger.info("System collector initialized (optimized)")
            
            self.logger.info(f"{len(self.collectors)} collectors initialized")
            
        except Exception as e:
            self.logger.error(f"Collector initialization failed: {e}")
            raise
    
    async def start(self):
        """Start the agent"""
        try:
            self.logger.info("Starting agent...")
            
            # Register with server
            await self._register_with_server()
            
            # Check if alert endpoints are available
            await self._check_alert_endpoints_availability()
            
            # Start event processor
            await self.event_processor.start()
            
            # Gán event_processor cho từng collector trước khi start
            for collector in self.collectors.values():
                collector.set_event_processor(self.event_processor)
            
            # Start collectors
            await self._start_collectors()
            
            # Start monitoring
            self.is_monitoring = True
            
            # Start heartbeat task
            asyncio.create_task(self._heartbeat_loop())
            
            self.logger.info(f"[START] Using AgentID: {self.agent_id}")
            if self.event_processor:
                self.event_processor.set_agent_id(self.agent_id)
                self.logger.info(f"[EVENT_PROCESSOR] Set AgentID: {self.agent_id}")
            
            self.logger.info("Agent started successfully")
            
        except Exception as e:
            self.logger.error(f"Agent start failed: {e}")
            raise
    
    async def stop(self):
        """Stop the agent gracefully"""
        try:
            self.logger.info("Stopping agent...")
            self.is_monitoring = False
            
            # Stop collectors
            await self._stop_collectors()
            
            # Stop event processor
            if self.event_processor:
                await self.event_processor.stop()
            
            # Send final heartbeat
            if self.is_registered:
                await self._send_heartbeat(status='Offline')
            
            self.logger.info("Agent stopped")
            
        except Exception as e:
            self.logger.error(f"Agent stop error: {e}")
    
    async def _register_with_server(self):
        """Register agent with EDR server"""
        try:
            self.logger.info("Registering with EDR server...")
            
            # Get system information
            system_info = self._get_system_info()
            
            # Create registration data
            registration_data = AgentRegistrationData(
                hostname=system_info['hostname'],
                ip_address=system_info['ip_address'],
                operating_system=system_info['operating_system'],
                os_version=system_info['os_version'],
                architecture=system_info['architecture'],
                agent_version=self.config.get('agent', {}).get('version', '1.0.0'),
                mac_address=system_info.get('mac_address'),
                domain=system_info.get('domain'),
                install_path=str(Path(__file__).resolve().parent.parent.parent)
            )
            
            # Send registration request
            response = await self.communication.register_agent(registration_data)
            
            if response and response.get('success'):
                self.agent_id = response.get('agent_id')
                self.is_registered = True
                self.logger.info(f"Agent registered: {self.agent_id}")
                
                # Update configuration with server settings
                if 'heartbeat_interval' in response:
                    self.config['agent']['heartbeat_interval'] = response['heartbeat_interval']
                
                self.logger.info(f"[REGISTER] Hostname: {system_info['hostname']} | AgentID: {self.agent_id}")
                
            else:
                raise Exception("Registration failed")
                
        except Exception as e:
            self.logger.error(f"Registration failed: {e}")
            raise
    
    async def _check_alert_endpoints_availability(self):
        """Check if server has alert endpoints available - FIXED: New method"""
        try:
            if not self.agent_id or not self.communication:
                return
            
            # Try to call pending alerts endpoint to test availability
            test_response = await self.communication.get_pending_alerts(self.agent_id)
            
            if test_response is not None:
                self.alert_endpoints_available = True
                self.logger.info("Alert endpoints available on server")
            else:
                self.alert_endpoints_available = False
                self.logger.info("Alert endpoints not available on server (will be disabled)")
                
        except Exception as e:
            self.alert_endpoints_available = False
            self.logger.info("Alert endpoints not available on server (will be disabled)")
            self.logger.debug(f"Alert endpoint test failed: {e}")
    
    def _get_system_info(self) -> Dict[str, str]:
        """Get system information for registration"""
        try:
            import socket
            import getpass
            import platform
            import uuid
            import os

            # Get hostname (tên máy thật)
            hostname = socket.gethostname()

            # Get IP address (ưu tiên IP thật, fallback 127.0.0.1)
            try:
                server_host = self.config.get('server', {}).get('host', '8.8.8.8')
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((server_host, 80))
                ip_address = s.getsockname()[0]
                s.close()
            except:
                ip_address = '127.0.0.1'

            # Get MAC address
            try:
                mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
                mac_address = ':'.join([mac[i:i+2] for i in range(0, 12, 2)])
            except:
                mac_address = None

            # Get domain (Windows)
            try:
                domain = os.environ.get('USERDOMAIN') if platform.system().lower() == 'windows' else None
            except:
                domain = None

            # Get username
            try:
                username = getpass.getuser()
            except:
                username = None

            return {
                'hostname': hostname,
                'ip_address': ip_address,
                'operating_system': f"{platform.system()} {platform.release()}",
                'os_version': platform.version(),
                'architecture': platform.machine(),
                'mac_address': mac_address,
                'domain': domain,
                'username': username
            }
        except Exception as e:
            self.logger.error(f"Error getting system info: {e}")
            return {
                'hostname': 'unknown',
                'ip_address': '127.0.0.1',
                'operating_system': 'Unknown',
                'os_version': 'Unknown',
                'architecture': 'Unknown'
            }
    
    async def _start_collectors(self):
        """Start all data collectors"""
        try:
            for name, collector in self.collectors.items():
                await collector.start()
                self.logger.info(f"✅ Started {name} collector")
                
        except Exception as e:
            self.logger.error(f"❌ Failed to start collectors: {e}")
            raise
    
    async def _stop_collectors(self):
        """Stop all data collectors"""
        try:
            for name, collector in self.collectors.items():
                await collector.stop()
                self.logger.info(f"🛑 Stopped {name} collector")
                
        except Exception as e:
            self.logger.error(f"❌ Failed to stop collectors: {e}")
    
    async def _heartbeat_loop(self):
        """Heartbeat loop with conditional alert checking - FIXED"""
        while self.is_monitoring and self.is_registered:
            try:
                # Send heartbeat
                await self._send_heartbeat()
                
                # FIXED: Only check for pending alerts if endpoints are available
                if self.alert_endpoints_available:
                    await self._check_pending_alerts()
                else:
                    # Log debug message every 10 heartbeats to avoid spam
                    if hasattr(self, '_heartbeat_count'):
                        self._heartbeat_count += 1
                    else:
                        self._heartbeat_count = 1
                    
                    if self._heartbeat_count % 10 == 0:
                        self.logger.debug("📋 Alert endpoints not available, skipping alert check")
                
                # Wait for next heartbeat
                await asyncio.sleep(self.config.get('agent', {}).get('heartbeat_interval', 30))
                
            except Exception as e:
                self.logger.error(f"❌ Heartbeat loop error: {e}")
                await asyncio.sleep(10)  # Wait before retry

    async def _check_pending_alerts(self):
        """Check for pending alerts from server - FIXED: Enhanced error handling"""
        try:
            if not self.agent_id or not self.communication:
                return
            
            if not self.alert_endpoints_available:
                return
            
            # Get pending alerts
            response = await self.communication.get_pending_alerts(self.agent_id)
            
            if response and response.get('pending_alerts'):
                alerts = response['pending_alerts']
                self.logger.warning(f"🚨 Processing {len(alerts)} pending alerts from server")
                
                # Process each alert
                for alert_data in alerts:
                    try:
                        notification_data = alert_data.get('notification_data', {})
                        if notification_data:
                            # Send to security notifier for display
                            if hasattr(self, 'event_processor') and self.event_processor:
                                self.event_processor.security_notifier.process_server_alerts(
                                    {'alerts_generated': [notification_data]}, 
                                    []
                                )
                    except Exception as e:
                        self.logger.error(f"Failed to process alert: {e}")
                        
        except Exception as e:
            # FIXED: Don't log error for missing endpoints - disable endpoints
            if "Server endpoint not found" in str(e) or "404" in str(e):
                if self.alert_endpoints_available:
                    self.alert_endpoints_available = False
                    self.logger.info("⚠️ Alert endpoints no longer available, disabling alert checks")
            else:
                self.logger.debug(f"Alert check failed: {e}")
    
    async def _send_heartbeat(self, status: str = 'Active'):
        """Send heartbeat to server"""
        try:
            if not self.is_registered:
                return
            
            # Get current performance metrics
            performance_data = self._get_performance_metrics()
            
            # Create heartbeat data
            heartbeat_data = AgentHeartbeatData(
                hostname=platform.node(),
                status=status,
                cpu_usage=performance_data['cpu_usage'],
                memory_usage=performance_data['memory_usage'],
                disk_usage=performance_data['disk_usage'],
                network_latency=performance_data['network_latency']
            )
            
            # Send heartbeat
            response = await self.communication.send_heartbeat(heartbeat_data)
            
            if response and response.get('success'):
                self.last_heartbeat = datetime.now()
                self.logger.debug("💓 Heartbeat sent successfully")
            else:
                self.logger.warning("⚠️ Heartbeat failed")
                
        except Exception as e:
            self.logger.error(f"❌ Heartbeat send error: {e}")
    
    def _get_performance_metrics(self) -> Dict[str, float]:
        """Get current system performance metrics - FIXED: Optimized"""
        try:
            # FIXED: Use cached values to improve performance
            current_time = time.time()
            
            if (not hasattr(self, '_last_metrics_time') or 
                current_time - self._last_metrics_time > 30):  # Cache for 30 seconds
                
                # CPU usage with minimal interval
                self._cached_cpu = psutil.cpu_percent(interval=0.1)  # FIXED: Reduce from 1s to 0.1s
                
                # Memory usage
                memory = psutil.virtual_memory()
                self._cached_memory = memory.percent
                
                # Disk usage
                disk = psutil.disk_usage('/')
                self._cached_disk = disk.percent
                
                # Network latency (simple simulation)
                self._cached_latency = 0
                try:
                    start_time = time.time()
                    # This is a placeholder - in real implementation, ping the server
                    self._cached_latency = int((time.time() - start_time) * 1000)
                except:
                    self._cached_latency = 0
                
                self._last_metrics_time = current_time
            
            return {
                'cpu_usage': getattr(self, '_cached_cpu', 0.0),
                'memory_usage': getattr(self, '_cached_memory', 0.0),
                'disk_usage': getattr(self, '_cached_disk', 0.0),
                'network_latency': getattr(self, '_cached_latency', 0)
            }
            
        except Exception as e:
            self.logger.error(f"Error getting performance metrics: {e}")
            return {
                'cpu_usage': 0.0,
                'memory_usage': 0.0,
                'disk_usage': 0.0,
                'network_latency': 0
            }
    
    async def health_check(self):
        """Perform health check"""
        try:
            health_status = {
                'agent_id': self.agent_id,
                'is_registered': self.is_registered,
                'is_monitoring': self.is_monitoring,
                'last_heartbeat': self.last_heartbeat.isoformat() if self.last_heartbeat else None,
                'uptime': (datetime.now() - self.start_time).total_seconds(),
                'collectors_running': len([c for c in self.collectors.values() if c.is_running]),
                'total_collectors': len(self.collectors),
                'alert_endpoints_available': self.alert_endpoints_available  # FIXED: Add status
            }
            
            self.logger.debug(f"💊 Health check: {health_status}")
            return health_status
            
        except Exception as e:
            self.logger.error(f"❌ Health check error: {e}")
            return {'healthy': False, 'error': str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """Get current agent status"""
        return {
            'agent_id': self.agent_id,
            'is_registered': self.is_registered,
            'is_monitoring': self.is_monitoring,
            'last_heartbeat': self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            'start_time': self.start_time.isoformat(),
            'collectors': {name: collector.is_running for name, collector in self.collectors.items()},
            'performance': self._get_performance_metrics(),
            'alert_endpoints_available': self.alert_endpoints_available  # FIXED: Add status
        }