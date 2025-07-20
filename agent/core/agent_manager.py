# agent/core/agent_manager.py - ENHANCED FOR MALWARE DETECTION
"""
Enhanced Agent Manager - Tích hợp phát hiện mã độc nâng cao
Quản lý các collector nâng cao để phát hiện reverse shell và mã độc
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
import os

from agent.core.communication import ServerCommunication
from agent.core.config_manager import ConfigManager
from agent.core.event_processor import EventProcessor
from agent.core.alert_polling_service import AlertPollingService

# ENHANCED: Import enhanced collectors for malware detection
from agent.collectors.process_collector import EnhancedProcessCollector
from agent.collectors.file_collector import EnhancedFileCollector
from agent.collectors.network_collector import EnhancedNetworkCollector
from agent.collectors.registry_collector import EnhancedRegistryCollector
from agent.collectors.authentication_collector import AuthenticationCollector
from agent.collectors.system_collector import SystemCollector
from agent.schemas.agent_data import AgentRegistrationData, AgentHeartbeatData

class EnhancedAgentManager:
    """Enhanced Agent Manager - Tích hợp phát hiện mã độc nâng cao"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.get_config()
        self.logger = logging.getLogger(__name__)
        
        # Agent state
        self.is_initialized = False
        self.is_running = False
        self.is_monitoring = False
        self.is_paused = False
        
        # Agent identification
        self.agent_id_file = os.path.join(os.path.dirname(__file__), 'agent_id.txt')
        self.agent_id = self._load_agent_id()
        self.is_registered = False
        
        # Communication and processing
        self.communication = None
        self.event_processor = None
        self.alert_polling_service = None
        
        # Enhanced data collectors for malware detection
        self.collectors = {}
        self.malware_detection_enabled = True
        
        # Performance tracking
        self.start_time = None
        self.last_heartbeat = None
        
        # ENHANCED: Malware detection statistics
        self.malware_stats = {
            'total_processes_analyzed': 0,
            'suspicious_processes_detected': 0,
            'reverse_shell_connections_detected': 0,
            'c2_communications_detected': 0,
            'malicious_ips_detected': 0,
            'total_malware_events': 0,
            'last_malware_detection': None
        }
        
        self.logger.info("Enhanced Agent Manager initialized - MALWARE DETECTION ENABLED")
    
    async def initialize(self):
        """Initialize enhanced agent manager with malware detection"""
        try:
            self.logger.info("🔧 Starting Enhanced Agent Manager initialization...")
            self.logger.info("🚨 MALWARE DETECTION MODE ENABLED")
            self.logger.info("   - Reverse Shell Detection: ACTIVE")
            self.logger.info("   - C2 Communication Detection: ACTIVE") 
            self.logger.info("   - Malicious IP Detection: ACTIVE")
            self.logger.info("   - Process Analysis: ENHANCED")
            self.logger.info("   - Network Analysis: ENHANCED")
            
            # Initialize server communication
            try:
                self.logger.info("📡 Initializing enhanced server communication...")
                self.communication = ServerCommunication(self.config_manager)
                await self.communication.initialize()
                self.logger.info("✅ Enhanced server communication initialized")
            except Exception as e:
                self.logger.error(f"❌ Server communication initialization failed: {e}")
                raise Exception(f"Server communication failed: {e}")
            
            # Initialize event processor
            try:
                self.logger.info("⚙️ Initializing enhanced event processor...")
                self.event_processor = EventProcessor(self.config_manager, self.communication)
                self.logger.info("✅ Enhanced event processor initialized")
            except Exception as e:
                self.logger.error(f"❌ Event processor initialization failed: {e}")
                raise Exception(f"Event processor failed: {e}")
            
            # Initialize alert polling service
            try:
                self.logger.info("📡 Initializing enhanced alert polling service...")
                self.alert_polling_service = AlertPollingService(self.communication, self.config_manager)
                self.logger.info("✅ Enhanced alert polling service initialized")
            except Exception as e:
                self.logger.error(f"❌ Alert polling service initialization failed: {e}")
            
            # Initialize enhanced collectors
            try:
                self.logger.info("📊 Initializing enhanced data collectors...")
                await self._initialize_enhanced_collectors()
                self.logger.info("✅ Enhanced data collectors initialized")
            except Exception as e:
                self.logger.error(f"❌ Enhanced collector initialization failed: {e}")
                raise Exception(f"Enhanced collector initialization failed: {e}")
            
            self.is_initialized = True
            self.logger.info("🎉 Enhanced Agent Manager initialization completed successfully")
            self.logger.info("🛡️ Advanced malware detection capabilities ACTIVE")
            
        except Exception as e:
            self.logger.error(f"❌ Enhanced agent manager initialization failed: {e}")
            import traceback
            self.logger.error(f"🔍 Full error details:\n{traceback.format_exc()}")
            raise Exception(f"Enhanced agent manager initialization failed: {e}")
    
    async def _initialize_enhanced_collectors(self):
        """Initialize enhanced data collectors with malware detection"""
        try:
            config = self.config_manager.get_config()
            collection_config = config.get('collection', {})
            malware_config = config.get('malware_detection', {})
            
            # ENHANCED: Process collector with malware detection
            if collection_config.get('collect_processes', True):
                try:
                    self.logger.info("🔄 Initializing Enhanced Process Collector...")
                    self.collectors['process'] = EnhancedProcessCollector(self.config_manager)
                    self.collectors['process'].set_event_processor(self.event_processor)
                    
                    # Configure for malware detection
                    if malware_config.get('enabled', True):
                        self.collectors['process'].polling_interval = 1  # Faster scanning for malware
                        # Set malware detection mode through configuration
                        self.collectors['process'].config['malware_detection_enabled'] = True
                        self.logger.info("   🚨 Malware detection ENABLED for processes")
                    
                    await self.collectors['process'].initialize()
                    self.logger.info("✅ Enhanced Process collector initialized with malware detection")
                except Exception as e:
                    self.logger.error(f"❌ Enhanced Process collector failed: {e}")
            
            # ENHANCED: Network collector with reverse shell detection
            if collection_config.get('collect_network', True):
                try:
                    self.logger.info("🌐 Initializing Enhanced Network Collector...")
                    self.collectors['network'] = EnhancedNetworkCollector(self.config_manager)
                    self.collectors['network'].set_event_processor(self.event_processor)
                    
                    # Configure for reverse shell detection
                    if malware_config.get('reverse_shell_detection', {}).get('enabled', True):
                        self.collectors['network'].polling_interval = 0.5  # Very fast for reverse shells
                        # Set reverse shell detection through configuration
                        self.collectors['network'].config['reverse_shell_detection_enabled'] = True
                        self.logger.info("   🚨 Reverse shell detection ENABLED")
                    
                    if malware_config.get('c2_communication_detection', {}).get('enabled', True):
                        # Set C2 detection through configuration
                        self.collectors['network'].config['c2_detection_enabled'] = True
                        self.logger.info("   🎯 C2 communication detection ENABLED")
                    
                    await self.collectors['network'].initialize()
                    self.logger.info("✅ Enhanced Network collector initialized with reverse shell detection")
                except Exception as e:
                    self.logger.error(f"❌ Enhanced Network collector failed: {e}")
            
            # ENHANCED: File collector with malware file detection
            if collection_config.get('collect_files', True):
                try:
                    self.logger.info("📁 Initializing Enhanced File Collector...")
                    self.collectors['file'] = EnhancedFileCollector(self.config_manager)
                    self.collectors['file'].set_event_processor(self.event_processor)
                    
                    # Configure for malware file detection
                    # Set malware file detection through configuration
                    self.collectors['file'].config['malware_file_detection_enabled'] = True
                    self.collectors['file'].config['monitor_executable_creation'] = True
                    
                    await self.collectors['file'].initialize()
                    self.logger.info("✅ Enhanced File collector initialized with malware detection")
                except Exception as e:
                    self.logger.error(f"❌ Enhanced File collector failed: {e}")
            
            # Registry collector (Windows only)
            if (collection_config.get('collect_registry', True) and 
                platform.system().lower() == 'windows'):
                try:
                    self.logger.info("🔧 Initializing Enhanced Registry Collector...")
                    self.collectors['registry'] = EnhancedRegistryCollector(self.config_manager)
                    self.collectors['registry'].set_event_processor(self.event_processor)
                    await self.collectors['registry'].initialize()
                    self.logger.info("✅ Enhanced Registry collector initialized")
                except Exception as e:
                    self.logger.error(f"❌ Enhanced Registry collector failed: {e}")
            
            # Authentication collector
            if collection_config.get('collect_authentication', True):
                try:
                    self.logger.info("🔐 Initializing Authentication Collector...")
                    self.collectors['authentication'] = AuthenticationCollector(self.config_manager)
                    self.collectors['authentication'].set_event_processor(self.event_processor)
                    await self.collectors['authentication'].initialize()
                    self.logger.info("✅ Authentication collector initialized")
                except Exception as e:
                    self.logger.error(f"❌ Authentication collector failed: {e}")
            
            # System collector
            try:
                self.logger.info("💻 Initializing System Collector...")
                self.collectors['system'] = SystemCollector(self.config_manager)
                self.collectors['system'].set_event_processor(self.event_processor)
                await self.collectors['system'].initialize()
                self.logger.info("✅ System collector initialized")
            except Exception as e:
                self.logger.error(f"❌ System collector failed: {e}")
            
            # Log enhanced capabilities
            enhanced_features = []
            if 'process' in self.collectors:
                enhanced_features.append("Process Malware Analysis")
            if 'network' in self.collectors:
                enhanced_features.append("Reverse Shell Detection")
                enhanced_features.append("C2 Communication Detection")
            if 'file' in self.collectors:
                enhanced_features.append("Malware File Detection")
            
            self.logger.info(f"🛡️ Enhanced capabilities active: {', '.join(enhanced_features)}")
            self.logger.info(f"📊 {len(self.collectors)} enhanced collectors initialized")
            
        except Exception as e:
            self.logger.error(f"❌ Enhanced collector initialization failed: {e}")
            import traceback
            self.logger.error(f"🔍 Full enhanced collector error details:\n{traceback.format_exc()}")
            raise
    
    async def start(self):
        """Start the enhanced agent with malware detection"""
        try:
            self.logger.info("🚀 Starting Enhanced Agent with Malware Detection...")
            
            # Register with server
            await self._register_with_server()
            
            # Ensure agent_id is available
            if not self.agent_id:
                raise Exception("Enhanced agent registration failed - no agent_id received")
            
            # Set agent_id for all components
            if self.event_processor and self.agent_id:
                self.event_processor.set_agent_id(self.agent_id)
                self.logger.info(f"[EVENT_PROCESSOR] Enhanced AgentID: {self.agent_id}")
            
            if self.communication and self.agent_id:
                self.communication.set_agent_id(self.agent_id)
                self.logger.info(f"[COMMUNICATION] Enhanced AgentID: {self.agent_id}")
            
            if self.alert_polling_service and self.agent_id:
                self.alert_polling_service.set_agent_id(self.agent_id)
                self.logger.info(f"[ALERT_POLLING] Enhanced AgentID: {self.agent_id}")
            
            # Start event processor
            await self.event_processor.start()
            
            # Set agent_id on all enhanced collectors
            for name, collector in self.collectors.items():
                if hasattr(collector, 'set_agent_id'):
                    collector.set_agent_id(self.agent_id)
                    self.logger.debug(f"[{name.upper()}_COLLECTOR] Enhanced AgentID: {self.agent_id}")
            
            # Start enhanced collectors
            await self._start_enhanced_collectors()
            
            # Start alert polling service
            if self.alert_polling_service:
                try:
                    await self.alert_polling_service.start()
                    self.logger.info("✅ Enhanced alert polling service started")
                except Exception as e:
                    self.logger.error(f"❌ Failed to start enhanced alert polling service: {e}")
            
            # Start monitoring
            self.is_monitoring = True
            self.is_running = True
            self.start_time = datetime.now()
            
            # Start enhanced heartbeat task
            asyncio.create_task(self._enhanced_heartbeat_loop())
            
            # Start malware statistics tracking
            asyncio.create_task(self._malware_statistics_loop())
            
            # Start server connection monitor
            asyncio.create_task(self.monitor_server_connection())
            
            self.logger.info("=" * 80)
            self.logger.info("🛡️ ENHANCED EDR AGENT WITH MALWARE DETECTION STARTED")
            self.logger.info(f"🆔 Agent ID: {self.agent_id}")
            self.logger.info("🚨 Active Detection Capabilities:")
            self.logger.info("   - Process Malware Analysis")
            self.logger.info("   - Reverse Shell Detection")
            self.logger.info("   - C2 Communication Detection")
            self.logger.info("   - Malicious IP Detection")
            self.logger.info("   - Network Traffic Analysis")
            self.logger.info("   - File Malware Detection")
            self.logger.info("   - Real-time Threat Monitoring")
            self.logger.info("=" * 80)
            
        except Exception as e:
            self.logger.error(f"❌ Enhanced agent start failed: {e}")
            raise
    
    async def _start_enhanced_collectors(self):
        """Start all enhanced data collectors"""
        try:
            self.logger.info("🚀 Starting enhanced collectors...")
            
            for name, collector in self.collectors.items():
                try:
                    await collector.start()
                    
                    # Log enhanced capabilities for each collector
                    if name == 'process' and hasattr(collector, 'enhanced_malware_detection'):
                        self.logger.info(f"✅ Started {name} collector - MALWARE DETECTION ACTIVE")
                    elif name == 'network' and hasattr(collector, 'reverse_shell_detection'):
                        self.logger.info(f"✅ Started {name} collector - REVERSE SHELL DETECTION ACTIVE")
                    else:
                        self.logger.info(f"✅ Started {name} collector")
                        
                except Exception as e:
                    self.logger.error(f"❌ Failed to start enhanced {name} collector: {e}")
            
            self.logger.info("🎉 All enhanced collectors started successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to start enhanced collectors: {e}")
            raise
    
    async def _enhanced_heartbeat_loop(self):
        """Enhanced heartbeat loop with malware statistics"""
        while self.is_monitoring and self.is_registered:
            try:
                # Send enhanced heartbeat
                await self._send_enhanced_heartbeat()
                
                # Check for pending alerts
                await self._check_pending_alerts()
                
                # Wait for next heartbeat
                await asyncio.sleep(self.config.get('agent', {}).get('heartbeat_interval', 30))
                
            except Exception as e:
                self.logger.error(f"❌ Enhanced heartbeat loop error: {e}")
                await asyncio.sleep(10)
    
    async def _malware_statistics_loop(self):
        """Track and log malware detection statistics"""
        while self.is_monitoring:
            try:
                # Collect malware statistics from enhanced collectors
                await self._update_malware_statistics()
                
                # Log statistics every 5 minutes
                current_time = time.time()
                if int(current_time) % 300 == 0:
                    await self._log_malware_statistics()
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"❌ Malware statistics loop error: {e}")
                await asyncio.sleep(60)
    
    async def _update_malware_statistics(self):
        """Update malware detection statistics from collectors"""
        try:
            # Reset counters
            total_processes = 0
            suspicious_processes = 0
            reverse_shells = 0
            c2_communications = 0
            malicious_ips = 0
            total_events = 0
            
            # Collect from process collector
            if 'process' in self.collectors:
                process_stats = self.collectors['process'].get_stats()
                total_processes += process_stats.get('total_processes_monitored', 0)
                suspicious_processes += process_stats.get('suspicious_processes_detected', 0)
                total_events += process_stats.get('total_malware_events', 0)
            
            # Collect from network collector
            if 'network' in self.collectors:
                network_stats = self.collectors['network'].get_stats()
                reverse_shells += network_stats.get('reverse_shell_connections_detected', 0)
                c2_communications += network_stats.get('c2_communication_detected', 0)
                malicious_ips += network_stats.get('malicious_ip_connections', 0)
                total_events += network_stats.get('total_malware_network_events', 0)
            
            # Update global statistics
            self.malware_stats.update({
                'total_processes_analyzed': total_processes,
                'suspicious_processes_detected': suspicious_processes,
                'reverse_shell_connections_detected': reverse_shells,
                'c2_communications_detected': c2_communications,
                'malicious_ips_detected': malicious_ips,
                'total_malware_events': total_events
            })
            
            # Update last detection time if any threats found
            if suspicious_processes > 0 or reverse_shells > 0 or c2_communications > 0:
                self.malware_stats['last_malware_detection'] = datetime.now()
            
        except Exception as e:
            self.logger.error(f"❌ Malware statistics update failed: {e}")
    
    async def _log_malware_statistics(self):
        """Log comprehensive malware detection statistics"""
        try:
            stats = self.malware_stats
            uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            
            self.logger.info("🛡️ ENHANCED MALWARE DETECTION STATISTICS:")
            self.logger.info(f"   📊 Processes Analyzed: {stats['total_processes_analyzed']}")
            self.logger.info(f"   🚨 Suspicious Processes: {stats['suspicious_processes_detected']}")
            self.logger.info(f"   🔴 Reverse Shells: {stats['reverse_shell_connections_detected']}")
            self.logger.info(f"   🎯 C2 Communications: {stats['c2_communications_detected']}")
            self.logger.info(f"   🚫 Malicious IPs: {stats['malicious_ips_detected']}")
            self.logger.info(f"   📈 Total Malware Events: {stats['total_malware_events']}")
            
            if stats['last_malware_detection']:
                time_since_last = (datetime.now() - stats['last_malware_detection']).total_seconds()
                self.logger.info(f"   ⏰ Last Detection: {time_since_last:.0f} seconds ago")
            else:
                self.logger.info("   ⏰ Last Detection: None")
            
            self.logger.info(f"   🕐 Uptime: {uptime/3600:.1f} hours")
            self.logger.info("-" * 50)
            
        except Exception as e:
            self.logger.error(f"❌ Malware statistics logging failed: {e}")
    
    async def _send_enhanced_heartbeat(self, status: str = 'Active'):
        """Send enhanced heartbeat with malware detection status"""
        try:
            if not self.is_registered:
                return
            
            # Get enhanced performance metrics
            performance_data = self._get_enhanced_performance_metrics()
            
            # Create enhanced heartbeat data
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
                self.logger.debug("💓 Enhanced heartbeat sent successfully")
            else:
                self.logger.warning("⚠️ Enhanced heartbeat failed")
                
        except Exception as e:
            self.logger.error(f"❌ Enhanced heartbeat send error: {e}")
    
    def _get_enhanced_performance_metrics(self) -> Dict[str, float]:
        """Get enhanced system performance metrics"""
        try:
            current_time = time.time()
            
            if (not hasattr(self, '_last_enhanced_metrics_time') or 
                current_time - self._last_enhanced_metrics_time > 30):
                
                self._cached_enhanced_cpu = psutil.cpu_percent(interval=0.1)
                
                memory = psutil.virtual_memory()
                self._cached_enhanced_memory = memory.percent
                
                disk = psutil.disk_usage('/')
                self._cached_enhanced_disk = disk.percent
                
                # Enhanced network latency (simplified)
                self._cached_enhanced_latency = 0
                try:
                    start_time = time.time()
                    self._cached_enhanced_latency = int((time.time() - start_time) * 1000)
                except:
                    self._cached_enhanced_latency = 0
                
                self._last_enhanced_metrics_time = current_time
            
            return {
                'cpu_usage': getattr(self, '_cached_enhanced_cpu', 0.0),
                'memory_usage': getattr(self, '_cached_enhanced_memory', 0.0),
                'disk_usage': getattr(self, '_cached_enhanced_disk', 0.0),
                'network_latency': getattr(self, '_cached_enhanced_latency', 0)
            }
            
        except Exception as e:
            self.logger.error(f"Error getting enhanced performance metrics: {e}")
            return {
                'cpu_usage': 0.0,
                'memory_usage': 0.0,
                'disk_usage': 0.0,
                'network_latency': 0
            }
    
    async def stop(self):
        """Stop the enhanced agent gracefully"""
        try:
            self.logger.info("🛑 Stopping Enhanced Agent...")
            self.is_monitoring = False
            self.is_running = False
            
            # Stop enhanced collectors
            await self._stop_collectors()
            
            # Stop alert polling service
            if self.alert_polling_service:
                try:
                    await self.alert_polling_service.stop()
                    self.logger.info("✅ Enhanced alert polling service stopped")
                except Exception as e:
                    self.logger.error(f"❌ Failed to stop enhanced alert polling service: {e}")
            
            # Stop event processor
            if self.event_processor:
                await self.event_processor.stop()
            
            # Send final heartbeat
            if self.is_registered:
                try:
                    await self._send_enhanced_heartbeat(status='Offline')
                except:
                    pass
            
            # Log final malware statistics
            await self._log_malware_statistics()
            
            self.logger.info("✅ Enhanced Agent stopped gracefully")
            
        except Exception as e:
            self.logger.error(f"❌ Enhanced Agent stop error: {e}")
    
    async def pause(self):
        """Pause enhanced agent monitoring"""
        try:
            if not self.is_paused:
                self.is_paused = True
                self.logger.info("⏸️  Enhanced Agent monitoring PAUSED")
                
                # Pause all enhanced collectors
                for name, collector in self.collectors.items():
                    try:
                        if hasattr(collector, 'pause'):
                            await collector.pause()
                        self.logger.debug(f"⏸️  Paused enhanced {name} collector")
                    except Exception as e:
                        self.logger.error(f"❌ Failed to pause enhanced {name} collector: {e}")
                
                # Pause alert polling service
                if self.alert_polling_service:
                    try:
                        await self.alert_polling_service.pause()
                        self.logger.debug("⏸️  Paused enhanced alert polling service")
                    except Exception as e:
                        self.logger.error(f"❌ Failed to pause enhanced alert polling service: {e}")
                
                # Send pause status to server
                if self.is_registered:
                    try:
                        await self._send_enhanced_heartbeat(status='Paused')
                    except:
                        pass
        except Exception as e:
            self.logger.error(f"❌ Enhanced Agent pause error: {e}")
    
    async def resume(self):
        """Resume enhanced agent monitoring"""
        try:
            if self.is_paused:
                self.is_paused = False
                self.logger.info("▶️  Enhanced Agent monitoring RESUMED")
                
                # Resume all enhanced collectors
                for name, collector in self.collectors.items():
                    try:
                        if hasattr(collector, 'resume'):
                            await collector.resume()
                        self.logger.debug(f"▶️  Resumed enhanced {name} collector")
                    except Exception as e:
                        self.logger.error(f"❌ Failed to resume enhanced {name} collector: {e}")
                
                # Resume alert polling service
                if self.alert_polling_service:
                    try:
                        await self.alert_polling_service.resume()
                        self.logger.debug("▶️  Resumed enhanced alert polling service")
                    except Exception as e:
                        self.logger.error(f"❌ Failed to resume enhanced alert polling service: {e}")
                
                # Send active status to server
                if self.is_registered:
                    try:
                        await self._send_enhanced_heartbeat(status='Active')
                    except:
                        pass
        except Exception as e:
            self.logger.error(f"❌ Enhanced Agent resume error: {e}")
    
    def is_paused_state(self) -> bool:
        """Check if enhanced agent is currently paused"""
        return self.is_paused
    
    async def monitor_server_connection(self):
        """Enhanced background task: Pause/resume agent based on server connection status"""
        self.logger.info("🔄 Starting enhanced server connection monitor task...")
        while True:
            try:
                is_connected = False
                if self.communication and hasattr(self.communication, 'is_connected'):
                    is_connected = self.communication.is_connected()
                if is_connected and self.is_paused:
                    self.logger.info("🔗 Server reconnected. Resuming enhanced agent...")
                    await self.resume()
                elif not is_connected and not self.is_paused:
                    self.logger.warning("❌ Server disconnected. Pausing enhanced agent...")
                    await self.pause()
            except Exception as e:
                self.logger.error(f"[Enhanced Monitor] Error: {e}")
            await asyncio.sleep(5)
    
    async def _register_with_server(self):
        """Register enhanced agent with EDR server"""
        try:
            self.logger.info("📡 Registering Enhanced Agent with EDR server...")
            
            # Get system information
            system_info = self._get_system_info()
            
            # If agent_id exists, try to update registration
            if self.agent_id:
                self.logger.info(f"🔄 Using existing enhanced agent_id: {self.agent_id}")
                registration_data = AgentRegistrationData(
                    hostname=system_info['hostname'],
                    ip_address=system_info['ip_address'],
                    operating_system=system_info['operating_system'],
                    os_version=system_info['os_version'],
                    architecture=system_info['architecture'],
                    agent_version='2.1.0-Enhanced-Malware-Detection',
                    mac_address=system_info.get('mac_address'),
                    domain=system_info.get('domain'),
                    install_path=str(Path(__file__).resolve().parent.parent.parent)
                )
            else:
                registration_data = AgentRegistrationData(
                    hostname=system_info['hostname'],
                    ip_address=system_info['ip_address'],
                    operating_system=system_info['operating_system'],
                    os_version=system_info['os_version'],
                    architecture=system_info['architecture'],
                    agent_version='2.1.0-Enhanced-Malware-Detection',
                    mac_address=system_info.get('mac_address'),
                    domain=system_info.get('domain'),
                    install_path=str(Path(__file__).resolve().parent.parent.parent)
                )
            
            # Send registration request
            response = await self.communication.register_agent(registration_data)
            if response and response.get('success'):
                self.agent_id = response.get('agent_id')
                self.is_registered = True
                self._save_agent_id(self.agent_id)
                
                self.logger.info("✅ Enhanced Agent registered successfully")
                self.logger.info(f"🆔 Enhanced Agent ID: {self.agent_id}")
                self.logger.info(f"🏠 Hostname: {system_info['hostname']}")
                self.logger.info(f"🛡️ Version: 2.1.0-Enhanced-Malware-Detection")
                
                # Update configuration with server settings
                if 'heartbeat_interval' in response:
                    self.config['agent']['heartbeat_interval'] = response['heartbeat_interval']
            else:
                raise Exception("Enhanced agent registration failed")
        except Exception as e:
            self.logger.error(f"❌ Enhanced agent registration failed: {e}")
            raise
    
    async def _check_pending_alerts(self):
        """Check for pending alerts from server"""
        try:
            if not self.agent_id or not self.communication:
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
                                await self.event_processor.security_notifier.process_server_alerts(
                                    {'alerts_generated': [notification_data]}, 
                                    []
                                )
                    except Exception as e:
                        self.logger.error(f"Failed to process alert: {e}")
                        
        except Exception as e:
            self.logger.debug(f"Alert check failed: {e}")
    
    async def _stop_collectors(self):
        """Stop all enhanced data collectors"""
        try:
            self.logger.info("🛑 Stopping all enhanced collectors...")
            
            for name, collector in self.collectors.items():
                try:
                    await collector.stop()
                    self.logger.info(f"✅ Stopped enhanced {name} collector")
                except Exception as e:
                    self.logger.error(f"❌ Error stopping enhanced {name} collector: {e}")
            
            self.logger.info("✅ All enhanced collectors stopped")
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping enhanced collectors: {e}")
    
    def _get_system_info(self) -> Dict[str, str]:
        """Get enhanced system information for registration"""
        try:
            import socket
            import getpass
            import platform
            import uuid
            import os

            hostname = socket.gethostname()

            try:
                server_host = self.config.get('server', {}).get('host', '8.8.8.8')
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((server_host, 80))
                ip_address = s.getsockname()[0]
                s.close()
            except:
                ip_address = '127.0.0.1'

            try:
                mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
                mac_address = ':'.join([mac[i:i+2] for i in range(0, 12, 2)])
            except:
                mac_address = None

            try:
                domain = os.environ.get('USERDOMAIN') if platform.system().lower() == 'windows' else None
            except:
                domain = None

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
            self.logger.error(f"Error getting enhanced system info: {e}")
            return {
                'hostname': 'unknown',
                'ip_address': '127.0.0.1',
                'operating_system': 'Unknown',
                'os_version': 'Unknown',
                'architecture': 'Unknown'
            }
    
    def _load_agent_id(self):
        """Load agent_id from file if exists, else None"""
        try:
            if os.path.exists(self.agent_id_file):
                with open(self.agent_id_file, 'r') as f:
                    agent_id = f.read().strip()
                    if agent_id:
                        self.logger.info(f"📁 Loaded persistent enhanced agent_id: {agent_id}")
                        return agent_id
        except Exception as e:
            self.logger.error(f"Failed to load enhanced agent_id: {e}")
        return None

    def _save_agent_id(self, agent_id):
        """Save agent_id to file for persistence"""
        try:
            with open(self.agent_id_file, 'w') as f:
                f.write(agent_id)
            self.logger.info(f"💾 Saved persistent enhanced agent_id: {agent_id}")
        except Exception as e:
            self.logger.error(f"Failed to save enhanced agent_id: {e}")
    
    def get_enhanced_status(self) -> Dict[str, Any]:
        """Get enhanced agent status with malware detection info"""
        try:
            uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            
            return {
                'agent_id': self.agent_id,
                'is_running': self.is_running,
                'is_monitoring': self.is_monitoring,
                'is_paused': self.is_paused,
                'is_registered': self.is_registered,
                'uptime_seconds': uptime,
                'enhanced_features': {
                    'malware_detection': True,
                    'reverse_shell_detection': True,
                    'c2_detection': True,
                    'malicious_ip_detection': True,
                    'real_time_analysis': True
                },
                'malware_statistics': self.malware_stats.copy(),
                'collectors_status': {
                    name: {
                        'running': hasattr(collector, 'is_running') and collector.is_running,
                        'enhanced': True
                    }
                    for name, collector in self.collectors.items()
                },
                'last_heartbeat': self.last_heartbeat.isoformat() if self.last_heartbeat else None,
                'version': '2.1.0-Enhanced-Malware-Detection'
            }
        except Exception as e:
            self.logger.error(f"❌ Enhanced status calculation failed: {e}")
            return {}

# Alias for backward compatibility
AgentManager = EnhancedAgentManager