# agent/core/communication.py - XỬ LÝ RESPONSE TỪ SERVER
"""
Server Communication - XỬ LÝ ĐÚNG RESPONSE TỪ SERVER
Xử lý response từ server để phát hiện alert/threat detection
"""

import aiohttp
import asyncio
import logging
import json
import time
import socket
import requests
from typing import Optional, Dict, List, Any
from datetime import datetime
import platform

from agent.core.config_manager import ConfigManager
from agent.schemas.agent_data import AgentRegistrationData, AgentHeartbeatData
from agent.schemas.events import EventData

class ServerCommunication:
    """Server Communication - Xử lý response từ server để phát hiện alerts"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.config = self.config_manager.get_config()
        self.server_config = self.config.get('server', {})
        
        # Auto-detect working server
        self.working_server = None
        self.server_host = None
        self.server_port = None
        self.base_url = None
        self.offline_mode = False
        
        # Authentication
        self.auth_token = self.server_config.get('auth_token', 'edr_agent_auth_2024')
        
        # HTTP session
        self.session: Optional[aiohttp.ClientSession] = None
        self._session_closed = False
        
        # Optimized timeout settings
        self.timeout = 5
        self.connect_timeout = 2
        self.read_timeout = 3
        self.max_retries = 1
        self.retry_delay = 0.5
        
        # Connection pooling
        self.connection_pool_size = 5
        self.keep_alive_timeout = 15
        self.total_timeout = 8
        
        # Performance tracking
        self.connection_attempts = 0
        self.successful_connections = 0
        self.failed_connections = 0
        self.last_successful_connection = None
        
        # Offline mode support
        self.offline_events_queue = []
        self.max_offline_events = 1000
        
        # Server response tracking
        self.threats_detected_by_server = 0
        self.alerts_received_from_server = 0
        self.last_threat_detection = None
        
        self.logger.info("🔧 Communication initialized - Server response processing enabled")
    
    async def initialize(self):
        """Initialize communication with server detection"""
        try:
            # Auto-detect working server
            self.working_server = await self._detect_working_server()
            
            if not self.working_server:
                self.logger.warning("⚠️ No EDR server found - enabling offline mode")
                self.offline_mode = True
                self._setup_offline_mode()
                return
            
            # Set server details
            self.server_host = self.working_server['host']
            self.server_port = self.working_server['port']
            self.base_url = f"http://{self.server_host}:{self.server_port}"
            self.offline_mode = False
            
            # Close existing session if any
            await self.close()
            
            # Setup timeout configuration
            timeout = aiohttp.ClientTimeout(
                total=self.total_timeout,
                connect=self.connect_timeout,
                sock_read=self.read_timeout,
                sock_connect=self.connect_timeout
            )
            
            # Setup headers
            headers = {
                'Content-Type': 'application/json',
                'X-Agent-Token': self.auth_token,
                'User-Agent': 'EDR-Agent/2.0-ServerResponse',
                'Connection': 'keep-alive',
                'Accept': 'application/json'
            }
            
            # Setup connector
            connector = aiohttp.TCPConnector(
                limit=self.connection_pool_size,
                limit_per_host=self.connection_pool_size,
                ttl_dns_cache=300,
                use_dns_cache=True,
                keepalive_timeout=self.keep_alive_timeout,
                enable_cleanup_closed=True,
                force_close=False,
                ssl=False
            )
            
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
                connector=connector,
                raise_for_status=False
            )
            self._session_closed = False
            
            # Test connection
            connection_ok = await self._test_connection()
            
            if connection_ok:
                self.logger.info(f"✅ Communication initialized successfully: {self.base_url}")
            else:
                self.logger.warning(f"⚠️ Server detected but not responding: {self.base_url}")
                self.offline_mode = True
                self._setup_offline_mode()
            
        except Exception as e:
            self.logger.error(f"❌ Communication initialization failed: {e}")
            self.offline_mode = True
            self._setup_offline_mode()
    
    def _setup_offline_mode(self):
        """Setup offline mode"""
        self.logger.info("🔄 Setting up offline mode...")
        self.offline_events_queue = []
        asyncio.create_task(self._periodic_server_detection())
    
    async def _periodic_server_detection(self):
        """Periodically check for server availability"""
        while True:
            try:
                await asyncio.sleep(30)
                
                if self.offline_mode:
                    working_server = await self._detect_working_server()
                    
                    if working_server:
                        self.logger.info("✅ Server detected! Reconnecting...")
                        self.working_server = working_server
                        await self.initialize()
                        
                        if not self.offline_mode:
                            await self._send_queued_events()
                            
            except Exception as e:
                self.logger.debug(f"Periodic server detection error: {e}")
    
    async def _send_queued_events(self):
        """Send queued offline events and acknowledgments"""
        if not self.offline_events_queue and not hasattr(self, 'offline_acknowledgments'):
            return
        
        # Send queued events
        if self.offline_events_queue:
            self.logger.info(f"📤 Sending {len(self.offline_events_queue)} queued events...")
            events_to_send = self.offline_events_queue.copy()
            self.offline_events_queue.clear()
            sent_count = 0
            for event_data in events_to_send:
                try:
                    response = await self._make_request_with_retry('POST', f"{self.base_url}/api/v1/events/submit", event_data)
                    if response:
                        sent_count += 1
                    else:
                        self.offline_events_queue.append(event_data)
                except:
                    self.offline_events_queue.append(event_data)
            self.logger.info(f"✅ Sent {sent_count}/{len(events_to_send)} queued events")
        
        # Send queued acknowledgments
        await self.send_queued_acknowledgments()
    
    async def _detect_working_server(self):
        """Auto-detect working EDR server"""
        potential_servers = [
            {'host': 'localhost', 'port': 5000, 'name': 'Local Server'},
            {'host': '127.0.0.1', 'port': 5000, 'name': 'Loopback Server'},
            {'host': '192.168.20.85', 'port': 5000, 'name': 'Configured Server'},
            {'host': 'localhost', 'port': 8000, 'name': 'Alt Port 8000'},
            {'host': '127.0.0.1', 'port': 3000, 'name': 'Alt Port 3000'},
        ]
        
        for server in potential_servers:
            if await self._test_server_connection(server):
                self.logger.info(f"✅ Found working server: {server['name']} ({server['host']}:{server['port']})")
                return server
        
        return None
    
    async def _test_server_connection(self, server):
        """Test connection to a specific server"""
        try:
            host = server['host']
            port = server['port']
            
            # Test TCP connection
            def test_tcp():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    return result == 0
                except:
                    return False
            
            tcp_success = await asyncio.to_thread(test_tcp)
            return tcp_success
            
        except Exception as e:
            return False
    
    async def _test_connection(self):
        """Test connection to selected server"""
        try:
            if not self.working_server:
                return False
            
            test_endpoints = ['/health', '/api/v1/status', '/', '/status']
            
            for endpoint in test_endpoints:
                try:
                    url = f"{self.base_url}{endpoint}"
                    response = await self._make_request_internal('GET', url, timeout_override=3)
                    
                    if response is not None:
                        self.last_successful_connection = time.time()
                        self.successful_connections += 1
                        return True
                except:
                    continue
            
            return False
            
        except Exception as e:
            return False
    
    async def submit_event(self, event_data: EventData) -> Optional[Dict]:
        """
        GỬI EVENT LÊN SERVER VÀ XỬ LÝ RESPONSE
        Trả về response từ server để event processor có thể xử lý alerts
        """
        try:
            if self.offline_mode:
                # Store event for later sending
                event_payload = self._convert_event_to_payload(event_data)
                
                if len(self.offline_events_queue) >= self.max_offline_events:
                    self.offline_events_queue.pop(0)
                
                self.offline_events_queue.append(event_payload)
                
                return {
                    'success': True,
                    'event_id': f'offline_{int(time.time())}',
                    'message': 'Event stored in offline mode',
                    'offline_mode': True,
                    'threat_detected': False,
                    'risk_score': 0
                }
            
            url = f"{self.base_url}/api/v1/events/submit"
            payload = self._convert_event_to_payload(event_data)
            
            response = await self._make_request_with_retry('POST', url, payload)
            
            if response:
                # XỬ LÝ RESPONSE TỪ SERVER ĐỂ PHÁT HIỆN ALERTS
                processed_response = self._process_server_response(response, event_data)
                return processed_response
            else:
                # Switch to offline mode if server stops responding
                self.offline_mode = True
                return await self.submit_event(event_data)  # Retry in offline mode
                
        except Exception as e:
            self.logger.debug(f"❌ Event send error: {e}")
            
            if not self.offline_mode:
                self.offline_mode = True
                return await self.submit_event(event_data)
            
            return None
    
    def _process_server_response(self, response: Dict[str, Any], original_event: EventData) -> Dict[str, Any]:
        """
        XỬ LÝ RESPONSE TỪ SERVER ĐỂ PHÁT HIỆN THREATS/ALERTS
        Trả về response đã được xử lý với thông tin threat detection
        """
        try:
            if not response:
                return {'success': False, 'threat_detected': False, 'risk_score': 0}
            
            # Khởi tạo processed response
            processed_response = response.copy()
            
            # Đảm bảo có các field cần thiết
            if 'threat_detected' not in processed_response:
                processed_response['threat_detected'] = False
            if 'risk_score' not in processed_response:
                processed_response['risk_score'] = 0
            
            # CASE 1: Server trả về threat_detected = True
            if response.get('threat_detected', False):
                self.threats_detected_by_server += 1
                self.last_threat_detection = datetime.now()
                
                self.logger.warning(f"🚨 SERVER DETECTED THREAT: {original_event.event_type} - Risk: {response.get('risk_score', 0)}")
                
                # Đảm bảo có đủ thông tin cho alert
                if 'rule_triggered' not in processed_response:
                    processed_response['rule_triggered'] = 'Server Threat Detection'
                if 'threat_description' not in processed_response:
                    processed_response['threat_description'] = f'Suspicious {original_event.event_type} activity detected'
                
                return processed_response
            
            # CASE 2: Server trả về alerts_generated
            if 'alerts_generated' in response and response['alerts_generated']:
                alerts = response['alerts_generated']
                self.alerts_received_from_server += len(alerts)
                self.last_threat_detection = datetime.now()
                
                self.logger.warning(f"🚨 SERVER GENERATED {len(alerts)} ALERTS for {original_event.event_type}")
                
                # Set threat_detected = True if có alerts
                processed_response['threat_detected'] = True
                if not processed_response.get('risk_score'):
                    # Tính risk score từ alerts
                    max_risk = max((alert.get('risk_score', 50) for alert in alerts), default=50)
                    processed_response['risk_score'] = max_risk
                
                return processed_response
            
            # CASE 3: Risk score cao (>= 70)
            risk_score = response.get('risk_score', 0)
            if risk_score >= 70:
                self.threats_detected_by_server += 1
                self.last_threat_detection = datetime.now()
                
                self.logger.warning(f"🚨 HIGH RISK SCORE: {risk_score} for {original_event.event_type}")
                
                processed_response['threat_detected'] = True
                processed_response['rule_triggered'] = 'High Risk Score Detection'
                processed_response['threat_description'] = f'High risk {original_event.event_type} activity (Score: {risk_score})'
                
                return processed_response
            
            # CASE 4: Server trả về alerts array
            if 'alerts' in response and response['alerts']:
                alerts = response['alerts']
                self.alerts_received_from_server += len(alerts)
                self.last_threat_detection = datetime.now()
                
                self.logger.warning(f"🚨 SERVER SENT {len(alerts)} ALERTS for {original_event.event_type}")
                
                processed_response['threat_detected'] = True
                processed_response['alerts_generated'] = alerts  # Normalize to alerts_generated
                
                return processed_response
            
            # CASE 5: Không có threat - normal response
            self.logger.debug(f"✅ Server processed {original_event.event_type} normally - no threats detected")
            processed_response['threat_detected'] = False
            
            return processed_response
            
        except Exception as e:
            self.logger.error(f"❌ Server response processing error: {e}")
            return {
                'success': True,
                'threat_detected': False,
                'risk_score': 0,
                'error': str(e)
            }
    
    def _convert_event_to_payload(self, event_data: EventData) -> Dict:
        """Convert event data to API payload"""
        try:
            payload = {
                # Core event fields
                # Core event fields
                'agent_id': event_data.agent_id,
                'event_type': event_data.event_type,
                'event_action': event_data.event_action,
                'event_timestamp': event_data.event_timestamp.isoformat(),
                'severity': event_data.severity,
                
                # Process fields
                'process_id': event_data.process_id,
                'process_name': event_data.process_name,
                'process_path': event_data.process_path,
                'command_line': event_data.command_line,
                'parent_pid': event_data.parent_pid,
                'parent_process_name': event_data.parent_process_name,
                'process_user': event_data.process_user,
                'process_hash': event_data.process_hash,
                
                # File fields
                'file_path': event_data.file_path,
                'file_name': event_data.file_name,
                'file_size': event_data.file_size,
                'file_hash': event_data.file_hash,
                'file_extension': event_data.file_extension,
                'file_operation': event_data.file_operation,
                
                # Network fields
                'source_ip': event_data.source_ip,
                'destination_ip': event_data.destination_ip,
                'source_port': event_data.source_port,
                'destination_port': event_data.destination_port,
                'protocol': event_data.protocol,
                'direction': event_data.direction,
                
                # Registry fields
                'registry_key': event_data.registry_key,
                'registry_value_name': event_data.registry_value_name,
                'registry_value_data': event_data.registry_value_data,
                'registry_operation': event_data.registry_operation,
                
                # Authentication fields
                'login_user': event_data.login_user,
                'login_type': event_data.login_type,
                'login_result': event_data.login_result,
                
                # System fields
                'cpu_usage': event_data.cpu_usage,
                'memory_usage': event_data.memory_usage,
                'disk_usage': event_data.disk_usage,
                
                # Metadata fields
                'description': event_data.description,
                'threat_level': 'None',
                'risk_score': 0,
                'analyzed': True,
                'analyzed_at': datetime.now().isoformat(),
                
                # Raw event data
                'raw_event_data': event_data.raw_event_data or {}
            }
            
            # Convert None values to null for JSON
            for key, value in payload.items():
                if value is None:
                    payload[key] = None
            
            return payload
            
        except Exception as e:
            self.logger.error(f"❌ Event payload conversion failed: {e}")
            return {
                'agent_id': event_data.agent_id or 'unknown',
                'event_type': event_data.event_type or 'Unknown',
                'event_action': event_data.event_action or 'Unknown',
                'event_timestamp': datetime.now().isoformat(),
                'severity': event_data.severity or 'Info',
                'description': str(event_data.description) or 'Error converting event data'
            }
    
    async def _make_request_with_retry(self, method: str, url: str, payload: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request with retry logic"""
        if self.offline_mode:
            return None
        
        for attempt in range(self.max_retries + 1):
            try:
                self.connection_attempts += 1
                response = await self._make_request_internal(method, url, payload)
                
                if response is not None:
                    self.successful_connections += 1
                    return response
                
            except Exception as e:
                self.failed_connections += 1
                
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay)
        
        # All attempts failed
        if not self.offline_mode:
            self.offline_mode = True
        
        return None
    
    async def _make_request_internal(self, method: str, url: str, payload: Optional[Dict] = None, 
                                   timeout_override: Optional[float] = None) -> Optional[Dict]:
        """Internal method to make HTTP request"""
        if self.offline_mode or not self.session or self._session_closed:
            return None
        
        try:
            if timeout_override:
                timeout = aiohttp.ClientTimeout(total=timeout_override)
            else:
                timeout = None
            
            if method.upper() == 'GET':
                async with self.session.get(url, timeout=timeout) as response:
                    return await self._handle_response(response)
                    
            elif method.upper() == 'POST':
                async with self.session.post(url, json=payload, timeout=timeout) as response:
                    return await self._handle_response(response)
                    
            else:
                raise Exception(f"Unsupported HTTP method: {method}")
                
        except asyncio.TimeoutError:
            raise asyncio.TimeoutError(f"Request timeout: {url}")
        except Exception as e:
            raise Exception(f"Request error: {e}")
    
    async def _handle_response(self, response: aiohttp.ClientResponse) -> Optional[Dict]:
        """Handle HTTP response"""
        try:
            if response.status == 200:
                try:
                    data = await response.json()
                    return data
                except json.JSONDecodeError:
                    text = await response.text()
                    if len(text) < 200:
                        return {'success': True, 'message': text}
                    return None
                    
            elif response.status in [404, 405]:
                return None
            elif response.status >= 500:
                text = await response.text()
                raise Exception(f"Server error {response.status}: {text}")
            else:
                return None
                
        except Exception as e:
            self.logger.debug(f"Response handling error: {e}")
            return None
    
    async def register_agent(self, registration_data: AgentRegistrationData) -> Optional[Dict]:
        """Register agent with server"""
        try:
            if self.offline_mode:
                import uuid
                agent_id = str(uuid.uuid4())
                return {
                    'success': True,
                    'agent_id': agent_id,
                    'message': 'Agent registered in offline mode',
                    'heartbeat_interval': 30,
                    'offline_mode': True
                }
            
            url = f"{self.base_url}/api/v1/agents/register"
            
            payload = {
                'hostname': registration_data.hostname,
                'ip_address': registration_data.ip_address,
                'operating_system': registration_data.operating_system,
                'os_version': registration_data.os_version,
                'architecture': registration_data.architecture,
                'agent_version': registration_data.agent_version,
                'mac_address': registration_data.mac_address,
                'domain': registration_data.domain,
                'install_path': registration_data.install_path
            }
            
            response = await self._make_request_with_retry('POST', url, payload)
            
            if response and response.get('agent_id'):
                return response
            else:
                # Fallback to offline registration
                import uuid
                agent_id = str(uuid.uuid4())
                return {
                    'success': True,
                    'agent_id': agent_id,
                    'message': 'Agent registered in offline mode',
                    'heartbeat_interval': 30,
                    'offline_mode': True
                }
                
        except Exception as e:
            # Fallback to offline registration
            import uuid
            agent_id = str(uuid.uuid4())
            return {
                'success': True,
                'agent_id': agent_id,
                'message': 'Agent registered in offline mode (error fallback)',
                'offline_mode': True
            }
    
    async def send_heartbeat(self, heartbeat_data: AgentHeartbeatData) -> Optional[Dict]:
        """Send heartbeat to server"""
        try:
            if self.offline_mode:
                return {
                    'success': True, 
                    'message': 'Offline mode heartbeat',
                    'offline_mode': True
                }
            
            url = f"{self.base_url}/api/v1/agents/heartbeat"
            
            payload = {
                'hostname': heartbeat_data.hostname,
                'status': heartbeat_data.status,
                'cpu_usage': heartbeat_data.cpu_usage,
                'memory_usage': heartbeat_data.memory_usage,
                'disk_usage': heartbeat_data.disk_usage,
                'network_latency': heartbeat_data.network_latency
            }
            
            response = await self._make_request_with_retry('POST', url, payload)
            return response or {
                'success': True, 
                'message': 'Heartbeat sent (no response)',
                'offline_mode': self.offline_mode
            }
            
        except Exception as e:
            return {
                'success': True, 
                'message': 'Offline mode heartbeat (error)',
                'offline_mode': True
            }
    
    async def get_pending_alerts(self, agent_id: str) -> Optional[Dict]:
        """Get pending alert notifications from server"""
        try:
            if self.offline_mode:
                return None
            
            url = f"{self.base_url}/api/v1/agents/{agent_id}/pending-alerts"
            response = await self._make_request_with_retry('GET', url)
            return response
            
        except Exception as e:
            return None
    
    async def close(self):
        """Close communication session"""
        try:
            if self.session and not self._session_closed:
                await self.session.close()
                self._session_closed = True
        except Exception as e:
            self.logger.error(f"Error closing session: {e}")
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get server connection information including acknowledgment stats"""
        base_info = {
            'working_server': self.working_server,
            'host': self.server_host,
            'port': self.server_port,
            'base_url': self.base_url,
            'offline_mode': self.offline_mode,
            'timeout': self.timeout,
            'connection_attempts': self.connection_attempts,
            'successful_connections': self.successful_connections,
            'failed_connections': self.failed_connections,
            'last_successful_connection': self.last_successful_connection,
            'session_active': self.session is not None and not self._session_closed,
            'success_rate': (self.successful_connections / max(self.connection_attempts, 1)) * 100 if self.connection_attempts > 0 else 0,
            'offline_events_queued': len(self.offline_events_queue),
            'max_offline_events': self.max_offline_events,
            'threats_detected_by_server': self.threats_detected_by_server,
            'alerts_received_from_server': self.alerts_received_from_server,
            'last_threat_detection': self.last_threat_detection.isoformat() if self.last_threat_detection else None,
            'server_response_processing': True,
            'alert_acknowledgment_support': True
        }
        
        # Add acknowledgment statistics
        if hasattr(self, 'offline_acknowledgments'):
            base_info['offline_acknowledgments_queued'] = len(self.offline_acknowledgments)
        else:
            base_info['offline_acknowledgments_queued'] = 0
        
        return base_info
    
    async def send_alert_acknowledgment(self, ack_data: Dict[str, Any]) -> bool:
        """
        Send alert acknowledgment to server để insert vào database
        """
        try:
            if self.offline_mode:
                self.logger.info("📝 Alert acknowledgment stored for offline mode")
                # Store acknowledgment for later sending
                if not hasattr(self, 'offline_acknowledgments'):
                    self.offline_acknowledgments = []
                self.offline_acknowledgments.append(ack_data)
                return True
            
            url = f"{self.base_url}/api/v1/alerts/acknowledge"
            
            # Prepare comprehensive acknowledgment payload for database
            payload = {
                # Core acknowledgment data
                'alert_id': ack_data.get('alert_id'),
                'agent_id': ack_data.get('agent_id') or self.agent_id,
                'status': ack_data.get('status', 'acknowledged'),
                'acknowledged_at': ack_data.get('acknowledged_at'),
                
                # Display information
                'display_status': ack_data.get('display_status', 'displayed'),
                'notification_method': ack_data.get('notification_method', 'desktop_notification'),
                'user_action': ack_data.get('user_action', 'auto_acknowledged'),
                'acknowledgment_type': ack_data.get('acknowledgment_type', 'rule_violation_display'),
                
                # Rule information (if available)
                'rule_id': ack_data.get('rule_id'),
                'rule_name': ack_data.get('rule_name'),
                'rule_violation': ack_data.get('rule_violation', True),
                
                # Alert metadata
                'severity': ack_data.get('severity'),
                'risk_score': ack_data.get('risk_score'),
                'detection_method': ack_data.get('detection_method'),
                'mitre_technique': ack_data.get('mitre_technique'),
                'mitre_tactic': ack_data.get('mitre_tactic'),
                
                # Event context
                'event_id': ack_data.get('event_id'),
                'process_name': ack_data.get('process_name'),
                'file_path': ack_data.get('file_path'),
                
                # System information
                'agent_hostname': platform.node(),
                'agent_version': '2.1.0-RuleBasedAlerts',
                'acknowledgment_timestamp': datetime.now().isoformat(),
                
                # Additional metadata
                'notification_success': True,
                'display_duration_seconds': 8,
                'alert_category': 'security_rule_violation'
            }
            
            response = await self._make_request_with_retry('POST', url, payload)
            
            if response and response.get('success'):
                self.logger.info(f"✅ Alert acknowledgment sent to database: {ack_data.get('alert_id')}")
                return True
            else:
                self.logger.warning(f"⚠️ Alert acknowledgment failed: {response}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Alert acknowledgment error: {e}")
            return False
    
    async def send_queued_acknowledgments(self):
        """Send queued acknowledgments when coming back online"""
        try:
            if not hasattr(self, 'offline_acknowledgments'):
                return
            
            acknowledgments_to_send = self.offline_acknowledgments.copy()
            self.offline_acknowledgments.clear()
            
            sent_count = 0
            for ack_data in acknowledgments_to_send:
                try:
                    success = await self.send_alert_acknowledgment(ack_data)
                    if success:
                        sent_count += 1
                    else:
                        self.offline_acknowledgments.append(ack_data)
                except:
                    self.offline_acknowledgments.append(ack_data)
            
            if sent_count > 0:
                self.logger.info(f"✅ Sent {sent_count}/{len(acknowledgments_to_send)} queued acknowledgments")
                
        except Exception as e:
            self.logger.error(f"❌ Error sending queued acknowledgments: {e}")