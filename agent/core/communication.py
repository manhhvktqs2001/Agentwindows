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
        
        # Agent ID - will be set by agent manager
        self.agent_id = None
        
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
        
        # Rate limiting for alerts
        self._last_alert_time = {}
    
    def set_agent_id(self, agent_id: str):
        """Set the agent ID for this communication instance"""
        self.agent_id = agent_id
        self.logger.info(f"🔧 Communication AgentID set: {agent_id}")
    
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
            
            # ALWAYS start periodic server detection task
            # This ensures we can detect connection loss and reconnect automatically
            if not hasattr(self, '_periodic_task_started'):
                self._periodic_task_started = True
                asyncio.create_task(self._periodic_server_detection())
                self.logger.info("🔄 Periodic server detection task started")
            
        except Exception as e:
            self.logger.error(f"❌ Communication initialization failed: {e}")
            self.offline_mode = True
            self._setup_offline_mode()
    
    def _setup_offline_mode(self):
        """Setup offline mode"""
        self.logger.info("🔄 Setting up offline mode...")
        self.offline_events_queue = []
        
        # Only start periodic detection task if not already started
        if not hasattr(self, '_periodic_task_started'):
            self._periodic_task_started = True
            asyncio.create_task(self._periodic_server_detection())
            self.logger.info("🔄 Periodic server detection task started")
    
    async def _periodic_server_detection(self):
        """Periodically check for server availability - CONTINUOUS RECONNECTION"""
        last_reconnection_attempt = 0
        reconnection_interval = 2  # Try every 2 seconds when offline
        
        while True:
            try:
                current_time = time.time()
                
                # If offline, continuously try to reconnect every 2 seconds
                if self.offline_mode:
                    if current_time - last_reconnection_attempt >= reconnection_interval:
                        self.logger.info("🔄 Attempting to reconnect to server...")
                        last_reconnection_attempt = current_time
                        
                        # Try force reconnection for more aggressive attempts
                        if await self.force_reconnection():
                            self.logger.info("✅ Successfully reconnected to server!")
                            await self._send_queued_events()
                        else:
                            self.logger.debug("📡 Reconnection failed - will try again in 2 seconds")
                    
                    # Sleep for a short time to avoid busy loop
                    await asyncio.sleep(0.5)
                
                # If online, check connection every 10 seconds
                else:
                    # Detect connection loss
                    await self._detect_connection_loss()
                    await asyncio.sleep(10)
                    
            except Exception as e:
                self.logger.debug(f"Periodic server detection error: {e}")
                await asyncio.sleep(2)  # Wait 2 seconds on error
    
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
        """Test connection to a specific server - FAST TIMEOUT"""
        try:
            host = server['host']
            port = server['port']
            
            # Test TCP connection with shorter timeout
            def test_tcp():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)  # Reduced from 2 to 1 second
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
    
    async def submit_event(self, event_data: EventData) -> tuple[bool, Optional[Dict], Optional[str]]:
        """
        Submit event to server - FIXED to return (success, response, error)
        """
        try:
            # FIXED: Test connection before sending
            if not await self.test_connection():
                self.logger.debug("📡 Server not connected - skipping event submission")
                return False, None, "Server not connected"
            
            if self.offline_mode:
                return False, None, "Server offline"
            
            if not self.working_server:
                return False, None, "No working server"
            
            # Convert event to payload
            payload = self._convert_event_to_payload(event_data)
            
            # FIXED: Handle case where payload conversion failed
            if payload is None:
                return False, None, "Event payload conversion failed - missing agent_id"
            
            # Send to server
            url = f"{self.base_url}/api/v1/events/submit"
            response = await self._make_request_with_retry('POST', url, payload)
            
            if response:
                # Update last successful connection time
                self.last_successful_connection = time.time()
                
                # Process server response for threat detection
                processed_response = self._process_server_response(response, event_data)
                return True, processed_response, None
            else:
                # FIXED: Mark as disconnected if no response
                self.logger.debug("📡 No response from server - marking as disconnected")
                return False, None, "No response from server"
                
        except Exception as e:
            return False, None, str(e)
    
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
            
            # CASE 1: Server trả về alerts_generated
            if 'alerts_generated' in response and response['alerts_generated']:
                alerts = response['alerts_generated']
                self.alerts_received_from_server += len(alerts)
                self.last_threat_detection = datetime.now()
                self.logger.warning(f"🚨 SERVER GENERATED {len(alerts)} ALERTS for {original_event.event_type}")
                self.logger.warning(f"   📋 Alert details: {alerts}")
                processed_response['threat_detected'] = True
                if not processed_response.get('risk_score'):
                    max_risk = max((alert.get('risk_score', 50) for alert in alerts), default=50)
                    processed_response['risk_score'] = max_risk
                return processed_response
            # CASE 2: Server trả về alerts array
            if 'alerts' in response and response['alerts']:
                alerts = response['alerts']
                self.alerts_received_from_server += len(alerts)
                self.last_threat_detection = datetime.now()
                self.logger.warning(f"🚨 SERVER SENT {len(alerts)} ALERTS for {original_event.event_type}")
                processed_response['threat_detected'] = True
                processed_response['alerts_generated'] = alerts
                return processed_response
            # CASE 3: Không có threat - normal response
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
        """Convert event data to API payload - FIXED to match server schema"""
        try:
            # FIXED: Validate agent_id is present
            if not event_data.agent_id:
                self.logger.error(f"❌ CRITICAL: Event missing agent_id - Type: {event_data.event_type}, Action: {event_data.event_action}")
                return None
            
            # Normalize severity to server format (Info, Low, Medium, High, Critical)
            severity_mapping = {
                'INFO': 'Info',
                'LOW': 'Low', 
                'MEDIUM': 'Medium',
                'HIGH': 'High',
                'CRITICAL': 'Critical',
                'Info': 'Info',
                'Low': 'Low',
                'Medium': 'Medium', 
                'High': 'High',
                'Critical': 'Critical'
            }
            normalized_severity = severity_mapping.get(event_data.severity, 'Info')
            
            # Normalize event_type to server format
            event_type_mapping = {
                'Process': 'Process',
                'File': 'File', 
                'Network': 'Network',
                'Registry': 'Registry',
                'Authentication': 'Authentication',
                'System': 'System'
            }
            normalized_event_type = event_type_mapping.get(event_data.event_type, 'System')
            
            payload = {
                # Core event fields - EXACTLY matching server schema
                'agent_id': event_data.agent_id,
                'event_type': normalized_event_type,
                'event_action': event_data.event_action,
                'event_timestamp': event_data.event_timestamp.isoformat(),
                'severity': normalized_severity,
                
                # Process fields - only if they exist
                'process_id': event_data.process_id,
                'process_name': event_data.process_name,
                'process_path': event_data.process_path,
                'command_line': event_data.command_line,
                'parent_pid': event_data.parent_pid,
                'parent_process_name': event_data.parent_process_name,
                'process_user': event_data.process_user,
                'process_hash': event_data.process_hash,
                
                # File fields - only if they exist
                'file_path': event_data.file_path,
                'file_name': event_data.file_name,
                'file_size': event_data.file_size,
                'file_hash': event_data.file_hash,
                'file_extension': event_data.file_extension,
                'file_operation': event_data.file_operation,
                
                # Network fields - only if they exist
                'source_ip': event_data.source_ip,
                'destination_ip': event_data.destination_ip,
                'source_port': event_data.source_port,
                'destination_port': event_data.destination_port,
                'protocol': event_data.protocol,
                'direction': event_data.direction,
                
                # Registry fields - only if they exist
                'registry_key': event_data.registry_key,
                'registry_value_name': event_data.registry_value_name,
                'registry_value_data': event_data.registry_value_data,
                'registry_operation': event_data.registry_operation,
                
                # Authentication fields - only if they exist
                'login_user': event_data.login_user,
                'login_type': event_data.login_type,
                'login_result': event_data.login_result,
                
                # Raw event data - only if it exists
                'raw_event_data': event_data.raw_event_data or {}
            }
            
            # Remove None values to avoid validation errors
            cleaned_payload = {}
            for key, value in payload.items():
                if value is not None:
                    cleaned_payload[key] = value
            
            # Debug logging for payload
            self.logger.debug(f"📦 EVENT PAYLOAD CREATED:")
            self.logger.debug(f"   🎯 Type: {cleaned_payload.get('event_type')}")
            self.logger.debug(f"   🔧 Action: {cleaned_payload.get('event_action')}")
            self.logger.debug(f"   📊 Severity: {cleaned_payload.get('severity')}")
            self.logger.debug(f"   🆔 Agent ID: {cleaned_payload.get('agent_id')}")
            self.logger.debug(f"   📋 Fields: {list(cleaned_payload.keys())}")
            
            return cleaned_payload
            
        except Exception as e:
            self.logger.error(f"❌ Event payload conversion failed: {e}")
            return {
                'agent_id': event_data.agent_id or 'unknown',
                'event_type': event_data.event_type or 'System',
                'event_action': event_data.event_action or 'Unknown',
                'event_timestamp': datetime.now().isoformat(),
                'severity': 'Info'
            }
    
    async def _make_request_with_retry(self, method: str, url: str, payload: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request with retry logic - FAST OFFLINE MODE"""
        # Allow testing connection even when offline (for reconnection attempts)
        if self.offline_mode and '/health' not in url and '/status' not in url:
            return None
        
        # Use shorter timeouts when trying to reconnect
        max_retries = 1 if self.offline_mode else self.max_retries
        retry_delay = 0.5 if self.offline_mode else self.retry_delay
        
        for attempt in range(max_retries + 1):
            try:
                self.connection_attempts += 1
                response = await self._make_request_internal(method, url, payload)
                
                if response is not None:
                    self.successful_connections += 1
                    self.last_successful_connection = time.time()
                    return response
                
            except Exception as e:
                self.failed_connections += 1
                
                # Check if it's a connection error
                if "Cannot connect to host" in str(e) or "Connection refused" in str(e):
                    # Immediately mark as offline on connection failure
                    self._mark_as_offline("Server connection refused")
                    break
                
                if attempt < max_retries:
                    await asyncio.sleep(retry_delay)
        
        # All attempts failed - mark as disconnected
        if not self.offline_mode:
            self._mark_as_offline("All request attempts failed")
        
        return None
    
    async def _make_request_internal(self, method: str, url: str, payload: Optional[Dict] = None, 
                                   timeout_override: Optional[float] = None) -> Optional[Dict]:
        """Internal method to make HTTP request"""
        # Allow testing connection even when offline (for reconnection attempts)
        if (self.offline_mode and '/health' not in url and '/status' not in url) or not self.session or self._session_closed:
            return None
        
        try:
            # Use shorter timeouts when offline for faster reconnection
            if timeout_override:
                timeout = aiohttp.ClientTimeout(total=timeout_override)
            elif self.offline_mode:
                # Very short timeouts when offline for quick reconnection attempts
                timeout = aiohttp.ClientTimeout(total=3, connect=1, sock_read=2)
            else:
                timeout = None
            
            # ADDED: Debug log for HTTP request
            self.logger.info(f"🌐 HTTP {method} REQUEST: {url}")
            if payload:
                self.logger.info(f"📦 PAYLOAD SIZE: {len(str(payload))} chars")
            
            if method.upper() == 'GET':
                async with self.session.get(url, timeout=timeout) as response:
                    # ADDED: Debug log for response status
                    self.logger.info(f"📡 HTTP RESPONSE: {response.status} - {url}")
                    return await self._handle_response(response)
                    
            elif method.upper() == 'POST':
                async with self.session.post(url, json=payload, timeout=timeout) as response:
                    # ADDED: Debug log for response status
                    self.logger.info(f"📡 HTTP RESPONSE: {response.status} - {url}")
                    return await self._handle_response(response)
                    
            else:
                raise Exception(f"Unsupported HTTP method: {method}")
                
        except asyncio.TimeoutError:
            self.logger.error(f"⏰ REQUEST TIMEOUT: {url}")
            raise asyncio.TimeoutError(f"Request timeout: {url}")
        except Exception as e:
            self.logger.error(f"❌ REQUEST ERROR: {url} - {e}")
            raise Exception(f"Request error: {e}")
    
    async def _handle_response(self, response: aiohttp.ClientResponse) -> Optional[Dict]:
        """Handle HTTP response"""
        try:
            # ADDED: Debug log for response handling
            self.logger.info(f"📥 HANDLING RESPONSE: Status={response.status}, Content-Type={response.headers.get('content-type', 'unknown')}")
            
            if response.status == 200:
                try:
                    data = await response.json()
                    # ADDED: Debug log for successful JSON response
                    self.logger.info(f"✅ JSON RESPONSE RECEIVED: {len(str(data))} chars")
                    return data
                except json.JSONDecodeError:
                    text = await response.text()
                    # ADDED: Debug log for text response
                    self.logger.info(f"📄 TEXT RESPONSE RECEIVED: {len(text)} chars")
                    if len(text) < 200:
                        return {'success': True, 'message': text}
                    return None
                    
            elif response.status == 422:
                # FIXED: Better handling of validation errors
                try:
                    error_data = await response.json()
                    self.logger.error(f"❌ VALIDATION ERROR (422):")
                    self.logger.error(f"   📋 Error: {error_data}")
                    if 'detail' in error_data:
                        self.logger.error(f"   🔍 Details: {error_data['detail']}")
                    return None
                except json.JSONDecodeError:
                    text = await response.text()
                    self.logger.error(f"❌ VALIDATION ERROR (422): {text}")
                    return None
                    
            elif response.status in [404, 405]:
                # ADDED: Debug log for 404/405 errors
                self.logger.error(f"❌ ENDPOINT NOT FOUND: {response.status} - {response.url}")
                return None
            elif response.status >= 500:
                text = await response.text()
                # ADDED: Debug log for server errors
                self.logger.error(f"❌ SERVER ERROR: {response.status} - {text[:200]}")
                raise Exception(f"Server error {response.status}: {text}")
            else:
                # ADDED: Debug log for other status codes
                text = await response.text()
                self.logger.warning(f"⚠️ UNEXPECTED STATUS: {response.status} - {text[:200]}")
                return None
                
        except Exception as e:
            self.logger.error(f"❌ Response handling error: {e}")
            return None
    
    async def register_agent(self, registration_data: AgentRegistrationData) -> Optional[Dict]:
        """Register agent with EDR server"""
        try:
            if not self.working_server:
                self.logger.warning("⚠️ No server available for registration")
                return None
            
            url = f"{self.base_url}/api/v1/agents/register"
            
            # Create registration payload with FIXED AgentVersion
            registration_payload = {
                'hostname': registration_data.hostname,
                'ip_address': registration_data.ip_address,
                'mac_address': registration_data.mac_address,
                'operating_system': registration_data.operating_system,
                'os_version': registration_data.os_version,
                'architecture': registration_data.architecture,
                'domain': registration_data.domain,
                'agent_version': '2.1.0',  # FIXED: Shortened version to avoid truncation
                'install_path': registration_data.install_path,
                'status': 'Active',
                'cpu_usage': 0.0,
                'memory_usage': 0.0,
                'disk_usage': 0.0,
                'network_latency': 0,
                'monitoring_enabled': True
            }
            
            response = await self._make_request_with_retry('POST', url, registration_payload)
            
            if response and response.get('agent_id'):
                self.logger.info(f"✅ Agent registered successfully: {response['agent_id']}")
                return response
            else:
                self.logger.error(f"❌ Agent registration failed: {response}")
                return None
                
        except Exception as e:
            self.logger.error(f"❌ Agent registration error: {e}")
            return None
    
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
            
            # Get alert_id from ack_data or generate one
            alert_id = ack_data.get('alert_id', 'unknown')
            url = f"{self.base_url}/api/v1/alerts/{alert_id}/acknowledge"
            
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
    
    def is_connected(self) -> bool:
        """Check if server is connected and responding"""
        try:
            # Check if we have a working server and are not in offline mode
            if not self.working_server or self.offline_mode:
                return False
            
            # Check if we have an active session
            if not self.session or self._session_closed:
                self.offline_mode = True
                return False
            
            # Check if we have recent successful connections
            if self.last_successful_connection:
                # Consider connected if we had a successful connection in the last 15 seconds
                time_since_last_success = time.time() - self.last_successful_connection
                if time_since_last_success < 15:  # Increased from 10 to 15 seconds
                    return True
                else:
                    # Connection is stale - mark as offline
                    self.offline_mode = True
                    return False
            
            # If no recent success, we're not connected
            self.offline_mode = True
            return False
            
        except Exception:
            self.offline_mode = True
            return False
    
    async def test_connection(self) -> bool:
        """Test actual connection to server - FAST TIMEOUT"""
        try:
            if not self.working_server:
                self.logger.debug("📡 No working server configured")
                return False
            
            self.logger.debug(f"📡 Testing HTTP connection to: {self.base_url}/health")
            
            # Try to make a simple health check request with short timeout
            response = await self._make_request_with_retry('GET', f"{self.base_url}/health")
            if response:
                self.last_successful_connection = time.time()
                self.logger.debug("📡 HTTP connection test successful")
                return True
            else:
                self.logger.debug("📡 HTTP connection test failed - no response")
                return False
            
        except Exception as e:
            self.logger.debug(f"📡 HTTP connection test error: {e}")
            return False
    
    async def attempt_reconnection(self) -> bool:
        """Attempt to reconnect to server - FAST AND AGGRESSIVE"""
        try:
            if self.offline_mode:
                # Try to reconnect immediately without waiting
                self.logger.debug("🔄 Attempting to reconnect to server...")
                
                # Test if server is available
                working_server = await self._detect_working_server()
                if working_server:
                    self.working_server = working_server
                    self.server_host = working_server['host']
                    self.server_port = working_server['port']
                    self.base_url = f"http://{self.server_host}:{self.server_port}"
                    
                    # Test connection with shorter timeout
                    if await self.test_connection():
                        self.offline_mode = False
                        self.logger.info("✅ Successfully reconnected to server")
                        return True
                    else:
                        self.logger.debug("📡 Server detected but not responding")
                        return False
                else:
                    self.logger.debug("📡 No server available for reconnection")
                    return False
            else:
                # If not in offline mode, try to detect server anyway
                working_server = await self._detect_working_server()
                if working_server:
                    self.working_server = working_server
                    self.server_host = working_server['host']
                    self.server_port = working_server['port']
                    self.base_url = f"http://{self.server_host}:{self.server_port}"
                    
                    if await self.test_connection():
                        self.logger.info("✅ Server connection verified")
                        return True
                    
        except Exception as e:
            self.logger.debug(f"Reconnection attempt failed: {e}")
            return False
        
        return False
    
    async def _detect_connection_loss(self):
        """Detect if connection is lost and update status immediately"""
        try:
            if self.offline_mode:
                return
            
            # Check if we have recent successful connections
            if self.last_successful_connection:
                time_since_last_success = time.time() - self.last_successful_connection
                if time_since_last_success > 15:  # More than 15 seconds since last success
                    self.logger.info("📡 Connection lost - entering offline mode")
                    self.offline_mode = True
                    return
            
            # If no recent success and we're not in offline mode, mark as offline
            if not self.last_successful_connection and not self.offline_mode:
                self.logger.info("📡 No recent connection - entering offline mode")
                self.offline_mode = True
                
        except Exception as e:
            self.logger.debug(f"Connection loss detection error: {e}")
            self.offline_mode = True
    
    def _mark_as_offline(self, reason: str = "Connection error"):
        """Immediately mark communication as offline"""
        if not self.offline_mode:
            self.logger.info(f"📡 {reason} - entering offline mode")
            self.offline_mode = True
    
    async def force_reconnection(self) -> bool:
        """Force reconnection attempt - bypass normal checks"""
        try:
            self.logger.debug("🔄 Force reconnection attempt...")
            
            # Clear any cached connection state
            self.last_successful_connection = None
            
            # Try to detect working server
            working_server = await self._detect_working_server()
            if working_server:
                self.working_server = working_server
                self.server_host = working_server['host']
                self.server_port = working_server['port']
                self.base_url = f"http://{self.server_host}:{self.server_port}"
                
                self.logger.debug(f"📡 Server detected: {self.base_url}")
                
                # Reinitialize the session for the new server
                await self.close()
                
                # Setup timeout configuration with longer timeouts for reconnection
                timeout = aiohttp.ClientTimeout(
                    total=10,  # Increased from 8 to 10 seconds
                    connect=3,  # Increased from 2 to 3 seconds
                    sock_read=5,  # Increased from 3 to 5 seconds
                    sock_connect=3  # Increased from 2 to 3 seconds
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
                
                self.logger.debug("📡 Session reinitialized, testing connection...")
                
                # Test connection with detailed logging
                try:
                    if await self.test_connection():
                        self.offline_mode = False
                        self.logger.info("✅ Force reconnection successful")
                        return True
                    else:
                        self.logger.debug("📡 Force reconnection failed - HTTP test failed")
                        return False
                except Exception as e:
                    self.logger.debug(f"📡 HTTP connection test error: {e}")
                    return False
            else:
                self.logger.debug("📡 Force reconnection failed - no server detected")
                return False
                
        except Exception as e:
            self.logger.debug(f"Force reconnection error: {e}")
            return False

    def show_rate_limited_alert(self, alert: Dict[str, Any], rate_limit_seconds: int = 30):
        """Show alert with rate limiting to prevent spam"""
        try:
            current_time = time.time()
            alert_key = f"{alert.get('title', 'Alert')}_{alert.get('severity', 'Unknown')}"
            
            # Check if we should show this alert (rate limit)
            if alert_key in self._last_alert_time:
                time_since_last = current_time - self._last_alert_time[alert_key]
                if time_since_last < rate_limit_seconds:
                    self.logger.debug(f"Rate limiting alert: {alert_key} (last shown {time_since_last:.1f}s ago)")
                    return False
            
            # Update last alert time
            self._last_alert_time[alert_key] = current_time
            
            # Show the alert
            self.logger.warning(f"[ALERT] {alert.get('title', 'Alert')}: {alert.get('description', '')} | Severity: {alert.get('severity', 'Unknown')}")
            title = alert.get('title', 'EDR Alert')
            message = f"{alert.get('description', '')} | Severity: {alert.get('severity', 'Unknown')}"
            print(f"[ALERT] {title}: {message}")
            return True
        except Exception as e:
            self.logger.error(f"[ALERT] Error displaying alert: {e}")
            return False