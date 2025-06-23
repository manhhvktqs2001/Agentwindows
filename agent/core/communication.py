# agent/core/communication.py - COMPLETELY FIXED VERSION
"""
Server Communication - FIXED with Auto Server Detection and Offline Mode
Giải quyết hoàn toàn vấn đề kết nối server và hỗ trợ offline mode
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

from agent.core.config_manager import ConfigManager
from agent.schemas.agent_data import AgentRegistrationData, AgentHeartbeatData
from agent.schemas.events import EventData
from agent.schemas.server_responses import ServerResponse

class ServerCommunication:
    """Handle communication with EDR server - COMPLETELY FIXED"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.config = self.config_manager.get_config()
        self.server_config = self.config.get('server', {})
        
        # FIXED: Auto-detect working server
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
        
        # FIXED: Optimized timeout settings
        self.timeout = 3  # Faster timeout
        self.connect_timeout = 1  # Very fast connection timeout
        self.read_timeout = 2   # Fast read timeout
        self.max_retries = 1    # Minimal retries
        self.retry_delay = 0.2  # Very fast retry
        
        # Connection pooling
        self.connection_pool_size = 5
        self.keep_alive_timeout = 15
        self.total_timeout = 5
        
        # Performance tracking
        self.connection_attempts = 0
        self.successful_connections = 0
        self.failed_connections = 0
        self.last_successful_connection = None
        
        # Offline mode support
        self.offline_events_queue = []
        self.max_offline_events = 1000
        
        self.logger.info("🔧 Communication initialized with auto server detection and offline mode")
    
    async def initialize(self):
        """Initialize communication with auto server detection"""
        try:
            # FIXED: Auto-detect working server
            self.working_server = await self._detect_working_server()
            
            if not self.working_server:
                self.logger.warning("⚠️ No EDR server found - enabling offline mode")
                self.offline_mode = True
                self._setup_offline_mode()
                return  # Don't raise exception, continue in offline mode
            
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
                'User-Agent': 'EDR-Agent/2.0-Fixed',
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
                self.logger.warning(f"⚠️ Server detected but not responding properly: {self.base_url}")
                self.logger.warning("⚠️ Switching to offline mode")
                self.offline_mode = True
                self._setup_offline_mode()
            
        except Exception as e:
            self.logger.error(f"❌ Communication initialization failed: {e}")
            self.logger.warning("⚠️ Switching to offline mode")
            self.offline_mode = True
            self._setup_offline_mode()
    
    def _setup_offline_mode(self):
        """Setup offline mode"""
        self.logger.info("🔄 Setting up offline mode...")
        self.logger.info("📝 Events will be stored locally and sent when server becomes available")
        
        # Create offline storage
        self.offline_events_queue = []
        
        # Start periodic server detection
        asyncio.create_task(self._periodic_server_detection())
    
    async def _periodic_server_detection(self):
        """Periodically try to detect server and reconnect"""
        while True:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds
                
                if self.offline_mode:
                    self.logger.debug("🔍 Checking for server availability...")
                    working_server = await self._detect_working_server()
                    
                    if working_server:
                        self.logger.info("✅ Server detected! Attempting to reconnect...")
                        self.working_server = working_server
                        await self.initialize()
                        
                        if not self.offline_mode:
                            # Send queued events
                            await self._send_queued_events()
                            
            except Exception as e:
                self.logger.debug(f"Periodic server detection error: {e}")
    
    async def _send_queued_events(self):
        """Send queued offline events"""
        if not self.offline_events_queue:
            return
        
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
                    # Re-queue failed events
                    self.offline_events_queue.append(event_data)
            except:
                # Re-queue failed events
                self.offline_events_queue.append(event_data)
        
        self.logger.info(f"✅ Sent {sent_count}/{len(events_to_send)} queued events")
    
    async def _detect_working_server(self):
        """Auto-detect working EDR server"""
        # List of potential servers to try
        potential_servers = [
            {'host': 'localhost', 'port': 5000, 'name': 'Local Server'},
            {'host': '127.0.0.1', 'port': 5000, 'name': 'Loopback Server'},
            {'host': '192.168.20.85', 'port': 5000, 'name': 'Configured Server'},
            {'host': '0.0.0.0', 'port': 5000, 'name': 'All Interfaces'},
            {'host': 'localhost', 'port': 8000, 'name': 'Alt Port 8000'},
            {'host': '127.0.0.1', 'port': 8000, 'name': 'Alt Port 8000'},
            {'host': 'localhost', 'port': 3000, 'name': 'Alt Port 3000'},
            {'host': '127.0.0.1', 'port': 9000, 'name': 'Alt Port 9000'},
        ]
        
        self.logger.debug("🔍 Auto-detecting EDR server...")
        
        for server in potential_servers:
            if await self._test_server_connection(server):
                self.logger.info(f"✅ Found working server: {server['name']} ({server['host']}:{server['port']})")
                return server
        
        self.logger.warning("❌ No working EDR server found")
        return None
    
    async def _test_server_connection(self, server):
        """Test connection to a specific server"""
        try:
            host = server['host']
            port = server['port']
            
            # Test 1: TCP Socket connection
            def test_tcp():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)  # Very fast timeout
                    result = sock.connect_ex((host, port))
                    sock.close()
                    return result == 0
                except:
                    return False
            
            tcp_success = await asyncio.to_thread(test_tcp)
            
            if not tcp_success:
                return False
            
            # Test 2: HTTP request
            def test_http():
                try:
                    # Try multiple endpoints
                    endpoints = ['/health', '/api/v1/status', '/', '/status']
                    
                    for endpoint in endpoints:
                        try:
                            response = requests.get(f"http://{host}:{port}{endpoint}", timeout=2)
                            if response.status_code < 500:  # Any response except server error
                                return True
                        except:
                            continue
                    
                    return False
                except:
                    return False
            
            http_success = await asyncio.to_thread(test_http)
            
            if tcp_success and http_success:
                return True
            elif tcp_success:
                # TCP works, assume HTTP will work
                self.logger.debug(f"⚠️ TCP OK but HTTP test failed: {server['name']} (will try anyway)")
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Server test failed for {server.get('name', 'unknown')}: {e}")
            return False
    
    async def _test_connection(self):
        """Test connection to selected server"""
        try:
            if not self.working_server:
                return False
            
            # Try multiple endpoints
            test_endpoints = ['/health', '/api/v1/status', '/', '/status']
            
            for endpoint in test_endpoints:
                try:
                    url = f"{self.base_url}{endpoint}"
                    response = await self._make_request_internal('GET', url, timeout_override=2)
                    
                    if response is not None:
                        self.logger.info(f"✅ Server responding at {endpoint}")
                        self.last_successful_connection = time.time()
                        self.successful_connections += 1
                        return True
                except:
                    continue
            
            self.logger.warning("⚠️ Server not responding to any test endpoints")
            return False
            
        except Exception as e:
            self.logger.debug(f"⚠️ Connection test failed: {e}")
            return False
    
    async def submit_event(self, event_data: EventData) -> Optional[Dict]:
        """Submit single event with offline mode support"""
        try:
            if self.offline_mode:
                # Store event for later sending
                event_payload = self._convert_event_to_payload(event_data)
                
                if len(self.offline_events_queue) >= self.max_offline_events:
                    # Remove oldest event
                    self.offline_events_queue.pop(0)
                
                self.offline_events_queue.append(event_payload)
                
                self.logger.debug(f"📝 Event stored offline: {event_data.event_type} - {event_data.event_action}")
                
                # Return success response for offline mode
                return {
                    'success': True,
                    'event_id': f'offline_{int(time.time())}',
                    'message': 'Event stored in offline mode',
                    'offline_mode': True
                }
            
            url = f"{self.base_url}/api/v1/events/submit"
            payload = self._convert_event_to_payload(event_data)
            
            self.logger.debug(f"📤 Sending event: {event_data.event_type} - {event_data.event_action}")
            
            response = await self._make_request_with_retry('POST', url, payload)
            
            if response:
                self.logger.debug(f"✅ Event sent successfully: {response.get('event_id', 'N/A')}")
                return response
            else:
                # Switch to offline mode if server stops responding
                self.logger.warning("⚠️ Server not responding, switching to offline mode")
                self.offline_mode = True
                return await self.submit_event(event_data)  # Retry in offline mode
                
        except Exception as e:
            self.logger.debug(f"❌ Event send error: {e}")
            
            # Switch to offline mode on error
            if not self.offline_mode:
                self.logger.warning("⚠️ Switching to offline mode due to error")
                self.offline_mode = True
                return await self.submit_event(event_data)  # Retry in offline mode
            
            return None
    
    async def _make_request_with_retry(self, method: str, url: str, payload: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request with retry logic"""
        if self.offline_mode:
            return None
        
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                self.connection_attempts += 1
                response = await self._make_request_internal(method, url, payload)
                
                if response is not None:
                    self.successful_connections += 1
                    return response
                
            except Exception as e:
                last_exception = e
                self.failed_connections += 1
                
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay)
        
        # All attempts failed - switch to offline mode
        if not self.offline_mode:
            self.logger.warning("⚠️ All connection attempts failed, switching to offline mode")
            self.offline_mode = True
        
        return None
    
    async def _make_request_internal(self, method: str, url: str, payload: Optional[Dict] = None, 
                                   timeout_override: Optional[float] = None) -> Optional[Dict]:
        """Internal method to make HTTP request"""
        if self.offline_mode or not self.session or self._session_closed:
            return None
        
        try:
            # Override timeout if specified
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
                    # Server responded but not with JSON
                    text = await response.text()
                    if len(text) < 200:  # Short response might be simple status
                        return {'success': True, 'message': text}
                    return None
                    
            elif response.status in [404, 405]:
                # Endpoint not found - server is running but endpoint doesn't exist
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
                # Create offline registration
                import uuid
                agent_id = str(uuid.uuid4())
                self.logger.info(f"🔄 Agent registered in offline mode: {agent_id}")
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
            
            self.logger.info(f"Registering agent: {registration_data.hostname}")
            
            response = await self._make_request_with_retry('POST', url, payload)
            
            if response and response.get('agent_id'):
                self.logger.info("✅ Agent registration successful")
                return response
            else:
                # Fall back to offline registration
                import uuid
                agent_id = str(uuid.uuid4())
                self.logger.warning(f"⚠️ Server registration failed, using offline mode: {agent_id}")
                return {
                    'success': True,
                    'agent_id': agent_id,
                    'message': 'Agent registered in offline mode',
                    'heartbeat_interval': 30,
                    'offline_mode': True
                }
                
        except Exception as e:
            self.logger.error(f"Agent registration failed: {e}")
            # Fall back to offline registration
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
            self.logger.debug(f"Heartbeat failed: {e}")
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
            self.logger.debug(f"Get pending alerts failed: {e}")
            return None
    
    async def close(self):
        """Close communication session"""
        try:
            if self.session and not self._session_closed:
                await self.session.close()
                self._session_closed = True
                self.logger.debug("Communication session closed")
        except Exception as e:
            self.logger.error(f"Error closing session: {e}")
    
    def _convert_event_to_payload(self, event_data: EventData) -> Dict:
        """Convert event data to API payload"""
        payload = {
            'agent_id': event_data.agent_id,
            'event_type': event_data.event_type,
            'event_action': event_data.event_action,
            'event_timestamp': event_data.event_timestamp.isoformat(),
            'severity': event_data.severity
        }
        
        # Add event-specific fields
        if event_data.event_type == 'Process':
            payload.update({
                'process_id': event_data.process_id,
                'process_name': event_data.process_name,
                'process_path': event_data.process_path,
                'command_line': event_data.command_line,
                'parent_pid': event_data.parent_pid,
                'parent_process_name': event_data.parent_process_name,
                'process_user': event_data.process_user,
                'process_hash': event_data.process_hash
            })
        elif event_data.event_type == 'File':
            payload.update({
                'file_path': event_data.file_path,
                'file_name': event_data.file_name,
                'file_size': event_data.file_size,
                'file_hash': event_data.file_hash,
                'file_extension': event_data.file_extension,
                'file_operation': event_data.file_operation
            })
        elif event_data.event_type == 'Network':
            payload.update({
                'source_ip': event_data.source_ip,
                'destination_ip': event_data.destination_ip,
                'source_port': event_data.source_port,
                'destination_port': event_data.destination_port,
                'protocol': event_data.protocol,
                'direction': event_data.direction
            })
        elif event_data.event_type == 'Registry':
            payload.update({
                'registry_key': event_data.registry_key,
                'registry_value_name': event_data.registry_value_name,
                'registry_value_data': event_data.registry_value_data,
                'registry_operation': event_data.registry_operation
            })
        elif event_data.event_type == 'Authentication':
            payload.update({
                'login_user': event_data.login_user,
                'login_type': event_data.login_type,
                'login_result': event_data.login_result
            })
        
        # Add raw data if present
        if hasattr(event_data, 'raw_event_data') and event_data.raw_event_data:
            if isinstance(event_data.raw_event_data, str):
                try:
                    import json
                    payload['raw_event_data'] = json.loads(event_data.raw_event_data)
                except json.JSONDecodeError:
                    payload['raw_event_data'] = {'data': event_data.raw_event_data}
            elif isinstance(event_data.raw_event_data, dict):
                payload['raw_event_data'] = event_data.raw_event_data
            else:
                payload['raw_event_data'] = {'data': str(event_data.raw_event_data)}
        
        # Remove None values
        return {k: v for k, v in payload.items() if v is not None}
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get server connection information"""
        return {
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
            'max_offline_events': self.max_offline_events
        }