# agent/core/communication.py - MODIFIED FOR ZERO DELAY
"""
Server Communication - ZERO DELAY Support
Enhanced with immediate event submission
"""

import aiohttp
import asyncio
import logging
import json
from typing import Optional, Dict, List, Any
from datetime import datetime

from agent.core.config_manager import ConfigManager
from agent.schemas.agent_data import AgentRegistrationData, AgentHeartbeatData
from agent.schemas.events import EventData
from agent.schemas.server_responses import ServerResponse

class ServerCommunication:
    """Handle communication with EDR server - ZERO DELAY Support"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.config = self.config_manager.get_config()
        self.server_config = self.config.get('server', {})
        
        # Server settings
        self.server_host = self.server_config.get('host', '192.168.20.85')
        self.server_port = self.server_config.get('port', 5000)
        self.base_url = f"http://{self.server_host}:{self.server_port}"
        
        # Authentication
        self.auth_token = self.server_config.get('auth_token', 'edr_agent_auth_2024')
        
        # HTTP session
        self.session: Optional[aiohttp.ClientSession] = None
        self._session_closed = False
        
        # ZERO DELAY: Optimized connection settings
        self.timeout = 5  # MODIFIED: Reduced from 30 to 5 seconds for immediate response
        self.max_retries = 1  # MODIFIED: Reduced retries for immediate processing
        self.retry_delay = 1  # MODIFIED: Reduced retry delay
        
        # ZERO DELAY: Connection pooling for immediate processing
        self.connection_pool_size = 20  # INCREASED: More connections for immediate processing
        self.keep_alive_timeout = 30
        
        # Agent ID for alert acknowledgment
        self.agent_id = None
        
        # ZERO DELAY: Performance tracking
        self.immediate_requests = 0
        self.failed_immediate_requests = 0
        
    async def initialize(self):
        """Initialize communication session with ZERO DELAY optimization"""
        try:
            # Close existing session if any
            await self.close()
            
            # ZERO DELAY: Optimized session configuration
            timeout = aiohttp.ClientTimeout(
                total=self.timeout,
                connect=2,  # Quick connection timeout
                sock_read=3  # Quick read timeout
            )
            
            # Setup headers
            headers = {
                'Content-Type': 'application/json',
                'X-Agent-Token': self.auth_token,
                'User-Agent': 'EDR-Agent/2.0-ZeroDelay',
                'Connection': 'keep-alive'  # Keep connections alive for immediate reuse
            }
            
            # ZERO DELAY: Optimized connector
            connector = aiohttp.TCPConnector(
                limit=self.connection_pool_size,  # More connections
                limit_per_host=self.connection_pool_size,
                ttl_dns_cache=300,
                use_dns_cache=True,
                keepalive_timeout=self.keep_alive_timeout,
                enable_cleanup_closed=True
            )
            
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
                connector=connector
            )
            self._session_closed = False
            
            # Test connection to server
            await self._test_connection()
            
            self.logger.info(f"🚀 ZERO DELAY Communication initialized: {self.base_url}")
            
        except Exception as e:
            self.logger.error(f"Communication initialization failed: {e}")
            raise
    
    async def _test_connection(self):
        """Test connection to server with immediate response check"""
        try:
            # Test basic connectivity to server
            url = f"{self.base_url}/health"
            response = await self._make_request('GET', url)
            
            if response:
                self.logger.debug("🚀 Server connection test successful - Ready for immediate transmission")
            else:
                self.logger.warning("Server connection test failed - immediate transmission may be affected")
                
        except Exception as e:
            self.logger.warning(f"Server connection test failed: {e}")
    
    async def close(self):
        """Close communication session properly"""
        try:
            if self.session and not self._session_closed:
                await self.session.close()
                self._session_closed = True
                self.logger.info("Communication session closed")
        except Exception as e:
            self.logger.error(f"Error closing session: {e}")
    
    async def submit_event(self, event_data: EventData) -> Optional[Dict]:
        """Submit single event IMMEDIATELY - ZERO DELAY"""
        try:
            url = f"{self.base_url}/api/v1/events/submit"
            
            payload = self._convert_event_to_payload(event_data)
            
            # ENHANCED LOGGING: Log event submission
            self.logger.info(f"📤 SENDING EVENT: Type={event_data.event_type}, Action={event_data.event_action}, "
                           f"Severity={event_data.severity}, Agent={event_data.agent_id}")
            
            # ZERO DELAY: Send immediately with minimal retry
            start_time = asyncio.get_event_loop().time()
            response = await self._make_immediate_request('POST', url, payload)
            end_time = asyncio.get_event_loop().time()
            
            if response:
                self.immediate_requests += 1
                response_time = (end_time - start_time) * 1000  # Convert to milliseconds
                self.logger.info(f"✅ EVENT SENT SUCCESSFULLY: Type={event_data.event_type}, "
                               f"Response time: {response_time:.1f}ms, Event ID: {response.get('event_id', 'N/A')}")
                return response
            else:
                self.failed_immediate_requests += 1
                self.logger.warning(f"❌ EVENT SEND FAILED: Type={event_data.event_type}, Action={event_data.event_action}")
                return None
                
        except Exception as e:
            self.failed_immediate_requests += 1
            self.logger.error(f"❌ EVENT SEND ERROR: Type={event_data.event_type}, Error: {e}")
            return None
    
    async def submit_event_batch(self, agent_id: str, events: List[EventData]) -> Optional[Dict]:
        """Submit batch of events - MODIFIED for immediate processing"""
        try:
            url = f"{self.base_url}/api/v1/events/batch"
            
            event_payloads = [self._convert_event_to_payload(event) for event in events]
            
            payload = {
                'agent_id': agent_id,
                'events': event_payloads
            }
            
            # ENHANCED LOGGING: Log batch submission
            event_types = [event.event_type for event in events]
            self.logger.info(f"📤 SENDING BATCH: {len(events)} events, Types={list(set(event_types))}, Agent={agent_id}")
            
            # ZERO DELAY: Use immediate request for batch as well
            start_time = asyncio.get_event_loop().time()
            response = await self._make_immediate_request('POST', url, payload)
            end_time = asyncio.get_event_loop().time()
            
            if response:
                response_time = (end_time - start_time) * 1000
                self.logger.info(f"✅ BATCH SENT SUCCESSFULLY: {len(events)} events, "
                               f"Response time: {response_time:.1f}ms, "
                               f"Processed: {response.get('processed_events', 'N/A')}")
                return response
            else:
                self.logger.warning(f"❌ BATCH SEND FAILED: {len(events)} events, Agent={agent_id}")
                return None
                
        except Exception as e:
            self.logger.error(f"❌ BATCH SEND ERROR: {len(events)} events, Error: {e}")
            return None
    
    async def register_agent(self, registration_data: AgentRegistrationData) -> Optional[Dict]:
        """Register agent with server"""
        try:
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
            
            response = await self._make_request('POST', url, payload)
            
            if response and response.get('agent_id'):
                self.agent_id = response['agent_id']
                self.logger.info("🚀 Agent registration successful - Ready for immediate transmission")
                return response
            else:
                raise Exception("Registration failed - no response")
                
        except Exception as e:
            self.logger.error(f"Agent registration failed: {e}")
            raise
    
    async def send_heartbeat(self, heartbeat_data: AgentHeartbeatData) -> Optional[Dict]:
        """Send heartbeat to server"""
        try:
            url = f"{self.base_url}/api/v1/agents/heartbeat"
            
            payload = {
                'hostname': heartbeat_data.hostname,
                'status': heartbeat_data.status,
                'cpu_usage': heartbeat_data.cpu_usage,
                'memory_usage': heartbeat_data.memory_usage,
                'disk_usage': heartbeat_data.disk_usage,
                'network_latency': heartbeat_data.network_latency
            }
            
            response = await self._make_request('POST', url, payload)
            return response
            
        except Exception as e:
            self.logger.error(f"Heartbeat failed: {e}")
            return None
    
    async def get_pending_alerts(self, agent_id: str) -> Optional[Dict]:
        """Get pending alert notifications from server"""
        try:
            url = f"{self.base_url}/api/v1/agents/{agent_id}/pending-alerts"
            response = await self._make_request('GET', url)
            
            if response and response.get('success'):
                alert_count = response.get('alert_count', 0)
                if alert_count > 0:
                    self.logger.warning(f"🚨 Received {alert_count} pending alerts from server")
                return response
            else:
                self.logger.debug("No pending alerts from server")
                return None
                
        except Exception as e:
            self.logger.error(f"Get pending alerts failed: {e}")
            return None
    
    async def acknowledge_alert(self, alert_id: str, status: str = "acknowledged", 
                              details: Dict[str, Any] = None) -> Optional[Dict]:
        """Acknowledge alert receipt IMMEDIATELY"""
        try:
            url = f"{self.base_url}/api/v1/alerts/{alert_id}/acknowledge"
            
            payload = {
                'alert_id': alert_id,
                'status': status,
                'acknowledged_at': datetime.now().isoformat(),
                'acknowledged_by': 'agent',
                'agent_id': self.agent_id,
                'details': details or {},
                'client_timestamp': datetime.now().isoformat()
            }
            
            self.logger.info(f"🚀 Acknowledging alert immediately: {alert_id} - {status}")
            
            # ZERO DELAY: Use immediate request for alert acknowledgment
            response = await self._make_immediate_request('POST', url, payload)
            
            if response and response.get('success'):
                self.logger.debug(f"🚀 Alert acknowledged immediately: {alert_id}")
                return response
            else:
                self.logger.warning(f"🚨 Immediate alert acknowledgment failed: {alert_id}")
                return None
                
        except Exception as e:
            self.logger.error(f"🚨 Alert acknowledgment error: {e}")
            return None
    
    async def _make_immediate_request(self, method: str, url: str, payload: Optional[Dict] = None) -> Optional[Dict]:
        """Make immediate HTTP request with minimal retry - ZERO DELAY"""
        if not self.session or self._session_closed:
            await self.initialize()
        
        try:
            if method.upper() == 'GET':
                async with self.session.get(url) as response:
                    return await self._handle_response(response)
            elif method.upper() == 'POST':
                async with self.session.post(url, json=payload) as response:
                    return await self._handle_response(response)
            elif method.upper() == 'PUT':
                async with self.session.put(url, json=payload) as response:
                    return await self._handle_response(response)
            else:
                raise Exception(f"Unsupported HTTP method: {method}")
                
        except asyncio.TimeoutError:
            self.logger.warning(f"🚨 Immediate request timeout: {url}")
            return None
        except aiohttp.ClientError as e:
            self.logger.warning(f"🚨 Immediate request failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"🚨 Immediate request error: {e}")
            return None
    
    async def _make_request(self, method: str, url: str, payload: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request with retry logic - Standard method"""
        if not self.session or self._session_closed:
            await self.initialize()
        
        for attempt in range(self.max_retries):
            try:
                if method.upper() == 'GET':
                    async with self.session.get(url) as response:
                        return await self._handle_response(response)
                elif method.upper() == 'POST':
                    async with self.session.post(url, json=payload) as response:
                        return await self._handle_response(response)
                elif method.upper() == 'PUT':
                    async with self.session.put(url, json=payload) as response:
                        return await self._handle_response(response)
                else:
                    raise Exception(f"Unsupported HTTP method: {method}")
                    
            except aiohttp.ClientError as e:
                self.logger.warning(f"Request failed (attempt {attempt + 1}/{self.max_retries}): {e}")
                
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay)
                else:
                    raise Exception(f"Request failed after {self.max_retries} attempts: {e}")
                    
            except Exception as e:
                self.logger.error(f"Unexpected request error: {e}")
                raise
        
        return None
    
    async def _handle_response(self, response: aiohttp.ClientResponse) -> Optional[Dict]:
        """Handle HTTP response"""
        try:
            if response.status == 200:
                try:
                    data = await response.json()
                    return data
                except json.JSONDecodeError:
                    text = await response.text()
                    self.logger.warning(f"Invalid JSON response: {text}")
                    return None
                    
            elif response.status == 401:
                raise Exception("Authentication failed - invalid token")
            elif response.status == 403:
                raise Exception("Access denied - check network permissions")
            elif response.status == 404:
                raise Exception("Server endpoint not found")
            elif response.status == 429:
                self.logger.warning("Rate limit exceeded")
                await asyncio.sleep(self.retry_delay)
                return None
            elif response.status >= 500:
                text = await response.text()
                raise Exception(f"Server error {response.status}: {text}")
            else:
                text = await response.text()
                self.logger.warning(f"Unexpected response {response.status}: {text}")
                return None
                
        except Exception as e:
            self.logger.error(f"Response handling error: {e}")
            raise
    
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
        """Get server connection information with ZERO DELAY stats"""
        return {
            'host': self.server_host,
            'port': self.server_port,
            'base_url': self.base_url,
            'timeout': self.timeout,
            'max_retries': self.max_retries,
            'auth_configured': bool(self.auth_token),
            'session_active': self.session is not None and not self._session_closed,
            'agent_id': self.agent_id,
            'zero_delay_enabled': True,
            'immediate_requests': self.immediate_requests,
            'failed_immediate_requests': self.failed_immediate_requests,
            'connection_pool_size': self.connection_pool_size,
            'immediate_success_rate': (self.immediate_requests / max(self.immediate_requests + self.failed_immediate_requests, 1)) * 100
        }

    async def send_alert_acknowledgment(self, alert_id: int, acknowledgment_data: Dict) -> Optional[Dict]:
        """Send alert acknowledgment to server"""
        try:
            url = f"{self.base_url}/api/v1/alerts/acknowledge/{alert_id}"
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=acknowledgment_data) as response:
                    if response.status == 200:
                        result = await response.json()
                        self.logger.info(f"✅ Alert acknowledgment sent: {alert_id}")
                        return result
                    else:
                        self.logger.warning(f"⚠️ Alert acknowledgment failed: {response.status}")
                        return None
                        
        except Exception as e:
            self.logger.error(f"❌ Alert acknowledgment error: {e}")
            return None
    
    async def submit_alert(self, alert_data: Dict) -> Optional[Dict]:
        """Submit alert from agent to server"""
        try:
            url = f"{self.base_url}/api/v1/alerts/submit-from-agent"
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=alert_data) as response:
                    if response.status == 200:
                        result = await response.json()
                        self.logger.info(f"✅ Alert submitted to server: {result.get('alert_id')}")
                        return result
                    else:
                        self.logger.warning(f"⚠️ Alert submission failed: {response.status}")
                        return None
                        
        except Exception as e:
            self.logger.error(f"❌ Alert submission error: {e}")
            return None
    
    async def check_for_alerts(self) -> List[Dict]:
        """Check for pending alerts from server"""
        try:
            url = f"{self.base_url}/api/v1/alerts/pending"
            params = {'agent_id': self.agent_id}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        result = await response.json()
                        alerts = result.get('alerts', [])
                        if alerts:
                            self.logger.info(f"📋 Found {len(alerts)} pending alerts")
                        return alerts
                    else:
                        return []
                        
        except Exception as e:
            self.logger.debug(f"Alert check error: {e}")
            return []