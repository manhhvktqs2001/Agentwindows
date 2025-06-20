# agent/core/communication.py
"""
Server Communication - Handle all communication with EDR server
"""

import aiohttp
import asyncio
import logging
import json
from typing import Optional, Dict, List, Any
from datetime import datetime

from .config_manager import ConfigManager
from ..schemas.agent_data import AgentRegistrationData, AgentHeartbeatData
from ..schemas.events import EventData
from ..schemas.server_responses import ServerResponse

class ServerCommunication:
    """Handle communication with EDR server"""
    
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
        
        # Connection settings
        self.timeout = self.server_config.get('timeout', 30)
        self.max_retries = self.server_config.get('max_retries', 3)
        self.retry_delay = self.server_config.get('retry_delay', 5)
        
    async def initialize(self):
        """Initialize communication session"""
        try:
            # Create session with timeout
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            # Setup headers
            headers = {
                'Content-Type': 'application/json',
                'X-Agent-Token': self.auth_token,
                'User-Agent': 'EDR-Agent/1.0'
            }
            
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers
            )
            
            self.logger.info(f"✅ Communication initialized: {self.base_url}")
            
        except Exception as e:
            self.logger.error(f"❌ Communication initialization failed: {e}")
            raise
    
    async def close(self):
        """Close communication session"""
        if self.session:
            await self.session.close()
            self.logger.info("🔌 Communication session closed")
    
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
            
            self.logger.info(f"📡 Registering agent: {registration_data.hostname}")
            
            response = await self._make_request('POST', url, payload)
            
            if response:
                self.logger.info("✅ Agent registration successful")
                return response
            else:
                raise Exception("Registration failed - no response")
                
        except Exception as e:
            self.logger.error(f"❌ Agent registration failed: {e}")
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
            self.logger.error(f"❌ Heartbeat failed: {e}")
            return None
    
    async def submit_event(self, event_data: EventData) -> Optional[Dict]:
        """Submit single event to server"""
        try:
            url = f"{self.base_url}/api/v1/events/submit"
            
            payload = self._convert_event_to_payload(event_data)
            
            response = await self._make_request('POST', url, payload)
            
            if response:
                self.logger.debug(f"📤 Event submitted: {event_data.event_type}")
                return response
            else:
                self.logger.warning("⚠️ Event submission failed")
                return None
                
        except Exception as e:
            self.logger.error(f"❌ Event submission error: {e}")
            return None
    
    async def submit_event_batch(self, agent_id: str, events: List[EventData]) -> Optional[Dict]:
        """Submit batch of events to server"""
        try:
            url = f"{self.base_url}/api/v1/events/batch"
            
            event_payloads = [self._convert_event_to_payload(event) for event in events]
            
            payload = {
                'agent_id': agent_id,
                'events': event_payloads
            }
            
            response = await self._make_request('POST', url, payload)
            
            if response:
                self.logger.info(f"📤 Event batch submitted: {len(events)} events")
                return response
            else:
                self.logger.warning("⚠️ Event batch submission failed")
                return None
                
        except Exception as e:
            self.logger.error(f"❌ Event batch submission error: {e}")
            return None
    
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
            payload['raw_event_data'] = event_data.raw_event_data
        
        # Remove None values
        return {k: v for k, v in payload.items() if v is not None}
    
    async def get_agent_config(self, agent_id: str) -> Optional[Dict]:
        """Get agent configuration from server"""
        try:
            url = f"{self.base_url}/api/v1/agents/{agent_id}/config"
            
            response = await self._make_request('GET', url)
            
            if response:
                self.logger.info("✅ Agent configuration retrieved")
                return response
            else:
                self.logger.warning("⚠️ Failed to get agent configuration")
                return None
                
        except Exception as e:
            self.logger.error(f"❌ Get config error: {e}")
            return None
    
    async def check_server_health(self) -> bool:
        """Check server health"""
        try:
            url = f"{self.base_url}/health"
            
            response = await self._make_request('GET', url)
            
            if response and response.get('status') in ['healthy', 'running']:
                return True
            else:
                return False
                
        except Exception:
            return False
    
    async def discover_server(self) -> Optional[Dict]:
        """Discover server capabilities"""
        try:
            url = f"{self.base_url}/api/discover"
            
            response = await self._make_request('GET', url)
            return response
            
        except Exception as e:
            self.logger.error(f"❌ Server discovery failed: {e}")
            return None
    
    async def _make_request(self, method: str, url: str, payload: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request with retry logic"""
        if not self.session:
            raise Exception("Session not initialized")
        
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
                self.logger.warning(f"⚠️ Request failed (attempt {attempt + 1}/{self.max_retries}): {e}")
                
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay)
                else:
                    raise Exception(f"Request failed after {self.max_retries} attempts: {e}")
                    
            except Exception as e:
                self.logger.error(f"❌ Unexpected request error: {e}")
                raise
        
        return None
    
    async def _handle_response(self, response: aiohttp.ClientResponse) -> Optional[Dict]:
        """Handle HTTP response"""
        try:
            # Check status code
            if response.status == 200:
                try:
                    data = await response.json()
                    return data
                except json.JSONDecodeError:
                    text = await response.text()
                    self.logger.warning(f"⚠️ Invalid JSON response: {text}")
                    return None
                    
            elif response.status == 401:
                raise Exception("Authentication failed - invalid token")
            elif response.status == 403:
                raise Exception("Access denied - check network permissions")
            elif response.status == 404:
                raise Exception("Server endpoint not found")
            elif response.status == 429:
                self.logger.warning("⚠️ Rate limit exceeded")
                await asyncio.sleep(self.retry_delay)
                return None
            elif response.status >= 500:
                text = await response.text()
                raise Exception(f"Server error {response.status}: {text}")
            else:
                text = await response.text()
                self.logger.warning(f"⚠️ Unexpected response {response.status}: {text}")
                return None
                
        except Exception as e:
            self.logger.error(f"❌ Response handling error: {e}")
            raise
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get server connection information"""
        return {
            'host': self.server_host,
            'port': self.server_port,
            'base_url': self.base_url,
            'timeout': self.timeout,
            'max_retries': self.max_retries,
            'auth_configured': bool(self.auth_token)
        }