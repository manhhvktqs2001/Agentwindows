# agent/core/communication.py - TIMEOUT FIXED VERSION
"""
Server Communication - TIMEOUT FIXED + Enhanced Connection Management
Giải quyết vấn đề timeout và connection overload
"""

import aiohttp
import asyncio
import logging
import json
import time
from typing import Optional, Dict, List, Any
from datetime import datetime

from agent.core.config_manager import ConfigManager
from agent.schemas.agent_data import AgentRegistrationData, AgentHeartbeatData
from agent.schemas.events import EventData
from agent.schemas.server_responses import ServerResponse

class ServerCommunication:
    """Handle communication with EDR server - TIMEOUT FIXED"""
    
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
        
        # TIMEOUT FIX: Increased timeouts and better retry logic
        self.timeout = 10  # INCREASED: From 2 to 10 seconds
        self.connect_timeout = 5  # INCREASED: Connection timeout
        self.read_timeout = 8   # INCREASED: Read timeout
        self.max_retries = 2    # INCREASED: More retries
        self.retry_delay = 1    # Retry delay
        
        # TIMEOUT FIX: Enhanced connection pooling
        self.connection_pool_size = 50  # INCREASED: More connections
        self.keep_alive_timeout = 60    # INCREASED: Keep alive longer
        self.total_timeout = 15         # INCREASED: Total operation timeout
        
        # TIMEOUT FIX: Rate limiting to prevent server overload
        self.rate_limit_requests = 100   # Max requests per second
        self.rate_limit_window = 1       # 1 second window
        self.request_timestamps = []
        self.rate_limit_enabled = True
        
        # Agent ID for alert acknowledgment
        self.agent_id = None
        
        # TIMEOUT FIX: Performance tracking
        self.immediate_requests = 0
        self.failed_immediate_requests = 0
        self.timeout_count = 0
        self.retry_count = 0
        
        # TIMEOUT FIX: Request queue for managing load
        self.request_queue = asyncio.Queue(maxsize=1000)
        self.queue_processor_task = None
        
    async def initialize(self):
        """Initialize communication session with TIMEOUT FIX"""
        try:
            # Close existing session if any
            await self.close()
            
            # TIMEOUT FIX: Enhanced timeout configuration
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
                'User-Agent': 'EDR-Agent/2.0-TimeoutFixed',
                'Connection': 'keep-alive',
                'Accept': 'application/json'
            }
            
            # TIMEOUT FIX: Enhanced connector with better limits
            connector = aiohttp.TCPConnector(
                limit=self.connection_pool_size,
                limit_per_host=self.connection_pool_size,
                ttl_dns_cache=300,
                use_dns_cache=True,
                keepalive_timeout=self.keep_alive_timeout,
                enable_cleanup_closed=True,
                force_close=False,  # Don't force close connections
                ssl=False  # Disable SSL for better performance
            )
            
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
                connector=connector,
                raise_for_status=False  # Handle status manually
            )
            self._session_closed = False
            
            # TIMEOUT FIX: Start queue processor for managing requests
            self.queue_processor_task = asyncio.create_task(self._process_request_queue())
            
            # Test connection to server with retry
            await self._test_connection_with_retry()
            
            self.logger.info(f"🚀 TIMEOUT FIXED Communication initialized: {self.base_url}")
            
        except Exception as e:
            self.logger.error(f"Communication initialization failed: {e}")
            raise
    
    async def _process_request_queue(self):
        """Process request queue to manage server load"""
        try:
            while not self._session_closed:
                try:
                    # Get request from queue with timeout
                    request_data = await asyncio.wait_for(
                        self.request_queue.get(), 
                        timeout=1.0
                    )
                    
                    # Process the request
                    if request_data:
                        method, url, payload, future = request_data
                        
                        try:
                            result = await self._make_request_internal(method, url, payload)
                            future.set_result(result)
                        except Exception as e:
                            future.set_exception(e)
                        finally:
                            self.request_queue.task_done()
                
                except asyncio.TimeoutError:
                    continue  # Continue processing
                except Exception as e:
                    self.logger.error(f"Request queue processing error: {e}")
                    await asyncio.sleep(0.1)
                    
        except Exception as e:
            self.logger.error(f"Request queue processor failed: {e}")
    
    async def _test_connection_with_retry(self):
        """Test connection to server with retry mechanism"""
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                url = f"{self.base_url}/health"
                response = await self._make_request_internal('GET', url, timeout_override=5)
                
                if response is not None:
                    self.logger.info(f"✅ Server connection test successful (attempt {attempt + 1})")
                    return
                else:
                    self.logger.warning(f"⚠️ Server connection test failed (attempt {attempt + 1})")
                    
            except Exception as e:
                self.logger.warning(f"Server connection test error (attempt {attempt + 1}): {e}")
                
            if attempt < max_attempts - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        self.logger.warning("⚠️ Server connection test failed after all attempts")
    
    async def close(self):
        """Close communication session properly"""
        try:
            if self.queue_processor_task:
                self.queue_processor_task.cancel()
                
            if self.session and not self._session_closed:
                await self.session.close()
                self._session_closed = True
                self.logger.info("Communication session closed")
        except Exception as e:
            self.logger.error(f"Error closing session: {e}")
    
    async def submit_event(self, event_data: EventData) -> Optional[Dict]:
        """Submit single event with TIMEOUT FIX"""
        try:
            # TIMEOUT FIX: Check rate limit
            if self.rate_limit_enabled and not self._check_rate_limit():
                self.logger.warning("⚠️ Rate limit exceeded, queueing request")
                await asyncio.sleep(0.1)  # Brief delay
            
            url = f"{self.base_url}/api/v1/events/submit"
            payload = self._convert_event_to_payload(event_data)
            
            # ENHANCED LOGGING: Log event submission
            self.logger.info(f"📤 SENDING EVENT: Type={event_data.event_type}, Action={event_data.event_action}, "
                           f"Severity={event_data.severity}, Agent={event_data.agent_id}")
            
            # TIMEOUT FIX: Use enhanced request with retry
            start_time = time.time()
            response = await self._make_request_with_retry('POST', url, payload)
            end_time = time.time()
            
            if response:
                self.immediate_requests += 1
                response_time = (end_time - start_time) * 1000
                self.logger.info(f"✅ EVENT SENT SUCCESSFULLY: Type={event_data.event_type}, "
                               f"Response time: {response_time:.1f}ms, Event ID: {response.get('event_id', 'N/A')}")
                
                # Update rate limiting
                self._update_rate_limit_tracker()
                
                return response
            else:
                self.failed_immediate_requests += 1
                self.logger.warning(f"❌ EVENT SEND FAILED: Type={event_data.event_type}, Action={event_data.event_action}")
                return None
                
        except Exception as e:
            self.failed_immediate_requests += 1
            self.logger.error(f"❌ EVENT SEND ERROR: Type={event_data.event_type}, Error: {e}")
            return None
    
    async def _make_request_with_retry(self, method: str, url: str, payload: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request with enhanced retry logic"""
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                # TIMEOUT FIX: Use queue for high-frequency requests
                if attempt == 0 and not self.request_queue.full():
                    try:
                        future = asyncio.Future()
                        await self.request_queue.put((method, url, payload, future))
                        result = await asyncio.wait_for(future, timeout=self.timeout)
                        return result
                    except asyncio.TimeoutError:
                        self.logger.warning(f"⚠️ Queue request timeout for {url}")
                        # Fall back to direct request
                    except Exception as e:
                        self.logger.debug(f"Queue request failed: {e}")
                        # Fall back to direct request
                
                # Direct request as fallback
                response = await self._make_request_internal(method, url, payload)
                
                if response is not None:
                    if attempt > 0:
                        self.retry_count += 1
                        self.logger.info(f"✅ Request succeeded on attempt {attempt + 1}")
                    return response
                
            except asyncio.TimeoutError as e:
                self.timeout_count += 1
                last_exception = e
                self.logger.warning(f"🚨 Request timeout (attempt {attempt + 1}/{self.max_retries + 1}): {url}")
                
            except aiohttp.ClientError as e:
                last_exception = e
                self.logger.warning(f"🚨 Client error (attempt {attempt + 1}/{self.max_retries + 1}): {e}")
                
            except Exception as e:
                last_exception = e
                self.logger.error(f"🚨 Request error (attempt {attempt + 1}/{self.max_retries + 1}): {e}")
            
            # Wait before retry with exponential backoff
            if attempt < self.max_retries:
                wait_time = self.retry_delay * (2 ** attempt)
                self.logger.debug(f"⏳ Waiting {wait_time}s before retry...")
                await asyncio.sleep(wait_time)
        
        # All attempts failed
        self.logger.error(f"❌ Request failed after {self.max_retries + 1} attempts: {last_exception}")
        return None
    
    async def _make_request_internal(self, method: str, url: str, payload: Optional[Dict] = None, 
                                   timeout_override: Optional[float] = None) -> Optional[Dict]:
        """Internal method to make HTTP request"""
        if not self.session or self._session_closed:
            await self.initialize()
        
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
                    
            elif method.upper() == 'PUT':
                async with self.session.put(url, json=payload, timeout=timeout) as response:
                    return await self._handle_response(response)
            else:
                raise Exception(f"Unsupported HTTP method: {method}")
                
        except asyncio.TimeoutError:
            raise asyncio.TimeoutError(f"Request timeout: {url}")
        except aiohttp.ClientError as e:
            raise aiohttp.ClientError(f"Client error: {e}")
        except Exception as e:
            raise Exception(f"Request error: {e}")
    
    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits"""
        try:
            current_time = time.time()
            
            # Remove old timestamps
            self.request_timestamps = [
                ts for ts in self.request_timestamps 
                if current_time - ts < self.rate_limit_window
            ]
            
            # Check if we're over the limit
            return len(self.request_timestamps) < self.rate_limit_requests
            
        except Exception as e:
            self.logger.error(f"Rate limit check error: {e}")
            return True  # Allow if check fails
    
    def _update_rate_limit_tracker(self):
        """Update rate limit tracking"""
        try:
            self.request_timestamps.append(time.time())
        except Exception as e:
            self.logger.error(f"Rate limit tracker update error: {e}")
    
    async def submit_event_batch(self, agent_id: str, events: List[EventData]) -> Optional[Dict]:
        """Submit batch of events with TIMEOUT FIX"""
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
            
            # TIMEOUT FIX: Use enhanced request with retry
            start_time = time.time()
            response = await self._make_request_with_retry('POST', url, payload)
            end_time = time.time()
            
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
            
            response = await self._make_request_with_retry('POST', url, payload)
            
            if response and response.get('agent_id'):
                self.agent_id = response['agent_id']
                self.logger.info("🚀 Agent registration successful - Enhanced communication ready")
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
            
            response = await self._make_request_with_retry('POST', url, payload)
            return response
            
        except Exception as e:
            self.logger.error(f"Heartbeat failed: {e}")
            return None
    
    async def get_pending_alerts(self, agent_id: str) -> Optional[Dict]:
        """Get pending alert notifications from server"""
        try:
            url = f"{self.base_url}/api/v1/agents/{agent_id}/pending-alerts"
            response = await self._make_request_with_retry('GET', url)
            
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
    
    async def _handle_response(self, response: aiohttp.ClientResponse) -> Optional[Dict]:
        """Handle HTTP response with enhanced error handling"""
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
        """Get server connection information with timeout stats"""
        return {
            'host': self.server_host,
            'port': self.server_port,
            'base_url': self.base_url,
            'timeout': self.timeout,
            'connect_timeout': self.connect_timeout,
            'read_timeout': self.read_timeout,
            'max_retries': self.max_retries,
            'auth_configured': bool(self.auth_token),
            'session_active': self.session is not None and not self._session_closed,
            'agent_id': self.agent_id,
            'timeout_fixed': True,
            'immediate_requests': self.immediate_requests,
            'failed_immediate_requests': self.failed_immediate_requests,
            'timeout_count': self.timeout_count,
            'retry_count': self.retry_count,
            'connection_pool_size': self.connection_pool_size,
            'rate_limit_enabled': self.rate_limit_enabled,
            'queue_size': self.request_queue.qsize() if self.request_queue else 0,
            'success_rate': (self.immediate_requests / max(self.immediate_requests + self.failed_immediate_requests, 1)) * 100
        }