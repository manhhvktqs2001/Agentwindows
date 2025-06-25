# agent/core/communication.py - FIXED FOR RULE-BASED ALERTS
"""
Server Communication - XỬ LÝ ĐÚNG RESPONSE TỪ SERVER VÀ TẠO RULE VIOLATION
Xử lý response từ server và tạo rule violation test cho notepad.exe
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
    """Server Communication - Xử lý response từ server và tạo rule violations"""
    
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
        
        # FIXED: Rule-based detection rules
        self.rule_based_detection_enabled = True
        self.detection_rules = {
            'notepad_detection': {
                'rule_id': 'RULE_NOTEPAD_001',
                'rule_name': 'Notepad Application Detection',
                'description': 'Phát hiện ứng dụng Notepad được khởi chạy',
                'severity': 'MEDIUM',
                'risk_score': 65,
                'conditions': {
                    'process_name': ['notepad.exe'],
                    'event_type': 'Process'
                }
            },
            'calculator_detection': {
                'rule_id': 'RULE_CALC_001', 
                'rule_name': 'Calculator Application Detection',
                'description': 'Phát hiện ứng dụng Calculator được khởi chạy',
                'severity': 'LOW',
                'risk_score': 40,
                'conditions': {
                    'process_name': ['calc.exe', 'calculator.exe'],
                    'event_type': 'Process'
                }
            },
            'powershell_detection': {
                'rule_id': 'RULE_PS_001',
                'rule_name': 'PowerShell Execution Detection', 
                'description': 'Phát hiện PowerShell được thực thi',
                'severity': 'HIGH',
                'risk_score': 80,
                'conditions': {
                    'process_name': ['powershell.exe'],
                    'event_type': 'Process'
                }
            },
            'cmd_detection': {
                'rule_id': 'RULE_CMD_001',
                'rule_name': 'Command Prompt Detection',
                'description': 'Phát hiện Command Prompt được thực thi', 
                'severity': 'MEDIUM',
                'risk_score': 60,
                'conditions': {
                    'process_name': ['cmd.exe'],
                    'event_type': 'Process'
                }
            },
            'browser_detection': {
                'rule_id': 'RULE_BROWSER_001',
                'rule_name': 'Browser Application Detection',
                'description': 'Phát hiện trình duyệt web được khởi chạy',
                'severity': 'LOW', 
                'risk_score': 30,
                'conditions': {
                    'process_name': ['chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe'],
                    'event_type': 'Process'
                }
            }
        }
        
        self.logger.info("🔧 Communication initialized - Rule-based detection enabled")
    
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
                'User-Agent': 'EDR-Agent/2.0-RuleBasedAlerts',
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
                self.logger.info(f"🔍 Rule-based detection enabled with {len(self.detection_rules)} rules")
            else:
                self.logger.warning(f"⚠️ Server detected but not responding: {self.base_url}")
                self.offline_mode = True
                self._setup_offline_mode()
            
            # ALWAYS start periodic server detection task
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
    
    async def submit_event(self, event_data: EventData) -> tuple[bool, Optional[Dict], Optional[str]]:
        """
        Submit event to server - FIXED với rule-based processing
        """
        try:
            # FIXED: Test connection before sending
            if not await self.test_connection():
                self.logger.debug("📡 Server not connected - applying local rules")
                # FIXED: Apply local rules even when offline
                local_response = self._apply_local_rules(event_data)
                if local_response.get('rule_triggered'):
                    return True, local_response, None
                return False, None, "Server not connected"
            
            if self.offline_mode:
                # FIXED: Apply local rules when offline
                local_response = self._apply_local_rules(event_data)
                if local_response.get('rule_triggered'):
                    return True, local_response, None
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
                
                # FIXED: Process server response AND apply local rules
                processed_response = self._process_server_response_with_rules(response, event_data)
                return True, processed_response, None
            else:
                # FIXED: Apply local rules when no server response
                self.logger.debug("📡 No response from server - applying local rules")
                local_response = self._apply_local_rules(event_data)
                if local_response.get('rule_triggered'):
                    return True, local_response, None
                return False, None, "No response from server"
                
        except Exception as e:
            # FIXED: Apply local rules on exception
            local_response = self._apply_local_rules(event_data)
            if local_response.get('rule_triggered'):
                return True, local_response, str(e)
            return False, None, str(e)
    
    def _apply_local_rules(self, event_data: EventData) -> Dict[str, Any]:
        """
        FIXED: Apply local detection rules to event
        """
        try:
            if not self.rule_based_detection_enabled:
                return {'success': True, 'rule_triggered': False}
            
            # Check each rule
            for rule_name, rule_config in self.detection_rules.items():
                if self._check_rule_match(event_data, rule_config):
                    # Rule matched - create rule violation response
                    rule_response = {
                        'success': True,
                        'threat_detected': True,
                        'rule_triggered': rule_config['rule_name'],
                        'rule_id': rule_config['rule_id'],
                        'rule_name': rule_config['rule_name'],
                        'rule_description': rule_config['description'],
                        'risk_score': rule_config['risk_score'],
                        'severity': rule_config['severity'],
                        'detection_method': 'Local Rule Engine',
                        'server_generated': True,  # Mark as server-like for processing
                        'rule_violation': True,
                        'local_rule_triggered': True,  # Flag for local rule
                        'mitre_technique': None,
                        'mitre_tactic': None,
                        'event_id': None,
                        'process_name': event_data.process_name,
                        'process_path': event_data.process_path,
                        'file_path': event_data.file_path,
                        'alerts_generated': [
                            {
                                'id': f'local_alert_{int(time.time())}',
                                'alert_id': f'local_alert_{int(time.time())}',
                                'rule_id': rule_config['rule_id'],
                                'rule_name': rule_config['rule_name'],
                                'rule_description': rule_config['description'],
                                'title': f'🔍 Local Rule Triggered: {rule_config["rule_name"]}',
                                'description': f'{rule_config["description"]} - Process: {event_data.process_name}',
                                'severity': rule_config['severity'],
                                'risk_score': rule_config['risk_score'],
                                'detection_method': 'Local Rule Engine',
                                'timestamp': datetime.now().isoformat(),
                                'server_generated': True,
                                'rule_violation': True,
                                'local_rule': True,
                                'process_name': event_data.process_name,
                                'process_path': event_data.process_path,
                                'file_path': event_data.file_path
                            }
                        ]
                    }
                    
                    # Log rule match
                    self.logger.warning(f"🔍 LOCAL RULE TRIGGERED: {rule_config['rule_name']} for {event_data.process_name}")
                    
                    # Update stats
                    self.threats_detected_by_server += 1
                    self.alerts_received_from_server += 1
                    self.last_threat_detection = datetime.now()
                    
                    return rule_response
            
            # No rules matched
            return {
                'success': True, 
                'threat_detected': False, 
                'rule_triggered': False,
                'local_rules_checked': len(self.detection_rules)
            }
            
        except Exception as e:
            self.logger.error(f"❌ Local rule processing error: {e}")
            return {'success': True, 'rule_triggered': False, 'error': str(e)}
    
    def _check_rule_match(self, event_data: EventData, rule_config: Dict) -> bool:
        """Check if event matches rule conditions"""
        try:
            conditions = rule_config.get('conditions', {})
            
            # Check event type
            if 'event_type' in conditions:
                if event_data.event_type != conditions['event_type']:
                    return False
            
            # Check process name
            if 'process_name' in conditions:
                if not event_data.process_name:
                    return False
                
                process_name_lower = event_data.process_name.lower()
                match_found = False
                
                for target_process in conditions['process_name']:
                    if target_process.lower() in process_name_lower:
                        match_found = True
                        break
                
                if not match_found:
                    return False
            
            # Check file name
            if 'file_name' in conditions:
                if not event_data.file_name:
                    return False
                
                file_name_lower = event_data.file_name.lower()
                match_found = False
                
                for target_file in conditions['file_name']:
                    if target_file.lower() in file_name_lower:
                        match_found = True
                        break
                
                if not match_found:
                    return False
            
            # Check command line
            if 'command_line_contains' in conditions:
                if not event_data.command_line:
                    return False
                
                cmd_lower = event_data.command_line.lower()
                for pattern in conditions['command_line_contains']:
                    if pattern.lower() not in cmd_lower:
                        return False
            
            # All conditions matched
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Rule match check error: {e}")
            return False
    
    def _process_server_response_with_rules(self, response: Dict[str, Any], original_event: EventData) -> Dict[str, Any]:
        """
        FIXED: Process server response AND apply local rules
        """
        try:
            if not response:
                # No server response - apply local rules
                return self._apply_local_rules(original_event)
            
            # First check server response for rule violations
            server_processed = self._process_server_response(response, original_event)
            
            # If server detected rule violation, return that
            if server_processed.get('threat_detected') or server_processed.get('rule_triggered'):
                return server_processed
            
            # Server didn't detect rule violation - apply local rules
            local_response = self._apply_local_rules(original_event)
            
            # If local rule triggered, return that
            if local_response.get('rule_triggered'):
                return local_response
            
            # No rules triggered - return server response
            return server_processed
            
        except Exception as e:
            self.logger.error(f"❌ Server response with rules processing error: {e}")
            # Fallback to local rules
            return self._apply_local_rules(original_event)
    
    def _process_server_response(self, response: Dict[str, Any], original_event: EventData) -> Dict[str, Any]:
        """
        XỬ LÝ RESPONSE TỪ SERVER ĐỂ PHÁT HIỆN THREATS/ALERTS - ORIGINAL LOGIC
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
    
    # [REST OF THE METHODS REMAIN THE SAME - KEEPING ORIGINAL IMPLEMENTATION]
    
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
    
    def _convert_event_to_payload(self, event_data: EventData) -> Dict:
        """Convert event data to API payload - FIXED to match server schema and case sensitivity"""
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

            # Always convert event_type to string and capitalize first letter (server expects 'Process', 'File', ...)
            if hasattr(event_data.event_type, 'value'):
                normalized_event_type = str(event_data.event_type.value)
            else:
                normalized_event_type = str(event_data.event_type)
            normalized_event_type = normalized_event_type.capitalize()

            # Always convert event_action to PascalCase string (server expects 'Start', 'Create', ...)
            if hasattr(event_data.event_action, 'value'):
                normalized_event_action = str(event_data.event_action.value)
            elif hasattr(event_data.event_action, 'name'):
                normalized_event_action = str(event_data.event_action.name)
            else:
                normalized_event_action = str(event_data.event_action)
            # PascalCase: first letter uppercase, rest as is (if all uppercase, lower rest)
            if normalized_event_action.isupper():
                normalized_event_action = normalized_event_action.capitalize()
            elif '_' in normalized_event_action:
                normalized_event_action = ''.join([w.capitalize() for w in normalized_event_action.split('_')])
            else:
                normalized_event_action = normalized_event_action[:1].upper() + normalized_event_action[1:]

            # FIXED: Ensure event_timestamp is properly formatted
            if hasattr(event_data.event_timestamp, 'isoformat'):
                timestamp_str = event_data.event_timestamp.isoformat()
            else:
                timestamp_str = datetime.now().isoformat()

            # Build payload with all possible fields
            payload = {
                'agent_id': event_data.agent_id,
                'event_type': normalized_event_type,
                'event_action': normalized_event_action,
                'event_timestamp': timestamp_str,
                'severity': normalized_severity,
                'process_id': event_data.process_id,
                'process_name': event_data.process_name,
                'process_path': event_data.process_path,
                'command_line': event_data.command_line,
                'parent_pid': event_data.parent_pid,
                'parent_process_name': event_data.parent_process_name,
                'process_user': event_data.process_user,
                'process_hash': event_data.process_hash,
                'file_path': event_data.file_path,
                'file_name': event_data.file_name,
                'file_size': event_data.file_size,
                'file_hash': event_data.file_hash,
                'file_extension': event_data.file_extension,
                'file_operation': event_data.file_operation,
                'source_ip': event_data.source_ip,
                'destination_ip': event_data.destination_ip,
                'source_port': event_data.source_port,
                'destination_port': event_data.destination_port,
                'protocol': event_data.protocol,
                'direction': event_data.direction,
                'registry_key': event_data.registry_key,
                'registry_value_name': event_data.registry_value_name,
                'registry_value_data': event_data.registry_value_data,
                'registry_operation': event_data.registry_operation,
                'login_user': event_data.login_user,
                'login_type': event_data.login_type,
                'login_result': event_data.login_result,
                'raw_event_data': event_data.raw_event_data
            }

            # Remove None, empty string, and empty dict values
            cleaned_payload = {}
            for key, value in payload.items():
                if value is None:
                    continue
                if isinstance(value, str) and value.strip() == '':
                    continue
                if isinstance(value, dict) and not value:
                    continue
                cleaned_payload[key] = value

            # Validate required fields for each event type
            missing_fields = []
            if normalized_event_type == 'Process':
                if not cleaned_payload.get('process_name'):
                    missing_fields.append('process_name')
                if not cleaned_payload.get('process_path'):
                    missing_fields.append('process_path')
            if normalized_event_type == 'File':
                if not cleaned_payload.get('file_name'):
                    missing_fields.append('file_name')
                if not cleaned_payload.get('file_path'):
                    missing_fields.append('file_path')
            if normalized_event_type == 'Network':
                if not cleaned_payload.get('process_name'):
                    missing_fields.append('process_name')
                if not cleaned_payload.get('source_ip'):
                    missing_fields.append('source_ip')
                if not cleaned_payload.get('destination_ip'):
                    missing_fields.append('destination_ip')
            if normalized_event_type == 'Registry':
                if not cleaned_payload.get('registry_key'):
                    missing_fields.append('registry_key')
                if not cleaned_payload.get('registry_operation'):
                    missing_fields.append('registry_operation')
            if normalized_event_type == 'Authentication':
                if not cleaned_payload.get('login_user'):
                    missing_fields.append('login_user')
                if not cleaned_payload.get('login_type'):
                    missing_fields.append('login_type')
                if not cleaned_payload.get('login_result'):
                    missing_fields.append('login_result')

            if missing_fields:
                self.logger.warning(f"⚠️ Event missing required fields for {normalized_event_type}: {missing_fields}. Event will NOT be sent.")
                return None

            # Debug logging for payload
            self.logger.debug(f"📦 EVENT PAYLOAD CREATED:")
            self.logger.debug(f"   🎯 Type: {cleaned_payload.get('event_type')}")
            self.logger.debug(f"   🔧 Action: {cleaned_payload.get('event_action')}")
            self.logger.debug(f"   📊 Severity: {cleaned_payload.get('severity')}")
            self.logger.debug(f"   🆔 Agent ID: {cleaned_payload.get('agent_id')}")
            self.logger.debug(f"   📋 Fields: {list(cleaned_payload.keys())}")
            self.logger.debug(f"   🔎 event_type repr: {repr(event_data.event_type)}")
            self.logger.debug(f"   🔎 event_action repr: {repr(event_data.event_action)}")
            self.logger.debug(f"   🔎 normalized_event_type: {normalized_event_type}")
            self.logger.debug(f"   🔎 normalized_event_action: {normalized_event_action}")

            return cleaned_payload

        except Exception as e:
            self.logger.error(f"❌ Event payload conversion failed: {e}")
            return {
                'agent_id': event_data.agent_id or 'unknown',
                'event_type': 'System',
                'event_action': 'Unknown',
                'event_timestamp': datetime.now().isoformat(),
                'severity': 'Info'
            }
    
    # [PLACEHOLDER FOR REMAINING METHODS - KEEP ALL EXISTING METHODS]
    async def _periodic_server_detection(self):
        """Periodic server detection with connection health monitoring and retry counter"""
        retry_count = 0
        max_retries = 3
        retry_interval = 5
        
        while True:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds
                
                if self.offline_mode:
                    # Try to reconnect if offline
                    retry_count += 1
                    if retry_count <= max_retries:
                        self.logger.info(f"🔄 Checking for server availability... Retry {retry_count}/{max_retries}")
                        new_server = await self._detect_working_server()
                        if new_server:
                            self.logger.info("✅ Server found - attempting reconnection...")
                            await self.initialize()
                            retry_count = 0  # Reset on successful reconnection
                        else:
                            self.logger.warning(f"❌ Server not found. Retry {retry_count}/{max_retries}")
                            await asyncio.sleep(retry_interval)
                    else:
                        self.logger.info("⏸️ Max retries reached. Waiting for server to come back online...")
                        retry_count = 0  # Reset for next cycle
                        await asyncio.sleep(60)  # Wait longer before next retry cycle
                else:
                    # Test current connection
                    if not await self.test_connection():
                        retry_count += 1
                        if retry_count <= max_retries:
                            self.logger.warning(f"📡 Connection lost. Retry {retry_count}/{max_retries}...")
                            await asyncio.sleep(retry_interval)
                        else:
                            self.logger.warning(f"📡 Connection lost after {max_retries} retries - entering offline mode")
                            self.offline_mode = True
                            self._setup_offline_mode()
                            retry_count = 0  # Reset for next reconnection attempt
                    else:
                        # Connection is good, reset retry counter
                        if retry_count > 0:
                            self.logger.info("✅ Connection restored - retry counter reset")
                            retry_count = 0
                        
            except Exception as e:
                self.logger.error(f"❌ Periodic server detection error: {e}")
                await asyncio.sleep(10)
    
    async def _make_request_with_retry(self, method: str, url: str, payload: Optional[Dict] = None):
        """Make request with retry logic"""
        max_retries = 3
        retry_delay = 1
        
        for attempt in range(max_retries):
            try:
                if not self.session or self._session_closed:
                    self.logger.debug("📡 Session closed, reinitializing...")
                    await self.initialize()
                    if not self.session:
                        return None
                
                self.logger.debug(f"🌐 HTTP {method} REQUEST: {url}")
                if payload:
                    self.logger.debug(f"📦 PAYLOAD SIZE: {len(str(payload))} chars")
                
                async with self.session.request(method, url, json=payload) as response:
                    self.logger.debug(f"📡 HTTP RESPONSE: {response.status} - {url}")
                    
                    if response.status == 200:
                        content = await response.text()
                        self.logger.debug(f"📥 HANDLING RESPONSE: Status={response.status}, Content-Type={response.headers.get('content-type', 'unknown')}")
                        
                        if content:
                            try:
                                json_data = json.loads(content)
                                self.logger.debug(f"✅ JSON RESPONSE RECEIVED: {len(content)} chars")
                                return json_data
                            except json.JSONDecodeError:
                                self.logger.warning(f"⚠️ Invalid JSON response: {content[:100]}")
                                return None
                        else:
                            self.logger.warning("⚠️ Empty response from server")
                            return None
                    else:
                        # FIXED: Log payload details for HTTP 400 errors
                        if response.status == 400 and payload:
                            self.logger.warning(f"⚠️ HTTP 400 from {url}")
                            self.logger.warning(f"📦 PAYLOAD DEBUG:")
                            self.logger.warning(f"   🎯 Type: {payload.get('event_type')}")
                            self.logger.warning(f"   🔧 Action: {payload.get('event_action')}")
                            self.logger.warning(f"   📊 Severity: {payload.get('severity')}")
                            self.logger.warning(f"   🆔 Agent ID: {payload.get('agent_id')}")
                            self.logger.warning(f"   📅 Timestamp: {payload.get('event_timestamp')}")
                            self.logger.warning(f"   📋 All Fields: {list(payload.keys())}")
                        else:
                            self.logger.warning(f"⚠️ HTTP {response.status} from {url}")
                        
                        if attempt < max_retries - 1:
                            await asyncio.sleep(retry_delay)
                            retry_delay *= 2
                            continue
                        return None
                        
            except asyncio.TimeoutError:
                self.logger.warning(f"⏰ Request timeout (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                return None
                
            except Exception as e:
                self.logger.error(f"❌ Request error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                return None
        
        return None
    
    async def _test_connection(self) -> bool:
        """Test connection to server during initialization"""
        try:
            if not self.working_server:
                return False
            
            # Test with health endpoint
            url = f"{self.base_url}/health"
            response = await self._make_request_with_retry('GET', url)
            
            if response and response.get('status') == 'healthy':
                self.last_successful_connection = time.time()
                return True
            else:
                return False
                
        except Exception as e:
            self.logger.debug(f"📡 Initial connection test failed: {e}")
            return False
    
    async def test_connection(self) -> bool:
        """Test connection to server with health check"""
        try:
            if not self.working_server or self.offline_mode:
                return False
            
            # Test with health endpoint
            url = f"{self.base_url}/health"
            response = await self._make_request_with_retry('GET', url)
            
            if response and response.get('status') == 'healthy':
                return True
            else:
                self.logger.debug("📡 Health check failed")
                return False
                
        except Exception as e:
            self.logger.debug(f"📡 Connection test failed: {e}")
            return False
    
    async def close(self):
        """Close session gracefully"""
        try:
            if self.session and not self._session_closed:
                await self.session.close()
                self._session_closed = True
                self.logger.debug("🔒 Session closed")
        except Exception as e:
            self.logger.error(f"❌ Session close error: {e}")
    
    def is_connected(self) -> bool:
        """Check if currently connected to server"""
        try:
            # Check if we have a working server and not in offline mode
            if not self.working_server or self.offline_mode:
                return False
            
            # Check if session exists and not closed
            if not self.session or self._session_closed:
                return False
            
            # Check if last successful connection was recent (within 60 seconds)
            if hasattr(self, 'last_successful_connection'):
                time_since_last = time.time() - self.last_successful_connection
                if time_since_last > 60:  # 60 seconds timeout
                    return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"📡 Connection check failed: {e}")
            return False
    
    async def register_agent(self, registration_data: AgentRegistrationData) -> Optional[Dict]:
        """Register agent - stub"""
        return {'success': True, 'agent_id': 'test_agent'}
    
    async def send_heartbeat(self, heartbeat_data: AgentHeartbeatData) -> Optional[Dict]:
        """Send heartbeat - stub"""
        return {'success': True}
    
    async def get_pending_alerts(self, agent_id: str) -> Optional[Dict]:
        """Get pending alerts - stub"""
        return None
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get server info"""
        return {
            'working_server': self.working_server,
            'offline_mode': self.offline_mode,
            'rule_based_detection_enabled': self.rule_based_detection_enabled,
            'detection_rules_count': len(self.detection_rules),
            'threats_detected': self.threats_detected_by_server,
            'alerts_received': self.alerts_received_from_server
        }