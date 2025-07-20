# agent/collectors/network_collector.py - ENHANCED FOR REVERSE SHELL DETECTION
"""
Enhanced Network Collector - Phát hiện reverse shell và kết nối mã độc
Thu thập và phân tích tất cả kết nối mạng để phát hiện mã độc điều khiển từ xa
"""

import psutil
import socket
import asyncio
import logging
import time
import json
import subprocess
from typing import Dict, List, Optional, Set, Any
from datetime import datetime, timedelta
from collections import defaultdict, deque
import ipaddress
import re

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventAction
from agent.utils.network_utils import NetworkUtils, get_connection_info, is_suspicious_connection

logger = logging.getLogger('NetworkCollector')

# Alias for backward compatibility
# EnhancedNetworkCollector = EnhancedNetworkCollector  # Removed circular reference

class EnhancedNetworkCollector(BaseCollector):
    """Enhanced Network Collector - Phát hiện reverse shell và mã độc qua mạng"""
    
    def __init__(self, config_manager=None):
        if config_manager is None:
            from agent.core.config_manager import ConfigManager
            config_manager = ConfigManager()
        super().__init__(config_manager, "NetworkCollector")
        
        # Enhanced tracking for malware detection
        self.monitored_connections = {}
        self.connection_history = deque(maxlen=2000)  # Increased capacity
        self.suspicious_ips = set()
        self.reverse_shell_indicators = {}
        self.c2_communication_patterns = {}
        
        # ENHANCED: Malware-specific port analysis
        self.reverse_shell_ports = {
            # Common reverse shell ports
            4444, 4445, 5555, 6666, 7777, 8888, 9999,
            1234, 12345, 31337, 54321, 1337, 9876,
            # Web-based reverse shells
            80, 443, 8080, 8443, 9090, 3000, 8000,
            # DNS tunneling
            53,
            # SSH tunneling
            22, 2222,
            # Custom backdoor ports
            1981, 1999, 6969, 13337, 27374, 27665
        }
        
        # ENHANCED: C2 communication patterns
        self.c2_patterns = {
            'beacon_intervals': [30, 60, 300, 600, 3600],  # Common beacon intervals in seconds
            'data_sizes': {
                'small_beacon': (1, 100),      # Small beacon data
                'medium_payload': (100, 1024), # Medium payload
                'large_exfil': (1024, 10240)   # Large data exfiltration
            },
            'suspicious_domains': [
                'pastebin.com', 'github.com', 'dropbox.com',
                'telegram.org', 'discord.com', 'bit.ly',
                'tinyurl.com', 'duckdns.org'
            ]
        }
        
        # ENHANCED: Geo-blocking suspicious countries (example)
        self.high_risk_countries = {
            'CN', 'RU', 'KP', 'IR'  # China, Russia, North Korea, Iran
        }
        
        # ENHANCED: Known malicious IP ranges (simplified examples)
        self.malicious_ip_ranges = [
            '1.2.3.0/24',    # Example malicious range
            '10.0.0.0/8',    # Private range (for testing)
        ]
        
        # Performance settings
        self.polling_interval = 0.5  # Scan every 500ms for real-time detection
        self.connection_timeout = 30  # Consider connection stale after 30s
        
        # Enhanced statistics
        self.stats = {
            'total_connections_monitored': 0,
            'reverse_shell_connections_detected': 0,
            'c2_communication_detected': 0,
            'malicious_ip_connections': 0,
            'suspicious_port_connections': 0,
            'data_exfiltration_detected': 0,
            'dns_tunneling_detected': 0,
            'total_malware_network_events': 0
        }
        
        self.logger.info("Enhanced Network Collector initialized - REVERSE SHELL & MALWARE DETECTION")
    
    async def _collect_data(self):
        """Collect network events with enhanced malware detection"""
        try:
            start_time = time.time()
            events = []
            current_connections = {}
            
            # Get all network connections
            try:
                connections = psutil.net_connections(kind='inet')
            except Exception as e:
                self.logger.debug(f"Network connections scan failed: {e}")
                return []
            
            # ENHANCED: Analyze each connection for malware indicators
            for conn in connections:
                try:
                    if not conn.laddr:
                        continue
                    
                    # Helper để lấy ip, port an toàn
                    def get_ip_port(addr):
                        if hasattr(addr, 'ip') and hasattr(addr, 'port'):
                            return addr.ip, addr.port
                        elif isinstance(addr, tuple) and len(addr) >= 2:
                            return addr[0], addr[1]
                        return '0.0.0.0', 0
                    
                    l_ip, l_port = get_ip_port(conn.laddr)
                    r_ip, r_port = get_ip_port(conn.raddr) if conn.raddr else ('0.0.0.0', 0)
                    
                    conn_key = f"{l_ip}:{l_port}-{r_ip}:{r_port}-{conn.status}"
                    current_connections[conn_key] = conn
                    
                    # ENHANCED: Analyze connection for malware indicators
                    malware_analysis = await self._analyze_connection_for_malware(conn, l_ip, l_port, r_ip, r_port)
                    
                    # Track connection if suspicious
                    if malware_analysis['risk_score'] > 0:
                        self.suspicious_ips.add(r_ip)
                    
                    # Create events for NEW connections only
                    if conn_key not in self.monitored_connections:
                        # EVENT 1: Standard connection event (for all external connections)
                        if r_ip and self._is_external_ip(r_ip):
                            event = await self._create_enhanced_connection_event(conn, malware_analysis)
                            if event:
                                events.append(event)
                                self.stats['total_connections_monitored'] += 1
                        
                        # EVENT 2: Reverse Shell Detection
                        if malware_analysis.get('reverse_shell_likelihood', 0) > 50:
                            reverse_shell_event = await self._create_reverse_shell_detection_event(conn, malware_analysis)
                            if reverse_shell_event:
                                events.append(reverse_shell_event)
                                self.stats['reverse_shell_connections_detected'] += 1
                        
                        # EVENT 3: C2 Communication Detection
                        if malware_analysis.get('c2_likelihood', 0) > 40:
                            c2_event = await self._create_c2_communication_event(conn, malware_analysis)
                            if c2_event:
                                events.append(c2_event)
                                self.stats['c2_communication_detected'] += 1
                        
                        # EVENT 4: Malicious IP Connection
                        if malware_analysis.get('malicious_ip', False):
                            malicious_ip_event = await self._create_malicious_ip_event(conn, malware_analysis)
                            if malicious_ip_event:
                                events.append(malicious_ip_event)
                                self.stats['malicious_ip_connections'] += 1
                        
                        # EVENT 5: Suspicious Port Connection
                        if r_port in self.reverse_shell_ports:
                            suspicious_port_event = await self._create_suspicious_port_event(conn, malware_analysis)
                            if suspicious_port_event:
                                events.append(suspicious_port_event)
                                self.stats['suspicious_port_connections'] += 1
                        
                        # EVENT 6: DNS Tunneling Detection
                        if malware_analysis.get('dns_tunneling_likelihood', 0) > 30:
                            dns_tunnel_event = await self._create_dns_tunneling_event(conn, malware_analysis)
                            if dns_tunnel_event:
                                events.append(dns_tunnel_event)
                                self.stats['dns_tunneling_detected'] += 1
                    
                    # Store connection with analysis
                    self.monitored_connections[conn_key] = {
                        'connection': conn,
                        'malware_analysis': malware_analysis,
                        'first_seen': time.time(),
                        'last_seen': time.time()
                    }
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # ENHANCED: Detect closed connections and analyze patterns
            closed_connections = set(self.monitored_connections.keys()) - set(current_connections.keys())
            for conn_key in closed_connections:
                try:
                    conn_info = self.monitored_connections[conn_key]
                    connection_duration = time.time() - conn_info['first_seen']
                    
                    # Analyze connection patterns for C2 behavior
                    c2_pattern_analysis = await self._analyze_connection_patterns(conn_info, connection_duration)
                    
                    if c2_pattern_analysis['suspicious']:
                        pattern_event = await self._create_connection_pattern_event(conn_info, c2_pattern_analysis)
                        if pattern_event:
                            events.append(pattern_event)
                    
                    del self.monitored_connections[conn_key]
                except Exception as e:
                    self.logger.debug(f"Error analyzing closed connection: {e}")
            
            # Update global stats
            self.stats['total_malware_network_events'] += len(events)
            
            # Log events when connected to server
            if events:
                self.logger.info(f"📤 Generated {len(events)} ENHANCED NETWORK EVENTS (malware detection)")
                
                # Log malware-specific events
                malware_events = [e for e in events if 'malware' in e.description.lower() or 'shell' in e.description.lower()]
                if malware_events:
                    self.logger.warning(f"🚨 {len(malware_events)} POTENTIAL MALWARE NETWORK EVENTS detected")
            
            # Performance logging
            collection_time = (time.time() - start_time) * 1000
            if collection_time > 1000:
                self.logger.warning(f"⚠️ Slow network collection: {collection_time:.1f}ms")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Enhanced network events collection failed: {e}")
            return []
    
    async def _analyze_connection_for_malware(self, conn, l_ip: str, l_port: int, r_ip: str, r_port: int) -> Dict[str, Any]:
        """Analyze network connection for malware indicators"""
        try:
            analysis = {
                'risk_score': 0,
                'reverse_shell_likelihood': 0,
                'c2_likelihood': 0,
                'indicators': [],
                'malicious_ip': False,
                'dns_tunneling_likelihood': 0,
                'connection_type': 'normal'
            }
            
            if not r_ip or r_ip == '0.0.0.0':
                return analysis
            
            # INDICATOR 1: Suspicious ports
            if r_port in self.reverse_shell_ports:
                analysis['risk_score'] += 30
                analysis['reverse_shell_likelihood'] += 40
                analysis['indicators'].append(f'Suspicious port: {r_port}')
                analysis['connection_type'] = 'suspicious_port'
            
            # INDICATOR 2: External connection analysis
            if self._is_external_ip(r_ip):
                analysis['risk_score'] += 10
                analysis['indicators'].append(f'External connection: {r_ip}')
                
                # Check against malicious IP ranges
                if await self._is_malicious_ip(r_ip):
                    analysis['risk_score'] += 50
                    analysis['malicious_ip'] = True
                    analysis['c2_likelihood'] += 60
                    analysis['indicators'].append(f'Known malicious IP: {r_ip}')
                    analysis['connection_type'] = 'malicious_ip'
            
            # INDICATOR 3: Reverse shell port patterns
            if r_port in {4444, 4445, 5555, 6666, 7777, 8888, 9999}:
                analysis['reverse_shell_likelihood'] += 50
                analysis['risk_score'] += 25
                analysis['indicators'].append(f'Common reverse shell port: {r_port}')
            
            # INDICATOR 4: Web-based reverse shells
            if r_port in {80, 443, 8080, 8443} and l_port > 49152:
                analysis['reverse_shell_likelihood'] += 30
                analysis['c2_likelihood'] += 25
                analysis['risk_score'] += 20
                analysis['indicators'].append('Potential web-based reverse shell')
                analysis['connection_type'] = 'web_shell'
            
            # INDICATOR 5: DNS tunneling detection
            if r_port == 53 and conn.status == 'ESTABLISHED':
                analysis['dns_tunneling_likelihood'] += 40
                analysis['c2_likelihood'] += 30
                analysis['risk_score'] += 25
                analysis['indicators'].append('Potential DNS tunneling')
                analysis['connection_type'] = 'dns_tunnel'
            
            # INDICATOR 6: SSH tunneling
            if r_port in {22, 2222} and self._is_external_ip(r_ip):
                analysis['reverse_shell_likelihood'] += 35
                analysis['risk_score'] += 20
                analysis['indicators'].append('Potential SSH tunnel')
                analysis['connection_type'] = 'ssh_tunnel'
            
            # INDICATOR 7: Process analysis
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    process_name = proc.name().lower()
                    
                    # Check for suspicious processes
                    suspicious_processes = ['nc.exe', 'netcat.exe', 'powershell.exe', 'cmd.exe', 'python.exe']
                    if any(susp_proc in process_name for susp_proc in suspicious_processes):
                        analysis['reverse_shell_likelihood'] += 25
                        analysis['risk_score'] += 15
                        analysis['indicators'].append(f'Suspicious process: {process_name}')
                    
                    # Check command line for reverse shell indicators
                    try:
                        cmdline_parts = proc.cmdline()
                        if cmdline_parts is None:
                            cmdline_parts = []
                        elif not isinstance(cmdline_parts, list):
                            cmdline_parts = [str(cmdline_parts)]
                        cmdline = ' '.join(cmdline_parts).lower()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        cmdline = ""
                    
                    shell_patterns = ['-e /bin/sh', '-e cmd.exe', 'reverse', 'shell', 'tcp']
                    if any(pattern in cmdline for pattern in shell_patterns):
                        analysis['reverse_shell_likelihood'] += 40
                        analysis['risk_score'] += 30
                        analysis['indicators'].append('Reverse shell command detected')
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # INDICATOR 8: Connection timing patterns (C2 beaconing)
            connection_key = f"{r_ip}:{r_port}"
            if connection_key in self.c2_communication_patterns:
                pattern_info = self.c2_communication_patterns[connection_key]
                if await self._detect_beaconing_pattern(pattern_info):
                    analysis['c2_likelihood'] += 45
                    analysis['risk_score'] += 35
                    analysis['indicators'].append('C2 beaconing pattern detected')
                    analysis['connection_type'] = 'c2_beacon'
            
            # INDICATOR 9: Geographic analysis
            geo_risk = await self._analyze_geographic_risk(r_ip)
            if geo_risk > 0:
                analysis['risk_score'] += geo_risk
                analysis['c2_likelihood'] += geo_risk
                analysis['indicators'].append(f'High-risk geographic location')
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"❌ Connection malware analysis failed: {e}")
            return {'risk_score': 0, 'reverse_shell_likelihood': 0, 'c2_likelihood': 0, 'indicators': [], 'malicious_ip': False}
    
    async def _create_malicious_ip_event(self, conn, malware_analysis: Dict) -> Optional[EventData]:
        """Create malicious IP connection event"""
        try:
            l_ip, l_port = self._get_connection_endpoints(conn.laddr)
            r_ip, r_port = self._get_connection_endpoints(conn.raddr) if conn.raddr else ('0.0.0.0', 0)
            
            process_info = await self._get_process_info_for_connection(conn.pid) if conn.pid else {}
            
            return EventData(
                event_type="Network",
                event_action=EventAction.BLOCKED,
                event_timestamp=datetime.now(),
                severity="Critical",
                
                source_ip=l_ip,
                destination_ip=r_ip,
                source_port=l_port,
                destination_port=r_port,
                protocol='TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                direction="Outbound",
                
                process_id=conn.pid,
                process_name=process_info.get('name'),
                process_path=process_info.get('exe'),
                
                description=f"🚨 MALICIOUS IP CONNECTION: {process_info.get('name', 'Unknown')} -> {r_ip}:{r_port}",
                
                raw_event_data={
                    'event_subtype': 'malicious_ip_connection',
                    'threat_type': 'malicious_ip',
                    'malware_analysis': malware_analysis,
                    'process_info': process_info,
                    'threat_intelligence': {
                        'ip_reputation': 'malicious',
                        'threat_categories': ['malware', 'c2'],
                        'confidence': 'high'
                    },
                    'geographic_info': await self._get_ip_geographic_info(r_ip),
                    'timestamp': time.time()
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Malicious IP event failed: {e}")
            return None
    
    async def _create_suspicious_port_event(self, conn, malware_analysis: Dict) -> Optional[EventData]:
        """Create suspicious port connection event"""
        try:
            l_ip, l_port = self._get_connection_endpoints(conn.laddr)
            r_ip, r_port = self._get_connection_endpoints(conn.raddr) if conn.raddr else ('0.0.0.0', 0)
            
            process_info = await self._get_process_info_for_connection(conn.pid) if conn.pid else {}
            
            return EventData(
                event_type="Network",
                event_action=EventAction.SUSPICIOUS_ACTIVITY,
                event_timestamp=datetime.now(),
                severity="High",
                
                source_ip=l_ip,
                destination_ip=r_ip,
                source_port=l_port,
                destination_port=r_port,
                protocol='TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                direction="Outbound",
                
                process_id=conn.pid,
                process_name=process_info.get('name'),
                
                description=f"⚠️ SUSPICIOUS PORT: {process_info.get('name', 'Unknown')} -> {r_ip}:{r_port}",
                
                raw_event_data={
                    'event_subtype': 'suspicious_port_connection',
                    'port_analysis': {
                        'port': r_port,
                        'port_category': self._categorize_port(r_port),
                        'common_malware_usage': self._get_port_malware_usage(r_port)
                    },
                    'malware_analysis': malware_analysis,
                    'process_info': process_info,
                    'timestamp': time.time()
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Suspicious port event failed: {e}")
            return None
    
    async def _create_dns_tunneling_event(self, conn, malware_analysis: Dict) -> Optional[EventData]:
        """Create DNS tunneling detection event"""
        try:
            l_ip, l_port = self._get_connection_endpoints(conn.laddr)
            r_ip, r_port = self._get_connection_endpoints(conn.raddr) if conn.raddr else ('0.0.0.0', 0)
            
            process_info = await self._get_process_info_for_connection(conn.pid) if conn.pid else {}
            
            return EventData(
                event_type="Network",
                event_action=EventAction.SUSPICIOUS_ACTIVITY,
                event_timestamp=datetime.now(),
                severity="High",
                
                source_ip=l_ip,
                destination_ip=r_ip,
                source_port=l_port,
                destination_port=r_port,
                protocol='UDP',
                direction="Outbound",
                
                process_id=conn.pid,
                process_name=process_info.get('name'),
                
                description=f"🔍 DNS TUNNELING: {process_info.get('name', 'Unknown')} -> {r_ip}:53",
                
                raw_event_data={
                    'event_subtype': 'dns_tunneling_detection',
                    'tunnel_type': 'dns_tunnel',
                    'malware_analysis': malware_analysis,
                    'process_info': process_info,
                    'dns_analysis': {
                        'unusual_dns_traffic': True,
                        'long_connection_duration': True,
                        'data_exfiltration_likelihood': malware_analysis.get('dns_tunneling_likelihood', 0)
                    },
                    'timestamp': time.time()
                }
            )
        except Exception as e:
            self.logger.error(f"❌ DNS tunneling event failed: {e}")
            return None
    
    async def _analyze_connection_patterns(self, conn_info: Dict, duration: float) -> Dict[str, Any]:
        """Analyze connection patterns for C2 behavior"""
        try:
            analysis = {
                'suspicious': False,
                'pattern_type': 'normal',
                'indicators': []
            }
            
            # Check for beaconing behavior
            if duration > 60:  # Connection lasted more than 1 minute
                # This could indicate persistent C2 communication
                analysis['suspicious'] = True
                analysis['pattern_type'] = 'persistent_connection'
                analysis['indicators'].append(f'Long-duration connection: {duration:.1f}s')
            
            # Check for short-lived connections (potential beaconing)
            if 5 < duration < 30:
                analysis['suspicious'] = True
                analysis['pattern_type'] = 'beacon_pattern'
                analysis['indicators'].append(f'Short beacon-like connection: {duration:.1f}s')
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"❌ Connection pattern analysis failed: {e}")
            return {'suspicious': False, 'pattern_type': 'normal', 'indicators': []}
    
    async def _create_connection_pattern_event(self, conn_info: Dict, pattern_analysis: Dict) -> Optional[EventData]:
        """Create connection pattern analysis event"""
        try:
            conn = conn_info['connection']
            malware_analysis = conn_info['malware_analysis']
            
            l_ip, l_port = self._get_connection_endpoints(conn.laddr)
            r_ip, r_port = self._get_connection_endpoints(conn.raddr) if conn.raddr else ('0.0.0.0', 0)
            
            process_info = await self._get_process_info_for_connection(conn.pid) if conn.pid else {}
            
            return EventData(
                event_type="Network",
                event_action=EventAction.SUSPICIOUS_ACTIVITY,
                event_timestamp=datetime.now(),
                severity="Medium",
                
                source_ip=l_ip,
                destination_ip=r_ip,
                source_port=l_port,
                destination_port=r_port,
                protocol='TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                direction="Outbound",
                
                process_id=conn.pid,
                process_name=process_info.get('name'),
                
                description=f"📊 SUSPICIOUS PATTERN: {pattern_analysis['pattern_type']} -> {r_ip}:{r_port}",
                
                raw_event_data={
                    'event_subtype': 'connection_pattern_analysis',
                    'pattern_analysis': pattern_analysis,
                    'malware_analysis': malware_analysis,
                    'process_info': process_info,
                    'connection_duration': conn_info.get('last_seen', 0) - conn_info.get('first_seen', 0),
                    'timestamp': time.time()
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Connection pattern event failed: {e}")
            return None
    
    # Helper methods
    def _get_connection_endpoints(self, addr) -> tuple:
        """Get IP and port from connection address"""
        try:
            if hasattr(addr, 'ip') and hasattr(addr, 'port'):
                return addr.ip, addr.port
            elif isinstance(addr, tuple) and len(addr) >= 2:
                return addr[0], addr[1]
            return '0.0.0.0', 0
        except:
            return '0.0.0.0', 0
    
    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP address is external (not private)"""
        try:
            private_ranges = [
                '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                '172.20.', '172.21.', '172.22.', '172.23.',
                '172.24.', '172.25.', '172.26.', '172.27.',
                '172.28.', '172.29.', '172.30.', '172.31.',
                '192.168.', '127.', '169.254.'
            ]
            return not any(ip.startswith(prefix) for prefix in private_ranges)
        except:
            return False
    
    async def _is_malicious_ip(self, ip: str) -> bool:
        """Check if IP is in malicious IP ranges"""
        try:
            for ip_range in self.malicious_ip_ranges:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range):
                    return True
            return False
        except:
            return False
    
    async def _get_process_info_for_connection(self, pid: int) -> Dict[str, Any]:
        """Get process information for connection"""
        try:
            if not pid:
                return {}
            
            proc = psutil.Process(pid)
            return {
                'pid': pid,
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': ' '.join(proc.cmdline()),
                'username': proc.username(),
                'create_time': proc.create_time()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {}
    
    async def _get_ip_geographic_info(self, ip: str) -> Dict[str, Any]:
        """Get geographic information for IP (simplified)"""
        try:
            if self._is_external_ip(ip):
                # In real implementation, use geolocation service
                return {
                    'ip': ip,
                    'type': 'external',
                    'country': 'Unknown',
                    'region': 'Unknown',
                    'risk_level': 'medium'
                }
            return {
                'ip': ip,
                'type': 'internal',
                'country': 'Local',
                'region': 'Local',
                'risk_level': 'low'
            }
        except:
            return {}
    
    async def _analyze_geographic_risk(self, ip: str) -> int:
        """Analyze geographic risk for IP address"""
        try:
            # Simplified geographic risk analysis
            # In real implementation, use GeoIP database
            if self._is_external_ip(ip):
                return 15  # External IPs have moderate risk
            return 0
        except:
            return 0
    
    async def _detect_beaconing_pattern(self, pattern_info: Dict) -> bool:
        """Detect C2 beaconing patterns"""
        try:
            # Simplified beaconing detection
            # In real implementation, analyze timing patterns
            connection_count = pattern_info.get('connection_count', 0)
            if connection_count > 5:  # Multiple connections could indicate beaconing
                return True
            return False
        except:
            return False
    
    def _categorize_port(self, port: int) -> str:
        """Categorize port based on common usage"""
        if port in {80, 443, 8080, 8443}:
            return 'web'
        elif port in {22, 2222}:
            return 'ssh'
        elif port == 53:
            return 'dns'
        elif port in self.reverse_shell_ports:
            return 'backdoor'
        elif port > 49152:
            return 'ephemeral'
        else:
            return 'other'
    
    def _get_port_malware_usage(self, port: int) -> List[str]:
        """Get common malware usage for port"""
        port_malware_map = {
            4444: ['Metasploit', 'Reverse shells'],
            5555: ['Backdoors', 'RATs'],
            6666: ['Various malware'],
            8888: ['Web shells', 'Backdoors'],
            31337: ['Back Orifice', 'Elite backdoors'],
            12345: ['NetBus', 'Various trojans']
        }
        return port_malware_map.get(port, ['Unknown'])
    
    def get_stats(self) -> Dict:
        """Get detailed statistics for enhanced network monitoring with malware detection"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'Network_Enhanced_MalwareDetection',
            'total_connections_monitored': self.stats['total_connections_monitored'],
            'reverse_shell_connections_detected': self.stats['reverse_shell_connections_detected'],
            'c2_communication_detected': self.stats['c2_communication_detected'],
            'malicious_ip_connections': self.stats['malicious_ip_connections'],
            'suspicious_port_connections': self.stats['suspicious_port_connections'],
            'data_exfiltration_detected': self.stats['data_exfiltration_detected'],
            'dns_tunneling_detected': self.stats['dns_tunneling_detected'],
            'total_malware_network_events': self.stats['total_malware_network_events'],
            'active_connections': len(self.monitored_connections),
            'suspicious_ips_tracked': len(self.suspicious_ips),
            'enhanced_malware_detection': True,
            'reverse_shell_detection': True,
            'c2_detection': True,
            'dns_tunneling_detection': True,
            'geographic_analysis': True,
            'suspicious_ports_monitored': len(self.reverse_shell_ports),
            'malware_detection_features': [
                'reverse_shell_detection',
                'c2_communication_analysis',
                'malicious_ip_detection',
                'dns_tunneling_detection',
                'connection_pattern_analysis',
                'geographic_risk_analysis',
                'process_correlation',
                'real_time_monitoring'
            ]
        })
        return base_stats
    
    async def _create_enhanced_connection_event(self, conn, malware_analysis: Dict) -> Optional[EventData]:
        """Create enhanced connection event with malware analysis"""
        try:
            l_ip, l_port = self._get_connection_endpoints(conn.laddr)
            r_ip, r_port = self._get_connection_endpoints(conn.raddr) if conn.raddr else ('0.0.0.0', 0)
            
            # Determine severity based on risk score
            risk_score = malware_analysis.get('risk_score', 0)
            if risk_score >= 50:
                severity = "High"
            elif risk_score >= 25:
                severity = "Medium"
            else:
                severity = "Info"
            
            # Get process information
            process_info = await self._get_process_info_for_connection(conn.pid) if conn.pid else {}
            
            return EventData(
                event_type="Network",
                event_action=EventAction.CONNECT,
                event_timestamp=datetime.now(),
                severity=severity,
                
                source_ip=l_ip,
                destination_ip=r_ip,
                source_port=l_port,
                destination_port=r_port,
                protocol='TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                direction="Outbound" if r_ip != '0.0.0.0' else "Inbound",
                
                process_id=conn.pid,
                process_name=process_info.get('name'),
                
                description=f"🌐 NETWORK CONNECTION: {l_ip}:{l_port} -> {r_ip}:{r_port} (Risk: {risk_score}/100)",
                
                raw_event_data={
                    'event_subtype': 'enhanced_network_connection',
                    'malware_analysis': malware_analysis,
                    'connection_status': conn.status,
                    'process_info': process_info,
                    'is_external': self._is_external_ip(r_ip),
                    'connection_family': conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                    'connection_type': conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                    'risk_assessment': {
                        'risk_score': risk_score,
                        'reverse_shell_likelihood': malware_analysis.get('reverse_shell_likelihood', 0),
                        'c2_likelihood': malware_analysis.get('c2_likelihood', 0),
                        'indicators': malware_analysis.get('indicators', [])
                    },
                    'geographic_info': await self._get_ip_geographic_info(r_ip),
                    'timestamp': time.time()
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Enhanced connection event creation failed: {e}")
            return None
    
    async def _create_reverse_shell_detection_event(self, conn, malware_analysis: Dict) -> Optional[EventData]:
        """Create reverse shell detection event"""
        try:
            l_ip, l_port = self._get_connection_endpoints(conn.laddr)
            r_ip, r_port = self._get_connection_endpoints(conn.raddr) if conn.raddr else ('0.0.0.0', 0)
            
            process_info = await self._get_process_info_for_connection(conn.pid) if conn.pid else {}
            
            return EventData(
                event_type="Network",
                event_action=EventAction.SUSPICIOUS_ACTIVITY,
                event_timestamp=datetime.now(),
                severity="Critical",
                
                source_ip=l_ip,
                destination_ip=r_ip,
                source_port=l_port,
                destination_port=r_port,
                protocol='TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                direction="Outbound",
                
                process_id=conn.pid,
                process_name=process_info.get('name'),
                process_path=process_info.get('exe'),
                
                description=f"🚨 REVERSE SHELL DETECTED: {process_info.get('name', 'Unknown')} -> {r_ip}:{r_port}",
                
                raw_event_data={
                    'event_subtype': 'reverse_shell_detection',
                    'shell_type': 'reverse_shell',
                    'malware_analysis': malware_analysis,
                    'process_info': process_info,
                    'connection_details': {
                        'local_endpoint': f"{l_ip}:{l_port}",
                        'remote_endpoint': f"{r_ip}:{r_port}",
                        'status': conn.status
                    },
                    'detection_confidence': malware_analysis.get('reverse_shell_likelihood', 0),
                    'risk_indicators': malware_analysis.get('indicators', []),
                    'command_line': process_info.get('cmdline', ''),
                    'timestamp': time.time()
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Reverse shell detection event failed: {e}")
            return None
    
    async def _create_c2_communication_event(self, conn, malware_analysis: Dict) -> Optional[EventData]:
        """Create C2 communication detection event"""
        try:
            l_ip, l_port = self._get_connection_endpoints(conn.laddr)
            r_ip, r_port = self._get_connection_endpoints(conn.raddr) if conn.raddr else ('0.0.0.0', 0)
            
            process_info = await self._get_process_info_for_connection(conn.pid) if conn.pid else {}
            
            return EventData(
                event_type="Network",
                event_action=EventAction.SUSPICIOUS_ACTIVITY,
                event_timestamp=datetime.now(),
                severity="High",
                
                source_ip=l_ip,
                destination_ip=r_ip,
                source_port=l_port,
                destination_port=r_port,
                protocol='TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                direction="Outbound",
                
                process_id=conn.pid,
                process_name=process_info.get('name'),
                
                description=f"🎯 C2 COMMUNICATION: {process_info.get('name', 'Unknown')} -> {r_ip}:{r_port}",
                
                raw_event_data={
                    'event_subtype': 'c2_communication',
                    'communication_type': 'command_and_control',
                    'malware_analysis': malware_analysis,
                    'process_info': process_info,
                    'c2_likelihood': malware_analysis.get('c2_likelihood', 0),
                    'connection_pattern': malware_analysis.get('connection_type', 'unknown'),
                    'indicators': malware_analysis.get('indicators', []),
                    'timestamp': time.time()
                }
            )
        except Exception as e:
            self.logger.error(f"❌ C2 communication event failed: {e}")
            return None