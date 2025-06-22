# agent/collectors/network_collector.py
"""
Network Activity Collector - ENHANCED
Thu thập thông tin về hoạt động mạng liên tục với tần suất cao
"""

import asyncio
import logging
import socket
import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import psutil
import subprocess
import platform
from collections import defaultdict

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventType, EventAction, Severity
from agent.utils.network_utils import NetworkUtils

class NetworkCollector(BaseCollector):
    """Enhanced Network Activity Collector"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "NetworkCollector")
        
        # Enhanced configuration
        self.polling_interval = 1  # ENHANCED: Reduced from 5 to 1 second for continuous monitoring
        self.max_connections_per_batch = 100  # ENHANCED: Increased batch size
        self.track_connection_history = True
        self.monitor_suspicious_connections = True
        
        # Network tracking
        self.known_connections = set()
        self.connection_history = defaultdict(list)
        self.suspicious_connections = set()
        
        # Enhanced monitoring
        self.monitor_dns_queries = True
        self.monitor_http_requests = True
        self.monitor_ssl_connections = True
        self.monitor_port_scanning = True
        
        # Suspicious network patterns
        self.suspicious_ports = {
            22, 23, 3389, 445, 135, 139, 1433, 1521, 3306, 5432, 6379, 27017
        }
        
        self.suspicious_domains = [
            'malware.com', 'evil.com', 'hacker.com', 'c2.com', 'backdoor.com'
        ]
        
        self.suspicious_ips = set()
        
        # Network statistics
        self.network_stats = {
            'total_connections': 0,
            'suspicious_connections': 0,
            'dns_queries': 0,
            'http_requests': 0
        }
        
        self.logger.info("🌐 Enhanced Network Collector initialized")
    
    async def initialize(self):
        """Initialize network collector with enhanced monitoring"""
        try:
            # Get initial network state
            await self._scan_all_connections()
            
            # Set up enhanced monitoring
            self._setup_network_monitoring()
            
            # Load suspicious IPs from threat intelligence
            await self._load_suspicious_ips()
            
            self.logger.info(f"✅ Enhanced Network Collector initialized - Monitoring {len(self.known_connections)} connections")
            
        except Exception as e:
            self.logger.error(f"❌ Network collector initialization failed: {e}")
            raise
    
    def _setup_network_monitoring(self):
        """Set up enhanced network monitoring"""
        try:
            # Set up network event callbacks
            self._setup_network_callbacks()
            
            # Initialize network utilities
            self.network_utils = NetworkUtils()
            
        except Exception as e:
            self.logger.error(f"Network monitoring setup failed: {e}")
    
    def _setup_network_callbacks(self):
        """Set up network event callbacks for real-time monitoring"""
        try:
            # This would integrate with Windows API for real-time network events
            # For now, we use polling with enhanced frequency
            pass
        except Exception as e:
            self.logger.debug(f"Network callbacks setup failed: {e}")
    
    async def collect_data(self) -> List[EventData]:
        """Collect network data with enhanced monitoring"""
        try:
            events = []
            
            # ENHANCED: Collect new connections
            new_connections = await self._detect_new_connections()
            events.extend(new_connections)
            
            # ENHANCED: Collect closed connections
            closed_connections = await self._detect_closed_connections()
            events.extend(closed_connections)
            
            # ENHANCED: Monitor suspicious connections
            suspicious_events = await self._monitor_suspicious_connections()
            events.extend(suspicious_events)
            
            # ENHANCED: Collect DNS queries
            dns_events = await self._collect_dns_queries()
            events.extend(dns_events)
            
            # ENHANCED: Monitor HTTP traffic
            http_events = await self._monitor_http_traffic()
            events.extend(http_events)
            
            # ENHANCED: Monitor SSL connections
            ssl_events = await self._monitor_ssl_connections()
            events.extend(ssl_events)
            
            # ENHANCED: Detect port scanning
            port_scan_events = await self._detect_port_scanning()
            events.extend(port_scan_events)
            
            if events:
                self.logger.debug(f"📊 Collected {len(events)} network events")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Network data collection failed: {e}")
            return []
    
    async def _scan_all_connections(self):
        """Scan all current network connections for baseline"""
        try:
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    conn_key = self._create_connection_key(conn)
                    self.known_connections.add(conn_key)
                    
                    # Check if suspicious
                    if self._is_suspicious_connection(conn):
                        self.suspicious_connections.add(conn_key)
            
            self.logger.info(f"📋 Baseline scan: {len(self.known_connections)} connections")
            
        except Exception as e:
            self.logger.error(f"Network scan failed: {e}")
    
    async def _detect_new_connections(self) -> List[EventData]:
        """Detect newly established connections"""
        try:
            events = []
            current_connections = set()
            
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    conn_key = self._create_connection_key(conn)
                    current_connections.add(conn_key)
                    
                    # Check if this is a new connection
                    if conn_key not in self.known_connections:
                        # New connection detected
                        event = self._create_network_event(
                            action=EventAction.CONNECTION,
                            source_ip=conn.laddr.ip if conn.laddr else '',
                            source_port=conn.laddr.port if conn.laddr else 0,
                            destination_ip=conn.raddr.ip if conn.raddr else '',
                            destination_port=conn.raddr.port if conn.raddr else 0,
                            protocol=self._get_protocol_name(conn.raddr.port if conn.raddr else 0),
                            direction='outbound' if conn.raddr else 'inbound',
                            severity=self._determine_connection_severity(conn)
                        )
                        events.append(event)
                        
                        # Update tracking
                        self.known_connections.add(conn_key)
                        self.connection_history[conn_key].append({
                            'timestamp': datetime.now(),
                            'status': 'established'
                        })
                        
                        # Check if suspicious
                        if self._is_suspicious_connection(conn):
                            self.suspicious_connections.add(conn_key)
                            self.logger.warning(f"🚨 Suspicious connection detected: {conn.raddr.ip}:{conn.raddr.port}")
            
            # Update known connections
            self.known_connections = current_connections
            
            return events
            
        except Exception as e:
            self.logger.error(f"New connection detection failed: {e}")
            return []
    
    async def _detect_closed_connections(self) -> List[EventData]:
        """Detect closed connections"""
        try:
            events = []
            current_connections = set()
            
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    conn_key = self._create_connection_key(conn)
                    current_connections.add(conn_key)
            
            # Find closed connections
            closed_connections = self.known_connections - current_connections
            
            for conn_key in closed_connections:
                # Parse connection key
                parts = conn_key.split('|')
                if len(parts) >= 4:
                    source_ip, source_port, dest_ip, dest_port = parts[:4]
                    
                    event = self._create_network_event(
                        action=EventAction.CONNECTION_CLOSED,
                        source_ip=source_ip,
                        source_port=int(source_port),
                        destination_ip=dest_ip,
                        destination_port=int(dest_port),
                        protocol='unknown',
                        direction='unknown',
                        severity=Severity.LOW
                    )
                    events.append(event)
                    
                    # Clean up tracking
                    self.connection_history.pop(conn_key, None)
                    self.suspicious_connections.discard(conn_key)
            
            return events
            
        except Exception as e:
            self.logger.error(f"Closed connection detection failed: {e}")
            return []
    
    async def _monitor_suspicious_connections(self) -> List[EventData]:
        """Monitor activities of suspicious connections"""
        try:
            events = []
            
            for conn_key in list(self.suspicious_connections):
                try:
                    # Parse connection key
                    parts = conn_key.split('|')
                    if len(parts) >= 4:
                        source_ip, source_port, dest_ip, dest_port = parts[:4]
                        
                        # Check if connection still exists
                        connections = psutil.net_connections()
                        conn_exists = False
                        
                        for conn in connections:
                            if (conn.status == 'ESTABLISHED' and 
                                conn.laddr and conn.raddr and
                                conn.laddr.ip == source_ip and
                                conn.laddr.port == int(source_port) and
                                conn.raddr.ip == dest_ip and
                                conn.raddr.port == int(dest_port)):
                                conn_exists = True
                                break
                        
                        if not conn_exists:
                            self.suspicious_connections.discard(conn_key)
                            continue
                        
                        # Monitor suspicious activities
                        event = await self._check_suspicious_network_activity(conn_key)
                        if event:
                            events.append(event)
                
                except Exception as e:
                    self.logger.debug(f"Suspicious connection monitoring failed: {e}")
                    continue
            
            return events
            
        except Exception as e:
            self.logger.error(f"Suspicious connection monitoring failed: {e}")
            return []
    
    async def _check_suspicious_network_activity(self, conn_key: str) -> Optional[EventData]:
        """Check for suspicious activities in a network connection"""
        try:
            # Parse connection key
            parts = conn_key.split('|')
            if len(parts) >= 4:
                source_ip, source_port, dest_ip, dest_port = parts[:4]
                
                # Check for data transfer patterns
                # This would require integration with network monitoring tools
                
                # Check for unusual port usage
                if int(dest_port) in self.suspicious_ports:
                    return self._create_network_event(
                        action=EventAction.SUSPICIOUS_ACTIVITY,
                        source_ip=source_ip,
                        source_port=int(source_port),
                        destination_ip=dest_ip,
                        destination_port=int(dest_port),
                        protocol=self._get_protocol_name(int(dest_port)),
                        direction='outbound',
                        severity=Severity.HIGH,
                        additional_data={'suspicious_port': dest_port}
                    )
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Suspicious network activity check failed: {e}")
            return None
    
    async def _collect_dns_queries(self) -> List[EventData]:
        """Collect DNS queries"""
        try:
            events = []
            
            # This would require integration with DNS monitoring tools
            # For now, we'll simulate DNS query collection
            
            # Monitor DNS cache
            try:
                import subprocess
                result = subprocess.run(['ipconfig', '/displaydns'], 
                                      capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Record Name' in line:
                            domain = line.split(':')[1].strip()
                            if self._is_suspicious_domain(domain):
                                event = self._create_network_event(
                                    action=EventAction.DNS_QUERY,
                                    source_ip='',
                                    source_port=0,
                                    destination_ip='',
                                    destination_port=53,
                                    protocol='DNS',
                                    direction='outbound',
                                    severity=Severity.HIGH,
                                    additional_data={'domain': domain}
                                )
                                events.append(event)
            
            except Exception as e:
                self.logger.debug(f"DNS query collection failed: {e}")
            
            return events
            
        except Exception as e:
            self.logger.error(f"DNS query collection failed: {e}")
            return []
    
    async def _monitor_http_traffic(self) -> List[EventData]:
        """Monitor HTTP traffic"""
        try:
            events = []
            
            # Monitor connections on HTTP ports
            connections = psutil.net_connections()
            
            for conn in connections:
                if (conn.status == 'ESTABLISHED' and conn.raddr and 
                    conn.raddr.port in [80, 443, 8080, 8443]):
                    
                    event = self._create_network_event(
                        action=EventAction.HTTP_REQUEST,
                        source_ip=conn.laddr.ip if conn.laddr else '',
                        source_port=conn.laddr.port if conn.laddr else 0,
                        destination_ip=conn.raddr.ip,
                        destination_port=conn.raddr.port,
                        protocol='HTTP' if conn.raddr.port == 80 else 'HTTPS',
                        direction='outbound',
                        severity=Severity.LOW
                    )
                    events.append(event)
            
            return events
            
        except Exception as e:
            self.logger.error(f"HTTP traffic monitoring failed: {e}")
            return []
    
    async def _monitor_ssl_connections(self) -> List[EventData]:
        """Monitor SSL connections"""
        try:
            events = []
            
            # Monitor SSL/TLS connections
            connections = psutil.net_connections()
            
            for conn in connections:
                if (conn.status == 'ESTABLISHED' and conn.raddr and 
                    conn.raddr.port in [443, 993, 995, 465, 587]):
                    
                    event = self._create_network_event(
                        action=EventAction.SSL_CONNECTION,
                        source_ip=conn.laddr.ip if conn.laddr else '',
                        source_port=conn.laddr.port if conn.laddr else 0,
                        destination_ip=conn.raddr.ip,
                        destination_port=conn.raddr.port,
                        protocol='SSL/TLS',
                        direction='outbound',
                        severity=Severity.MEDIUM
                    )
                    events.append(event)
            
            return events
            
        except Exception as e:
            self.logger.error(f"SSL connection monitoring failed: {e}")
            return []
    
    async def _detect_port_scanning(self) -> List[EventData]:
        """Detect port scanning activities"""
        try:
            events = []
            
            # Analyze connection patterns for port scanning
            connection_counts = defaultdict(int)
            
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    dest_ip = conn.raddr.ip
                    connection_counts[dest_ip] += 1
            
            # Check for potential port scanning
            for dest_ip, count in connection_counts.items():
                if count > 10:  # Threshold for port scanning detection
                    event = self._create_network_event(
                        action=EventAction.PORT_SCAN,
                        source_ip='',
                        source_port=0,
                        destination_ip=dest_ip,
                        destination_port=0,
                        protocol='unknown',
                        direction='outbound',
                        severity=Severity.HIGH,
                        additional_data={'connection_count': count}
                    )
                    events.append(event)
            
            return events
            
        except Exception as e:
            self.logger.error(f"Port scanning detection failed: {e}")
            return []
    
    async def _load_suspicious_ips(self):
        """Load suspicious IP addresses from threat intelligence"""
        try:
            # This would load from threat intelligence feeds
            # For now, we'll use a basic list
            self.suspicious_ips = {
                '192.168.1.100',  # Example suspicious IP
                '10.0.0.50'       # Example suspicious IP
            }
            
        except Exception as e:
            self.logger.debug(f"Suspicious IP loading failed: {e}")
    
    def _create_connection_key(self, conn) -> str:
        """Create unique key for connection tracking"""
        try:
            source_ip = conn.laddr.ip if conn.laddr else ''
            source_port = conn.laddr.port if conn.laddr else 0
            dest_ip = conn.raddr.ip if conn.raddr else ''
            dest_port = conn.raddr.port if conn.raddr else 0
            
            return f"{source_ip}|{source_port}|{dest_ip}|{dest_port}"
        except:
            return ""
    
    def _is_suspicious_connection(self, conn) -> bool:
        """Check if connection is suspicious"""
        try:
            if not conn.raddr:
                return False
            
            # Check suspicious ports
            if conn.raddr.port in self.suspicious_ports:
                return True
            
            # Check suspicious IPs
            if conn.raddr.ip in self.suspicious_ips:
                return True
            
            # Check for unusual protocols
            if conn.raddr.port not in [80, 443, 22, 21, 25, 110, 143, 993, 995]:
                return True
            
            return False
            
        except:
            return False
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is suspicious"""
        return any(suspicious in domain.lower() for suspicious in self.suspicious_domains)
    
    def _get_protocol_name(self, port: int) -> str:
        """Get protocol name from port number"""
        protocol_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
            5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB'
        }
        return protocol_map.get(port, 'Unknown')
    
    def _determine_connection_severity(self, conn) -> Severity:
        """Determine severity based on connection details"""
        if self._is_suspicious_connection(conn):
            return Severity.HIGH
        elif conn.raddr and conn.raddr.port in [22, 3389, 445]:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _create_network_event(self, action: EventAction, source_ip: str, source_port: int,
                            destination_ip: str, destination_port: int, protocol: str,
                            direction: str, severity: Severity, additional_data: Dict = None) -> EventData:
        """Create network event data"""
        try:
            return EventData(
                event_type=EventType.NETWORK,
                event_action=action,
                event_timestamp=datetime.now(),
                severity=severity,
                source_ip=source_ip,
                source_port=source_port,
                destination_ip=destination_ip,
                destination_port=destination_port,
                protocol=protocol,
                direction=direction,
                raw_event_data=additional_data or {}
            )
            
        except Exception as e:
            self.logger.error(f"Network event creation failed: {e}")
            return None