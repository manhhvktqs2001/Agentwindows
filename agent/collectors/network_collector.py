# agent/collectors/network_collector.py - FIXED FOR COMPLETE DATA
"""
Fixed Network Collector - Ensures ALL network fields are populated
Thu thập đầy đủ thông tin network: SourceIP, DestinationIP, SourcePort, DestinationPort, Protocol, Direction
"""

import psutil
import socket
import asyncio
import logging
import time
from typing import Dict, List, Optional, Set
from datetime import datetime
from collections import defaultdict, deque

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventAction
from agent.utils.network_utils import NetworkUtils, get_connection_info, is_suspicious_connection

logger = logging.getLogger('NetworkCollector')

class EnhancedNetworkCollector(BaseCollector):
    """Fixed Network Collector - Ensures complete data collection with ALL required fields"""
    
    def __init__(self, config_manager=None):
        super().__init__(config_manager, "NetworkCollector")
        
        # Network tracking
        self.monitored_connections = {}  # connection_key -> connection_info
        self.connection_history = deque(maxlen=1000)
        self.port_activity = defaultdict(int)
        self.bandwidth_usage = defaultdict(list)
        self.dns_queries = deque(maxlen=500)
        
        # Network categories
        self.suspicious_ports = {
            22, 23, 443, 3389, 445, 135, 139, 1433, 3306, 5432,
            4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345
        }
        
        self.common_services = {
            80: 'HTTP',
            443: 'HTTPS',
            53: 'DNS',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            110: 'POP3',
            143: 'IMAP',
            993: 'IMAPS',
            995: 'POP3S'
        }
        
        self.outbound_countries = set()
        self.bandwidth_threshold = 10 * 1024 * 1024  # 10MB
        self.polling_interval = 0.5  # 500ms for network monitoring
        
        # Statistics
        self.stats = {
            'connection_established_events': 0,
            'connection_closed_events': 0,
            'suspicious_connection_events': 0,
            'high_bandwidth_events': 0,
            'port_scan_events': 0,
            'dns_query_events': 0,
            'network_summary_events': 0,
            'firewall_events': 0,
            'external_connection_events': 0,
            'total_network_events': 0
        }
        
        self.logger.info("🌐 FIXED Network Collector initialized - COMPLETE DATA COLLECTION")
    
    async def _collect_data(self):
        """Collect network events - ENHANCED for better performance"""
        try:
            start_time = time.time()
            events = []
            current_connections = {}
            
            # FIXED: Check server connectivity before processing
            is_connected = False
            if hasattr(self, 'event_processor') and self.event_processor:
                if hasattr(self.event_processor, 'communication') and self.event_processor.communication:
                    is_connected = not self.event_processor.communication.offline_mode
            
            # ENHANCED: Get network connections efficiently
            try:
                connections = psutil.net_connections(kind='inet')
            except Exception as e:
                self.logger.debug(f"Network connections scan failed: {e}")
                return []
            
            # FIXED: Process connections efficiently
            for conn in connections:
                try:
                    if not conn.laddr:
                        continue
                    
                    # Create connection key
                    if conn.raddr:
                        conn_key = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}-{conn.status}"
                    else:
                        conn_key = f"{conn.laddr.ip}:{conn.laddr.port}-LISTENING-{conn.status}"
                    
                    current_connections[conn_key] = conn
                    
                    # FIXED: Only create events for NEW connections, not all connections
                    if conn_key not in self.monitored_connections:
                        # EVENT TYPE 1: New Connection Established Event with COMPLETE data
                        if conn.raddr:
                            event = await self._create_complete_connection_established_event(conn)
                            if event:
                                events.append(event)
                                self.stats['connection_established_events'] += 1
                        
                        # EVENT TYPE 2: Suspicious Connection Event with COMPLETE data
                        if conn.raddr and is_suspicious_connection(conn):
                            event = await self._create_complete_suspicious_connection_event(conn)
                            if event:
                                events.append(event)
                                self.stats['suspicious_connection_events'] += 1
                        
                        # EVENT TYPE 3: External Connection Event with COMPLETE data
                        if conn.raddr and self._is_external_connection(conn):
                            event = await self._create_complete_external_connection_event(conn)
                            if event:
                                events.append(event)
                                self.stats['external_connection_events'] += 1
                        
                        # EVENT TYPE 4: Listening Port Event with COMPLETE data
                        if not conn.raddr and conn.status == 'LISTEN':
                            event = await self._create_complete_listening_port_event(conn)
                            if event:
                                events.append(event)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # EVENT TYPE 5: Connection Closed Events with COMPLETE data
            closed_connections = set(self.monitored_connections.keys()) - set(current_connections.keys())
            for conn_key in closed_connections:
                if conn_key in self.monitored_connections:
                    event = await self._create_complete_connection_closed_event(conn_key, self.monitored_connections[conn_key])
                    if event:
                        events.append(event)
                        self.stats['connection_closed_events'] += 1
                    del self.monitored_connections[conn_key]
            
            # EVENT TYPE 6: Network Summary Event (every 20 scans)
            if self.stats['total_network_events'] % 20 == 0:
                summary_event = await self._create_complete_network_summary_event()
                if summary_event:
                    events.append(summary_event)
                    self.stats['network_summary_events'] += 1
            
            # Update tracking
            self.monitored_connections = current_connections
            self.stats['total_network_events'] += len(events)
            
            # FIXED: Only log events when connected to server
            if events and is_connected:
                self.logger.info(f"📤 Generated {len(events)} COMPLETE NETWORK EVENTS")
                # Log sample event details
                for event in events[:2]:  # Log first 2 events
                    self.logger.info(f"📤 Network event: {event.source_ip}:{event.source_port} -> {event.destination_ip}:{event.destination_port} ({event.protocol})")
            
            # FIXED: Log performance metrics
            collection_time = (time.time() - start_time) * 1000
            if collection_time > 1000:
                self.logger.warning(f"⚠️ Slow network collection: {collection_time:.1f}ms")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Network events collection failed: {e}")
            return []
    
    async def _create_complete_connection_established_event(self, conn):
        """EVENT TYPE 1: Connection Established Event with ALL required fields"""
        try:
            # Get process info if available
            process_info = None
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    process_info = {
                        'pid': conn.pid,
                        'name': proc.name(),
                        'exe': proc.exe()
                    }
                except:
                    pass
            
            # FIXED: Extract ALL required network fields
            source_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
            source_port = conn.laddr.port if conn.laddr else 0
            destination_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
            destination_port = conn.raddr.port if conn.raddr else 0
            protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
            direction = self._determine_connection_direction(conn)
            
            # FIXED: Create network event with ALL required fields populated
            return EventData(
                event_type="Network",
                event_action=EventAction.CONNECT,
                event_timestamp=datetime.now(),
                severity="Medium" if destination_port in self.suspicious_ports else "Info",
                
                # FIXED: ALWAYS populate ALL network-specific fields
                source_ip=source_ip,                    # REQUIRED FIELD
                source_port=source_port,                # REQUIRED FIELD
                destination_ip=destination_ip,          # REQUIRED FIELD
                destination_port=destination_port,      # REQUIRED FIELD
                protocol=protocol,                      # REQUIRED FIELD
                direction=direction,                    # REQUIRED FIELD
                
                # Process information
                process_id=conn.pid,
                process_name=process_info['name'] if process_info else None,
                
                description=f"🔗 CONNECTION ESTABLISHED: {source_ip}:{source_port} -> {destination_ip}:{destination_port} ({protocol})",
                
                raw_event_data={
                    'event_subtype': 'connection_established',
                    'connection_status': conn.status,
                    'process_info': process_info,
                    'is_suspicious_port': destination_port in self.suspicious_ports,
                    'service_name': self.common_services.get(destination_port, 'Unknown'),
                    'data_complete': True,
                    
                    # Complete network details
                    'local_address': f"{source_ip}:{source_port}",
                    'remote_address': f"{destination_ip}:{destination_port}",
                    'connection_family': conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                    'connection_type': conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                    'is_listening': conn.status == 'LISTEN',
                    'is_established': conn.status == 'ESTABLISHED',
                    'is_external': self._is_external_ip(destination_ip),
                    'is_localhost': destination_ip in ['127.0.0.1', '::1'],
                    'timestamp': time.time()
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Complete connection established event failed: {e}")
            return None
    
    async def _create_complete_connection_closed_event(self, conn_key: str, conn):
        """EVENT TYPE 2: Connection Closed Event with ALL required fields"""
        try:
            # Parse connection key to extract details
            parts = conn_key.split('-')
            if len(parts) >= 2:
                local_part = parts[0]
                remote_part = parts[1]
                
                # Extract local address
                if ':' in local_part:
                    source_ip, source_port_str = local_part.rsplit(':', 1)
                    source_port = int(source_port_str) if source_port_str.isdigit() else 0
                else:
                    source_ip, source_port = "0.0.0.0", 0
                
                # Extract remote address
                if remote_part == 'LISTENING':
                    destination_ip, destination_port = "0.0.0.0", 0
                    direction = "Listening"
                else:
                    if ':' in remote_part:
                        destination_ip, destination_port_str = remote_part.rsplit(':', 1)
                        destination_port = int(destination_port_str) if destination_port_str.isdigit() else 0
                    else:
                        destination_ip, destination_port = "0.0.0.0", 0
                    direction = self._determine_connection_direction(conn)
            else:
                source_ip, source_port = "0.0.0.0", 0
                destination_ip, destination_port = "0.0.0.0", 0
                direction = "Unknown"
            
            protocol = 'TCP' if hasattr(conn, 'type') and conn.type == socket.SOCK_STREAM else 'TCP'
            
            # FIXED: Create network event with ALL required fields populated
            return EventData(
                event_type="Network",
                event_action=EventAction.DISCONNECT,
                event_timestamp=datetime.now(),
                severity="Info",
                
                # FIXED: ALWAYS populate ALL network-specific fields
                source_ip=source_ip,                    # REQUIRED FIELD
                source_port=source_port,                # REQUIRED FIELD
                destination_ip=destination_ip,          # REQUIRED FIELD
                destination_port=destination_port,      # REQUIRED FIELD
                protocol=protocol,                      # REQUIRED FIELD
                direction=direction,                    # REQUIRED FIELD
                
                description=f"❌ CONNECTION CLOSED: {source_ip}:{source_port} -> {destination_ip}:{destination_port}",
                
                raw_event_data={
                    'event_subtype': 'connection_closed',
                    'connection_key': conn_key,
                    'close_time': time.time(),
                    'data_complete': True,
                    'local_address': f"{source_ip}:{source_port}",
                    'remote_address': f"{destination_ip}:{destination_port}",
                    'was_established': True
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Complete connection closed event failed: {e}")
            return None
    
    async def _create_complete_suspicious_connection_event(self, conn):
        """EVENT TYPE 3: Suspicious Connection Event with ALL required fields"""
        try:
            # FIXED: Extract ALL required network fields
            source_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
            source_port = conn.laddr.port if conn.laddr else 0
            destination_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
            destination_port = conn.raddr.port if conn.raddr else 0
            protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
            direction = self._determine_connection_direction(conn)
            
            # FIXED: Create network event with ALL required fields populated
            return EventData(
                event_type="Network",
                event_action=EventAction.SUSPICIOUS_ACTIVITY,
                event_timestamp=datetime.now(),
                severity="High",
                
                # FIXED: ALWAYS populate ALL network-specific fields
                source_ip=source_ip,                    # REQUIRED FIELD
                source_port=source_port,                # REQUIRED FIELD
                destination_ip=destination_ip,          # REQUIRED FIELD
                destination_port=destination_port,      # REQUIRED FIELD
                protocol=protocol,                      # REQUIRED FIELD
                direction=direction,                    # REQUIRED FIELD
                
                description=f"🚨 SUSPICIOUS CONNECTION: {source_ip}:{source_port} -> {destination_ip}:{destination_port}",
                
                raw_event_data={
                    'event_subtype': 'suspicious_connection',
                    'suspicion_reason': 'suspicious_port_or_pattern',
                    'risk_level': 'high',
                    'connection_pattern': 'suspicious',
                    'data_complete': True,
                    'connection_status': conn.status,
                    'is_suspicious_port': destination_port in self.suspicious_ports,
                    'service_name': self.common_services.get(destination_port, 'Unknown')
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Complete suspicious connection event failed: {e}")
            return None
    
    async def _create_complete_external_connection_event(self, conn):
        """EVENT TYPE 4: External Connection Event with ALL required fields"""
        try:
            # FIXED: Extract ALL required network fields
            source_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
            source_port = conn.laddr.port if conn.laddr else 0
            destination_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
            destination_port = conn.raddr.port if conn.raddr else 0
            protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
            direction = "Outbound"  # External connections are typically outbound
            
            # FIXED: Create network event with ALL required fields populated
            return EventData(
                event_type="Network",
                event_action=EventAction.CONNECT,
                event_timestamp=datetime.now(),
                severity="Info",
                
                # FIXED: ALWAYS populate ALL network-specific fields
                source_ip=source_ip,                    # REQUIRED FIELD
                source_port=source_port,                # REQUIRED FIELD
                destination_ip=destination_ip,          # REQUIRED FIELD
                destination_port=destination_port,      # REQUIRED FIELD
                protocol=protocol,                      # REQUIRED FIELD
                direction=direction,                    # REQUIRED FIELD
                
                description=f"🌐 EXTERNAL CONNECTION: {source_ip}:{source_port} -> {destination_ip}:{destination_port}",
                
                raw_event_data={
                    'event_subtype': 'external_connection',
                    'connection_type': 'outbound_external',
                    'destination_classification': 'external_ip',
                    'data_complete': True,
                    'is_external': True,
                    'connection_status': conn.status,
                    'service_name': self.common_services.get(destination_port, 'Unknown')
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Complete external connection event failed: {e}")
            return None
    
    async def _create_complete_listening_port_event(self, conn):
        """EVENT TYPE 5: Listening Port Event with ALL required fields"""
        try:
            # FIXED: Extract ALL required network fields for listening port
            source_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
            source_port = conn.laddr.port if conn.laddr else 0
            destination_ip = "0.0.0.0"  # Listening ports don't have destinations
            destination_port = 0        # Listening ports don't have destination ports
            protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
            direction = "Listening"
            
            # FIXED: Create network event with ALL required fields populated
            return EventData(
                event_type="Network",
                event_action=EventAction.ACCESS,
                event_timestamp=datetime.now(),
                severity="Medium" if source_port in self.suspicious_ports else "Info",
                
                # FIXED: ALWAYS populate ALL network-specific fields
                source_ip=source_ip,                    # REQUIRED FIELD
                source_port=source_port,                # REQUIRED FIELD
                destination_ip=destination_ip,          # REQUIRED FIELD (0.0.0.0 for listening)
                destination_port=destination_port,      # REQUIRED FIELD (0 for listening)
                protocol=protocol,                      # REQUIRED FIELD
                direction=direction,                    # REQUIRED FIELD
                
                description=f"🔌 LISTENING PORT: {source_ip}:{source_port} ({protocol})",
                
                raw_event_data={
                    'event_subtype': 'listening_port',
                    'port': source_port,
                    'service_name': self.common_services.get(source_port, 'Unknown'),
                    'is_suspicious_port': source_port in self.suspicious_ports,
                    'data_complete': True,
                    'connection_status': 'LISTEN',
                    'is_listening': True,
                    'bind_address': source_ip
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Complete listening port event failed: {e}")
            return None
    
    async def _create_complete_network_summary_event(self):
        """EVENT TYPE 6: Network Summary Event with ALL required fields"""
        try:
            active_connections = len(self.monitored_connections)
            
            # FIXED: Create network event with ALL required fields populated (using defaults for summary)
            return EventData(
                event_type="Network",
                event_action=EventAction.RESOURCE_USAGE,
                event_timestamp=datetime.now(),
                severity="Info",
                
                # FIXED: ALWAYS populate ALL network-specific fields (summary uses defaults)
                source_ip="0.0.0.0",                   # REQUIRED FIELD (summary event)
                source_port=0,                         # REQUIRED FIELD (summary event)
                destination_ip="0.0.0.0",              # REQUIRED FIELD (summary event)
                destination_port=0,                    # REQUIRED FIELD (summary event)
                protocol="Summary",                    # REQUIRED FIELD (summary event)
                direction="Summary",                   # REQUIRED FIELD (summary event)
                
                description=f"📊 NETWORK SUMMARY: {active_connections} active connections",
                
                raw_event_data={
                    'event_subtype': 'network_summary',
                    'active_connections': active_connections,
                    'network_statistics': self.stats.copy(),
                    'port_activity_summary': dict(list(self.port_activity.items())[:10]),  # Top 10 ports
                    'connection_types': {
                        'tcp': len([c for c in self.monitored_connections.values() if c.type == socket.SOCK_STREAM]),
                        'udp': len([c for c in self.monitored_connections.values() if c.type == socket.SOCK_DGRAM])
                    },
                    'data_complete': True,
                    'is_summary': True
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Complete network summary event failed: {e}")
            return None
    
    def _determine_connection_direction(self, conn) -> str:
        """Determine connection direction"""
        try:
            if not conn.raddr:
                return "Listening"
            
            # Check if destination is external
            if self._is_external_ip(conn.raddr.ip):
                return "Outbound"
            
            # Check if source is external
            if hasattr(conn, 'laddr') and conn.laddr and self._is_external_ip(conn.laddr.ip):
                return "Inbound"
            
            # Local connections
            if conn.raddr.ip in ['127.0.0.1', '::1']:
                return "Internal"
            
            # Default to outbound for established connections
            if conn.status == 'ESTABLISHED':
                return "Outbound"
            
            return "Unknown"
            
        except Exception as e:
            self.logger.debug(f"Direction determination failed: {e}")
            return "Unknown"
    
    def _is_external_connection(self, conn) -> bool:
        """Check if connection is to external IP"""
        try:
            if not conn.raddr:
                return False
            
            return self._is_external_ip(conn.raddr.ip)
            
        except Exception:
            return False
    
    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP address is external (not private)"""
        try:
            # Check for private IP ranges
            private_ranges = [
                '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                '172.20.', '172.21.', '172.22.', '172.23.',
                '172.24.', '172.25.', '172.26.', '172.27.',
                '172.28.', '172.29.', '172.30.', '172.31.',
                '192.168.', '127.', '169.254.'
            ]
            
            return not any(ip.startswith(prefix) for prefix in private_ranges)
            
        except Exception:
            return False
    
    def get_stats(self) -> Dict:
        """Get detailed statistics for complete network event types"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'Network_CompleteData',
            'connection_established_events': self.stats['connection_established_events'],
            'connection_closed_events': self.stats['connection_closed_events'],
            'suspicious_connection_events': self.stats['suspicious_connection_events'],
            'high_bandwidth_events': self.stats['high_bandwidth_events'],
            'port_scan_events': self.stats['port_scan_events'],
            'dns_query_events': self.stats['dns_query_events'],
            'network_summary_events': self.stats['network_summary_events'],
            'firewall_events': self.stats['firewall_events'],
            'external_connection_events': self.stats['external_connection_events'],
            'total_network_events': self.stats['total_network_events'],
            'active_connections': len(self.monitored_connections),
            'port_activity_count': len(self.port_activity),
            'complete_data_collection': True,
            'all_fields_populated': True,
            'network_event_types_generated': [
                'connection_established', 'connection_closed', 'suspicious_connection',
                'external_connection', 'listening_port', 'network_summary'
            ]
        })
        return base_stats