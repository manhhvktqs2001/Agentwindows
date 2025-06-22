# agent/collectors/network_collector.py - MULTIPLE NETWORK EVENT TYPES
"""
Enhanced Network Collector - Gửi nhiều loại network events liên tục
Thu thập nhiều loại thông tin network và gửi events khác nhau cho server
"""

import psutil
import socket
import asyncio
import logging
import time
from typing import Dict, List, Optional, Set
from datetime import datetime
import subprocess
from collections import defaultdict, deque

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventType, EventAction
from agent.utils.network_utils import get_connection_info, is_suspicious_connection

logger = logging.getLogger('NetworkCollector')

class EnhancedNetworkCollector(BaseCollector):
    """Enhanced Network Collector - Multiple network event types for continuous sending"""
    
    def __init__(self, config_manager=None):
        super().__init__(config_manager, "NetworkCollector")
        
        # MULTIPLE EVENTS: Network tracking
        self.monitored_connections = {}  # connection_key -> connection_info
        self.connection_history = deque(maxlen=1000)
        self.port_activity = defaultdict(int)
        self.bandwidth_usage = defaultdict(list)
        self.dns_queries = deque(maxlen=500)
        
        # MULTIPLE EVENTS: Network categories
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
        
        self.outbound_countries = set()  # Track outbound connections by country
        self.bandwidth_threshold = 10 * 1024 * 1024  # 10MB
        self.polling_interval = 0.5  # 500ms for network monitoring
        
        # MULTIPLE EVENTS: Statistics
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
        
        self.logger.info("Enhanced Network Collector initialized for MULTIPLE NETWORK EVENT TYPES")
    
    async def _collect_data(self):
        """Collect multiple types of network events"""
        try:
            events = []
            current_connections = {}
            
            # MULTIPLE EVENTS: Scan all network connections
            connections = psutil.net_connections(kind='inet')
            
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
                    
                    # EVENT TYPE 1: New Connection Established Event
                    if conn_key not in self.monitored_connections and conn.raddr:
                        event = await self._create_connection_established_event(conn)
                        if event:
                            events.append(event)
                            self.stats['connection_established_events'] += 1
                    
                    # EVENT TYPE 2: Suspicious Connection Event
                    if conn.raddr and is_suspicious_connection(conn):
                        event = await self._create_suspicious_connection_event(conn)
                        if event:
                            events.append(event)
                            self.stats['suspicious_connection_events'] += 1
                    
                    # EVENT TYPE 3: External Connection Event
                    if conn.raddr and self._is_external_connection(conn):
                        event = await self._create_external_connection_event(conn)
                        if event:
                            events.append(event)
                            self.stats['external_connection_events'] += 1
                    
                    # EVENT TYPE 4: Port Activity Event
                    port = conn.laddr.port if conn.laddr else 0
                    self.port_activity[port] += 1
                    if self.port_activity[port] % 10 == 0:  # Every 10 connections on same port
                        event = await self._create_port_activity_event(conn, self.port_activity[port])
                        if event:
                            events.append(event)
                    
                    # EVENT TYPE 5: Service Detection Event
                    if conn.raddr and port in self.common_services:
                        event = await self._create_service_detection_event(conn)
                        if event:
                            events.append(event)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # EVENT TYPE 6: Connection Closed Events
            closed_connections = set(self.monitored_connections.keys()) - set(current_connections.keys())
            for conn_key in closed_connections:
                event = await self._create_connection_closed_event(conn_key, self.monitored_connections[conn_key])
                if event:
                    events.append(event)
                    self.stats['connection_closed_events'] += 1
            
            # EVENT TYPE 7: Network Bandwidth Event
            bandwidth_event = await self._check_network_bandwidth_event()
            if bandwidth_event:
                events.append(bandwidth_event)
                self.stats['high_bandwidth_events'] += 1
            
            # EVENT TYPE 8: Port Scan Detection Event
            port_scan_event = await self._detect_port_scan_event()
            if port_scan_event:
                events.append(port_scan_event)
                self.stats['port_scan_events'] += 1
            
            # EVENT TYPE 9: Network Summary Event (every 20 scans)
            if self.stats['total_network_events'] % 20 == 0:
                summary_event = await self._create_network_summary_event()
                if summary_event:
                    events.append(summary_event)
                    self.stats['network_summary_events'] += 1
            
            # EVENT TYPE 10: DNS Query Event (simulated)
            dns_event = await self._create_dns_query_event()
            if dns_event:
                events.append(dns_event)
                self.stats['dns_query_events'] += 1
            
            # Update tracking
            self.monitored_connections = current_connections
            self.stats['total_network_events'] += len(events)
            
            if events:
                self.logger.info(f"📤 Generated {len(events)} MULTIPLE NETWORK EVENTS for continuous sending")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Multiple network events collection failed: {e}")
            return []
    
    async def _create_connection_established_event(self, conn):
        """EVENT TYPE 1: Connection Established Event"""
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
            
            return EventData(
                event_type=EventType.NETWORK,
                event_action=EventAction.CONNECT,
                event_timestamp=datetime.now(),
                severity="Medium" if conn.raddr.port in self.suspicious_ports else "Info",
                
                source_ip=conn.laddr.ip if conn.laddr else None,
                source_port=conn.laddr.port if conn.laddr else None,
                destination_ip=conn.raddr.ip if conn.raddr else None,
                destination_port=conn.raddr.port if conn.raddr else None,
                protocol='TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                
                process_id=conn.pid,
                process_name=process_info['name'] if process_info else None,
                
                description=f"🔗 CONNECTION ESTABLISHED: {conn.laddr.ip if conn.laddr else 'Unknown'}:{conn.laddr.port if conn.laddr else 'Unknown'} -> {conn.raddr.ip if conn.raddr else 'Unknown'}:{conn.raddr.port if conn.raddr else 'Unknown'}",
                raw_event_data={
                    'event_subtype': 'connection_established',
                    'connection_status': conn.status,
                    'process_info': process_info,
                    'is_suspicious_port': conn.raddr.port in self.suspicious_ports if conn.raddr else False,
                    'service_name': self.common_services.get(conn.raddr.port if conn.raddr else 0, 'Unknown')
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Connection established event failed: {e}")
            return None
    
    async def _create_connection_closed_event(self, conn_key: str, conn):
        """EVENT TYPE 2: Connection Closed Event"""
        try:
            return EventData(
                event_type=EventType.NETWORK,
                event_action=EventAction.DISCONNECT,
                event_timestamp=datetime.now(),
                severity="Info",
                
                source_ip=conn.laddr.ip if conn.laddr else None,
                source_port=conn.laddr.port if conn.laddr else None,
                destination_ip=conn.raddr.ip if conn.raddr else None,
                destination_port=conn.raddr.port if conn.raddr else None,
                
                description=f"❌ CONNECTION CLOSED: {conn_key}",
                raw_event_data={
                    'event_subtype': 'connection_closed',
                    'connection_key': conn_key,
                    'close_time': time.time()
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Connection closed event failed: {e}")
            return None
    
    async def _create_suspicious_connection_event(self, conn):
        """EVENT TYPE 3: Suspicious Connection Event"""
        try:
            return EventData(
                event_type=EventType.NETWORK,
                event_action=EventAction.SUSPICIOUS_ACTIVITY,
                event_timestamp=datetime.now(),
                severity="High",
                
                source_ip=conn.laddr.ip if conn.laddr else None,
                source_port=conn.laddr.port if conn.laddr else None,
                destination_ip=conn.raddr.ip if conn.raddr else None,
                destination_port=conn.raddr.port if conn.raddr else None,
                
                description=f"🚨 SUSPICIOUS CONNECTION: {conn.raddr.ip if conn.raddr else 'Unknown'}:{conn.raddr.port if conn.raddr else 'Unknown'}",
                raw_event_data={
                    'event_subtype': 'suspicious_connection',
                    'suspicion_reason': 'suspicious_port_or_pattern',
                    'risk_level': 'high',
                    'connection_pattern': 'suspicious'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Suspicious connection event failed: {e}")
            return None
    
    async def _create_external_connection_event(self, conn):
        """EVENT TYPE 4: External Connection Event"""
        try:
            return EventData(
                event_type=EventType.NETWORK,
                event_action=EventAction.CONNECT,
                event_timestamp=datetime.now(),
                severity="Info",
                
                source_ip=conn.laddr.ip if conn.laddr else None,
                destination_ip=conn.raddr.ip if conn.raddr else None,
                destination_port=conn.raddr.port if conn.raddr else None,
                
                description=f"🌐 EXTERNAL CONNECTION: Outbound to {conn.raddr.ip if conn.raddr else 'Unknown'}",
                raw_event_data={
                    'event_subtype': 'external_connection',
                    'connection_type': 'outbound_external',
                    'destination_classification': 'external_ip'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ External connection event failed: {e}")
            return None
    
    async def _create_port_activity_event(self, conn, activity_count: int):
        """EVENT TYPE 5: Port Activity Event"""
        try:
            port = conn.laddr.port if conn.laddr else 0
            service_name = self.common_services.get(port, 'Unknown')
            
            return EventData(
                event_type=EventType.NETWORK,
                event_action=EventAction.ACCESS,
                event_timestamp=datetime.now(),
                severity="Medium" if activity_count > 50 else "Info",
                
                source_port=port,
                
                description=f"🔌 PORT ACTIVITY: Port {port} ({service_name}) - {activity_count} connections",
                raw_event_data={
                    'event_subtype': 'port_activity',
                    'port': port,
                    'service_name': service_name,
                    'activity_count': activity_count,
                    'port_category': 'suspicious' if port in self.suspicious_ports else 'normal'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Port activity event failed: {e}")
            return None
    
    async def _create_service_detection_event(self, conn):
        """EVENT TYPE 6: Service Detection Event"""
        try:
            port = conn.raddr.port if conn.raddr else 0
            service_name = self.common_services.get(port, 'Unknown')
            
            return EventData(
                event_type=EventType.NETWORK,
                event_action=EventAction.ACCESS,
                event_timestamp=datetime.now(),
                severity="Info",
                
                destination_ip=conn.raddr.ip if conn.raddr else None,
                destination_port=port,
                
                description=f"🔍 SERVICE DETECTED: {service_name} service on {conn.raddr.ip if conn.raddr else 'Unknown'}:{port}",
                raw_event_data={
                    'event_subtype': 'service_detection',
                    'service_name': service_name,
                    'service_port': port,
                    'service_category': 'common_service'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Service detection event failed: {e}")
            return None
    
    async def _check_network_bandwidth_event(self):
        """EVENT TYPE 7: Network Bandwidth Event"""
        try:
            net_io = psutil.net_io_counters()
            current_time = time.time()
            
            if hasattr(self, '_last_net_io') and hasattr(self, '_last_net_time'):
                time_diff = current_time - self._last_net_time
                if time_diff > 0:
                    bytes_sent_rate = (net_io.bytes_sent - self._last_net_io.bytes_sent) / time_diff
                    bytes_recv_rate = (net_io.bytes_recv - self._last_net_io.bytes_recv) / time_diff
                    total_rate = bytes_sent_rate + bytes_recv_rate
                    
                    if total_rate > self.bandwidth_threshold:  # > 10MB/s
                        return EventData(
                            event_type=EventType.NETWORK,
                            event_action=EventAction.RESOURCE_USAGE,
                            event_timestamp=datetime.now(),
                            severity="Medium",
                            
                            description=f"📊 HIGH BANDWIDTH: {total_rate/(1024*1024):.1f}MB/s network usage",
                            raw_event_data={
                                'event_subtype': 'high_bandwidth_usage',
                                'bytes_sent_rate': bytes_sent_rate,
                                'bytes_recv_rate': bytes_recv_rate,
                                'total_rate_mbps': total_rate / (1024 * 1024),
                                'threshold_mbps': self.bandwidth_threshold / (1024 * 1024)
                            }
                        )
            
            self._last_net_io = net_io
            self._last_net_time = current_time
            
        except Exception as e:
            self.logger.error(f"❌ Bandwidth event check failed: {e}")
        return None
    
    async def _detect_port_scan_event(self):
        """EVENT TYPE 8: Port Scan Detection Event"""
        try:
            # Simple port scan detection based on connection patterns
            recent_connections = list(self.monitored_connections.values())
            
            if len(recent_connections) > 20:  # Many connections
                unique_dest_ips = set()
                unique_dest_ports = set()
                
                for conn in recent_connections[-20:]:  # Last 20 connections
                    if conn.raddr:
                        unique_dest_ips.add(conn.raddr.ip)
                        unique_dest_ports.add(conn.raddr.port)
                
                # Potential port scan: many ports on few IPs
                if len(unique_dest_ports) > 10 and len(unique_dest_ips) < 5:
                    return EventData(
                        event_type=EventType.NETWORK,
                        event_action=EventAction.SUSPICIOUS_ACTIVITY,
                        event_timestamp=datetime.now(),
                        severity="High",
                        
                        description=f"🔍 POTENTIAL PORT SCAN: {len(unique_dest_ports)} ports scanned on {len(unique_dest_ips)} IPs",
                        raw_event_data={
                            'event_subtype': 'port_scan_detected',
                            'unique_ports_count': len(unique_dest_ports),
                            'unique_ips_count': len(unique_dest_ips),
                            'connection_count': len(recent_connections),
                            'scan_pattern': 'many_ports_few_ips'
                        }
                    )
        except Exception as e:
            self.logger.error(f"❌ Port scan detection failed: {e}")
        return None
    
    async def _create_network_summary_event(self):
        """EVENT TYPE 9: Network Summary Event"""
        try:
            active_connections = len(self.monitored_connections)
            
            return EventData(
                event_type=EventType.NETWORK,
                event_action=EventAction.RESOURCE_USAGE,
                event_timestamp=datetime.now(),
                severity="Info",
                
                description=f"📊 NETWORK SUMMARY: {active_connections} active connections",
                raw_event_data={
                    'event_subtype': 'network_summary',
                    'active_connections': active_connections,
                    'network_statistics': self.stats.copy(),
                    'port_activity_summary': dict(list(self.port_activity.items())[:10]),  # Top 10 ports
                    'connection_types': {
                        'tcp': len([c for c in self.monitored_connections.values() if c.type == socket.SOCK_STREAM]),
                        'udp': len([c for c in self.monitored_connections.values() if c.type == socket.SOCK_DGRAM])
                    }
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Network summary event failed: {e}")
            return None
    
    async def _create_dns_query_event(self):
        """EVENT TYPE 10: DNS Query Event (simulated)"""
        try:
            # Simulate DNS query detection based on port 53 connections
            dns_connections = [c for c in self.monitored_connections.values() 
                             if c.raddr and c.raddr.port == 53]
            
            if dns_connections:
                dns_conn = dns_connections[0]  # Take first DNS connection
                return EventData(
                    event_type=EventType.NETWORK,
                    event_action=EventAction.ACCESS,
                    event_timestamp=datetime.now(),
                    severity="Info",
                    
                    source_ip=dns_conn.laddr.ip if dns_conn.laddr else None,
                    destination_ip=dns_conn.raddr.ip if dns_conn.raddr else None,
                    destination_port=53,
                    protocol='UDP',
                    
                    description=f"🔍 DNS QUERY: DNS resolution to {dns_conn.raddr.ip if dns_conn.raddr else 'Unknown'}",
                    raw_event_data={
                        'event_subtype': 'dns_query',
                        'dns_server': dns_conn.raddr.ip if dns_conn.raddr else None,
                        'query_type': 'A_record',  # Simulated
                        'dns_activity': 'domain_resolution'
                    }
                )
        except Exception as e:
            self.logger.error(f"❌ DNS query event failed: {e}")
        return None
    
    def _is_external_connection(self, conn) -> bool:
        """Check if connection is to external IP"""
        try:
            if not conn.raddr:
                return False
            
            ip = conn.raddr.ip
            
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
        """Get detailed statistics for multiple network event types"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'Network_MultipleEvents',
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
            'multiple_event_types': True,
            'network_event_types_generated': [
                'connection_established', 'connection_closed', 'suspicious_connection',
                'external_connection', 'port_activity', 'service_detection',
                'high_bandwidth_usage', 'port_scan_detected', 'network_summary', 'dns_query'
            ]
        })
        return base_stats