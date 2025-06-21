# agent/collectors/network_collector.py
"""
Network Collector - Enhanced network connection monitoring
Monitors network connections, DNS queries, and suspicious traffic patterns
"""

import asyncio
import logging
import psutil
import socket
import ipaddress
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
import json

from .base_collector import BaseCollector
from ..schemas.events import EventData

class NetworkConnectionTracker:
    """Track network connections and detect suspicious patterns"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Connection tracking
        self.known_connections: Set[Tuple] = set()
        self.connection_history: deque = deque(maxlen=10000)
        
        # Suspicious activity detection
        self.connection_counts: Dict[str, int] = defaultdict(int)
        self.port_scan_detection: Dict[str, Set[int]] = defaultdict(set)
        self.beaconing_detection: Dict[str, List[float]] = defaultdict(list)
        
        # Known suspicious ports
        self.suspicious_ports = {
            # Common malware ports
            4444, 5555, 6666, 7777, 8888, 9999,
            # RAT ports
            1337, 31337, 12345, 54321,
            # Backdoor ports
            2222, 3333, 10101, 20202,
            # Bitcoin/crypto mining
            8333, 8332, 9332, 9333,
            # Tor
            9050, 9051, 9150, 9151
        }
        
        # Private IP ranges
        self.private_ranges = [
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('127.0.0.0/8')
        ]
    
    def add_connection(self, conn_info: Dict) -> Dict:
        """Add connection and analyze for suspicious patterns"""
        try:
            # Create connection tuple for tracking
            conn_tuple = (
                conn_info.get('local_ip'),
                conn_info.get('local_port'),
                conn_info.get('remote_ip'),
                conn_info.get('remote_port'),
                conn_info.get('protocol')
            )
            
            # Check if new connection
            is_new = conn_tuple not in self.known_connections
            self.known_connections.add(conn_tuple)
            
            # Add to history
            conn_info['timestamp'] = time.time()
            self.connection_history.append(conn_info)
            
            # Analyze for suspicious patterns
            analysis_result = {
                'is_new_connection': is_new,
                'is_suspicious': False,
                'risk_score': 0,
                'suspicious_indicators': []
            }
            
            if is_new:
                analysis_result.update(self._analyze_connection(conn_info))
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"❌ Connection tracking error: {e}")
            return {'is_new_connection': False, 'is_suspicious': False, 'risk_score': 0}
    
    def _analyze_connection(self, conn_info: Dict) -> Dict:
        """Analyze connection for suspicious patterns"""
        suspicious_indicators = []
        risk_score = 0
        
        try:
            remote_ip = conn_info.get('remote_ip')
            remote_port = conn_info.get('remote_port')
            local_port = conn_info.get('local_port')
            direction = conn_info.get('direction', '')
            
            # Check suspicious ports
            if remote_port in self.suspicious_ports:
                suspicious_indicators.append(f"suspicious_port_{remote_port}")
                risk_score += 40
            
            # Check for external connections
            if remote_ip and self._is_external_ip(remote_ip):
                risk_score += 10
                
                # Check for unusual high ports
                if remote_port and remote_port > 49152:
                    suspicious_indicators.append("high_port_external")
                    risk_score += 20
            
            # Check for port scanning behavior
            if direction == 'Outbound' and remote_ip:
                self.port_scan_detection[remote_ip].add(remote_port)
                if len(self.port_scan_detection[remote_ip]) > 10:
                    suspicious_indicators.append("potential_port_scan")
                    risk_score += 50
            
            # Check for beaconing behavior
            if remote_ip and direction == 'Outbound':
                current_time = time.time()
                self.beaconing_detection[remote_ip].append(current_time)
                
                # Keep only recent connections (last 10 minutes)
                self.beaconing_detection[remote_ip] = [
                    t for t in self.beaconing_detection[remote_ip] 
                    if current_time - t < 600
                ]
                
                # Check for regular intervals (beaconing)
                if len(self.beaconing_detection[remote_ip]) >= 5:
                    intervals = []
                    times = sorted(self.beaconing_detection[remote_ip])
                    for i in range(1, len(times)):
                        intervals.append(times[i] - times[i-1])
                    
                    # Check if intervals are suspiciously regular
                    if intervals and max(intervals) - min(intervals) < 10:  # Within 10 seconds
                        suspicious_indicators.append("potential_beaconing")
                        risk_score += 60
            
            # Check for localhost connections on unusual ports
            if (remote_ip in ['127.0.0.1', '::1'] and 
                remote_port and remote_port not in [80, 443, 8080, 3389]):
                suspicious_indicators.append("localhost_unusual_port")
                risk_score += 15
            
            return {
                'is_suspicious': len(suspicious_indicators) > 0,
                'risk_score': min(risk_score, 100),
                'suspicious_indicators': suspicious_indicators
            }
            
        except Exception as e:
            self.logger.error(f"❌ Connection analysis error: {e}")
            return {'is_suspicious': False, 'risk_score': 0, 'suspicious_indicators': []}
    
    def _is_external_ip(self, ip_str: str) -> bool:
        """Check if IP address is external (not private)"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return not any(ip in private_range for private_range in self.private_ranges)
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    def cleanup_old_data(self):
        """Clean up old tracking data"""
        try:
            current_time = time.time()
            
            # Clean up port scan detection (keep only last 5 minutes)
            for ip in list(self.port_scan_detection.keys()):
                # Reset if no recent activity
                if ip not in [conn.get('remote_ip') for conn in 
                             list(self.connection_history)[-100:] if conn.get('timestamp', 0) > current_time - 300]:
                    del self.port_scan_detection[ip]
            
            # Clean up beaconing detection
            for ip in list(self.beaconing_detection.keys()):
                self.beaconing_detection[ip] = [
                    t for t in self.beaconing_detection[ip] 
                    if current_time - t < 600
                ]
                if not self.beaconing_detection[ip]:
                    del self.beaconing_detection[ip]
            
        except Exception as e:
            self.logger.error(f"❌ Cleanup error: {e}")

class NetworkCollector(BaseCollector):
    """Enhanced network collector with connection tracking and threat detection"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "NetworkCollector")
        
        # Network monitoring
        self.connection_tracker = NetworkConnectionTracker()
        
        # Configuration
        self.monitor_tcp = True
        self.monitor_udp = True
        self.monitor_listening = True
        self.monitor_established = True
        self.exclude_loopback = True
        self.exclude_private = False
        
        # Process name resolution
        self.resolve_process_names = True
        self.process_cache: Dict[int, str] = {}
        
        # Performance settings
        self.max_connections_per_scan = 1000
        self.connection_scan_interval = 10  # seconds
        self.last_cleanup_time = time.time()
    
    async def _collector_specific_init(self):
        """Initialize network collector"""
        try:
            # Validate psutil network capabilities
            test_connections = psutil.net_connections(kind='inet')
            self.logger.info(f"✅ Network monitoring capability validated: {len(test_connections)} connections")
            
        except Exception as e:
            self.logger.error(f"❌ Network collector initialization failed: {e}")
            raise
    
    async def _collect_data(self):
        """Collect network connection data"""
        try:
            events = []
            connections_processed = 0
            
            # Get network connections
            connection_kinds = []
            if self.monitor_tcp:
                connection_kinds.extend(['tcp', 'tcp6'])
            if self.monitor_udp:
                connection_kinds.extend(['udp', 'udp6'])
            
            for kind in connection_kinds:
                try:
                    connections = psutil.net_connections(kind=kind)
                    
                    for conn in connections:
                        if connections_processed >= self.max_connections_per_scan:
                            break
                        
                        # Filter connections
                        if not self._should_monitor_connection(conn):
                            continue
                        
                        # Process connection
                        event = await self._process_connection(conn)
                        if event:
                            events.append(event)
                            connections_processed += 1
                
                except Exception as e:
                    self.logger.debug(f"Error getting {kind} connections: {e}")
            
            # Periodic cleanup
            current_time = time.time()
            if current_time - self.last_cleanup_time > 300:  # Every 5 minutes
                self.connection_tracker.cleanup_old_data()
                self._cleanup_process_cache()
                self.last_cleanup_time = current_time
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Network data collection error: {e}")
            return []
    
    def _should_monitor_connection(self, conn) -> bool:
        """Check if connection should be monitored"""
        try:
            # Skip connections without address info
            if not conn.laddr:
                return False
            
            # Filter by status
            if self.monitor_listening and conn.status == psutil.CONN_LISTEN:
                return True
            elif self.monitor_established and conn.status == psutil.CONN_ESTABLISHED:
                return True
            elif conn.status in [psutil.CONN_SYN_SENT, psutil.CONN_SYN_RECV]:
                return True
            elif not self.monitor_listening and conn.status == psutil.CONN_LISTEN:
                return False
            
            # Exclude loopback if configured
            if self.exclude_loopback and conn.laddr.ip in ['127.0.0.1', '::1']:
                return False
            
            # Exclude private IPs if configured
            if self.exclude_private and conn.raddr:
                if self.connection_tracker._is_external_ip(conn.raddr.ip):
                    return False
            
            return True
            
        except Exception:
            return False
    
    async def _process_connection(self, conn) -> Optional[EventData]:
        """Process network connection and create event"""
        try:
            # Extract connection information
            conn_info = {
                'local_ip': conn.laddr.ip if conn.laddr else None,
                'local_port': conn.laddr.port if conn.laddr else None,
                'remote_ip': conn.raddr.ip if conn.raddr else None,
                'remote_port': conn.raddr.port if conn.raddr else None,
                'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                'status': conn.status,
                'pid': conn.pid,
                'direction': self._determine_direction(conn)
            }
            
            # Get process name
            process_name = await self._get_process_name(conn.pid)
            conn_info['process_name'] = process_name
            
            # Analyze connection for suspicious patterns
            analysis = self.connection_tracker.add_connection(conn_info)
            
            # Only create events for new or suspicious connections
            if not analysis.get('is_new_connection') and not analysis.get('is_suspicious'):
                return None
            
            # Determine event severity
            severity = self._determine_connection_severity(conn_info, analysis)
            
            # Create network event
            event_data = EventData(
                event_type='Network',
                event_action='Connection',
                event_timestamp=datetime.now(),
                source_ip=conn_info['local_ip'],
                source_port=conn_info['local_port'],
                destination_ip=conn_info['remote_ip'],
                destination_port=conn_info['remote_port'],
                protocol=conn_info['protocol'],
                direction=conn_info['direction'],
                process_id=conn.pid,
                process_name=process_name,
                severity=severity,
                raw_event_data=json.dumps({
                    'status': conn_info['status'],
                    'analysis': analysis,
                    'is_external': self.connection_tracker._is_external_ip(conn_info['remote_ip']) if conn_info['remote_ip'] else False
                })
            )
            
            return event_data
            
        except Exception as e:
            self.logger.debug(f"Connection processing error: {e}")
            return None
    
    def _determine_direction(self, conn) -> str:
        """Determine connection direction"""
        try:
            if conn.status == psutil.CONN_LISTEN:
                return 'Listening'
            elif conn.raddr:
                # Check if remote IP is external
                if self.connection_tracker._is_external_ip(conn.raddr.ip):
                    return 'Outbound'
                else:
                    return 'Internal'
            else:
                return 'Unknown'
        except Exception:
            return 'Unknown'
    
    async def _get_process_name(self, pid: Optional[int]) -> Optional[str]:
        """Get process name for PID with caching"""
        try:
            if not pid:
                return None
            
            # Check cache first
            if pid in self.process_cache:
                return self.process_cache[pid]
            
            # Get process name
            try:
                process = psutil.Process(pid)
                process_name = process.name()
                
                # Cache the result
                self.process_cache[pid] = process_name
                return process_name
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return None
                
        except Exception:
            return None
    
    def _cleanup_process_cache(self):
        """Clean up process name cache"""
        try:
            # Remove entries for non-existent processes
            current_pids = set(p.pid for p in psutil.process_iter())
            cached_pids = set(self.process_cache.keys())
            
            for pid in cached_pids - current_pids:
                self.process_cache.pop(pid, None)
            
            self.logger.debug(f"🧹 Process cache cleaned: {len(cached_pids - current_pids)} entries removed")
            
        except Exception as e:
            self.logger.error(f"❌ Process cache cleanup error: {e}")
    
    def _determine_connection_severity(self, conn_info: Dict, analysis: Dict) -> str:
        """Determine connection event severity"""
        try:
            risk_score = analysis.get('risk_score', 0)
            suspicious_indicators = analysis.get('suspicious_indicators', [])
            remote_ip = conn_info.get('remote_ip', '')
            remote_port = conn_info.get('remote_port', 0)
            protocol = conn_info.get('protocol', '')
            
            # High severity for suspicious connections
            if any([
                remote_port in self.connection_tracker.suspicious_ports,
                'potential_port_scan' in suspicious_indicators,
                'potential_beaconing' in suspicious_indicators
            ]):
                return 'High'
            
            # Medium severity for unusual connections
            if any([
                remote_port > 49152,  # Dynamic ports
                remote_ip.startswith('10.') or remote_ip.startswith('192.168.'),
                protocol in ['UDP', 'ICMP']
            ]):
                return 'Medium'
            
            # Default to info
            return 'Info'
            
        except Exception:
            return 'Info'
    
    def get_network_stats(self) -> Dict:
        """Get network monitoring statistics"""
        try:
            stats = {
                'known_connections': len(self.connection_tracker.known_connections),
                'connection_history_size': len(self.connection_tracker.connection_history),
                'process_cache_size': len(self.process_cache),
                'port_scan_targets': len(self.connection_tracker.port_scan_detection),
                'beaconing_targets': len(self.connection_tracker.beaconing_detection),
                'monitor_tcp': self.monitor_tcp,
                'monitor_udp': self.monitor_udp,
                'monitor_listening': self.monitor_listening,
                'monitor_established': self.monitor_established,
                'exclude_loopback': self.exclude_loopback,
                'exclude_private': self.exclude_private,
                'max_connections_per_scan': self.max_connections_per_scan
            }
            
            # Get current network interface statistics
            try:
                net_io = psutil.net_io_counters()
                stats.update({
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv,
                    'errors_in': net_io.errin,
                    'errors_out': net_io.errout,
                    'drops_in': net_io.dropin,
                    'drops_out': net_io.dropout
                })
            except Exception:
                pass
            
            return stats
            
        except Exception as e:
            self.logger.error(f"❌ Network stats error: {e}")
            return {}
    
    def configure_monitoring(self, **kwargs):
        """Configure network monitoring options"""
        if 'monitor_tcp' in kwargs:
            self.monitor_tcp = kwargs['monitor_tcp']
        if 'monitor_udp' in kwargs:
            self.monitor_udp = kwargs['monitor_udp']
        if 'monitor_listening' in kwargs:
            self.monitor_listening = kwargs['monitor_listening']
        if 'monitor_established' in kwargs:
            self.monitor_established = kwargs['monitor_established']
        if 'exclude_loopback' in kwargs:
            self.exclude_loopback = kwargs['exclude_loopback']
        if 'exclude_private' in kwargs:
            self.exclude_private = kwargs['exclude_private']
        if 'max_connections_per_scan' in kwargs:
            self.max_connections_per_scan = kwargs['max_connections_per_scan']
        
        self.logger.info(f"🔧 Network monitoring configured: {kwargs}")
    
    def get_suspicious_connections(self) -> List[Dict]:
        """Get list of current suspicious connections"""
        try:
            suspicious_connections = []
            
            # Analyze recent connections from history
            recent_time = time.time() - 300  # Last 5 minutes
            
            for conn in self.connection_tracker.connection_history:
                if conn.get('timestamp', 0) > recent_time:
                    analysis = self.connection_tracker._analyze_connection(conn)
                    if analysis.get('is_suspicious'):
                        suspicious_connections.append({
                            'remote_ip': conn.get('remote_ip'),
                            'remote_port': conn.get('remote_port'),
                            'protocol': conn.get('protocol'),
                            'process_name': conn.get('process_name'),
                            'risk_score': analysis.get('risk_score'),
                            'indicators': analysis.get('suspicious_indicators'),
                            'timestamp': conn.get('timestamp')
                        })
            
            return suspicious_connections
            
        except Exception as e:
            self.logger.error(f"❌ Suspicious connections query error: {e}")
            return []
    
    def check_ip_reputation(self, ip: str) -> Dict:
        """Check IP address reputation (placeholder for future integration)"""
        # This could be expanded to integrate with threat intelligence feeds
        return {
            'is_known_malicious': False,
            'reputation_score': 0,
            'threat_categories': [],
            'last_seen': None
        }
    
    def detect_data_exfiltration(self) -> List[Dict]:
        """Detect potential data exfiltration patterns"""
        try:
            alerts = []
            current_time = time.time()
            
            # Analyze outbound connections for large data transfers
            outbound_volumes = defaultdict(int)
            
            for conn in self.connection_tracker.connection_history:
                if (conn.get('timestamp', 0) > current_time - 1800 and  # Last 30 minutes
                    conn.get('direction') == 'Outbound' and
                    self.connection_tracker._is_external_ip(conn.get('remote_ip', ''))):
                    
                    key = f"{conn.get('remote_ip')}:{conn.get('remote_port')}"
                    outbound_volumes[key] += 1
            
            # Check for suspicious volume patterns
            for connection, count in outbound_volumes.items():
                if count > 100:  # More than 100 connections to same external endpoint
                    alerts.append({
                        'type': 'potential_data_exfiltration',
                        'connection': connection,
                        'connection_count': count,
                        'severity': 'High',
                        'description': f'High volume of connections to external endpoint: {connection}'
                    })
            
            return alerts
            
        except Exception as e:
            self.logger.error(f"❌ Data exfiltration detection error: {e}")
            return []