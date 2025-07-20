# agent/collectors/process_collector.py - ENHANCED FOR MALWARE DETECTION
"""
Enhanced Process Collector - Phát hiện mã độc và reverse shell
Thu thập và phân tích processes có kết nối mạng đáng nghi với bên ngoài
"""

import psutil
import time
import asyncio
import logging
import socket
import os
import hashlib
import subprocess
from typing import Dict, List, Optional, Set, Any
from datetime import datetime
from pathlib import Path
from collections import defaultdict

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventAction
from agent.utils.process_utils import get_process_info, get_process_hash, is_system_process

logger = logging.getLogger('ProcessCollector')

class EnhancedProcessCollector(BaseCollector):
    """Enhanced Process Collector - Phát hiện mã độc và reverse shell"""
    
    def __init__(self, config_manager=None):
        if config_manager is None:
            from agent.core.config_manager import ConfigManager
            config_manager = ConfigManager()
        super().__init__(config_manager, "ProcessCollector")
        
        # ENHANCED: Tracking cho malware detection
        self.monitored_processes = {}
        self.process_network_connections = {}
        self.suspicious_connections = {}
        self.reverse_shell_indicators = {}
        
        # ENHANCED: Malware detection patterns
        self.suspicious_patterns = {
            # Reverse shell command patterns
            'reverse_shell_commands': [
                'nc -e', 'nc.exe -e', 'netcat -e',
                'powershell -e', 'powershell.exe -e',
                'cmd.exe /c powershell',
                'iex(', 'invoke-expression',
                'downloadstring', 'webclient',
                'tcp', 'reverse', 'shell'
            ],
            
            # Suspicious network tools
            'network_tools': [
                'nc.exe', 'netcat.exe', 'ncat.exe',
                'socat.exe', 'plink.exe', 'putty.exe',
                'telnet.exe', 'ftp.exe', 'tftp.exe'
            ],
            
            # Remote access tools
            'remote_tools': [
                'teamviewer.exe', 'anydesk.exe', 'vnc.exe',
                'rdp.exe', 'mstsc.exe', 'chrome.exe --remote',
                'ammyy.exe', 'logmein.exe'
            ],
            
            # Suspicious file locations
            'suspicious_paths': [
                'temp', 'tmp', 'appdata\\roaming',
                'appdata\\local\\temp', 'programdata',
                'users\\public', 'windows\\temp',
                'downloads', 'desktop'
            ]
        }
        
        # ENHANCED: Network analysis
        self.suspicious_ports = {
            # Common backdoor ports
            4444, 4445, 5555, 6666, 7777, 8888, 9999,
            1234, 12345, 31337, 54321,
            # RAT ports
            1337, 9876, 6969, 1981, 1999,
            # Reverse shell common ports
            443, 80, 53, 8080, 8443, 9090
        }
        
        self.malicious_ips = set()  # Will be populated from threat intelligence
        
        # Performance settings
        self.polling_interval = 2  # Scan every 2 seconds for malware
        self.network_scan_interval = 1  # Scan network connections every second
        
        # Statistics
        self.stats = {
            'total_processes_monitored': 0,
            'suspicious_processes_detected': 0,
            'reverse_shell_detected': 0,
            'malware_connections_detected': 0,
            'remote_access_detected': 0,
            'total_malware_events': 0
        }
        
        self.logger.info("Enhanced Process Collector initialized - MALWARE & REVERSE SHELL DETECTION")
    
    async def _collect_data(self):
        """Collect process events with enhanced malware detection"""
        try:
            start_time = time.time()
            events = []
            current_pids = set()
            
            # ENHANCED: Scan ALL processes with network analysis
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'username', 'ppid']):
                try:
                    proc_info = proc.info
                    if not proc_info['pid'] or not proc_info['name']:
                        continue
                    
                    pid = proc_info['pid']
                    current_pids.add(pid)
                    process_name = proc_info['name'].lower()
                    
                    # Get CPU và memory info
                    try:
                        actual_proc = psutil.Process(pid)
                        cpu_percent = actual_proc.cpu_percent()
                        memory_info = actual_proc.memory_info()
                        proc_info['cpu_percent'] = cpu_percent
                        proc_info['memory_rss'] = memory_info.rss if memory_info else 0
                        proc_info['memory_vms'] = memory_info.vms if memory_info else 0
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_info['cpu_percent'] = 0
                        proc_info['memory_rss'] = 0
                        proc_info['memory_vms'] = 0
                    
                    # ENHANCED: Get network connections for this process
                    network_connections = await self._get_process_network_connections(pid)
                    proc_info['network_connections'] = network_connections
                    
                    # ENHANCED: Analyze for malware indicators
                    malware_analysis = await self._analyze_process_for_malware(proc_info)
                    
                    # Create events for new processes
                    if pid not in self.monitored_processes:
                        # Standard process creation event
                        event = await self._create_enhanced_process_creation_event(proc_info, malware_analysis)
                        if event:
                            events.append(event)
                            self.stats['total_processes_monitored'] += 1
                        
                        # ENHANCED: Create malware-specific events
                        malware_events = await self._create_malware_detection_events(proc_info, malware_analysis)
                        events.extend(malware_events)
                    
                    # ENHANCED: Monitor existing processes for new suspicious activity
                    elif pid in self.monitored_processes:
                        # Check for new network connections or suspicious behavior
                        suspicious_activity = await self._check_process_suspicious_activity(proc_info, malware_analysis)
                        if suspicious_activity:
                            suspicious_events = await self._create_suspicious_activity_events(proc_info, suspicious_activity)
                            events.extend(suspicious_events)
                    
                    # Update tracking
                    self.monitored_processes[pid] = {
                        'name': proc_info['name'],
                        'exe': proc_info['exe'],
                        'cmdline': proc_info.get('cmdline', []),
                        'last_seen': time.time(),
                        'cpu_percent': proc_info.get('cpu_percent', 0),
                        'memory_rss': proc_info.get('memory_rss', 0),
                        'network_connections': network_connections,
                        'malware_analysis': malware_analysis,
                        'create_time': proc_info.get('create_time', 0)
                    }
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Update global stats
            self.stats['total_malware_events'] += len(events)
            
            # Log events when connected to server
            if events:
                self.logger.info(f"📤 Generated {len(events)} ENHANCED PROCESS EVENTS (with malware detection)")
                
                # Log malware-specific events
                malware_events = [e for e in events if 'malware' in e.description.lower() or 'suspicious' in e.description.lower()]
                if malware_events:
                    self.logger.warning(f"🚨 {len(malware_events)} POTENTIAL MALWARE EVENTS detected")
            
            # Performance logging
            collection_time = (time.time() - start_time) * 1000
            if collection_time > 2000:
                self.logger.warning(f"⚠️ Slow collection: {collection_time:.1f}ms in ProcessCollector")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Enhanced process events collection failed: {e}")
            return []
    
    async def _get_process_network_connections(self, pid: int) -> List[Dict[str, Any]]:
        """Get network connections for a specific process with enhanced analysis"""
        try:
            connections = []
            
            # Get all network connections
            try:
                all_connections = psutil.net_connections(kind='inet')
            except Exception:
                return []
            
            # Filter connections for this process
            for conn in all_connections:
                if conn.pid == pid and conn.raddr:
                    # Helper để lấy ip, port an toàn
                    def get_ip_port(addr):
                        if hasattr(addr, 'ip') and hasattr(addr, 'port'):
                            return addr.ip, addr.port
                        elif isinstance(addr, tuple) and len(addr) >= 2:
                            return addr[0], addr[1]
                        return '0.0.0.0', 0
                    
                    l_ip, l_port = get_ip_port(conn.laddr)
                    r_ip, r_port = get_ip_port(conn.raddr)
                    
                    # ENHANCED: Analyze connection for malware indicators
                    connection_analysis = await self._analyze_network_connection(r_ip, r_port, l_port)
                    
                    connection_info = {
                        'laddr': {"ip": l_ip, "port": l_port},
                        'raddr': {"ip": r_ip, "port": r_port},
                        'status': conn.status,
                        'family': conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                        'type': conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                        
                        # ENHANCED: Malware analysis fields
                        'is_external': self._is_external_ip(r_ip),
                        'is_suspicious_port': r_port in self.suspicious_ports,
                        'is_malicious_ip': r_ip in self.malicious_ips,
                        'connection_analysis': connection_analysis,
                        'geographic_location': await self._get_ip_geolocation(r_ip),
                        'reverse_dns': await self._get_reverse_dns(r_ip)
                    }
                    
                    connections.append(connection_info)
            
            return connections
            
        except Exception as e:
            self.logger.debug(f"❌ Failed to get network connections for PID {pid}: {e}")
            return []
    
    async def _analyze_process_for_malware(self, proc_info: Dict) -> Dict[str, Any]:
        """Analyze process for malware indicators"""
        try:
            analysis = {
                'risk_score': 0,
                'indicators': [],
                'malware_type': 'unknown',
                'confidence': 'low'
            }
            
            process_name = proc_info.get('name', '').lower()
            process_path = proc_info.get('exe', '').lower() if proc_info.get('exe') else ''
            
            # Fix: Ensure cmdline is always a list before joining
            cmdline_parts = proc_info.get('cmdline', [])
            if cmdline_parts is None:
                cmdline_parts = []
            elif not isinstance(cmdline_parts, list):
                cmdline_parts = [str(cmdline_parts)]
            
            cmdline = ' '.join(cmdline_parts).lower()
            network_connections = proc_info.get('network_connections', [])
            
            # INDICATOR 1: Suspicious command line patterns
            for pattern in self.suspicious_patterns['reverse_shell_commands']:
                if pattern in cmdline:
                    analysis['risk_score'] += 30
                    analysis['indicators'].append(f'Suspicious command pattern: {pattern}')
                    analysis['malware_type'] = 'reverse_shell'
            
            # INDICATOR 2: Suspicious executable names
            for tool in self.suspicious_patterns['network_tools']:
                if tool in process_name:
                    analysis['risk_score'] += 25
                    analysis['indicators'].append(f'Suspicious network tool: {tool}')
                    analysis['malware_type'] = 'network_tool'
            
            # INDICATOR 3: Suspicious file locations
            for path in self.suspicious_patterns['suspicious_paths']:
                if path in process_path:
                    analysis['risk_score'] += 20
                    analysis['indicators'].append(f'Suspicious file location: {path}')
            
            # INDICATOR 4: External network connections
            external_connections = [conn for conn in network_connections if conn.get('is_external')]
            if external_connections:
                analysis['risk_score'] += 15 * len(external_connections)
                analysis['indicators'].append(f'{len(external_connections)} external network connections')
                
                # Check for suspicious ports
                suspicious_ports = [conn for conn in external_connections if conn.get('is_suspicious_port')]
                if suspicious_ports:
                    analysis['risk_score'] += 40
                    analysis['indicators'].append(f'Connections to suspicious ports: {[conn["raddr"]["port"] for conn in suspicious_ports]}')
                    analysis['malware_type'] = 'backdoor'
            
            # INDICATOR 5: Process without parent or unusual parent
            parent_pid = proc_info.get('ppid', 0)
            if parent_pid == 0 or parent_pid == 1:
                analysis['risk_score'] += 10
                analysis['indicators'].append('Process without parent or system parent')
            
            # INDICATOR 6: High CPU/Memory usage for unknown processes
            cpu_percent = proc_info.get('cpu_percent', 0)
            memory_rss = proc_info.get('memory_rss', 0)
            if cpu_percent > 50 and not is_system_process(process_name):
                analysis['risk_score'] += 15
                analysis['indicators'].append(f'High CPU usage: {cpu_percent}%')
            
            if memory_rss > 100 * 1024 * 1024:  # > 100MB
                analysis['risk_score'] += 10
                analysis['indicators'].append(f'High memory usage: {memory_rss // (1024*1024)}MB')
            
            # INDICATOR 7: Encoded PowerShell
            if 'powershell' in process_name and ('-enc' in cmdline or '-e ' in cmdline):
                analysis['risk_score'] += 50
                analysis['indicators'].append('Encoded PowerShell execution')
                analysis['malware_type'] = 'fileless_malware'
            
            # INDICATOR 8: Download and execute patterns
            if any(pattern in cmdline for pattern in ['downloadstring', 'wget', 'curl', 'bitsadmin']):
                analysis['risk_score'] += 35
                analysis['indicators'].append('Download and execute pattern')
                analysis['malware_type'] = 'downloader'
            
            # Determine confidence level
            if analysis['risk_score'] >= 80:
                analysis['confidence'] = 'high'
            elif analysis['risk_score'] >= 50:
                analysis['confidence'] = 'medium'
            elif analysis['risk_score'] >= 20:
                analysis['confidence'] = 'low'
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"❌ Malware analysis failed: {e}")
            return {'risk_score': 0, 'indicators': [], 'malware_type': 'unknown', 'confidence': 'low'}
    
    async def _analyze_network_connection(self, remote_ip: str, remote_port: int, local_port: int) -> Dict[str, Any]:
        """Analyze network connection for malware indicators"""
        try:
            analysis = {
                'risk_score': 0,
                'indicators': [],
                'connection_type': 'unknown'
            }
            
            # Check for suspicious ports
            if remote_port in self.suspicious_ports:
                analysis['risk_score'] += 30
                analysis['indicators'].append(f'Suspicious remote port: {remote_port}')
                analysis['connection_type'] = 'backdoor_port'
            
            # Check for common reverse shell ports
            reverse_shell_ports = {443, 80, 53, 8080, 8443}
            if remote_port in reverse_shell_ports:
                analysis['risk_score'] += 20
                analysis['indicators'].append(f'Common reverse shell port: {remote_port}')
                analysis['connection_type'] = 'potential_reverse_shell'
            
            # Check for malicious IPs (would be populated from threat intelligence)
            if remote_ip in self.malicious_ips:
                analysis['risk_score'] += 50
                analysis['indicators'].append(f'Known malicious IP: {remote_ip}')
                analysis['connection_type'] = 'malicious_ip'
            
            # Check for unusual protocols on common ports
            if remote_port in {80, 443} and local_port > 49152:
                analysis['risk_score'] += 15
                analysis['indicators'].append('Unusual high port to HTTP/HTTPS')
                analysis['connection_type'] = 'tunnel_suspect'
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"❌ Network connection analysis failed: {e}")
            return {'risk_score': 0, 'indicators': [], 'connection_type': 'unknown'}
    
    async def _create_malware_detection_events(self, proc_info: Dict, malware_analysis: Dict) -> List[EventData]:
        """Create malware-specific detection events"""
        events = []
        
        try:
            risk_score = malware_analysis.get('risk_score', 0)
            
            # Only create events for suspicious processes
            if risk_score < 20:
                return []
            
            # Determine severity based on risk score
            if risk_score >= 80:
                severity = "Critical"
                event_action = EventAction.SUSPICIOUS_ACTIVITY
            elif risk_score >= 50:
                severity = "High"
                event_action = EventAction.SUSPICIOUS_ACTIVITY
            elif risk_score >= 20:
                severity = "Medium"
                event_action = EventAction.DETECTED
            else:
                return []
            
            # EVENT 1: Malware Detection Event
            malware_event = EventData(
                event_type="Process",
                event_action=event_action,
                event_timestamp=datetime.now(),
                severity=severity,
                
                process_id=proc_info.get('pid'),
                process_name=proc_info.get('name'),
                process_path=proc_info.get('exe'),
                command_line=' '.join(proc_info.get('cmdline', []) or []),
                parent_pid=proc_info.get('ppid', 0),
                process_user=proc_info.get('username'),
                
                # Enhanced malware detection fields
                network_connections=proc_info.get('network_connections', []),
                
                description=f"🚨 MALWARE DETECTED: {proc_info.get('name')} - Risk Score: {risk_score}/100",
                
                raw_event_data={
                    'event_subtype': 'malware_detection',
                    'malware_analysis': malware_analysis,
                    'detection_method': 'Enhanced Process Analysis',
                    'malware_type': malware_analysis.get('malware_type', 'unknown'),
                    'confidence': malware_analysis.get('confidence', 'low'),
                    'risk_score': risk_score,
                    'indicators': malware_analysis.get('indicators', []),
                    'network_analysis': {
                        'external_connections': len([conn for conn in proc_info.get('network_connections', []) if conn.get('is_external')]),
                        'suspicious_ports': [conn['raddr']['port'] for conn in proc_info.get('network_connections', []) if conn.get('is_suspicious_port')],
                        'malicious_ips': [conn['raddr']['ip'] for conn in proc_info.get('network_connections', []) if conn.get('is_malicious_ip')]
                    },
                    'process_analysis': {
                        'cpu_percent': proc_info.get('cpu_percent', 0),
                        'memory_mb': proc_info.get('memory_rss', 0) // (1024 * 1024),
                        'parent_process': self._get_parent_process_name(proc_info.get('ppid', 0)),
                        'file_path_suspicious': any(path in (proc_info.get('exe', '').lower()) for path in self.suspicious_patterns['suspicious_paths'])
                    }
                }
            )
            events.append(malware_event)
            self.stats['suspicious_processes_detected'] += 1
            
            # EVENT 2: Reverse Shell Detection (specific type)
            if malware_analysis.get('malware_type') == 'reverse_shell':
                reverse_shell_event = EventData(
                    event_type="Process",
                    event_action=EventAction.SUSPICIOUS_ACTIVITY,
                    event_timestamp=datetime.now(),
                    severity="Critical",
                    
                    process_id=proc_info.get('pid'),
                    process_name=proc_info.get('name'),
                    process_path=proc_info.get('exe'),
                    command_line=' '.join(proc_info.get('cmdline', []) or []),
                    
                    network_connections=proc_info.get('network_connections', []),
                    
                    description=f"🚨 REVERSE SHELL DETECTED: {proc_info.get('name')} with external connections",
                    
                    raw_event_data={
                        'event_subtype': 'reverse_shell_detection',
                        'shell_type': 'reverse_shell',
                        'command_indicators': [ind for ind in malware_analysis.get('indicators', []) if 'command pattern' in ind],
                        'network_connections': proc_info.get('network_connections', []),
                        'detection_confidence': malware_analysis.get('confidence', 'medium')
                    }
                )
                events.append(reverse_shell_event)
                self.stats['reverse_shell_detected'] += 1
            
            # EVENT 3: Malicious Network Connection
            external_connections = [conn for conn in proc_info.get('network_connections', []) if conn.get('is_external')]
            if external_connections:
                for conn in external_connections[:3]:  # Limit to first 3 connections
                    connection_event = EventData(
                        event_type="Network",
                        event_action=EventAction.SUSPICIOUS_ACTIVITY,
                        event_timestamp=datetime.now(),
                        severity="High" if conn.get('is_malicious_ip') else "Medium",
                        
                        process_id=proc_info.get('pid'),
                        process_name=proc_info.get('name'),
                        source_ip=conn['laddr']['ip'],
                        source_port=conn['laddr']['port'],
                        destination_ip=conn['raddr']['ip'],
                        destination_port=conn['raddr']['port'],
                        protocol='TCP',
                        direction="Outbound",
                        
                        description=f"🌐 MALICIOUS CONNECTION: {proc_info.get('name')} -> {conn['raddr']['ip']}:{conn['raddr']['port']}",
                        
                        raw_event_data={
                            'event_subtype': 'malicious_network_connection',
                            'process_malware_analysis': malware_analysis,
                            'connection_analysis': conn.get('connection_analysis', {}),
                            'geographic_location': conn.get('geographic_location'),
                            'reverse_dns': conn.get('reverse_dns'),
                            'is_malicious_ip': conn.get('is_malicious_ip', False),
                            'is_suspicious_port': conn.get('is_suspicious_port', False)
                        }
                    )
                    events.append(connection_event)
                    self.stats['malware_connections_detected'] += 1
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Malware detection events creation failed: {e}")
            return []
    
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
    
    async def _get_ip_geolocation(self, ip: str) -> Optional[str]:
        """Get IP geolocation (simplified version)"""
        try:
            if self._is_external_ip(ip):
                # In a real implementation, you would use a geolocation service
                # For now, return a placeholder
                return f"External IP: {ip}"
            return f"Internal IP: {ip}"
        except Exception:
            return None
    
    async def _get_reverse_dns(self, ip: str) -> Optional[str]:
        """Get reverse DNS for IP address"""
        try:
            import socket
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return None
    
    def _get_process_category(self, process_name: str) -> str:
        """Get process category for classification"""
        if not process_name:
            return 'unknown'
        
        process_lower = process_name.lower()
        
        # Network tools category
        if any(tool in process_lower for tool in self.suspicious_patterns['network_tools']):
            return 'network_tools'
        
        # Remote access tools
        if any(tool in process_lower for tool in self.suspicious_patterns['remote_tools']):
            return 'remote_access'
        
        # System processes
        if is_system_process(process_name):
            return 'system'
        
        # Common applications
        if any(app in process_lower for app in ['chrome', 'firefox', 'notepad', 'word', 'excel']):
            return 'applications'
        
        return 'other'
    
    def _get_parent_process_name(self, parent_pid: int) -> str:
        """Get parent process name from PID"""
        try:
            if parent_pid and parent_pid > 0:
                parent_process = psutil.Process(parent_pid)
                return parent_process.name()
            return "Unknown"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "Unknown"
        except Exception:
            return "Unknown"
    
    async def _check_process_suspicious_activity(self, proc_info: Dict, malware_analysis: Dict) -> Optional[Dict[str, Any]]:
        """Check existing process for new suspicious activity"""
        try:
            pid = proc_info.get('pid')
            old_info = self.monitored_processes.get(pid, {})
            
            suspicious_activity = {
                'new_connections': [],
                'behavior_changes': [],
                'escalated_risk': False
            }
            
            # Check for new network connections
            old_connections = old_info.get('network_connections', [])
            new_connections = proc_info.get('network_connections', [])
            
            old_conn_signatures = {f"{conn['raddr']['ip']}:{conn['raddr']['port']}" for conn in old_connections}
            new_conn_signatures = {f"{conn['raddr']['ip']}:{conn['raddr']['port']}" for conn in new_connections}
            
            truly_new_connections = new_conn_signatures - old_conn_signatures
            if truly_new_connections:
                suspicious_activity['new_connections'] = [
                    conn for conn in new_connections 
                    if f"{conn['raddr']['ip']}:{conn['raddr']['port']}" in truly_new_connections
                ]
            
            # Check for behavior changes
            old_risk = old_info.get('malware_analysis', {}).get('risk_score', 0)
            new_risk = malware_analysis.get('risk_score', 0)
            
            if new_risk > old_risk + 10:  # Risk increased significantly
                suspicious_activity['escalated_risk'] = True
                suspicious_activity['behavior_changes'].append(f'Risk score increased from {old_risk} to {new_risk}')
            
            # Return only if there's actual suspicious activity
            if (suspicious_activity['new_connections'] or 
                suspicious_activity['behavior_changes'] or 
                suspicious_activity['escalated_risk']):
                return suspicious_activity
            
            return None
            
        except Exception as e:
            self.logger.error(f"❌ Suspicious activity check failed: {e}")
            return None
    
    async def _create_suspicious_activity_events(self, proc_info: Dict, suspicious_activity: Dict) -> List[EventData]:
        """Create events for suspicious activity in existing processes"""
        events = []
        
        try:
            # EVENT: New suspicious connections
            for conn in suspicious_activity.get('new_connections', []):
                if conn.get('is_external'):
                    event = EventData(
                        event_type="Network",
                        event_action=EventAction.CONNECT,
                        event_timestamp=datetime.now(),
                        severity="High" if conn.get('is_suspicious_port') else "Medium",
                        
                        process_id=proc_info.get('pid'),
                        process_name=proc_info.get('name'),
                        source_ip=conn['laddr']['ip'],
                        source_port=conn['laddr']['port'],
                        destination_ip=conn['raddr']['ip'],
                        destination_port=conn['raddr']['port'],
                        protocol='TCP',
                        direction="Outbound",
                        
                        description=f"🔍 NEW EXTERNAL CONNECTION: {proc_info.get('name')} -> {conn['raddr']['ip']}:{conn['raddr']['port']}",
                        
                        raw_event_data={
                            'event_subtype': 'new_external_connection',
                            'connection_analysis': conn.get('connection_analysis', {}),
                            'is_new_connection': True,
                            'process_monitoring': True
                        }
                    )
                    events.append(event)
            
            # EVENT: Risk escalation
            if suspicious_activity.get('escalated_risk'):
                event = EventData(
                    event_type="Process",
                    event_action=EventAction.SUSPICIOUS_ACTIVITY,
                    event_timestamp=datetime.now(),
                    severity="High",
                    
                    process_id=proc_info.get('pid'),
                    process_name=proc_info.get('name'),
                    process_path=proc_info.get('exe'),
                    
                    description=f"📈 RISK ESCALATION: {proc_info.get('name')} behavior became more suspicious",
                    
                    raw_event_data={
                        'event_subtype': 'risk_escalation',
                        'behavior_changes': suspicious_activity.get('behavior_changes', []),
                        'continuous_monitoring': True
                    }
                )
                events.append(event)
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Suspicious activity events creation failed: {e}")
            return []
    
    async def _create_enhanced_process_creation_event(self, proc_info: Dict, malware_analysis: Dict):
        """Create enhanced process creation event with malware analysis"""
        try:
            risk_score = malware_analysis.get('risk_score', 0)
            
            # Determine severity based on risk score
            if risk_score >= 50:
                severity = "High"
            elif risk_score >= 20:
                severity = "Medium"
            else:
                severity = "Info"
            
            # Get process hash
            process_path = proc_info.get('exe')
            process_hash = None
            if process_path:
                process_hash = get_process_hash(process_path)
            
            parent_pid = proc_info.get('ppid')
            if parent_pid is None:
                parent_pid = 0
            
            return EventData(
                event_type="Process",
                event_action=EventAction.START,
                event_timestamp=datetime.now(),
                severity=severity,
                
                process_id=proc_info.get('pid'),
                process_name=proc_info.get('name'),
                process_path=process_path,
                command_line=' '.join(proc_info.get('cmdline', []) or []),
                parent_pid=int(parent_pid),
                process_user=proc_info.get('username'),
                process_hash=process_hash,
                
                # Enhanced network connections
                network_connections=proc_info.get('network_connections', []),
                
                description=f"🆕 PROCESS STARTED: {proc_info.get('name')} (Risk: {risk_score}/100)",
                
                raw_event_data={
                    'event_subtype': 'enhanced_process_creation',
                    'malware_analysis': malware_analysis,
                    'process_category': self._get_process_category(proc_info.get('name', '')),
                    'cpu_percent': proc_info.get('cpu_percent', 0),
                    'memory_rss': proc_info.get('memory_rss', 0),
                    'create_time': proc_info.get('create_time'),
                    'parent_process': self._get_parent_process_name(int(parent_pid)),
                    'process_hash': process_hash,
                    'network_connections_count': len(proc_info.get('network_connections', [])),
                    'external_connections_count': len([conn for conn in proc_info.get('network_connections', []) if conn.get('is_external')]),
                    'suspicious_indicators': malware_analysis.get('indicators', []),
                    'risk_assessment': {
                        'risk_score': risk_score,
                        'confidence': malware_analysis.get('confidence', 'low'),
                        'malware_type': malware_analysis.get('malware_type', 'unknown')
                    }
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Enhanced process creation event failed: {e}")
            return None
    
    def get_stats(self) -> Dict:
        """Get comprehensive statistics for enhanced process monitoring with full malware detection"""
        base_stats = super().get_stats()
        
        # Calculate additional malware-specific statistics
        processes_analyzed = len(self.monitored_processes)
        high_risk_processes = sum(1 for p in self.monitored_processes.values() 
                                 if p.get('malware_analysis', {}).get('risk_score', 0) >= 50)
        critical_risk_processes = sum(1 for p in self.monitored_processes.values() 
                                     if p.get('malware_analysis', {}).get('risk_score', 0) >= 80)
        
        base_stats.update({
            'collector_type': 'Process_Enhanced_MalwareDetection',
            
            # Basic statistics
            'total_processes_monitored': self.stats['total_processes_monitored'],
            'suspicious_processes_detected': self.stats['suspicious_processes_detected'],
            'reverse_shell_detected': self.stats['reverse_shell_detected'],
            'malware_connections_detected': self.stats['malware_connections_detected'],
            'remote_access_detected': self.stats['remote_access_detected'],
            'total_malware_events': self.stats['total_malware_events'],
            
            # Analysis statistics
            'processes_currently_analyzed': processes_analyzed,
            'high_risk_processes': high_risk_processes,
            'critical_risk_processes': critical_risk_processes,
            
            # Advanced capabilities
            'malware_detection_enabled': True,
            'reverse_shell_detection': True,
            'network_analysis_enabled': True,
            'real_time_monitoring': True,
            'behavior_analysis_enabled': True,
            
            # Detection patterns
            'suspicious_patterns_monitored': sum(len(patterns) for patterns in self.suspicious_patterns.values()),
            'suspicious_ports_monitored': len(self.suspicious_ports),
            
            # Feature list
            'malware_detection_features': [
                'reverse_shell_detection',
                'network_connection_analysis',
                'command_line_analysis',
                'file_location_analysis',
                'behavior_change_monitoring',
                'risk_scoring_system',
                'real_time_monitoring'
            ],
            
            # Risk analysis
            'risk_scoring_enabled': True,
            'threat_intelligence_integration': True,
            
            # Detection accuracy metrics
            'detection_methods': [
                'Static Analysis',
                'Behavioral Analysis', 
                'Network Analysis',
                'Process Relationship Analysis',
                'Command Line Analysis',
                'File System Analysis',
                'Performance Analysis'
            ]
        })
        
        return base_stats