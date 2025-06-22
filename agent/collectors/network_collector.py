# agent/collectors/network_collector.py
"""
Enhanced Network Collector - Continuous Network Monitoring
Thu thập thông tin network liên tục và gửi cho server
"""

import psutil
import socket
import asyncio
import logging
import time
from typing import Dict, List, Optional, Set
from datetime import datetime
import subprocess

from ..schemas.events import EventData, EventType, EventAction
from ..utils.network_utils import get_connection_info, is_suspicious_connection

logger = logging.getLogger('NetworkCollector')

class EnhancedNetworkCollector:
    """Enhanced Network Collector with continuous monitoring"""
    
    def __init__(self, config_manager=None):
        self.config_manager = config_manager
        self.logger = logging.getLogger('NetworkCollector')
        self.is_running = False
        self.monitored_connections = set()
        self.suspicious_ips = {
            '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',  # Private networks
            '127.0.0.1', 'localhost'  # Localhost
        }
        
        # Performance tracking
        self.stats = {
            'connections_scanned': 0,
            'new_connections_detected': 0,
            'suspicious_connections_detected': 0,
            'events_generated': 0,
            'last_scan_time': None
        }
        
        self.logger.info("Enhanced Network Collector initialized")
    
    async def initialize(self):
        """Initialize the network collector"""
        try:
            self.logger.info("🔧 Initializing Enhanced Network Collector...")
            # No specific initialization needed for network collector
            self.logger.info("✅ Enhanced Network Collector initialized successfully")
        except Exception as e:
            self.logger.error(f"❌ Enhanced Network Collector initialization failed: {e}")
            raise
    
    async def start_monitoring(self):
        """Start continuous network monitoring"""
        self.is_running = True
        self.logger.info("🚀 Starting continuous network monitoring...")
        
        # Start monitoring loop
        asyncio.create_task(self._monitoring_loop())
        
        self.logger.info("✅ Network monitoring started")
    
    async def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_running = False
        self.logger.info("🛑 Network monitoring stopped")
    
    async def _monitoring_loop(self):
        """Continuous monitoring loop"""
        while self.is_running:
            try:
                await self._scan_network_connections()
                await asyncio.sleep(3)  # Scan every 3 seconds
                
            except Exception as e:
                self.logger.error(f"❌ Network monitoring error: {e}")
                await asyncio.sleep(10)  # Wait longer on error
    
    async def _scan_network_connections(self):
        """Scan current network connections"""
        try:
            current_connections = set()
            new_connections = []
            suspicious_connections = []
            
            # Get all network connections
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                try:
                    # Create connection key
                    conn_key = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}-{conn.status}"
                    current_connections.add(conn_key)
                    
                    # Check for new connections
                    if conn_key not in self.monitored_connections:
                        new_connections.append(conn)
                        self.monitored_connections.add(conn_key)
            
                    # Check for suspicious connections
                    if is_suspicious_connection(conn):
                        suspicious_connections.append(conn)
                
                except Exception as e:
                    self.logger.debug(f"Connection processing error: {e}")
                    continue
            
            # Generate events for new connections
            for conn in new_connections:
                await self._generate_network_event(conn, EventAction.CREATE)
                self.stats['new_connections_detected'] += 1
            
            # Generate events for suspicious connections
            for conn in suspicious_connections:
                await self._generate_network_event(conn, EventAction.SUSPICIOUS_ACTIVITY, severity="High")
                self.stats['suspicious_connections_detected'] += 1
            
            self.stats['connections_scanned'] += len(connections)
            self.stats['last_scan_time'] = datetime.now()
            
        except Exception as e:
            self.logger.error(f"❌ Network scan failed: {e}")
    
    async def _generate_network_event(self, conn, action: str, severity: str = "Info"):
        """Generate network event for server"""
        try:
            # Get process info if available
            process_info = None
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    process_info = {
                        'pid': conn.pid,
                        'name': proc.name(),
                        'exe': proc.exe(),
                        'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else None
                    }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Get connection details
            connection_info = get_connection_info(conn)
            
            event = EventData(
                event_type=EventType.NETWORK,
                event_action=action,
                event_timestamp=datetime.now(),
                severity=severity,
                
                # Network details
                source_ip=conn.laddr.ip if conn.laddr else None,
                source_port=conn.laddr.port if conn.laddr else None,
                destination_ip=conn.raddr.ip if conn.raddr else None,
                destination_port=conn.raddr.port if conn.raddr else None,
                protocol=conn.type,
                
                # Process details
                process_id=conn.pid,
                process_name=process_info['name'] if process_info else None,
                process_path=process_info['exe'] if process_info else None,
                command_line=process_info['cmdline'] if process_info else None,
                
                # Additional context
                description=f"Network {action.lower()}: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}"
            )
            
            # Add raw event data
            event.raw_event_data = {
                'connection_info': connection_info,
                'is_suspicious': is_suspicious_connection(conn),
                'family': conn.family,
                'type': conn.type,
                'status': conn.status,
                'connection_status': conn.status
            }
            
            # Send event to event processor
            if hasattr(self, 'event_processor') and self.event_processor:
                await self.event_processor.submit_event(event)
                self.stats['events_generated'] += 1
            
            self.logger.debug(f"📝 Network event generated: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}")
            
        except Exception as e:
            self.logger.error(f"❌ Network event generation failed: {e}")
    
    def get_stats(self) -> Dict:
        """Get collector statistics"""
        return {
            'collector_type': 'Network',
            'is_running': self.is_running,
            'connections_scanned': self.stats['connections_scanned'],
            'new_connections_detected': self.stats['new_connections_detected'],
            'suspicious_connections_detected': self.stats['suspicious_connections_detected'],
            'events_generated': self.stats['events_generated'],
            'last_scan_time': self.stats['last_scan_time'].isoformat() if self.stats['last_scan_time'] else None,
            'monitored_connections': len(self.monitored_connections)
        }
    
    def set_event_processor(self, event_processor):
        """Set event processor for sending events"""
        self.event_processor = event_processor
        self.logger.info("Event processor linked to Network Collector")
    
    async def stop(self):
        """Stop network monitoring"""
        await self.stop_monitoring()