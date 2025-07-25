# agent/collectors/process_collector.py - THỰC TẾ DATA COLLECTION
"""
Enhanced Process Collector - Thu thập THÔNG TIN THỰC TẾ của processes
KHÔNG đoán hay đưa ra khả năng - CHỈ LẤY DỮ LIỆU THỰC từ hệ thống
"""

import psutil
import time
import asyncio
import logging
import hashlib
import os
import socket
import subprocess
import re
from typing import Dict, List, Optional, Set, Any
from datetime import datetime
from pathlib import Path

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventAction
from agent.utils.process_utils import get_process_info, get_process_hash, is_system_process

logger = logging.getLogger('ProcessCollector')

class RealProcessDataCollector(BaseCollector):
    """Thu thập THÔNG TIN THỰC TẾ của processes - không đoán hay phân tích"""
    
    def __init__(self, config_manager=None):
        if config_manager is None:
            from agent.core.config_manager import ConfigManager
            config_manager = ConfigManager()
        super().__init__(config_manager, "ProcessCollector")
        
        # Process tracking
        self.monitored_processes = {}
        self.last_scan_pids = set()
        
        # Performance settings - REALTIME CONTINUOUS
        self.polling_interval = 0.1  # 100ms scan - realtime
        self.max_events_per_scan = 200  # Tăng để không miss events
        self.continuous_mode = True
        self.batch_size = 50  # Gửi theo batch để tối ưu network
        
        # Statistics
        self.stats = {
            'total_processes_scanned': 0,
            'processes_with_network': 0,
            'processes_with_files': 0,
            'processes_analyzed': 0,
            'events_generated': 0
        }
        
        self.logger.info("Real Process Data Collector initialized - REALTIME CONTINUOUS MODE")
    
    async def start_continuous_collection(self):
        """Bắt đầu thu thập liên tục realtime"""
        self.logger.info("🚀 Starting REALTIME CONTINUOUS process collection...")
        
        while self.continuous_mode:
            try:
                events = await self._collect_data()
                
                # Gửi ngay lập tức về server nếu có events
                if events:
                    await self._send_events_to_server(events)
                
                # Sleep ngắn để realtime
                await asyncio.sleep(self.polling_interval)
                
            except Exception as e:
                self.logger.error(f"❌ Continuous collection error: {e}")
                await asyncio.sleep(1)  # Chờ 1s rồi tiếp tục
    
    async def _send_events_to_server(self, events: List):
        """Gửi events về server ngay lập tức"""
        try:
            # Gửi theo batch để tối ưu
            for i in range(0, len(events), self.batch_size):
                batch = events[i:i + self.batch_size]
                
                # Gửi batch về server (sử dụng base collector method)
                await self._send_to_server(batch)
                
                self.logger.debug(f"📤 Sent {len(batch)} events to server (batch {i//self.batch_size + 1})")
            
            self.logger.info(f"✅ Sent {len(events)} total events to server")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to send events to server: {e}")
    
    def stop_continuous_collection(self):
        """Dừng thu thập liên tục"""
        self.continuous_mode = False
        self.logger.info("🛑 Stopped continuous collection")
    
    async def _collect_data(self):
        """Thu thập THÔNG TIN THỰC TẾ từ processes - REALTIME MODE"""
        try:
            start_time = time.time()
            events = []
            current_pids = set()
            
            # Scan tất cả processes để lấy thông tin thực - NHANH
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'username', 'ppid']):
                try:
                    proc_info = proc.info
                    if not proc_info['pid'] or not proc_info['name']:
                        continue
                    
                    pid = proc_info['pid']
                    current_pids.add(pid)
                    
                    # Thu thập THÔNG TIN THỰC TẾ của process - OPTIMIZED
                    real_data = await self._collect_real_process_data_optimized(proc_info, pid)
                    
                    # Realtime: Tạo event cho mọi thay đổi quan trọng
                    should_create_event = (
                        pid not in self.monitored_processes or  # Process mới
                        real_data.get('actual_network_connections') or  # Có network activity
                        real_data.get('actual_file_operations') or  # Có file activity
                        real_data.get('unusual_behavior_detected') or  # Behavior thay đổi
                        self._has_significant_change(pid, real_data)  # Resource/status thay đổi đáng kể
                    )
                    
                    if should_create_event:
                        event = await self._create_real_data_event(real_data)
                        if event:
                            events.append(event)
                            self.stats['events_generated'] += 1
                    
                    # Update tracking với data thực - REALTIME
                    self.monitored_processes[pid] = {
                        'name': proc_info['name'],
                        'exe': real_data.get('executable_path'),
                        'last_seen': time.time(),
                        'network_count': len(real_data.get('actual_network_connections', [])),
                        'file_count': len(real_data.get('actual_file_operations', [])),
                        'cpu_percent': real_data.get('actual_cpu_percent', 0),
                        'memory_rss': real_data.get('actual_memory_rss', 0),
                        'create_time': proc_info.get('create_time', 0)
                    }
                    
                    self.stats['processes_analyzed'] += 1
                    
                    # Realtime: Không chờ - process ngay
                    if len(events) >= self.max_events_per_scan:
                        break
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    self.logger.debug(f"Error collecting data for PID {proc_info.get('pid', 'unknown')}: {e}")
                    continue
            
            # Update tracking
            self.last_scan_pids = current_pids
            self.stats['total_processes_scanned'] = len(current_pids)
            
            # Realtime logging - minimal
            if events:
                self.logger.info(f"📊 Collected {len(events)} events (realtime)")
            
            # Performance - tối ưu cho realtime
            collection_time = (time.time() - start_time) * 1000
            if collection_time > 200:  # Warn nếu > 200ms
                self.logger.warning(f"⚠️ Slow realtime collection: {collection_time:.1f}ms")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Realtime process data collection failed: {e}")
            return []
    
    def _has_significant_change(self, pid: int, real_data: Dict) -> bool:
        """Kiểm tra có thay đổi đáng kể không - cho realtime"""
        try:
            if pid not in self.monitored_processes:
                return True  # Process mới
            
            old_data = self.monitored_processes[pid]
            
            # Kiểm tra thay đổi network connections
            old_network = old_data.get('network_count', 0)
            new_network = len(real_data.get('actual_network_connections', []))
            if abs(new_network - old_network) > 0:
                return True
            
            # Kiểm tra thay đổi file operations
            old_files = old_data.get('file_count', 0)
            new_files = len(real_data.get('actual_file_operations', []))
            if abs(new_files - old_files) > 5:  # Thay đổi >5 files
                return True
            
            # Kiểm tra thay đổi CPU đáng kể
            old_cpu = old_data.get('cpu_percent', 0)
            new_cpu = real_data.get('actual_cpu_percent', 0)
            if abs(new_cpu - old_cpu) > 20:  # Thay đổi >20% CPU
                return True
            
            # Kiểm tra thay đổi memory đáng kể
            old_memory = old_data.get('memory_rss', 0)
            new_memory = real_data.get('actual_memory_rss', 0)
            memory_change = abs(new_memory - old_memory) / (old_memory + 1)  # % change
            if memory_change > 0.5:  # Thay đổi >50% memory
                return True
            
            return False
            
        except Exception:
            return True  # Lỗi thì coi như có thay đổi
    
    async def _collect_real_process_data_optimized(self, proc_info: Dict, pid: int) -> Dict:
        """Thu thập THÔNG TIN THỰC TẾ - OPTIMIZED cho realtime"""
        try:
            real_data = proc_info.copy()
            
            # 1. Thu thập thông tin cơ bản THỰC TẾ - NHANH
            try:
                actual_proc = psutil.Process(pid)
                real_data['actual_cpu_percent'] = actual_proc.cpu_percent(interval=None)  # Non-blocking
                memory_info = actual_proc.memory_info()
                real_data['actual_memory_rss'] = memory_info.rss if memory_info else 0
                real_data['actual_status'] = actual_proc.status()
                real_data['actual_num_threads'] = actual_proc.num_threads()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                real_data['actual_cpu_percent'] = 0
                real_data['actual_memory_rss'] = 0
                real_data['actual_status'] = 'unknown'
                real_data['actual_num_threads'] = 0
            
            # 2. Network connections - PRIORITY cho realtime
            actual_connections = await self._get_actual_network_connections_fast(pid)
            real_data['actual_network_connections'] = actual_connections
            if actual_connections:
                self.stats['processes_with_network'] += 1
            
            # 3. File operations - OPTIMIZED
            actual_files = await self._get_actual_file_operations_fast(pid)
            real_data['actual_file_operations'] = actual_files
            if actual_files:
                self.stats['processes_with_files'] += 1
            
            # 4. Executable info - CACHE để tối ưu
            exe_path = proc_info.get('exe', '')
            real_data['executable_path'] = exe_path
            
            # Cache SHA256 để không tính lại liên tục
            if exe_path and pid not in getattr(self, '_hash_cache', {}):
                if not hasattr(self, '_hash_cache'):
                    self._hash_cache = {}
                self._hash_cache[pid] = self._calculate_actual_file_hash(exe_path)
            
            real_data['actual_file_sha256'] = getattr(self, '_hash_cache', {}).get(pid)
            
            # 5. Command line - NHANH
            real_data['actual_command_line'] = ' '.join(proc_info.get('cmdline', []))
            real_data['actual_command_args'] = proc_info.get('cmdline', [])
            
            # 6. Unusual behavior - FAST CHECK
            real_data['unusual_behavior_detected'] = self._detect_unusual_behavior_fast(real_data)
            
            return real_data
            
        except Exception as e:
            self.logger.debug(f"❌ Failed to collect optimized data for PID {pid}: {e}")
            return proc_info
    
    async def _get_actual_network_connections_fast(self, pid: int) -> List[Dict[str, Any]]:
        """Lấy network connections NHANH cho realtime"""
        try:
            # Chỉ lấy connections của process này - TARGETED
            try:
                proc = psutil.Process(pid)
                connections = proc.connections(kind='inet')
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return []
            
            actual_connections = []
            for conn in connections:
                try:
                    connection_data = {
                        'status': conn.status,
                        'local_address': None,
                        'remote_address': None
                    }
                    
                    # Local address
                    if conn.laddr:
                        connection_data['local_address'] = {
                            'ip': conn.laddr.ip if hasattr(conn.laddr, 'ip') else conn.laddr[0],
                            'port': conn.laddr.port if hasattr(conn.laddr, 'port') else conn.laddr[1]
                        }
                    
                    # Remote address  
                    if conn.raddr:
                        connection_data['remote_address'] = {
                            'ip': conn.raddr.ip if hasattr(conn.raddr, 'ip') else conn.raddr[0],
                            'port': conn.raddr.port if hasattr(conn.raddr, 'port') else conn.raddr[1]
                        }
                    
                    if connection_data['local_address'] or connection_data['remote_address']:
                        actual_connections.append(connection_data)
                        
                except Exception:
                    continue
            
            return actual_connections
            
        except Exception:
            return []
    
    async def _get_actual_file_operations_fast(self, pid: int) -> List[Dict[str, Any]]:
        """Lấy file operations NHANH - chỉ count"""
        try:
            proc = psutil.Process(pid)
            open_files = proc.open_files()
            
            # Realtime: Chỉ lấy thông tin cần thiết
            actual_files = []
            for file_info in open_files[:20]:  # Limit 20 files cho performance
                actual_files.append({
                    'path': file_info.path,
                    'fd': file_info.fd
                })
            
            return actual_files
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []
        except Exception:
            return []
    
    def _detect_unusual_behavior_fast(self, real_data: Dict) -> List[str]:
        """Enhanced behavioral detection - không fix cứng ports"""
        unusual_behaviors = []
        threat_indicators = []
        
        try:
            # 1. DOWNLOADS FOLDER + NETWORK = ALWAYS SUSPICIOUS
            exe_path = real_data.get('exe', '').lower()
            process_name = real_data.get('name', '').lower()
            actual_connections = real_data.get('actual_network_connections', [])
            
            # Critical: Any process from Downloads making network connections
            if '\\downloads\\' in exe_path and actual_connections:
                threat_indicators.append("CRITICAL: Downloaded executable making network connections")
                unusual_behaviors.append("DOWNLOADED_EXECUTABLE_WITH_NETWORK_ACTIVITY")
                
                # Check connection patterns
                for conn in actual_connections:
                    if not conn or not isinstance(conn, dict):
                        continue
                    if conn.get('status') == 'ESTABLISHED':
                        remote_addr = conn.get('remote_address', {}) if isinstance(conn, dict) else {}
                        if remote_addr:
                            port = remote_addr.get('port', 0)
                            ip = remote_addr.get('ip', '')
                            
                            # Any ESTABLISHED outbound connection from Downloads = Suspicious
                            threat_indicators.append(f"CRITICAL: Outbound connection to {ip}:{port}")
                            unusual_behaviors.append(f"POTENTIAL_REVERSE_SHELL: Connected to {ip}:{port}")
                            
                            # Check if it's a high port (common for reverse shells)
                            if port > 1024:
                                threat_indicators.append(f"HIGH: Non-standard port connection: {port}")
            
            # 2. BEHAVIORAL PATTERNS for reverse shell
            reverse_shell_indicators = 0
            
            # Pattern 1: Single persistent connection
            if len(actual_connections) == 1 and actual_connections[0] and isinstance(actual_connections[0], dict) and actual_connections[0].get('status') == 'ESTABLISHED':
                reverse_shell_indicators += 1
                unusual_behaviors.append("SINGLE_PERSISTENT_CONNECTION")
            
            # Pattern 2: Connection to non-standard ports
            for conn in actual_connections:
                if not conn or not isinstance(conn, dict):
                    continue
                port = (conn.get('remote_address', {}) or {}).get('port', 0)
                if port > 1024 and port not in [80, 443, 8080, 3389]:  # Not common service ports
                    reverse_shell_indicators += 1
                    unusual_behaviors.append(f"NON_STANDARD_PORT: {port}")
            
            # Pattern 3: Process name indicators
            if self._is_suspicious_filename(process_name):
                reverse_shell_indicators += 1
                threat_indicators.append(f"SUSPICIOUS_FILENAME: {process_name}")
            
            # Pattern 4: No parent process info (often for malware)
            if not real_data.get('actual_parent_info'):
                reverse_shell_indicators += 1
                unusual_behaviors.append("NO_PARENT_PROCESS_INFO")
            
            # If multiple indicators present = likely reverse shell
            if reverse_shell_indicators >= 2:
                threat_indicators.append("HIGH: Multiple reverse shell indicators detected")
                unusual_behaviors.append("LIKELY_REVERSE_SHELL_BEHAVIOR")
            
            # 3. Command line analysis
            cmd = real_data.get('actual_command_line', '').lower()
            
            # Direct execution from Downloads
            if '\\downloads\\' in cmd and not any(safe in cmd for safe in ['chrome', 'firefox', 'edge']):
                threat_indicators.append("HIGH: Direct execution from Downloads folder")
                unusual_behaviors.append("DIRECT_DOWNLOADS_EXECUTION")
            
            # 4. Network behavior analysis
            if actual_connections:
                # Multiple connections to same host (C2 behavior)
                remote_ips = {}
                for conn in actual_connections:
                    if not conn or not isinstance(conn, dict):
                        continue
                    ip = (conn.get('remote_address', {}) or {}).get('ip')
                    if ip:
                        remote_ips[ip] = remote_ips.get(ip, 0) + 1
                
                for ip, count in remote_ips.items():
                    if count > 3:
                        unusual_behaviors.append(f"MULTIPLE_CONNECTIONS_TO_SAME_HOST: {ip} ({count} connections)")
                        threat_indicators.append(f"HIGH: Possible C2 communication to {ip}")
            
            # 5. File characteristics
            file_size = real_data.get('actual_file_size')
            if file_size and file_size < 100000:  # Small executable (<100KB)
                unusual_behaviors.append(f"SMALL_EXECUTABLE: {file_size} bytes")
            
            # 6. Time-based analysis
            current_hour = datetime.now().hour
            if (current_hour < 6 or current_hour > 22) and actual_connections:
                unusual_behaviors.append(f"OFF_HOURS_NETWORK_ACTIVITY: {current_hour}:00")
            
            # Merge threat indicators
            if threat_indicators:
                unusual_behaviors = threat_indicators + unusual_behaviors
        
        except Exception as e:
            self.logger.error(f"Error in threat detection: {e}")
        
        return unusual_behaviors
    
    def _is_suspicious_filename(self, filename: str) -> bool:
        """Check if filename is suspicious"""
        if not filename:
            return False
        
        filename = filename.lower()
        
        # Numeric-only names (123.exe, 456.exe, etc)
        name_without_ext = filename.split('.')[0]
        if name_without_ext.isdigit():
            return True
        
        # Random-looking names
        if len(name_without_ext) <= 3:  # a.exe, ab.exe, 123.exe
            return True
        
        # Common malware patterns
        suspicious_patterns = [
            'svchost', 'chrome_update', 'flashplayer', 'java_update',
            'temp', 'tmp', 'payload', 'shell', 'backdoor', 'rat'
        ]
        
        return any(pattern in filename for pattern in suspicious_patterns)
    
    async def _collect_real_process_data(self, proc_info: Dict, pid: int) -> Dict:
        """Thu thập THÔNG TIN THỰC TẾ của process - không đoán"""
        try:
            real_data = proc_info.copy()
            
            # 1. Thu thập thông tin cơ bản THỰC TẾ
            try:
                actual_proc = psutil.Process(pid)
                real_data['actual_cpu_percent'] = actual_proc.cpu_percent()
                memory_info = actual_proc.memory_info()
                real_data['actual_memory_rss'] = memory_info.rss if memory_info else 0
                real_data['actual_memory_vms'] = memory_info.vms if memory_info else 0
                real_data['actual_status'] = actual_proc.status()
                real_data['actual_num_threads'] = actual_proc.num_threads()
                real_data['actual_num_fds'] = actual_proc.num_fds() if hasattr(actual_proc, 'num_fds') else 0
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                real_data['actual_cpu_percent'] = 0
                real_data['actual_memory_rss'] = 0
                real_data['actual_status'] = 'unknown'
                real_data['actual_num_threads'] = 0
                real_data['actual_num_fds'] = 0
            
            # 2. Thu thập NETWORK CONNECTIONS THỰC TẾ
            actual_connections = await self._get_actual_network_connections(pid)
            real_data['actual_network_connections'] = actual_connections
            if actual_connections:
                self.stats['processes_with_network'] += 1
            
            # 3. Thu thập FILE OPERATIONS THỰC TẾ
            actual_files = await self._get_actual_file_operations(pid)
            real_data['actual_file_operations'] = actual_files
            if actual_files:
                self.stats['processes_with_files'] += 1
            
            # 4. Thu thập EXECUTABLE INFO THỰC TẾ
            real_data['executable_path'] = proc_info.get('exe', '')
            real_data['actual_file_sha256'] = self._calculate_actual_file_hash(proc_info.get('exe'))
            real_data['actual_file_size'] = self._get_actual_file_size(proc_info.get('exe'))
            real_data['actual_file_created'] = self._get_actual_file_creation_time(proc_info.get('exe'))
            
            # 5. Thu thập COMMAND LINE THỰC TẾ 
            real_data['actual_command_line'] = ' '.join(proc_info.get('cmdline', []))
            real_data['actual_command_args'] = proc_info.get('cmdline', [])
            real_data['actual_working_directory'] = self._get_actual_working_directory(pid)
            
            # 6. Thu thập PARENT PROCESS THỰC TẾ
            real_data['actual_parent_info'] = self._get_actual_parent_info(proc_info.get('ppid'))
            
            # 7. Thu thập ENVIRONMENT VARIABLES THỰC TẾ (nếu có quyền)
            real_data['actual_environment'] = self._get_actual_environment(pid)
            
            # 8. Phát hiện UNUSUAL BEHAVIOR dựa trên DATA THỰC TẾ
            real_data['unusual_behavior_detected'] = self._detect_unusual_behavior_from_real_data(real_data)
            
            return real_data
            
        except Exception as e:
            self.logger.error(f"❌ Failed to collect real data for PID {pid}: {e}")
            return proc_info
    
    async def _get_actual_network_connections(self, pid: int) -> List[Dict[str, Any]]:
        """Lấy NETWORK CONNECTIONS THỰC TẾ của process"""
        try:
            if not pid:
                return []
            
            actual_connections = []
            
            # Lấy connections thực tế từ hệ thống
            try:
                all_connections = psutil.net_connections(kind='inet')
            except Exception:
                return []
            
            # Filter connections thực tế cho process này
            for conn in all_connections:
                if conn.pid == pid:
                    try:
                        # Lấy thông tin thực tế từ connection
                        connection_data = {
                            'family': str(conn.family),
                            'type': str(conn.type),
                            'status': conn.status,
                            'local_address': None,
                            'remote_address': None
                        }
                        
                        # Local address thực tế
                        if conn.laddr:
                            if hasattr(conn.laddr, 'ip') and hasattr(conn.laddr, 'port'):
                                connection_data['local_address'] = {
                                    'ip': conn.laddr.ip,
                                    'port': conn.laddr.port
                                }
                            elif isinstance(conn.laddr, tuple) and len(conn.laddr) >= 2:
                                connection_data['local_address'] = {
                                    'ip': conn.laddr[0],
                                    'port': conn.laddr[1]
                                }
                        
                        # Remote address thực tế  
                        if conn.raddr:
                            if hasattr(conn.raddr, 'ip') and hasattr(conn.raddr, 'port'):
                                connection_data['remote_address'] = {
                                    'ip': conn.raddr.ip,
                                    'port': conn.raddr.port
                                }
                            elif isinstance(conn.raddr, tuple) and len(conn.raddr) >= 2:
                                connection_data['remote_address'] = {
                                    'ip': conn.raddr[0],
                                    'port': conn.raddr[1]
                                }
                        
                        # Chỉ thêm nếu có thông tin thực tế
                        if connection_data['local_address'] or connection_data['remote_address']:
                            actual_connections.append(connection_data)
                            
                    except Exception as e:
                        self.logger.debug(f"Error getting connection data: {e}")
                        continue
            
            return actual_connections
            
        except Exception as e:
            self.logger.debug(f"❌ Failed to get actual network connections for PID {pid}: {e}")
            return []
    
    async def _get_actual_file_operations(self, pid: int) -> List[Dict[str, Any]]:
        """Lấy FILE OPERATIONS THỰC TẾ của process"""
        try:
            if not pid:
                return []
            
            actual_files = []
            
            try:
                proc = psutil.Process(pid)
                
                # Lấy open files thực tế
                open_files = proc.open_files()
                for file_info in open_files:
                    actual_files.append({
                        'path': file_info.path,
                        'fd': file_info.fd,
                        'position': getattr(file_info, 'position', None),
                        'mode': getattr(file_info, 'mode', None),
                        'flags': getattr(file_info, 'flags', None)
                    })
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            except Exception as e:
                self.logger.debug(f"Error getting file operations: {e}")
            
            return actual_files
            
        except Exception as e:
            self.logger.debug(f"❌ Failed to get actual file operations for PID {pid}: {e}")
            return []
    
    def _calculate_actual_file_hash(self, file_path: str) -> Optional[str]:
        """Tính SHA256 HASH THỰC TẾ của file executable"""
        try:
            if not file_path or not os.path.exists(file_path):
                return None
            
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):  # Tăng chunk size cho SHA256
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return None
    
    def _get_actual_file_size(self, file_path: str) -> Optional[int]:
        """Lấy KÍCH THƯỚC THỰC TẾ của file"""
        try:
            if not file_path or not os.path.exists(file_path):
                return None
            return os.path.getsize(file_path)
        except Exception:
            return None
    
    def _get_actual_file_creation_time(self, file_path: str) -> Optional[float]:
        """Lấy THỜI GIAN TẠO THỰC TẾ của file"""
        try:
            if not file_path or not os.path.exists(file_path):
                return None
            return os.path.getctime(file_path)
        except Exception:
            return None
    
    def _get_actual_working_directory(self, pid: int) -> Optional[str]:
        """Lấy WORKING DIRECTORY THỰC TẾ của process"""
        try:
            proc = psutil.Process(pid)
            return proc.cwd()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
        except Exception:
            return None
    
    def _get_actual_parent_info(self, parent_pid: int) -> Optional[Dict]:
        """Lấy THÔNG TIN THỰC TẾ của parent process"""
        try:
            if not parent_pid or parent_pid <= 0:
                return None
            
            parent_proc = psutil.Process(parent_pid)
            return {
                'pid': parent_pid,
                'name': parent_proc.name(),
                'exe': parent_proc.exe(),
                'cmdline': parent_proc.cmdline(),
                'create_time': parent_proc.create_time(),
                'username': parent_proc.username()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
        except Exception:
            return None
    
    def _get_actual_environment(self, pid: int) -> Optional[Dict]:
        """Lấy ENVIRONMENT VARIABLES THỰC TẾ (nếu có quyền)"""
        try:
            proc = psutil.Process(pid)
            return proc.environ()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
        except Exception:
            return None
    
    def _detect_unusual_behavior_from_real_data(self, real_data: Dict) -> List[str]:
        """Phát hiện UNUSUAL BEHAVIOR dựa trên DATA THỰC TẾ - không đoán"""
        unusual_behaviors = []
        
        try:
            # 1. Kiểm tra NETWORK BEHAVIOR THỰC TẾ
            actual_connections = real_data.get('actual_network_connections', [])
            if actual_connections:
                # Đếm số connections thực tế
                connection_count = len(actual_connections)
                if connection_count > 10:
                    unusual_behaviors.append(f"High network activity: {connection_count} active connections")
                
                # Kiểm tra ports thực tế được sử dụng
                used_ports = []
                for conn in actual_connections:
                    if conn.get('remote_address'):
                        port = conn['remote_address'].get('port')
                        if port:
                            used_ports.append(port)
                
                if used_ports:
                    unusual_behaviors.append(f"Active connections to ports: {sorted(set(used_ports))}")
            
            # 2. Kiểm tra FILE BEHAVIOR THỰC TẾ
            actual_files = real_data.get('actual_file_operations', [])
            if actual_files:
                file_count = len(actual_files)
                if file_count > 20:
                    unusual_behaviors.append(f"High file activity: {file_count} open files")
                
                # Kiểm tra file paths thực tế
                temp_files = [f for f in actual_files if 'temp' in f.get('path', '').lower()]
                if temp_files:
                    unusual_behaviors.append(f"Accessing temp files: {len(temp_files)} files")
            
            # 3. Kiểm tra RESOURCE USAGE THỰC TẾ
            cpu_percent = real_data.get('actual_cpu_percent', 0)
            if cpu_percent > 80:
                unusual_behaviors.append(f"High CPU usage: {cpu_percent:.1f}%")
            
            memory_mb = real_data.get('actual_memory_rss', 0) / (1024 * 1024) if real_data.get('actual_memory_rss') else 0
            if memory_mb > 500:
                unusual_behaviors.append(f"High memory usage: {memory_mb:.1f}MB")
            
            # 4. Kiểm tra COMMAND LINE THỰC TẾ
            actual_cmd = real_data.get('actual_command_line', '')
            if actual_cmd:
                if len(actual_cmd) > 500:
                    unusual_behaviors.append(f"Very long command line: {len(actual_cmd)} characters")
                
                # Tìm patterns thực tế trong command
                if 'powershell' in actual_cmd.lower() and '-e' in actual_cmd.lower():
                    unusual_behaviors.append("PowerShell with encoded command detected")
                
                if any(keyword in actual_cmd.lower() for keyword in ['download', 'invoke-webrequest', 'curl']):
                    unusual_behaviors.append("Download commands in command line")
            
            # 5. Kiểm tra FILE PROPERTIES THỰC TẾ
            file_size = real_data.get('actual_file_size')
            if file_size and file_size < 1024:  # Very small executable
                unusual_behaviors.append(f"Very small executable: {file_size} bytes")
            
            # 6. Kiểm tra TIMING THỰC TẾ
            current_hour = datetime.now().hour
            if current_hour < 6 or current_hour > 22:
                unusual_behaviors.append(f"Running during off-hours: {current_hour}:00")
            
        except Exception as e:
            self.logger.debug(f"Error detecting unusual behavior: {e}")
        
        return unusual_behaviors
    
    async def _create_real_data_event(self, real_data: Dict):
        """Tạo event với ENHANCED THREAT DETECTION"""
        try:
            process_name = real_data.get('name', 'Unknown')
            exe_path = real_data.get('exe', '').lower()
            
            # Enhanced severity determination
            unusual_behaviors = real_data.get('unusual_behavior_detected', [])
            actual_connections = real_data.get('actual_network_connections', [])
            
            # CRITICAL severity conditions
            severity = 'Info'  # Default
            threat_type = None
            
            # Check for CRITICAL threats
            critical_indicators = [
                'REVERSE_SHELL_DETECTED' in str(unusual_behaviors),
                'CRITICAL:' in str(unusual_behaviors),
                any(
                    conn and isinstance(conn, dict) and (conn.get('remote_address', {}) or {}).get('port') in [4444, 1337, 5555, 9001]
                    for conn in actual_connections
                ),
                '\\downloads\\' in exe_path and len(actual_connections) > 0
            ]
            
            if any(critical_indicators):
                severity = 'Critical'
                threat_type = 'reverse_shell' if 'REVERSE_SHELL' in str(unusual_behaviors) else 'malware'
            
            # HIGH severity conditions
            elif any(indicator in str(unusual_behaviors) for indicator in ['HIGH:', 'SUSPICIOUS_LOCATION', 'POWERSHELL_ENCODED']):
                severity = 'High'
                threat_type = 'suspicious_process'
            
            # MEDIUM severity conditions
            elif len(actual_connections) > 5 or 'network activity' in str(unusual_behaviors):
                severity = 'Medium'
                threat_type = 'unusual_network_activity'
            
            # LOW severity for other unusual behaviors
            elif unusual_behaviors:
                severity = 'Low'
            
            # Network info enhancement
            source_ip = None
            destination_ip = None
            source_port = None
            destination_port = None
            protocol = None
            
            # Prioritize suspicious connections
            suspicious_conn = None
            for conn in actual_connections:
                if not conn or not isinstance(conn, dict):
                    continue
                remote_port = (conn.get('remote_address', {}) or {}).get('port')
                if remote_port in [4444, 1337, 5555, 9001, 2222, 31337]:
                    suspicious_conn = conn
                    break
            
            if suspicious_conn or actual_connections:
                conn = suspicious_conn or actual_connections[0]
                if conn and isinstance(conn, dict) and conn.get('local_address'):
                    source_ip = conn['local_address'].get('ip')
                    source_port = conn['local_address'].get('port')
                if conn and isinstance(conn, dict) and conn.get('remote_address'):
                    destination_ip = conn['remote_address'].get('ip')
                    destination_port = conn['remote_address'].get('port')
                protocol = 'TCP'  # Most reverse shells use TCP
            
            # Enhanced description
            description = f"🚨 THREAT DETECTED: {process_name}"
            
            if threat_type == 'reverse_shell':
                description = f"🚨 CRITICAL: REVERSE SHELL DETECTED - {process_name} connecting to {destination_ip}:{destination_port}"
            elif threat_type == 'malware':
                description = f"🚨 CRITICAL: POTENTIAL MALWARE - {process_name} from Downloads folder with network activity"
            elif severity == 'High':
                description = f"⚠️ HIGH RISK PROCESS: {process_name} - {unusual_behaviors[0] if unusual_behaviors else 'Suspicious activity'}"
            
            # Enhanced raw event data
            raw_event_data = {
                'data_collection_type': 'enhanced_threat_detection',
                'threat_type': threat_type,
                'threat_level': severity,
                'reverse_shell_detected': threat_type == 'reverse_shell',
                'suspicious_indicators': [b for b in unusual_behaviors if 'CRITICAL' in b or 'HIGH' in b],
                'process_location': exe_path,
                'is_from_downloads': '\\downloads\\' in exe_path,
                'is_from_temp': any(temp in exe_path for temp in ['\\temp\\', '\\tmp\\']),
                'actual_cpu_percent': real_data.get('actual_cpu_percent', 0),
                'actual_memory_rss': real_data.get('actual_memory_rss', 0),
                'actual_status': real_data.get('actual_status', 'unknown'),
                'actual_file_sha256': real_data.get('actual_file_sha256'),
                'actual_network_connections': actual_connections,
                'unusual_behavior_detected': unusual_behaviors,
                'analysis_timestamp': datetime.now().isoformat()
            }
            
            # Create enhanced event
            event = EventData(
                event_type="Process",
                event_action=EventAction.START,
                event_timestamp=datetime.now(),
                severity=severity,
                # agent_id có thể thêm nếu có
                # description luôn hợp lệ
                description=description,
                # Process information
                process_id=real_data.get('pid'),
                process_name=process_name,
                process_path=real_data.get('executable_path', ''),
                command_line=real_data.get('actual_command_line', ''),
                parent_pid=int(real_data.get('ppid', 0)),
                process_user=real_data.get('username'),
                process_hash=real_data.get('actual_file_sha256'),
                # Network information
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=destination_port,
                protocol=protocol,
                direction='Outbound' if destination_ip else None,
                # Network connections array
                network_connections=actual_connections,
                # Enhanced description
                # description=description,  # đã có ở trên
                # Raw event data with threat intelligence
                raw_event_data=raw_event_data
            )
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Enhanced event creation failed: {e}")
            return None
    
    def get_stats(self) -> Dict:
        """Get statistics về real data collection"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'Real_Process_Data_Collector',
            'total_processes_scanned': self.stats['total_processes_scanned'],
            'processes_with_network': self.stats['processes_with_network'],
            'processes_with_files': self.stats['processes_with_files'],
            'processes_analyzed': self.stats['processes_analyzed'],
            'events_generated': self.stats['events_generated'],
            'monitored_processes_count': len(self.monitored_processes),
            'data_collection_approach': 'facts_only',
            'capabilities': [
                'real_network_connections',
                'real_file_operations', 
                'real_resource_usage',
                'real_command_analysis',
                'real_parent_child_relationships',
                'real_environment_variables',
                'fact_based_unusual_behavior_detection'
            ]
        })
        return base_stats

# Factory function
def create_process_collector(config_manager):
    """Factory function to create real process data collector"""
    return RealProcessDataCollector(config_manager)

# Alias
ProcessCollector = RealProcessDataCollector
EnhancedProcessCollector = RealProcessDataCollector