"""
Process Utilities for Enhanced Process Monitoring
"""

import psutil
import hashlib
import os
from typing import Dict, Optional
import platform
import subprocess

class ProcessUtils:
    @staticmethod
    def list_processes():
        return [p.info for p in psutil.process_iter(['pid', 'name', 'exe', 'username'])]

    @staticmethod
    def kill_process(pid):
        try:
            p = psutil.Process(pid)
            p.terminate()
            return True
        except Exception:
            return False

def get_process_info(pid: int) -> Optional[Dict]:
    """Get detailed process information"""
    try:
        proc = psutil.Process(pid)
        return {
            'pid': pid,
            'name': proc.name(),
            'exe': proc.exe(),
            'cmdline': proc.cmdline(),
            'username': proc.username(),
            'parent_pid': proc.ppid(),
            'parent_name': psutil.Process(proc.ppid()).name() if proc.ppid() else None,
            'cpu_percent': proc.cpu_percent(),
            'memory_percent': proc.memory_percent(),
            'num_threads': proc.num_threads(),
            'create_time': proc.create_time(),
            'status': proc.status()
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def get_process_hash(process_path: str) -> Optional[str]:
    """Calculate hash of process executable"""
    try:
        if not os.path.exists(process_path):
            return None
        
        hash_md5 = hashlib.md5()
        with open(process_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception:
        return None

def is_system_process(process_name: str) -> bool:
    """Check if process is a system process"""
    system_processes = {
        'svchost.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe',
        'wininit.exe', 'services.exe', 'spoolsv.exe', 'explorer.exe'
    }
    return process_name.lower() in system_processes

def kill_process(process_id, force_kill=True):
    system = platform.system().lower()
    try:
        if system == 'windows':
            cmd = ["taskkill", "/PID", str(process_id)]
            if force_kill:
                cmd.append("/F")
            subprocess.run(cmd, check=True)
        else:
            # Linux, macOS
            sig = '-9' if force_kill else '-15'
            cmd = ["kill", sig, str(process_id)]
            subprocess.run(cmd, check=True)
        print(f"[AGENT] Killed process {process_id} (force={force_kill})")
        return True
    except Exception as e:
        print(f"[AGENT] Failed to kill process {process_id}: {e}")
        return False
