# agent/core/config_manager.py
"""
Configuration Manager - Handle agent configuration
"""

import yaml
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

class ConfigManager:
    """Manage agent configuration"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.config: Dict[str, Any] = {}
        self.config_file = None
        
        # Default configuration
        self.default_config = self._get_default_config()
    
    async def load_config(self, config_path: Optional[str] = None):
        """Load configuration from file"""
        try:
            # Determine config file path
            if config_path:
                self.config_file = Path(config_path)
            else:
                # Look for config files in standard locations
                possible_paths = [
                    Path(__file__).parent.parent.parent / 'config' / 'agent_config.yaml',
                    Path(__file__).parent.parent.parent / 'agent_config.yaml',
                    Path('agent_config.yaml'),
                    Path('config') / 'agent_config.yaml'
                ]
                
                for path in possible_paths:
                    if path.exists():
                        self.config_file = path
                        break
            
            # Load config from file or use defaults
            if self.config_file and self.config_file.exists():
                self.config = self._load_from_file(self.config_file)
                self.logger.info(f"✅ Configuration loaded from: {self.config_file}")
            else:
                self.config = self.default_config.copy()
                self.logger.info("✅ Using default configuration")
            
            # Validate configuration
            self._validate_config()
            
        except Exception as e:
            self.logger.error(f"❌ Configuration load failed: {e}")
            self.config = self.default_config.copy()
    
    def _load_from_file(self, file_path: Path) -> Dict[str, Any]:
        """Load configuration from YAML or JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.suffix.lower() in ['.yaml', '.yml']:
                    return yaml.safe_load(f) or {}
                elif file_path.suffix.lower() == '.json':
                    return json.load(f) or {}
                else:
                    # Try YAML first, then JSON
                    content = f.read()
                    try:
                        return yaml.safe_load(content) or {}
                    except:
                        return json.loads(content) or {}
                        
        except Exception as e:
            self.logger.error(f"❌ Failed to load config file {file_path}: {e}")
            return {}
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default agent configuration"""
        return {
            'agent': {
                'name': 'EDR-Agent',
                'version': '1.0.0',
                'heartbeat_interval': 30,
                'event_batch_size': 100,
                'event_queue_size': 1000,
                'max_memory_usage': 512,  # MB
                'debug_mode': False
            },
            'server': {
                'host': '192.168.20.85',
                'port': 5000,
                'auth_token': 'edr_agent_auth_2024',
                'timeout': 30,
                'max_retries': 3,
                'retry_delay': 5,
                'ssl_enabled': False,
                'ssl_verify': True
            },
            'collection': {
                'enabled': True,
                'collect_processes': True,
                'collect_files': True,
                'collect_network': True,
                'collect_registry': True,
                'collect_authentication': True,
                'collect_system_events': True,
                'real_time_monitoring': True,
                'polling_interval': 5,
                'max_events_per_interval': 1000
            },
            'detection': {
                'enabled': True,
                'local_rules_enabled': True,
                'behavior_analysis': True,
                'threat_cache_enabled': True,
                'cache_size': 10000,
                'suspicious_threshold': 70
            },
            'logging': {
                'level': 'INFO',
                'file_enabled': True,
                'console_enabled': True,
                'max_file_size': '10MB',
                'backup_count': 5,
                'log_directory': 'logs'
            },
            'security': {
                'anti_tamper_enabled': True,
                'integrity_check_enabled': True,
                'encryption_enabled': False,
                'secure_communication': True
            },
            'performance': {
                'max_cpu_usage': 20,
                'max_memory_usage': 512,
                'monitoring_enabled': True,
                'auto_throttle': True,
                'batch_processing': True
            },
            'filters': {
                'exclude_system_processes': True,
                'exclude_windows_directories': [
                    'C:\\Windows\\System32',
                    'C:\\Windows\\SysWOW64'
                ],
                'exclude_file_extensions': [
                    '.tmp', '.log', '.bak'
                ],
                'include_only_executables': False
            }
        }
    
    def _validate_config(self):
        """Validate configuration values"""
        try:
            # Validate required sections
            required_sections = ['agent', 'server', 'collection']
            for section in required_sections:
                if section not in self.config:
                    self.logger.warning(f"⚠️ Missing config section: {section}")
                    self.config[section] = self.default_config.get(section, {})
            
            # Validate server configuration
            server_config = self.config.get('server', {})
            if not server_config.get('host'):
                self.logger.warning("⚠️ No server host configured, using default")
                self.config['server']['host'] = self.default_config['server']['host']
            
            if not server_config.get('auth_token'):
                self.logger.warning("⚠️ No auth token configured, using default")
                self.config['server']['auth_token'] = self.default_config['server']['auth_token']
            
            # Validate numeric values
            self._validate_numeric_config('agent.heartbeat_interval', 10, 300)
            self._validate_numeric_config('agent.event_batch_size', 1, 1000)
            self._validate_numeric_config('server.timeout', 5, 120)
            self._validate_numeric_config('performance.max_cpu_usage', 1, 100)
            self._validate_numeric_config('performance.max_memory_usage', 64, 2048)
            
            self.logger.info("✅ Configuration validated")
            
        except Exception as e:
            self.logger.error(f"❌ Configuration validation failed: {e}")
    
    def _validate_numeric_config(self, key_path: str, min_val: int, max_val: int):
        """Validate numeric configuration value"""
        try:
            keys = key_path.split('.')
            config_section = self.config
            
            for key in keys[:-1]:
                config_section = config_section.get(key, {})
            
            value = config_section.get(keys[-1])
            if value is not None:
                if not isinstance(value, (int, float)) or value < min_val or value > max_val:
                    self.logger.warning(f"⚠️ Invalid {key_path}: {value}, using default")
                    # Reset to default value
                    default_section = self.default_config
                    for key in keys[:-1]:
                        default_section = default_section.get(key, {})
                    config_section[keys[-1]] = default_section.get(keys[-1])
                        
        except Exception as e:
            self.logger.error(f"Error validating {key_path}: {e}")
    
    def get_config(self) -> Dict[str, Any]:
        """Get complete configuration"""
        return self.config
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get configuration section"""
        return self.config.get(section, {})
    
    def get_value(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        try:
            keys = key_path.split('.')
            value = self.config
            
            for key in keys:
                value = value[key]
            
            return value
            
        except (KeyError, TypeError):
            return default
    
    def set_value(self, key_path: str, value: Any):
        """Set configuration value using dot notation"""
        try:
            keys = key_path.split('.')
            config_section = self.config
            
            for key in keys[:-1]:
                if key not in config_section:
                    config_section[key] = {}
                config_section = config_section[key]
            
            config_section[keys[-1]] = value
            self.logger.debug(f"Config updated: {key_path} = {value}")
            
        except Exception as e:
            self.logger.error(f"Failed to set config {key_path}: {e}")
    
    def update_from_server(self, server_config: Dict[str, Any]):
        """Update configuration from server response"""
        try:
            # Update heartbeat interval
            if 'heartbeat_interval' in server_config:
                self.set_value('agent.heartbeat_interval', server_config['heartbeat_interval'])
            
            # Update monitoring settings
            if 'monitoring_enabled' in server_config:
                self.set_value('collection.enabled', server_config['monitoring_enabled'])
            
            # Update event batch size
            if 'event_batch_size' in server_config:
                self.set_value('agent.event_batch_size', server_config['event_batch_size'])
            
            # Update collection settings
            if 'collection_settings' in server_config:
                collection_settings = server_config['collection_settings']
                for key, value in collection_settings.items():
                    self.set_value(f'collection.{key}', value)
            
            # Update detection settings
            if 'detection_settings' in server_config:
                detection_settings = server_config['detection_settings']
                for key, value in detection_settings.items():
                    self.set_value(f'detection.{key}', value)
            
            self.logger.info("✅ Configuration updated from server")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to update config from server: {e}")
    
    def save_config(self, file_path: Optional[str] = None):
        """Save current configuration to file"""
        try:
            if file_path:
                output_file = Path(file_path)
            elif self.config_file:
                output_file = self.config_file
            else:
                output_file = Path('agent_config.yaml')
            
            # Create directory if it doesn't exist
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Save as YAML
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)
            
            self.logger.info(f"✅ Configuration saved to: {output_file}")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to save configuration: {e}")
    
    def is_enabled(self, feature: str) -> bool:
        """Check if a feature is enabled"""
        return self.get_value(feature, False)
    
    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration"""
        return self.get_section('logging')
    
    def get_performance_limits(self) -> Dict[str, Any]:
        """Get performance limits"""
        return self.get_section('performance')
    
    def get_collection_settings(self) -> Dict[str, Any]:
        """Get collection settings"""
        return self.get_section('collection')
    
    def get_server_settings(self) -> Dict[str, Any]:
        """Get server connection settings"""
        return self.get_section('server')