# EDR Windows Agent - Troubleshooting Guide

## Common Issues and Solutions

### 1. Import Error: BaseCollector.__init__() got an unexpected keyword argument 'collector_type'

**Problem**: The ProcessCollector is passing `collector_type` instead of `collector_name` to BaseCollector.

**Solution**: ✅ **FIXED** - The ProcessCollector constructor has been corrected to use `collector_name="Process"`.

### 2. Missing Dependencies

**Problem**: Import errors for modules like `wmi`, `pywin32`, `plyer`, etc.

**Solutions**:

#### Quick Fix - Run the installer:
```bash
python install_dependencies.py
```

#### Manual Installation:
```bash
# Core dependencies
pip install aiohttp psutil watchdog pydantic colorlog requests

# Windows-specific
pip install pywin32 wmi

# Security
pip install cryptography pycryptodome

# Notifications
pip install plyer
```

#### Check Dependencies:
```bash
python fix_imports.py
```

### 3. WMI Import Issues

**Problem**: `ImportError: No module named 'wmi'`

**Solutions**:
1. Install WMI: `pip install wmi`
2. Ensure pywin32 is installed: `pip install pywin32`
3. Run as administrator if needed
4. The code now handles missing WMI gracefully and falls back to polling

### 4. Administrator Privileges Required

**Problem**: Some features require administrator privileges

**Solutions**:
1. Run PowerShell as Administrator
2. Right-click on PowerShell and select "Run as administrator"
3. Navigate to agent directory and run: `python main.py`

### 5. Visual C++ Build Tools Required

**Problem**: Error installing `pywin32` or `cryptography`

**Solutions**:
1. Install Visual Studio Build Tools
2. Or use pre-compiled wheels: `pip install --only-binary=all pywin32 cryptography`

### 6. Network Connection Issues

**Problem**: Agent cannot connect to server

**Solutions**:
1. Check server is running: `python backend/run_server.py`
2. Verify server URL in `config/agent_config.yaml`
3. Check firewall settings
4. Ensure network connectivity

### 7. File Permission Issues

**Problem**: Access denied errors when monitoring files

**Solutions**:
1. Run as administrator
2. Check file permissions
3. The agent now gracefully handles inaccessible paths

### 8. Notification System Issues

**Problem**: Security alerts not showing popups

**Solutions**:
1. Install plyer: `pip install plyer`
2. Ensure pywin32 is installed: `pip install pywin32`
3. Check Windows notification settings
4. Run as administrator if needed

## Testing and Verification

### 1. Test Dependencies
```bash
python fix_imports.py
```

### 2. Test Agent Startup
```bash
python test_agent_startup.py
```

### 3. Test Individual Components
```bash
# Test config manager
python -c "from agent.core.config_manager import ConfigManager; print('Config OK')"

# Test communication
python -c "from agent.core.communication import ServerCommunication; print('Communication OK')"

# Test notifications
python -c "from agent.utils.security_notifications import SecurityAlertNotifier; print('Notifications OK')"
```

## Debug Mode

Enable debug logging by modifying `config/logging_config.yaml`:

```yaml
logging:
  level: DEBUG
  format: '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
```

## Common Error Messages

### "Failed to restart as administrator"
- **Cause**: UAC prompt was cancelled or denied
- **Solution**: Manually run PowerShell as administrator

### "Unclosed client session"
- **Cause**: aiohttp session not properly closed
- **Solution**: ✅ **FIXED** - Proper cleanup added

### "Permission denied"
- **Cause**: Insufficient privileges
- **Solution**: Run as administrator

### "Module not found"
- **Cause**: Missing dependency
- **Solution**: Install missing package or run `python install_dependencies.py`

## Performance Issues

### High CPU Usage
- Reduce polling intervals in `config/agent_config.yaml`
- Disable unnecessary collectors
- Monitor specific paths only

### High Memory Usage
- Reduce `max_events_per_interval` in configuration
- Enable event deduplication
- Clean up old logs

## Getting Help

1. Check this troubleshooting guide
2. Run diagnostic scripts:
   - `python fix_imports.py`
   - `python test_agent_startup.py`
3. Check logs in `logs/` directory
4. Enable debug logging for detailed information

## System Requirements

- Windows 10/11 (64-bit)
- Python 3.8+
- Administrator privileges (recommended)
- Internet connection (for initial setup)
- 2GB RAM minimum
- 100MB disk space

## Quick Start After Fixes

1. Install dependencies: `python install_dependencies.py`
2. Check imports: `python fix_imports.py`
3. Test startup: `python test_agent_startup.py`
4. Run agent: `python main.py` 