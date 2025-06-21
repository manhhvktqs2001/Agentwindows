# EDR Windows Agent - Administrator Guide

## Quick Start with Admin Privileges

### 🚀 Method 1: Batch File (Recommended)
```bash
# Double-click or run:
run_agent_admin.bat
```

### 🚀 Method 2: PowerShell Script
```bash
# Right-click and "Run as administrator":
run_agent_admin.ps1

# Or run with force flag:
.\run_agent_admin.ps1 -Force
```

### 🚀 Method 3: Python Script
```bash
# Interactive admin helper:
python run_as_admin.py
```

### 🚀 Method 4: Manual
1. Right-click PowerShell
2. Select "Run as administrator"
3. Navigate to agent directory:
   ```bash
   cd C:\Users\Manh\Desktop\agenwindowns
   ```
4. Run agent:
   ```bash
   python main.py
   ```

## Why Administrator Privileges?

The EDR agent needs administrator privileges for:

- ✅ **Process Monitoring**: Access to all system processes
- ✅ **Registry Monitoring**: Read system registry keys
- ✅ **File System Monitoring**: Monitor protected directories
- ✅ **Network Monitoring**: Access to network connection details
- ✅ **Security Notifications**: Display system notifications
- ✅ **Anti-Tamper Protection**: Protect against malicious termination

## Limited Privileges Mode

If you run without admin privileges, the agent will:
- ⚠️ Monitor only user-accessible processes
- ⚠️ Skip protected registry keys
- ⚠️ Monitor only user directories
- ⚠️ Have limited network visibility
- ⚠️ May not display security notifications

## Troubleshooting

### "Access Denied" Errors
- Run with administrator privileges
- Check Windows Defender settings
- Ensure antivirus is not blocking the agent

### "Permission Denied" for Files
- The agent will automatically skip inaccessible paths
- Check file permissions if needed
- Run as administrator for full access

### Network Connection Issues
- Check firewall settings
- Ensure server is running
- Verify server URL in `config/agent_config.yaml`

## Security Note

The EDR agent is designed for security monitoring and requires elevated privileges to function properly. Always run from trusted sources and ensure your system is secure.

## Quick Commands

```bash
# Run with admin (batch)
run_agent_admin.bat

# Run with admin (PowerShell)
.\run_agent_admin.ps1 -Force

# Run with admin (Python)
python run_as_admin.py

# Run normally (limited privileges)
python main.py
``` 