# EDR Windows Agent

EDR Security Agent for Windows - Complete endpoint security monitoring agent compatible with EDR Server.

## Features

- **Process Monitoring**: Real-time process creation and termination monitoring
- **File System Monitoring**: File creation, modification, deletion, and move events
- **Network Monitoring**: Network connection monitoring and analysis
- **Registry Monitoring**: Windows registry changes monitoring
- **Authentication Monitoring**: Login and authentication events
- **System Monitoring**: System performance and health monitoring

## Quick Start

### 1. Install Dependencies

```bash
# Install required packages
pip install -r requirements.txt
```

### 2. Configure the Agent

Edit `config/agent_config.yaml` to set your server details:

```yaml
server:
  host: "192.168.20.85"  # Your EDR server IP
  port: 5000
  auth_token: "edr_agent_auth_2024"
```

### 3. Run the Agent

```bash
# Test imports first
python test_imports.py

# Run the agent
python main.py
```

## Troubleshooting

### Import Errors

If you get import errors like `ModuleNotFoundError: No module named 'agent.utils.severity_utils'`:

1. **Check your current directory**: Make sure you're running from the `agent/agenwindowns/` directory
2. **Run the test script**: `python test_imports.py` to diagnose issues
3. **Install dependencies**: `pip install -r requirements.txt`

### Common Issues

1. **Permission Errors**: Run as Administrator for full monitoring capabilities
2. **Network Issues**: Check firewall settings and server connectivity
3. **Missing Dependencies**: Install all required packages from requirements.txt

### Debug Mode

Run with debug logging:

```bash
python main.py --debug
```

## Configuration

The agent can be configured through `config/agent_config.yaml`:

- **Server settings**: Host, port, authentication
- **Collection settings**: Enable/disable specific collectors
- **Performance settings**: Batch sizes, intervals
- **Security settings**: Anti-tamper protection

## Architecture

```
agent/
├── core/           # Core agent components
├── collectors/     # Data collection modules
├── utils/          # Utility functions
├── schemas/        # Data schemas
├── security/       # Security features
└── config/         # Configuration files
```

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Run `python test_imports.py` to diagnose import issues
3. Check the logs in the `logs/` directory
