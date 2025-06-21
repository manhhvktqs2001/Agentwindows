#!/usr/bin/env python3
"""
Comprehensive Fix Script
Runs all fixes and tests for the EDR Windows Agent
"""

import subprocess
import sys
import os
import platform

def run_command(command, description):
    """Run a command and return success status"""
    print(f"\n🔧 {description}")
    print(f"Running: {command}")
    print("-" * 50)
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Success")
            if result.stdout:
                print(result.stdout)
            return True
        else:
            print("❌ Failed")
            if result.stderr:
                print(result.stderr)
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Main fix function"""
    print("🚀 EDR Windows Agent - Comprehensive Fix Script")
    print("=" * 60)
    
    # Check if running on Windows
    if platform.system().lower() != 'windows':
        print("⚠️ This script is designed for Windows systems")
        print("Some fixes may not be applicable on other platforms")
    
    # Step 1: Install dependencies
    print("\n📦 STEP 1: Installing Dependencies")
    print("=" * 40)
    
    if run_command("python install_dependencies.py", "Installing dependencies"):
        print("✅ Dependencies installed successfully")
    else:
        print("⚠️ Some dependencies may have failed to install")
        print("Continuing with other fixes...")
    
    # Step 2: Check imports
    print("\n🔍 STEP 2: Checking Imports")
    print("=" * 40)
    
    if run_command("python fix_imports.py", "Checking import issues"):
        print("✅ Import check completed")
    else:
        print("⚠️ Some import issues detected")
    
    # Step 3: Test agent startup
    print("\n🧪 STEP 3: Testing Agent Startup")
    print("=" * 40)
    
    if run_command("python test_agent_startup.py", "Testing agent components"):
        print("✅ Agent startup test completed")
    else:
        print("⚠️ Some startup issues detected")
    
    # Step 4: Check configuration
    print("\n⚙️ STEP 4: Checking Configuration")
    print("=" * 40)
    
    config_files = [
        "config/agent_config.yaml",
        "config/logging_config.yaml",
        "config/detection_rules.yaml",
        "config/server_endpoints.yaml"
    ]
    
    for config_file in config_files:
        if os.path.exists(config_file):
            print(f"✅ {config_file} - Found")
        else:
            print(f"❌ {config_file} - Missing")
    
    # Step 5: Check directory structure
    print("\n📁 STEP 5: Checking Directory Structure")
    print("=" * 40)
    
    required_dirs = [
        "agent",
        "agent/core",
        "agent/collectors", 
        "agent/utils",
        "agent/schemas",
        "config",
        "logs"
    ]
    
    for directory in required_dirs:
        if os.path.exists(directory):
            print(f"✅ {directory}/ - Found")
        else:
            print(f"❌ {directory}/ - Missing")
    
    # Step 6: Test individual components
    print("\n🔧 STEP 6: Testing Individual Components")
    print("=" * 40)
    
    component_tests = [
        ("Config Manager", "python -c \"from agent.core.config_manager import ConfigManager; print('Config OK')\""),
        ("Communication", "python -c \"from agent.core.communication import ServerCommunication; print('Communication OK')\""),
        ("Security Notifications", "python -c \"from agent.utils.security_notifications import SecurityAlertNotifier; print('Notifications OK')\""),
        ("Base Collector", "python -c \"from agent.collectors.base_collector import BaseCollector; print('Base Collector OK')\""),
        ("Process Collector", "python -c \"from agent.collectors.process_collector import ProcessCollector; print('Process Collector OK')\"")
    ]
    
    for name, command in component_tests:
        if run_command(command, f"Testing {name}"):
            print(f"✅ {name} - OK")
        else:
            print(f"❌ {name} - FAILED")
    
    # Step 7: Final recommendations
    print("\n💡 STEP 7: Final Recommendations")
    print("=" * 40)
    
    print("Based on the test results, here are the next steps:")
    print()
    
    print("1. If all tests passed:")
    print("   🎉 Your agent should work correctly!")
    print("   Run: python main.py")
    print()
    
    print("2. If some tests failed:")
    print("   📋 Check the error messages above")
    print("   🔧 Run individual fix scripts:")
    print("      - python install_dependencies.py")
    print("      - python fix_imports.py")
    print("      - python test_agent_startup.py")
    print()
    
    print("3. For administrator privileges:")
    print("   🛡️ Right-click PowerShell and 'Run as administrator'")
    print("   📁 Navigate to agent directory")
    print("   🚀 Run: python main.py")
    print()
    
    print("4. For network connectivity:")
    print("   🌐 Ensure server is running: python backend/run_server.py")
    print("   🔗 Check server URL in config/agent_config.yaml")
    print()
    
    print("5. For detailed troubleshooting:")
    print("   📖 Check TROUBLESHOOTING.md")
    print("   📝 Enable debug logging in config/logging_config.yaml")
    print()
    
    print("🎯 Ready to run the EDR Windows Agent!")
    print("Run: python main.py")

if __name__ == "__main__":
    main() 