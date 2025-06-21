#!/usr/bin/env python3
"""
Fix Imports Script
Checks and fixes import issues in the EDR Windows Agent
"""

import sys
import os
import importlib
import platform

def test_import(module_name, package_name=None):
    """Test if a module can be imported"""
    try:
        if package_name:
            module = importlib.import_module(package_name)
        else:
            module = importlib.import_module(module_name)
        return True, None
    except ImportError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

def main():
    """Main function to test imports"""
    print("🔍 EDR Windows Agent - Import Checker")
    print("=" * 50)
    
    # Core modules to test
    core_modules = [
        ("aiohttp", "aiohttp"),
        ("psutil", "psutil"),
        ("watchdog", "watchdog"),
        ("pydantic", "pydantic"),
        ("colorlog", "colorlog"),
        ("requests", "requests"),
        ("cryptography", "cryptography"),
        ("plyer", "plyer")
    ]
    
    # Windows-specific modules
    windows_modules = [
        ("pywin32", "win32api"),
        ("wmi", "wmi")
    ]
    
    print("🔧 Testing core modules...")
    failed_core = []
    
    for module_name, import_name in core_modules:
        success, error = test_import(module_name, import_name)
        if success:
            print(f"✅ {module_name} - OK")
        else:
            print(f"❌ {module_name} - FAILED: {error}")
            failed_core.append(module_name)
    
    print(f"\n🪟 Testing Windows-specific modules...")
    failed_windows = []
    
    if platform.system().lower() == 'windows':
        for module_name, import_name in windows_modules:
            success, error = test_import(module_name, import_name)
            if success:
                print(f"✅ {module_name} - OK")
            else:
                print(f"❌ {module_name} - FAILED: {error}")
                failed_windows.append(module_name)
    else:
        print("⚠️ Not on Windows, skipping Windows-specific modules")
    
    # Test agent modules
    print(f"\n🤖 Testing agent modules...")
    
    # Add agent directory to path
    agent_dir = os.path.join(os.path.dirname(__file__), 'agent')
    if agent_dir not in sys.path:
        sys.path.insert(0, agent_dir)
    
    agent_modules = [
        "agent.core.config_manager",
        "agent.core.communication", 
        "agent.core.agent_manager",
        "agent.core.event_processor",
        "agent.utils.security_notifications",
        "agent.collectors.base_collector",
        "agent.collectors.process_collector",
        "agent.collectors.file_collector",
        "agent.collectors.network_collector",
        "agent.collectors.registry_collector",
        "agent.collectors.authentication_collector",
        "agent.collectors.system_collector"
    ]
    
    failed_agent = []
    
    for module_name in agent_modules:
        success, error = test_import(module_name)
        if success:
            print(f"✅ {module_name} - OK")
        else:
            print(f"❌ {module_name} - FAILED: {error}")
            failed_agent.append(module_name)
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Import Check Summary:")
    
    total_tests = len(core_modules) + len(windows_modules) + len(agent_modules)
    total_failed = len(failed_core) + len(failed_windows) + len(failed_agent)
    total_passed = total_tests - total_failed
    
    print(f"✅ Passed: {total_passed}/{total_tests}")
    print(f"❌ Failed: {total_failed}/{total_tests}")
    
    if failed_core:
        print(f"\n❌ Failed core modules: {', '.join(failed_core)}")
        print("💡 Install with: pip install " + " ".join(failed_core))
    
    if failed_windows and platform.system().lower() == 'windows':
        print(f"\n❌ Failed Windows modules: {', '.join(failed_windows)}")
        print("💡 Install with: pip install " + " ".join(failed_windows))
    
    if failed_agent:
        print(f"\n❌ Failed agent modules: {', '.join(failed_agent)}")
        print("💡 Check file structure and dependencies")
    
    if total_failed == 0:
        print("\n🎉 All imports successful! Agent should work correctly.")
    else:
        print(f"\n⚠️ {total_failed} import(s) failed. Please fix before running the agent.")
        
        # Provide specific fixes
        if "wmi" in failed_windows:
            print("\n🔧 For WMI issues:")
            print("1. Install: pip install wmi")
            print("2. Ensure pywin32 is installed: pip install pywin32")
            print("3. Run as administrator if needed")
        
        if "plyer" in failed_core:
            print("\n🔧 For Plyer issues:")
            print("1. Install: pip install plyer")
            print("2. On Windows, may need: pip install pywin32")
        
        if "cryptography" in failed_core:
            print("\n🔧 For Cryptography issues:")
            print("1. Install: pip install cryptography")
            print("2. May need Visual C++ build tools on Windows")

if __name__ == "__main__":
    main() 